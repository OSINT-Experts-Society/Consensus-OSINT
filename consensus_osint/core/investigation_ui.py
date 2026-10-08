"""Guided local investigation and follow-up actions in the terminal session."""
from __future__ import annotations

from .continuity import Continuation, compare, inventory, new_source_counts
from .investigations import Investigations


def show_changes(session, changes=None):
    changes = changes or (session.latest.options.get("changes") if session.latest else None)
    if not changes:
        session.printer.message("No comparison yet. Open a saved search and choose Recheck, or compare two investigation searches.")
        return
    if session.printer.terminal_ui:
        import io

        from rich.console import Console

        from .console import Printer

        def render(width):
            stream = io.StringIO()
            printer = Printer(stream=stream)
            printer.terminal_ui = None
            printer.console = Console(file=stream, width=width, force_terminal=True, color_system="truecolor",
                                      legacy_windows=False, highlight=False)
            _print_changes(printer, changes)
            return stream.getvalue()

        session.printer.terminal_ui.review(render, actions=False, title="Search changes", exit_label="Back")
        return
    _print_changes(session.printer, changes)


def _print_changes(printer, changes):
    printer.message(changes["note"])
    rows = [["Identifier", "Site", "Change", "Changed fields"]]
    rows += [[r["query"], r["site"], r["change"], ", ".join(r["fields"])]
             for r in changes["rows"] if r["change"] not in ("Unchanged", "Not rechecked")]
    counts = {label: sum(r["change"] == label for r in changes["rows"]) for label in ("Unchanged", "Not rechecked")}
    printer.message(f"{counts['Unchanged']} unchanged; {counts['Not rechecked']} not rechecked.")
    if len(rows) == 1:
        printer.message("No changes observed in the sources rechecked.")
    else:
        printer.summary_table(rows, "Changes since previous search")
    from .continuity import observation_time
    from .models import Finding
    from .presentation import enrichment_fields

    for row in changes["rows"]:
        if row.get("previous_evidence"):
            old = Finding.from_dict(row["previous_evidence"])
            printer.message(f"Previous observation only: {old.query} / {old.site} / {observation_time(old)}")
            printer.summary_table([["Field", "Previous value"], ["Result", old.status.value],
                                           ["URL", old.url or ""],
                                           *[[k, str(v)] for k, v in enrichment_fields(old).items()]], "Earlier evidence")


def follow_up(session, mode):
    previous = session.latest
    if previous is None:
        session.printer.message("Run or open a saved search first.")
        return
    continuation = Continuation(previous, mode)
    queries = [q["type"] + ":" + q["query"] for q in previous.queries if not q.get("parent")]
    if not queries:
        raise ValueError("This search contains no starting identifiers.")
    flags = []
    # Replay scope and safety preferences, never report paths or expansion flags.
    values = ("site", "exclude", "tags", "exclude_tags", "source", "family", "timeout", "concurrency",
              "delay", "per_host", "phone_region")
    toggles = ("nsfw", "allow_loud", "no_breach", "no_sites", "no_modules", "no_extract", "no_impersonate", "tor", "all_modules")
    for key in values:
        value = previous.options.get(key)
        if value is not None and value != "":
            flags += ["--" + key.replace("_", "-"), str(value)]
    flags += ["--" + key.replace("_", "-") for key in toggles if previous.options.get(key) is True]
    proxy = previous.options.get("proxy")
    if proxy:
        # Saved metadata deliberately lacks credentials; never silently fall
        # back to a direct connection for a previously routed investigation.
        proxy = session.back_prompt("Proxy URL for this follow-up (Enter cancels): ").strip()
        if not proxy:
            return
        flags += ["--proxy", proxy]
    if previous.options.get("no_verify"):
        raise ValueError("This search disabled TLS verification. Start a new verified search before continuing it.")
    if mode == "new":
        counts = new_source_counts(previous)
        if not sum(counts.values()):
            session.printer.message("No new lookup sources are available for these identifiers.")
            return
        session.printer.message(f"{sum(counts.values())} new lookup opportunities; your saved filters still apply.")
    session.printer.message({"continue": "Continuing the full search; completed lookups will be retained.",
                             "new": "Searching new sources; existing results will be retained.",
                             "recheck": "Rechecking saved identifiers and comparing the returned information."}[mode])
    session.execute(["scan", *flags, "--", *queries], continuation=continuation)


def actions(session):
    while True:
        session.printer.message("1 Continue full search   2 Search new sources   3 Recheck & compare\n"
                                "4 View changes   5 Investigations   0 Back")
        answer = session.back_prompt("Follow-up action: ", zero=True).strip()
        if answer in ("", "0"):
            return
        if answer in ("1", "2", "3"):
            follow_up(session, {"1": "continue", "2": "new", "3": "recheck"}[answer])
            return
        if answer == "4":
            show_changes(session)
        elif answer == "5":
            screen(session)
            return


def screen(session):
    store = Investigations()
    while True:
        entries = store.entries()
        session.clear_menu()
        session.printer.summary_table([["Open", "Investigation", "Saved searches"],
                                       *[[str(i), name, str(count)] for i, (_, name, count) in enumerate(entries, 1)]],
                                      "Investigations · saved on this computer")
        session.printer.message("N New investigation · number Open · 0 / Esc Back\n"
                                "Identifiers, findings and notes are stored locally only when you choose Save.")
        answer = session.back_prompt("Investigation: ", zero=True).strip()
        if answer in ("", "0"):
            return
        if answer.lower() == "n":
            name = session.back_prompt("Investigation name (Enter cancels): ").strip()
            if not name:
                continue
            key = store.create(name)
        elif answer.isdecimal() and 1 <= int(answer) <= len(entries):
            key = entries[int(answer) - 1][0]
        else:
            session.printer.message("Choose a listed number or N.")
            continue
        if case_screen(session, store, key):
            return


def case_screen(session, store, key):
    current_inventory = inventory()
    while True:
        value = store.read(key)
        session.clear_menu()
        session.printer.message(value["name"], "bold")
        if value["notes"]:
            session.printer.message(value["notes"])
        rows = [["Open", "Identifiers", "Matches"]]
        for i, snapshot in enumerate(value["searches"], 1):
            rows.append([str(i), ", ".join(q["query"] for q in snapshot["queries"] if not q.get("parent")),
                         str(sum(f.get("status") == "found" for f in snapshot["findings"]))])
        session.printer.summary_table(rows, "Saved searches")
        if value["searches"]:
            try:
                count = sum(new_source_counts(store.open_search(key), current_inventory).values())
                session.printer.message(f"{count} new lookup opportunities available for the latest saved search.")
            except ValueError:
                session.printer.message("Older saved search: run a fresh search to enable new-source comparisons.")
        session.printer.message("Number Open · S Save latest · N Notes · R Rename · V Review a result\n"
                                "C Compare searches · F Follow up latest · D Delete investigation · 0 Back")
        choice = session.back_prompt("Investigation action: ", zero=True).strip().lower()
        if choice in ("", "0"):
            return
        if choice == "s":
            if session.latest is None:
                session.printer.message("Run a search first, then choose Save latest here.")
                continue
            if session.back_prompt("Save the latest search in this investigation? [y/N]: ").lower() in ("y", "yes"):
                store.save(key, session.latest)
                session.latest = store.open_search(key)
        elif choice in ("n", "r"):
            label = "Notes" if choice == "n" else "New name"
            updated = session.back_prompt(label + " (Enter cancels; - clears notes): ")
            if updated:
                store.update(key, **({"notes": "" if updated == "-" else updated} if choice == "n" else {"name": updated}))
        elif choice == "d":
            if session.back_prompt("Delete this investigation and its saved searches? [y/N]: ").lower() in ("y", "yes"):
                store.delete(key)
                return
        elif choice == "c":
            pair = session.back_prompt("Two search numbers, oldest first (e.g. 1 2): ").split()
            if not pair:
                continue
            if len(pair) != 2 or not all(p.isdecimal() and 1 <= int(p) <= len(value["searches"]) for p in pair):
                raise ValueError("Choose two available search numbers")
            show_changes(session, compare(store.open_search(key, int(pair[0])-1), store.open_search(key, int(pair[1])-1)))
            session.back_prompt("Enter to return: ")
        elif choice == "f":
            session.latest = store.open_search(key)
            actions(session)
            return True
        elif choice == "v":
            latest = store.open_search(key)
            found = latest.found
            session.printer.summary_table([["Result", "Identifier", "Site"],
                                           *[[str(i), f.query, f.site] for i, f in enumerate(found, 1)]], "Review findings")
            number = session.back_prompt("Result number (Enter cancels): ").strip()
            if not number:
                continue
            if not number.isdecimal() or not 1 <= int(number) <= len(found):
                raise ValueError("Choose an available result")
            decision = session.back_prompt("Relevant / unrelated / unreviewed (Enter cancels): ").strip().lower()
            if not decision:
                continue
            note = session.back_prompt("Review note (optional): ")
            if session.back_prompt("Save this analyst decision and note? [y/N]: ").lower() in ("y", "yes"):
                store.review(key, found[int(number)-1], decision, note)
                session.latest = store.open_search(key)
        elif choice.isdecimal() and 1 <= int(choice) <= len(value["searches"]):
            opened = store.open_search(key, int(choice)-1)
            session.latest = opened
            if session.printer.terminal_ui:
                session.printer.terminal_ui.result_filters = {}
            session.show_latest()
            return True
        else:
            session.printer.message("Choose an available search or action.")
