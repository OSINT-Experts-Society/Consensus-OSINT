"""Terminal output: coloured live results and progress, JSON-line streaming,
or nothing at all (``--quiet``).  Uses *rich* when available, plain text otherwise."""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

from .branding import (
    ACCENT,
    DESCRIPTION,
    EXAMPLES,
    HEALTH_WARNING,
    LINKS,
    MENU,
    ORGANIZATION,
    PHONE_GUIDANCE,
    QUERY_GUIDANCE,
    SLOGAN,
    TERMINAL_MARK,
    UPDATE_NOTE,
)
from .models import INFO_CATEGORIES, Finding, Status
from .presentation import assessment, has_details, split_fields
from .provenance import LEGEND, coverage_text, repository_coverage

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Column, Table
    from rich.text import Text

    HAVE_RICH = True
except Exception:  # noqa: BLE001
    HAVE_RICH = False


if HAVE_RICH:
    class ScanProgress(Progress):
        def get_renderables(self):
            yield from super().get_renderables()
            if self.tasks:
                fields = self.tasks[0].fields
                mark = "[+] " if time.monotonic() - fields.get("last_hit", 0) < 1.8 else ""
                yield Text(f"{mark}{fields['state']} · Found {fields['matches']} · Enriched {fields['enriched']}", style=ACCENT)
                preview = fields.get("preview")
                if preview and preview.visible:
                    limit = min(5, max(1, (self.console.size.height - 8) // 2))
                    yield Text(preview.text(self.console.width - 2, limit), style=ACCENT)

STATUS_STYLE = {
    Status.FOUND: "bold green",
    Status.NOT_FOUND: "dim",
    Status.UNKNOWN: "yellow",
    Status.BLOCKED: "magenta",
    Status.RATE_LIMITED: "yellow",
    Status.ERROR: "red",
    Status.SKIPPED: "dim",
}
STATUS_SYMBOL = {
    Status.FOUND: "[+]",
    Status.NOT_FOUND: "[-]",
    Status.UNKNOWN: "[?]",
    Status.BLOCKED: "[!]",
    Status.RATE_LIMITED: "[!]",
    Status.ERROR: "[x]",
    Status.SKIPPED: "[ ]",
}

_CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _display(value, *, single_line=False) -> str:
    text = _CONTROLS.sub("", str(value))
    return text.replace("\n", " ").replace("\t", " ") if single_line else text


def compact_extra(extra: dict, limit: int = 6, width: int = 60) -> str:
    from .reports import display_fields

    details, _ = split_fields(extra)
    return "  ".join(f"{field.key}={_display(field.value, single_line=True)}"
                     for field in display_fields(details, max_fields=limit, limit=width, include_images=True))


class Printer:
    """Streams findings to the terminal as they arrive."""

    def __init__(self, *, show_all: bool = False, quiet: bool = False, jsonl: bool = False, color: bool = True,
                 verbose: bool = False, details: bool = False, summary_limit: int = 0, live_limit: int = 0, stream=None,
                 animate: bool = True):
        self.show_all = show_all
        self.quiet = quiet
        self.jsonl = jsonl
        self.verbose = verbose
        self.details = details
        self.summary_limit = summary_limit
        self.live_limit = live_limit
        self._compact_live = live_limit == 0
        self._last_counter = 0.0
        self.detail_count = 0
        self._state = "Scanning"
        self.animate = animate
        self.stream = stream or sys.stdout
        color = color and "NO_COLOR" not in os.environ
        self.console = Console(file=self.stream, highlight=False, force_terminal=None if color else False,
                               no_color=not color, emoji=False) if HAVE_RICH else None
        self.progress = None
        self.task_id = None
        self.counts: dict = {}
        self.match_count = 0
        from .terminal_ui import current_ui

        self.terminal_ui = current_ui()
        from .terminal_progress import TerminalProgress

        self.tab_progress = TerminalProgress(self.stream, enabled=(color and animate and not quiet and not jsonl
                                             and (self.terminal_ui is None or self.terminal_ui.animate)))
        from .scan_preview import HitPreview

        self.preview = HitPreview()
        self._last_hit = 0.0
        self._preparation = None

    def welcome(self, version: str) -> None:
        """Small start page; no provider imports, prompts or full option dump."""
        self.identity(version)
        self.session_information()
        self.command_menu()

    def home(self, version: str, *, has_results=False, saved_report=None, graph_report=None, reset_screen=False) -> None:
        """Interactive home sized to the actual input terminal, including footer."""
        if self.quiet or self.jsonl:
            return
        from .session_info import SessionInfo

        info = self.terminal_ui.info if self.terminal_ui else SessionInfo.current()
        if saved_report and self.terminal_ui:
            self.terminal_ui.update("Report saved", last_report=Path(saved_report).resolve())
        if self.console:
            from .home import home_page
            from .terminal_ui import input_rows

            size = self.terminal_ui.session.app.output.get_size() if self.terminal_ui else self.console.size
            width = size.columns if self.terminal_ui else size.width
            height = size.rows if self.terminal_ui else size.height
            if (saved_report or reset_screen) and self.terminal_ui:
                self.console.clear()
            footer = getattr(self.terminal_ui, "footer_text", None)
            page = home_page(info, width=width, height=height - bool(saved_report) - bool(graph_report), version=version,
                             history=self.terminal_ui is not None, has_results=has_results,
                             input_rows=input_rows(width, height) if self.terminal_ui else 1,
                             footer_rows=len(footer(width).splitlines()) if footer else None)
            self.console.print(page, soft_wrap=True)
            if saved_report:
                self.report_saved(saved_report, graph_path=graph_report, compact_width=width)
        else:
            self.message(f"[OES] CONSENSUS {version} · By {ORGANIZATION}\n{SLOGAN}\n"
                         "Weekly catalogue updates from major lookup repositories.\n"
                         "1 Username   2 Email   3 Phone   4 Bulk search\n"
                         "5 View results   6 Save report   7 Settings\n"
                         "8 Investigations   9 Help   0 Exit\n"
                         "Paste a username, email or phone below.\n"
                         "/ commands · /config settings · info: full paths\n"
                         "Bugs can occur. Use test accounts and verify findings.\n"
                         "Lawful, authorised use only. Respect privacy and terms.")
            if saved_report:
                self.report_saved(saved_report, graph_path=graph_report)

    def actions(self, *, has_results=False):
        if self.quiet or self.jsonl:
            return
        if self.console:
            from .home import action_panels

            size = self.terminal_ui.session.app.output.get_size() if self.terminal_ui else self.console.size
            width = size.columns if self.terminal_ui else size.width
            height = size.rows if self.terminal_ui else size.height
            if width >= 40:
                rows = action_panels(width, has_results=has_results)
                self.console.print(Text("\n").join(row for row, rank in rows if height >= 28 or not rank), soft_wrap=True)
                return
        self.message("1 Username · 2 Email · 3 Phone · 4 Bulk search")
        self.message("5 View results · 6 Save report · 7 Settings")
        self.message("8 Investigations · 9 Help · 0 Exit")
        if not has_results:
            self.message("5/6: Run a search first.", "dim")

    def session_information(self, output=None) -> None:
        if self.quiet or self.jsonl:
            return
        from .session_info import SessionInfo

        info = self.terminal_ui.info if self.terminal_ui else SessionInfo.current()
        rows = info.rows(output)
        if self.terminal_ui and hasattr(self.terminal_ui, "network"):
            network = self.terminal_ui.network
            rows += [("Public IP (direct)", network.public_ip), ("Proxy egress IP", network.proxy_ip),
                     ("Proxy observation", network.proxy_status)]
        if self.console:
            from rich.style import Style

            table = Table(title="Your session", title_style=f"bold {ACCENT}", title_justify="left",
                          box=box.ROUNDED, border_style="dim", show_header=False, padding=(0, 1))
            table.add_column(style=ACCENT, no_wrap=True)
            table.add_column(overflow="fold")
            for label, value in rows:
                link = value if label == "Project repository" else (
                    Path(value).as_uri() if label in {"Working folder", "Default reports", "Report file", "Application files"} else None)
                table.add_row(Text(label), Text(_display(value, single_line=True), style=Style(link=link)))
            self.console.print(table)
        else:
            for label, value in rows:
                self.message(f"{label}: {_display(value, single_line=True)}")
        self.message("Reports are saved only when you choose Save or use -o FILE. Relative paths start in the working folder.", "dim")

    def identity(self, version: str = "") -> None:
        if self.quiet or self.jsonl:
            return
        if self.console is None:
            self.message(f"[ OES ]  C O N S E N S U S  {version}\n{SLOGAN}\n{DESCRIPTION}\n{UPDATE_NOTE}\nBy {ORGANIZATION}")
        else:
            mark = Table.grid(padding=(0, 2))
            mark.add_column(style=ACCENT, no_wrap=True)
            mark.add_column()
            title = Text("C O N S E N S U S", style=f"bold {ACCENT}")
            title.append(f"  {version}\n", style="dim default")
            title.append(SLOGAN + "\n", style="bold default")
            title.append(DESCRIPTION + "\n", style="default")
            title.append("\n" + UPDATE_NOTE + "\n\n", style=ACCENT)
            title.append(f"By {ORGANIZATION}", style="dim default")
            mark.add_row(Text(TERMINAL_MARK, style=ACCENT), title)
            self.console.print(Panel(mark, border_style=ACCENT, box=box.ROUNDED, padding=(0, 1)))
        for name, url in LINKS:
            if self.console:
                from rich.style import Style

                line = Text()
                line.append(f"{name:8} ", style="dim")
                line.append(url, style=Style(link=url, color=ACCENT))
                self.console.print(line)
            else:
                self.message(f"{name}: {url}")
        self.message("Health & lawful use: " + HEALTH_WARNING, "yellow")

    def command_menu(self) -> None:
        if self.quiet or self.jsonl:
            return
        self.message("What would you like to do? Run a command below:", f"bold {ACCENT}")
        if self.console:
            table = Table(box=None, show_header=False, padding=(0, 1))
            table.add_column(style=ACCENT)
            table.add_column(overflow="fold")
            for label, command in MENU:
                table.add_row(Text(label), Text(command, style="bold"))
            self.console.print(table)
        else:
            for label, command in MENU:
                self.message(f"{label:14} {command}")
        self.message(QUERY_GUIDANCE, "dim")
        self.message(PHONE_GUIDANCE, "dim")
        self.message("Ctrl+C stops a scan and keeps collected results.", "dim")

    def examples(self) -> None:
        self.message("Consensus · Examples", f"bold {ACCENT}")
        self.message("These are commands to copy and edit; displaying this page does not run a search.")
        self.message(QUERY_GUIDANCE + "\n" + PHONE_GUIDANCE, "dim")
        if self.console:
            table = Table(box=box.ROUNDED, show_lines=True, header_style=f"bold {ACCENT}", expand=True)
            table.add_column("Example / command", ratio=5, overflow="fold")
            table.add_column("What it does", ratio=4, overflow="fold")
            for label, command, explanation in EXAMPLES:
                table.add_row(Text.assemble((label + "\n", f"bold {ACCENT}"), command), Text(explanation))
            self.console.print(table)
        else:
            for label, command, explanation in EXAMPLES:
                self.message(f"\n{label}\n  {command}\n  {explanation}")
        self.message(HEALTH_WARNING, "yellow")

    def help(self, parser) -> None:
        """Style argparse's actual visible actions; parsing remains argparse's job."""
        import argparse

        if self.console is None:
            self.message(parser.format_help())
            return
        self.console.print(Panel(Text(parser.prog + " · Help", style=f"bold {ACCENT}"), border_style=ACCENT))
        if parser.prog.split()[-1] in ("scan", "user", "email", "phone"):
            kind = {"user": "YOUR_USERNAME", "email": "YOUR_EMAIL", "phone": "+COUNTRY_CODE_NUMBER"}.get(
                parser.prog.split()[-1], "YOUR_QUERY")
            self.message(f'Start here: {parser.prog} "{kind}" [options]', f"bold {ACCENT}")
            self.message(QUERY_GUIDANCE, "dim")
            if parser.prog.split()[-1] in ("phone", "scan"):
                self.message(PHONE_GUIDANCE, "dim")
        elif parser.description:
            self.message(parser.description)
        formatter = parser._get_formatter()
        table = Table(box=box.SIMPLE_HEAD, padding=(0, 1), expand=True,
                      header_style=f"bold {ACCENT}")
        table.add_column("Command / option", ratio=2, overflow="fold")
        table.add_column("What it does", ratio=3, overflow="fold")
        headings = {"positional arguments": "What to search / open", "options": "Help",
                    "output": "Results & reports", "network": "Connection",
                    "scope": "Choose sites", "pivoting": "Input & discovery"}
        for group in parser._action_groups:
            actions = [a for a in group._group_actions if a.help != argparse.SUPPRESS]
            if not actions:
                continue
            table.add_row(Text(headings.get(group.title, group.title.capitalize()), style=f"bold {ACCENT}"), "")
            for action in actions:
                if isinstance(action, argparse._SubParsersAction):
                    for child in action._get_subactions():
                        table.add_row(child.dest, Text(child.help or ""))
                    continue
                name = ", ".join(action.option_strings) or action.dest
                if action.option_strings and action.nargs != 0:
                    name += " " + str(action.metavar or action.dest.upper())
                description = formatter._expand_help(action) if action.help else ""
                if action.choices:
                    description += " Choices: " + ", ".join(map(str, action.choices)) + "."
                table.add_row(Text(name, style=ACCENT), Text(description))
        self.console.print(table)
        self.message("More guidance: consensus examples  |  Full reference: consensus scan --help-all", "dim")

    # ---------------------------------------------------------------- progress
    def start_preparation(self, label="Preparing search"):
        if self.quiet or self.jsonl:
            return
        if self.terminal_ui:
            if self.terminal_ui.controller is None:
                self.terminal_ui.begin_scan()
            self.activity(label)
        elif self.console and self.console.is_interactive:
            if self._preparation is None:
                self._preparation = self.console.status(Text(label), spinner="dots", spinner_style=ACCENT,
                                                        speed=1 if self.animate else 0)
                self._preparation.start()
            else:
                self._preparation.update(Text(label))
        else:
            self.message(label + "…", "dim")

    def stop_preparation(self):
        if self._preparation is not None:
            self._preparation.stop()
            self._preparation = None
        if self.terminal_ui:
            self.terminal_ui.update(preparing=False)

    def start_progress(self, total: int, label: str) -> None:
        self.stop_preparation()
        if self.terminal_ui and not self.quiet and not self.jsonl:
            self.terminal_ui.start_phase(total, label)
            return
        if (self.quiet or self.jsonl or self.console is None or not self.stream.isatty()
                or not self.console.is_interactive):
            return
        self.progress = ScanProgress(
            SpinnerColumn(style=ACCENT) if self.animate else TextColumn("•", style=ACCENT),
            TextColumn("{task.description}", style="progress.description", markup=False,
                       table_column=Column(max_width=max(12, self.console.width // 3), no_wrap=True, overflow="ellipsis")),
            BarColumn(bar_width=None, complete_style=ACCENT, finished_style=ACCENT),
            MofNCompleteColumn(),
            TextColumn("sites"),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        )
        self.progress.start()
        self.task_id = self.progress.add_task(_display(label, single_line=True), total=total,
                                               matches=self.match_count, enriched=self.detail_count, state=self._state,
                                               preview=self.preview)

    def toggle_preview(self):
        if self.quiet or self.jsonl:
            return
        if self.terminal_ui:
            self.terminal_ui.toggle_preview()
        elif self.progress:
            self.preview.toggle()
            self.progress.refresh()

    def activity(self, label, sources=None):
        if self.terminal_ui and not self.quiet and not self.jsonl:
            values = {"sources": tuple(sorted(set(sources)))} if sources is not None else {}
            self.terminal_ui.update(label, **values)
        elif self._preparation is not None:
            self._preparation.update(Text(_display(label, single_line=True)))

    def separator(self, title):
        if self.quiet or self.jsonl:
            return
        self.message("")
        if self.console:
            self.console.rule(Text(_display(title), style=f"bold {ACCENT}"), style=ACCENT)
        else:
            self.message("=" * 20 + " " + title + " " + "=" * 20)
        self.message("")

    def query_heading(self, query, kind):
        self.separator("Searching " + kind)
        self.message("Search query: " + query, f"bold {ACCENT}")
        self.message("")
        if self.terminal_ui:
            self.terminal_ui.update(total=0, completed=0, sources=())
        self.start_preparation("Preparing " + kind + " lookup")

    def scan_state(self, state, explanation):
        self._state = state
        if state == "Paused":
            self.tab_progress.pause()
        else:
            self.tab_progress.resume()
        if self.terminal_ui:
            self.terminal_ui.update(state)
        if self.progress is not None:
            self.progress.update(self.task_id, state=state)
        self.message(explanation, "yellow" if state != "Scanning" else "dim")

    def _counter(self):
        if self.terminal_ui:
            return
        # Non-TTY logs remain readable without cursor escapes or one line per site.
        now = time.monotonic()
        if self.progress is None and now - self._last_counter >= 2:
            self._last_counter = now
            self.message(f"{self._state}: {sum(self.counts.values())} results · "
                         f"Found {self.match_count} · Enriched {self.detail_count}", "dim")

    def stop_progress(self) -> None:
        if self.progress is not None:
            try:
                self.progress.stop()
            except Exception:  # noqa: BLE001
                pass
            self.progress = None
            self.task_id = None

    # ---------------------------------------------------------------- output
    def __call__(self, f: Finding) -> None:
        self.counts[f.status.value] = self.counts.get(f.status.value, 0) + 1
        if f.status is Status.FOUND and f.category not in INFO_CATEGORIES:
            self.match_count += 1
            self.detail_count += has_details(f)
        if self.jsonl:
            if self.show_all or f.status is Status.FOUND:
                self.stream.write(json.dumps(f.to_dict(), ensure_ascii=False) + "\n")
                self.stream.flush()
            return
        if self.quiet:
            return
        if self.terminal_ui:
            self.terminal_ui.result(self.match_count, self.detail_count, f)
            # The pinned counters and optional V preview own live output.
            # Full cards can flood scrollback and compete with prompt redraws.
            return
        else:
            if self.preview.add(f):
                self._last_hit = time.monotonic()
        if self.progress is not None:
            self.progress.update(self.task_id, advance=1, matches=self.match_count, enriched=self.detail_count,
                                 last_hit=self._last_hit)
        if self.match_count > self.live_limit and not self._compact_live:
            self._compact_live = True
            self.message(f"More than {self.live_limit} positive results: switching to counters. "
                         "Results will be listed in the final table.", "dim")
        if self._compact_live:
            self._counter()
            return
        informational = f.category in INFO_CATEGORIES
        if not (self.show_all or informational or f.status is Status.FOUND
                or (self.verbose and f.status not in (Status.NOT_FOUND, Status.SKIPPED))):
            return
        self._print_line(f)

    def _result_table(self, title=None):
        table = Table(title=Text(_display(title)) if title else None, box=box.ROUNDED, show_lines=True,
                      header_style=f"bold {ACCENT}", width=self.console.width, expand=True)
        if self.console.width < 120:
            table.add_column("Results and returned details", overflow="fold")
        else:
            # Fixed widths shared by preview and final tables; content cannot move a divider.
            available = self.console.width - 16  # six borders and ten padding cells
            widths = [int(available * .18), int(available * .20), int(available * .29), int(available * .17)]
            widths.append(available - sum(widths))
            for heading, width in zip(self.result_headings(), widths, strict=True):
                table.add_column(heading, width=width, min_width=width, max_width=width, overflow="fold")
        return table

    @staticmethod
    def result_headings():
        return ("Site / query", "Result", "Enriched information", "Tools with this lookup", "Profile / result link")

    def _result_cells(self, f):
        from .provenance import information_source
        from .reports import display_fields, result_link

        label, explanation, tone = assessment(f)
        fields, _ = split_fields(f.extra)
        display = display_fields(fields, max_fields=0, limit=0, include_images=True)
        if f.category in INFO_CATEGORIES:
            details = "Supporting information (not account enrichment)"
        elif has_details(f):
            details = f"Yes · {len(fields)} returned fields"
        else:
            details = ("No extra details" if not display else
                       "Supporting returned fields" if f.status is Status.FOUND else "Unconfirmed fields")
        if display:
            details += "\n" + "\n".join(f"{field.label}: {field.value}" for field in display)
        result = label
        result += "\n" + explanation
        if f.error:
            result += "\n" + f.error
        context = f"{f.site}\n{f.query} ({f.query_type})"
        origin = information_source(f)
        if origin:
            context += "\nSource: " + origin
        if f.parent:
            context += f"\nvia {f.parent}"
        url, link_label = result_link(f)
        link_text = link_label + ("\n" + url if url else "")
        if self.console is None:
            return [context, result, details, coverage_text(f), link_text]
        from rich.style import Style

        from .reports import _safe_http_url

        site = Text(_display(context))
        site.stylize(Style(bold=True, link=_safe_http_url(f.url)), 0, len(_display(f.site)))
        verdict = Text(_display(result), style="yellow" if tone == "warn" else STATUS_STYLE[f.status])
        link = Text(link_label)
        if url:
            link.append("\n" + _display(url), style=Style(link=url, color=ACCENT))
        enriched = Text(_display(details))
        for field in display:
            for field_url in field.urls:
                # URLs stay visible/copyable as well as clickable in supporting terminals.
                start = enriched.plain.find(field_url)
                if start >= 0:
                    enriched.stylize(Style(link=field_url, color=ACCENT), start, start + len(field_url))
        return [site, verdict, enriched, self._coverage_cell(f), link]

    def _add_result(self, table, f):
        cells = self._result_cells(f)
        headings = self.result_headings()
        if table is None:
            for heading, cell in zip(headings, cells, strict=True):
                self.message(f"{heading}: {cell}")
            self.message("─" * 50)
        elif self.console.width < 120:
            stacked = Text()
            for heading, cell in zip(headings, cells, strict=True):
                if stacked:
                    stacked.append("\n\n")
                stacked.append(heading + ": ", style=f"bold {ACCENT}")
                stacked.append(cell)
            table.add_row(stacked)
        else:
            table.add_row(*cells)

    def _print_line(self, f: Finding) -> None:
        table = self._result_table() if self.console else None
        self._add_result(table, f)
        if table is not None:
            self.console.print(table)

    def _coverage_cell(self, f):
        from rich.style import Style

        text = Text()
        for row in repository_coverage(f):
            if text:
                text.append("\n")
            text.append("[x] ", style=ACCENT)
            text.append(row["name"], style=Style(link=row["url"]))
        if not text:
            return Text(coverage_text(f), style="dim")
        return text

    def report_saved(self, path, *, graph_path=None, compact_width=None) -> None:
        if self.jsonl:
            return
        resolved = Path(path).expanduser().resolve()
        graph = Path(graph_path).expanduser().resolve() if graph_path else None
        if self.terminal_ui:
            self.terminal_ui.update("Reports saved" if graph else "Report saved",
                                    last_report=resolved, last_graph_report=graph)
        links = [("Open HTML report", resolved), ("Open interactive graph", graph)] if graph else [("Report saved", resolved)]
        for label, target in links:
            if self.console is not None:
                from rich.style import Style

                text = Text(label + ": ", style=f"bold {ACCENT}")
                text.append(_display(target.name if compact_width else str(target), single_line=True))
                if compact_width:
                    text.truncate(max(1, compact_width - 1), overflow="ellipsis")
                text.stylize(Style(link=target.as_uri()), 0, len(text))
                self.console.print(text, soft_wrap=True)
            else:
                self.message(f"{label}: {target}", always=True)

    def finish(self, summary, *, review=False, follow_end=False, include_identity=True) -> None:
        """Closing review uses final, deduplicated findings rather than streamed counts."""
        if self.jsonl:
            return
        if review and self.terminal_ui and not self.quiet:
            from .console_results import result_pages

            render, detail = result_pages(summary, show_all=self.show_all, limit=self.summary_limit,
                                          filters=getattr(self.terminal_ui, "result_filters", None))
            self.terminal_ui.review(render, detail=detail, follow_end=follow_end)
            return
        if self.terminal_ui:
            self.terminal_ui.update("Displaying results")
        from .reports import _fmt_duration, group_by_query

        matches = [f for f in summary.findings if f.status is Status.FOUND and f.category not in INFO_CATEGORIES]
        info = sum(f.category in INFO_CATEGORIES for f in summary.findings)
        review = sum(assessment(f)[0] == "Needs review" for f in matches)
        details_count = sum(has_details(f) for f in matches)
        elapsed = _fmt_duration((summary.finished or summary.started) - summary.started)
        incomplete = sum(f.category not in INFO_CATEGORIES and
                         f.status in (Status.UNKNOWN, Status.BLOCKED, Status.RATE_LIMITED, Status.ERROR)
                         for f in summary.findings)
        # Background analysis rows are reported once, as background checks: an
        # unparseable number or address is not a site that answered "no match".
        no_match, skipped = (sum(f.category not in INFO_CATEGORIES and f.status is status for f in summary.findings)
                             for status in (Status.NOT_FOUND, Status.SKIPPED))
        title = "Partial scan" if summary.options.get("interrupted") else "Scan complete"
        lines = [f"{len(matches)} matches  /  {details_count} with additional information  /  {review} need review",
                 f"{len(summary.findings)} results in {elapsed}  /  {info} background checks",
                 f"No match {no_match}  |  Inconclusive {incomplete}  |  Skipped {skipped}"]
        self.separator("Search results")
        if include_identity:
            self.identity()
        self.message("")
        for view in group_by_query(summary):
            self.message(f"Search query: {view.title}", f"bold {ACCENT}")
        self.message("")
        if self.console is not None and not self.quiet:
            self.console.print(Panel(Text("\n".join(lines)), title=title, title_align="left",
                                     border_style=ACCENT, box=box.ROUNDED))
        else:
            self.message(title + " — " + "; ".join(lines), always=True)
        decoding = sum(bool(f.extra.get("_text_decoding")) for f in summary.findings)
        if decoding:
            self.message(f"Text decoding: {decoding} result(s) contain replaced characters; review their text.",
                         "yellow", always=True)
        if self.quiet:
            return
        if info:
            self.message("Background checks = email/domain or phone analysis and search links; enriched account details are counted separately.", "dim")
        self.message("Found = the selected check returned a positive signal for this query. "
                     "Ticks beside tools show catalogue coverage, not separate successful checks.", "dim")
        self.message("Enriched = additional returned information; query echoes, redacted placeholders, identified page metadata and checking flags "
                     "are excluded from the count. Verify its content and connection to the query. "
                     "Needs review = limited evidence. These labels do not prove identity.", "dim")
        if review:
            self.message("Needs review rows are included in the match total; treat them as unconfirmed.", "yellow")
        self.message(LEGEND, "dim")
        from .common_details import compare_details

        for view in group_by_query(summary):
            self.separator("Results for " + view.title)
            self.common_details(compare_details(view.findings), "Information shared by multiple sites")
            rows = list(view.findings) if self.show_all else list(view.found)
            rows = [f for f in rows if f.category not in INFO_CATEGORIES] + [
                f for f in view.findings if f.category in INFO_CATEGORIES]
            rows.sort(key=lambda f: (assessment(f)[0] == "Needs review", not has_details(f), f.site.casefold()))
            if not rows:
                self.message(f"\n{view.title}: no matches reported. Check the inconclusive/skipped totals.", "dim")
                continue
            shown = rows[:self.summary_limit] if self.summary_limit else rows
            table = self._result_table(view.title) if self.console else None
            for f in shown:
                self._add_result(table, f)
            if table is not None:
                self.console.print(table)
            if len(shown) < len(rows):
                self.message(f"Showing {len(shown)} of {len(rows)} results. Use --summary-limit 0 for every row; exports retain all results selected for saving.", "dim")
        if matches and not details_count:
            self.message("These matches returned checking signals only. An 'enricher' registry label does not guarantee profile fields.", "dim")
        if (summary.options or {}).get("compare_queries") is True:
            from .common_details import shared_sites

            self.common_details(compare_details(summary.findings, across_queries=True), "Compare across queries")
            overlaps = shared_sites(summary.findings)
            if overlaps:
                self.summary_table([["Shared site", "Queries reporting a match"]] + [
                    [r["site"], ", ".join(f'{q["query"]} ({q["query_type"]})' for q in r["queries"])] for r in overlaps],
                    "Shared sites across queries · coverage overlap, not an identity link")
        elif len(group_by_query(summary)) > 1:
            self.message("Queries were compared separately. Use --compare-queries to look for shared details across related queries.", "dim")
        from .breach_review import breach_review

        breaches = breach_review(summary)
        self.message("\nBreach lookup coverage", f"bold {ACCENT}")
        self.message(breaches["explanation"], "dim")
        if breaches["rows"]:
            self._comparison_table([["Provider / query", "Outcome", "Returned evidence"]] + [
                [row["site"] + "\n" + row["query"], row["outcome"] + "\n\n" + row["explanation"],
                 "\n\n".join(field["label"] + "\n  " + field["value"] for field in row["evidence"])
                 or "No supporting fields were returned or saved."] for row in breaches["rows"]])
        if breaches["held"]:
            self.message("Unavailable breach checks: " + ", ".join(row["site"] for row in breaches["held"])
                         + ". Held because their response handling does not provide dependable verdicts.", "dim")
        self.separator("End of search results")

    def common_details(self, comparison: dict, title: str) -> None:
        """Show repeated returned values and their actual source context."""
        from .common_details import EXPLANATION

        self.message("\n" + title, f"bold {ACCENT}")
        if not comparison["common"]:
            self.message("No matching values or words were found across different sites." if comparison["compared_sites"] >= 2
                         else "Fewer than two sites returned information that can be compared.", "dim")
        else:
            self.message(EXPLANATION, "dim")
            shown = comparison["common"] if self.details else comparison["common"][:8]
            rows = [["Information found on multiple sites", "Sites returning it", "Original fields and sources"]]
            for item in shown:
                sources = []
                evidence = item["evidence"]
                for entry in evidence:
                    who = f'{entry["site"]} ({entry["query"]})' if comparison["across_queries"] else entry["site"]
                    value = entry["value"]
                    sources.append(f'{who}' + (" — Needs review" if entry["needs_review"] else "")
                                   + f'\n  Field: {entry["field"]}\n  Value: {value}')
                omitted = len(item["evidence"]) - len(evidence)
                if omitted:
                    sources.append(f"+{omitted} source fields; see the detailed report")
                if item["omitted_evidence"]:
                    sources.append(f'{item["omitted_evidence"]} source fields exceed the comparison limit; see original results')
                count = f'{item["site_count"]} ' + ("site" if item["site_count"] == 1 else "sites")
                if comparison["across_queries"]:
                    count += f' / {item["query_count"]} queries'
                label = f'{item["field"]}: {item["value"]}'
                if item["needs_review"]:
                    label += "\nIncludes needs-review results"
                rows.append([label, count, "\n\n".join(sources)])
            self._comparison_table(rows)
            remaining = len(comparison["common"]) - len(shown)
            if remaining:
                self.message(f"{remaining} more patterns; use --details or expand Common details in the HTML report.", "dim")
        if comparison["variations"]:
            rows = [["Different values returned", "Site / field / value"]]
            for variation in comparison["variations"]:
                values = variation["values"] if self.details else variation["values"][:4]
                evidence = []
                for value in values:
                    sites = ", ".join(sorted({f'{e["site"]} ({e["query"]})' if comparison["across_queries"]
                                              else e["site"] for e in value["evidence"]}))
                    evidence.append(f'{value["value"]} — {sites}' + (" [Needs review]" if value["needs_review"] else ""))
                remaining = len(variation["values"]) - len(values) + variation["omitted_values"]
                if remaining:
                    evidence.append(f"+{remaining} values; see the detailed report")
                rows.append([variation["field"], "\n".join(evidence)])
            self.message("Different values to review · profiles may use different names or outdated details.", "dim")
            self._comparison_table(rows)
        if comparison["truncated_input"] or comparison["omitted_patterns"]:
            self.message("Comparison limits were reached; consult the original returned fields for the full data.", "dim")

    def _comparison_table(self, rows):
        if self.console is None:
            for row in rows:
                self.message(" | ".join(map(str, row)))
            return
        table = Table(box=box.ROUNDED, show_lines=True, header_style=f"bold {ACCENT}", expand=True)
        narrow = self.console.width < 76
        for index, heading in enumerate(["Detail / count / evidence"] if narrow else rows[0]):
            table.add_column(heading, overflow="fold", ratio=(2 if index == len(rows[0]) - 1 else 1))
        for row in rows[1:]:
            cells = ["\n".join(map(str, row))] if narrow else row
            table.add_row(*[Text(_display(cell)) for cell in cells])
        self.console.print(table)

    def message(self, text: str, style: str = "", *, always: bool = False) -> None:
        # --quiet means "no per-result output (summary only)": the closing summary
        # and "report saved" pass ``always``; JSON-lines mode keeps stdout clean.
        if self.jsonl or (self.quiet and not always):
            return
        if self.console is not None:
            self.console.print(Text(_display(text), style=style.replace("cyan", ACCENT)))
        else:
            print(_display(text), file=self.stream)

    def warn(self, text: str) -> None:
        # A warning is never chatter: --quiet drops per-result output and the
        # summary, not "interrupted" or "could not save report".
        if self.jsonl or self.quiet:
            print(_display(text), file=sys.stderr)
            return
        self.message(text, "yellow")

    def summary_table(self, rows: list, title: str) -> None:
        if self.quiet or self.jsonl:
            return
        if self.console is None or not rows:
            for r in rows:
                print("  ".join(_display(x, single_line=True) for x in r), file=self.stream)
            return
        t = Table(title=Text(_display(title), style=f"bold {ACCENT}"), title_justify="left",
                  show_lines=False, box=box.ROUNDED, border_style="dim", header_style=f"bold {ACCENT}")
        for h in rows[0]:
            t.add_column(Text(_display(h, single_line=True)))
        for r in rows[1:]:
            t.add_row(*[Text(_display(x, single_line=True)) for x in r])
        self.console.print(t)


def _esc(s: str) -> str:
    return str(s).replace("[", "\\[")
