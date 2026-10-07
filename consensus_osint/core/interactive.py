"""Persistent, line-based terminal session over the existing CLI commands."""
from __future__ import annotations

import os
import re
import shlex
import sys
from datetime import datetime
from pathlib import Path

from .. import __version__
from .branding import ACCENT, PHONE_GUIDANCE
from .console import Printer
from .models import QueryType, redact_options
from .scan_control import terminal_available

CHOICES = (
    ("1", "Username", "user"), ("2", "Email", "email"), ("3", "Phone", "phone"),
    ("4", "Bulk search", "bulk"), ("5", "View latest results", "last"),
    ("6", "Save latest report", "save"), ("7", "Settings", "settings"),
    ("8", "Examples", "examples"), ("9", "Help", "help"), ("0", "Exit", "exit"),
)
_DEFAULTS = {"details": False, "all": False, "fast": False, "no_breach": False, "timeout": None}
_SETTINGS = (
    ("details", "Expand comparison evidence"), ("all", "Show all outcomes"),
    ("fast", "Quick username search"), ("no_breach", "Exclude breach lookups"),
    ("timeout", "Site timeout"),
)
_COMMANDS = {"scan", "user", "username", "email", "phone", "sites", "modules", "report", "version", "update"}
# Words people type expecting a command or answering a prompt that is no longer open. Each would otherwise
# be detected as a username and looked up on every site; `user WORD` still searches for the word itself.
_LEAVE_WORDS = {"0", "back", "cancel", "menu", "q", "quit", "exit"}
_TERMINAL_ONLY = {"keys", "mcp", "shell"}
_NOT_A_SEARCH = {"y", "n", "yes", "no", "ok", "okay", "cancel", "stop", "back", "clear", "cls", "history", "options",
                 "home", "list", "open", "close", "status", "undo", "retry", "again", "rescan", "search", "find",
                 "lookup", "start", "run", "go", "commands", "print", "delete", "new"}


def _cli_words():
    # The command line explains these first words instead of searching for them; the session agrees.
    from ..cli import NOT_A_SEARCH

    return NOT_A_SEARCH


def split_command(line):
    # Quotes group arguments; literal backslashes preserve Windows paths.
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    lexer.escape = ""
    return list(lexer)


def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


class Session:
    def __init__(self, *, color=True, animate=True, printer=None, read=None):
        self.color = color
        self.animate = animate
        self.initial_animation = animate
        self.printer = printer or Printer(color=color, animate=animate)
        self.read = read or input
        self.preferences = dict(_DEFAULTS)
        self.latest = None
        self._saved_report = None
        self._saved_graph_report = None
        self.restart_requested = False
        self._return_home = False

    def back_prompt(self, question, *, zero=False):
        """Give menu/form input an explicit Escape action without submitting it."""
        ui = self.printer.terminal_ui
        if ui:
            ui.update(back_enabled=True, zero_back=zero)
        try:
            return self.read(question)
        finally:
            if ui:
                ui.update(back_enabled=False, zero_back=False)

    def clear_menu(self):
        if self.printer.terminal_ui and self.printer.console:
            self.printer.console.clear()

    def active_settings(self):
        p = self.preferences
        return (f"Returned fields: all · Comparisons: {'expanded' if p['details'] else 'summary'} · "
                f"Results: {'all outcomes' if p['all'] else 'matches'} · "
                f"Username: {'quick' if p['fast'] else 'full'} · "
                f"Breaches: {'excluded' if p['no_breach'] else 'eligible checks only'} · "
                f"Timeout: {str(p['timeout']) + 's' if p['timeout'] is not None else 'configured default'}")

    def menu(self):
        self.printer.actions(has_results=self.latest is not None)
        if self.latest is not None:
            self.printer.message(f"Latest search: {len(self.latest.queries)} queries · {len(self.latest.findings)} results. "
                                 "Use last to view or save to export.", "dim")
        self.printer.message("Or type a username, email or phone — we detect its type. / shows commands; /config opens settings.", "dim")

    def remember(self, summary):
        # Retain only the latest scan; never add findings from earlier people.
        self.latest = summary
        if self.printer.terminal_ui:
            self.printer.terminal_ui.result_filters = {}
        try:
            from .search_history import SearchHistory

            SearchHistory().save(summary)
        except (OSError, ValueError, TypeError) as exc:
            self.printer.warn(f"Could not retain local history: {exc}. Results are still available in this session.")

    def execute(self, tokens, *, remember=False):
        from ..cli import main

        if self.printer.terminal_ui:
            if remember:
                self.printer.terminal_ui.remember_command(shlex.join(tokens))
            self.printer.terminal_ui.update("Preparing " + tokens[0])
        if not self.color and "--no-color" not in tokens and tokens[0] in {"scan", "user", "username", "email", "phone"}:
            tokens = [tokens[0], "--no-color", *tokens[1:]]
        if not self.animate and "--no-animation" not in tokens and tokens[0] in {"scan", "user", "username", "email", "phone"}:
            tokens = [tokens[0], "--no-animation", *tokens[1:]]
        code = main(tokens, scan_defaults=dict(self.preferences), on_summary=self.remember, in_session=True)
        if code:
            self.printer.message("Search stopped; collected results are retained." if code == 130
                                 else "Command did not complete successfully. You can correct it and try again.", "yellow")

    def query(self, command, value=None):
        if command == "phone":
            self.printer.message(PHONE_GUIDANCE, "dim")
        if value is None:
            label = "Username" if command == "user" else command.capitalize()
            value = _unquote(self.read(f"{label} to search (Enter to go back): "))
            if self._leaves_prompt(value, f"{command} {value}"):
                return
        if value:
            flags = []
            phone_value = re.sub(r"^tel:", "", value.lstrip(), flags=re.I).lstrip()
            if command == "phone" and not phone_value.startswith(("+", "00")):
                from ..cli import _phone_region

                region = self.read("Country for this local number (GB for UK, US for USA; Enter cancels): ").strip()
                if not region or region.lower() in _LEAVE_WORDS:
                    return
                flags = ["--phone-region", _phone_region(region)]
            self.printer.message(self.active_settings(), "dim")
            self.execute([command, *flags, "--", value], remember=True)

    def _leaves_prompt(self, value, instead):
        """At a prompt that says 'Enter to go back', words such as back or 0 mean leave, not 'search for this'."""
        if value.strip().lower() not in _LEAVE_WORDS:
            return False
        self.printer.message(f"Went back without searching. To search for that word itself, type: {instead}", "dim")
        return True

    def bulk(self, arguments):
        if len(arguments) > 1:
            raise ValueError('Use bulk "path to queries.txt"; use scan -i FILE for additional options.')
        self.printer.message("Do these identifiers belong to the same person or different people?")
        self.printer.message("1 Same person: compare shared details and sites across the queries.\n"
                             "2 Different people: keep each person's results separate (default).", "dim")
        while True:
            answer = self.read("Same person or different people [1/2, default 2]: ").strip().lower()
            if answer in ("", "2", "different", "different people", "n", "no", "1", "same", "same person", "y", "yes"):
                break
            if answer in _LEAVE_WORDS:
                self.printer.message("Bulk search cancelled.")       # the prompt used to accept nothing but 1 or 2
                return
            self.printer.message("Enter 1 for the same person, 2 for different people, or 0 to go back.")
        flags = ["--compare-queries"] if answer in ("1", "same", "same person", "y", "yes") else []
        self.printer.message("Enter usernames, emails or international phone numbers. Paste several separated by commas\n"
                             "or new lines, or add them one at a time. To use a file, enter file followed by its path.\n"
                             "Start an identifier with username:, email: or phone: to state its type, e.g. username:12345678.\n"
                             "An empty line starts the search; Ctrl+C cancels.", "dim")
        value = arguments[0] if arguments else self.read("Identifiers or file path (Enter to go back): ").strip()
        if not value or (not arguments and self._leaves_prompt(value, f"user {value}")):
            return
        prefixed_file = not arguments and value.lower().startswith("file ")
        explicit_file = bool(arguments) or prefixed_file
        path = _unquote(value[5:] if prefixed_file else value)
        try:
            is_file = "\n" not in path and Path(path).expanduser().is_file()
        except OSError:
            is_file = False
        if explicit_file or is_file:
            if not is_file:
                raise ValueError("Query file does not exist. Enter file followed by the full path, or paste identifiers directly.")
            tokens = ["scan", "-i", path, *flags]
        else:
            if ("\\" in path or "/" in path) and QueryType.detect(path) is not QueryType.EMAIL:
                raise ValueError("Query file does not exist. Paste identifiers directly, or check the full file path.")
            values = []
            while value:
                values.extend(_unquote(part) for line in value.splitlines() for part in line.split(",") if part.strip())
                self.printer.message(f"{len(values)} identifier{'s' if len(values) != 1 else ''} entered.", "dim")
                value = self.read("Add identifiers (Enter starts search; 0 cancels): ").strip()
                if value.lower() in _LEAVE_WORDS:
                    self.printer.message("Bulk search cancelled; nothing was searched.")
                    return
            tokens = ["scan", *flags, "--", *values]
        self.printer.message(self.active_settings(), "dim")
        self.execute(tokens, remember=True)

    def show_latest(self):
        if self.latest is None:
            self.printer.message("No search results yet. Choose Username, Email, Phone or Bulk search.")
            return
        Printer(color=self.color, details=self.preferences["details"], show_all=self.preferences["all"],
                summary_limit=0).finish(self.latest, review=True)

    def save_latest(self, arguments):
        if self.latest is None:
            self.printer.message("No search results to save yet.")
            return
        if len(arguments) > 1:
            raise ValueError('Use save "path to report.html": one file name, in quotes if it contains spaces. '
                             "Every outcome is always saved here, so options such as -a are not needed.")
        from .session_info import SessionInfo

        info = self.printer.terminal_ui.info if self.printer.terminal_ui else SessionInfo.current()
        default = str(info.report_folder / ("consensus-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".html"))
        if not arguments:
            self.printer.message("Enter saves two files: an HTML report and an interactive evidence graph. Both links appear below the menu.\n"
                                 "Or choose .graph.html, .json, .csv, .md, .txt or .pdf for a single export. Ctrl+C cancels.")
            self.printer.message("Suggested file: " + default)
        path = arguments[0] if arguments else _unquote(self.read("Save here? Press Enter, or type a different path: ")) or default
        from .reports import infer_format, save_report

        if Path(path).expanduser().is_dir():
            raise ValueError(f"{path} is a folder: add a file name, for example {Path(path) / 'report.html'}")
        if self.printer.terminal_ui:
            self.printer.terminal_ui.update("Saving report")
        saved = save_report(self.latest, Path(path).expanduser(), include_all=True)
        graph = None
        if infer_format(saved) == "html":
            try:
                graph = save_report(self.latest, saved.with_name(saved.stem + ".graph.html"), include_all=True)
            except (OSError, ValueError) as exc:
                self.printer.report_saved(saved)
                raise ValueError(f"HTML report saved, but the interactive graph could not be saved: {exc}") from exc
        if self.printer.terminal_ui:
            self._saved_report = saved
            self._saved_graph_report = graph
        else:
            self.printer.report_saved(saved, graph_path=graph)

    def change_setting(self, name, value):
        from ..cli import _positive_float

        if name in {"animation", "animations"}:
            if value.lower() not in {"on", "true", "yes", "off", "false", "no"}:
                raise ValueError("Use on or off for animation.")
            self.animate = value.lower() in {"on", "true", "yes"}
            if self.printer.terminal_ui:
                ui = self.printer.terminal_ui
                ui.update(animate=self.animate)
            return
        if name not in _DEFAULTS:
            raise ValueError("Settings: details, all, fast, no_breach, timeout, animation.")
        if name == "timeout":
            self.preferences[name] = None if value.lower() in ("default", "reset") else _positive_float(value)
        elif value.lower() in ("on", "true", "yes", "off", "false", "no"):
            self.preferences[name] = value.lower() in ("on", "true", "yes")
        else:
            raise ValueError("Use on or off for this setting.")
        self.printer.message("Setting changed for this session. " + self.active_settings(), "dim")

    def settings(self):
        self.clear_menu()
        while True:
            self.printer.summary_table([["Choose", "Setting", "Current"]] + [
                [str(i), label, "configured default" if self.preferences[name] is None
                 else str(self.preferences[name]) if name == "timeout"
                 else "on" if self.preferences[name] else "off"]
                for i, (name, label) in enumerate(_SETTINGS, 1)
            ] + [[str(len(_SETTINGS) + 1), "Loading, footer and tab animations", "on" if self.animate else "off"],
                 ["u", "Installation & updates", "Open"],
                 ["h", "Recent searches", "Open"],
                 ["0", "Back", ""], ["reset", "Reset session and forget latest results", ""]],
                "Settings · search preferences apply to this session")
            choice = self.back_prompt("Setting to change [0 / Esc = back]: ", zero=True).strip().lower()
            if not choice or choice in _LEAVE_WORDS:
                return
            if choice == "reset":
                self.reset()
                return
            if choice == "u":
                from .installation_ui import screen

                screen(self)
                if self.restart_requested:
                    return
                self.clear_menu()
                continue
            if choice == "h":
                from .search_history import screen

                if screen(self):
                    return
                self.clear_menu()
                continue
            if choice == str(len(_SETTINGS) + 1):
                self.change_setting("animation", "off" if self.animate else "on")
                continue
            if not choice.isdigit() or not 1 <= int(choice) <= len(_SETTINGS):
                self.printer.message("Choose a setting number or 0 to go back.", "yellow")
                continue
            name = _SETTINGS[int(choice) - 1][0]
            if name == "timeout":
                value = self.back_prompt("Seconds per site, or default (Esc cancels): ").strip()
                if value and value.lower() not in _LEAVE_WORDS:
                    self.change_setting(name, value)
            else:
                self.preferences[name] = not self.preferences[name]

    def reset(self):
        self.preferences = dict(_DEFAULTS)
        self.change_setting("animation", "on" if self.initial_animation else "off")
        self.latest = None
        if self.printer.terminal_ui:
            self.printer.terminal_ui.clear_history()
        self.printer.message("Session settings reset and latest results forgotten. Saved report files remain available.")

    def help(self):
        if self.printer.terminal_ui:
            self.printer.message("Type / for the command menu. Use Up/Down and Enter to choose; Esc dismisses suggestions.")
        else:
            self.printer.message("Type / and press Enter to list commands. Type a command or its numbered choice to run it. "
                                 "Live suggestions require the managed terminal interface.")
        self.printer.message("/config opens settings; /config animation off disables loading and tab animations.")
        self.printer.message("Paste an email address, phone number or username directly to detect the search type. "
                             "Local phone numbers ask for a country; use user VALUE to force a numeric username.")
        self.printer.message("Choose 1–4 for guided searches, or type commands such as:", f"bold {ACCENT}")
        self.printer.message('  email "YOUR_EMAIL" --details\n  user "YOUR_USERNAME" --fast\n'
                             '  phone "+COUNTRY_CODE_NUMBER"\n  scan -i "queries.txt" --compare-queries\n'
                             '  report "scan.json" -o "report.html"\n  set details on\n  set timeout 20')
        self.printer.message("last = review latest results · save [PATH] = export · settings = preferences · "
                             "reset = reset session · info = paths and version · about = project details · menu = home · exit = close")
        self.printer.message("Use email --help for scan options. Quote paths containing spaces; backslashes stay literal.", "dim")
        if self.printer.terminal_ui:
            self.printer.message("At the main prompt, Up/Down recalls commands from this session, including guided searches. "
                                 "Edit a recalled command and press Enter to run it. History clears on reset or exit.", "dim")
        else:
            self.printer.message("In this plain input mode, arrow-key history depends on your terminal. "
                                 "Consensus cannot clear history retained by the terminal itself.", "dim")
        preview_available = self.printer.terminal_ui or (self.printer.console and self.printer.console.is_interactive)
        self.printer.message(("V shows/hides a compact hit preview. " if preview_available else "") +
                             "P pauses new site checks, R continues, S stops a running scan. Ctrl+C cancels a search "
                             "or an input form; at the main prompt it exits. Checks already running may finish.\n"
                             "Only Settings/set persists options. Extra command flags apply to that command. "
                             "Queries, report paths and cross-query comparison are never carried into the next search.", "dim")

    def dispatch(self, tokens):
        command, *arguments = tokens
        if command == "/":
            if arguments:
                raise ValueError("Type / alone to show commands, or /config to open settings.")
            from .slash_commands import COMMANDS

            self.printer.summary_table([["Command", "What it does"], *COMMANDS], "Commands")
            return True
        if command.startswith("/") and QueryType.detect(command) is not QueryType.EMAIL:
            from .slash_commands import COMMANDS

            if command.lower() not in {row[0] for row in COMMANDS} | {"/settings", "/set"}:
                raise ValueError("Unknown slash command. Type / to see available commands.")
            command = command[1:]
        if command.lower() == "config":
            command = "set" if arguments else "settings"
        aliases = {key: value for key, _, value in CHOICES}
        # The menu's own words open that item; searching for them as a username
        # would start thousands of lookups nobody asked for (use: user results).
        aliases.update(results="last", view="last", latest="last", export="save")
        command = aliases.get(command.lower(), command.lower())
        if command in {"menu", "help", "?", "info", "about", "examples", "settings", "last", "reset", "exit", "quit", "q"} and arguments:
            raise ValueError(f"{command} does not take extra arguments.")
        if command in {"exit", "quit", "q"}:
            return False
        if command in {"menu", "help", "?"}:
            if command == "menu":
                self.printer.home(__version__, has_results=self.latest is not None)
            else:
                self.help()
        elif command == "about":
            self.printer.identity(__version__)
        elif command == "info":
            self.printer.session_information()
            if self.printer.terminal_ui and self.printer.terminal_ui.last_report:
                self.printer.report_saved(self.printer.terminal_ui.last_report,
                                          graph_path=self.printer.terminal_ui.last_graph_report)
        elif command == "examples":
            self.printer.examples()
            self.printer.message("Inside this session, leave off the initial consensus in those examples.", "dim")
        elif command == "settings":
            try:
                self.settings()
            finally:
                self._return_home = True
        elif command == "updates":
            from .installation_ui import screen

            try:
                screen(self)
            finally:
                self._return_home = True
        elif command == "history":
            from .search_history import screen

            try:
                screen(self)
            finally:
                self._return_home = True
        elif command == "set":
            if len(arguments) != 2:
                raise ValueError("Use set SETTING VALUE, for example: set details on.")
            self.change_setting(*arguments)
        elif command == "reset":
            self.reset()
        elif command == "last":
            self.show_latest()
        elif command == "save":
            self.save_latest(arguments)
        elif command == "bulk":
            self.bulk(arguments)
        elif command == "terminal":
            from .terminal_profile import command as terminal_command

            terminal_command(arguments, self.printer)
        elif command in {"user", "username", "email", "phone"} and not arguments:
            self.query("user" if command == "username" else command)
        elif command in _COMMANDS:
            if command in {"scan", "user", "username", "email", "phone"}:
                self.printer.message(self.active_settings(), "dim")
            self.execute([command, *arguments])
        else:
            value, stated = QueryType.split_typed(" ".join(tokens))
            if stated and not value:
                raise ValueError(f"Type the {stated} after the colon, for example {stated}:EXAMPLE.")
            kind = QueryType(stated) if stated else QueryType.detect(value)
            if not stated and len(tokens) == 1 and value.lower() in _TERMINAL_ONLY:
                raise ValueError(f"{value} is a terminal command, not a session one: leave the session and run "
                                 f"consensus {value.lower()}. To search for the word itself, type: user {value}")
            if not stated and len(tokens) == 1 and (value.lower() in _NOT_A_SEARCH or value.lower() in _cli_words()):
                raise ValueError(f"{value} is not a session command, and searching for it as a username would start "
                                 f"a full lookup. Type help for commands, or user {value} to search for that word.")
            if (value.startswith("-") or "://" in value or "\\" in value
                    or (len(tokens) > 1 and kind is not QueryType.PHONE)
                    or (kind is QueryType.USERNAME and any(char.isspace() for char in value))):
                raise ValueError("Unknown command or input. Paste one username, email or phone number, "
                                 "choose a menu number, or type help.")
            self.printer.message(f"Detected {kind.value} search: {value}", f"bold {ACCENT}")
            self.query("user" if kind is QueryType.USERNAME else kind.value, value=value)
        return True

    def results_actions(self):
        ui = self.printer.terminal_ui
        while ui is not None and ui.results_action:
            action, ui.results_action = ui.results_action, None
            try:
                if action == "save":
                    ui.returned_from_results = False
                    self.save_latest([])
                    return
                if action == "again":
                    from .reports import group_by_query

                    groups = [v for v in group_by_query(self.latest) if not v.parent]
                    if groups:
                        ui.prefill = shlex.join(["scan", "--", *[v.query_type + ":" + v.query for v in groups]])
                    return  # Prefill only. Enter is required to issue another search.
                if action == "filter":
                    self.printer.message("1 Site name · 2 Enriched only · 3 Possible matches · 4 Clear all · 0 Back")
                    choice = self.read("Filter results: ").strip()
                    if choice == "1":
                        value = self.read("Site name contains (Enter clears name filter): ").strip()
                        if value:
                            ui.result_filters["site"] = value
                        else:
                            ui.result_filters.pop("site", None)
                    elif choice in ("2", "3"):
                        ui.result_filters["kind"] = "enriched" if choice == "2" else "possible"
                    elif choice == "4":
                        ui.result_filters = {}
            except KeyboardInterrupt:
                self.printer.message("Cancelled. Returning to results.")
            except (OSError, ValueError) as exc:
                self.printer.warn(f"Could not complete the action: {exc}. Results are still available.")
            self.show_latest()

    def run(self):
        self.printer.home(__version__, has_results=self.latest is not None)
        last_update_notice = ""
        while True:
            try:
                if not self.printer.terminal_ui:
                    from .auto_update import notification

                    notice = notification()
                    if notice and notice != last_update_notice:
                        self.printer.message(notice, ACCENT)
                        last_update_notice = notice
                line = self.read("consensus> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue
            try:
                # A pasted identifier is literal input; apostrophes in an email
                # address must not be mistaken for unfinished command quoting.
                tokens = ([line] if not any(char.isspace() for char in line) and not line.startswith(("'", '"'))
                          else split_command(line))
                if tokens and tokens[0].lower() == "consensus":
                    tokens = tokens[1:]
                if tokens and not self.dispatch(tokens):
                    break
                if self.restart_requested:
                    break
                self.results_actions()
                ui = self.printer.terminal_ui
                if self._return_home or (ui is not None and ui.returned_from_results):
                    self._return_home = False
                    if ui is not None:
                        ui.returned_from_results = False
                        ui.update("Ready")
                    self.printer.home(__version__, has_results=self.latest is not None,
                                      saved_report=self._saved_report, graph_report=self._saved_graph_report,
                                      reset_screen=True)
                    self._saved_report = None
                    self._saved_graph_report = None
                    continue
                if self._saved_report is not None:
                    self.printer.home(__version__, has_results=self.latest is not None,
                                      saved_report=self._saved_report, graph_report=self._saved_graph_report)
                    self._saved_report = None
                    self._saved_graph_report = None
                    continue
                if tokens and tokens[0].lower() == "menu":
                    continue
            except EOFError:
                break
            except KeyboardInterrupt:
                self.printer.message("Cancelled. Back to the menu.", "yellow")
            except SystemExit as exc:  # argparse help/errors must not close the session
                if exc.code:
                    self.printer.message("Check the command and try again.", "yellow")
            except Exception as exc:
                message = redact_options({"error": str(exc)})["error"]
                if self._return_home:
                    self._return_home = False
                    self.printer.home(__version__, has_results=self.latest is not None, reset_screen=True)
                    self.printer.warn(f"Could not complete that action: {message}")
                    continue
                self.printer.warn(f"Could not complete that action: {message}")
            if self._return_home:
                self._return_home = False
                self.printer.home(__version__, has_results=self.latest is not None, reset_screen=True)
            else:
                self.menu()
        self.printer.message("\nConsensus closed. Saved reports remain available.")
        return 0


def prepare_screen():
    """Start the home screen at the top of an interactive terminal viewport."""
    if not terminal_available() or os.environ.get("TERM", "").lower() == "dumb":
        return
    from prompt_toolkit.output.defaults import create_output

    output = create_output(stdout=sys.stdout)
    output.erase_screen()
    output.cursor_goto(0, 0)
    output.flush()


def start_session(*, color=True, footer=True, animate=True):
    if not terminal_available():
        Printer(color=color, stream=sys.stderr).warn("Interactive mode needs a terminal. Use a direct command, such as consensus email ADDRESS.")
        return 2
    from .terminal_ui import TerminalUI, supported

    sessions = []
    if footer and supported(color=color):
        def start(read):
            import os

            from .config import get_config
            from .terminal_ui import current_ui

            current_ui().refresh_network(os.environ.get("CONSENSUS_PROXY") or get_config().get("defaults", {}).get("proxy"))
            session = Session(color=color, animate=animate, read=read)
            sessions.append(session)
            return session.run()

        result = TerminalUI(animate=animate, network=True).run(start)
    else:
        session = Session(color=color, animate=animate)
        sessions.append(session)
        result = session.run()
    if sessions and sessions[0].restart_requested:
        from .installation_ui import restart

        return restart()
    return result
