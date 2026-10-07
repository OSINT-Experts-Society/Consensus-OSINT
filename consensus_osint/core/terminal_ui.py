"""Keep a footer pinned while normal Rich output remains in terminal scrollback.

prompt_toolkit owns terminal input and redraws. Existing synchronous command/session
code runs in one worker; scan controls are dispatched onto that scan's asyncio loop.
"""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import os
import queue
import random
import re
import threading
import time

from .session_info import SessionInfo

_current = contextvars.ContextVar("consensus_terminal_ui", default=None)
_controls = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SCAN_TIPS = (
    "A shared username is a lead, not proof that accounts share an owner.",
    "Compare names, biographies and linked websites before joining identities.",
    "Blocked or timed-out lookups are inconclusive, not proof of no account.",
    "Check when a profile was last active; old information can mislead.",
    "A signup or availability signal may not mean a public profile exists.",
    "Open enriched fields to see what a site actually returned.",
    "Save JSON to keep results for later reports without another search.",
    "Project coverage shows where a lookup is listed, not extra confirmations.",
    "Use known test accounts to check a tool's positive and negative results.",
    "Keep unrelated people separate when comparing bulk-search results.",
    "A profile's linked website can provide context for checking a match.",
    "Keep source links and collection dates with notes you plan to share.",
)


def current_ui():
    return _current.get()


def supported(*, color=True):
    from .scan_control import terminal_available

    if not color or "NO_COLOR" in os.environ or not terminal_available() or os.environ.get("TERM", "").lower() == "dumb":
        return False
    try:
        import prompt_toolkit  # noqa: F401
    except ImportError:
        return False
    return True


def clean(value):
    return _controls.sub(" ", str(value))


def input_rows(width, height):
    """Reserve a framed input line where the viewport has room for it."""
    return 3 if width >= 40 and height >= 18 else 1


@contextlib.contextmanager
def _output_proxy():
    """Preserve the active UI context when the output-flush thread schedules redraws.

    A fresh OS thread otherwise sees the default AppSession and writes through a
    dummy app, overwriting the footer. This also isolates repeated UI sessions.
    """
    import sys

    from prompt_toolkit.patch_stdout import StdoutProxy

    class ContextOutput(StdoutProxy):
        def __init__(self):
            self.context = contextvars.copy_context()
            super().__init__(raw=True)

        def _write_and_flush(self, loop, text):
            self.context.run(super()._write_and_flush, loop, text)

    original = sys.stdout, sys.stderr
    with ContextOutput() as proxy:
        try:
            sys.stdout = sys.stderr = proxy
            yield proxy
        finally:
            sys.stdout, sys.stderr = original


class TerminalUI:
    def __init__(self, *, info=None, input=None, output=None, animate=True, network=False):
        from prompt_toolkit.history import InMemoryHistory

        self.info = info or SessionInfo.current()
        self.input = input
        self.output = output
        self.activity = "Starting"
        self.question = ""
        self.reading = False
        self.back_enabled = False
        self.zero_back = False
        self.closing = False
        self.completed = 0
        self.total = 0
        self.found = 0
        self.enriched = 0
        self.last_report = None
        self.last_graph_report = None
        self.controller = None
        self.sources = ()
        self.animate = animate
        self.stop_requested = False
        self.session = None
        self.responses = queue.Queue()
        self.lock = threading.RLock()
        self.command_history = InMemoryHistory()
        self.loop = None
        self.preview = None
        self.last_hit = 0.0
        self.preparing = False
        from .network_status import NetworkStatus

        self.network = NetworkStatus(public_ip="not checked")
        self.network_enabled = network
        self.network_task = None
        self.network_route = None
        self.network_checked = 0.0
        self.results_view = None
        self.returned_from_results = False
        self.results_action = None
        self.result_filters = {}
        self.prefill = ""
        self.scan_tips = list(_SCAN_TIPS)
        self.tip_started = None
        self.phase_label = ""

    def refresh_network(self, proxy=None):
        if not self.network_enabled or self.loop is None:
            return
        from .network_status import NetworkStatus, check_network, system_proxy_configured

        system_proxy = not proxy and system_proxy_configured()
        route = (proxy, system_proxy)

        def start():
            if self.closing or (route == self.network_route and time.monotonic() - self.network_checked < 300):
                return
            self.network_route, self.network_checked = route, time.monotonic()
            if self.network_task:
                self.network_task.cancel()
            self.update(network=NetworkStatus(proxy_ip="checking…" if proxy or system_proxy else "not configured",
                                              proxy_status="checking" if proxy or system_proxy else "off"))

            async def check():
                result = await check_network(proxy, system_proxy=system_proxy)
                self.update(network=result)

            self.network_task = asyncio.create_task(check())

        self.loop.call_soon_threadsafe(start)

    def review(self, render, *, detail=None, follow_end=False):
        """Suspend input ownership cleanly while a full-screen viewer is active."""
        async def show():
            from prompt_toolkit.application import in_terminal
            from prompt_toolkit.input import DummyInput

            from .results_view import ResultsView

            class SuspendedInput(DummyInput):
                @property
                def closed(self):
                    return False

            self.update("Viewing results")
            async with in_terminal():
                app = self.session.app
                original_input = app.input
                # Detaching the prompt does not cancel its delayed flush/read
                # callbacks. Give those an idle input while the viewer owns
                # the terminal, otherwise they can consume the viewer's keys.
                app.input = SuspendedInput()
                try:
                    self.results_view = ResultsView(render, input=original_input, output=app.output,
                                                    context=self.footer_text, detail=detail, follow_end=follow_end, actions=True)
                    self.results_action = await self.results_view.run()
                    self.returned_from_results = True
                    # The alternate screen has gone. Reset its cursor geometry
                    # before the suspended prompt measures its available height.
                    app.output.erase_screen()
                    app.output.cursor_goto(0, 0)
                    app.output.flush()
                finally:
                    self.results_view = None
                    app.input = original_input

        asyncio.run_coroutine_threadsafe(show(), self.loop).result()

    def update(self, activity=None, **values):
        with self.lock:
            for key, value in values.items():
                setattr(self, key, value)
            if activity is not None:
                if isinstance(self.controller, tuple):
                    control = self.controller[1]
                    if control.stopping:
                        activity = "Stopping"
                    elif control.paused:
                        activity = "Paused"
                self.activity = clean(activity)
        if self.session is not None:
            self.session.app.invalidate()
        if self.results_view is not None:
            self.results_view.app.invalidate()

    def start_phase(self, total, label):
        label = re.sub(r"^(?:scanning|checking)\s+", "Searching: ", clean(label))
        self.update("Scanning", total=total, completed=0, phase_label=label)

    def begin_scan(self):
        random.shuffle(self.scan_tips)
        self.tip_started = time.monotonic()
        self.update("Preparing search", preparing=True, found=0, enriched=0, phase_label="",
                    completed=0, total=0, sources=(), preview=None, last_hit=0.0)

    def result(self, found, enriched, finding=None):
        with self.lock:
            if finding is not None and self.preview is not None and self.preview.add(finding):
                self.last_hit = time.monotonic()
        self.update(completed=self.completed + 1, found=found, enriched=enriched)

    def attach_scan(self, control, owner, printer):
        from .scan_preview import HitPreview

        if self.tip_started is None:
            random.shuffle(self.scan_tips)
            self.tip_started = time.monotonic()
        self.update("Preparing search" if self.preparing else "Scanning", preparing=False,
                    controller=(asyncio.get_running_loop(), control, owner, printer),
                    found=0, enriched=0, completed=0, total=0, sources=(), preview=HitPreview(), last_hit=0.0)
        if self.stop_requested:
            self.key("s")

    def detach_scan(self):
        self.tip_started = None
        self.update("Preparing results", controller=None, preparing=False, stop_requested=False,
                    preview=None, last_hit=0.0, phase_label="")

    def toggle_preview(self):
        with self.lock:
            if self.controller is not None and self.preview is not None:
                self.preview.toggle()
        self.update()

    def key(self, key):
        with self.lock:
            controller = self.controller
        if controller is not None:
            from .scan_control import handle_key

            loop, control, owner, printer = controller
            if not loop.is_closed():
                try:
                    loop.call_soon_threadsafe(handle_key, key, control, owner, printer)
                except RuntimeError:
                    if not loop.is_closed():
                        raise
        elif key in ("s", "\x03", "\x1b"):
            self.stop_requested = True

    def footer_text(self, width):
        from rich.cells import cell_len
        from rich.text import Text

        def fit(value, columns):
            text = Text(clean(value))
            text.truncate(max(1, columns), overflow="ellipsis")
            return text.plain

        def path_text(columns):
            if cell_len(path) <= columns:
                return path
            tail = ""
            for char in reversed(path):
                if cell_len(char + tail) > columns - 1:
                    break
                tail = char + tail
            return "…" + tail

        def row(left, middle, right):
            left, middle, right = fit(left, side), fit(middle, centre), fit(right, side)
            middle_space = centre - cell_len(middle)
            return (left + " " * (side - cell_len(left) + 2 + middle_space // 2)
                    + middle + " " * (middle_space - middle_space // 2 + 2 + side - cell_len(right))
                    + right)

        def gauge(columns):
            counter = f"{completed}/{total} sites"
            bar_width = min(24, columns - len(counter) - 3)
            prefix = []
            if bar_width < 2:
                prefix.append(fit(counter, columns))
                bar_width = max(1, columns - 2)
                counter = ""
            filled = min(bar_width, max(0, completed * bar_width // total))
            bar = "[" + "█" * filled + "░" * (bar_width - filled) + "]"
            return prefix + [bar + (" " + counter if counter else "")]

        with self.lock:
            status = self.activity
            moving = self.animate and self.activity not in ("Paused", "Stopping")
            frame = int(time.monotonic() * 3) if moving else 0
            mark = ("[▣]", "[◈]", "[▢]", "[◈]")[frame % 4] if self.controller or self.preparing else "[▣]"
            if self.controller and self.last_hit and time.monotonic() - self.last_hit < 1.8:
                mark = "[+]"
            status = mark + " Status: " + status
            scanning = self.controller is not None or self.preparing
            counts = f"Found {self.found} · Enriched {self.enriched}"
            completed, total = self.completed, self.total
            version = f"v{self.info.version}"
            path = str(self.info.working_folder)
            credit = ""
            if self.controller and self.sources:
                index = int(time.monotonic() / 2) if moving else 0
                credit = "Projects combined: " + self.sources[index % len(self.sources)]
        width = max(1, width - 2)
        side = max(26, (width - 4) // 3)
        if width >= 76 and (not scanning or cell_len(counts) <= side):
            centre = width - 2 * side - 4
            if scanning:
                progress = gauge(centre)[-1] if total else "Preparing site checks"
                credit_width = min(max(side, cell_len(credit)), width - len(version) - 12)
                path_width = width - credit_width - len(version) - 4
                credit_text = fit(credit, credit_width)
                location = path_text(path_width)
                lines = [row(status, progress, counts),
                         credit_text + " " * (credit_width - cell_len(credit_text) + 2)
                         + location + " " * (path_width - cell_len(location) + 2) + version]
            else:
                lines = [row(status, path_text(centre), version)]
        elif scanning:
            if cell_len(status + " · " + counts) <= width:
                lines = [status + " · " + counts]
            else:
                lines = [fit(status, width), fit(counts, width)]
            if total:
                lines.extend(gauge(width))
            if credit:
                lines.append(fit(credit, width))
            lines.append(fit(version + " │ " + path_text(max(1, width - len(version) - 3)), width))
        else:
            lines = [fit(status, width), fit(version + " │ " + path_text(max(1, width - len(version) - 3)), width)]
        network = self.network
        left = "Public IP: " + network.public_ip
        right = "Proxy: off" if network.proxy_status == "off" else "Proxy IP: " + network.proxy_ip + " · " + network.proxy_status
        if cell_len(left + "  " + right) <= width:
            lines.append(left + " " * (width - cell_len(left + right)) + right)
        else:
            lines.extend([fit(left, width), fit(right, width)])
        from .auto_update import notification

        notice = notification()
        if notice:
            # Wrap the restart instruction instead of truncating it on phones
            # or narrow terminal windows. Home budgeting includes these rows.
            import textwrap

            lines.extend(textwrap.wrap(notice, width=width))
        return "\n".join(" " + line for line in lines)

    def toolbar(self):
        width = self.session.app.output.get_size().columns if self.session else 80
        return [("class:footer", self.footer_text(width))]

    def input_framed(self):
        size = self.session.app.output.get_size() if self.session else None
        if self.session and not self.session.app.renderer.height_is_known:
            return False
        return self.reading and input_rows(size.columns if size else 80, size.rows if size else 24) == 3

    def placeholder(self):
        if not self.reading or self.question != "consensus> ":
            return []
        width = self.session.app.output.get_size().columns if self.session else 80
        hint = ("Username, email or phone · / commands" if width >= 48 else
                "Search or / commands" if width >= 28 else "Search")
        return [("class:placeholder", hint)]

    def input_height(self):
        """Keep the frame compact; allow a few lines for pasted identifiers."""
        from prompt_toolkit.formatted_text import fragment_list_to_text
        from prompt_toolkit.layout import Dimension
        from prompt_toolkit.utils import get_cwidth

        size = self.session.app.output.get_size()
        value = fragment_list_to_text(self.prompt()) + self.session.default_buffer.text
        width = max(1, size.columns - 2)
        rows = sum(max(1, (get_cwidth(line) + width - 1) // width) for line in value.split("\n"))
        completion = self.session.default_buffer.complete_state
        if completion is not None:
            rows += min(8, len(completion.completions))
        return Dimension(max=min(max(1, size.rows - 4), rows + 2))

    def prompt(self):
        prefix = []
        size = self.session.app.output.get_size() if self.session else None
        width, height = (size.columns, size.rows) if size else (80, 24)
        with self.lock:
            scan_preview = self.preview if self.controller is not None else None
            busy = self.controller is not None or self.preparing
            activity = self.activity
        if busy:
            from rich.text import Text

            moving = self.animate and activity not in ("Paused", "Stopping")
            mark = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[int(time.monotonic() * 8) % 10] if moving else "•"
            label = (self.phase_label or "Searching sites…") if activity == "Scanning" else activity
            if activity in ("Paused", "Stopping") and self.phase_label:
                label += " · " + self.phase_label
            body = Text(" " + mark + "  " + clean(label))
            body.truncate(max(1, width - 2), overflow="ellipsis")
            prefix.append(("class:loading", "\n" + body.plain + "\n"))
        if scan_preview is not None:
            footer_rows = len(self.footer_text(width).splitlines())
            limit = min(5, max(1, (height - footer_rows - 9) // 2))
            preview = scan_preview.text(max(1, width - 2), limit)
            if preview:
                prefix.append(("class:preview", preview + "\n"))
        if self.session and not self.session.app.renderer.height_is_known:
            # PromptSession hides its bottom toolbar until it knows the space
            # below the cursor. Some terminals never provide that information.
            # Keep progress visible beside the input instead of losing it.
            width = self.session.app.output.get_size().columns
            prefix += [("class:footer", self.footer_text(width - 2 if self.input_framed() else width) + "\n")]
        if self.reading:
            label = " › " if self.question == "consensus> " else " " + clean(self.question)
            return prefix + [("class:prompt", label)]
        if self.controller is not None:
            toggle = "V hide preview" if scan_preview is not None and scan_preview.visible else "V preview"
            state = "R resume" if activity == "Paused" else "P pause"
            hint = ("Stopping… Collected results will be kept." if activity == "Stopping" else
                    f"{toggle} · {state} · S / Esc stop")
            controls = [("class:hint", hint)]
            if height >= 20 and width >= 40 and self.tip_started is not None:
                import textwrap

                index = int(max(0, time.monotonic() - self.tip_started) // 15) % len(self.scan_tips)
                tip = textwrap.fill("OSINT tip: " + self.scan_tips[index], width=max(1, width - 2), max_lines=2, placeholder="...")
                controls.append(("class:hint", "\n\n" + tip))
            return prefix + controls
        return prefix + [("class:hint", "Please wait…")]

    def read(self, question):
        with self.lock:
            if self.closing:
                raise EOFError
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self._show_input(question)))
        response = self.responses.get()
        if isinstance(response, BaseException):
            raise response
        return response

    async def _show_input(self, question):
        from prompt_toolkit.history import DummyHistory

        with self.lock:
            if self.closing:
                self.responses.put(EOFError())
                return
            buffer = self.session.default_buffer
            buffer.history = self.command_history if question == "consensus> " else DummyHistory()
            buffer.reset()
            buffer.load_history_if_not_yet_loaded()
        try:
            if buffer._load_history_task is not None:
                await buffer._load_history_task
        except asyncio.CancelledError:
            self.responses.put(EOFError())
            return
        with self.lock:
            if self.closing:
                self.responses.put(EOFError())
                return
            self.update("Ready" if question == "consensus> " else "Awaiting input",
                        question=question, reading=True, stop_requested=False)
            if question == "consensus> " and self.prefill:
                from prompt_toolkit.document import Document

                buffer.document = Document(self.prefill, cursor_position=len(self.prefill))
                self.prefill = ""

    def remember_command(self, command):
        self.loop.call_soon_threadsafe(self._remember_command, command)

    def _remember_command(self, command):
        command = command.strip()
        history = self.command_history.get_strings()
        if command and not command.isdigit() and (not history or history[-1] != command):
            self.command_history.append_string(command)

    def clear_history(self):
        self.loop.call_soon_threadsafe(self._clear_history)

    def _clear_history(self):
        from prompt_toolkit.history import InMemoryHistory

        self.command_history = InMemoryHistory()
        if self.session:
            self.session.history = self.command_history
            self.session.default_buffer.history = self.command_history
            self.session.default_buffer.reset()

    def respond(self, value):
        with self.lock:
            if not self.reading:
                return
            self.update("Working", reading=False, question="")
            self.responses.put(value)

    def close_input(self):
        with self.lock:
            self.closing = True
            if self.reading:
                self.respond(EOFError())
            else:
                self.key("s")

    def run(self, action):
        return asyncio.run(self._run(action))

    async def _run(self, action):
        from prompt_toolkit import PromptSession
        from prompt_toolkit.application import run_in_terminal
        from prompt_toolkit.application.current import create_app_session
        from prompt_toolkit.filters import Condition
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.styles import Style

        keys = KeyBindings()
        self.loop = asyncio.get_running_loop()

        @keys.add("<any>", filter=Condition(lambda: not self.reading))
        def ignore(event):
            pass

        for arrow, direction in (("up", "history_backward"), ("down", "history_forward")):
            def recall(event, direction=direction):
                if not self.reading or self.question != "consensus> ":
                    return
                if event.current_buffer.complete_state is not None:
                    if direction == "history_backward":
                        event.current_buffer.complete_previous()
                    else:
                        event.current_buffer.complete_next()
                    return
                # History is loaded before showing the prompt, so Up followed
                # immediately by Enter still accepts the recalled command.
                getattr(event.current_buffer, direction)()
            keys.add(arrow, eager=True)(recall)

        @keys.add("enter", eager=True)
        def enter(event):
            if self.reading:
                event.current_buffer.complete_state = None
                value = event.current_buffer.text
                from .models import redact_options

                label = "› " if self.question == "consensus> " else self.question
                echo = redact_options({"error": label + value})["error"]
                print(clean(echo))
                if self.question == "consensus> ":
                    self._remember_command(value)
                event.current_buffer.reset()
                self.respond(value)

        @keys.add("c-c", eager=True)
        def interrupt(event):
            if self.reading:
                event.current_buffer.reset()
                self.respond(KeyboardInterrupt())
            else:
                self.key("s")

        @keys.add("c-d", eager=True)
        def eof(event):
            if self.reading and not event.current_buffer.text:
                self.respond(EOFError())

        @keys.add("escape", eager=True, filter=Condition(
            lambda: self.reading and self.back_enabled
            and self.session.default_buffer.complete_state is None))
        def back(event):
            event.current_buffer.reset()
            self.respond("")

        @keys.add("0", eager=True, filter=Condition(
            lambda: self.reading and self.back_enabled and self.zero_back
            and not self.session.default_buffer.text))
        def zero_back(event):
            event.current_buffer.reset()
            self.respond("0")

        @keys.add("escape", eager=True, filter=Condition(
            lambda: self.reading and self.session.default_buffer.complete_state is not None))
        def dismiss_completion(event):
            event.current_buffer.cancel_completion()

        @keys.add("escape", eager=True, filter=Condition(
            lambda: not self.reading and (self.controller is not None or self.preparing)))
        def stop_scan(event):
            self.key("\x1b")

        for key in ("p", "P", "r", "R", "c", "C", "s", "S", "v", "V"):
            def control(event, key=key):
                self.key(key.lower())
            keys.add(key, filter=Condition(lambda: not self.reading), eager=True)(control)

        from .slash_commands import completer

        def slash_enabled():
            return self.reading and self.question == "consensus> "
        self.session = PromptSession(
            message=self.prompt, bottom_toolbar=self.toolbar, key_bindings=keys,
            show_frame=Condition(self.input_framed), placeholder=self.placeholder,
            completer=completer(slash_enabled), complete_while_typing=Condition(slash_enabled),
            refresh_interval=.3, erase_when_done=True, history=self.command_history,
            reserve_space_for_menu=0, input=self.input, output=self.output,
            style=Style.from_dict({"bottom-toolbar": "noreverse bg:#252525 #ff6a00",
                                  "footer": "noreverse bg:#252525 #ff6a00", "prompt": "#ff6a00 bold",
                                  "preview": "#dddddd",
                                  "frame": "bg:#202020 #eeeeee",
                                  "frame.border": "#666666",
                                  "placeholder": "#888888 nobold",
                                  "loading": "#ff6a00",
                                  "hint": "#888888"}))
        self.session.default_buffer.read_only = Condition(lambda: not self.reading)
        # A burst of finished checks must not trigger a full terminal redraw per
        # result. Counters still update immediately; rendering stays responsive.
        self.session.app.min_redraw_interval = 1 / 15
        # PromptSession's built-in Frame otherwise fills every spare row above
        # the toolbar. Bound that frame, while keeping its native input/completions.
        self.session.layout.container.children[0].content.height = self.input_height
        worker = None
        token = _current.set(self)
        try:
            with create_app_session(input=self.session.app.input, output=self.session.app.output), _output_proxy() as proxy:

                async def work():
                    result, error = None, None
                    try:
                        result = await asyncio.to_thread(action, self.read)
                    except BaseException as exc:
                        error = exc
                    finally:
                        await asyncio.to_thread(proxy.close)
                        await run_in_terminal(lambda: None)
                    if not self.closing and self.session.app.is_running and not self.session.app.is_done:
                        if error is not None:
                            self.session.app.exit(exception=error)
                        else:
                            self.session.app.exit(result=result)
                    return result

                def start():
                    nonlocal worker
                    worker = asyncio.create_task(work())

                try:
                    return await self.session.prompt_async(pre_run=start, handle_sigint=False,
                                                           show_frame=Condition(self.input_framed))
                except EOFError:
                    return 0
                finally:
                    self.close_input()
                    if self.network_task:
                        self.network_task.cancel()
                        await asyncio.gather(self.network_task, return_exceptions=True)
                    if worker is not None:
                        await worker
        finally:
            self._clear_history()
            _current.reset(token)
