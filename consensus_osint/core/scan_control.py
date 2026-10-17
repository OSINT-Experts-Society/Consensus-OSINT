"""Per-scan cooperative pause and terminal keys; no process-global input thread."""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import os
import sys
import time
from collections import deque

from prompt_toolkit.input.vt100_parser import Vt100Parser


class _ScanKeys:
    """Distinguish a standalone Escape from arrow/function escape sequences."""
    def __init__(self):
        self.pending = deque()
        self.deadline = 0
        self.parser = Vt100Parser(lambda key: self.pending.append(key.data) if len(key.data) == 1 else None)

    def read(self, data):
        if data:
            self.parser.feed(data)
            self.deadline = time.monotonic() + .05
        elif time.monotonic() >= self.deadline:
            self.parser.flush()
        return self.pending.popleft() if self.pending else ""

_active = contextvars.ContextVar("consensus_scan_control", default=None)


def terminal_available() -> bool:
    try:
        return bool(sys.stdin.isatty() and sys.stdout.isatty())
    except (AttributeError, OSError, ValueError):
        return False


class ScanControl:
    def __init__(self):
        self.ready = asyncio.Event()
        self.ready.set()
        self.stopping = False

    @property
    def paused(self):
        return not self.ready.is_set()

    def pause(self):
        if not self.stopping:
            self.ready.clear()

    def resume(self):
        self.ready.set()

    def stop(self):
        self.stopping = True
        self.ready.set()


async def checkpoint():
    control = _active.get()
    if control is not None:
        await control.ready.wait()
        if control.stopping:
            raise asyncio.CancelledError


@contextlib.contextmanager
def _key_reader():
    """Nonblocking single-key input; POSIX terminal mode is always restored."""
    if os.name == "nt":
        import msvcrt

        def read():
            if not msvcrt.kbhit():
                return ""
            char = msvcrt.getwch()
            if char in ("\x00", "\xe0"):  # discard function/arrow key sequence
                if msvcrt.kbhit():
                    msvcrt.getwch()
                return ""
            return char
        yield read
        return
    import select
    import termios
    import tty

    descriptor = sys.stdin.fileno()
    before = termios.tcgetattr(descriptor)
    try:
        tty.setcbreak(descriptor)
        keys = _ScanKeys()

        def read():
            data = os.read(descriptor, 4096).decode("ascii", errors="ignore") if select.select([descriptor], [], [], 0)[0] else ""
            return keys.read(data)
        yield read
    finally:
        termios.tcsetattr(descriptor, termios.TCSADRAIN, before)


def handle_key(key, control, owner, printer):
    key = key.lower()
    if key == "v":
        printer.toggle_preview()
    elif key == "p" and not control.paused:
        control.pause()
        printer.scan_state("Paused", "New checks paused; checks already running may finish. R resumes, S stops.")
    elif key in ("r", "c") and control.paused:
        control.resume()
        printer.scan_state("Scanning", "Continuing scan. P pauses, S stops.")
    elif key in ("s", "\x03", "\x1b") and not control.stopping:
        control.stop()
        printer.scan_state("Stopping", "Stopping; keeping collected results while active checks clean up.")
        owner.cancel()


@contextlib.asynccontextmanager
async def scan_controls(printer):
    control = ScanControl()
    token = _active.set(control)
    listener = None
    try:
        from .terminal_ui import current_ui

        ui = current_ui()
        if ui is not None:
            # The footer owns input; never start a competing terminal reader.
            ui.attach_scan(control, asyncio.current_task(), printer)
            try:
                yield control
            finally:
                ui.detach_scan()
            return
        if terminal_available() and not printer.quiet and not printer.jsonl:
            stack = contextlib.ExitStack()
            try:
                read = stack.enter_context(_key_reader())
            except (OSError, ValueError, ImportError, AttributeError):
                stack.close()
                read = None
            with stack:
                if read is not None:
                    owner = asyncio.current_task()
                    preview = "V show/hide hit preview · " if printer.console and printer.console.is_interactive else ""
                    printer.message("Keys during scan: " + preview + "P pause · R continue · S / Esc stop · Ctrl+C stop.", "dim")

                    async def listen():
                        while not control.stopping:
                            try:
                                key = read()
                            except (OSError, ValueError):
                                control.resume()
                                printer.scan_state("Scanning", "Terminal keys unavailable; continuing. Ctrl+C stops the scan.")
                                return
                            if key:
                                handle_key(key, control, owner, printer)
                            await asyncio.sleep(.1)

                    listener = asyncio.create_task(listen())
                try:
                    yield control
                finally:
                    if listener is not None:
                        listener.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await listener
        else:
            yield control
    finally:
        _active.reset(token)
