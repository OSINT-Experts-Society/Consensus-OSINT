"""Native tab/taskbar activity for terminals known to support OSC 9;4.

The terminal draws the animation; no timer, title changes or user data are sent.
Unknown terminals and redirected output receive no escape sequences.
"""
from __future__ import annotations

import os


class TerminalProgress:
    def __init__(self, stream, *, enabled=True):
        self.stream = stream
        self.state = 0
        env = os.environ
        term = env.get("TERM", "").lower()
        compatible = bool(env.get("WT_SESSION") or env.get("ConEmuANSI") == "ON"
                          or env.get("TERM_PROGRAM", "").lower() == "vscode")
        try:
            tty = bool(stream.isatty())
        except (AttributeError, OSError, ValueError):
            tty = False
        self.enabled = bool(enabled and tty and compatible and "NO_COLOR" not in env
                            and term != "dumb" and not term.startswith(("screen", "tmux"))
                            and not env.get("TMUX") and not env.get("STY"))

    def _set(self, state):
        if not self.enabled or state == self.state:
            return
        try:
            self.stream.write(f"\x1b]9;4;{state};0\x07")
            self.stream.flush()
        except (AttributeError, OSError, ValueError):
            # Cosmetic output must never turn a completed scan into a failure.
            self.enabled = False
            return
        self.state = state

    def start(self):
        self._set(3)  # Indeterminate: all phases of a scan, with no false percentage.

    def pause(self):
        if self.state:
            self._set(4)

    def resume(self):
        if self.state:
            self._set(3)

    def clear(self):
        self._set(0)
