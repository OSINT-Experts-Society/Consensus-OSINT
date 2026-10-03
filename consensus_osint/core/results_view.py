"""A read-only results viewport that starts at the first line on every visit."""
from __future__ import annotations

import re

from prompt_toolkit.application import Application
from prompt_toolkit.data_structures import Point
from prompt_toolkit.formatted_text import ANSI, to_formatted_text
from prompt_toolkit.formatted_text.utils import split_lines
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.styles import Style


class ResultsView:
    def __init__(self, render, *, input=None, output=None, context=None):
        self.render = render
        self.context = context
        self.line = 0
        self.width = None
        self.lines = [[]]
        self.fragments = []
        keys = KeyBindings()
        self.window = Window(FormattedTextControl(self.content, focusable=True, show_cursor=False,
                                                 get_cursor_position=lambda: Point(0, self.line)),
                             wrap_lines=False, always_hide_cursor=True, get_vertical_scroll=lambda window: self.line)

        def move(delta):
            self.line = max(0, min(len(self.lines) - 1, self.line + delta))

        for key, delta in (("up", -1), ("down", 1), ("k", -1), ("j", 1)):
            keys.add(key)(lambda event, delta=delta: move(delta))
        for key, direction in (("pageup", -1), ("pagedown", 1), (" ", 1)):
            keys.add(key)(lambda event, direction=direction: move(direction * max(1, self.app.output.get_size().rows - len(self.footer().splitlines()) - 1)))

        @keys.add("home")
        def top(event):
            self.line = 0

        @keys.add("end")
        def bottom(event):
            self.line = len(self.lines) - 1

        for key in ("enter", "escape", "q", "c-c", "c-d"):
            keys.add(key)(lambda event: event.app.exit())
        self.app = Application(layout=Layout(HSplit([
            self.window, Window(FormattedTextControl(self.footer), height=lambda: len(self.footer().splitlines()), style="class:footer")
        ])), key_bindings=keys, full_screen=True, input=input, output=output,
            style=Style.from_dict({"footer": "bg:#252525 #ff6a00"}))

    def content(self):
        width = max(10, self.app.output.get_size().columns - 1)
        if width != self.width:
            self.width = width
            # Rich's trusted OSC-8 links are zero-width escapes, not visible
            # content. ANSI handles SGR colours; it needs these spans marked.
            rendered = re.sub(r"(\x1b\]8;[^\x1b\x07]*(?:\x1b\\|\x07))",
                              lambda match: "\x01" + match[0] + "\x02", self.render(width))
            self.fragments = to_formatted_text(ANSI(rendered))
            self.lines = list(split_lines(self.fragments))
            self.line = min(self.line, len(self.lines) - 1)
        return self.fragments

    def footer(self):
        width = self.app.output.get_size().columns
        controls = (" ↑↓ scroll · PgUp/PgDn page · Home/End · Enter returns to menu" if width >= 65 else
                    " ↑↓ scroll · PgUp/PgDn page\n Home/End · Enter: menu")
        text = f" Results · line {self.line + 1} of {len(self.lines)}\n" + controls
        return text + ("\n" + self.context(width) if self.context else "")

    async def run(self):
        try:
            await self.app.run_async()
        except EOFError:
            pass
