"""Scrollable results with bounded links and in-console evidence navigation."""
from __future__ import annotations

import re

from prompt_toolkit.application import Application
from prompt_toolkit.data_structures import Point
from prompt_toolkit.formatted_text import ANSI, to_formatted_text
from prompt_toolkit.formatted_text.utils import split_lines
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.mouse_events import MouseEventType
from prompt_toolkit.styles import Style


class ResultsView:
    def __init__(self, render, *, input=None, output=None, context=None, detail=None, follow_end=False):
        self.render = render
        self.context = context
        self.detail = detail
        self.follow_end = follow_end
        self.history = []
        self.links = []
        self.selected = None
        self.line = 0
        self.width = None
        self.lines = [[]]
        self.fragments = []
        keys = KeyBindings()
        view = self

        class ResultsControl(FormattedTextControl):
            def mouse_handler(self, event):
                if event.event_type in (MouseEventType.SCROLL_UP, MouseEventType.SCROLL_DOWN):
                    move(-3 if event.event_type == MouseEventType.SCROLL_UP else 3)
                    view.app.invalidate()
                    return None
                return super().mouse_handler(event)

        self.window = Window(ResultsControl(self.content, focusable=True, show_cursor=False,
                                                 get_cursor_position=lambda: Point(0, self.line)),
                             wrap_lines=False, always_hide_cursor=True, get_vertical_scroll=lambda window: self.line)

        def move(delta):
            self.selected = None
            self.line = max(0, min(self.last_page(), self.line + delta))

        for key, delta in (("up", -1), ("down", 1), ("k", -1), ("j", 1)):
            keys.add(key)(lambda event, delta=delta: move(delta))
        for key, direction in (("pageup", -1), ("pagedown", 1), (" ", 1)):
            keys.add(key)(lambda event, direction=direction: move(direction * max(1, self.app.output.get_size().rows - len(self.footer().splitlines()) - 1)))

        @keys.add("home")
        def top(event):
            self.selected = None
            self.line = 0

        @keys.add("end")
        def bottom(event):
            self.selected = None
            self.line = self.last_page()

        for key, delta in (("tab", 1), ("s-tab", -1)):
            keys.add(key)(lambda event, delta=delta: self.select_link(delta))

        @keys.add("enter")
        def enter(event):
            if self.selected is not None:
                self.activate(self.links[self.selected][0])
            else:
                self.back()

        for key in ("escape", "q", "c-c", "c-d"):
            keys.add(key)(lambda event: self.back())
        self.app = Application(layout=Layout(HSplit([
            self.window, Window(FormattedTextControl(self.footer), height=lambda: len(self.footer().splitlines()), style="class:footer")
        ])), key_bindings=keys, full_screen=True, mouse_support=True, input=input, output=output,
            style=Style.from_dict({"footer": "bg:#252525 #ff6a00", "selected-link": "reverse"}))

    def last_page(self):
        visible = max(1, self.app.output.get_size().rows - len(self.footer().splitlines()))
        return max(0, len(self.lines) - visible)

    def select_link(self, delta):
        if not self.links:
            return
        self.selected = ((self.selected + delta) % len(self.links) if self.selected is not None else
                         0 if delta > 0 else len(self.links) - 1)
        self.line = min(self.links[self.selected][1], self.last_page())

    def activate(self, url):
        if url.startswith("consensus-detail:") and self.detail:
            key = url.partition(":")[2]
            self.history.append((self.render, self.line, self.selected))
            self.render = lambda width: self.detail(key, width)
            self.width, self.line, self.selected = None, 0, None
        else:
            from .reports import _safe_http_url

            safe = _safe_http_url(url)
            if safe:
                import webbrowser

                webbrowser.open(safe)
        self.app.invalidate()

    def back(self):
        if self.history:
            self.render, self.line, self.selected = self.history.pop()
            self.width = None
            self.app.invalidate()
        else:
            self.app.exit()

    def _linked_fragments(self, rendered):
        # Never forward OSC-8 to the physical terminal. A viewport may clip its
        # closing marker, leaving all subsequent output inside the last link.
        osc = r"\x1b\]8;[^\x1b\x07]*(?:\x1b\\|\x07)"
        rendered = re.sub(osc, lambda match: "\x01" + match[0] + "\x02", rendered)
        active, line = "", 0
        self.links = []
        fragments = []
        handlers = {}
        for style, text, *_ in to_formatted_text(ANSI(rendered)):
            if "[ZeroWidthEscape]" in style:
                match = re.fullmatch(r"\x1b\]8;[^;]*;(.*?)(?:\x1b\\|\x07)", text)
                active = match[1] if match else ""
                continue
            if active:
                url = active
                if url not in handlers:
                    self.links.append((url, line))

                    def click(event, url=url):
                        if event.event_type == MouseEventType.MOUSE_UP:
                            self.activate(url)
                            return None
                        return NotImplemented

                    handlers[url] = (click, len(self.links) - 1)
                handler, index = handlers[url]
                fragments.append((style + f" underline class:result-link-{index}", text, handler))
            else:
                fragments.append((style, text))
            line += text.count("\n")
        return fragments

    def content(self):
        width = max(10, self.app.output.get_size().columns - 1)
        if width != self.width:
            self.width = width
            self.fragments = self._linked_fragments(self.render(width))
            self.lines = list(split_lines(self.fragments))
            if self.selected is not None and self.selected < len(self.links):
                self.line = min(self.links[self.selected][1], self.last_page())
        if self.follow_end:
            self.line = self.last_page()
            self.follow_end = False
        self.line = min(self.line, self.last_page())
        if self.selected is None or self.selected >= len(self.links):
            self.selected = None
            return self.fragments
        # Mouse handlers belong only to explicit link text, never its neighbours.
        selected_style = f"class:result-link-{self.selected}"
        return [(style + (" class:selected-link" if selected_style in style.split() else ""), text, *rest)
                for style, text, *rest in self.fragments]

    def footer(self):
        import textwrap

        width = self.app.output.get_size().columns
        destination = "table" if self.history else "menu"
        controls = (f" ↑↓ / PgUp/PgDn · Home/End · Tab selects link · Enter opens · Esc: {destination}" if width >= 90 else
                    f" ↑↓ / PgUp/PgDn · Home/End\n Tab: link · Enter: open/back · Esc: {destination}")
        text = f" Results · line {self.line + 1} of {len(self.lines)}\n" + controls
        text += "\n" + self.context(width) if self.context else ""
        return "\n".join(wrapped for line in text.splitlines()
                         for wrapped in (textwrap.wrap(line, width=max(1, width - 1)) or [""]))

    async def run(self):
        try:
            await self.app.run_async()
        except EOFError:
            pass
