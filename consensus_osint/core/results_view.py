"""Scrollable results with bounded links and in-console evidence navigation."""
from __future__ import annotations

import re

from prompt_toolkit.application import Application
from prompt_toolkit.data_structures import Point
from prompt_toolkit.formatted_text import ANSI, to_formatted_text
from prompt_toolkit.formatted_text.utils import split_lines
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, ScrollOffsets, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl, UIContent, UIControl
from prompt_toolkit.mouse_events import MouseEvent, MouseEventType
from prompt_toolkit.styles import Style
from prompt_toolkit.utils import get_cwidth


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
        self.column = 0
        self.document_width = 0
        self.width = None
        self.lines = [[]]
        self.fragments = []
        self.scrollbar_height = 1
        self.scrollbar_drag = None
        self._footer_cache = None
        keys = KeyBindings()
        view = self

        class ResultsControl(UIControl):
            def is_focusable(self):
                return True

            def create_content(self, width, height):
                view.prepare(width)
                return UIContent(get_line=view.display_line, line_count=len(view.lines),
                                 cursor_position=Point(view.cursor_x(), view.line), show_cursor=False)

            def mouse_handler(self, event):
                if view.scrollbar_drag is not None and event.event_type == MouseEventType.MOUSE_MOVE:
                    # A held thumb keeps following when the pointer drifts
                    # left off the one-cell track into the results document.
                    return view.drag_at(event, event.position.y - view.window.vertical_scroll)
                if event.event_type in (MouseEventType.SCROLL_UP, MouseEventType.SCROLL_DOWN):
                    view.move(-3 if event.event_type == MouseEventType.SCROLL_UP else 3)
                    view.app.invalidate()
                    return None
                if event.event_type == MouseEventType.MOUSE_UP:
                    was_dragging = view.scrollbar_drag is not None
                    view.scrollbar_drag = None
                    if was_dragging:
                        return None  # Releasing a drag over a link must not open it.
                # Window maps this position to document rows, including scroll.
                if 0 <= event.position.y < len(view.lines):
                    x = 0
                    for fragment in view.lines[event.position.y]:
                        # Window already maps screen cells (including wide
                        # glyphs and horizontal scroll) to character indices.
                        x += len(fragment[1])
                        if event.position.x < x:
                            return fragment[2](event) if len(fragment) == 3 else NotImplemented
                return NotImplemented

        class BarControl(FormattedTextControl):
            def __init__(self, text, *, above=False):
                super().__init__(text)
                self.above = above

            def mouse_handler(self, event):
                if view.scrollbar_drag is not None:
                    if event.event_type == MouseEventType.MOUSE_MOVE:
                        return view.drag_at(event, 0 if self.above else view.scrollbar_height)
                    if event.event_type == MouseEventType.MOUSE_UP:
                        view.scrollbar_drag = None
                        return None
                return super().mouse_handler(event)

        class ScrollControl(UIControl):
            def create_content(self, width, height):
                view.scrollbar_height = height
                top, size, track = view.scrollbar_thumb()
                rows = [[("class:scrollbar.arrow", "▲")]]
                for row in range(track):
                    rows.append([("class:scrollbar.thumb", "█")] if top <= row < top + size else
                                [("class:scrollbar.track", "│")])
                if height >= 2:
                    rows.append([("class:scrollbar.arrow", "▼")])
                return UIContent(get_line=lambda index: rows[index], line_count=len(rows), show_cursor=False)

            def mouse_handler(self, event):
                return view.scrollbar_mouse(event)

        self.window = Window(ResultsControl(),
                             wrap_lines=False, always_hide_cursor=True, get_vertical_scroll=lambda window: self.line,
                             get_horizontal_scroll=lambda window: self.column, scroll_offsets=ScrollOffsets())
        self.scrollbar = Window(ScrollControl(), width=1, always_hide_cursor=True)

        for key, delta in (("up", -1), ("down", 1), ("k", -1), ("j", 1)):
            keys.add(key)(lambda event, delta=delta: self.move(delta))
        for key, delta in (("left", -12), ("right", 12)):
            keys.add(key)(lambda event, delta=delta: self.pan(delta))
        for key, direction in (("pageup", -1), ("pagedown", 1), (" ", 1)):
            keys.add(key)(lambda event, direction=direction: self.move(direction * max(1, self.visible_height() - 1)))

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

        # Escape only navigates back within results. Repeated Escape must not
        # dismiss the table; leaving it is a separate, labelled action.
        keys.add("escape")(lambda event: self.back(close=False))
        keys.add("b")(lambda event: self.back(close=False))
        for key in ("q", "c-c", "c-d"):
            keys.add(key)(lambda event: self.back())
        self.header = Window(BarControl(self.navigation, above=True), height=3, style="class:toolbar")
        self.footer_window = Window(BarControl(self.footer), height=2, style="class:footer")
        self.app = Application(layout=Layout(HSplit([
            self.header,
            VSplit([self.window, self.scrollbar]),
            self.footer_window
        ])), key_bindings=keys, full_screen=True, mouse_support=True, input=input, output=output,
            min_redraw_interval=1 / 60, max_render_postpone_time=0, before_render=lambda app: self._clear_footer(),
            style=Style.from_dict({"footer": "bg:#202226 #b9bdc5", "toolbar": "bg:#16181c #d8dbe2",
                                  "nav-button": "bg:#ff6a00 #101114 bold", "nav-border": "#ff6a00",
                                  "selected-link": "reverse",
                                  "scrollbar.arrow": "#ff6a00 bold", "scrollbar.thumb": "#ff6a00",
                                  "scrollbar.track": "#777777"}))

    def _clear_footer(self):
        self._footer_cache = None

    def navigation(self):
        def click(event):
            if event.event_type == MouseEventType.MOUSE_UP:
                self.back()
                return None
            return NotImplemented

        width = self.app.output.get_size().columns
        label = "  ← Back to results  Esc  " if self.history else "  ← Main menu  Q  "
        if width < len(label) + 2:
            label = " ← Results " if self.history else " ← Menu "
        title = "Result details" if self.history else "Search results"
        return [("class:nav-border", "╭" + "─" * len(label) + "╮\n", click),
                ("class:nav-border", "│", click), ("class:nav-button", label, click),
                ("class:nav-border", "│", click), ("bold", "   " + title if width >= len(label) + len(title) + 6 else ""),
                ("", "\n"), ("class:nav-border", "╰" + "─" * len(label) + "╯", click)]

    def pan(self, delta):
        self.column = max(0, min(max(0, self.document_width - (self.width or 1)), self.column + delta))

    def cursor_x(self):
        if not self.column:
            return 0
        # prompt-toolkit's cursor is a character index, but horizontal scroll
        # is measured in cells. Preserve wide-character hit testing.
        text = "".join(f[1] for f in self.lines[self.line])
        cells = 0
        for index, char in enumerate(text):
            if cells >= self.column:
                return index
            cells += get_cwidth(char)
        return len(text) + max(0, self.column - cells)

    def drag_at(self, event, y):
        return self.scrollbar_mouse(MouseEvent(Point(0, y), event.event_type, event.button, event.modifiers))

    def move(self, delta):
        self.selected = None
        self.line = max(0, min(self.last_page(), self.line + delta))

    def scrollbar_thumb(self):
        track = max(0, self.scrollbar_height - 2)
        size = min(track, max(1, round(track * self.scrollbar_height / max(1, len(self.lines)))))
        top = round((track - size) * self.line / max(1, self.last_page()))
        return top, size, track

    def scrollbar_mouse(self, event):
        y = event.position.y
        top, size, track = self.scrollbar_thumb()
        if event.event_type in (MouseEventType.SCROLL_UP, MouseEventType.SCROLL_DOWN):
            self.move(-3 if event.event_type == MouseEventType.SCROLL_UP else 3)
        elif event.event_type == MouseEventType.MOUSE_DOWN:
            self.selected = None
            if y == 0:
                self.move(-1)
            elif y >= self.scrollbar_height - 1:
                self.move(1)
            elif top <= y - 1 < top + size:
                self.scrollbar_drag = y - 1 - top
            else:
                self.move((1 if y - 1 > top else -1) * max(1, self.scrollbar_height - 1))
        elif event.event_type == MouseEventType.MOUSE_MOVE and self.scrollbar_drag is not None:
            position = max(0, min(track - size, y - 1 - self.scrollbar_drag))
            self.line = round(self.last_page() * position / max(1, track - size))
        elif event.event_type == MouseEventType.MOUSE_UP:
            self.scrollbar_drag = None
        else:
            return NotImplemented
        self.app.invalidate()
        return None

    def visible_height(self):
        return max(1, self.app.output.get_size().rows - 5)

    def last_page(self):
        return max(0, len(self.lines) - self.visible_height())

    def select_link(self, delta):
        if not self.links:
            return
        self.selected = ((self.selected + delta) % len(self.links) if self.selected is not None else
                         0 if delta > 0 else len(self.links) - 1)
        self.line = min(self.links[self.selected][1], self.last_page())
        self.column = 0
        # Bring a selected link into view even in the horizontally panned grid.
        x = 0
        for style, text, *_ in self.lines[self.links[self.selected][1]]:
            if f"class:result-link-{self.selected}" in style.split():
                if x + get_cwidth(text) > (self.width or 1):
                    self.column = max(0, x + get_cwidth(text) - (self.width or 1))
                break
            x += get_cwidth(text)

    def activate(self, url):
        if url.startswith("consensus-detail:") and self.detail:
            key = url.partition(":")[2]
            self.history.append((self.render, self.line, self.selected, self.width,
                                 self.lines, self.fragments, self.links, self.column, self.document_width))
            self.render = lambda width: self.detail(key, width)
            self.width, self.line, self.selected = None, 0, None
            self.column = 0
            self._clear_footer()
        else:
            from .reports import _safe_http_url

            safe = _safe_http_url(url)
            if safe:
                import webbrowser

                webbrowser.open(safe)
        self.app.invalidate()

    def back(self, *, close=True):
        if self.history:
            (self.render, self.line, self.selected, self.width,
             self.lines, self.fragments, self.links, self.column, self.document_width) = self.history.pop()
            self._clear_footer()
            self.app.invalidate()
        elif close:
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
        # ANSI emits individual characters. Keep runs with the same style/action
        # together so the persistent document isn't one tuple per character.
        compact = []
        parts = []
        previous = None
        for style, text, *handler in fragments:
            key = (style, *handler)
            if previous is not None and key != previous:
                compact.append((previous[0], "".join(parts), *previous[1:]))
                parts = []
            previous = key
            parts.append(text)
        if previous is not None:
            compact.append((previous[0], "".join(parts), *previous[1:]))
        return compact

    def prepare(self, width):
        previous_line = self.line
        width = max(1, width)
        if width != self.width:
            self.width = width
            self.fragments = self._linked_fragments(self.render(width))
            self.lines = list(split_lines(self.fragments))
            self.document_width = max(sum(get_cwidth(f[1]) for f in line) for line in self.lines)
            self.pan(0)
            self._clear_footer()
            if self.selected is not None and self.selected < len(self.links):
                self.line = min(self.links[self.selected][1], self.last_page())
        if self.follow_end:
            self.line = self.last_page()
            self.follow_end = False
        self.line = min(self.line, self.last_page())
        if self.line != previous_line:
            self._clear_footer()
        if self.selected is None or self.selected >= len(self.links):
            self.selected = None
            return

    def display_line(self, index):
        """Only visible lines need selection styling or renderer processing."""
        fragments = self.lines[index]
        if index == self.line and self.column:
            cells = sum(get_cwidth(f[1]) for f in fragments)
            if cells < self.column:
                fragments = [*fragments, ("", " " * (self.column - cells))]
        if self.selected is None:
            return fragments
        # Mouse handlers belong only to explicit link text, never its neighbours.
        selected_style = f"class:result-link-{self.selected}"
        return [(style + (" class:selected-link" if selected_style in style.split() else ""), text, *rest)
                for style, text, *rest in fragments]

    def footer(self):
        width = self.app.output.get_size().columns
        if self._footer_cache is not None and self._footer_cache[0] == width:
            return self._footer_cache[1]
        from rich.text import Text

        def fit(text):
            value = Text(text)
            value.truncate(max(1, width - 1), overflow="ellipsis")
            return value.plain

        controls = " ↑↓ Scroll   PgUp/PgDn Page   Home/End   Tab Links   Enter Open"
        if width < 65:
            controls = " ↑↓ Scroll   Tab Links   Enter Open"
        end = min(len(self.lines), self.line + self.visible_height())
        position = f" {self.line + 1:,}–{end:,} / {len(self.lines):,} lines"
        if self.document_width > (self.width or 1):
            position += "    ← → More columns"
        result = fit(controls) + "\n" + fit(position)
        self._footer_cache = (width, result)
        return result

    async def run(self):
        try:
            await self.app.run_async()
        except EOFError:
            pass
