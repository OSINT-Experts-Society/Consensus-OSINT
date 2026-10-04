"""Restrained, viewport-aware home screen for the interactive terminal."""
from __future__ import annotations

from rich.cells import cell_len
from rich.style import Style
from rich.text import Text

from .branding import ACCENT, LINKS, ORGANIZATION, SLOGAN, TERMINAL_MARK
from .terminal_ui import clean


def action_panels(width, *, has_results=False):
    """Shared home/after-action menu, with optional dividers in short windows."""
    available = min(118, width - 2)
    panel_width = (available - 2) // 2
    inset = " " if panel_width >= 24 else ""
    inside = panel_width - 2 - 2 * len(inset)

    def edge(title="", first="╭", last="╮"):
        label = " " + title + " " if title else ""
        value = Text(first, style="dim")
        value.append(label, style="bold not dim" if title else "dim")
        value.append("─" * max(0, panel_width - len(label) - 2) + last, style="dim")
        return value

    def item(number, label, description, short, *, inactive=False):
        content = Text(number + "  " + label, style="dim" if inactive else "default not dim")
        if not inactive:
            content.stylize(f"bold {ACCENT}", 0, 1)
        hint_start = 19 if inside >= 38 else 16
        room = inside - hint_start
        hint = description if len(description) <= room else short
        if room >= len(hint):
            content.append(" " * max(1, hint_start - content.cell_len))
            content.append(hint, style="dim")
        content.truncate(max(1, inside), overflow="ellipsis")
        return content

    def body(content):
        content = content.copy()
        content.truncate(max(1, inside), overflow="ellipsis")
        value = Text("│" + inset, style="dim")
        value.append(content)
        value.append(" " * max(0, inside - content.cell_len) + inset + "│", style="dim")
        return value

    def pair(left, right, optional=0):
        value = Text(" ")
        value.append(left)
        value.append("  ")
        value.append(right)
        return value, optional

    search = [item("1", "Username", "Find matching profiles", "Matching profiles"),
              item("2", "Email", "Find linked accounts", "Linked accounts"),
              item("3", "Phone", "Check number details", "Number details"),
              item("4", "Bulk search", "Search a list of identifiers", "Search a list")]
    hint = "Run a search first"
    results = [item("5", "View results", "Reopen your latest search" if has_results else hint,
                    "Latest search" if has_results else hint, inactive=not has_results),
               item("6", "Save report", "Export your latest results" if has_results else hint,
                    "Export results" if has_results else hint, inactive=not has_results),
               item("7", "Settings", "Adjust search preferences", "Preferences"),
               Text("" if has_results or inside >= 34 else "Search first", style="dim")]
    rows = [pair(edge("Start a search"), edge("Results & settings" if panel_width >= 24 else "Results/setup"))]
    for index, (left, right) in enumerate(zip(search, results, strict=True)):
        if index:
            rows.append(pair(edge(first="├", last="┤"), edge(first="├", last="┤"), 2))
        rows.append(pair(body(left), body(right)))
    rows.append(pair(edge(first="╰", last="╯"), edge(first="╰", last="╯")))
    tools = Text(" ")
    for number, label in (("8", "Show Examples"), ("9", "Help"), ("0", "Exit")):
        if len(tools) > 1:
            tools.append("   ")
        tools.append(number, style=f"bold {ACCENT}")
        tools.append("  " + label)
    rows.append((tools, 0))
    return rows


def home_page(info, *, width, height, version, history=False, footer_rows=None, has_results=False):
    """Framed identity, aligned actions and one clear input invitation.

    Reserve the actual responsive footer, input and cursor. Full metadata and
    branding remain under info/about. Long paths retain their full link targets.
    """
    terminal_width = width
    frame_width = max(34, min(118, width - 2))
    wide = frame_width >= 76
    padding = 2 if wide else 1
    content_width = frame_width - 2 - 2 * padding
    footer_rows = footer_rows if footer_rows is not None else (2 if terminal_width >= 78 else 3)
    budget = max(1, height - footer_rows - 2)
    rows = []
    metadata = dict(info.rows())

    def text(value="", style=""):
        return value.copy() if isinstance(value, Text) else Text(clean(value), style=style)

    def fit(value, columns):
        value = text(value)
        value.truncate(max(1, columns), overflow="ellipsis")
        return value

    def add(value="", *, optional=0, framed=False):
        value = fit(value, content_width)
        if framed:
            row = Text()
            row.append(" │" + " " * padding, style="dim")
            row.append(value)
            row.append(" " * (content_width - value.cell_len + padding) + "│", style="dim")
        else:
            row = Text(" " * (2 + padding))
            row.append(value)
        rows.append((row, optional))

    def location(label, path):
        label_width = 11 if wide else 9
        available = content_width - label_width
        value = clean(path)
        if cell_len(value) > available:
            # Preserve the directory name, particularly the report destination.
            tail = ""
            for char in reversed(value):
                if cell_len(char + tail) > available - 1:
                    break
                tail = char + tail
            value = "…" + tail
        row = Text(f"{label:<{label_width}}", style="dim")
        row.append(value, style=Style(link=path.as_uri(), dim=False))
        add(row, framed=True)

    title = Text("Consensus", style="bold default")
    title.append(" v" + clean(version), style="dim")
    if wide and budget < 16:
        # A shallow window keeps a compact mark without sacrificing the menu.
        header = Text(" ╭─ ", style="dim")
        header.append("●─◎ ", style=ACCENT)
        header.append(title)
        header.append(" " + "─" * max(1, frame_width - header.cell_len - 1) + "╮", style="dim")
        rows.append((header, 0))
        add(ORGANIZATION, framed=True)
    else:
        rows.append((Text(" ╭" + "─" * (frame_width - 2) + "╮", style="dim"), 0))
        labels = [title, text(ORGANIZATION), text(SLOGAN if wide else "Many sources. One tool.", "dim")]
        for mark, label in zip(TERMINAL_MARK.splitlines(), labels, strict=True):
            row = Text(mark + "  ", style=ACCENT)
            row.append(label)
            add(row, framed=True)
    location("Working", info.working_folder)
    location("Reports", info.report_folder)
    catalogue = metadata["Lookup database updated"]
    if "not verified" in catalogue:
        catalogue = "Lookup database unverified · info" if wide else "Database unverified · info"
    elif "days old" in catalogue:
        catalogue = "Database " + catalogue.rsplit(" · ", 1)[-1] + " · info for details"
    else:
        if wide:
            catalogue = "Lookup database updated: " + catalogue + " · Weekly review"
        else:
            parts = catalogue.split()
            if len(parts) == 3:
                catalogue = f"{parts[0]} {parts[1][:3]} {parts[2]}"
            catalogue = "Database updated: " + catalogue
    if not wide and "info for details" in catalogue:
        catalogue = catalogue.replace(" · info for details", " · info")
    add(text(catalogue, "yellow" if "unverified" in catalogue or "days old" in catalogue else "dim"), framed=True)
    rows.append((Text(" ╰" + "─" * (frame_width - 2) + "╯", style="dim"), 0))
    add(optional=1)
    rows.extend(action_panels(terminal_width, has_results=has_results))
    links = Text()
    for label, url in [("osint.ngo", LINKS[0][1]), ("LinkedIn", LINKS[1][1]),
                       ("Reddit", LINKS[2][1]), ("GitHub", info.repository)]:
        if links.plain:
            links.append("  " if wide else " ", style="dim")
        links.append(label, style=Style(link=url, color=ACCENT))
    community_title = "╭─ Join the Community "
    community_header = text(community_title + "─" * (content_width - cell_len(community_title) - 1) + "╮", "dim")
    community_header.stylize(f"bold {ACCENT}", 3, 21)
    add(community_header)
    community_links = Text("│ " if wide else "│", style="dim")
    community_links.append(links)
    community_links.append(" " * max(0, content_width - community_links.cell_len - 1) + "│", style="dim")
    add(community_links)
    add(text("╰" + "─" * (content_width - 2) + "╯", "dim"))
    add(optional=1)
    notice = Text("Bugs can occur. " if wide else "", style="yellow")
    notice.append("Verify findings. Lawful use; use test accounts." if wide else
                  "Use test accounts. Lawful use only.", style="default")
    add(notice)
    add(optional=1)
    invitation = Text("Type a username, email or phone (auto-detect). / commands" if wide else
                      "Auto-detect input · / commands", style="dim")
    if history and invitation.cell_len + 22 <= content_width:
        invitation.append("  ↑↓ previous commands", style="dim not bold")
    add(invitation, optional=4)

    # Remove spacing first, then supplementary copy in short windows. Frame
    # edges, actions and safety text are never selected here.
    for index in range(len(rows) - 1, -1, -1):
        if len(rows) <= budget:
            break
        if rows[index][1] == 1:
            rows.pop(index)
    for priority in (2, 4):
        if len(rows) > budget:
            rows = [(row, rank) for row, rank in rows if rank != priority]
    if len(rows) > budget or any(row.cell_len > terminal_width for row, _ in rows):
        return _small_home(info, width=terminal_width, budget=budget, version=version, has_results=has_results)
    return Text("\n").join(row for row, _ in rows)


def _small_home(info, *, width, budget, version, has_results=False):
    """Keep entry usable when a framed menu cannot fit above input and footer."""
    width, budget = max(1, width), max(1, budget)
    title = Text("●─◎ ", style=ACCENT)
    title.append("Consensus", style="bold default")
    title.append(" v" + clean(version), style="dim")
    if width >= 36 and budget >= 10:
        rows = [title]
        if budget >= 11:
            rows.append(Text(ORGANIZATION, style=ACCENT))
        column_width = (width - 2) // 2
        for first, second in (("1  Username", "5  View results"), ("2  Email", "6  Save report"),
                              ("3  Phone", "7  Settings"), ("4  Bulk search", "9  Help"),
                              ("8  Show Examples", "0  Exit")):
            row = Text(first.ljust(column_width) + "  " + second)
            row.stylize(f"bold {ACCENT}", 0, 1)
            row.stylize(f"bold {ACCENT}", column_width + 2, column_width + 3)
            if not has_results and second.startswith(("5", "6")):
                row.stylize("dim", column_width + 2)
            rows.append(row)
        rows.append(Text("Resize for full home." if has_results else "Resize; 5/6: Run a search first.", style="dim"))
        if budget >= 13:
            links = Text()
            for label, url in (("osint.ngo", LINKS[0][1]), ("LinkedIn", LINKS[1][1]),
                               ("Reddit", LINKS[2][1]), ("GitHub", info.repository)):
                if links:
                    links.append(" ")
                links.append(label, style=Style(link=url, dim=True))
            header = Text("╭─ Join the Community " + "─" * (width - 22) + "╮", style="dim")
            header.stylize(f"bold {ACCENT}", 3, 21)
            link_row = Text("│ ", style="dim")
            link_row.append(links)
            link_row.append(" " * max(0, width - link_row.cell_len - 1) + "│", style="dim")
            rows.extend((header, link_row, Text("╰" + "─" * (width - 2) + "╯", style="dim")))
        rows.extend((Text("Bugs occur. Use test accounts.", style="yellow"),
                     Text("Lawful use; respect privacy/terms.", style="dim"),
                     Text("Type a username, email or phone.", style="dim")))
    else:
        # The smallest windows cannot show every choice. Help and Exit remain
        # explicit; entering an identifier still uses the normal session parser.
        rows = [Text("Resize for menu.", style=ACCENT), Text("9 Help  0 Exit"),
                Text("Use test accounts.", style="yellow"), Text("Lawful use only.", style="dim")]
        if budget >= 5:
            rows.insert(0, title)
        if budget >= 6 and width >= cell_len(ORGANIZATION):
            rows.insert(1, Text(ORGANIZATION, style=ACCENT))
    rows = rows[:budget]
    for row in rows:
        row.truncate(width, overflow="ellipsis")
    return Text("\n").join(rows)
