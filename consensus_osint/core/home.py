"""Restrained, viewport-aware home screen for the interactive terminal."""
from __future__ import annotations

from rich.cells import cell_len
from rich.style import Style
from rich.text import Text

from .branding import ACCENT, LINKS, ORGANIZATION, SLOGAN
from .terminal_ui import clean


def home_page(info, *, width, height, version, history=False, footer_rows=None):
    """Framed identity, aligned actions and one clear input invitation.

    Reserve the actual responsive footer, input and cursor. Full metadata and
    branding remain under info/about. Long paths retain their full link targets.
    """
    terminal_width = width
    frame_width = max(34, min(98, width - 2))
    wide = frame_width >= 76
    padding = 2 if wide else 1
    content_width = frame_width - 2 - 2 * padding
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

    def key(number, label):
        value = Text()
        value.append(number, style=f"bold {ACCENT}")
        value.append("  " + label, style="default")
        return value

    def columns(*values):
        gap = 2
        column_width = (content_width - gap * (len(values) - 1)) // len(values)
        row = Text()
        for i, value in enumerate(values):
            value = fit(value, column_width)
            if i:
                row.append(" " * gap)
            row.append(value)
            if i < len(values) - 1:
                row.append(" " * (column_width - value.cell_len))
        add(row)

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

    header = Text()
    header.append(" ╭─ ", style="dim")
    header.append("◈ ", style=ACCENT)
    header.append("Consensus", style="bold default")
    version_text = fit("v" + clean(version), max(5, frame_width - 22))
    header.append(" " + "─" * max(1, frame_width - 19 - version_text.cell_len) + " ", style="dim")
    header.append(version_text.plain, style="dim")
    header.append(" ─╮", style="dim")
    rows.append((header, 0))
    organization = Text("OSINT", style=ACCENT)
    organization.append(ORGANIZATION.removeprefix("OSINT"), style="default")
    add(organization, framed=True)
    slogan_lines = [SLOGAN] if cell_len(SLOGAN) <= content_width else [
        clause.strip() + "." for clause in SLOGAN.split(".") if clause.strip()]
    for line in slogan_lines:
        add(line, optional=4, framed=True)
    if wide:
        add(text("Major lookup tools, brought together.", "dim"), optional=2, framed=True)
        add(optional=1, framed=True)
    location("Working", info.working_folder)
    location("Reports", info.report_folder)
    catalogue = metadata["Installed catalogue"]
    if "not verified" in catalogue:
        catalogue = "Catalogue unverified · info for details"
    elif "days old" in catalogue:
        catalogue = "Catalogue " + catalogue.rsplit(" · ", 1)[-1] + " · info for details"
    else:
        catalogue = ("Catalogue  " + catalogue + "  ·  Weekly updates" if wide else
                     "Weekly catalogue " + catalogue)
    if not wide and "info for details" in catalogue:
        catalogue = catalogue.replace(" · info for details", " · info")
    add(text(catalogue, "yellow" if "unverified" in catalogue or "days old" in catalogue else "dim"), framed=True)
    rows.append((Text(" ╰" + "─" * (frame_width - 2) + "╯", style="dim"), 0))
    add(optional=1)
    if wide:
        headings = text("Start a search", "bold")
        group_stride = 2 * ((content_width - 6) // 4 + 2)
        headings.append(" " * (group_stride - headings.cell_len))
        headings.append("Results & settings", style="bold")
        add(headings)
        columns(key("1", "Username"), key("2", "Email"), key("5", "View results"), key("6", "Save report"))
        columns(key("3", "Phone"), key("4", "Bulk search"), key("7", "Settings"), key("0", "Exit"))
        add(optional=1)
        tools = key("8", "Show Examples")
        tools.append("    ")
        tools.append(key("9", "Help"))
        tools.append("    info: paths    about: project", style="dim")
        add(tools)
    else:
        add(text("Choose a number", "bold"))
        for left, right in [(key("1", "Username"), key("2", "Email")),
                            (key("3", "Phone"), key("4", "Bulk search")),
                            (key("5", "View results"), key("6", "Save report")),
                            (key("7", "Settings"), key("8", "Show Examples")),
                            (key("9", "Help"), key("0", "Exit"))]:
            columns(left, right)
        add(text("info: full paths · about: project", "dim"))
    links = Text()
    for label, url in [("osint.ngo", LINKS[0][1]), ("LinkedIn", LINKS[1][1]),
                       ("Reddit", LINKS[2][1]), ("GitHub", info.repository)]:
        if links.plain:
            links.append("  " if wide else " ", style="dim")
        links.append(label, style=Style(link=url, dim=True))
    add(links)
    add(optional=1)
    notice = Text("Bugs can occur. ", style="yellow")
    notice.append("Use test accounts you control; verify findings." if wide else "Use test accounts.", style="default")
    add(notice)
    add(text("Lawful, authorised use only. Respect privacy and service terms." if wide else
             "Lawful use; respect privacy/terms.", "dim"))
    add(optional=1)
    invitation = Text("Type a username, email or phone (auto-detect). / commands" if wide else
                      "Auto-detect input · / commands", style="dim")
    if history and invitation.cell_len + 22 <= content_width:
        invitation.append("  ↑↓ previous commands", style="dim not bold")
    add(invitation)

    footer_rows = footer_rows if footer_rows is not None else (2 if terminal_width >= 78 else 3)
    budget = max(1, height - footer_rows - 2)
    # Remove spacing first, then supplementary copy in short windows. Frame
    # edges, actions, input guidance and safety text are never selected here.
    for index in range(len(rows) - 1, -1, -1):
        if len(rows) <= budget:
            break
        if rows[index][1] == 1:
            rows.pop(index)
    for priority in (2, 4):
        if len(rows) > budget:
            rows = [(row, rank) for row, rank in rows if rank != priority]
    if len(rows) > budget or any(row.cell_len > terminal_width for row, _ in rows):
        return _small_home(info, width=terminal_width, budget=budget, version=version)
    return Text("\n").join(row for row, _ in rows)


def _small_home(info, *, width, budget, version):
    """Keep entry usable when a framed menu cannot fit above input and footer."""
    width, budget = max(1, width), max(1, budget)
    title = Text("Consensus", style="bold default")
    title.append(" v" + clean(version), style="dim")
    if width >= 36 and budget >= 10:
        rows = [title]
        if budget >= 11:
            rows.append(Text(ORGANIZATION, style=ACCENT))
        column_width = (width - 2) // 2
        for first, second in (("1  Username", "2  Email"), ("3  Phone", "4  Bulk search"),
                              ("5  View results", "6  Save report"), ("7  Settings", "8  Show Examples"),
                              ("9  Help", "0  Exit")):
            row = Text(first.ljust(column_width) + "  " + second)
            row.stylize(f"bold {ACCENT}", 0, 1)
            row.stylize(f"bold {ACCENT}", column_width + 2, column_width + 3)
            rows.append(row)
        rows.append(Text("Resize for full home; info: paths", style="dim"))
        if budget >= 12:
            links = Text()
            for label, url in (("osint.ngo", LINKS[0][1]), ("LinkedIn", LINKS[1][1]),
                               ("Reddit", LINKS[2][1]), ("GitHub", info.repository)):
                if links:
                    links.append(" ")
                links.append(label, style=Style(link=url, dim=True))
            rows.append(links)
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
