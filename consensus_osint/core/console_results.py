"""Compact interactive result matrix, with evidence available on demand."""
from __future__ import annotations

import io

from rich import box
from rich.console import Console
from rich.style import Style
from rich.table import Table
from rich.text import Text

from .branding import ACCENT
from .models import INFO_CATEGORIES, Status
from .presentation import assessment, enrichment_fields, has_details
from .provenance import repository_coverage
from .terminal_ui import clean


def result_pages(summary, *, show_all=False, limit=0):
    """Keep detail IDs stable across resizing, query groups and coverage panels."""
    findings = list(summary.findings)

    def console(width):
        stream = io.StringIO()
        return Console(file=stream, width=width, height=25, force_terminal=True, color_system="truecolor",
                       legacy_windows=False, highlight=False), stream

    def link(label, key):
        text = Text(label)
        text.stylize(Style(color=ACCENT, underline=True, link="consensus-detail:" + key), 0, len(label))
        return text

    def overview(width):
        from .reports import group_by_query, result_link

        out, stream = console(width)
        matches = [f for f in findings if f.status is Status.FOUND and f.category not in INFO_CATEGORIES]
        title = "Search stopped · partial results" if summary.options.get("interrupted") else "Search complete"
        out.print(Text(title, style=f"bold {ACCENT}"))
        out.print(Text(f"{len(matches)} found · {sum(has_details(f) for f in matches)} enriched · {len(findings)} outcomes"))
        out.print(Text("X = recorded project coverage, not another search. - = no recorded coverage.", style="dim"))
        out.print(Text("Found* = limited evidence; verify before relying on it.", style="dim"))
        identifiers = {id(f): str(i + 1) for i, f in enumerate(findings)}
        for group in group_by_query(summary):
            out.print(Text("\n" + clean(group.title), style="bold"))
            rows = [f for f in group.findings if f.category not in INFO_CATEGORIES and
                    (show_all or f.status is Status.FOUND)]
            rows.sort(key=lambda f: (assessment(f)[0] == "Needs review", f.site.casefold()))
            shown = rows[:limit] if limit else rows
            if not shown:
                out.print(Text("No matches reported. See all outcomes for inconclusive or skipped checks.", style="dim"))
                continue
            coverage = {id(f): repository_coverage(f) for f in shown}
            projects = {p["id"]: p["name"] for values in coverage.values() for p in values}
            keys = sorted(projects)
            # Numbered column headings keep long project names out of every row.
            # Repeat the identifiers when coverage needs more than one panel.
            per_panel = max(1, (width - 52) // 4)
            panels = [keys[n:n + per_panel] for n in range(0, len(keys), per_panel)] or [[]]
            if width < 60:
                panels = [keys]
            for panel in panels:
                table = Table(box=box.SIMPLE_HEAD, header_style=f"bold {ACCENT}", expand=True,
                              padding=(0, 1), collapse_padding=True)
                table.add_column("Site / result" if width < 60 else "Site", ratio=2, overflow="fold")
                if width >= 60:
                    table.add_column("Result", width=10)
                table.add_column("Enriched", width=11 if width >= 40 else 8)
                if width < 60:
                    table.add_column("Projects", ratio=1, overflow="fold")
                else:
                    for key in panel:
                        table.add_column(str(keys.index(key) + 1), width=2, justify="center")
                for f in shown:
                    verdict = "Found*" if assessment(f)[0] == "Needs review" else f.status.value.replace("_", " ").title()
                    profile, _ = result_link(f)
                    site = Text(clean(f.site))
                    if profile:
                        site.stylize(Style(link=profile, underline=True), 0, len(site))
                    if width < 60:
                        site.append("\n" + verdict, style="dim")
                    cells = [site]
                    if width >= 60:
                        cells.append(Text(verdict, style="yellow" if verdict == "Found*" else "green" if f.status is Status.FOUND else "dim"))
                    cells.append(link("Yes · View" if width >= 40 else "View", identifiers[id(f)]) if has_details(f) else Text("-", style="dim"))
                    sources = {p["id"] for p in coverage[id(f)]}
                    if width < 60:
                        cells.append(Text(" ".join(f"X{keys.index(k) + 1}" for k in panel if k in sources) or "?"))
                    else:
                        cells.extend(Text("X" if key in sources else "-", style=ACCENT if key in sources else "dim") for key in panel)
                    table.add_row(*cells)
                out.print(table)
                if panel:
                    out.print(Text(" · ".join(f"{keys.index(k) + 1} {projects[k]}" for k in panel), style="dim"))
            if any(not coverage[id(f)] for f in shown):
                out.print(Text("Some rows have no saved project attribution; missing coverage is unknown.", style="dim"))
            if len(shown) < len(rows):
                out.print(Text(f"Showing {len(shown)} of {len(rows)} rows; full analysis retains every outcome.", style="dim"))
        out.print()
        inconclusive = sum(f.status in (Status.UNKNOWN, Status.BLOCKED, Status.RATE_LIMITED, Status.ERROR)
                           for f in findings if f.category not in INFO_CATEGORIES)
        out.print(Text(f"Found {len(matches)} · Enriched {sum(has_details(f) for f in matches)} · Inconclusive {inconclusive}", style="bold"))
        out.print(link("All outcomes & full analysis", "all"))
        out.print(Text("Select an underlined link for details. No enrichment means no additional profile fields.", style="dim"))
        return stream.getvalue()

    def detail(key, width):
        from .console import Printer

        out, stream = console(width)
        printer = Printer(stream=stream, show_all=True, details=True, summary_limit=0)
        printer.terminal_ui = None
        printer.console = out
        if key == "all":
            printer.finish(summary)
        elif key.isdecimal() and 1 <= int(key) <= len(findings):
            f = findings[int(key) - 1]
            out.print(Text(clean(f.site) + " · returned details", style=f"bold {ACCENT}"))
            count = len(enrichment_fields(f))
            out.print(Text(f"{count} enriched field{'s' if count != 1 else ''} · verify their connection to the query.", style="dim"))
            for heading, cell in zip(printer.result_headings(), printer._result_cells(f), strict=True):
                out.print(Text("\n" + heading, style="bold"))
                out.print(cell)
        else:
            out.print(Text("This result is no longer available."))
        return stream.getvalue()

    return overview, detail
