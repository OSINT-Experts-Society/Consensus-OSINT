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
from .presentation import assessment, enrichment_fields, has_details, split_fields
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
        out.print(Text("X = project lists this lookup; coverage does not mean separate searches.", style="dim"))
        out.print(Text("Possible match = limited evidence. Select the result label to see why.", style="dim"))
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
            site_width = min(26, max(12, max(len(clean(f.site)) for f in shown)))
            # Use named matrix columns when they fit, otherwise a named list.
            # Never repeat every result in multiple panels just to fit sources.
            matrix = width >= 60 and site_width + 32 + sum(len(projects[k]) + 2 for k in keys) <= width
            narrow = width < 60
            table = Table(box=box.SIMPLE_HEAD, header_style=f"bold {ACCENT}", expand=True,
                          padding=(0, 1), collapse_padding=True)
            table.add_column("Site / result" if narrow else "Site", width=None if narrow else site_width,
                             ratio=1 if narrow else None, overflow="fold")
            if not narrow:
                table.add_column("Result", width=18, overflow="fold")
            if width >= 40:
                table.add_column("Enriched", width=11)
            if matrix:
                for key in keys:
                    table.add_column(projects[key], justify="center", min_width=len(projects[key]))
            else:
                table.add_column("Enriched / tools" if width < 40 else "Tools with this lookup", ratio=2, overflow="fold")
            for f in shown:
                label, _, tone = assessment(f)
                verdict = "Possible match" if label == "Needs review" else label
                key = identifiers[id(f)]
                profile, _ = result_link(f)
                site = Text(clean(f.site))
                if profile:
                    site.stylize(Style(link=profile, underline=True), 0, len(site))
                result = link(verdict, key) if label == "Needs review" else Text(verdict)
                result.stylize("yellow" if tone == "warn" else "green" if f.status is Status.FOUND else "dim")
                if narrow:
                    site.append("\n")
                    site.append(result)
                cells = [site]
                if not narrow:
                    cells.append(result)
                enriched = link("Yes · View" if width >= 40 else "View", key) if has_details(f) else Text("-", style="dim")
                if width >= 40:
                    cells.append(enriched)
                sources = {p["id"] for p in coverage[id(f)]}
                if matrix:
                    cells.extend(Text("X" if k in sources else "-", style=ACCENT if k in sources else "dim") for k in keys)
                else:
                    tools = Text("\n".join("X " + projects[k] for k in keys if k in sources) or "Not recorded")
                    if width < 40:
                        enriched.append("\n")
                        enriched.append(tools)
                        tools = enriched
                    cells.append(tools)
                table.add_row(*cells)
            out.print(table)
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
            from .reports import display_fields, result_link

            label, explanation, tone = assessment(f)
            out.print(Text(f"{clean(f.query_type).title()}: {clean(f.query)}"))
            out.print(Text("Possible match" if label == "Needs review" else label,
                           style="bold yellow" if tone == "warn" else f"bold {ACCENT}"))
            out.print(Text(clean(explanation)))
            if f.error:
                out.print(Text(clean(f.error), style="yellow"))
            enriched = enrichment_fields(f)
            returned, _ = split_fields(f.extra)
            other = {key: value for key, value in returned.items() if key not in enriched}
            for heading, values in (("Enriched information", enriched), ("Other returned information", other)):
                fields = display_fields(values, max_fields=0, limit=0, include_images=True)
                if not fields:
                    continue
                out.print(Text("\n" + heading, style=f"bold {ACCENT}"))
                table = Table(box=box.SIMPLE, show_lines=True, expand=True,
                              header_style=f"bold {ACCENT}", padding=(0, 1))
                table.add_column("Field", width=min(24, max(6, width // 4)), style=f"bold {ACCENT}", overflow="fold")
                table.add_column("Value", ratio=1, overflow="fold")
                for field in fields:
                    value = Text(clean(field.value))
                    for url in field.urls:
                        start = value.plain.find(url)
                        if start >= 0:
                            value.stylize(Style(link=url, underline=True), start, start + len(url))
                    table.add_row(Text(clean(field.label)), value)
                out.print(table)
            if not enriched:
                out.print(Text("\nNo additional profile fields were returned.", style="dim"))
            out.print(Text("Returned information must be verified against the searched identifier.", style="dim"))
            profile, label = result_link(f)
            if profile:
                out.print(Text("\n" + label, style=f"bold {ACCENT}"))
                target = Text(profile)
                target.stylize(Style(link=profile, underline=True), 0, len(profile))
                out.print(target)
            out.print(Text("\nTools with this lookup", style=f"bold {ACCENT}"))
            out.print(printer._coverage_cell(f))
        else:
            out.print(Text("This result is no longer available."))
        return stream.getvalue()

    return overview, detail
