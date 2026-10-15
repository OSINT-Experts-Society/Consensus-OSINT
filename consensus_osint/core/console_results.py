"""Compact interactive result matrix, with evidence available on demand."""
from __future__ import annotations

import io

from rich import box
from rich.cells import cell_len
from rich.console import Console
from rich.style import Style
from rich.table import Table
from rich.text import Text

from .branding import ACCENT
from .models import INFO_CATEGORIES, Status
from .presentation import assessment, enrichment_fields, has_details, split_fields
from .provenance import repository_coverage
from .terminal_ui import clean


class ResultDocument(str):
    """Rendered text with query/header positions for the scrollable viewer."""

    def __new__(cls, value, sections, caption):
        result = super().__new__(cls, value)
        result.sections = sections
        result.caption = caption
        return result


class _Buffer(io.StringIO):
    lines = 0

    def write(self, value):
        self.lines += value.count("\n")
        return super().write(value)


def result_pages(summary, *, show_all=False, limit=0, filters=None):
    """Keep detail IDs stable across resizing, query groups and coverage panels."""
    findings = list(summary.findings)
    filters = dict(filters or {})

    def console(width):
        stream = _Buffer()
        return Console(file=stream, width=width, height=25, force_terminal=True, color_system="truecolor",
                       legacy_windows=False, highlight=False), stream

    def link(label, key):
        text = Text(label)
        text.stylize(Style(color=ACCENT, underline=True, link="consensus-detail:" + key), 0, len(label))
        return text

    def overview(width):
        from .reports import group_by_query, result_link

        out, stream = console(width)
        sections = []
        matches = [f for f in findings if f.status is Status.FOUND and f.category not in INFO_CATEGORIES]
        inconclusive = sum(f.status in (Status.UNKNOWN, Status.BLOCKED, Status.RATE_LIMITED, Status.ERROR)
                           for f in findings if f.category not in INFO_CATEGORIES)
        title = "Search stopped · partial results" if summary.options.get("interrupted") else "Search complete"
        if filters:
            title += " · filtered view"
        out.print(Text(title, style=f"bold {ACCENT}"))
        if filters:
            label = " · ".join(clean(value) for value in (filters.get("site"), filters.get("kind")) if value)
            out.print(Text("Filter: " + label
                           + ". F changes or clears filters. Saving keeps every outcome.", style=f"bold {ACCENT}"))
        out.print(Text(("Full search: " if filters else "") +
                       f"{len(matches)} found · {sum(has_details(f) for f in matches)} enriched · {len(findings)} outcomes"))
        if summary.options.get("top"):
            out.print(Text(f"Search limit: up to {summary.options['top']} checks per username/email · "
                           "I Follow up → Continue full search keeps completed results.", style=f"bold {ACCENT}"))
        elif summary.options.get("fast"):
            out.print(Text("Quick search · I Follow up → Continue full search keeps completed results.", style=f"bold {ACCENT}"))
        if summary.options.get("continuation"):
            retained = summary.options["continuation"].get("retained_results", 0)
            out.print(Text(f"{retained} earlier outcomes retained with their original observation times.", style="dim"))
        if summary.options.get("changes"):
            out.print(Text("Changes available · I Follow up → View changes", style=f"bold {ACCENT}"))
        if matches or show_all:
            out.print(Text("X = project lists this lookup; coverage does not mean separate searches.", style="dim"))
        if any(assessment(f)[0] == "Needs review" for f in matches):
            out.print(Text("Possible match = limited evidence. Select the result label to see why.", style="dim"))
        if summary.options.get("interrupted"):
            out.print(Text("Only collected outcomes are shown; this is not a complete search.", style="yellow"))
        identifiers = {id(f): str(i + 1) for i, f in enumerate(findings)}
        groups = group_by_query(summary)
        if not groups:
            out.print(Text("No lookup outcomes were collected.", style="dim"))
        for group in groups:
            out.print(Text("\n" + clean(group.title), style="bold"))
            rows = [f for f in group.findings if f.category not in INFO_CATEGORIES and
                    (show_all or f.status is Status.FOUND)]
            if filters:
                rows = [f for f in rows if filters.get("site", "").casefold() in f.site.casefold()
                        and (filters.get("kind", "all") != "enriched" or has_details(f))
                        and (filters.get("kind", "all") != "possible" or assessment(f)[0] == "Needs review")]
            rows.sort(key=lambda f: (assessment(f)[0] == "Needs review", f.site.casefold()))
            shown = rows[:limit] if limit else rows
            if filters:
                out.print(Text(f"{len(shown)} rows match the filters", style="dim"))
            if not shown:
                if filters:
                    message = "No rows match these filters. Press F to change or clear them."
                elif summary.options.get("interrupted"):
                    message = "No matches reported before the search stopped. This search is incomplete."
                elif any(f.status in (Status.UNKNOWN, Status.BLOCKED, Status.RATE_LIMITED, Status.ERROR)
                         for f in group.findings if f.category not in INFO_CATEGORIES):
                    message = "No matches reported. Some sites could not be checked conclusively."
                elif not any(f.status is Status.NOT_FOUND for f in group.findings if f.category not in INFO_CATEGORIES):
                    message = "No matches reported. No conclusive lookup results; review skipped or unavailable lookups in all outcomes."
                else:
                    message = "No matches reported by the completed lookups. Try another identifier or review all outcomes."
                # A bulk query with no rows must replace the previous query's
                # sticky context too; its explanation takes the header's place.
                sections.append((stream.lines, clean(group.title)))
                out.print(Text(message, style="dim"))
                continue
            coverage = {id(f): repository_coverage(f) for f in shown}
            projects = {p["id"]: p["name"] for values in coverage.values() for p in values}
            keys = sorted(projects)
            verdicts = {id(f): assessment(f) for f in shown}
            result_width = max(6, min(20, max(cell_len("Possible match" if verdicts[id(f)][0] == "Needs review"
                                                     else verdicts[id(f)][0]) for f in shown)))
            # One separator cell, no expanding padding and no stacked coverage.
            # Small windows pan across the same single-row matrix.
            fixed_width = result_width + 8 + sum(cell_len(projects[k]) for k in keys) + len(keys) + 2
            site_width = max(8, min(28, max(12, max(cell_len(clean(f.site)) for f in shown)), width - fixed_width))
            table_width = site_width + fixed_width
            table = Table(box=None, header_style=f"bold {ACCENT}", expand=False,
                          padding=(0, 1, 0, 0), pad_edge=False)
            table.add_column("Site", width=site_width, no_wrap=True, overflow="ellipsis")
            table.add_column("Result", width=result_width, no_wrap=True, overflow="ellipsis")
            table.add_column("Enriched", width=8, no_wrap=True)
            for key in keys:
                table.add_column(projects[key], width=cell_len(projects[key]), justify="center", no_wrap=True)
            for f in shown:
                label, _, tone = verdicts[id(f)]
                verdict = "Possible match" if label == "Needs review" else label
                key = identifiers[id(f)]
                profile, _ = result_link(f)
                site = Text(clean(f.site))
                if profile:
                    site.stylize(Style(link=profile, underline=True), 0, len(site))
                result = link(verdict, key) if label == "Needs review" else Text(verdict)
                result.stylize("yellow" if tone == "warn" else "green" if f.status is Status.FOUND else "dim")
                cells = [site, result, link("View", key) if has_details(f) else Text("-", style="dim")]
                sources = {p["id"] for p in coverage[id(f)]}
                cells.extend(Text("X" if k in sources else "-", style=ACCENT if k in sources else "dim") for k in keys)
                table.add_row(*cells)
            table_out, table_stream = console(max(width, table_width))
            table_out.print(table)
            sections.append((stream.lines, clean(group.title)))
            stream.write(table_stream.getvalue())
            if any(not coverage[id(f)] for f in shown):
                out.print(Text("Some rows have no saved project attribution; missing coverage is unknown.", style="dim"))
            if len(shown) < len(rows):
                out.print(Text(f"Showing {len(shown)} of {len(rows)} rows; full analysis retains every outcome.", style="dim"))
        out.print()
        out.print(Text(f"Found {len(matches)} · Enriched {sum(has_details(f) for f in matches)} · Inconclusive {inconclusive}", style="bold"))
        out.print(link("All outcomes & full analysis", "all"))
        if matches:
            out.print(Text("Site opens the profile · View opens enriched fields · X marks project coverage.", style="dim"))
        return ResultDocument(stream.getvalue(), sections, title)

    def detail(key, width):
        from .console import Printer

        out, stream = console(width)
        printer = Printer(stream=stream, show_all=True, details=True, summary_limit=0)
        printer.terminal_ui = None
        printer.console = out
        if key == "all":
            printer.finish(summary, include_identity=False)
        elif key.isdecimal() and 1 <= int(key) <= len(findings):
            f = findings[int(key) - 1]
            out.print(Text(clean(f.site) + " · returned details", style=f"bold {ACCENT}"))
            from .reports import display_fields, result_link

            label, explanation, tone = assessment(f)
            out.print(Text(f"{clean(f.query_type).title()}: {clean(f.query)}"))
            out.print(Text("Possible match" if label == "Needs review" else label,
                           style="bold yellow" if tone == "warn" else f"bold {ACCENT}"))
            out.print(Text(clean(explanation)))
            from .continuity import observation_time

            out.print(Text("Observed: " + observation_time(f), style="dim"))
            review = f.extra.get("_analyst_review")
            if isinstance(review, dict):
                out.print(Text("Analyst decision: " + clean(review.get("decision", "unreviewed")), style=f"bold {ACCENT}"))
                if review.get("note"):
                    out.print(Text(clean(review["note"])))
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
            out.print(Text("Project coverage shows shared lookup definitions, not independent confirmations.", style="dim"))
        else:
            out.print(Text("This result is no longer available."))
        return stream.getvalue()

    return overview, detail
