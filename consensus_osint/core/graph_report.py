"""Offline interactive evidence graph. No network assets or ownership inference."""

from __future__ import annotations

import json

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import INFO_CATEGORIES, Status
from .presentation import assessment


def graph_data(summary, include_all=False):
    nodes, edges, ids = [], [], {}

    def node(key, label, kind, details):
        if key not in ids:
            ids[key] = len(nodes)
            nodes.append({"id": len(nodes), "label": str(label), "kind": kind, "details": details})
        return ids[key]

    seen = set()
    for finding in summary.findings:
        if finding.category in INFO_CATEGORIES or (not include_all and finding.status is not Status.FOUND):
            continue
        query = node(
            ("query", finding.query_type, finding.query),
            finding.query,
            "query",
            {"type": finding.query_type, "meaning": "Search input; identity and ownership are unverified"},
        )
        site = node(
            ("site", finding.source, finding.site_id),
            finding.site,
            "site",
            {"source": finding.source, "site_id": finding.site_id},
        )
        # Different query types and providers must never collapse into one person.
        key = (
            "result",
            finding.query_type,
            finding.query,
            finding.source,
            finding.site_id,
            finding.url,
            finding.status.value,
        )
        result = node(
            key,
            # Verdict first, in the wording used by every other view: a long site
            # name is shortened on screen and must not hide what was found.
            assessment(finding)[0] + " · " + finding.site,
            "result",
            {
                "query": finding.query,
                "query_type": finding.query_type,
                "status": finding.status.value,
                "url": finding.url,
                "method": finding.method,
                "source": finding.source,
                "error": finding.error,
                "metadata": finding.extra,
            },
        )
        for edge in ((query, result, "returned evidence"), (result, site, "reported by")):
            if edge not in seen:
                seen.add(edge)
                edges.append({"source": edge[0], "target": edge[1], "label": edge[2]})
    return {"nodes": nodes, "edges": edges}


def render_graph(summary, include_all=False):
    from .sitesdb import DATA_DIR

    env = Environment(
        loader=FileSystemLoader(str(DATA_DIR.parent / "templates")), autoescape=select_autoescape(["html", "j2"])
    )
    # JSON is embedded as text, never executable markup. Escape script terminators
    # and HTML metacharacters even when a provider supplies hostile metadata.
    payload = json.dumps(graph_data(summary, include_all), ensure_ascii=True, allow_nan=False)
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return env.get_template("graph.html.j2").render(graph_json=payload)
