"""Locally bundled project marks with original source and licence notices."""
import base64
import json
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def _logos():
    folder = Path(__file__).resolve().parents[1] / "templates"
    manifest = json.loads((folder / "tool-logos.json").read_text(encoding="utf-8"))
    return {source: {**row, "uri": "data:image/png;base64," + base64.b64encode((folder / row["file"]).read_bytes()).decode("ascii")}
            for source, row in manifest.items()}


def report_logos(findings):
    from .provenance import repository_coverage

    sources = {row["id"] for finding in findings for row in repository_coverage(finding)}
    return {source: row for source, row in _logos().items() if source in sources}
