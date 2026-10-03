"""Small, transient hit summaries; full result evidence remains in the final table."""
from __future__ import annotations

from collections import deque
from threading import RLock

from .models import INFO_CATEGORIES, Status
from .presentation import assessment, enrichment_fields
from .terminal_ui import clean


class HitPreview:
    def __init__(self):
        self.visible = False
        self.hits = deque(maxlen=5)
        self.count = 0
        self.lock = RLock()

    def add(self, finding):
        if finding.status is not Status.FOUND or finding.category in INFO_CATEGORIES:
            return False
        fields = len(enrichment_fields(finding))
        row = (clean(finding.site), clean(finding.query), assessment(finding)[0], fields)
        with self.lock:
            self.hits.append(row)
            self.count += 1
        return True

    def toggle(self):
        with self.lock:
            self.visible = not self.visible

    def text(self, width, limit=5):
        from rich.cells import cell_len
        from rich.text import Text

        with self.lock:
            if not self.visible:
                return ""
            hits = list(self.hits)[-max(1, limit):]
            count = self.count

        def fit(value, columns):
            text = Text(value)
            text.truncate(max(1, columns), overflow="ellipsis")
            return text.plain

        lines = [fit(f"HIT PREVIEW · latest {len(hits)} of {count} · V hides", width)]
        if not hits:
            lines.append(fit("No hits yet. The scan is still running.", width))
        for site, query, verdict, fields in hits:
            # Two bounded rows keep the queried identifier and review verdict
            # visible even in a narrow terminal. Raw enrichment is never echoed.
            site = fit(site, max(1, width // 2 - 2))
            lines.append(site + " · " + fit(query, width - cell_len(site) - 3))
            detail = f"{fields} enriched field" + ("s" if fields != 1 else "") if fields else "No enrichment"
            lines.append(fit(f"  {verdict} · {detail}", width))
        return "\n".join(lines)
