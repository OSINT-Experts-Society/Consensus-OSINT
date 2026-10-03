"""Bounded, ephemeral MCP result retrieval; no report data is written to disk."""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections import Counter, OrderedDict
from dataclasses import dataclass

from .models import Status, as_json_safe

MAX_REPLY_BYTES = 24_000
MAX_CHUNK_BYTES = 4_096
STATUSES = {status.value for status in Status}


def encode(value) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True)
class _Scan:
    document: str
    offsets: tuple[tuple[int, int], ...]
    statuses: tuple[str, ...]
    previews: dict[int, str]
    created: float
    digest: str


class ResultStore:
    """Opaque IDs grant access to one scan; each server owns its own store.

    Retain up to eight scans / 128 MiB for an hour. Oldest scans are discarded
    when capacity is needed. Expiry is enforced on access; cleanup is lazy.
    All stored JSON is ASCII-escaped, so byte and character offsets agree and
    chunks can be concatenated losslessly even across Unicode escape sequences.
    """

    def __init__(self, *, max_scans=8, max_bytes=128 * 1024 * 1024, ttl=3600, clock=time.monotonic):
        if max_scans < 1 or max_bytes < 1 or ttl <= 0:
            raise ValueError("result cache limits must be positive")
        self.max_scans, self.max_bytes, self.ttl = max_scans, max_bytes, ttl
        self._clock = clock
        self._scans: OrderedDict[str, _Scan] = OrderedDict()
        self._bytes = 0

    def _discard(self, scan_id):
        scan = self._scans.pop(scan_id)
        self._bytes -= len(scan.document)

    def _expire(self):
        now = self._clock()
        for scan_id, scan in list(self._scans.items()):
            if now - scan.created >= self.ttl:
                self._discard(scan_id)

    def close(self):
        self._scans.clear()
        self._bytes = 0

    def add(self, result: dict) -> str:
        """Detach a complete redacted snapshot, without silently dropping rows."""
        safe = as_json_safe(result)
        if not isinstance(safe, dict) or not isinstance(safe.get("findings"), list):
            raise ValueError("scan result must contain a findings array")
        findings = safe.pop("findings")
        statuses = tuple(row.get("status") if isinstance(row, dict) else None for row in findings)
        if any(not isinstance(status, str) or status not in STATUSES for status in statuses):
            raise ValueError("each finding must have a recognised status")
        # Serialize the header and each row exactly once; offsets address the
        # original row, not a preview or a later re-interpretation of its fields.
        header = encode(safe)
        chunks = [header[:-1] + ("," if safe else "") + '"findings":[']
        position = len(chunks[0])
        offsets, previews = [], {}
        for i, row in enumerate(findings):
            if i:
                chunks.append(",")
                position += 1
            raw = encode(row)
            if len(raw) > MAX_REPLY_BYTES - 4000:
                preview = {key: str(row[key])[:200] for key in
                           ("query", "query_type", "site", "site_id", "status") if key in row}
                interpretation = row.get("interpretation")
                if isinstance(interpretation, dict):
                    preview["interpretation"] = {key: str(interpretation[key])[:500] for key in
                                                 ("label", "explanation") if key in interpretation}
                previews[i] = encode(preview)
            offsets.append((position, len(raw)))
            chunks.append(raw)
            position += len(raw)
            if position + 2 > self.max_bytes:
                raise ValueError("scan exceeds the MCP result cache size limit; narrow the scan scope")
        chunks.append("]}")
        document = "".join(chunks)
        if len(document) > self.max_bytes:
            raise ValueError("scan exceeds the MCP result cache size limit; narrow the scan scope")
        self._expire()
        while self._scans and (len(self._scans) >= self.max_scans or self._bytes + len(document) > self.max_bytes):
            self._discard(next(iter(self._scans)))
        scan_id = secrets.token_urlsafe(32)
        self._scans[scan_id] = _Scan(document, tuple(offsets), statuses, previews, self._clock(),
                                    hashlib.sha256(document.encode("ascii")).hexdigest())
        self._bytes += len(document)
        return scan_id

    def _get(self, scan_id: str) -> _Scan:
        self._expire()
        try:
            return self._scans[scan_id]
        except KeyError:
            raise ValueError("unknown, expired or released scan ID; run a new scan") from None

    def page(self, scan_id: str, *, offset: int = 0, limit: int = 20, status: str | None = None) -> dict:
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("offset must be nonnegative; limit must be between 1 and 100")
        if status is not None and status not in STATUSES:
            raise ValueError("status must be a recorded outcome such as found, unknown or error")
        scan = self._get(scan_id)
        total = len(scan.offsets)
        if offset > total:
            raise ValueError("offset is beyond the last finding")
        page = {
            "scan_id": scan_id, "counts": dict(Counter(scan.statuses)), "total_findings": total,
            "status_filter": status, "offset": offset, "next_offset": None, "findings": [],
            "full_report": {"bytes": len(scan.document), "sha256": scan.digest,
                            "tool": "read_scan_chunk", "encoding": "ASCII-escaped JSON"},
            "retention": {"expires_in_seconds": max(0, int(self.ttl - (self._clock() - scan.created))),
                          "maximum_cached_scans": self.max_scans,
                          "note": "Memory only; oldest scans may be evicted earlier when the cache is full."},
        }
        for index in range(offset, total):
            if status is not None and scan.statuses[index] != status:
                continue
            if len(page["findings"]) >= limit:
                page["next_offset"] = index
                break
            start, length = scan.offsets[index]
            if index in scan.previews:
                entry = {"index": index, "complete": False,
                         "finding": json.loads(scan.previews[index]),
                         "detail_offset": start, "detail_bytes": length,
                         "note": "Preview only. Retrieve the complete finding with read_scan_chunk using these byte offsets."}
            else:
                row = json.loads(scan.document[start:start + length])
                entry = {"index": index, "complete": True, "finding": row}
            page["findings"].append(entry)
            page["next_offset"] = index + 1  # Include the cursor in the size check.
            if len(encode(page)) > MAX_REPLY_BYTES:
                page["findings"].pop()
                page["next_offset"] = index
                break
        else:
            page["next_offset"] = None
        return page

    def chunk(self, scan_id: str, *, offset: int = 0, length: int = MAX_CHUNK_BYTES) -> dict:
        if type(offset) is not int or offset < 0 or type(length) is not int or not 1 <= length <= MAX_CHUNK_BYTES:
            raise ValueError(f"offset must be nonnegative; length must be between 1 and {MAX_CHUNK_BYTES}")
        scan = self._get(scan_id)
        if offset > len(scan.document):
            raise ValueError("offset is beyond the JSON document")
        end = min(offset + length, len(scan.document))
        return {"scan_id": scan_id, "offset": offset, "next_offset": end if end < len(scan.document) else None,
                "total_bytes": len(scan.document), "sha256": scan.digest, "fragment": scan.document[offset:end],
                "note": "Concatenate fragments in offset order, then parse JSON; individual fragments may split a JSON value."}

    def release(self, scan_id: str) -> dict:
        self._get(scan_id)
        self._discard(scan_id)
        return {"scan_id": scan_id, "released": True}
