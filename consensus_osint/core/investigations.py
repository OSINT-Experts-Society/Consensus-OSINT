"""Explicitly saved local investigations, separate from automatic search history."""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from pathlib import Path

from .continuity import clone_summary, identity, load_summary
from .install_manager import atomic_json

MAX_BYTES = 32 * 1024 * 1024
MAX_SEARCHES = 100


def text(value, limit, label):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError(f"Invalid {label}; use at most {limit} characters.")
    return value.strip()


def result_key(finding):
    return hashlib.sha256(json.dumps(identity(finding), ensure_ascii=True).encode()).hexdigest()


class Investigations:
    def __init__(self, root=None):
        if root is None:
            from .sitesdb import user_config_dir
            root = user_config_dir()
        self.folder = Path(root) / "investigations"

    def path(self, key):
        if not isinstance(key, str) or not re.fullmatch(r"[a-f0-9]{32}", key):
            raise ValueError("Invalid investigation")
        if self.folder.is_symlink():
            raise ValueError("Investigation folder cannot be a link")
        path = self.folder / (key + ".json")
        if path.is_symlink() or path.resolve().parent != self.folder.resolve():
            raise ValueError("Investigation points outside its folder")
        return path

    def create(self, name):
        name = text(name, 120, "investigation name")
        if not name:
            raise ValueError("Enter an investigation name")
        key = uuid.uuid4().hex
        self.write(key, {"schema": 1, "name": name, "notes": "", "created": time.time(),
                         "searches": [], "reviews": {}})
        return key

    def write(self, key, value):
        if len(json.dumps(value, ensure_ascii=True).encode()) > MAX_BYTES:
            raise ValueError("Investigation exceeds the local size limit; start another investigation.")
        atomic_json(self.path(key), value)

    def read(self, key):
        path = self.path(key)
        if path.stat().st_size > MAX_BYTES:
            raise ValueError("Investigation exceeds the local size limit")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise ValueError("Invalid investigation format")
        if not text(value.get("name"), 120, "investigation name"):
            raise ValueError("Invalid investigation name")
        text(value.get("notes"), 20000, "notes")
        searches, reviews = value.get("searches"), value.get("reviews")
        if not isinstance(searches, list) or len(searches) > MAX_SEARCHES or not isinstance(reviews, dict):
            raise ValueError("Invalid investigation records")
        for snapshot in searches:
            if not isinstance(snapshot, dict) or not isinstance(snapshot.get("findings"), list):
                raise ValueError("Invalid investigation snapshot")
            # Validate identifiers and metadata here; construct and validate
            # findings only for the snapshot being opened, not every menu draw.
            load_summary({**snapshot, "findings": []})
        for key, review in reviews.items():
            if not re.fullmatch(r"[a-f0-9]{64}", key) or not isinstance(review, dict):
                raise ValueError("Invalid investigation review")
            if review.get("decision") not in ("unreviewed", "relevant", "unrelated"):
                raise ValueError("Invalid investigation decision")
            text(review.get("note"), 2000, "review note")
        return value

    def entries(self):
        if not self.folder.exists():
            return []
        entries = []
        for path in sorted(self.folder.glob("*.json")):
            try:
                value = self.read(path.stem)
                entries.append((path.stem, value["name"], len(value["searches"])))
            except (ValueError, OSError, TypeError, OverflowError, RecursionError):
                entries.append((path.stem, "Unreadable investigation", 0))
        return entries

    def save(self, key, summary):
        value = self.read(key)
        if len(value["searches"]) >= MAX_SEARCHES:
            raise ValueError("This investigation contains 100 searches. Start another to retain more.")
        snapshot = clone_summary(summary)
        snapshot.options.pop("investigation", None)
        for finding in snapshot.findings:
            finding.extra.pop("_analyst_review", None)
        value["searches"].append(snapshot.to_dict())
        self.write(key, value)

    def open_search(self, key, index=-1):
        value = self.read(key)
        if not value["searches"]:
            raise ValueError("This investigation has no saved searches yet.")
        try:
            summary = load_summary(value["searches"][index])
        except IndexError:
            raise ValueError("Choose an available search") from None
        summary.options["investigation"] = {"name": value["name"], "notes": value["notes"]}
        for finding in summary.findings:
            review = value["reviews"].get(result_key(finding))
            if review:
                finding.extra["_analyst_review"] = dict(review)
        return summary

    def update(self, key, *, name=None, notes=None):
        value = self.read(key)
        if name is not None:
            name = text(name, 120, "investigation name")
            if not name:
                raise ValueError("Enter an investigation name")
            value["name"] = name
        if notes is not None:
            value["notes"] = text(notes, 20000, "notes")
        self.write(key, value)

    def review(self, key, finding, decision, note=""):
        if decision not in ("unreviewed", "relevant", "unrelated"):
            raise ValueError("Choose unreviewed, relevant or unrelated")
        value = self.read(key)
        value["reviews"][result_key(finding)] = {"decision": decision, "note": text(note, 2000, "review note")}
        self.write(key, value)

    def delete(self, key):
        self.path(key).unlink()
