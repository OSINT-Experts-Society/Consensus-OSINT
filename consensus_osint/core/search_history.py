"""Opt-in, bounded local result snapshots. No network and no shared identifiers."""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

from .install_manager import atomic_json
from .models import Finding, ScanSummary

MAX_BYTES = 32 * 1024 * 1024
KEEP = 10


class SearchHistory:
    def __init__(self, root=None):
        if root is None:
            from .sitesdb import user_config_dir

            root = user_config_dir()
        self.root = Path(root)
        self.folder = self.root / "history"
        self.preferences = self.root / "history-settings.json"

    def enabled(self):
        try:
            return json.loads(self.preferences.read_text(encoding="utf-8")).get("enabled") is True
        except (OSError, ValueError, AttributeError):
            return False

    def enable(self, enabled):
        atomic_json(self.preferences, {"enabled": bool(enabled)})

    def path(self, key):
        if not re.fullmatch(r"[a-f0-9]{32}", key):
            raise ValueError("Invalid saved search")
        path = self.folder / (key + ".json")
        if path.resolve().parent != self.folder.resolve():
            raise ValueError("Saved search points outside its folder")
        return path

    def save(self, summary):
        if not self.enabled():
            return None
        value = summary.to_dict()  # Redacts credential metadata using report contracts.
        if len(json.dumps(value).encode("utf-8")) > MAX_BYTES:
            raise ValueError("Search exceeds local history size limit; save a report instead")
        key = uuid.uuid4().hex
        atomic_json(self.path(key), value)
        from .reports import group_by_query

        atomic_json(self.path(key).with_suffix(".meta"), {
            "title": ", ".join(v.title for v in group_by_query(summary)), "found": len(summary.found),
            "partial": bool(summary.options.get("interrupted")), "saved_at": summary.finished or summary.started})
        for path in self.files()[KEEP:]:
            self.delete(path.stem)
        return key

    def files(self):
        if not self.folder.is_dir():
            return []
        return sorted((p for p in self.folder.glob("*.json") if re.fullmatch(r"[a-f0-9]{32}", p.stem)
                       and not p.is_symlink()), key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)

    def load(self, key):
        path = self.path(key)
        if path.stat().st_size > MAX_BYTES:
            raise ValueError("Saved search exceeds size limit")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or not isinstance(value.get("findings"), list):
            raise ValueError("Invalid saved search")
        return ScanSummary(queries=value.get("queries", []), started=value.get("started", 0),
                           finished=value.get("finished"), options=value.get("options", {}),
                           findings=[Finding.from_dict(f) for f in value["findings"]])

    def entries(self):
        entries = []
        for path in self.files():
            try:
                metadata = path.with_suffix(".meta")
                if metadata.is_symlink() or metadata.stat().st_size > 65536:
                    raise ValueError("Invalid history label")
                value = json.loads(metadata.read_text(encoding="utf-8"))
                if not isinstance(value, dict):
                    raise ValueError("Invalid history label")
                entries.append((path.stem, value))
            except (OSError, ValueError, TypeError, KeyError, RecursionError):
                entries.append((path.stem, {"title": "Saved search (open to inspect)", "found": "—"}))
        return entries

    def delete(self, key):
        self.path(key).unlink(missing_ok=True)
        self.path(key).with_suffix(".meta").unlink(missing_ok=True)

    def clear(self):
        for path in self.files():
            self.delete(path.stem)


def screen(session):
    history = SearchHistory()
    while True:
        entries = history.entries()
        rows = [["Open", "Saved search", "Matches"]]
        for i, (_, value) in enumerate(entries, 1):
            rows.append([str(i), str(value.get("title", "Saved search")) + (" · partial" if value.get("partial") else ""),
                         str(value.get("found", "—"))])
        session.printer.summary_table(rows, "Recent searches · local history " + ("ON" if history.enabled() else "OFF"))
        session.printer.message("Keeps up to 10 searches, including identifiers and returned fields, on this computer. Saved reports are separate.")
        session.printer.message("Number: open · on/off: retention · delete N: remove one · clear: delete all · 0: back")
        choice = session.read("History: ").strip().lower()
        if choice in ("", "0", "back", "cancel"):
            return
        if choice == "on":
            if session.read("Store future searches locally? [y/N]: ").strip().lower() in ("y", "yes"):
                history.enable(True)
        elif choice == "off":
            history.enable(False)
            session.printer.message("Retention is off. Use clear to delete previously stored searches.")
        elif choice == "clear":
            if session.read("Delete all locally saved searches? [y/N]: ").strip().lower() in ("y", "yes"):
                history.clear()
        else:
            delete = choice.startswith("delete ")
            number = choice[7:].strip() if delete else choice
            if not number.isdecimal() or not 1 <= int(number) <= len(entries):
                session.printer.message("Choose an available search number or action.")
                continue
            key, _ = entries[int(number)-1]
            if delete:
                history.delete(key)
            else:
                try:
                    session.latest = history.load(key)
                    session.show_latest()
                    return
                except (OSError, ValueError, TypeError, KeyError, RecursionError):
                    session.printer.warn("This saved search cannot be opened. You can delete it from history.")
