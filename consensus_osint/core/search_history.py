"""Opt-in, bounded local result snapshots. No network and no shared identifiers."""
from __future__ import annotations

import json
import math
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
        for name, expected in (("queries", list), ("options", dict)):
            if name in value and not isinstance(value[name], expected):
                raise ValueError(f"Invalid saved search {name}")
        for name in ("started", "finished"):
            number = value.get(name)
            if number is None and (name == "finished" or name not in value):
                continue
            try:
                valid = type(number) in (int, float) and math.isfinite(number)
            except OverflowError:
                valid = False
            if not valid:
                raise ValueError(f"Invalid saved search {name}")
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
        session.printer.message("Number: open · on/off: retention · delete N: remove one · clear: delete all · 0 / Esc: back")
        choice = session.back_prompt("History: ", zero=True).strip().lower()
        if choice in ("", "0", "back", "cancel"):
            return
        if choice == "on":
            if session.back_prompt("Store future searches locally? [y/N]: ").strip().lower() in ("y", "yes"):
                history.enable(True)
        elif choice == "off":
            history.enable(False)
            session.printer.message("Retention is off. Use clear to delete previously stored searches.")
        elif choice == "clear":
            if session.back_prompt("Delete all locally saved searches? [y/N]: ").strip().lower() in ("y", "yes"):
                history.clear()
                session.forget_saved_record("history")
        else:
            delete = choice.startswith("delete ")
            number = choice[7:].strip() if delete else choice
            if not number.isdecimal() or not 1 <= int(number) <= len(entries):
                session.printer.message("Choose an available search number or action.")
                continue
            key, _ = entries[int(number)-1]
            if delete:
                history.delete(key)
                session.forget_saved_record("history", key)
            else:
                previous = session.latest
                ui = session.printer.terminal_ui
                filters = ui.result_filters if ui else None
                saved = None
                try:
                    opened = history.load(key)
                    if not session.confirm_leave():
                        continue
                    saved = session._saved_summary, session._saved_location, session._saved_record
                    session.latest = opened
                    session.mark_saved(session.latest, "local history (last 10 searches)", record=("history", key))
                    if session.printer.terminal_ui:
                        session.printer.terminal_ui.result_filters = {}
                    session.show_latest()
                    return True
                except (OSError, ValueError, TypeError, KeyError, RecursionError, AttributeError, OverflowError):
                    session.latest = previous
                    if saved is not None:
                        session._saved_summary, session._saved_location, session._saved_record = saved
                    if ui:
                        ui.result_filters = filters
                        ui.result_save_status = "Saved" if session._saved_summary is previous else "Unsaved"
                    session.printer.warn("This saved search cannot be opened. You can delete it from history.")
