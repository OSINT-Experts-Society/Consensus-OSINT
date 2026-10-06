"""Local session locations: never infer a report was saved or contact a repository."""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .. import __version__
from .branding import PROJECT_REPOSITORY


@dataclass(frozen=True)
class SessionInfo:
    working_folder: Path
    application_folder: Path
    version: str = __version__
    repository: str = PROJECT_REPOSITORY

    @classmethod
    def current(cls):
        return cls(Path.cwd().resolve(), Path(__file__).resolve().parents[1])

    @property
    def report_folder(self):
        return Path(os.environ["CONSENSUS_REPORT_DIR"]).expanduser().resolve() if os.environ.get("CONSENSUS_REPORT_DIR") else self.working_folder / "reports"

    def rows(self, output=None):
        from .signing import check_database

        stamp = check_database()
        if stamp["present"]:
            try:
                updated = date.fromisoformat(stamp["date"])
                catalogue = f"{updated.day} {updated.strftime('%B')} {updated.year}"
            except (ValueError, TypeError):
                catalogue = "Unknown"
        else:
            catalogue = "Unknown"
        if not stamp["verified"]:
            catalogue += " · not verified"
        if stamp.get("stale"):
            catalogue += f" · {stamp['age_days']} days old"
        destination = Path(output).expanduser() if output else self.report_folder
        if not destination.is_absolute():
            destination = self.working_folder / destination
        return [
            ("Version", self.version),
            ("Lookup database updated", catalogue),
            ("Working folder", str(self.working_folder)),
            ("Report file" if output else "Default reports", str(destination.resolve())),
            ("Application files", str(self.application_folder)),
            ("Project repository", self.repository),
        ]
