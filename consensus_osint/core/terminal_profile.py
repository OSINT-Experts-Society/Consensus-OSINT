"""Optional per-user Windows Terminal profile, isolated from existing settings.

Local fragment images require Windows Terminal 1.24 or later. Installation is an
explicit command, never an import/startup side effect. No shell scripts are run.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .branding import ACCENT

PROFILE_GUID = "{d7b9ce0a-e468-5103-98a0-1fad7bf9a673}"
MARKER = "Consensus terminal profile v1"


def profile_folder():
    if sys.platform != "win32":
        raise ValueError("The branded tab profile is available in Windows Terminal 1.24 or later on Windows.")
    local = os.environ.get("LOCALAPPDATA")
    if not local or not Path(local).is_absolute():
        raise ValueError("Windows LOCALAPPDATA is unavailable; the profile location could not be determined.")
    return Path(local) / "Microsoft" / "Windows Terminal" / "Fragments" / "Consensus"


def _owned(data):
    return (isinstance(data, dict) and data.get("_consensus") == MARKER
            and isinstance(data.get("profiles"), list) and len(data["profiles"]) == 1
            and isinstance(data["profiles"][0], dict) and data["profiles"][0].get("guid") == PROFILE_GUID)


def _replace(path, content):
    # A unique sibling and atomic replace also avoid following an existing file symlink.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".consensus-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def install():
    folder = profile_folder()
    path = folder / "consensus.json"
    icon = Path(__file__).resolve().parents[1] / "templates" / "consensus-icon.png"
    image = icon.read_bytes()
    data = {"_consensus": MARKER, "profiles": [{
        "guid": PROFILE_GUID, "name": "Consensus", "tabTitle": "◈ Consensus",
        "commandline": subprocess.list2cmdline([sys.executable, "-m", "consensus_osint.cli", "shell"]),
        "startingDirectory": str(Path.home()), "icon": "consensus-icon.png", "tabColor": ACCENT,
    }]}
    if path.exists():
        previous = json.loads(path.read_text(encoding="utf-8"))
        if not _owned(previous):
            raise ValueError("The Consensus profile location contains an unrecognised file; it was left untouched.")
        # Preserve any profile customizations, updating only the installed runtime.
        previous["profiles"][0]["commandline"] = data["profiles"][0]["commandline"]
        data = previous
    folder.mkdir(parents=True, exist_ok=True)
    # The icon is written first; the JSON only appears once its image is ready.
    _replace(folder / "consensus-icon.png", image)
    _replace(path, (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    return path.resolve()


def remove():
    path = profile_folder() / "consensus.json"
    if not path.exists():
        return False
    if not _owned(json.loads(path.read_text(encoding="utf-8"))):
        raise ValueError("The profile file is not recognised as Consensus's; it was left untouched.")
    path.unlink()
    # Remove only the known image if it still matches the bundled original.
    icon = path.with_name("consensus-icon.png")
    original = Path(__file__).resolve().parents[1] / "templates" / icon.name
    if icon.is_file() and icon.read_bytes() == original.read_bytes():
        icon.unlink()
    return True


def command(arguments, printer):
    if len(arguments) > 1 or arguments and arguments[0] not in {"show", "install", "remove"}:
        raise ValueError("Use terminal [show|install|remove].")
    action = arguments[0] if arguments else "show"
    if action == "install":
        path = install()
        printer.message("Consensus tab profile installed: " + str(path))
        printer.message("Open Windows Terminal's new-tab dropdown and choose Consensus. "
                        "Restart Windows Terminal if the profile is not listed. Local icons require version 1.24 or later.")
    elif action == "remove":
        printer.message("Consensus tab profile removed." if remove() else "No Consensus tab profile is installed.")
    else:
        path = profile_folder() / "consensus.json"
        printer.message("Windows Terminal profile: " + ("installed" if path.exists() else "not installed"))
        printer.message("Profile file: " + str(path))
        printer.message("Use /terminal install to add a Consensus tab with its own logo; /terminal remove removes it. "
                        "Outside the session use consensus terminal install. Requires Windows Terminal 1.24 or later. "
                        "Existing tabs retain their original profile icon.")
    return 0
