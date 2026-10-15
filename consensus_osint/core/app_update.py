"""Application updates and quiet, bounded startup notices."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import shlex
import subprocess
import sys
import threading
import time
from importlib import metadata
from pathlib import Path

from . import install_manager as manager

_message = ""
_errors = (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError,
           RecursionError, http.client.HTTPException)


def notification():
    """UI-only read: a slow check may finish after the first screen is drawn."""
    return _message


def notice_root(root):
    """Separate pip/checkout state from managed channels and other environments."""
    identity = str(Path(sys.prefix).resolve()) + "\n" + str(Path(__file__).resolve().parent)
    return root / "notices" / hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def update_instruction(*, managed=False):
    if managed:
        return "Run consensus update to install."
    package = Path(__file__).resolve().parents[1]
    # A source checkout (including editable installs) must not be replaced by pip.
    if (package.parent / "pyproject.toml").is_file() or (package.parent / ".git").exists():
        return "Update this source checkout using your existing Git/source workflow."
    try:
        dist = metadata.distribution(manager.PACKAGE)
        direct = json.loads(dist.read_text("direct_url.json") or "{}")
        if direct.get("dir_info", {}).get("editable"):
            return "Update this editable checkout using your existing Git/source workflow."
    except (metadata.PackageNotFoundError, *_errors):
        return "Get the release at https://github.com/OSINT-Experts-Society/Consensus-OSINT/releases/latest."
    parts = [part.lower() for part in Path(sys.prefix).parts]
    if "pipx" in parts and "venvs" in parts:
        return "Run pipx upgrade consensus-osint to install."
    if "uv" in parts and "tools" in parts:
        return "Run uv tool upgrade consensus-osint to install."
    command = [sys.executable, "-m", "pip", "install", "--upgrade", manager.PACKAGE]
    if os.name == "nt":
        return f"In PowerShell, run & {subprocess.list2cmdline(command)} to install."
    return f"Run {shlex.join(command)} to install."


def _save(path, value):
    try:
        manager.atomic_json(path, value)
    except OSError:
        pass  # Notifications must still work with an unwritable cache.


def _whats_new(root, version):
    """Once per installed version, using only the bundled release notes."""
    path = root / "noticed-version.json"
    try:
        if json.loads(path.read_text(encoding="utf-8")).get("version") == version:
            return ""
    except _errors:
        pass
    try:
        notes_path = Path(__file__).resolve().parents[1] / "data" / "release_notes.json"
        if notes_path.stat().st_size > 256 * 1024:
            return ""
        notes = json.loads(notes_path.read_text(encoding="utf-8"))
        if notes["schema"] != 1:
            return ""
        release = next(item for item in notes["releases"] if item["version"] == version)
        counts = {}
        for key in manager.CHANGE_CATEGORIES:
            items = release[key]
            if not isinstance(items, list) or any(not isinstance(item, str) or not item.strip() for item in items):
                return ""
            counts[key] = len(set(items))
        summary = manager.valid_summary(dict(from_version=release["previous_version"],
                                             to_version=version, **counts), version)
        if summary is None:
            return ""
        _save(path, {"version": version})
        return f"What's new in Consensus {version}: " + manager.summary_text(summary, version)
    except (*_errors, StopIteration):
        return ""


def network_problem(exc: Exception) -> str:
    """Put the everyday cause first; library wording such as '<urlopen error ...>' follows for support."""
    import socket
    import urllib.error

    reason = exc.reason if isinstance(exc, urllib.error.URLError) and not isinstance(exc, urllib.error.HTTPError) else exc
    if isinstance(reason, socket.gaierror):
        return f"the server name could not be found. Check your internet connection. ({reason})"
    if isinstance(reason, (TimeoutError, ConnectionError)):
        return f"the server could not be reached. Check your internet connection, proxy or firewall. ({reason})"
    return str(exc)


def command(args) -> int:
    from .. import __version__

    check = getattr(args, "check", False) or getattr(args, "json", False)
    try:
        root = manager.install_root()
        if check:
            latest = (manager.release_for(root) if manager.managed_install(root) else manager.latest_release())["version"]
            managed = manager.managed_install(root)
            _save((root if managed else notice_root(root)) / "update-check.json",
                  {"checked_at": time.time(), "version": latest})
            selected = manager.active_install(root)["version"] if managed else __version__
            restart = selected != __version__
            result = {"installed": selected, "running": __version__, "latest": latest,
                      "restart_required": restart,
                      "newer_available": manager.stable_version(latest) > manager.stable_version(selected)}
            if getattr(args, "json", False):
                print(json.dumps(result))
            else:
                print(f"Installed: {selected}. Latest: {latest}.")
                if result["newer_available"]:
                    print(update_instruction(managed=managed))
                if restart:
                    print(f"This session is running {__version__}. Restart Consensus to use {selected}.")
            return 0
        if not manager.managed_install(root):
            print("This copy is not managed by the Consensus installer. Run the installer from the README "
                  "to enable consensus update. For a development checkout, update with Git and your environment's package manager.", file=sys.stderr)
            return 2
        print("Checking for a Consensus update...", file=sys.stderr)
        if getattr(args, "rollback", False):
            result = manager.rollback(root)
            print(f"Restored Consensus {result['version']}. Restart to apply. Automatic upgrades are paused until your next manual update.")
            return 0
        result = manager.install_release(root, repair=True) if getattr(args, "repair", False) else manager.install_release(
            root, **({"feed": args.feed} if getattr(args, "feed", None) else {}))
        if result["updated"]:
            print(f"Consensus {result['version']} installed. "
                  + manager.summary_text(result.get("summary"), result["version"]))
            print("Restart Consensus to use it.")
        else:
            print(f"Consensus {result['version']} is already installed.")
            if result["version"] != __version__:
                print(manager.summary_text(result.get("summary"), result["version"]))
                print("Restart Consensus to use the installed version.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException, subprocess.SubprocessError) as exc:
        action = "check for a Consensus update" if check else "update Consensus"
        print(f"Could not {action}: {network_problem(exc)}", file=sys.stderr)
        return 1


def _cached(root, now):
    try:
        value = json.loads((root / "update-check.json").read_text(encoding="utf-8"))
        age = now - float(value["checked_at"])
        if 0 <= age < (3600 if value.get("version") else 300):
            if value.get("version") is not None:
                manager.stable_version(value["version"])
            return value
    except _errors:
        pass
    return None


def startup_notice(*, disabled=False, auto_install=False) -> None:
    """Notify interactive runs of every install type; never install into pip/Git.

    Interactive home launches use an isolated automatic updater; direct commands
    only check. At most 150ms is spent waiting for a check-only notice.
    No query or application configuration enters the request.
    """
    global _message
    _message = ""
    if (disabled or os.environ.get("CONSENSUS_NO_UPDATE_CHECK", "").lower() in ("1", "true", "yes")
            or not sys.stdin.isatty() or not sys.stdout.isatty() or not sys.stderr.isatty()):
        return
    try:
        root = manager.install_root()
        managed = manager.managed_install(root)
        from .config import get_config

        defaults = get_config().get("defaults", {})
        if os.environ.get("CONSENSUS_PROXY") or defaults.get("proxy") or defaults.get("tor"):
            return
        if managed and auto_install and os.environ.get("CONSENSUS_AUTO_UPDATE", "1").lower() not in ("0", "false", "no"):
            from .auto_update import start

            start()
            return
        from .. import __version__

        selected = manager.active_install(root)["version"] if managed else __version__
        manager.stable_version(selected)
        cache_root = root if managed else notice_root(root)
        installed_notice = _whats_new(cache_root, __version__) if not managed else ""
        instruction = update_instruction(managed=managed)

        def notice(value):
            newer = ""
            if value and value.get("version") and manager.stable_version(value["version"]) > manager.stable_version(selected):
                newer = f"Update available: Consensus {value['version']}. {instruction}"
            return " ".join(part for part in (installed_notice, newer) if part)

        now = time.time()
        cached = _cached(cache_root, now)
        _message = notice(cached)
        if cached is None:
            def refresh():
                global _message
                value = {"checked_at": now, "version": None}
                try:
                    value["version"] = (manager.release_for(root, timeout=1) if managed
                                        else manager.latest_release(timeout=1))["version"]
                    manager.stable_version(value["version"])
                    _message = notice(value)
                except _errors:
                    value["version"] = None
                _save(cache_root / "update-check.json", value)

            # Cache the attempt too, avoiding repeated requests while offline.
            _save(cache_root / "update-check.json", {"checked_at": now, "version": None})
            worker = threading.Thread(target=refresh, daemon=True, name="consensus-update-check")
            worker.start()
            worker.join(0.15)
        if _message and not auto_install:
            print(_message, file=sys.stderr)
    except _errors:
        # A read-only home, malformed cache or unavailable network must not block work.
        return
