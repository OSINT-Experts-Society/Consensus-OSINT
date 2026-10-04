"""Non-blocking managed updates, isolated from the running application."""
from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import threading
import time

from . import install_manager as manager

CHECK_INTERVAL = 3600
_message = ""
_started = False
_guard = threading.Lock()
_errors = (OSError, ValueError, KeyError, TypeError, RuntimeError,
           RecursionError, http.client.HTTPException, subprocess.SubprocessError)


def notification():
    """Read-only UI status; never performs network or disk work during redraw."""
    return _message


def _text(event):
    if not isinstance(event, dict):
        raise ValueError("Invalid update event")
    state = event.get("state")
    if state in ("installing", "installed", "ready"):
        version = event["version"]
        manager.stable_version(version)
        if state == "installing":
            return f"Installing Consensus {version} in the background…"
        if state == "installed":
            return f"Consensus {version} installed. Restart Consensus to use it."
        return f"Updated to Consensus {version}."
    if state == "failed":
        return "Automatic update could not finish. Run consensus update to retry."
    return ""


def start():
    """Called only after startup's terminal, opt-out and proxy checks."""
    global _message, _started
    with _guard:
        if _started:
            return
        root = manager.install_root()
        if not manager.managed_install(root):
            return
        from .. import __version__

        state = manager.active_install(root)
        if manager.stable_version(state["version"]) > manager.stable_version(__version__):
            _message = _text({"state": "installed", "version": state["version"]})
            return
        options = ({"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
                   if os.name == "nt" else {"start_new_session": True})
        # A separate interpreter survives closing the app and never replaces
        # the running environment or its Windows executable. No console popup.
        child = subprocess.Popen(
            [sys.executable, "-I", "-m", "consensus_osint.core.auto_update"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", env=dict(manager.clean_environment(root),
                                                 CONSENSUS_INSTALL_DIR=str(root)), **options)
        _started = True
        _message = "Checking for updates…"

    def monitor():
        global _message
        try:
            with child.stdout:
                for line in child.stdout:
                    _message = _text(json.loads(line))
            if child.wait():
                _message = _text({"state": "failed"})
        except _errors:
            _message = _text({"state": "failed"})
            child.wait()

    threading.Thread(target=monitor, daemon=True, name="consensus-auto-update-status").start()


def perform(root, emit):
    """Worker contract; installer verifies the download and activation first."""
    if not manager.managed_install(root):
        return
    from .. import __version__

    cache_path = root / "auto-update.json"
    now = time.time()
    try:
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        if not isinstance(cached, dict):
            raise ValueError("Invalid update cache")
        version = cached.get("version")
        if version:
            manager.stable_version(version)
        if cached.get("state") == "installed" and version == __version__:
            emit({"state": "ready", "version": version})
            manager.atomic_json(cache_path, dict(cached, state="current"))
            return
        if 0 <= now - float(cached["checked_at"]) < CHECK_INTERVAL:
            emit({"state": "current"})
            return
    except _errors:
        pass
    event = {"state": "current", "checked_at": now}
    installing = False
    try:
        release = manager.latest_release(timeout=5)
        active = manager.active_install(root)
        if manager.stable_version(release["version"]) > manager.stable_version(active["version"]):
            installing = True
            emit({"state": "installing", "version": release["version"]})
            result = manager.install_release(root)
            event.update(state="installed", version=result["version"])
        elif manager.stable_version(active["version"]) > manager.stable_version(__version__):
            event.update(state="installed", version=active["version"])
        try:
            manager.atomic_json(cache_path, event)
        except OSError:
            pass
        emit(event)
    except _errors:
        # Network/check failures stay quiet. A failed attempted installation
        # gets an actionable notice, and the verified old environment remains.
        event = {"state": "failed" if installing else "current", "checked_at": now}
        try:
            manager.atomic_json(cache_path, event)
        except OSError:
            pass
        emit(event)


if __name__ == "__main__":
    def publish(event):
        try:
            print(json.dumps(event), flush=True)
        except OSError:
            pass  # The user may already have closed the original terminal.

    try:
        perform(manager.install_root(), publish)
    except _errors:
        publish({"state": "failed"})
