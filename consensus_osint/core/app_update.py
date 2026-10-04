"""Application updates and quiet, bounded startup notices."""
from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import threading
import time

from . import install_manager as manager


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
            latest = manager.latest_release()["version"]
            selected = manager.active_install(root)["version"] if manager.managed_install(root) else __version__
            restart = selected != __version__
            result = {"installed": selected, "running": __version__, "latest": latest,
                      "restart_required": restart,
                      "newer_available": manager.stable_version(latest) > manager.stable_version(selected)}
            if getattr(args, "json", False):
                print(json.dumps(result))
            else:
                print(f"Installed: {selected}. Latest: {latest}.")
                if result["newer_available"]:
                    print("Run consensus update to install the update.")
                if restart:
                    print(f"This session is running {__version__}. Restart Consensus to use {selected}.")
            return 0
        if not manager.managed_install(root):
            print("This copy is not managed by the Consensus installer. Run the installer from the README "
                  "to enable consensus update. For a development checkout, update with Git and your environment's package manager.", file=sys.stderr)
            return 2
        print("Checking for a Consensus update...", file=sys.stderr)
        result = manager.install_release(root)
        if result["updated"]:
            print(f"Consensus {result['version']} installed. Restart Consensus to use it.")
        else:
            print(f"Consensus {result['version']} is already installed.")
            if result["version"] != __version__:
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
        if 0 <= age < 86400:
            if value.get("version") is not None:
                manager.stable_version(value["version"])
            return value
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        pass
    return None


def startup_notice(*, disabled=False, auto_install=False) -> None:
    """Only interactive, managed runs check. Never print from the worker thread.

    Interactive home launches use an isolated automatic updater; direct commands
    only check. At most 150ms is spent waiting for a check-only notice.
    No query or application configuration enters the request.
    """
    if (disabled or os.environ.get("CONSENSUS_NO_UPDATE_CHECK", "").lower() in ("1", "true", "yes")
            or not sys.stdin.isatty() or not sys.stdout.isatty() or not sys.stderr.isatty()):
        return
    try:
        root = manager.install_root()
        if not manager.managed_install(root):
            return
        from .config import get_config

        defaults = get_config().get("defaults", {})
        if os.environ.get("CONSENSUS_PROXY") or defaults.get("proxy") or defaults.get("tor"):
            return
        if auto_install and os.environ.get("CONSENSUS_AUTO_UPDATE", "1").lower() not in ("0", "false", "no"):
            from .auto_update import start

            start()
            return
        now = time.time()
        cached = _cached(root, now)
        if cached is None:
            def refresh():
                value = {"checked_at": now, "version": None}
                try:
                    value["version"] = manager.latest_release(timeout=1)["version"]
                except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
                    pass
                try:
                    manager.atomic_json(root / "update-check.json", value)
                except OSError:
                    pass

            # Cache the attempt too, avoiding repeated requests while offline.
            manager.atomic_json(root / "update-check.json", {"checked_at": now, "version": None})
            worker = threading.Thread(target=refresh, daemon=True, name="consensus-update-check")
            worker.start()
            worker.join(0.15)
            cached = _cached(root, now)
        if cached and cached.get("version"):
            state = manager.active_install(root)
            if manager.stable_version(cached["version"]) > manager.stable_version(state["version"]):
                print(f"Update available: Consensus {cached['version']}. Run consensus update to install.", file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        # A read-only home, malformed cache or unavailable network must not block work.
        return
