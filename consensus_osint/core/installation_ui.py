"""User-facing installation status, migration and recovery actions."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from .. import __version__
from . import install_manager as manager


def status(root):
    managed = manager.managed_install(root)
    state = manager.active_install(root) if managed else None
    from .auto_update import notification
    from .session_info import SessionInfo

    rows = [["Running version", __version__], ["Installed version", state["version"] if managed else __version__],
            ["Installation", "Managed" if managed else "Source / Python environment"],
            ["Update source", state.get("channel", "Public releases") if managed else "Switch to managed installation to enable updates"],
            ["Lookup database", dict(SessionInfo.current().rows())["Lookup database updated"]]]
    latest, checked = None, 0
    for name in ("update-check.json", "auto-update.json"):
        try:
            value = json.loads((root / name).read_text(encoding="utf-8"))
            when = float(value.get("checked_at", 0))
            if checked < when <= time.time() + 300:
                checked, latest = when, value.get("version")
        except (OSError, ValueError, TypeError, AttributeError):
            pass
    rows += [["Last checked", datetime.fromtimestamp(checked).strftime("%d %b %Y %H:%M") if checked else "Not checked"],
             ["Available version", latest or "Unknown — choose Check now"],
             ["Status", notification() or ("Restart to apply installed version" if managed and
                                           (state["version"] != __version__ or state["environment"] != Path(sys.prefix).name) else "Ready")]]
    if state and managed:
        rows.append(["Automatic updates", "Paused after rollback; install manually to resume" if state.get("auto_update_paused")
                     else "Off" if os.environ.get("CONSENSUS_NO_UPDATE_CHECK") else
                     "Notify only" if os.environ.get("CONSENSUS_AUTO_UPDATE") == "0" else "On at startup"])
        if state.get("summary"):
            rows.append(["Changes", manager.summary_text(state["summary"], state["version"])])
    return rows


def migrate(root, bundle, config_dir, reports_dir):
    """Explicit action; bootstrap in a separate runtime, preserving user files."""
    folder = Path(bundle).expanduser().resolve(strict=True)
    manager.bundle_release(folder)
    env = dict(manager.clean_environment(root), CONSENSUS_INSTALL_DIR=str(root),
               CONSENSUS_HOME=str(config_dir), CONSENSUS_REPORT_DIR=str(reports_dir))
    from importlib.metadata import PackageNotFoundError, version

    extras = list(manager.EXTRAS)
    for package, extra in (("mcp", "mcp"), ("playwright", "browser")):
        try:
            version(package)
            extras.append(extra)
        except PackageNotFoundError:
            pass
    env["CONSENSUS_INSTALL_EXTRAS"] = ",".join(extras)
    if os.name == "nt":
        command = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(folder / "install.ps1"),
                   "-BundlePath", str(folder), "-ConfigDirectory", str(config_dir), "-ReportsDirectory", str(reports_dir)]
    else:
        command = ["sh", str(folder / "install.sh"), str(folder)]
    subprocess.run(command, env=env, check=True)
    if not manager.active_install(root):
        raise ValueError("Installer did not activate a managed version")


def restart():
    root = manager.install_root()
    state = manager.active_install(root)
    if not state:
        raise ValueError("No managed installation is ready")
    python = manager.environment_python(root / "versions" / state["environment"])
    environment = dict(manager.clean_environment(root), CONSENSUS_INSTALL_DIR=str(root))
    environment.update(state.get("user_environment", {}))
    # Called only after the current full-screen application has restored the terminal.
    os.execve(str(python), [str(python), "-I", "-m", "consensus_osint.cli"], environment)


def screen(session):
    root = manager.install_root()
    while True:
        session.printer.summary_table([["Updates", "Details"], *status(root)], "Installation & updates")
        managed = manager.managed_install(root)
        session.printer.message("1 Check now · 2 Install update · 3 Restart\n4 Repair · 5 Restore previous · 6 Choose bundle"
                                if managed else "1 Check public release · 6 Switch to managed installation")
        session.printer.message("0 Back")
        choice = session.read("Updates: ").strip().lower()
        if choice in ("", "0", "back", "cancel"):
            return
        try:
            if choice == "1":
                release = manager.release_for(root) if managed else manager.latest_release()
                manager.atomic_json(root / "update-check.json", {"checked_at": time.time(), "version": release["version"]})
                session.printer.message("Available version: " + release["version"])
            elif choice == "6":
                bundle = session.read("Extracted install bundle folder (Enter cancels): ").strip().strip('"')
                if not bundle:
                    continue
                release = manager.bundle_release(bundle)
                session.printer.message(f"Install Consensus {release['version']} from {bundle}. Settings and reports remain in place.")
                if session.read("Continue? [y/N]: ").strip().lower() not in ("y", "yes"):
                    continue
                if managed:
                    manager.install_release(root, feed=bundle)
                else:
                    from .session_info import SessionInfo
                    from .sitesdb import user_config_dir

                    info = session.printer.terminal_ui.info if session.printer.terminal_ui else SessionInfo.current()
                    migrate(root, bundle, user_config_dir().resolve(), info.report_folder)
                    session.printer.message(f"Managed installation ready. Start with {root / 'bin' / ('consensus.cmd' if os.name == 'nt' else 'consensus')}")
                    session.printer.message("Switching closes this session. Save results first if local history is off.")
                    if session.read("Switch to it now? [y/N]: ").strip().lower() in ("y", "yes"):
                        session.restart_requested = True
                        return
            elif managed and choice == "2":
                result = manager.install_release(root)
                session.printer.message(manager.summary_text(result.get("summary"), result["version"]) + " Restart to apply.")
            elif managed and choice == "3":
                session.printer.message("Restart closes this session. Save results first if local history is off.")
                if session.read("Restart now? [y/N]: ").strip().lower() in ("y", "yes"):
                    session.restart_requested = True
                    return
            elif managed and choice in ("4", "5"):
                action = "Repair the installed version" if choice == "4" else "Restore the previous version and pause automatic upgrades"
                if session.read(action + "? [y/N]: ").strip().lower() in ("y", "yes"):
                    result = manager.install_release(root, repair=True) if choice == "4" else manager.rollback(root)
                    session.printer.message(f"Consensus {result['version']} is ready. Restart to apply.")
            else:
                session.printer.message("Choose an available action.")
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            from .app_update import network_problem

            session.printer.warn(network_problem(exc))
