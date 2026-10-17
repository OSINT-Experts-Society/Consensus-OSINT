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


def health_rows():
    """Read local metadata only: no provider calls, installs, keys or query values."""
    from importlib import metadata

    from .config import _ENV_KEYS, config_path, get_config, unused_settings
    from .session_info import SessionInfo
    from .update_backend import _FEATURES

    rows = list(SessionInfo.current().rows())
    rows += [("Python", sys.version.split()[0]), ("Python executable", sys.executable),
             ("Environment", sys.prefix), ("Settings file", str(config_path()))]
    for label, packages in _FEATURES.items():
        missing = []
        for package in packages:
            try:
                metadata.version(package)
            except metadata.PackageNotFoundError:
                missing.append(package)
        rows.append((label.capitalize(), "Dependencies present (not operationally tested)" if not missing else
                     "Missing dependencies: " + ", ".join(missing)))
    cfg = get_config()
    route = os.environ.get("CONSENSUS_PROXY") or cfg.get("defaults", {}).get("proxy")
    rows.append(("Default scan route", "Proxy configured (not tested)" if route else
                 "Tor configured (not tested)" if cfg.get("defaults", {}).get("tor") else "No Consensus proxy configured"))
    keys = cfg.get("keys", {})
    for name in _ENV_KEYS:
        rows.append(("Optional key: " + name, "Configured (not tested)" if keys.get(name) else "Not configured"))
    if unused_settings(cfg):
        rows.append(("Settings warning", "Some settings are not recognised; check the config file before searching."))
    return rows


def health_screen(session):
    session.printer.summary_table([["Setup / health", "Local status"], *health_rows()], "Setup / health · offline")
    session.printer.message("No network tests or changes were made. Missing optional keys do not prevent ordinary searches. "
                            "Browser dependencies do not prove that a browser is installed or usable.")
    session.printer.message("For missing capabilities, use the optional-extras instructions in the README with your existing "
                            "installation method. For keys, close Consensus and run 'consensus keys --help'. "
                            "Open Settings → Installation & updates for update options.")
    session.back_prompt("Enter / Esc to return: ")


def status(root):
    managed = manager.managed_install(root)
    state = manager.active_install(root) if managed else None
    from .app_update import notice_root, update_instruction
    from .auto_update import notification
    from .session_info import SessionInfo

    rows = [["Running version", __version__], ["Installed version", state["version"] if managed else __version__],
            ["Installation", "Managed" if managed else "Source / Python environment"],
            ["Update source", state.get("channel", "Public releases") if managed else "Existing package manager / source checkout"],
            ["Lookup database", dict(SessionInfo.current().rows())["Lookup database updated"]]]
    latest, checked = None, 0
    cache_root = root if managed else notice_root(root)
    for name in (("update-check.json", "auto-update.json") if managed else ("update-check.json",)):
        try:
            value = json.loads((cache_root / name).read_text(encoding="utf-8"))
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
    if not managed:
        rows.append(["How to update", update_instruction()])
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
        # Python preserves PowerShell 7's module path when starting Windows
        # PowerShell. Its incompatible core modules can break uv's bootstrap.
        # Let the child rebuild its own defaults; leave the parent untouched.
        env = {k: v for k, v in env.items() if k.upper() != "PSMODULEPATH"}
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
    command = [str(python), "-I", "-m", "consensus_osint.cli"]
    if os.name == "nt":
        # Windows exec does not preserve the process the launcher is waiting
        # for. Keep that parent alive until the restarted console exits.
        return subprocess.call(command, env=environment)
    os.execve(str(python), command, environment)


def screen(session):
    root = manager.install_root()
    while True:
        session.printer.summary_table([["Updates", "Details"], *status(root)], "Installation & updates")
        managed = manager.managed_install(root)
        session.printer.message("1 Check now · 2 Install update · 3 Restart\n4 Repair · 5 Restore previous · 6 Choose bundle"
                                if managed else "1 Check public release · 2 Install update · 6 Switch to managed installation")
        session.printer.message("0 / Esc Back")
        choice = session.back_prompt("Updates: ", zero=True).strip().lower()
        if choice in ("", "0", "back", "cancel"):
            return
        try:
            if choice in ("1", "2", "4", "6"):
                from .app_update import require_update_route

                require_update_route()
            if choice == "1":
                from .app_update import checked_release, notice_root, update_instruction

                release = manager.release_for(root) if managed else manager.latest_release()
                cache_root = root if managed else notice_root(root)
                manager.atomic_json(cache_root / "update-check.json", {"checked_at": time.time(), "version": release["version"]})
                checked_release(release["version"], time.time())
                session.printer.message("Available version: " + release["version"])
                if not managed:
                    session.printer.message(update_instruction())
            elif choice == "6":
                bundle = session.back_prompt("Extracted install bundle folder (Enter cancels): ").strip().strip('"')
                if not bundle:
                    continue
                release = manager.bundle_release(bundle)
                session.printer.message(f"Install Consensus {release['version']} from {bundle}. Settings and reports remain in place.")
                if session.back_prompt("Continue? [y/N]: ").strip().lower() not in ("y", "yes"):
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
                    if (session.back_prompt("Switch to it now? [y/N]: ").strip().lower() in ("y", "yes")
                            and session.confirm_leave()):
                        session.restart_requested = True
                        return
            elif not managed and choice == "2":
                session.execute(["update"])
                if session.update_requested:
                    return
            elif managed and choice == "2":
                result = manager.install_release(root)
                state = manager.active_install(root)
                pending = state["version"] != __version__ or state["environment"] != Path(sys.prefix).name
                if result["updated"]:
                    session.printer.message(manager.summary_text(result.get("summary"), result["version"]) + " Restart to apply.")
                elif pending:
                    session.printer.message(f"Consensus {result['version']} is installed. Restart to apply.")
                else:
                    session.printer.message(f"Consensus {result['version']} is already up to date.")
            elif managed and choice == "3":
                session.printer.message("Restart closes this session. Save results first if local history is off.")
                if (session.back_prompt("Restart now? [y/N]: ").strip().lower() in ("y", "yes")
                        and session.confirm_leave()):
                    session.restart_requested = True
                    return
            elif managed and choice in ("4", "5"):
                action = "Repair the installed version" if choice == "4" else "Restore the previous version and pause automatic upgrades"
                if session.back_prompt(action + "? [y/N]: ").strip().lower() in ("y", "yes"):
                    result = manager.install_release(root, repair=True) if choice == "4" else manager.rollback(root)
                    session.printer.message(f"Consensus {result['version']} is ready. Restart to apply.")
            else:
                session.printer.message("Choose an available action.")
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            from .app_update import network_problem

            session.printer.warn(network_problem(exc))
