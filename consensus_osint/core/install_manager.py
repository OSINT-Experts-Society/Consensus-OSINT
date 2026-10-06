"""Standalone managed installer; also shipped in releases for Python bootstrapping.

Only the activation file changes during an update. Running processes keep their
old environment, including on Windows. User configuration and reports live elsewhere.
This file deliberately uses only the Python standard library.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse

PACKAGE = "consensus-osint"
METADATA_URL = f"https://pypi.org/pypi/{PACKAGE}/json"
MAX_METADATA = 2 * 1024 * 1024
MAX_WHEEL = 128 * 1024 * 1024
EXTRAS = ["modules", "pdf"]
VALIDATION_TIMEOUT = 30
CHANGE_CATEGORIES = ("new_modules", "bug_fixes", "other_changes")


def valid_summary(value, version):
    """Optional release counts must describe this exact installed version."""
    if not isinstance(value, dict) or value.get("to_version") != version:
        return None
    try:
        if stable_version(value["from_version"]) >= stable_version(version):
            return None
        if any(type(value.get(key)) is not int or not 0 <= value[key] <= 100000 for key in CHANGE_CATEGORIES):
            return None
    except (ValueError, KeyError, TypeError):
        return None
    return {key: value[key] for key in ("from_version", "to_version", *CHANGE_CATEGORIES)}


def summary_text(value, version):
    summary = valid_summary(value, version)
    if summary is None:
        return "Change summary unavailable."
    labels = (("new_modules", "new module"), ("bug_fixes", "bug fix"), ("other_changes", "other change"))
    return " · ".join(f"{summary[key]} {label}" + ("" if summary[key] == 1 else "es" if key == "bug_fixes" else "s")
                      for key, label in labels) + "."


def release_summary(wheel, previous, version):
    """Read reviewed change IDs from the checksum-verified wheel, not Git logs.

    A complete release chain is required when skipping versions. Repeated IDs
    count once; missing history is unknown coverage, never zero changes.
    """
    if previous is None:
        return None
    try:
        with zipfile.ZipFile(wheel) as archive:
            entry = archive.getinfo("consensus_osint/data/release_notes.json")
            if entry.file_size > 256 * 1024:
                return None
            notes = json.loads(archive.read(entry))
        if notes["schema"] != 1 or not isinstance(notes["releases"], list):
            return None
        releases = {}
        for release in notes["releases"]:
            target = release["version"]
            if target in releases:
                return None
            if stable_version(release["previous_version"]) >= stable_version(target):
                return None
            releases[target] = release
        changes = {key: set() for key in CHANGE_CATEGORIES}
        cursor = version
        while cursor != previous:
            release = releases[cursor]
            if stable_version(release["previous_version"]) < stable_version(previous):
                return None
            for key in CHANGE_CATEGORIES:
                items = release[key]
                if not isinstance(items, list) or any(not isinstance(item, str) or not item.strip() for item in items):
                    return None
                changes[key].update(items)
            cursor = release["previous_version"]
        return valid_summary({"from_version": previous, "to_version": version,
                              **{key: len(items) for key, items in changes.items()}}, version)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, zipfile.BadZipFile):
        return None


def install_root() -> Path:
    return Path(os.environ.get("CONSENSUS_INSTALL_DIR", Path.home() / ".local/share/consensus-app")).expanduser().resolve()


def stable_version(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}", value):
        raise ValueError("Release version must use stable major.minor.patch numbering")
    return tuple(int(part) for part in value.split("."))


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).scheme != "https":
            raise ValueError("Refusing an insecure download redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_url(url: str, timeout: float):
    if urlparse(url).scheme != "https":
        raise ValueError("Downloads require HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "Consensus-updater", "Accept": "application/json"})
    return urllib.request.build_opener(HTTPSOnly()).open(request, timeout=timeout)


def latest_release(timeout: float = 5) -> dict:
    try:
        with open_url(METADATA_URL, timeout) as response:
            raw = response.read(MAX_METADATA + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ValueError("No Consensus application release is published on PyPI yet. "
                             "The installed version has not been changed.") from exc
        raise
    if len(raw) > MAX_METADATA:
        raise ValueError("Release metadata is too large")
    try:
        data = json.loads(raw)
    except RecursionError as exc:
        raise ValueError("Release metadata is nested too deeply") from exc
    version = data["info"]["version"]
    stable_version(version)
    expected = f"consensus_osint-{version}-py3-none-any.whl"
    for entry in data["urls"]:
        if not isinstance(entry, dict):
            raise ValueError("Invalid release file metadata")
        if entry.get("filename") == expected and not entry.get("yanked"):
            url = entry["url"]
            if not isinstance(url, str):
                raise ValueError("Invalid release download URL")
            parsed = urlparse(url)
            digest = entry["digests"]["sha256"]
            if (parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org"
                    or parsed.username or parsed.password or parsed.port not in (None, 443)
                    or not re.fullmatch(r"[a-f0-9]{64}", digest)):
                raise ValueError("Invalid release download metadata")
            return {"version": version, "filename": expected, "url": url, "sha256": digest}
    raise ValueError("No supported, non-yanked Consensus wheel has been published")


def bundle_release(folder) -> dict:
    """A user-selected private folder is a channel, not a public publication."""
    folder = Path(folder).expanduser().resolve(strict=True)
    manifest = folder / "release.json"
    if manifest.stat().st_size > MAX_METADATA:
        raise ValueError("Release metadata is too large")
    value = json.loads(manifest.read_text(encoding="utf-8"))
    stable_version(value["version"])
    expected = f"consensus_osint-{value['version']}-py3-none-any.whl"
    if value.get("filename") != expected or not re.fullmatch(r"[a-f0-9]{64}", value.get("sha256", "")):
        raise ValueError("Invalid bundle manifest")
    wheel = (folder / expected).resolve(strict=True)
    if wheel.parent != folder or not wheel.is_file() or wheel.stat().st_size > MAX_WHEEL:
        raise ValueError("Invalid bundle wheel")
    return {"version": value["version"], "filename": expected, "sha256": value["sha256"],
            "local_path": str(wheel), "channel": str(folder)}


def release_for(root, *, timeout=5):
    state = active_install(root)
    return bundle_release(state["channel"]) if state and state.get("channel") else latest_release(timeout=timeout)


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        if os.name != "nt":
            temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def active_install(root: Path) -> dict | None:
    pointer = root / "current.json"
    if not pointer.exists():
        return None
    try:
        state = json.loads(pointer.read_text(encoding="utf-8"))
    except RecursionError as exc:
        raise ValueError("Installation state is nested too deeply") from exc
    stable_version(state["version"])
    name = state["environment"]
    if not isinstance(name, str) or not re.fullmatch(r"[0-9.]+-[a-f0-9]{32}", name):
        raise ValueError("Invalid installation environment")
    target = (root / "versions" / name).resolve()
    if target.parent != (root / "versions").resolve():
        raise ValueError("Installation environment escapes its versions directory")
    if not isinstance(state.get("extras"), list) or any(x not in ("modules", "pdf", "registry", "browser", "mcp") for x in state["extras"]):
        raise ValueError("Invalid installed extras")
    context = state.get("user_environment", {})
    if not isinstance(context, dict) or any(k not in ("CONSENSUS_HOME", "CONSENSUS_REPORT_DIR") or
                                          not isinstance(v, str) or not Path(v).is_absolute() for k, v in context.items()):
        raise ValueError("Invalid saved configuration/report locations")
    if state.get("channel") is not None and (not isinstance(state["channel"], str) or not Path(state["channel"]).is_absolute()):
        raise ValueError("Invalid private update source")
    return state


def environment_python(environment: Path) -> Path:
    return environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def managed_install(root: Path) -> bool:
    # Previous sessions can still update after a newer version was activated.
    prefix = Path(sys.prefix).resolve()
    versions = (root / "versions").resolve()
    if prefix.parent != versions or not (prefix / "consensus-managed.json").is_file():
        return False
    return bool(active_install(root))


def clean_environment(root: Path) -> dict:
    # Do not inherit project indexes, source overrides or an activated environment.
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(("UV_", "PIP_", "PYTHON")) and key.upper() != "VIRTUAL_ENV"}
    env["UV_PYTHON_INSTALL_DIR"] = str(root / "python")
    env["UV_PYTHON_INSTALL_BIN"] = "0"
    return env


def run(command: list[str], root: Path, *, capture=False) -> subprocess.CompletedProcess:
    return subprocess.run(command, env=clean_environment(root), check=True,
                          stdout=subprocess.PIPE if capture else sys.stderr,
                          stderr=subprocess.PIPE if capture else sys.stderr, text=True,
                          # The child ignores PYTHON* settings, so its output encoding can differ
                          # from this process; an accented install path must not abort the update.
                          errors="replace",
                          timeout=VALIDATION_TIMEOUT if capture else None)


@contextmanager
def installation_lock(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    lock = root / "update.lock"
    try:
        handle = lock.open("x", encoding="utf-8")
    except FileExistsError as exc:
        raise ValueError(f"Another installation may be running. If it was interrupted, close it before removing {lock}") from exc
    try:
        with handle:
            handle.write(str(os.getpid()))
        yield
    finally:
        lock.unlink(missing_ok=True)


def download_wheel(release: dict, directory: Path) -> Path:
    target = directory / release["filename"]
    digest = hashlib.sha256()
    size = 0
    source = Path(release["local_path"]).open("rb") if release.get("local_path") else open_url(release["url"], 30)
    with source as response, target.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_WHEEL:
                raise ValueError("Release download is too large")
            digest.update(chunk)
            output.write(chunk)
    if digest.hexdigest() != release["sha256"]:
        raise ValueError("Release checksum does not match; the current installation is unchanged")
    return target


LAUNCHER = '''import json, os, pathlib, re, subprocess, sys
root = pathlib.Path(__file__).resolve().parent
try:
    os.environ["CONSENSUS_INSTALL_DIR"] = str(root)
    if len(sys.argv) == 3 and sys.argv[1] == "update" and sys.argv[2] in ("--repair", "--rollback"):
        raise SystemExit(subprocess.call([sys.executable, "-I", str(root / "install-manager.py"), sys.argv[2]]))
    state = json.loads((root / "current.json").read_text(encoding="utf-8"))
    name = state["environment"]
    if not isinstance(name, str) or not re.fullmatch(r"[0-9.]+-[a-f0-9]{32}", name):
        raise ValueError("invalid active environment")
    target = (root / "versions" / name).resolve()
    if target.parent != (root / "versions").resolve():
        raise ValueError("invalid active environment location")
    python = target / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    os.environ["CONSENSUS_INSTALL_DIR"] = str(root)
    for key, value in state.get("user_environment", {}).items():
        if key in ("CONSENSUS_HOME", "CONSENSUS_REPORT_DIR") and isinstance(value, str):
            os.environ.setdefault(key, value)
    command = [str(python), "-I", "-m", "consensus_osint.cli", *sys.argv[1:]]
    if os.name == "nt":
        raise SystemExit(subprocess.call(command))
    os.execv(str(python), command)
except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
    print("Consensus could not start: " + str(exc) + ". Run the installer again.", file=sys.stderr)
    raise SystemExit(1)
'''


def write_launcher(root: Path, runtime: Path) -> None:
    def replace_text(path, content):
        temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
        try:
            temporary.write_text(content, encoding="utf-8", newline="\n")
            if os.name != "nt":
                temporary.chmod(0o755)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    launcher = root / "launcher.py"
    replace_text(root / "install-manager.py", Path(__file__).read_text(encoding="utf-8"))
    replace_text(launcher, LAUNCHER)
    directory = root / "bin"
    directory.mkdir(exist_ok=True)
    if os.name == "nt":
        # Disable delayed expansion and escape literal percent signs in paths.
        def quote(path):
            try:
                return '"%~dp0..\\' + str(path.relative_to(root)).replace("%", "%%") + '"'
            except ValueError:
                return '"' + str(path).replace("%", "%%") + '"'

        content = "@echo off\nsetlocal DisableDelayedExpansion\n" + quote(runtime) + " -I " + quote(launcher) + " %*\nexit /b %errorlevel%\n"
        replace_text(directory / "consensus.cmd", content)
    else:
        command = directory / "consensus"
        replace_text(command, "#!/bin/sh\nexec " + shlex.quote(str(runtime)) + " -I " + shlex.quote(str(launcher)) + ' "$@"\n')


def install_release(root: Path, *, initial=False, repair=False, feed=None, user_environment=None, automatic=False, extras=None) -> dict:
    with installation_lock(root):
        previous = active_install(root)
        if automatic and previous and previous.get("auto_update_paused"):
            return {"version": previous["version"], "updated": False}
        if repair:
            if not previous:
                raise ValueError("No managed installation to repair")
            package = root / "versions" / previous["environment"] / "package"
            if not (package / "release.json").is_file():
                raise ValueError("This older installation has no cached package. Choose an install bundle or rerun the installer to repair it.")
            release = bundle_release(package)
            release["channel"] = previous.get("channel")
        else:
            release = bundle_release(feed) if feed else release_for(root)
        if previous and not repair and stable_version(previous["version"]) >= stable_version(release["version"]):
            previous_python = environment_python(root / "versions" / previous["environment"])
            intact = previous_python.is_file()
            if initial and intact:
                try:
                    run([str(previous_python), "-I", "-m", "consensus_osint.cli", "--version"], root, capture=True)
                except (OSError, subprocess.SubprocessError):
                    intact = False
            if not intact and (not initial or previous["version"] != release["version"]):
                raise ValueError("The active environment is missing or cannot start; rerun the installer "
                                 "with its current release available. A newer installed version will not be downgraded.")
            if intact:
                if initial:
                    write_launcher(root, Path(sys.executable))
                if feed:
                    previous["channel"] = release["channel"]
                if user_environment:
                    previous["user_environment"] = {k: str(Path(v).expanduser().resolve()) for k, v in user_environment.items()
                                                     if k in ("CONSENSUS_HOME", "CONSENSUS_REPORT_DIR") and isinstance(v, str)}
                if feed or user_environment:
                    atomic_json(root / "current.json", previous)
                result = {"version": previous["version"], "updated": False}
                if summary := valid_summary(previous.get("summary"), previous["version"]):
                    result["summary"] = summary
                return result
        uv = root / "uv" / ("uv.exe" if os.name == "nt" else "uv")
        if not uv.is_file():
            raise ValueError("The installation helper is missing; run the Consensus installer again")
        extras = previous["extras"] if previous else (EXTRAS if extras is None else extras)
        if not isinstance(extras, list) or any(x not in ("modules", "pdf", "browser", "mcp", "registry") for x in extras):
            raise ValueError("Invalid optional features")
        name = release["version"] + "-" + uuid.uuid4().hex
        environment = root / "versions" / name
        runtime = Path(sys.executable) if initial else Path(sys.base_prefix) / ("python.exe" if os.name == "nt" else "bin/python3")
        with tempfile.TemporaryDirectory(prefix="download-", dir=root) as temporary:
            wheel = download_wheel(release, Path(temporary))
            summary = release_summary(wheel, previous["version"] if previous else None, release["version"])
            run([str(uv), "--no-config", "venv", "--python", str(runtime), str(environment)], root)
            python = environment_python(environment)
            spec = str(wheel) + ("[" + ",".join(extras) + "]" if extras else "")
            run([str(uv), "--no-config", "pip", "install", "--python", str(python),
                 "--default-index", "https://pypi.org/simple", "--only-binary", ":all:", spec], root)
            run([str(uv), "--no-config", "pip", "check", "--python", str(python)], root)
            actual = run([str(python), "-I", "-c", "from importlib.metadata import version; print(version('consensus-osint'))"], root, capture=True).stdout.strip()
            if actual != release["version"]:
                raise ValueError("Installed version does not match the requested release")
            run([str(python), "-I", "-m", "consensus_osint.cli", "--version"], root, capture=True)
            # Keep the verified wheel so repair does not depend on an old
            # public release remaining available. Dependencies use pip's cache.
            package = environment / "package"
            package.mkdir(exist_ok=True)
            shutil.copyfile(wheel, package / release["filename"])
            atomic_json(package / "release.json", {k: release[k] for k in ("version", "filename", "sha256")})
        atomic_json(environment / "consensus-managed.json", {"version": actual, "extras": extras})
        # Prepare the launcher before committing the only activation change.
        if initial or repair:
            write_launcher(root, runtime)
        state = {"version": actual, "environment": name, "extras": extras,
                 "previous": previous["environment"] if previous else None}
        if release.get("channel"):
            state["channel"] = release["channel"]
        context = user_environment if user_environment is not None else (previous or {}).get("user_environment", {})
        state["user_environment"] = {k: str(Path(v).expanduser().resolve()) for k, v in context.items()
                                     if k in ("CONSENSUS_HOME", "CONSENSUS_REPORT_DIR") and isinstance(v, str)}
        if repair and previous.get("auto_update_paused"):
            state["auto_update_paused"] = True
        result = {"version": actual, "updated": True}
        if summary is not None:
            state["summary"] = result["summary"] = summary
        atomic_json(root / "current.json", state)
        try:
            atomic_json(root / "update-check.json", {"checked_at": time.time(), "version": actual})
        except OSError:
            pass
        return result


def rollback(root):
    with installation_lock(root):
        current = active_install(root)
        name = (current or {}).get("previous")
        if not isinstance(name, str) or not re.fullmatch(r"[0-9.]+-[a-f0-9]{32}", name):
            raise ValueError("No previous installation is available")
        environment = (root / "versions" / name).resolve()
        if environment.parent != (root / "versions").resolve():
            raise ValueError("Previous installation escapes its versions directory")
        marker = json.loads((environment / "consensus-managed.json").read_text(encoding="utf-8"))
        version = marker["version"]
        stable_version(version)
        extras = marker.get("extras", current["extras"])
        if not isinstance(extras, list) or any(x not in ("modules", "pdf", "browser", "mcp", "registry") for x in extras):
            raise ValueError("Previous installation has invalid optional features")
        python = environment_python(environment)
        actual = run([str(python), "-I", "-c", "from importlib.metadata import version; print(version('consensus-osint'))"],
                     root, capture=True).stdout.strip()
        if actual != version:
            raise ValueError("Previous installation version could not be verified")
        run([str(python), "-I", "-m", "consensus_osint.cli", "--version"], root, capture=True)
        state = dict(current, version=version, environment=name, previous=current["environment"],
                     extras=extras, auto_update_paused=True)
        state.pop("summary", None)
        atomic_json(root / "current.json", state)
        try:
            atomic_json(root / "auto-update.json", {"state": "paused", "checked_at": time.time()})
        except OSError:
            pass
        return {"version": version, "updated": True}


def main() -> int:
    parser = argparse.ArgumentParser(description="Install Consensus with its private runtime")
    parser.add_argument("--feed", help="private bundle directory containing release.json")
    parser.add_argument("--config-dir")
    parser.add_argument("--reports-dir")
    parser.add_argument("--extras", help="optional features to retain, comma-separated")
    recovery = parser.add_mutually_exclusive_group()
    recovery.add_argument("--repair", action="store_true")
    recovery.add_argument("--rollback", action="store_true")
    args = parser.parse_args()
    try:
        context = {k: v for k, v in {"CONSENSUS_HOME": args.config_dir or os.environ.get("CONSENSUS_HOME"),
                                   "CONSENSUS_REPORT_DIR": args.reports_dir or os.environ.get("CONSENSUS_REPORT_DIR")}.items() if v}
        result = rollback(install_root()) if args.rollback else install_release(
            install_root(), initial=True, repair=args.repair, feed=args.feed, user_environment=context or None,
            extras=args.extras.split(",") if args.extras is not None else None)
        if args.rollback:
            print(f"Restored Consensus {result['version']}. Restart Consensus to apply. Automatic upgrades are paused until your next manual update.")
        elif args.repair:
            print(f"Repaired Consensus {result['version']}. Restart Consensus to apply.")
        else:
            print(f"Consensus {result['version']} is ready. Run consensus to start your first search.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException, subprocess.SubprocessError) as exc:
        print(f"Installation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
