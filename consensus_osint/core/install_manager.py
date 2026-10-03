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
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse

PACKAGE = "consensus-osint"
METADATA_URL = f"https://pypi.org/pypi/{PACKAGE}/json"
MAX_METADATA = 2 * 1024 * 1024
MAX_WHEEL = 128 * 1024 * 1024
EXTRAS = ["modules", "pdf"]
VALIDATION_TIMEOUT = 30


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


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
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
    with open_url(release["url"], 30) as response, target.open("wb") as output:
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
    state = json.loads((root / "current.json").read_text(encoding="utf-8"))
    name = state["environment"]
    if not isinstance(name, str) or not re.fullmatch(r"[0-9.]+-[a-f0-9]{32}", name):
        raise ValueError("invalid active environment")
    target = (root / "versions" / name).resolve()
    if target.parent != (root / "versions").resolve():
        raise ValueError("invalid active environment location")
    python = target / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    os.environ["CONSENSUS_INSTALL_DIR"] = str(root)
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


def install_release(root: Path, *, initial=False) -> dict:
    with installation_lock(root):
        previous = active_install(root)
        release = latest_release()
        if previous and stable_version(previous["version"]) >= stable_version(release["version"]):
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
                return {"version": previous["version"], "updated": False}
        uv = root / "uv" / ("uv.exe" if os.name == "nt" else "uv")
        if not uv.is_file():
            raise ValueError("The installation helper is missing; run the Consensus installer again")
        extras = previous["extras"] if previous else EXTRAS
        name = release["version"] + "-" + uuid.uuid4().hex
        environment = root / "versions" / name
        runtime = Path(sys.executable) if initial else Path(sys.base_prefix) / ("python.exe" if os.name == "nt" else "bin/python3")
        with tempfile.TemporaryDirectory(prefix="download-", dir=root) as temporary:
            wheel = download_wheel(release, Path(temporary))
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
        atomic_json(environment / "consensus-managed.json", {"version": actual})
        # Prepare the launcher before committing the only activation change.
        if initial:
            write_launcher(root, runtime)
        atomic_json(root / "current.json", {"version": actual, "environment": name, "extras": extras,
                                           "previous": previous["environment"] if previous else None})
        return {"version": actual, "updated": True}


def main() -> int:
    parser = argparse.ArgumentParser(description="Install Consensus with its private runtime")
    parser.parse_args()
    try:
        result = install_release(install_root(), initial=True)
        print(f"Consensus {result['version']} is ready.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException, subprocess.SubprocessError) as exc:
        print(f"Installation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
