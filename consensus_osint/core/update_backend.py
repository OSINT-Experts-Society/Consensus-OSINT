"""Explicit updates in the installation's existing environment.

This module keeps the updater independent of application code during updates.
It must not import application modules at module scope: they may be replaced.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import site
import subprocess
import sys
import sysconfig
import tempfile
from contextlib import contextmanager
from importlib import metadata
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import url2pathname

PACKAGE = "consensus-osint"
_pending = None
_FEATURES = {
    "modules": ("aiohttp", "trio", "lxml", "curl_cffi", "socid-extractor", "requests", "termcolor", "colorama"),
    "pdf": ("reportlab", "pillow"), "browser": ("playwright",), "mcp": ("mcp", "PyJWT"),
    "registry": ("SQLAlchemy", "PyMySQL"),
}


def package_directory():
    return Path(__file__).resolve().parents[1]


def installation():
    """Identify ownership from local receipts, not guessed folder names."""
    prefix = Path(sys.prefix).resolve()
    package = package_directory()
    if getattr(sys, "frozen", False):
        raise ValueError("This frozen executable must be updated through its distributor; it cannot be replaced with pip.")
    pipx = prefix / "pipx_metadata.json"
    if pipx.is_file():
        record = json.loads(pipx.read_text(encoding="utf-8"))
        if not isinstance(record, dict) or not isinstance(record.get("main_package"), dict):
            raise ValueError("The pipx ownership receipt is damaged; repair it using pipx before updating.")
        if record.get("main_package", {}).get("package") != PACKAGE:
            raise ValueError("Consensus is injected into another pipx tool. Update that owning tool through pipx.")
        if record["main_package"].get("pinned"):
            raise ValueError("This pipx installation is pinned. Unpin it explicitly before updating.")
        return {"kind": "pipx", "prefix": str(prefix), "name": prefix.name}
    if (prefix / "uv-receipt.toml").is_file():
        if prefix.name != PACKAGE:
            raise ValueError("Consensus belongs to another uv tool; update the owning tool through uv.")
        return {"kind": "uv", "prefix": str(prefix), "name": PACKAGE}
    try:
        dist = metadata.distribution(PACKAGE)
        direct = json.loads(dist.read_text("direct_url.json") or "{}")
    except metadata.PackageNotFoundError:
        dist, direct = None, {}
    if not isinstance(direct, dict) or not isinstance(direct.get("dir_info", {}), dict):
        raise ValueError("The installed source metadata is damaged; no update was attempted.")
    editable = bool(direct.get("dir_info", {}).get("editable"))
    if editable:
        parsed = urlsplit(direct.get("url", ""))
        if (parsed.scheme != "file" or parsed.netloc not in ("", "localhost")
                or Path(url2pathname(parsed.path)).resolve() != package.parent):
            raise ValueError("The editable installation points to another checkout. Use that checkout's interpreter to update.")
        if (dist.read_text("INSTALLER") or "").strip() != "pip":
            raise ValueError("This editable checkout is managed by another tool. Update it through its existing project workflow.")
    if (package.parent / "pyproject.toml").is_file() or editable:
        return {"kind": "source", "directory": str(package.parent),
                "editable": editable, "reinstall": editable,
                "user": bool(editable and Path(dist.locate_file("")).resolve().is_relative_to(
                    Path(site.getusersitepackages()).resolve()))}
    if dist is None or Path(dist.locate_file("consensus_osint/__init__.py")).resolve() != package / "__init__.py":
        raise ValueError("The running copy has no matching package installation. Update its source or image; no migration was attempted.")
    if direct.get("vcs_info"):
        raise ValueError("This installation is pinned to a VCS source. Update that source requirement explicitly; it will not be replaced by PyPI.")
    if (sys.prefix == sys.base_prefix and
            (Path(sysconfig.get_path("stdlib")) / "EXTERNALLY-MANAGED").exists()):
        raise ValueError("This Python is managed by the operating system. Use its package manager; Consensus will not bypass its protection.")
    installer = (dist.read_text("INSTALLER") or "").strip()
    if installer not in {"pip", "uv"}:
        raise ValueError("This package is owned by another installer. Update it with that installer; no files were changed.")
    user = package.is_relative_to(Path(site.getusersitepackages()).resolve())
    if not user and not any(package.is_relative_to(Path(sysconfig.get_path(key)).resolve()) for key in ("purelib", "platlib")):
        raise ValueError("This environment is importing another installation. Run consensus update using that installation's own interpreter.")
    if "dir_info" in direct:
        parsed = urlsplit(direct.get("url", ""))
        if parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
            raise ValueError("The original source directory cannot be resolved safely; update it through its source workflow.")
        folder = Path(url2pathname(parsed.path)).resolve()
        if not (folder / "pyproject.toml").is_file() or installer != "pip":
            raise ValueError("The original source checkout is unavailable or managed by uv; update through its original source workflow.")
        return {"kind": "source", "directory": str(folder), "editable": False, "reinstall": True, "user": user}
    if installer == "uv":
        if ((prefix.parent / "uv.lock").exists() or "archive-v0" in prefix.parts or "builds-v0" in prefix.parts):
            raise ValueError("This is a locked project or temporary uv environment. Refresh it with its owning uv project/run command.")
        return {"kind": "uv-pip", "prefix": str(prefix)}
    return {"kind": "pip", "user": user}


def _tool(name):
    executable = shutil.which(name)
    if not executable:
        raise ValueError(f"The original {name} updater is not available on PATH. Restore it, then run consensus update again.")
    return str(Path(executable).resolve())


def _read(command, *, env=None):
    return subprocess.run(command, env=env, check=True, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=30).stdout.strip()


def _extras():
    """Retain complete optional capability groups already present; add none by default."""
    result = []
    for extra, packages in _FEATURES.items():
        try:
            for name in packages:
                metadata.version(name)
        except metadata.PackageNotFoundError:
            continue
        result.append(extra)
    return result


def _git_preflight(git, folder):
    prefix = [git, "-C", folder]
    if Path(_read([*prefix, "rev-parse", "--show-toplevel"])).resolve() != Path(folder).resolve():
        raise ValueError("This is a combined development checkout. Update it through its repository review workflow.")
    if _read([*prefix, "status", "--porcelain", "--untracked-files=no"]):
        raise ValueError("The source checkout has local changes. Commit or save them before updating; nothing was overwritten.")
    branch = _read([*prefix, "symbolic-ref", "--quiet", "--short", "HEAD"])
    upstream = _read([*prefix, "rev-parse", "--abbrev-ref", "@{upstream}"])
    ahead = _read([*prefix, "rev-list", "--count", "@{upstream}..HEAD"])
    if int(ahead):
        raise ValueError("The source branch has local commits. Review them before updating; no merge or reset was attempted.")
    return branch, upstream


def _pip_preflight():
    if (sys.prefix == sys.base_prefix and
            (Path(sysconfig.get_path("stdlib")) / "EXTERNALLY-MANAGED").exists()):
        raise ValueError("This Python is managed by the operating system; its protection will not be bypassed.")
    if any(os.environ.get(name) for name in ("PIP_TARGET", "PIP_PREFIX", "PIP_USER")):
        raise ValueError("PIP_TARGET/PIP_PREFIX/PIP_USER overrides are set. Clear them before updating this installation.")
    if _read([sys.executable, "-m", "pip", "--version"]) == "":
        raise ValueError("pip is unavailable for this interpreter.")
    config = _read([sys.executable, "-m", "pip", "config", "list"])
    if any(re.match(r"(?:global|install)\.(?:target|prefix|user)=", line) for line in config.splitlines()):
        raise ValueError("pip configuration redirects installations. Clear its target/prefix/user setting before updating this environment.")


def plan_update():
    from .. import __version__
    from . import install_manager as manager

    owner = installation()
    kind = owner["kind"]
    plan = {"kind": kind, "commands": [], "python": sys.executable,
            "package_parent": str(package_directory().parent), "environment": {},
            "previous": __version__, "target": None}
    if kind == "source":
        git, folder = _tool("git"), owner["directory"]
        branch, upstream = _git_preflight(git, folder)
        plan.update(git=git, directory=folder, branch=branch, upstream=upstream)
        plan["commands"].append([git, "-C", folder, "pull", "--ff-only", "--no-rebase"])
        if owner.get("reinstall", owner["editable"]):
            _pip_preflight()
            extras = _extras()
            requirement = folder + ("[" + ",".join(extras) + "]" if extras else "")
            plan["commands"].append([sys.executable, "-m", "pip", "install",
                                     *(["--user"] if owner.get("user") else []),
                                     *(["--editable"] if owner["editable"] else []), requirement])
        return plan
    latest = manager.latest_release()["version"]
    if manager.stable_version(latest) <= manager.stable_version(__version__):
        return None
    plan["target"] = latest
    extras = _extras()
    requirement = PACKAGE + ("[" + ",".join(extras) + "]" if extras else "") + "==" + latest
    if kind == "pip":
        _pip_preflight()
        plan["commands"] = [[sys.executable, "-m", "pip", "install", "--upgrade",
                              *(["--user"] if owner["user"] else []), requirement]]
    elif kind == "pipx":
        prefix = Path(owner["prefix"])
        plan["environment"]["PIPX_HOME"] = str(prefix.parent.parent)
        plan["commands"] = [[_tool("pipx"), "upgrade", owner["name"]]]
    elif kind == "uv":
        plan["environment"]["UV_TOOL_DIR"] = str(Path(owner["prefix"]).parent)
        plan["commands"] = [[_tool("uv"), "tool", "upgrade", owner["name"]]]
    else:
        plan["commands"] = [[_tool("uv"), "pip", "install", "--python", sys.executable, "--upgrade", requirement]]
    return plan


def prepare():
    global _pending
    _pending = None
    _pending = plan_update()
    return _pending is not None


def pending():
    return _pending is not None


def cancel():
    global _pending
    _pending = None


@contextmanager
def _update_lock(plan):
    identity = os.path.normcase(str(Path(plan["package_parent"]).resolve()))
    key = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    lock = Path(tempfile.gettempdir()) / ("consensus-update-" + key + ".lock")
    try:
        handle = lock.open("x", encoding="utf-8")
    except FileExistsError as exc:
        raise ValueError(f"Another update may be running. If interrupted, close it before removing {lock}") from exc
    try:
        with handle:
            handle.write(str(os.getpid()))
        yield
    finally:
        lock.unlink(missing_ok=True)


def run_pending():
    """After UI teardown, wait for installation and preserve its failure status."""
    global _pending
    if _pending is None:
        return 0
    plan, _pending = _pending, None
    print("Updating Consensus using the existing installation method. Please wait…", flush=True)
    try:
        with _update_lock(plan):
            return execute_plan(plan)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"Consensus update did not complete: {exc}. No automatic rollback was attempted; check the package-manager output above.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Update interrupted. The installation may have changed; rerun consensus update before searching.", file=sys.stderr)
        return 130


def execute_plan(plan):
    """Never import replaced application code or claim success without verification."""
    if plan["kind"] == "source":
        if _git_preflight(plan["git"], plan["directory"]) != (plan["branch"], plan["upstream"]):
            raise ValueError("The source branch changed after confirmation; no update was attempted.")
    environment = dict(os.environ, **plan["environment"])
    environment["PIP_NO_INPUT"] = "1"
    environment["UV_NO_PROGRESS"] = "1"
    for command in plan["commands"]:
        subprocess.run(command, env=environment, check=True)
    # A new interpreter avoids stale imported modules and stale dist-info caches.
    probe = ("import sys; sys.path.insert(0, sys.argv[1]); "
             "from consensus_osint import __version__; "
             "from consensus_osint.core.signing import check_database; "
             "assert check_database()['verified'], 'catalogue signature failed'; print(__version__)")
    version = _read([plan["python"], "-I", "-c", probe, plan["package_parent"]], env=environment)
    if not re.fullmatch(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}", version):
        raise ValueError("The updated installation did not return a valid version.")
    if plan["target"] and tuple(map(int, version.split("."))) < tuple(map(int, plan["target"].split("."))):
        raise ValueError(f"The package manager retained {version}. Check its pins/constraints; the requested update was not applied.")
    print(f"Consensus {version} is installed and verified. Restart Consensus to use it.")
    return 0
