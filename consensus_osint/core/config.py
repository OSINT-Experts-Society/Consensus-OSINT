"""User configuration: ``~/.consensus/config.yaml`` (or ``$CONSENSUS_HOME``).

Example::

    keys:
      hibp: "..."            # haveibeenpwned.com API key (optional)
      numverify: "..."       # apilayer numverify (optional)
      abstractapi: "..."     # abstractapi phone validation (optional)
      openai: "..."          # any OpenAI-compatible endpoint for --ai summaries
      telegram_api_id: 12345
      telegram_api_hash: "..."
    openai_base_url: "https://api.openai.com/v1"
    openai_model: "gpt-4o-mini"
    defaults:
      concurrency: 100
      timeout: 15
      proxy: null

Environment variables override file values: ``CONSENSUS_HIBP_KEY``,
``CONSENSUS_NUMVERIFY_KEY``, ``CONSENSUS_ABSTRACTAPI_KEY``, ``CONSENSUS_OPENAI_KEY``
(also ``OPENAI_API_KEY``), ``CONSENSUS_OPENAI_BASE_URL``, ``CONSENSUS_OPENAI_MODEL``.
"""
from __future__ import annotations

import json
import math
import os
import tempfile
from pathlib import Path
from typing import Any

from .sitesdb import user_config_dir

_ENV_KEYS = {
    "hibp": ["CONSENSUS_HIBP_KEY", "HIBP_API_KEY"],
    "numverify": ["CONSENSUS_NUMVERIFY_KEY", "NUMVERIFY_API_KEY"],
    "abstractapi": ["CONSENSUS_ABSTRACTAPI_KEY"],
    "openai": ["CONSENSUS_OPENAI_KEY", "OPENAI_API_KEY"],
    "google_cse_key": ["CONSENSUS_GOOGLE_CSE_KEY"],
    "google_cse_cx": ["CONSENSUS_GOOGLE_CSE_CX"],
    "serpapi": ["CONSENSUS_SERPAPI_KEY", "SERPAPI_KEY"],
    "telegram_api_id": ["CONSENSUS_TELEGRAM_API_ID"],
    "telegram_api_hash": ["CONSENSUS_TELEGRAM_API_HASH"],
}

_cache: dict | None = None


def config_path() -> Path:
    return user_config_dir() / "config.yaml"


def _load_file(path: Path) -> dict:
    """Load the configuration; a damaged file is reported with its location and never rewritten."""
    try:
        return _parse_file(path)
    except (ValueError, UnicodeError) as exc:
        reason = "is not UTF-8 text" if isinstance(exc, UnicodeError) else str(exc)
        raise ValueError(f"configuration file {path}: {reason}. Correct or rename that file; "
                         "Consensus has not changed it.") from exc


def _parse_file(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
    except ImportError:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("configuration is not valid JSON; install PyYAML for YAML support") from exc
    except yaml.YAMLError as exc:
        raise ValueError("configuration contains invalid YAML") from exc
    except RecursionError as exc:
        raise ValueError("configuration is nested too deeply") from exc
    if data is None:
        data = {}
    _validate_config(data)
    return data


def _validate_config(data: dict) -> None:
    """Reject malformed YAML at the configuration boundary, before use/write."""
    if not isinstance(data, dict):
        raise ValueError("configuration must be a mapping")
    active: set[int] = set()
    checked: set[int] = set()

    def visit(value, depth=0):
        if depth > 64:
            raise ValueError("configuration is nested too deeply")
        if isinstance(value, (dict, list)):
            if id(value) in active:
                raise ValueError("configuration contains a cyclic YAML alias")
            if id(value) in checked:
                return
            active.add(id(value))
            if isinstance(value, dict):
                if any(not isinstance(k, str) for k in value):
                    raise ValueError("configuration mapping keys must be strings")
                children = value.values()
            else:
                children = value
            for child in children:
                visit(child, depth + 1)
            active.remove(id(value))
            checked.add(id(value))
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError("configuration numbers must be finite")
        elif value is not None and not isinstance(value, (str, bool, int, float)):
            raise ValueError("configuration values must be ordinary YAML scalars or containers")

    visit(data)
    for section in ("keys", "defaults"):
        if data.get(section) is None:
            data[section] = {}
        elif not isinstance(data[section], dict):
            raise ValueError(f"configuration '{section}' must be a mapping")
    for value in data["keys"].values():
        if value is not None and (isinstance(value, bool) or not isinstance(value, (str, int))):
            raise ValueError("configuration 'keys' values must be strings, integers or null")
    defaults = data["defaults"]
    if "concurrency" in defaults:
        value = defaults["concurrency"]
        if type(value) is not int or value <= 0:
            raise ValueError("configuration 'defaults.concurrency' must be a positive integer")
    if "timeout" in defaults:
        value = defaults["timeout"]
        try:
            valid = not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value) and value > 0
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError("configuration 'defaults.timeout' must be a positive finite number")
    if defaults.get("proxy") is not None and not isinstance(defaults["proxy"], str):
        raise ValueError("configuration 'defaults.proxy' must be a string or null")
    if defaults.get("tor") is not None and not isinstance(defaults["tor"], bool):
        raise ValueError("configuration 'defaults.tor' must be true or false")
    for name in ("openai_base_url", "openai_model"):
        if data.get(name) is not None and not isinstance(data[name], str):
            raise ValueError(f"configuration '{name}' must be a string or null")


KNOWN_DEFAULTS = ("concurrency", "timeout", "proxy", "tor")


def unused_settings(cfg: dict | None = None) -> list[str]:
    """Settings that look intended for Consensus but have no effect, such as a misspelt 'defaults.proxy'.

    A silently ignored proxy setting leaves the user believing requests are routed when they are not.
    """
    import difflib

    cfg = get_config() if cfg is None else cfg
    unused = [f"defaults.{name}" for name in cfg.get("defaults", {}) if name not in KNOWN_DEFAULTS]
    for name in cfg:
        if name not in ("defaults", "keys") and difflib.get_close_matches(name, ("defaults", "keys"), n=1, cutoff=0.75):
            unused.append(name)
    return unused


def get_config(reload: bool = False) -> dict:
    global _cache
    if _cache is not None and not reload:
        return _cache
    cfg = _load_file(config_path())
    keys = dict(cfg.get("keys") or {})
    for name, envs in _ENV_KEYS.items():
        for env in envs:
            v = os.environ.get(env)
            if v:
                keys[name] = v
                break
    cfg["keys"] = keys
    if os.environ.get("CONSENSUS_OPENAI_BASE_URL"):
        cfg["openai_base_url"] = os.environ["CONSENSUS_OPENAI_BASE_URL"]
    if os.environ.get("CONSENSUS_OPENAI_MODEL"):
        cfg["openai_model"] = os.environ["CONSENSUS_OPENAI_MODEL"]
    cfg.setdefault("defaults", {})
    _cache = cfg
    return cfg


def get_key(name: str) -> str | None:
    v = get_config().get("keys", {}).get(name)
    return str(v) if v not in (None, "") else None


def key_origin(name: str) -> str | None:
    """The environment variable currently supplying this key, if any; it wins over the settings file."""
    return next((env for env in _ENV_KEYS.get(name, ()) if os.environ.get(env)), None)


def stored_keys() -> dict:
    """Keys as written in the settings file, without environment overrides."""
    return dict(_load_file(config_path()).get("keys") or {})


def set_key(name: str, value: Any, *, remove: bool = False) -> Path:
    """Persist an API key into the config file (creates it when missing), or remove it."""
    p = config_path()
    cfg = _load_file(p)
    if remove:
        (cfg.get("keys") or {}).pop(name, None)
    else:
        cfg.setdefault("keys", {})[name] = value
    _validate_config(cfg)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        import yaml  # type: ignore
    except ImportError:
        text = json.dumps(cfg, indent=1)
    else:
        text = yaml.safe_dump(cfg, sort_keys=False)
    # Keep the old credentials intact if writing or replacement fails. The
    # temporary file is owner-readable only on POSIX and on the same filesystem.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=p.parent,
                                         prefix=".config-", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, p)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    get_config(reload=True)
    return p
