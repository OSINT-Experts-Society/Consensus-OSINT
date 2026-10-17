"""Explicit, local preferences; never persist identifiers, routes or loud consent."""
from __future__ import annotations

import json
import math

DEFAULTS = {"details": False, "all": False, "fast": True, "top": None, "no_breach": False, "timeout": None}


def path():
    from .sitesdb import user_config_dir

    return user_config_dir() / "session-settings.json"


def validated(values):
    if not isinstance(values, dict) or set(values) - (DEFAULTS.keys() | {"animation"}):
        raise ValueError("Saved search preferences contain unsupported settings")
    result = dict(DEFAULTS, **values)
    for name in ("details", "all", "fast", "no_breach", "animation"):
        if name in result and type(result[name]) is not bool:
            raise ValueError(f"Saved preference {name} must be on or off")
    top, timeout = result["top"], result["timeout"]
    if top is not None and (type(top) is not int or top <= 0):
        raise ValueError("Saved search size must be a positive whole number")
    if timeout is not None:
        try:
            valid = type(timeout) in (int, float) and math.isfinite(timeout) and timeout > 0
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError("Saved timeout must be positive and finite")
    if top is not None:
        result["fast"] = False
    return result


def load():
    location = path()
    if not location.exists():
        return dict(DEFAULTS)
    if location.stat().st_size > 8192:
        raise ValueError("Saved search preferences file is too large")
    return validated(json.loads(location.read_text(encoding="utf-8")))


def save(preferences, *, animation):
    from .install_manager import atomic_json

    value = validated(dict(preferences, animation=animation))
    atomic_json(path(), value)
    return path()


def clear():
    path().unlink(missing_ok=True)
