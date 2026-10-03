'Verify the authenticity and age of the shipped Consensus lookup database.'
from __future__ import annotations

import calendar
import hashlib
import json
import time
from functools import lru_cache
from pathlib import Path

from .sitesdb import DATA_DIR

#: Maintainers' Ed25519 public key (hex).  Set once; a build signed by any other
#: key is reported as unverified.
PUBLIC_KEY_HEX = "a64ecdc060d24591528d5ddbf0ffb083286628df296e6813914bb9fdbc8948bd"

#: The files a build stamp covers - everything the scanner loads.
SIGNED_FILES = ("sites.json", "sites_wmn.json", "sites_fediverse.json", "rules.json")

#: After this many days a build is called stale and the tool suggests checking for a newer one.
STALE_AFTER_DAYS = 14

#: Where `consensus update` looks for the latest stamp: one small static file, fetched only on request.
LATEST_STAMP_URL = "https://raw.githubusercontent.com/OSINT-Experts-Society/Consensus-OSINT/main/consensus_osint/data/build.json"


# ------------------------------------------------------------------ Ed25519 (RFC 8032)
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q:
        x = x * _I % _Q
    if (x * x - xx) % _Q:
        raise ValueError("no such point")
    return x


_BY = 4 * pow(5, _Q - 2, _Q) % _Q
_BX = _xrecover(_BY)
if _BX & 1:
    _BX = _Q - _BX
_B = (_BX, _BY, 1, _BX * _BY % _Q)   # base point, extended coordinates (X, Y, Z, T)
_ID = (0, 1, 1, 0)


def _add(P, R):
    """Unified point addition (also doubling) on the twisted Edwards curve."""
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = R
    a = (y1 - x1) * (y2 - x2) % _Q
    b = (y1 + x1) * (y2 + x2) % _Q
    c = 2 * t1 * t2 * _D % _Q
    d = 2 * z1 * z2 % _Q
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q)


def _mul(P, e: int):
    Q = _ID
    for i in range(e.bit_length() - 1, -1, -1):
        Q = _add(Q, Q)
        if (e >> i) & 1:
            Q = _add(Q, P)
    return Q


def _encode(P) -> bytes:
    x, y, z, _ = P
    zi = pow(z, _Q - 2, _Q)
    x, y = x * zi % _Q, y * zi % _Q
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(s: bytes):
    if len(s) != 32:
        raise ValueError("bad point length")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _Q:
        raise ValueError("bad point")
    x = _xrecover(y)
    if x == 0 and sign:
        raise ValueError("non-canonical point")
    if (x & 1) != sign:
        x = _Q - x
    if (-x * x + y * y - 1 - _D * x * x * y * y) % _Q:
        raise ValueError("point not on curve")
    return (x, y, 1, x * y % _Q)


def _equal(P, R) -> bool:
    x1, y1, z1, _ = P
    x2, y2, z2, _ = R
    return (x1 * z2 - x2 * z1) % _Q == 0 and (y1 * z2 - y2 * z1) % _Q == 0








def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """True only for a valid signature; never raises."""
    try:
        if len(sig) != 64 or len(pk) != 32:
            return False
        R, A = _decode(sig[:32]), _decode(pk)
        if _equal(_mul(A, 8), _ID) or _equal(_mul(R, 8), _ID):
            return False
        S = int.from_bytes(sig[32:], "little")
        if S >= _L:
            return False
        k = int.from_bytes(hashlib.sha512(sig[:32] + pk + msg).digest(), "little") % _L
        return _equal(_mul(_B, S), _add(R, _mul(A, k)))
    except (ValueError, TypeError):
        return False


# ------------------------------------------------------------------ the build stamp
def _canonical(raw: bytes) -> bytes:
    """Line endings are not content: a checkout with core.autocrlf, an editor, or a
    Windows-written file must hash the same as the LF copy git stores."""
    return raw.replace(b"\r\n", b"\n")


def database_digest(data_dir=DATA_DIR) -> str:
    """SHA-256 over the signed data files (line endings normalised), in a fixed order."""
    h = hashlib.sha256()
    for name in SIGNED_FILES:
        p = Path(data_dir) / name
        h.update(name.encode() + b"\0")
        h.update(hashlib.sha256(_canonical(p.read_bytes())).digest() if p.exists() else b"missing")
    return h.hexdigest()


def stamp_message(stamp: dict) -> bytes:
    """Exactly what is signed: the build number, its date and the data digest."""
    core = {"build": stamp.get("build"), "date": stamp.get("date"), "digest": stamp.get("digest")}
    return json.dumps(core, sort_keys=True, separators=(",", ":")).encode()


def read_stamp(data_dir=DATA_DIR) -> dict:
    p = Path(data_dir) / "build.json"
    if not p.exists():
        return {}
    try:
        stamp = json.loads(p.read_text(encoding="utf-8"))
        return stamp if isinstance(stamp, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


@lru_cache(maxsize=128)
def _verify_cached(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Cache only the expensive mathematical check, keyed by its full inputs."""
    return verify(pk, msg, sig)


def check_database(data_dir=DATA_DIR, *, now: float = None, public_key_hex: str = None) -> dict:
    """Verify the shipped build stamp against the data files.

    Returns a dict with ``present``, ``build``, ``date``, ``sites``, ``notes``,
    ``verified``, ``reason``, ``age_days`` and ``stale``. File content, stamp
    metadata and age are read anew; only signature verification is cached.
    """
    data_dir = Path(data_dir)
    stamp = read_stamp(data_dir)
    out = {"present": bool(stamp),
           "build": stamp.get("build") if type(stamp.get("build")) is int else None,
           "date": stamp.get("date") if isinstance(stamp.get("date"), str) else None,
           "sites": stamp.get("sites") if type(stamp.get("sites")) is int and stamp["sites"] >= 0 else 0,
           "notes": stamp.get("notes") if isinstance(stamp.get("notes"), dict) else {},
           "verified": False, "reason": "", "age_days": None, "stale": False}
    if not stamp:
        out["reason"] = "no build stamp (unsigned local data)"
    else:
        pk_hex = PUBLIC_KEY_HEX if public_key_hex is None else public_key_hex
        try:
            pk, sig = bytes.fromhex(pk_hex), bytes.fromhex(stamp.get("signature") or "")
        except (ValueError, TypeError):
            pk, sig = b"", b""
        try:
            digest = database_digest(data_dir)
        except OSError:
            digest = None
        if not pk:
            out["reason"] = "no public key in this build of the tool"
        elif digest is None:
            out["reason"] = "could not read the signed data files"
        elif digest != stamp.get("digest"):
            out["reason"] = "data files differ from the signed build (modified locally?)"
        elif not _verify_cached(pk, stamp_message(stamp), sig):
            out["reason"] = "signature is not from the Consensus maintainers"
        else:
            out["verified"] = True
        try:
            built = calendar.timegm(time.strptime(stamp.get("date", ""), "%Y-%m-%d"))
            age = int(((time.time() if now is None else now) - built) // 86400)
            out["age_days"] = max(age, 0)
            out["stale"] = age > STALE_AFTER_DAYS
        except (ValueError, TypeError, OverflowError):
            pass
    return out


def fetch_latest_stamp(url: str = LATEST_STAMP_URL, timeout: float = 20.0) -> dict:
    """The maintainers' current build stamp - one request for a small static file.

    Only ever called by ``consensus update``, i.e. when the user explicitly asks.
    """
    import urllib.request

    req = urllib.request.Request(url, headers={"User-Agent": "consensus-update-check"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ValueError("build stamp exceeds 1 MiB")
        stamp = json.loads(raw.decode("utf-8"))
        if not isinstance(stamp, dict):
            raise ValueError("build stamp must be a JSON object")
        return stamp
