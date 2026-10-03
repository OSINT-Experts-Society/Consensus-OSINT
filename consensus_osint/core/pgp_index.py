"""Read legacy HKP index metadata, without verifying cryptographic key material.

Record grammar: draft-ietf-openpgp-hkp-01, section 7.3.1:
https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-hkp-01#section-7.3.1
Only keys with a complete, case-insensitive email UID match are returned.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import unquote


def _number(value):
    if not value:
        return None
    if not re.fullmatch(r"[0-9]{1,20}", value):
        raise ValueError("invalid index number")
    return int(value)


def _dates(fields, creation, expiration):
    output = {}
    for index, name in ((creation, "created"), (expiration, "expires")):
        value = _number(fields[index])
        if value is None:
            continue
        output[name + "_ts"] = value
        try:
            output[name] = datetime.fromtimestamp(value, timezone.utc).isoformat()
        except (ValueError, OSError, OverflowError):
            # Keep the reported integer; do not invent a calendar date.
            pass
    return output


def _record(line, maximum):
    parts = line.split(":")
    if len(parts) > maximum:
        raise ValueError("unexpected index fields")
    parts += [""] * (maximum - len(parts))
    if parts[-1] and not re.fullmatch(r"[a-zA-Z]+", parts[-1]):
        raise ValueError("invalid index flags")
    return parts


def _uid(value):
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ValueError("invalid UID escaping")
    uid = unquote(value, encoding="utf-8", errors="strict").strip()
    if not uid or any(ord(char) < 32 or ord(char) == 127 for char in uid):
        raise ValueError("invalid UID text")
    match = re.fullmatch(r"[^<>]*<([^<>]+)>", uid)
    address = match.group(1).strip() if match else uid
    return uid, address


def parse_index(document: str, email: str) -> tuple[bool | None, dict, str | None]:
    """True means an email-bound index key, False an explicit empty index.

    None is malformed, incomplete or unbound evidence. Dates and fingerprints
    are reported index metadata, not independently verified key properties.
    Revoked/expired keys may still be present; their flags are preserved.
    """
    if len(document) > 2_000_000:
        return None, {}, "public-key index exceeded the parser limit"
    lines = document.splitlines()
    if len(lines) > 10_000:
        return None, {}, "public-key index exceeded the record limit"
    keys, current, declared = [], None, None
    try:
        for line in lines:
            if not line:
                continue
            if line.startswith("info:"):
                parts = line.split(":")
                if declared is not None or keys or len(parts) != 3 or parts[1] not in ("", "1"):
                    raise ValueError("invalid index header")
                declared = _number(parts[2])
                if declared is None:
                    raise ValueError("missing index count")
            elif line.startswith("pub:"):
                fields = _record(line, 7)
                identifier = fields[1]
                if len(identifier) not in (16, 32, 40, 64) or not re.fullmatch(r"[0-9A-Fa-f]+", identifier):
                    raise ValueError("invalid public-key identifier")
                current = {"identifier" if len(identifier) == 16 else "fingerprint": identifier.upper(), "uids": []}
                for index, name in ((2, "algorithm_id"), (3, "bit_length")):
                    value = _number(fields[index])
                    if value is not None:
                        current[name] = value
                current.update(_dates(fields, 4, 5))
                if fields[6]:
                    current["flags"] = fields[6]
                keys.append(current)
            elif line.startswith("uid:"):
                if current is None:
                    raise ValueError("UID without a public key")
                fields = _record(line, 5)
                _dates(fields, 2, 3)  # validate UID dates without confusing them with key dates
                uid, address = _uid(fields[1])
                if address.lower() == email.strip().lower():
                    current["uids"].append(uid)
                    if fields[4]:
                        current.setdefault("uid_flags", {})[uid] = fields[4]
            else:
                raise ValueError("unrecognized index record")
        if declared is not None and declared != len(keys):
            raise ValueError("index count does not match its records")
        if declared == 0:
            return False, {}, None
        matched = [key for key in keys if key["uids"]]
        if not matched:
            return None, {}, "public-key index contained no complete email UID match"
        # These are public certificate records. Avoid credential-shaped field
        # names so normal secret redaction can remain strict everywhere else.
        extra = {"uid_exact": True, "certificate_count": len(matched), "certificates": matched}
        if len(matched) == 1:
            for field in ("created_ts", "created"):
                if field in matched[0]:
                    extra[field] = matched[0][field]
        return True, extra, None
    except (ValueError, UnicodeError):
        return None, {}, "public-key index was malformed or incomplete"
