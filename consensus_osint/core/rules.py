"""Data rules for any kind of identifier, with retained profile-parser repairs.

A rule says how to ask a site "does this username / e-mail address / phone number
have an account?" and how to read the reply.  Rules live in
``consensus_osint/data/rules.json`` (signed with the rest of the data) and are
maintained by Consensus.  Many were derived from upstream code modules whose whole
logic was one request plus a few string, status or JSON checks: the rule keeps the
credit in ``source`` and names the module it supersedes in ``replaces``.
The retained Andelemandele variant can supplement a positive profile with one
public product-page request, bound by numeric user ID and using the same route.

    id, name, kind      kind is "username" | "email" | "phone"
    url                 the human profile / site page (placeholders allowed)
    check_url           the request URL; placeholders {username} {email} {phone}
                        {query} {md5} {sha256} (hashes of the lower-cased query)
    method, headers     GET / POST / HEAD ...; headers get the same substitution
    payload             an object (JSON), a string body, or null; substitutions
                        in JSON/form strings use that body's encoding
    form                an object sent as a form-encoded body
    follow_redirects    default true; false judges a 3xx exactly as the site sent it
    detect              type "message" | "status_code" | "json", the marker lists,
                        optional "strict" (no marker matched -> unknown, never a
                        verdict) and "json_found_value" / "json_missing_value"
                        (equality instead of truthiness for the JSON paths)
    extract             metadata rules applied to a positive answer
    replaces            id of the code module this rule supersedes (optional)

Detection mirrors :mod:`consensus_osint.core.username_checker`: error and
bot-protection pages are classified first (:func:`~consensus_osint.core.errors.detect_error_page`)
and yield BLOCKED / RATE_LIMITED / UNKNOWN rather than a silent verdict; a rule
with no positive marker cannot claim an account from an empty or generic page;
and a hit is graded like a site-database hit (markers, then whether the page even
mentions the identifier).

:func:`check_rule` accepts either Consensus's :class:`~consensus_osint.core.http.Http`
wrapper or a plain ``httpx.AsyncClient`` (``ctx.client``).  It never raises.
"""
from __future__ import annotations

import hashlib
import html
import json
import logging
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from .errors import detect_error_page
from .models import Finding, Status
from .request_templates import graphql_url, prepare_headers, substitute, substitute_payload, substitute_url

log = logging.getLogger("consensus.rules")

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "rules.json"
KINDS = ("username", "email", "phone")
SOURCE = "rules"
ID_PREFIX = "rule-"
REJECTED_STATUSES = frozenset({400, 405, 406, 409, 415, 422, 423})

# error-page kinds that mean "the site refused us", not "no account"
_BLOCKED_KINDS = ("Captcha", "Bot protection", "Access denied", "Request blocked",
                  "Login required", "Censorship")
_MISSING = object()


# --------------------------------------------------------------------------- loading
def _valid_rule(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    if not isinstance(entry.get("id"), str) or not entry["id"].strip():
        return False
    if entry.get("kind", "email") not in KINDS:
        return False
    for key in ("loud", "nsfw", "impersonate", "follow_redirects"):
        if entry.get(key) is not None and not isinstance(entry[key], bool):
            return False
    for key in ("name", "url", "check_url", "method", "regex_check", "category", "source", "replaces"):
        if entry.get(key) is not None and not isinstance(entry[key], str):
            return False
    if not (entry.get("check_url") or entry.get("url")):
        return False
    headers = entry.get("headers") or {}
    if not isinstance(headers, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()):
        return False
    detect = entry.get("detect")
    if not isinstance(detect, dict) or detect.get("type", "status_code") not in ("message", "json", "status_code"):
        return False
    for key in ("found_strings", "missing_strings", "found_regex", "missing_regex"):
        values = detect.get(key) or []
        if not isinstance(values, list) or any(not isinstance(v, str) or not v.strip() for v in values):
            return False
    for key in ("found_status", "missing_status"):
        values = detect.get(key) or []
        if not isinstance(values, list) or any(type(v) is not int or not 100 <= v <= 599 for v in values):
            return False
    for key in ("json_found_path", "json_missing_path"):
        values = detect.get(key) or []
        if not isinstance(values, list) or any(type(v) not in (str, int) for v in values):
            return False
    return True


def load_rules(path: str | None = None, kind: str | None = None) -> list[dict]:
    """Return the rule entries (optionally one kind), or ``[]`` when the file is absent."""
    p = Path(path) if path else _DATA_PATH
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.debug("rules.json missing or invalid at %s", p, exc_info=True)
        return []
    rules = doc.get("rules") if isinstance(doc, dict) else doc
    if not isinstance(rules, list):
        return []
    out = []
    for r in rules:
        if not _valid_rule(r):
            continue
        k = r.get("kind") or "email"
        if k not in KINDS or (kind and k != kind):
            continue
        out.append(r)
    return out


def replaced_ids(rules: list | None = None) -> set:
    """Ids of code modules that a rule supersedes (the adapters skip them)."""
    return {r["replaces"] for r in (rules if rules is not None else load_rules()) if _valid_rule(r) and r.get("replaces")}


# --------------------------------------------------------------------------- helpers
def placeholders(query: str, kind: str) -> dict:
    """Every ``{name}`` a rule may use, for one query."""
    q = (query or "").strip()
    norm = q.lower().encode("utf-8")
    out = {
        "query": q, "username": q, "user": q, "email": q, "phone": q,
        "md5": hashlib.md5(norm).hexdigest(),
        "sha256": hashlib.sha256(norm).hexdigest(),
    }
    for k in ("query", "username", "user", "email", "phone"):
        out[k + "_lower"] = q.lower()
        out[k + "_upper"] = q.upper()
        out[k + "_re"] = re.escape(q)              # for use inside found_regex / missing_regex
        out[k + "_re_lower"] = re.escape(q.lower())
    return out


def _subst(value: Any, mapping: dict) -> Any:
    """Substitute ``{name}`` placeholders through strings, dicts and lists."""
    return substitute(value, mapping)


def _any_in(needles, hay: str) -> bool:
    return any(n and n in hay for n in needles)


def _truthy(value: Any) -> bool:
    return value not in (None, "", [], {}, 0, 0.0, False)


def _walk(obj: Any, path: list, default: Any = None) -> Any:
    """Follow a JSON path, preserving the distinction between missing and null."""
    cur = obj
    for key in path or []:
        if isinstance(key, bool):
            return default
        if isinstance(key, int):
            if isinstance(cur, list) and -len(cur) <= key < len(cur):
                cur = cur[key]
            else:
                return default
        else:
            if isinstance(key, str) and isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                return default
    return cur


def _parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _with_prefix(value: Any, prefix: str | None) -> Any:
    if prefix and isinstance(value, str) and not value.startswith(prefix):
        return prefix + value
    return value


def _apply_extract(rules: list | None, text: str) -> dict:
    """Pull metadata out of a positive response per the entry's ``extract`` rules.

    ``schema`` "HTML" applies a regex (group 1, else the whole match); "JSON"
    follows ``path`` (and ``item_path`` inside a list).  A rule with ``media`` true
    lands under ``extra["media"]`` like the code modules' avatar / banner links.
    """
    out: dict = {}
    page_fields: set[str] = set()
    if rules is not None and not isinstance(rules, list):
        return out
    body: Any = None
    body_parsed = False
    for rule in rules or []:
        if not isinstance(rule, dict):
            continue
        name = rule.get("name") or "value"
        schema = rule.get("schema") or "JSON"
        if not isinstance(name, str) or not isinstance(schema, str):
            continue
        schema = schema.upper()
        # A constant describes configuration, not evidence in the response.
        if schema == "CONST":
            continue
        if name == "media" and not rule.get("media"):
            continue
        if not isinstance(rule.get("replace") or [], list):
            continue
        prefix = rule.get("prefix")
        path = rule.get("path")
        item_path = rule.get("item_path")
        try:
            if schema == "HTML":
                if not isinstance(path, str):
                    continue
                m = _search(path, text, re.IGNORECASE | re.DOTALL)
                if not m:
                    continue
                value: Any = _with_prefix(html.unescape(m.group(1) if m.groups() else m.group(0)), prefix)
            else:  # JSON
                if not body_parsed:
                    body = _parse_json(text)
                    body_parsed = True
                raw = _walk(body, path if isinstance(path, list) else [])
                if raw is None:
                    continue
                if item_path:
                    if not isinstance(raw, list):
                        continue
                    values = []
                    for item in raw:
                        v = _walk(item, item_path)
                        if v is not None:
                            values.append(_with_prefix(v, prefix) if isinstance(v, str) else v)
                    if not values:
                        continue
                    value = values
                else:
                    value = _with_prefix(raw, prefix) if isinstance(raw, str) else raw
        except Exception:  # noqa: BLE001 - extraction must never break a finding
            continue
        if isinstance(value, str):
            for pair in rule.get("replace") or []:
                if isinstance(pair, (list, tuple)) and len(pair) == 2:
                    value = value.replace(str(pair[0]), str(pair[1]))
            value = value.strip()
            if rule.get("cast") == "int":
                digits = re.sub(r"[^0-9-]", "", value)
                try:
                    value = int(digits)
                except ValueError:
                    continue
        if value not in (None, "", [], {}):
            target = out.setdefault("media", {}) if rule.get("media") else out
            target[name] = value
            if target is out:
                if (schema == "HTML" and name in {"title", "description"} and isinstance(path, str)
                        and ("<title" in path.lower() or ("<meta" in path.lower() and "description" in path.lower()))):
                    page_fields.add(name)
                else:
                    page_fields.discard(name)
    if page_fields:
        out["_page_metadata_fields"] = sorted(page_fields)
    return out


def _base_fields(entry: dict, query: str, mapping: dict) -> dict:
    kind = entry.get("kind") or "email"
    url = substitute_url(entry.get("url"), mapping) if entry.get("url") else None
    if isinstance(url, str):
        try:
            host = (urlsplit(url).hostname or "").lower()
            if host == "invalid" or host.endswith(".invalid"):
                url = None
        except ValueError:
            url = None
    return dict(
        query=query,
        query_type=kind,
        site=entry.get("name") or entry.get("id") or "rule",
        site_id=ID_PREFIX + str(entry.get("id", "")),
        url=url,
        category=entry.get("category", "misc"),
        source=SOURCE,
        method="data rule",
        nsfw=bool(entry.get("nsfw")),
        loud=bool(entry.get("loud")),
        extra={k: v for k, v in (("_rule_source", entry.get("source")), ("_replaces", entry.get("replaces"))) if v},
    )


# --------------------------------------------------------------------------- transport
async def _send(http, method: str, url: str, headers: dict, payload: Any, form: Any,
                follow_redirects: bool, impersonate: bool = False,
                response_headers: dict | None = None) -> tuple[bool, int, str, str | None]:
    """Send the request through an Http wrapper or a raw httpx client.

    Returns ``(ok, status, text, error)``; ``ok`` is False only on a transport
    failure (never on an HTTP error status).
    """
    body_json = payload if isinstance(payload, (dict, list)) else None
    body_str = None if payload is None or body_json is not None else str(payload)
    form = form if isinstance(form, dict) else None
    try:
        if isinstance(http, httpx.AsyncClient):
            kw: dict = {"headers": headers, "follow_redirects": follow_redirects}
            if form is not None:
                kw["data"] = form
            elif body_json is not None:
                kw["json"] = body_json
            elif body_str is not None:
                kw["content"] = body_str.encode("utf-8")
            r = await http.request(method, url, **kw)
            if response_headers is not None:
                response_headers.update(r.headers)
            return True, r.status_code, (r.text or ""), None
        # Consensus Http wrapper (core.http.Http) -> core.http.Response
        kw = {"headers": headers, "follow_redirects": follow_redirects}
        if impersonate:
            kw["impersonate"] = True
        if form is not None:
            kw["data"] = form
        elif body_json is not None:
            kw["json"] = body_json
        elif body_str is not None:
            kw["data"] = body_str
        r = await http.request(method, url, **kw)
        if response_headers is not None:
            response_headers.update(getattr(r, "headers", {}) or {})
        ok = bool(getattr(r, "ok", True))
        return ok, int(getattr(r, "status", 0) or 0), \
            (getattr(r, "text", "") or ""), None if ok else "Provider request failed."
    except Exception as exc:  # noqa: BLE001 - httpx transport / timeout errors
        return False, 0, "", f"{type(exc).__name__}: provider request failed."


# --------------------------------------------------------------------------- evaluation
def native_public_page(response, query: str):
    """Keep retained status-page natives at the same evidence level as rules.

    These are weak page-presence signals, not typed or independently verified
    profile lookups. Error pages and missing query evidence cannot be hits.
    """
    from consensus_osint.vendor.user_scanner.core.result import Result

    if response.headers.get("cf-mitigated", "").lower() == "challenge":
        return Result.error("Page lookup was challenged")
    error = detect_error_page(response.text, response.status_code)
    if error is not None:
        return Result.error(str(error))
    detect = {"type": "status_code", "strict": True, "found_status": [200], "missing_status": [404]}
    status, note = _evaluate(detect, response.text, response.status_code, "username", query)
    if status is Status.FOUND:
        return Result.taken(extra={"_weak_rule": True, "_page_mentions_query": True})
    if status is Status.NOT_FOUND:
        return Result.available()
    return Result.error(note)


def _found_if_evidence(text: str, kind: str = "email", query: str | None = None,
                       has_negative: bool = False) -> tuple:
    """A rule with no positive marker may only claim an account when the body is at
    least a real answer.  An empty response proves nothing for any kind.  For an
    e-mail or phone probe (an API or form endpoint), status alone cannot establish
    an account, and a whole HTML document is not an answer. For a username rule the profile page
    IS an HTML document, so it is refused only when its own title says "not found"
    or, for a rule that has nothing but the status code, when the page never even
    mentions the name (``query``; the proof harness passes None to compare bare
    logic).  A surviving hit is graded weak, see :func:`grade`."""
    if not (text or "").strip():
        return Status.UNKNOWN, "empty response"
    if kind == "username":
        from .username_checker import _soft_404

        if _soft_404(text, query or ""):
            return Status.NOT_FOUND, "soft 404"
        if query and not has_negative and query.lower() not in text.lower():
            return Status.UNKNOWN, "page does not mention the name"
        return Status.FOUND, None
    head = text[:512].lower()
    if "<html" in head or "<!doctype" in head:
        return Status.UNKNOWN, "generic page, no marker for this site"
    return Status.UNKNOWN, "status or absence of a negative marker does not establish an account"


def _evaluate(detect: dict, text: str, status: int, kind: str = "email",
              query: str | None = None) -> tuple[Status, str | None]:
    if kind == "username" and detect.get("type") != "json":
        from .html_evidence import mask_inert

        active = mask_inert(text)
        if active != text:
            original = _evaluate_raw(detect, text, status, kind, query)
            cleaned = _evaluate_raw(detect, active, status, kind, query)
            if original[0] != cleaned[0]:
                return Status.UNKNOWN, "HTML comments or templates change the rule verdict; no reliable profile evidence"
            return cleaned
    return _evaluate_raw(detect, text, status, kind, query)


def _evaluate_raw(detect: dict, text: str, status: int, kind: str = "email",
                  query: str | None = None) -> tuple[Status, str | None]:
    """Apply one rule's detection to a (non-error) response body / status."""
    dtype = detect.get("type") or "status_code"
    if kind == "email" and dtype == "message":
        from .email_validation import _unique_object
        from .provider_contracts import has_service_error

        try:
            body = json.loads(text, object_pairs_hook=_unique_object)
        except (ValueError, TypeError):
            if (text or "").lstrip().startswith(("{", "[")):
                return Status.UNKNOWN, "Malformed or ambiguous JSON cannot supply message-rule evidence"
            body = None
        if isinstance(body, dict) and has_service_error(body):
            return Status.UNKNOWN, "Service error requires a specific structured response contract"
    strict = bool(detect.get("strict"))
    found_strings = detect.get("found_strings") or []
    missing_strings = detect.get("missing_strings") or []
    found_status = detect.get("found_status") or []
    missing_status = detect.get("missing_status") or []
    jf = detect.get("json_found_path") or []
    jm = detect.get("json_missing_path") or []
    jf_val = detect.get("json_found_value", _MISSING)
    jm_val = detect.get("json_missing_value", _MISSING)

    if strict and found_status:
        status_ok = status in found_status
    else:
        status_ok = (200 <= status < 300) or (status in found_status)
    if detect.get("ignore_case") and dtype != "json":
        text = text.lower()
        found_strings = [s.lower() for s in found_strings]
        missing_strings = [s.lower() for s in missing_strings]

    if dtype == "json":
        if status in missing_status:
            return Status.NOT_FOUND, None
        body = _parse_json(text)
        if body is None:
            return Status.UNKNOWN, "response is not JSON"
        if jm:
            v = _walk(body, jm, _MISSING)
            if v is not _MISSING and (_json_equal(v, jm_val) if jm_val is not _MISSING else _truthy(v)):
                return Status.NOT_FOUND, None
        if jf:
            v = _walk(body, jf, _MISSING)
            if v is not _MISSING and (_json_equal(v, jf_val) if jf_val is not _MISSING else _truthy(v)):
                return (Status.FOUND, None) if status_ok else (Status.UNKNOWN, "marker but unexpected status")
            return (Status.UNKNOWN, "no marker matched") if strict or v is _MISSING else (Status.NOT_FOUND, None)
        if jm:
            if strict or _walk(body, jm, _MISSING) is _MISSING:
                return Status.UNKNOWN, "no marker matched"
            return (Status.FOUND, None) if status_ok else (Status.UNKNOWN, "ambiguous response")
        return Status.UNKNOWN, "no json rule matched"

    if dtype == "status_code":
        if status in missing_status:
            return Status.NOT_FOUND, None
        if status_ok:
            return _found_if_evidence(text, kind, query, False)      # a status is not a content marker
        if status >= 500:
            return Status.UNKNOWN, "server error"
        if status in REJECTED_STATUSES:
            return Status.UNKNOWN, f"request rejected (HTTP {status})"
        if strict or kind == "email":
            return Status.UNKNOWN, f"unexpected status (HTTP {status})"
        return Status.NOT_FOUND, None

    # message (default)
    flags = re.IGNORECASE | re.DOTALL if detect.get("ignore_case") else re.DOTALL
    found_regex = detect.get("found_regex") or []
    missing_regex = detect.get("missing_regex") or []
    if status in missing_status:
        return Status.NOT_FOUND, None
    hits = [s in text for s in found_strings] + [bool(_search(p, text, flags)) for p in found_regex]
    matched = bool(hits) and (all(hits) if detect.get("match") == "all" else any(hits))
    negative = (missing_strings and _any_in(missing_strings, text)) or \
               (missing_regex and any(_search(p, text, flags) for p in missing_regex))
    # "found_first": the site's positive marker outranks its negative one when both appear
    # (a page that says "profile" and carries a generic "not found" banner is a profile)
    if matched and status_ok and detect.get("found_first"):
        return Status.FOUND, None
    if negative:
        return Status.NOT_FOUND, None
    if found_strings or found_regex:
        if matched:
            return (Status.FOUND, None) if status_ok else (Status.UNKNOWN, "presence string but unexpected status")
        if strict:
            return Status.UNKNOWN, "no marker matched"
        return Status.NOT_FOUND, None
    if strict and not status_ok:
        return Status.UNKNOWN, f"unexpected status (HTTP {status})"
    # body_not_contains style: no explicit presence string
    return (_found_if_evidence(text, kind, query, bool(missing_strings or missing_regex))
            if status_ok else (Status.UNKNOWN, "ambiguous response"))


_REGEX_CACHE: dict = {}


def _json_equal(value: Any, expected: Any) -> bool:
    # Python treats bool as a number; JSON distinguishes these evidence types.
    if isinstance(value, bool) != isinstance(expected, bool):
        return False
    if isinstance(value, dict) or isinstance(expected, dict):
        return (isinstance(value, dict) and isinstance(expected, dict) and value.keys() == expected.keys()
                and all(_json_equal(value[key], expected[key]) for key in value))
    if isinstance(value, list) or isinstance(expected, list):
        return (isinstance(value, list) and isinstance(expected, list) and len(value) == len(expected)
                and all(_json_equal(v, e) for v, e in zip(value, expected, strict=True)))
    return value == expected


def _search(pattern: str, text: str, flags: int):
    key = (pattern, flags)
    rx = _REGEX_CACHE.get(key)
    if rx is None:
        try:
            rx = re.compile(pattern, flags)
        except re.error:
            return None
        if len(_REGEX_CACHE) < 4096:
            _REGEX_CACHE[key] = rx
    return rx.search(text)


def has_positive_marker(detect: dict) -> bool:
    return bool(detect.get("found_strings") or detect.get("found_regex") or detect.get("json_found_path"))


def has_negative_marker(detect: dict) -> bool:
    return bool(detect.get("missing_strings") or detect.get("missing_regex") or detect.get("json_missing_path"))


def grade(detect: dict, text: str, query: str) -> tuple[float, bool]:
    """Confidence of a positive answer, graded like a site-database hit.

    Returns ``(confidence, page_mentions_query)``.  Markers on both sides score
    highest; a status-only rule is weak and capped; a page that never mentions the
    identifier costs more still.
    """
    pos, neg = has_positive_marker(detect), has_negative_marker(detect)
    if pos and neg:
        c = 0.9
    elif pos or neg:
        c = 0.75
    else:
        c = 0.55
    from .html_evidence import mentions_query

    mentions = mentions_query(text, query)
    if not pos and not mentions:
        c = min(c, 0.5)
    if not pos and not neg:              # status-only: the page loaded, nothing more
        c = min(c, 0.25 if not mentions else 0.4)
    return round(c, 2), mentions


# --------------------------------------------------------------------------- the check
async def check_rule(entry: dict, query: str, http, *, extract: bool = True,
                     allow_loud: bool = False) -> Finding:
    """Check one identifier against one rule.  Never raises."""
    if not _valid_rule(entry) or not isinstance(query, str) or not query.strip():
        return Finding(query=query if isinstance(query, str) else "", query_type="email",
                       site="invalid rule", site_id="rule-invalid", source=SOURCE,
                       status=Status.ERROR, error="invalid rule or identifier")
    query = (query or "").strip()
    kind = entry.get("kind") or "email"
    mapping = placeholders(query, kind)
    base = _base_fields(entry, query, mapping)
    from .module_policy import restriction_for

    restriction = restriction_for(ID_PREFIX + entry["id"])
    base["loud"] = bool(entry.get("loud") or restriction.require_loud)
    if restriction.disabled_reason:
        return Finding(status=Status.SKIPPED, error=restriction.disabled_reason, **base)
    if (entry.get("loud") or restriction.require_loud) and not allow_loud:
        return Finding(status=Status.SKIPPED, error="notification check requires allow_loud", **base)
    t0 = time.perf_counter()
    try:
        rx = entry.get("regex_check")
        if rx and not _search("^(?:" + rx + ")", query, 0):
            return Finding(status=Status.SKIPPED, error="identifier format not accepted by site", **base)
        method = (entry.get("method") or "GET").upper()
        from .eventbrite_lookup import lookup as eventbrite_lookup
        from .eventbrite_lookup import shipped_rule as eventbrite_rule

        if eventbrite_rule(entry):
            async def eventbrite_request(verb, target, *, headers, json=None):
                received = {}
                ok, code, text, _ = await _send(http, verb, target, headers, json, None, True,
                                               response_headers=received)
                if not ok:
                    raise RuntimeError("Eventbrite request failed")
                return httpx.Response(code, text=text, headers=received, request=httpx.Request(verb, target))

            client = http if isinstance(http, httpx.AsyncClient) else getattr(http, "client", None)
            status, fields, note, code = await eventbrite_lookup(
                eventbrite_request, query, {key: value for key, value in entry["headers"].items()
                                           if key.lower() not in {"cookie", "x-csrftoken"}},
                cookie_source=(lambda: client.cookies) if client is not None else None,
                payload_extra={"source_user_id": "", "source_provider": ""})
            extra = {"User ID": fields["user_id"]} if extract and "user_id" in fields else {}
            if status is Status.FOUND:
                extra = {**extra, "_positive_marker": True}
            return Finding(status=status, http_status=code, error=note,
                           elapsed=round(time.perf_counter() - t0, 3),
                           **(base | {"extra": base.get("extra", {}) | extra}))
        url_mapping = mapping
        subdomains = {
            "wix": ("https://{username}.wix.com", "us-user-dev-wix"),
            "blogger": ("https://{username}.blogspot.com/", "us-user-social-blogger"),
            "weebly": ("https://{username}.weebly.com/", "us-user-social-weebly"),
        }
        scoped = subdomains.get(entry["id"])
        if (scoped and kind == "username" and method == "GET" and entry.get("source") == "user-scanner"
                and entry.get("check_url") == entry.get("url") == scoped[0] and entry.get("replaces") == scoped[1]):
            from .request_templates import subdomain_label

            try:
                label = subdomain_label(query)
            except ValueError as exc:
                return Finding(status=Status.SKIPPED, error=str(exc), **(base | {"url": None}))
            # Only URL hostname slots use IDNA; body/header/detection values
            # retain the original identifier, as does the recorded query.
            url_mapping = mapping | {"username": label}
            base["url"] = substitute_url(entry["url"], url_mapping)
        url = substitute_url(entry.get("check_url") or entry.get("url") or "", url_mapping)
        headers = prepare_headers(dict(entry.get("headers") or {}), mapping, entry.get("payload"))
        follow = entry.get("follow_redirects", True)
        follow = True if follow is None else bool(follow)
        allow_profile_redirects = follow
        from .babepedia_contract import shipped_rule as shipped_babepedia_rule
        from .hackernews_contract import shipped_rule as shipped_hackernews_rule
        from .login_rule_contracts import shipped_rule as shipped_login_rule
        from .openstreetmap_contract import shipped_rule as shipped_openstreetmap_rule
        from .profile_http_rules import shipped_rule as shipped_profile_http_rule
        from .profile_metadata_rules import shipped_rule as shipped_metadata_rule
        from .twitter_email_contracts import shipped_rule as shipped_twitter_rule

        login_rule = shipped_login_rule(entry)
        hackernews_rule = shipped_hackernews_rule(entry)
        babepedia_rule = shipped_babepedia_rule(entry)
        openstreetmap_rule = shipped_openstreetmap_rule(entry)
        metadata_rule = shipped_metadata_rule(entry)
        profile_http_rule = shipped_profile_http_rule(entry)
        twitter_email = shipped_twitter_rule(entry)
        if twitter_email or login_rule or hackernews_rule or openstreetmap_rule or babepedia_rule or metadata_rule or profile_http_rule:
            follow = False

        payload = entry.get("payload")
        if payload is not None:
            payload = substitute_payload(payload, mapping, headers, graphql=graphql_url(url))
        form = _subst(entry.get("form"), mapping) if isinstance(entry.get("form"), dict) else None

        response_headers = {}
        ok, status, text, error = await _send(http, method, url, headers, payload, form, follow,
                                              impersonate=bool(entry.get("impersonate")), response_headers=response_headers)
        if ok and (metadata_rule or profile_http_rule) and allow_profile_redirects:
            from urllib.parse import urljoin

            from .profile_http_rules import redirect_target
            from .profile_metadata_rules import _bound

            for _ in range(2):
                location = response_headers.get("location", "")
                if (response_headers.get("cf-mitigated", "").lower() == "challenge"
                        or status not in (301, 302, 303, 307, 308)):
                    break
                if metadata_rule:
                    target = urljoin(url, location) if status != 303 and _bound(location, entry["id"], query) else None
                else:
                    target = redirect_target(entry["id"], url, location, query)
                if target is None or target == url:
                    break
                url = target
                response_headers = {}
                ok, status, text, error = await _send(http, method, url, headers, payload, form, False,
                    impersonate=bool(entry.get("impersonate")), response_headers=response_headers)
                if not ok:
                    break
        elapsed = round(time.perf_counter() - t0, 3)
        if not ok:
            return Finding(status=Status.ERROR, error=(error or "request failed")[:300],
                           elapsed=elapsed, **base)

        if hackernews_rule or openstreetmap_rule or babepedia_rule or metadata_rule:
            from .babepedia_contract import outcome as babepedia_outcome
            from .hackernews_contract import outcome as hackernews_outcome
            from .openstreetmap_contract import outcome as openstreetmap_outcome
            from .profile_metadata_rules import outcome as metadata_outcome

            profile_outcome = hackernews_outcome if hackernews_rule else openstreetmap_outcome if openstreetmap_rule else babepedia_outcome
            if metadata_rule:
                st, fields, note = metadata_outcome(entry["id"], status, text, query, response_headers)
            else:
                st, fields, note = profile_outcome(status, text, query, response_headers)
            fields = fields if extract else {}
            if st is Status.FOUND:
                fields.update(_positive_marker=True, _page_mentions_query=True)
            return Finding(status=st, error=note, http_status=status, elapsed=elapsed,
                           **(base | {"extra": base.get("extra", {}) | fields}))

        if login_rule:
            from .login_rule_contracts import outcome as login_outcome

            guarded = login_outcome(entry["id"], status, text, query, response_headers)
            if guarded is not None:
                st, fields, note = guarded
                fields = fields if extract else {}
                if st is Status.FOUND:
                    fields["_positive_marker"] = True
                return Finding(status=st, error=note, http_status=status, elapsed=elapsed,
                               **(base | {"extra": base.get("extra", {}) | fields}))

        from .zhihu_contract import preflight as zhihu_preflight
        from .zhihu_contract import shipped_rule as shipped_zhihu_rule

        if profile_http_rule:
            from .mailbox_contracts import http_issue

            if entry['id'] == 'mssg_me':
                from .selected_profile_guards import mssg_outcome
                st, fields, note = mssg_outcome(status, text, query, response_headers)
                return Finding(status=st, error=note, http_status=status, elapsed=elapsed,
                               **(base | {'extra': base.get('extra', {}) | (fields if extract else {})}))

            st, note = http_issue(status, response_headers, text)
            if st is not None:
                return Finding(status=st, error=note, http_status=status, elapsed=elapsed, **base)
            from .profile_http_rules import live_text

            shown = live_text(entry["id"], text)
            if shown != text:
                markers = _subst(entry.get("detect") or {}, mapping)
                if _evaluate(markers, text, status, kind, query)[0] != _evaluate(markers, shown, status, kind, query)[0]:
                    return Finding(status=Status.UNKNOWN, http_status=status, elapsed=elapsed, **base,
                                   error="The profile marker appears only inside a script or style sheet; "
                                         "no reliable profile evidence")

        if shipped_zhihu_rule(entry):
            guarded = zhihu_preflight(status, text, response_headers)
            if guarded is not None:
                st, note = guarded
                return Finding(status=st, error=note, http_status=status, elapsed=elapsed, **base)

        if twitter_email:
            from .twitter_email_contracts import outcome as twitter_outcome

            st, fields, note = twitter_outcome(httpx.Response(status, text=text, headers=response_headers), query)
            return Finding(status=st, error=note, http_status=status, elapsed=elapsed,
                           **(base | {"extra": base.get("extra", {}) | fields}))

        from .firebase_contracts import outcome as firebase_outcome
        from .firebase_contracts import shipped_reset_rule

        if shipped_reset_rule(entry):
            st, fields, note = firebase_outcome("reset", httpx.Response(status, text=text, headers=response_headers), query)
            return Finding(status=st, error=note, http_status=status, elapsed=elapsed,
                           **(base | {"extra": base.get("extra", {}) | fields}))

        detect = _subst(entry.get("detect") or {}, mapping)     # markers may name the identifier itself
        ignore_403 = 403 in (detect.get("found_status") or []) or 403 in (detect.get("missing_status") or [])
        if httpx.Headers(response_headers).get("cf-mitigated", "").lower() == "challenge":
            return Finding(status=Status.BLOCKED, http_status=status, elapsed=elapsed,
                           error="Provider challenge; account status is unknown.", **base)
        if (entry["id"] == "arduino" and kind == "username" and method == "GET"
                and entry.get("source") == "user-scanner" and entry.get("replaces") == "us-user-dev-arduino"
                and entry.get("url") == "https://forum.arduino.cc/u/{username}"
                and entry.get("check_url") == "https://forum.arduino.cc/u/{username}.json"
                and entry.get("detect") == {"type": "status_code", "strict": True,
                                             "found_status": [200], "missing_status": [404]}):
            from .discourse_contracts import profile_outcome

            st, _, note = profile_outcome(httpx.Response(status, text=text, headers=response_headers), query)
            fields = {"_positive_marker": True, "_profile_binding": "Returned forum username matches the query."} if st is Status.FOUND else {}
            return Finding(status=st, http_status=status, error=note, elapsed=elapsed,
                           **(base | {"extra": base.get("extra", {}) | fields}))
        # The shipped Spotify API uses exact typed JSON codes, never HTTP404 or text prefixes.
        if (entry["id"] == "spotify" and kind == "email" and method == "GET"
                and entry.get("check_url") == "https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}"):
            from .media_contracts import outcome

            st, fields, note = outcome("spotify", httpx.Response(status, text=text, headers=response_headers), query)
            if st is Status.FOUND:
                fields["_positive_marker"] = True
            return Finding(status=st, http_status=status, error=note, elapsed=elapsed,
                           **(base | {"extra": base.get("extra", {}) | fields}))
        if (entry["id"] == "soundcloud" and kind == "username" and method == "GET"
                and entry.get("source") == "user-scanner" and entry.get("replaces") == "us-user-music-soundcloud"
                and entry.get("check_url") == "https://soundcloud.com/{username}"
                and entry.get("detect") == {"type": "message", "strict": True,
                                             "found_strings": ["soundcloud://users:", '"username":"'],
                                             "match": "all", "found_status": [200], "missing_status": [404]}
                and entry.get("extract") == [{"name": "verified", "schema": "CONST", "value": "Yes"}]):
            from .soundcloud_contracts import response_outcome

            st, fields, note = response_outcome(httpx.Response(status, text=text, headers=response_headers), query)
            if st is Status.FOUND:
                fields = fields if extract else {}
                fields.update(_positive_marker=True, _page_mentions_query=True,
                              _profile_binding="SoundCloud hydration permalink matched the requested username.")
            return Finding(status=st, http_status=status, error=note, elapsed=elapsed,
                           confidence=0.9 if st is Status.FOUND else None,
                           **(base | {"extra": base.get("extra", {}) | fields}))
        err = detect_error_page(text, status, None, ignore_403)
        if err is not None:
            if err.kind == "Rate limited":
                st = Status.RATE_LIMITED
            elif err.kind in _BLOCKED_KINDS:
                st = Status.BLOCKED
            else:
                st = Status.UNKNOWN
            return Finding(status=st, http_status=status, error=str(err), elapsed=elapsed, **base)

        # Apply the maintained contract only to the shipped provider scope;
        # custom rules sharing a display name retain their own detectors.
        if (entry["id"] == "duolingo" and kind == "email" and method == "GET"
                and entry.get("check_url") == "https://www.duolingo.com/2017-06-30/users?email={email}"):
            from .jobs_learning_contracts import outcome

            st, fields, note = outcome("duolingo", httpx.Response(status, text=text, headers=response_headers), query)
            confidence = None
            if st is Status.FOUND:
                base["url"] = "https://www.duolingo.com/profile/" + quote(fields["username"], safe="")
                fields = fields if extract else {}
                fields["_positive_marker"] = True
                confidence, fields["_page_mentions_query"] = grade(detect, text, query)
            return Finding(status=st, http_status=status, error=note, elapsed=elapsed,
                           confidence=confidence, **(base | {"extra": base.get("extra", {}) | fields}))
        st, note = _evaluate(detect, text, status, kind, query)
        finding = Finding(status=st, http_status=status, error=note, elapsed=elapsed, **base)
        if st is Status.FOUND:
            if kind == "username" and detect.get("type") != "json":
                from .html_evidence import mask_inert

                text = mask_inert(text)
            extra = _apply_extract(entry.get("extract"), text) if extract else {}
            if extract:
                from .legacy_profiles import extract_legacy, supplement_legacy

                try:
                    extra = extract_legacy(entry, text, extra)
                    extra = await supplement_legacy(entry, text, extra, http)
                except Exception as exc:  # preserve the established verdict if optional parsing fails
                    extra["_enrichment_error"] = f"Additional profile details could not be read ({type(exc).__name__})."
                    log.debug("legacy profile extraction failed", exc_info=True)
            if extra:
                finding.extra.update(extra)
            finding.confidence, mentions = grade(detect, text, query)
            finding.extra["_page_mentions_query"] = mentions
            # Record why the rule matched. Email/hash APIs need not echo the input;
            # absence of that echo is useful for profile pages, not every API.
            dtype = detect.get("type") or "status_code"
            finding.extra["_positive_marker"] = bool(
                detect.get("json_found_path") if dtype == "json" else
                dtype != "status_code" and (detect.get("found_strings") or detect.get("found_regex")))
            if not has_positive_marker(detect) and not has_negative_marker(detect):
                finding.extra["_confidence_cap"] = 0.25 if not mentions else 0.4
        finding.elapsed = round(time.perf_counter() - t0, 3)
        return finding
    except Exception as exc:  # noqa: BLE001 - the checker must never raise
        log.debug("check_rule failed for %s", base.get("site_id"), exc_info=True)
        return Finding(status=Status.ERROR, error=f"{type(exc).__name__}: rule processing failed.",
                       elapsed=round(time.perf_counter() - t0, 3), **base)


__all__ = ["load_rules", "replaced_ids", "check_rule", "placeholders", "grade",
           "has_positive_marker", "has_negative_marker", "KINDS", "SOURCE", "ID_PREFIX"]
