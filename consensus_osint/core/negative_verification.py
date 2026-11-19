"""Per-scan negative controls for public account/profile checks."""
from __future__ import annotations

import re
import secrets
import string
from contextvars import ContextVar
from urllib.parse import unquote, urlsplit

from .emailinfo import valid_syntax
from .models import INFO_CATEGORIES, Finding, Status
from .modules import Module
from .sitesdb import Site

collect_control_evidence = ContextVar("collect_control_evidence", default=False)

# These native lookups read public profile records. Other native implementations
# need an individual suitability review before sending them synthetic inputs.
PUBLIC_PROFILE_MODULES = frozenset({
    "rule-gravatar", "rule-duolingo", "us-email-social-gravatar", "us-user-social-gravatar",
    "extras-github-search",
    *("us-user-gaming-" + name for name in (
        "habbo_com", "habbo_com_br", "habbo_com_tr", "habbo_de", "habbo_es", "habbo_fi",
        "habbo_fr", "habbo_it", "habbo_nl", "origins_habbo_com", "origins_habbo_com_br", "origins_habbo_es",
    )),
})


_ACTION = re.compile(
    r"(?:^|[^a-z])(reset|forgot|recover|delete|logout|login|sign[-_]?in|sign[-_]?up|register|sendmail|subscribe|notify|validate|availability)"
    r"(?:[^a-z]|$)", re.I)


def _public_profile_route(url):
    try:
        parsed = urlsplit(url)
        return (parsed.scheme in {"http", "https"} and bool(parsed.hostname) and not parsed.username
                and not parsed.password and not _ACTION.search(unquote(parsed.path + "?" + parsed.query)))
    except ValueError:
        return False


def control_input(item, primary: Finding) -> tuple[str | None, str]:
    if primary.status is Status.SKIPPED:
        return None, "Primary check skipped"
    if primary.status in (Status.BLOCKED, Status.RATE_LIMITED):
        return None, "Provider restricted the primary request"
    if primary.query_type not in {"username", "email"} or primary.category in (
            *INFO_CATEGORIES, "breach", "reputation"):
        return None, "Outside account-verification scope"
    if primary.loud or getattr(item, "loud", False):
        return None, "Check may send a notification"
    if isinstance(item, Module):
        if item.disabled_reason or item.id not in PUBLIC_PROFILE_MODULES:
            return None, "No reviewed public profile control for this module"
    elif isinstance(item, Site):
        if (item.effective_disabled or item.method.upper() != "GET" or item.payload
                or primary.query_type != "username" or not _public_profile_route(item.url)
                or not _public_profile_route(item.url_probe or item.url)):
            return None, "No reviewed public profile control for this site"
    else:
        return None, "Unsupported implementation"

    identifier = primary.query
    suffix = ""
    if primary.query_type == "email":
        if not valid_syntax(identifier):
            return None, "Unsupported email format"
        local, _, domain = identifier.rpartition("@")
        identifier, suffix = local, "@" + domain
    # Start with the target's shape, then try common valid lengths. Never
    # turn a stripped or format-rejected value into a passing observation.
    def replacement(ch):
        alphabet = string.digits if ch.isdigit() else string.ascii_lowercase
        value = secrets.choice(alphabet)
        return value.upper() if ch.isupper() else value

    def names():
        if (6 <= len(identifier) <= 32 and re.fullmatch(r"[A-Za-z0-9._-]+", identifier)
                and sum(ch.isalnum() for ch in identifier) >= 6 and not suffix):
            yield "".join(replacement(ch) if ch.isalnum() else ch for ch in identifier)
        for size in (12, 10, 8, 16, 6):
            yield "".join(secrets.choice(string.ascii_lowercase) for _ in range(size))

    for name in names():
        candidate = name + suffix
        if candidate.casefold() == primary.query.casefold() or (suffix and not valid_syntax(candidate)):
            continue
        if isinstance(item, Site) and (item.normalise_username(candidate) != candidate
                                     or not item.username_allowed(candidate)
                                     or item.normalise_username(primary.query).casefold() == candidate.casefold()
                                     or item.probe_url(candidate) == item.probe_url(primary.query)):
            continue
        return candidate, ""
    return None, "No distinct format-valid synthetic identifier"


def assess_control(primary: Finding, control: Finding, expected_query: str) -> dict:
    if (control.query != expected_query or control.query_type != primary.query_type
            or control.site_id != primary.site_id or control.extra.get("_lookup_id") != primary.extra.get("_lookup_id")):
        return {"outcome": "not_verified", "reason": "Control identity mismatch"}
    if control.status is Status.SKIPPED:
        reason = "Scan budget exhausted" if control.extra.get("_budget_skipped") else "Control skipped"
        return {"outcome": "not_verified", "reason": reason}
    if control.http_status in (400, 422) or (
            control.error and re.search(r"(?:invalid|unsupported|malformed).*(?:format|input|identifier|username|email|domain)", control.error, re.I)):
        return {"outcome": "not_verified", "reason": "Control input rejected"}
    if control.http_status in (401, 403, 407, 429) or (control.http_status or 0) >= 500:
        return {"outcome": "inconclusive", "reason": "Control access or service error"}
    if (control.status is Status.NOT_FOUND and str(control.extra.get("_lookup_id", "")).startswith("site:")
            and control.http_status not in (404, 410) and not getattr(control, "_explicit_absence", False)):
        return {"outcome": "inconclusive", "reason": "Catalogue inferred absence without an explicit missing-account response"}
    outcome = {Status.NOT_FOUND: "passed", Status.FOUND: "failed"}.get(control.status, "inconclusive")
    return {"outcome": outcome, "control_status": control.status.value}
