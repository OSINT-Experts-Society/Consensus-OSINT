"""Extra keyless e-mail / username checks (``source="extras"``).

This adapter fills the gaps left by the other vendored families: it only adds
*keyless* endpoints that ``holehe``, ``user-scanner`` and ``socialscan`` do not
already cover, a proper Gravatar **deep-profile** module (e-mail and username),
and a handful of breach / stealer-log hints.

Every module follows the same contract:

* uses ``ctx.client`` (an ``httpx.AsyncClient``) with ``timeout=ctx.timeout`` and
  a realistic browser ``User-Agent``;
* never raises - all exceptions become an ``ERROR`` :class:`Finding`;
* maps ``429`` to ``RATE_LIMITED``, captcha / Cloudflare / ``403`` to ``BLOCKED``,
  ``5xx`` and ambiguous bodies to ``UNKNOWN`` and network faults to ``ERROR``.

Only original code lives here; the referenced GPL-3.0 / MIT projects (Zehef,
Eyes, hashtray, mosint, numint) were studied for endpoint behaviour only.
"""
from __future__ import annotations

import functools
import hashlib
import re
from urllib.parse import quote

import httpx

from ..core.models import Finding, Status
from ..core.modules import Context, Module

# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_BLOCK_MARKERS = (
    "just a moment",
    "attention required",
    "cf-chl",
    "cloudflare",
    "captcha",
    "access denied",
    "request blocked",
    "are you a robot",
)

# Single source of truth for module metadata; the Module objects and the
# Finding objects both read from here so they can never drift apart.
SPECS: dict[str, dict] = {
    "extras-gravatar": dict(
        name="Gravatar", kind="email", category="profile",
        url="https://gravatar.com", method="profile json", tags=["profile"]),
    "extras-gravatar-username": dict(
        name="Gravatar", kind="username", category="profile",
        url="https://gravatar.com", method="profile json", tags=["profile"]),
    "extras-proton-pgp": dict(
        name="ProtonMail", kind="email", category="email",
        url="https://proton.me", method="pgp key lookup", tags=["email"]),
    "extras-adobe": dict(
        name="Adobe", kind="email", category="creative",
        url="https://adobe.com", method="signin account lookup", tags=[]),
    "extras-microsoft": dict(
        name="Microsoft account", kind="email", category="email",
        url="https://account.microsoft.com", method="GetCredentialType", tags=["email"]),
    "extras-picsart": dict(
        name="Picsart", kind="email", category="media",
        url="https://picsart.com", method="email existence api", tags=[]),
    "extras-flickr": dict(
        name="Flickr", kind="email", category="media",
        url="https://flickr.com", method="findByEmail api", tags=[]),
    "extras-mailru": dict(
        name="Mail.ru", kind="email", category="email",
        url="https://mail.ru", method="user exists api", tags=["email"]),
    "extras-bitmoji": dict(
        name="Bitmoji / Snapchat", kind="email", category="social",
        url="https://snapchat.com", method="bitmoji user find", tags=[]),
    "extras-duolingo": dict(
        name="Duolingo", kind="email", category="learning",
        url="https://duolingo.com", method="public users api", tags=[]),
    "extras-github-search": dict(
        name="GitHub (email search)", kind="email", category="dev",
        url="https://github.com", method="users search api", tags=[]),
    "extras-spotify": dict(
        name="Spotify", kind="email", category="music",
        url="https://spotify.com", method="signup validate", tags=[]),
    "extras-bandlab": dict(
        name="BandLab", kind="email", category="music",
        url="https://bandlab.com", method="signup validation api", tags=[]),
    "extras-kommo": dict(
        name="Kommo (amoCRM)", kind="email", category="crm",
        url="https://kommo.com", method="login-check api", tags=[]),
    "extras-hudsonrock-email": dict(
        name="Hudson Rock (email)", kind="email", category="breach",
        url="https://hudsonrock.com", method="cavalier osint", tags=["breach"]),
    "extras-hudsonrock-username": dict(
        name="Hudson Rock (username)", kind="username", category="breach",
        url="https://hudsonrock.com", method="cavalier osint", tags=["breach"]),
    "extras-proxynova-comb": dict(
        name="ProxyNova COMB", kind="email", category="breach",
        url="https://proxynova.com", method="comb leak search", tags=["breach"]),
    "extras-xposedornot": dict(
        name="XposedOrNot", kind="email", category="breach",
        url="https://xposedornot.com", method="breach check api", tags=["breach"]),
    "extras-leakcheck-public": dict(
        name="LeakCheck (email)", kind="email", category="breach",
        url="https://leakcheck.io", method="public breach api", tags=["breach"]),
    "extras-leakcheck-username": dict(
        name="LeakCheck (username)", kind="username", category="breach",
        url="https://leakcheck.io", method="public breach api", tags=["breach"]),
    "extras-leakcheck-phone": dict(
        name="LeakCheck (phone)", kind="phone", category="breach",
        url="https://leakcheck.io", method="public breach api", tags=["breach"]),
}


def _headers(ctx: Context, extra: dict | None = None) -> dict:
    h = {
        "User-Agent": (ctx.user_agent or _UA),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if extra:
        h.update(extra)
    return h


def _mk(site_id: str, query: str, status: Status, **kw) -> Finding:
    """Build a Finding from a module spec, keeping metadata consistent."""
    s = SPECS[site_id]
    return Finding(
        query=query,
        query_type=s["kind"],
        site=s["name"],
        site_id=site_id,
        status=status,
        source="extras",
        category=s.get("category", "misc"),
        url=kw.pop("url", s.get("url")),
        method=kw.pop("method", s.get("method")),
        tags=list(s.get("tags") or []),
        **kw,
    )


def _looks_blocked(r: httpx.Response) -> bool:
    if r.headers.get("cf-mitigated", "").lower() == "challenge":
        return True
    try:
        if isinstance(r.json(), (dict, list)):
            return False  # ordinary metadata can contain words such as Cloudflare
    except (ValueError, UnicodeError):
        pass
    try:
        body = r.text[:2048].lower()
    except Exception:
        return False
    return any(m in body for m in _BLOCK_MARKERS)


def _guard_status(r: httpx.Response, *, auth_block: bool = True, inspect_body: bool = True) -> Status | None:
    """Return a non-success Status for common failure responses, else None."""
    sc = r.status_code
    if sc == 429:
        return Status.RATE_LIMITED
    if auth_block and sc in (401, 403, 406, 407, 418, 451):
        return Status.BLOCKED
    if r.headers.get("cf-mitigated", "").lower() == "challenge":
        return Status.BLOCKED
    if not 200 <= sc < 300:
        return Status.UNKNOWN
    if inspect_body and _looks_blocked(r):
        return Status.BLOCKED
    return None


def _json(r: httpx.Response):
    try:
        return r.json()
    except Exception:
        return None


def _uniq(seq) -> list:
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _text(value) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _objects(value) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _provider_error(data: dict) -> bool:
    return bool(data.get("error") or data.get("Error"))


def _guarded(site_id: str):
    """Wrap a check so it can never raise and yields tidy ERROR messages."""

    def deco(fn):
        @functools.wraps(fn)
        async def wrap(query: str, ctx: Context) -> Finding:
            try:
                return await fn(query, ctx)
            except httpx.TimeoutException:
                return _mk(site_id, query, Status.ERROR, error="request timed out")
            except httpx.HTTPError as exc:
                return _mk(site_id, query, Status.ERROR, error=f"{type(exc).__name__}: {exc}")
            except Exception as exc:  # noqa: BLE001 - defensive, never raise
                return _mk(site_id, query, Status.ERROR, error=f"{type(exc).__name__}: {exc}")

        return wrap

    return deco


# ---------------------------------------------------------------------------
# Gravatar deep profile (email + username)
# ---------------------------------------------------------------------------
def _profile_strings(data: dict, fields: tuple) -> dict:
    return {target: data[source] for source, target in fields if _text(data.get(source))}


def _parse_gravatar_entry(entry: dict) -> dict:
    """Keep public legacy profile fields; malformed optional fields are omitted."""
    extra = _profile_strings(entry, (
        ("displayName", "display_name"), ("preferredUsername", "username"), ("aboutMe", "about"),
        ("currentLocation", "location"), ("jobTitle", "job_title"), ("job_title", "job_title"),
        ("company", "company"), ("pronouns", "pronouns"), ("hash", "hash"),
        ("thumbnailUrl", "thumbnail"), ("profileUrl", "profile_url"),
    ))
    name = entry.get("name")
    if isinstance(name, dict) and _text(name.get("formatted")):
        extra["full_name"] = name["formatted"]
    for source, target in (("emails", "emails"), ("photos", "photos")):
        values = _uniq(_text(row.get("value")) for row in _objects(entry.get(source)))
        if values:
            extra[target] = values
    links = [extra.get("profile_url")]
    links.extend(_text(row.get("value")) for row in _objects(entry.get("urls")))
    accounts = []
    for row in _objects(entry.get("accounts")):
        service = _text(row.get("shortname")) or _text(row.get("name")) or _text(row.get("domain"))
        url = _text(row.get("url")) or ""
        handle = _text(row.get("username")) or ""
        display = _text(row.get("display"))
        if service or url or handle or display:
            account = {"service": service, "url": url, "handle": handle}
            if display:
                account["display_name"] = display
            accounts.append(account)
            links.append(url)
    if _uniq(links):
        extra["links"] = _uniq(links)
    if accounts:
        extra["accounts"] = accounts
    return extra


def _parse_gravatar_v3(obj: dict) -> dict:
    """Keep public v3 fields without inventing usernames from service labels."""
    extra = _profile_strings(obj, (
        ("display_name", "display_name"), ("hash", "hash"), ("location", "location"),
        ("description", "about"), ("job_title", "job_title"), ("company", "company"),
        ("pronouns", "pronouns"), ("avatar_url", "thumbnail"), ("profile_url", "profile_url"),
    ))
    links = [extra.get("profile_url")]
    accounts = []
    for row in _objects(obj.get("verified_accounts")):
        service = _text(row.get("service_label")) or _text(row.get("service_type"))
        url = _text(row.get("url")) or ""
        if service or url:
            accounts.append({"service": service, "url": url})
            links.append(url)
    links.extend(_text(row.get("url")) for row in _objects(obj.get("links")))
    if _uniq(links):
        extra["links"] = _uniq(links)
    if accounts:
        extra["accounts"] = accounts
    return extra


def _gravatar_identity(extra: dict, *, legacy: bool = False) -> bool:
    digest = extra.get("hash")
    if isinstance(digest, str) and len(digest) in ((32, 64) if legacy else (64,)):
        if re.fullmatch(r"[0-9a-fA-F]+", digest):
            return True
    return bool(legacy and _text(extra.get("username")))


async def _gravatar_lookup(site_id: str, query: str, ctx: Context, identifiers: list[str]) -> Finding:
    """Resolve legacy hash/slug profiles and then the documented v3 SHA256/slug."""
    hdrs = _headers(ctx, {"Accept": "application/json"})
    for ident in identifiers:
        r = await ctx.client.get(
            f"https://gravatar.com/{quote(ident, safe='')}.json",
            headers=hdrs, timeout=ctx.timeout, follow_redirects=True,
        )
        guard = _guard_status(r)
        if r.status_code == 404 and guard is not Status.BLOCKED:
            continue
        if guard is not None:
            return _mk(site_id, query, guard, http_status=r.status_code)
        data = _json(r)
        entries = data.get("entry") if isinstance(data, dict) else None
        if (r.status_code == 200 and isinstance(data, dict) and not _provider_error(data) and isinstance(entries, list)
                and entries and isinstance(entries[0], dict)):
            extra = _parse_gravatar_entry(entries[0])
            if _gravatar_identity(extra, legacy=True):
                url = extra.get("profile_url") or f"https://gravatar.com/{quote(ident, safe='')}"
                return _mk(site_id, query, Status.FOUND, http_status=r.status_code, url=url, extra=extra)
        return _mk(site_id, query, Status.UNKNOWN, http_status=r.status_code,
                   error="profile response contained no identified profile")

    # Email callers supply MD5 followed by SHA256; username callers supply a slug.
    ident = identifiers[-1]
    r = await ctx.client.get(
        f"https://api.gravatar.com/v3/profiles/{quote(ident, safe='')}",
        headers=hdrs, timeout=ctx.timeout, follow_redirects=True,
    )
    guard = _guard_status(r)
    if r.status_code == 404 and guard is not Status.BLOCKED:
        return _mk(site_id, query, Status.NOT_FOUND, http_status=404)
    if guard is not None:
        return _mk(site_id, query, guard, http_status=r.status_code)
    data = _json(r)
    if r.status_code == 200 and isinstance(data, dict) and not _provider_error(data):
        extra = _parse_gravatar_v3(data)
        if _gravatar_identity(extra):
            url = extra.get("profile_url") or f"https://gravatar.com/{quote(ident, safe='')}"
            return _mk(site_id, query, Status.FOUND, http_status=r.status_code, url=url, extra=extra)
    return _mk(site_id, query, Status.UNKNOWN, http_status=r.status_code,
               error="fallback response contained no identified profile")


@_guarded("extras-gravatar")
async def _check_gravatar_email(query: str, ctx: Context) -> Finding:
    email = query.strip().lower()
    md5 = hashlib.md5(email.encode("utf-8")).hexdigest()
    sha = hashlib.sha256(email.encode("utf-8")).hexdigest()
    return await _gravatar_lookup("extras-gravatar", query, ctx, [md5, sha])


@_guarded("extras-gravatar-username")
async def _check_gravatar_username(query: str, ctx: Context) -> Finding:
    slug = query.strip().lstrip("@")
    return await _gravatar_lookup("extras-gravatar-username", query, ctx, [slug])


# ---------------------------------------------------------------------------
# ProtonMail - PGP key presence + creation timestamp
# ---------------------------------------------------------------------------
@_guarded("extras-proton-pgp")
async def _check_proton(query: str, ctx: Context) -> Finding:
    from ..core.pgp_index import parse_index

    r = await ctx.client.get(
        "https://api.protonmail.ch/pks/lookup",
        params={"op": "index", "search": query, "options": "mr"},
        headers=_headers(ctx, {"Accept": "*/*"}),
        timeout=ctx.timeout,
    )
    guard = _guard_status(r, inspect_body=False)
    if guard is not None:
        return _mk("extras-proton-pgp", query, guard, http_status=r.status_code)

    found, extra, error = parse_index(r.text, query)
    status = Status.FOUND if found is True else Status.NOT_FOUND if found is False else Status.UNKNOWN
    if found is None and _looks_blocked(r):
        status = Status.BLOCKED
    return _mk("extras-proton-pgp", query, status, http_status=r.status_code, extra=extra, error=error)


# ---------------------------------------------------------------------------
# Adobe - silent signin/v2 account lookup (holehe's adobe is a loud recovery flow)
# ---------------------------------------------------------------------------
@_guarded("extras-adobe")
async def _check_adobe(query: str, ctx: Context) -> Finding:
    r = await ctx.client.post(
        "https://auth.services.adobe.com/signin/v2/users/accounts",
        json={"username": query, "usernameType": "EMAIL"},
        headers=_headers(ctx, {
            "Content-Type": "application/json",
            "X-IMS-ClientId": "homepage_milo",
            "Origin": "https://auth.services.adobe.com",
        }),
        timeout=ctx.timeout,
    )
    guard = _guard_status(r)
    if guard is not None:
        return _mk("extras-adobe", query, guard, http_status=r.status_code)

    data = _json(r)
    if not isinstance(data, list):
        return _mk("extras-adobe", query, Status.UNKNOWN, http_status=r.status_code,
                   error="unexpected body")
    if not data:
        return _mk("extras-adobe", query, Status.NOT_FOUND, http_status=r.status_code)

    methods: list = []
    for acc in data:
        if isinstance(acc, dict) and not _provider_error(acc):
            for m in _objects(acc.get("authenticationMethods")):
                if _text(m.get("id")):
                    methods.append(m["id"])
    if not methods:
        return _mk("extras-adobe", query, Status.UNKNOWN, http_status=r.status_code,
                   error="account response contained no recognized method records")
    extra = {"auth_methods": _uniq(methods)} if methods else {}
    # Authentication metadata is useful but credential-shaped field names are
    # deliberately redacted by the shared model. Project only recognised public
    # method labels under a descriptive field; unknown IDs remain masked.
    labels = {"password": "Password", "federated": "Federated sign-in", "social": "Social sign-in"}
    known = _uniq(labels[m] for m in methods if isinstance(m, str) and m in labels)
    if known:
        extra["sign_in_methods"] = known
    return _mk("extras-adobe", query, Status.FOUND, http_status=r.status_code, extra=extra)


# ---------------------------------------------------------------------------
# Microsoft account - GetCredentialType (also valid for e-mail usernames)
# ---------------------------------------------------------------------------
@_guarded("extras-microsoft")
async def _check_microsoft(query: str, ctx: Context) -> Finding:
    # The common/GetCredentialType endpoint answers without a primed sign-in
    # flow, unlike login.live.com/GetCredentialType.srf (which 400s with
    # ErrorHR 80046703 outside a real flow).
    r = await ctx.client.post(
        "https://login.microsoftonline.com/common/GetCredentialType",
        params={"mkt": "en-US"},
        json={
            "username": query,
            "isOtherIdpSupported": True,
            "checkPhones": False,
            "isRemoteNGCSupported": True,
            "isCookieBannerShown": False,
            "isFidoSupported": True,
            "originalRequest": "",
            "flowToken": "",
        },
        headers=_headers(ctx, {
            "Content-Type": "application/json; charset=utf-8",
            "Origin": "https://login.microsoftonline.com",
            "Referer": "https://login.microsoftonline.com/",
        }),
        timeout=ctx.timeout,
    )
    guard = _guard_status(r)
    if guard is not None:
        return _mk("extras-microsoft", query, guard, http_status=r.status_code)

    data = _json(r)
    if not isinstance(data, dict) or "IfExistsResult" not in data or _provider_error(data):
        return _mk("extras-microsoft", query, Status.UNKNOWN, http_status=r.status_code,
                   error="account-status response is missing or contains a provider error")
    throttle = data.get("ThrottleStatus", 0)
    if type(throttle) is not int or throttle < 0:
        return _mk("extras-microsoft", query, Status.UNKNOWN, http_status=r.status_code)
    if throttle:
        return _mk("extras-microsoft", query, Status.RATE_LIMITED, http_status=r.status_code)
    res = data.get("IfExistsResult")
    if type(res) is not int:
        return _mk("extras-microsoft", query, Status.UNKNOWN, http_status=r.status_code)
    extra = {"if_exists_result": res}
    if type(data.get("IsUnmanaged")) is bool:
        extra["is_unmanaged"] = data.get("IsUnmanaged")
    # 0 = exists, 5/6 = exists via another identity provider, 1 = not found.
    if res in (0, 5, 6):
        return _mk("extras-microsoft", query, Status.FOUND, http_status=r.status_code, extra=extra)
    if res == 1:
        return _mk("extras-microsoft", query, Status.NOT_FOUND, http_status=r.status_code)
    return _mk("extras-microsoft", query, Status.UNKNOWN, http_status=r.status_code, extra=extra)


# ---------------------------------------------------------------------------
# Picsart - email existence API
# ---------------------------------------------------------------------------
@_guarded("extras-picsart")
async def _check_picsart(query: str, ctx: Context) -> Finding:
    r = await ctx.client.get(
        "https://api.picsart.com/users/email/existence",
        params={"email_encoded": 1, "emails": query},
        headers=_headers(ctx),
        timeout=ctx.timeout,
    )
    guard = _guard_status(r)
    if guard is not None:
        return _mk("extras-picsart", query, guard, http_status=r.status_code)

    data = _json(r)
    if not isinstance(data, dict):
        return _mk("extras-picsart", query, Status.UNKNOWN, http_status=r.status_code)
    if data.get("status") != "success" or _provider_error(data):
        return _mk("extras-picsart", query, Status.UNKNOWN, http_status=r.status_code,
                   error="response did not confirm a successful email lookup")
    resp = data.get("response")
    exists = resp if type(resp) is bool else None
    if isinstance(resp, dict):
        matching = [value for key, value in resp.items() if key.strip().lower() == query.strip().lower()]
        if matching and all(type(value) is bool for value in matching) and len(set(matching)) == 1:
            exists = matching[0]
    elif isinstance(resp, list) and len(resp) == 1 and type(resp[0]) is bool:
        exists = resp[0]
    if exists is None:
        return _mk("extras-picsart", query, Status.UNKNOWN, http_status=r.status_code,
                   error="no typed existence result for the submitted email")
    return _mk("extras-picsart", query, Status.FOUND if exists else Status.NOT_FOUND,
               http_status=r.status_code)


# ---------------------------------------------------------------------------
# Flickr - flickr.people.findByEmail (api key harvested from the homepage)
# ---------------------------------------------------------------------------
@_guarded("extras-flickr")
async def _check_flickr(query: str, ctx: Context) -> Finding:
    home = await ctx.client.get(
        "https://www.flickr.com/", headers=_headers(ctx, {"Accept": "text/html,*/*"}),
        timeout=ctx.timeout, follow_redirects=True,
    )
    guard = _guard_status(home)
    if guard is not None:
        return _mk("extras-flickr", query, guard, http_status=home.status_code)

    m = re.search(r'"?api[._]?key"?\s*[:=]\s*"([0-9a-f]{32})"', home.text)
    if not m:
        return _mk("extras-flickr", query, Status.UNKNOWN, http_status=home.status_code,
                   error="no labelled api key on homepage")
    api_key = m.group(1)

    r = await ctx.client.get(
        "https://api.flickr.com/services/rest",
        params={
            "method": "flickr.people.findByEmail",
            "api_key": api_key,
            "find_email": query,
            "format": "json",
            "nojsoncallback": 1,
        },
        headers=_headers(ctx),
        timeout=ctx.timeout,
    )
    guard = _guard_status(r)
    if guard is not None:
        return _mk("extras-flickr", query, guard, http_status=r.status_code)

    data = _json(r)
    if not isinstance(data, dict):
        return _mk("extras-flickr", query, Status.UNKNOWN, http_status=r.status_code)
    if _provider_error(data):
        return _mk("extras-flickr", query, Status.UNKNOWN, http_status=r.status_code)
    if data.get("stat") == "ok" and isinstance(data.get("user"), dict):
        user = data["user"]
        nsid = _text(user.get("nsid")) or _text(user.get("id"))
        if nsid is None:
            return _mk("extras-flickr", query, Status.UNKNOWN, http_status=r.status_code,
                       error="user response contained no identifier")
        uname = (user.get("username") or {}).get("_content") if isinstance(user.get("username"), dict) else user.get("username")
        extra = {"nsid": nsid}
        if _text(uname):
            extra["username"] = uname
        url = f"https://www.flickr.com/people/{quote(nsid, safe='')}/"
        return _mk("extras-flickr", query, Status.FOUND, http_status=r.status_code,
                   url=url, extra=extra)
    # code 1 == "User not found"
    if data.get("stat") == "fail" and type(data.get("code")) is int and data["code"] == 1:
        return _mk("extras-flickr", query, Status.NOT_FOUND, http_status=r.status_code)
    return _mk("extras-flickr", query, Status.UNKNOWN, http_status=r.status_code,
               error="Flickr returned an error or unrecognized result")


# ---------------------------------------------------------------------------
# Mail.ru - silent user/exists endpoint (holehe's mail_ru is a loud recovery flow)
# ---------------------------------------------------------------------------
@_guarded("extras-mailru")
async def _check_mailru(query: str, ctx: Context) -> Finding:
    r = await ctx.client.get(
        "https://account.mail.ru/api/v1/user/exists",
        params={"email": query},
        headers=_headers(ctx, {"X-Requested-With": "XMLHttpRequest"}),
        timeout=ctx.timeout,
    )
    guard = _guard_status(r)
    if guard is not None:
        return _mk("extras-mailru", query, guard, http_status=r.status_code)

    from consensus_osint.core.mailbox_contracts import mailru

    status, extra, reason = mailru(_json(r), query)
    return _mk("extras-mailru", query, status, http_status=r.status_code, extra=extra, error=reason)


# ---------------------------------------------------------------------------
# Bitmoji / Snapchat - bitmoji.api.snapchat.com user find
# ---------------------------------------------------------------------------
@_guarded("extras-bitmoji")
async def _check_bitmoji(query: str, ctx: Context) -> Finding:
    r = await ctx.client.post(
        "https://bitmoji.api.snapchat.com/api/user/find",
        data={"email": query},
        headers=_headers(ctx),
        timeout=ctx.timeout,
    )
    guard = _guard_status(r)
    if guard is not None:
        return _mk("extras-bitmoji", query, guard, http_status=r.status_code)

    data = _json(r)
    if isinstance(data, dict) and not _provider_error(data) and data.get("account_type") in ("snapchat", "bitmoji"):
        return _mk("extras-bitmoji", query, Status.FOUND, http_status=r.status_code,
                   extra={"account_type": data.get("account_type")})
    return _mk("extras-bitmoji", query, Status.UNKNOWN, http_status=r.status_code,
               error="no supported account-type result; absence is not established")


# ---------------------------------------------------------------------------
# Duolingo - public users API
# ---------------------------------------------------------------------------
@_guarded("extras-duolingo")
async def _check_duolingo(query: str, ctx: Context) -> Finding:
    r = await ctx.client.get(
        "https://www.duolingo.com/2017-06-30/users",
        params={"email": query},
        headers=_headers(ctx),
        timeout=ctx.timeout, follow_redirects=True,
    )
    guard = _guard_status(r)
    if guard is not None:
        return _mk("extras-duolingo", query, guard, http_status=r.status_code)

    from ..core.jobs_learning_contracts import outcome

    status, extra, reason = outcome('duolingo', r, query)
    if status is not Status.FOUND:
        return _mk('extras-duolingo', query, status, http_status=r.status_code, error=reason)
    url = 'https://www.duolingo.com/profile/' + quote(extra['username'], safe='')
    return _mk('extras-duolingo', query, status, http_status=r.status_code, url=url, extra=extra)


# ---------------------------------------------------------------------------
# GitHub - public "in:email" user search (unauth may 401/403 -> UNKNOWN)
# ---------------------------------------------------------------------------
@_guarded("extras-github-search")
async def _check_github(query: str, ctx: Context) -> Finding:
    r = await ctx.client.get(
        "https://api.github.com/search/users",
        params={"q": f"{query} in:email"},
        headers=_headers(ctx, {"Accept": "application/vnd.github+json"}),
        timeout=ctx.timeout,
    )
    if r.status_code == 429:
        return _mk("extras-github-search", query, Status.RATE_LIMITED, http_status=429)
    if r.status_code in (401, 403):
        # No token -> the search API refuses; can't tell, not a hard block.
        if r.headers.get("x-ratelimit-remaining") == "0":
            return _mk("extras-github-search", query, Status.RATE_LIMITED, http_status=r.status_code)
        return _mk("extras-github-search", query, Status.UNKNOWN, http_status=r.status_code,
                   error="search API requires auth")
    guard = _guard_status(r, auth_block=False)
    if guard is not None:
        return _mk("extras-github-search", query, guard, http_status=r.status_code)

    data = _json(r)
    if (not isinstance(data, dict) or type(data.get("total_count")) is not int or data["total_count"] < 0
            or not isinstance(data.get("items"), list) or type(data.get("incomplete_results")) is not bool):
        return _mk("extras-github-search", query, Status.UNKNOWN, http_status=r.status_code)
    items = data["items"]
    if data["total_count"] == 0 and not items and not data["incomplete_results"]:
        return _mk("extras-github-search", query, Status.NOT_FOUND, http_status=r.status_code)
    if not items or data["total_count"] < len(items):
        return _mk("extras-github-search", query, Status.UNKNOWN, http_status=r.status_code)
    u = items[0]
    if (not isinstance(u, dict) or not isinstance(u.get("login"), str) or not u["login"].strip()
            or type(u.get("id")) is not int or u["id"] < 1):
        return _mk("extras-github-search", query, Status.UNKNOWN, http_status=r.status_code)
    extra = {
        "login": u.get("login"),
        "user_id": u.get("id"),
        "profile": u.get("html_url"),
        "avatar": u.get("avatar_url"),
    }
    if data["incomplete_results"]:
        extra["search_incomplete"] = True
    return _mk("extras-github-search", query, Status.FOUND, http_status=r.status_code,
               url=u.get("html_url"), extra={k: v for k, v in extra.items() if v is not None})


# ---------------------------------------------------------------------------
# Spotify - signup validate
# ---------------------------------------------------------------------------
@_guarded("extras-spotify")
async def _check_spotify(query: str, ctx: Context) -> Finding:
    from ..core.media_contracts import outcome

    r = await ctx.client.get(
        "https://spclient.wg.spotify.com/signup/public/v1/account",
        params={"validate": 1, "email": query},
        headers=_headers(ctx),
        timeout=ctx.timeout,
    )
    status, fields, reason = outcome("spotify", r, query)
    return _mk("extras-spotify", query, status, http_status=r.status_code, extra=fields, error=reason)


# ---------------------------------------------------------------------------
# Hudson Rock (Cavalier) - email & username stealer-log OSINT (breach)
# ---------------------------------------------------------------------------
def _parse_hudsonrock(data: dict) -> tuple[bool | None, dict]:
    """Return (found, extra). found is None when the message is ambiguous."""
    extra: dict = {}
    msg = str(data.get("message", ""))
    if msg:
        extra["message"] = msg
    stealers = data.get("stealers") or []
    if isinstance(stealers, list) and stealers:
        details = []
        for s in stealers[:10]:
            if not isinstance(s, dict):
                continue
            detail = {
                "date_compromised": s.get("date_compromised"),
                "computer_name": s.get("computer_name"),
                "operating_system": s.get("operating_system"),
                "ip": s.get("ip"),
                "malware_path": s.get("malware_path"),
                "top_logins": s.get("top_logins"),
            }
            if any((isinstance(value, str) and value.strip()) or
                   (isinstance(value, list) and any(isinstance(item, str) and item.strip() for item in value))
                   for value in detail.values()):
                details.append(detail)
        extra["stealers"] = details
    for k in ("total_corporate_services", "total_user_services"):
        if data.get(k) is not None:
            extra[k] = data[k]

    low = msg.lower()
    if data.get("error") or data.get("success") is False:
        return None, extra
    negative = bool(re.search(r"\b(?:email(?: address)?|username) (?:is |was |has been )?not (?:associated|found)\b", low))
    if negative and extra.get("stealers"):
        return None, extra
    if negative:
        return False, extra
    if extra.get("stealers"):
        return True, extra
    return None, extra


async def _hudsonrock(site_id: str, query: str, ctx: Context, path: str, param: str) -> Finding:
    r = await ctx.client.get(
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/{path}",
        params={param: query},
        headers=_headers(ctx, {"api-key": "ROCKHUDSONROCK"}),
        timeout=ctx.timeout,
    )
    guard = _guard_status(r)
    if guard is not None:
        return _mk(site_id, query, guard, http_status=r.status_code)
    if r.status_code != 200:
        return _mk(site_id, query, Status.BLOCKED if r.status_code == 401 else Status.UNKNOWN,
                   http_status=r.status_code)
    data = _json(r)
    if not isinstance(data, dict):
        return _mk(site_id, query, Status.UNKNOWN, http_status=r.status_code)
    found, extra = _parse_hudsonrock(data)
    if found is True:
        return _mk(site_id, query, Status.FOUND, http_status=r.status_code, extra=extra)
    if found is False:
        return _mk(site_id, query, Status.NOT_FOUND, http_status=r.status_code, extra=extra)
    return _mk(site_id, query, Status.UNKNOWN, http_status=r.status_code, extra=extra)


@_guarded("extras-hudsonrock-email")
async def _check_hudsonrock_email(query: str, ctx: Context) -> Finding:
    return await _hudsonrock("extras-hudsonrock-email", query, ctx, "search-by-email", "email")


@_guarded("extras-hudsonrock-username")
async def _check_hudsonrock_username(query: str, ctx: Context) -> Finding:
    return await _hudsonrock("extras-hudsonrock-username", query, ctx, "search-by-username", "username")


# ---------------------------------------------------------------------------
# ProxyNova COMB - "email:password" leak search (breach)
# ---------------------------------------------------------------------------
def _mask_pw(pw: str) -> str:
    """Never preserve credential fragments or disclose their length."""
    return "[redacted]"


@_guarded("extras-proxynova-comb")
async def _check_proxynova(query: str, ctx: Context) -> Finding:
    r = await ctx.client.get(
        "https://api.proxynova.com/comb",
        params={"query": query, "start": 0, "limit": 20},
        headers=_headers(ctx),
        timeout=ctx.timeout,
    )
    guard = _guard_status(r)
    if guard is not None:
        return _mk("extras-proxynova-comb", query, guard, http_status=r.status_code)

    data = _json(r)
    if not isinstance(data, dict):
        return _mk("extras-proxynova-comb", query, Status.UNKNOWN, http_status=r.status_code)
    lines, count = data.get("lines"), data.get("count")
    if (_provider_error(data) or not isinstance(lines, list) or not all(isinstance(line, str) for line in lines)
            or type(count) is not int or count < len(lines)):
        return _mk("extras-proxynova-comb", query, Status.UNKNOWN, http_status=r.status_code,
                   error="incomplete or malformed search-page metadata")
    masked: list = []
    for line in lines:
        if ":" in line:
            email_part, pw_part = line.split(":", 1)
            if email_part.strip().lower() != query.strip().lower():
                continue
            masked.append(f"{email_part}:{_mask_pw(pw_part)}")
    extra = {"count": count, "leaks": _uniq(masked), "matched_count": len(masked),
             "returned_records": len(lines), "search_complete": count == len(lines), "result_limit": 20}
    status = Status.FOUND if masked else Status.NOT_FOUND if count == 0 else Status.UNKNOWN
    return _mk("extras-proxynova-comb", query, status, http_status=r.status_code, extra=extra,
               error="No exact-email record is available on this page; absence is not established" if status is Status.UNKNOWN else None)


# ---------------------------------------------------------------------------
# XposedOrNot - breach check (breach)
# ---------------------------------------------------------------------------
@_guarded("extras-xposedornot")
async def _check_xposedornot(query: str, ctx: Context) -> Finding:
    r = await ctx.client.get(
        f"https://api.xposedornot.com/v1/check-email/{quote(query, safe='')}",
        headers=_headers(ctx),
        timeout=ctx.timeout,
    )
    guard = _guard_status(r)
    if guard is not None and not (r.status_code == 404 and guard is Status.UNKNOWN):
        return _mk("extras-xposedornot", query, guard, http_status=r.status_code)
    data = _json(r)
    if isinstance(data, dict) and data.get("email") is not None:
        if not _text(data["email"]) or data["email"].strip().lower() != query.strip().lower():
            return _mk("extras-xposedornot", query, Status.UNKNOWN, http_status=r.status_code,
                       error="response email did not match the submitted identifier")
    if r.status_code == 404:
        if isinstance(data, dict) and data.get("Error") == "Not found" and data.get("breaches") in (None, []):
            return _mk("extras-xposedornot", query, Status.NOT_FOUND, http_status=404)
        return _mk("extras-xposedornot", query, Status.UNKNOWN, http_status=404,
                   error="404 response did not establish absence of breach records")
    if not isinstance(data, dict):
        return _mk("extras-xposedornot", query, Status.UNKNOWN, http_status=r.status_code)
    if data.get("status") not in (None, "success") or data.get("error"):
        return _mk("extras-xposedornot", query, Status.UNKNOWN, http_status=r.status_code)
    if data.get("Error"):
        if data["Error"] == "Not found" and data.get("breaches") in (None, []):
            return _mk("extras-xposedornot", query, Status.NOT_FOUND, http_status=r.status_code)
        return _mk("extras-xposedornot", query, Status.UNKNOWN, http_status=r.status_code,
                   error="provider reported an unrecognized error")
    breaches = data.get("breaches")
    if not isinstance(breaches, list):
        return _mk("extras-xposedornot", query, Status.UNKNOWN, http_status=r.status_code)
    flat = []
    for item in breaches:
        values = item if isinstance(item, list) else [item]
        if not all(_text(value) for value in values):
            return _mk("extras-xposedornot", query, Status.UNKNOWN, http_status=r.status_code)
        flat.extend(values)
    if flat:
        if "email" in data and data["email"] is None:
            return _mk("extras-xposedornot", query, Status.UNKNOWN, http_status=r.status_code)
        flat = _uniq(flat)
        return _mk("extras-xposedornot", query, Status.FOUND, http_status=r.status_code,
                   extra={"count": len(flat), "breaches": flat})
    return _mk("extras-xposedornot", query, Status.NOT_FOUND, http_status=r.status_code)


# ---------------------------------------------------------------------------
# LeakCheck public API (breach)
# ---------------------------------------------------------------------------
@_guarded("extras-bandlab")
async def _check_bandlab(query: str, ctx: Context) -> Finding:
    """BandLab signup validation (keyless): registered when the email is a valid
    address that is no longer available to register."""
    r = await ctx.client.get(
        "https://www.bandlab.com/api/v1.3/validation/user",
        params={"email": query}, headers=_headers(ctx), timeout=ctx.timeout)
    guard = _guard_status(r)
    if guard is not None:
        return _mk("extras-bandlab", query, guard, http_status=r.status_code)
    data = _json(r)
    if not isinstance(data, dict):
        return _mk("extras-bandlab", query, Status.UNKNOWN, http_status=r.status_code)
    if data.get("isValid") is True and data.get("isAvailable") is False:
        return _mk("extras-bandlab", query, Status.FOUND, http_status=r.status_code)
    if data.get("isValid") is True and data.get("isAvailable") is True:
        return _mk("extras-bandlab", query, Status.NOT_FOUND, http_status=r.status_code)
    return _mk("extras-bandlab", query, Status.UNKNOWN, http_status=r.status_code)


@_guarded("extras-kommo")
async def _check_kommo(query: str, ctx: Context) -> Finding:
    """Kommo (formerly amoCRM) account login check (keyless). Replaces holehe's
    amoCRM module, whose old endpoint now 301s to a 405."""
    r = await ctx.client.post(
        "https://www.kommo.com/account/check_login.php",
        data={"LOGIN": query}, headers=_headers(ctx, {"Content-Type": "application/x-www-form-urlencoded"}),
        timeout=ctx.timeout)
    guard = _guard_status(r)
    if guard is not None:
        return _mk("extras-kommo", query, guard, http_status=r.status_code)
    data = _json(r)
    status = data.get("status") if isinstance(data, dict) else None
    if status == "used":
        return _mk("extras-kommo", query, Status.FOUND, http_status=r.status_code)
    if status == "free":
        return _mk("extras-kommo", query, Status.NOT_FOUND, http_status=r.status_code)
    return _mk("extras-kommo", query, Status.UNKNOWN, http_status=r.status_code)


async def _leakcheck_impl(site_id: str, query: str, ctx: Context) -> Finding:
    """LeakCheck Public API documents email, email hash and username lookups.
    The endpoint auto-detects the identifier type. It returns a breach
    count, the exposed data-field types and the source breach names/dates, and
    never plaintext passwords."""
    r = await ctx.client.get(
        "https://leakcheck.io/api/public",
        params={"check": query},
        headers=_headers(ctx),
        timeout=ctx.timeout,
    )
    guard = _guard_status(r)
    if guard is not None:
        return _mk(site_id, query, guard, http_status=r.status_code)

    data = _json(r)
    if not isinstance(data, dict):
        return _mk(site_id, query, Status.UNKNOWN, http_status=r.status_code)
    found = data.get("found")
    if data.get("success") is not True or _provider_error(data) or type(found) is not int or found < 0:
        return _mk(site_id, query, Status.UNKNOWN, http_status=r.status_code,
                   error="no successful response with a valid breach count")
    sources, fields = data.get("sources", []), data.get("fields", [])
    if (not isinstance(sources, list) or not isinstance(fields, list)
            or not all(_text(field) for field in fields)
            or not all(isinstance(source, dict) and _text(source.get("name"))
                       and (source.get("date") is None or isinstance(source["date"], str)) for source in sources)
            or (found == 0 and (sources or fields))):
        return _mk(site_id, query, Status.UNKNOWN, http_status=r.status_code,
                   error="breach count and source metadata are malformed or inconsistent")
    norm_sources = []
    for source in sources:
        norm_sources.append({"name": source["name"], "date": source.get("date")})
    if found:
        extra = {"found": found, "sources": norm_sources, "attribution": "Powered by LeakCheck (leakcheck.io)"}
        if fields:
            extra["exposed_fields"] = fields
        return _mk(site_id, query, Status.FOUND, http_status=r.status_code, extra=extra)
    return _mk(site_id, query, Status.NOT_FOUND, http_status=r.status_code)


@_guarded("extras-leakcheck-public")
async def _check_leakcheck(query: str, ctx: Context) -> Finding:
    return await _leakcheck_impl("extras-leakcheck-public", query, ctx)


@_guarded("extras-leakcheck-username")
async def _check_leakcheck_username(query: str, ctx: Context) -> Finding:
    return await _leakcheck_impl("extras-leakcheck-username", query, ctx)


@_guarded("extras-leakcheck-phone")
async def _check_leakcheck_phone(query: str, ctx: Context) -> Finding:
    return _mk("extras-leakcheck-phone", query, Status.SKIPPED,
               error="LeakCheck Public API does not document phone lookup support")


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------
_CHECKS = {
    "extras-gravatar": _check_gravatar_email,
    "extras-gravatar-username": _check_gravatar_username,
    "extras-proton-pgp": _check_proton,
    "extras-adobe": _check_adobe,
    "extras-microsoft": _check_microsoft,
    "extras-picsart": _check_picsart,
    "extras-flickr": _check_flickr,
    "extras-mailru": _check_mailru,
    "extras-bitmoji": _check_bitmoji,
    "extras-duolingo": _check_duolingo,
    "extras-github-search": _check_github,
    "extras-spotify": _check_spotify,
    "extras-bandlab": _check_bandlab,
    "extras-kommo": _check_kommo,
    "extras-hudsonrock-email": _check_hudsonrock_email,
    "extras-hudsonrock-username": _check_hudsonrock_username,
    "extras-proxynova-comb": _check_proxynova,
    "extras-xposedornot": _check_xposedornot,
    "extras-leakcheck-public": _check_leakcheck,
    "extras-leakcheck-username": _check_leakcheck_username,
    "extras-leakcheck-phone": _check_leakcheck_phone,
}


def _module(site_id: str) -> Module:
    s = SPECS[site_id]
    return Module(
        id=site_id,
        name=s["name"],
        kind=s["kind"],
        check=_CHECKS[site_id],
        category=s.get("category", "misc"),
        source="extras",
        url_main=s.get("url"),
        loud=s.get("loud", False),
        nsfw=s.get("nsfw", False),
        tags=list(s.get("tags") or []),
        method=s.get("method"),
    )


def load_modules() -> list[Module]:
    """Return every extras module (never raises)."""
    return [_module(site_id) for site_id in SPECS]
