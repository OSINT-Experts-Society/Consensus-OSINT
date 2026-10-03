"""Mailbox-existence discovery: ``<username>@<provider>`` across providers.

Ported from *mailcat* (https://github.com/sharsil/mailcat) by sharsil.
Original licence: Apache License 2.0.  Modified for Consensus: rewritten on top
of Consensus's async :class:`~consensus_osint.core.http.Http` layer and the unified
:class:`~consensus_osint.core.models.Finding` model.  Only the keyless checks
that do NOT require pyppeteer / a headless browser are ported; browser-driven
providers (Fastmail, int.pl, Onet) and token/captcha-gated ones (Tutanota's
signupToken flow, iCloud, HushMail, WP/O2, Gazeta) are omitted.

   Copyright 2021 sharsil (original mailcat)
   Copyright 2024 Consensus contributors (modifications)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

The complete licence is bundled in licenses/Apache-2.0.txt; see
THIRD_PARTY_NOTICES.txt for the reviewed source revision and adaptation scope.

Given a username this checks each provider's keyless account-existence API (or
an SMTP ``RCPT TO`` probe) and returns a :class:`Finding` per provider.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import string
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from types import MappingProxyType
from urllib.parse import quote
from urllib.request import getproxies

from .http import Http, random_user_agent
from .mailbox_contracts import hidden_fields, http_issue, mailru, yahoo_signup
from .models import Finding, Status

log = logging.getLogger("consensus.mailcat")


# ---------------------------------------------------------------------------
# provider descriptor
# ---------------------------------------------------------------------------
# A check coroutine takes (username, http, timeout) and returns
# (Status, primary_email, extra_dict).
CheckFn = Callable[[str, Http, float], Awaitable[tuple]]


@dataclass
class ProviderCheck:
    key: str
    name: str
    domains: list
    method: str            # "api" | "smtp"
    check: CheckFn
    note: str = ""
    tags: list = field(default_factory=list)

    @property
    def disabled_reason(self) -> str | None:
        return _PROVIDER_RESTRICTIONS.get(self.key)


_PROVIDER_RESTRICTIONS = MappingProxyType({
    "gmail": "A generic Set-Cookie header does not establish mailbox existence.",
    "outlook": "Missing or boolean account-status fields produce definitive mailbox verdicts.",
    "proton": "A single public-key result is expanded into unverified mailbox aliases.",
    "mailru": "Response contracts repaired; controlled mailbox and per-domain evidence remain unverified.",
    "rambler": "Typed positive profile parser repaired; negative profile contract and controlled live evidence remain unverified.",
    "tuta": "Missing availability fields are interpreted as mailbox absence.",
    "zoho": "Generic validation JSON is interpreted as mailbox absence.",
    "yahoo": "Response contracts repaired; current signup response and mailbox reliability remain unverified.",
    "firemail": "Unrecognised HTTP 200 responses are interpreted as mailbox absence.",
})


def _randstr(n: int) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _json(text: str):
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# API-based checks
# ---------------------------------------------------------------------------
async def _chk_gmail(username: str, http: Http, timeout: float) -> tuple:
    """A legacy gxlu cookie is not proof of a current mailbox; keep its hold."""
    addr = f"{username}@gmail.com"
    try:
        resp = await http.get(
            f"https://mail.google.com/mail/gxlu?email={quote(addr)}",
            headers={"User-Agent": random_user_agent()}, follow_redirects=False, timeout=timeout)
    except Exception:
        return Status.ERROR, addr, {"reason": "Gmail request failed; mailbox status is unknown."}
    status, reason = http_issue(resp.status, resp.headers, resp.text, error=resp.error, accepted=(200, 204))
    if status is not None:
        return status, addr, {"reason": reason, "http_status": resp.status}
    return Status.UNKNOWN, addr, {"reason": "A legacy Gmail response or cookie does not establish mailbox existence."}


async def _chk_outlook(username: str, http: Http, timeout: float) -> tuple:
    """Microsoft Account lookup via GetCredentialType.  IfExistsResult:
    0/5/6 = the address is a registered MSA (exists), 1 = free, 4 = invalid."""
    domains = ["outlook.com", "hotmail.com", "live.com", "outlook.de", "msn.com"]
    exists_codes = {0, 5, 6}
    matches: list[str] = []
    saw_answer = False
    throttled = False
    for domain in domains:
        addr = f"{username}@{domain}"
        resp = await http.request(
            "POST",
            "https://login.live.com/GetCredentialType.srf",
            json={"Username": addr, "isOtherIdpSupported": True},
            headers={
                "Content-Type": "application/json; charset=UTF-8",
                "User-Agent": random_user_agent(),
                "Origin": "https://login.live.com",
                "Referer": "https://login.live.com/",
            },
            timeout=timeout,
        )
        if not resp.ok or resp.status != 200:
            continue
        body = _json(resp.text)
        if not isinstance(body, dict):
            continue
        if body.get("ThrottleStatus", 0):
            throttled = True
            continue
        saw_answer = True
        if body.get("IfExistsResult") in exists_codes:
            matches.append(addr)
    if matches:
        return Status.FOUND, matches[0], {"matches": matches}
    if throttled and not saw_answer:
        return Status.RATE_LIMITED, f"{username}@outlook.com", {"throttled": True}
    if saw_answer:
        return Status.NOT_FOUND, f"{username}@outlook.com", {}
    return Status.UNKNOWN, f"{username}@outlook.com", {}


async def _chk_proton(username: str, http: Http, timeout: float) -> tuple:
    """Proton publishes a public key for every mailbox, so the SKS-style key
    server (pks/lookup) doubles as an existence oracle."""
    domains = ["proton.me", "protonmail.com", "protonmail.ch", "pm.me"]
    addr = f"{username}@proton.me"
    resp = await http.get(
        f"https://api.protonmail.ch/pks/lookup?op=index&search={quote(addr)}",
        headers={"User-Agent": random_user_agent()},
        timeout=timeout,
    )
    if not resp.ok:
        return Status.ERROR, addr, {"error": resp.error}
    text = resp.text or ""
    if resp.status == 200 and ("pub:" in text or re.search(r"info:\d+:[1-9]", text)):
        return Status.FOUND, addr, {"matches": [f"{username}@{d}" for d in domains]}
    if resp.status == 200 and "info:1:0" in text:
        return Status.NOT_FOUND, addr, {}
    if resp.status == 404:
        return Status.NOT_FOUND, addr, {}
    if resp.status == 429:
        return Status.RATE_LIMITED, addr, {}
    return Status.UNKNOWN, addr, {"http_status": resp.status}


async def _chk_mailru(username: str, http: Http, timeout: float) -> tuple:
    domains = ["mail.ru", "bk.ru", "inbox.ru", "list.ru", "internet.ru"]
    matches, unresolved = [], {}
    for domain in domains:
        addr = f"{username}@{domain}"
        try:
            resp = await http.request("POST", "https://account.mail.ru/api/v1/user/exists",
                data={"email": addr}, headers={"User-Agent": random_user_agent()}, timeout=timeout)
            status, reason = http_issue(resp.status, resp.headers, resp.text, error=resp.error)
            if status is None:
                status, _, reason = mailru(_json(resp.text), addr)
                await asyncio.sleep(random.uniform(0.2, 0.6))
        except Exception:
            status = Status.ERROR
        if status is Status.FOUND:
            matches.append(addr)
        elif status is not Status.NOT_FOUND:
            unresolved[domain] = status
    extra = {"inconclusive_domains": list(unresolved)} if unresolved else {}
    if matches:
        return Status.FOUND, matches[0], extra | {"matches": matches}
    if unresolved:
        status = next(value for value in (Status.RATE_LIMITED, Status.BLOCKED, Status.ERROR, Status.UNKNOWN)
                      if value in unresolved.values())
        return status, f"{username}@mail.ru", extra | {"reason": "Mailbox absence was not established for every queried domain."}
    return Status.NOT_FOUND, f"{username}@mail.ru", {}


async def _chk_rambler(username: str, http: Http, timeout: float) -> tuple:
    from .media_contracts import rambler_profile

    domains = ["rambler.ru", "lenta.ru", "autorambler.ru", "myrambler.ru", "ro.ru", "rambler.ua"]
    matches: list[str] = []
    unresolved = {}

    async def one(domain: str):
        addr = f"{username}@{domain}"
        resp = await http.request(
            "POST",
            "https://id.rambler.ru/jsonrpc",
            json={
                "method": "Rambler::Id::login_available",
                "params": [{"username": username, "realm": domain}],
                "rpc": "2.0",
            },
            headers={
                "User-Agent": random_user_agent(),
                "Content-Type": "application/json",
                "Origin": "https://id.rambler.ru",
                "X-Client-Request-Id": _randstr(20),
            },
            timeout=timeout,
        )
        status, reason = http_issue(resp.status, resp.headers, resp.text, error=resp.error)
        if status is not None:
            unresolved[domain] = status
            return None
        body = _json(resp.text)
        if rambler_profile(body, username, domain) is True:
            return addr
        # The retained source documents only the exact positive profile marker.
        # Null/missing profiles and unknown codes do not establish absence.
        unresolved[domain] = Status.UNKNOWN
        return None

    async def guarded(domain):
        try:
            return await one(domain)
        except Exception:
            unresolved[domain] = Status.ERROR
            return None

    for addr in await asyncio.gather(*(guarded(d) for d in domains)):
        if addr:
            matches.append(addr)
    extra = {"inconclusive_domains": [domain for domain in domains if domain in unresolved]} if unresolved else {}
    if matches:
        return Status.FOUND, matches[0], extra | {"matches": matches}
    status = next(value for value in (Status.RATE_LIMITED, Status.BLOCKED, Status.ERROR, Status.UNKNOWN)
                  if value in unresolved.values())
    return status, f"{username}@rambler.ru", extra | {"reason": "No verified negative contract for the returned Rambler profile responses."}


async def _chk_tuta(username: str, http: Http, timeout: float) -> tuple:
    """Tuta (ex-Tutanota) mail-address availability service.  available == "0"
    means the address is taken (exists)."""
    domains = ["tuta.com", "tutanota.com", "tutamail.com", "tuta.io", "keemail.me"]
    matches: list[str] = []
    answered = False
    for domain in domains:
        addr = f"{username}@{domain}"
        resp = await http.get(
            f"https://app.tuta.com/rest/sys/mailaddressavailabilityservice?mailAddress={quote(addr)}",
            headers={
                "User-Agent": random_user_agent(),
                "Accept": "application/json",
                "v": "116",
                "cv": "3.118.12",
            },
            timeout=timeout,
        )
        if not resp.ok or resp.status != 200:
            continue
        body = _json(resp.text)
        if not isinstance(body, dict):
            continue
        answered = True
        if str(body.get("available")) == "0":
            matches.append(addr)
        await asyncio.sleep(random.uniform(0.3, 0.8))
    if matches:
        return Status.FOUND, matches[0], {"matches": matches}
    return (Status.NOT_FOUND if answered else Status.UNKNOWN), f"{username}@tuta.com", {}


async def _chk_zoho(username: str, http: Http, timeout: float) -> tuple:
    addr = f"{username}@zohomail.com"
    resp = await http.request(
        "POST",
        "https://accounts.zoho.com/accounts/validate/register.ac",
        data={"username": username, "servicename": "VirtualOffice", "serviceurl": "/"},
        headers={
            "User-Agent": random_user_agent(),
            "Referer": "https://www.zoho.com/",
            "Origin": "https://www.zoho.com",
        },
        timeout=timeout,
    )
    if not resp.ok:
        return Status.ERROR, addr, {"error": resp.error}
    if resp.status != 200:
        return Status.UNKNOWN, addr, {"http_status": resp.status}
    body = _json(resp.text)
    if not isinstance(body, dict):
        return Status.UNKNOWN, addr, {}
    err = (body.get("error") or {}).get("username", "")
    if err == "This username is taken" or "already registered" in str(err):
        return Status.FOUND, addr, {}
    return Status.NOT_FOUND, addr, {}


async def _chk_yahoo(username: str, http: Http, timeout: float) -> tuple:
    """Retained signup validator; reserved/unavailable names are inconclusive."""
    addr = f"{username}@yahoo.com"
    headers = {"User-Agent": random_user_agent()}
    try:
        page = await http.get("https://login.yahoo.com/account/create", headers=headers, timeout=timeout)
        status, reason = http_issue(page.status, page.headers, page.text, error=page.error)
        if status is not None:
            return status, addr, {"reason": reason, "http_status": page.status, "stage": "signup-page"}
        tokens = hidden_fields(page.text, ("crumb", "acrumb", "sessionIndex"))
        if tokens is None:
            return Status.UNKNOWN, addr, {"reason": "Yahoo signup prerequisites are missing or ambiguous.", "stage": "no-tokens"}
        resp = await http.request("POST", "https://login.yahoo.com/account/create/validate?validateField=userId",
            data=tokens | {"specId": "yidregsimplified", "context": "REGISTRATION", "attrSetIndex": "0",
                           "tos0": "oath_freereg|en|en-US", "lastName": "r", "yidDomain": "yahoo.com", "userId": username},
            headers=headers | {"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://login.yahoo.com",
                               "Referer": "https://login.yahoo.com/account/create", "X-Requested-With": "XMLHttpRequest"},
            timeout=timeout)
        # Http's client owns the cookie jar. Set-Cookie attributes must never be
        # replayed as a hand-built Cookie request header.
        status, reason = http_issue(resp.status, resp.headers, resp.text, error=resp.error)
        if status is not None:
            return status, addr, {"reason": reason, "http_status": resp.status, "stage": "validate"}
        status, extra, reason = yahoo_signup(_json(resp.text), username)
        return status, addr, extra | ({"reason": reason} if reason else {})
    except Exception:
        return Status.ERROR, addr, {"reason": "Yahoo lookup request failed; mailbox status is unknown."}


async def _chk_firemail(username: str, http: Http, timeout: float) -> tuple:
    domains = ["firemail.de", "firemail.at", "firemail.eu"]
    matches: list[str] = []
    answered = False
    for domain in domains:
        addr = f"{username}@{domain}"
        resp = await http.get(
            f"https://firemail.de/index.php?action=checkAddressAvailability&address={quote(addr)}",
            headers={
                "User-Agent": random_user_agent(),
                "Referer": "https://firemail.de/E-Mail-Adresse-anmelden",
                "X-Requested-With": "XMLHttpRequest",
            },
            timeout=timeout,
        )
        if not resp.ok or resp.status != 200:
            continue
        answered = True
        # availability 0 (>0<) == taken == exists
        if ">0<" in (resp.text or ""):
            matches.append(addr)
        await asyncio.sleep(random.uniform(0.3, 0.8))
    if matches:
        return Status.FOUND, matches[0], {"matches": matches}
    return (Status.NOT_FOUND if answered else Status.UNKNOWN), f"{username}@firemail.de", {}


async def _chk_lycos(username: str, http: Http, timeout: float) -> tuple:
    """Lycos username assistant.  Uses a hard-coded session key that Lycos
    rotates, so this frequently returns UNKNOWN."""
    addr = f"{username}@lycos.com"
    url = (
        "https://registration.lycos.com/usernameassistant.php?validate=1&m_AID=0"
        f"&t=1625674151843&m_U={quote(username)}&m_PR=27"
        "&m_SESSIONKEY=4kCL5VaODOZ5M5lBF2lgVONl7tveoX8RKmedGRU3XjV3xRX5MqCP2NWHKynX4YL4"
    )
    resp = await http.get(
        url,
        headers={"User-Agent": random_user_agent(), "X-Requested-With": "XMLHttpRequest"},
        timeout=timeout,
    )
    if not resp.ok or resp.status != 200:
        return Status.UNKNOWN, addr, {"http_status": resp.status}
    text = (resp.text or "").strip()
    if text == "Unavailable":
        return Status.FOUND, addr, {}
    if text in ("Available", "OK", "Valid"):
        return Status.NOT_FOUND, addr, {}
    return Status.UNKNOWN, addr, {"body": text[:60]}


# ---------------------------------------------------------------------------
# SMTP RCPT check (aiosmtplib if present, else a minimal asyncio dialog)
# ---------------------------------------------------------------------------
async def _mx_hosts(domain: str) -> list[str]:
    def resolve() -> list[str]:
        import dns.resolver  # type: ignore

        answers = dns.resolver.Resolver().resolve(domain, "MX")
        ranked = sorted(answers, key=lambda r: r.preference)
        return [str(r.exchange).rstrip(".") for r in ranked]

    return await asyncio.to_thread(resolve)


def _classify_rcpt(code: int) -> Status:
    # Acceptance can be catch-all; rejection can mean syntax or sender policy.
    # An SMTP response alone does not prove mailbox existence or absence.
    return Status.UNKNOWN


def _validate_smtp_fields(*values: str) -> None:
    if any(not isinstance(value, str) or "\r" in value or "\n" in value for value in values):
        raise ValueError("SMTP fields must be strings without CR or LF characters")


async def _smtp_probe_asyncio(host: str, mail_from: str, rcpt_to: str, helo: str, timeout: float) -> int:
    _validate_smtp_fields(host, mail_from, rcpt_to, helo)
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, 25), timeout)

    async def read_response() -> int:
        code = 0
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout)
            if not line:
                break
            s = line.decode("utf-8", "replace")
            try:
                code = int(s[:3])
            except ValueError:
                pass
            # last line of a multiline reply has a space (not '-') at index 3
            if len(s) < 4 or s[3] != "-":
                break
        return code

    async def cmd(text: str) -> int:
        writer.write((text + "\r\n").encode())
        await writer.drain()
        return await read_response()

    try:
        await read_response()          # greeting
        code = await cmd(f"EHLO {helo}")
        if code >= 400:
            await cmd(f"HELO {helo}")
        await cmd(f"MAIL FROM:<{mail_from}>")
        rcpt_code = await cmd(f"RCPT TO:<{rcpt_to}>")
        try:
            await cmd("QUIT")
        except Exception:  # noqa: BLE001
            pass
        return rcpt_code
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout)
        except Exception:  # noqa: BLE001
            pass


async def _smtp_check(username: str, domain: str, timeout: float, *, proxy: str | None = None) -> tuple:
    _validate_smtp_fields(username, domain)
    addr = f"{username}@{domain}"
    if _smtp_proxy_configured(proxy):
        return Status.SKIPPED, addr, {"method": "smtp", "error": "SMTP checks cannot use the configured proxy"}
    mail_from = f"{_randstr(8)}@{domain}"
    helo = domain
    try:
        hosts = await asyncio.wait_for(_mx_hosts(domain), timeout)
    except Exception as exc:  # noqa: BLE001
        return Status.UNKNOWN, addr, {"error": f"MX lookup failed: {exc}", "method": "smtp"}
    if not hosts:
        return Status.UNKNOWN, addr, {"error": "no MX records", "method": "smtp"}

    last_err = ""
    for host in hosts[:2]:
        # Prefer aiosmtplib when installed; otherwise use the built-in dialog.
        try:
            _validate_smtp_fields(host, mail_from, addr, helo)
            try:
                import aiosmtplib  # type: ignore

                server = aiosmtplib.SMTP(hostname=host, port=25, timeout=timeout, validate_certs=True)
                try:
                    await server.connect()
                    await server.helo(helo)
                    await server.mail(mail_from)
                    code, _msg = await server.rcpt(addr)
                    try:
                        await server.quit()
                    except Exception:  # noqa: BLE001
                        pass
                finally:
                    try:
                        server.close()
                    except Exception:  # noqa: BLE001 - preserve the original failure/cancellation
                        pass
            except ImportError:
                code = await _smtp_probe_asyncio(host, mail_from, addr, helo, timeout)
        except Exception as exc:  # noqa: BLE001
            last_err = f"{type(exc).__name__}: {exc}"[:150]
            continue
        status = _classify_rcpt(code)
        return status, addr, {"method": "smtp", "mx": host, "smtp_code": code}
    return Status.UNKNOWN, addr, {"method": "smtp", "error": last_err or "connect failed (port 25 likely blocked)"}


def _smtp_proxy_configured(proxy=None) -> bool:
    """SMTP has no supported proxy route, including inherited HTTP proxy settings."""
    if proxy:
        return True
    proxies = getproxies()
    return any(proxies.get(scheme) for scheme in ("http", "https", "all"))


async def _chk_gmx(username: str, http: Http, timeout: float) -> tuple:
    for domain in ("gmx.com", "gmx.net", "gmx.de"):
        status, addr, extra = await _smtp_check(username, domain, timeout, proxy=http.proxy)
        if status in (Status.FOUND, Status.NOT_FOUND):
            return status, addr, extra
    return status, addr, extra  # type: ignore[name-defined]


async def _chk_webde(username: str, http: Http, timeout: float) -> tuple:
    return await _smtp_check(username, "web.de", timeout, proxy=http.proxy)


async def _chk_mailde(username: str, http: Http, timeout: float) -> tuple:
    return await _smtp_check(username, "mail.de", timeout, proxy=http.proxy)


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------
PROVIDERS: dict[str, ProviderCheck] = {
    "gmail": ProviderCheck("gmail", "Gmail", ["gmail.com"], "api", _chk_gmail),
    "outlook": ProviderCheck(
        "outlook", "Outlook / Hotmail / Live",
        ["outlook.com", "hotmail.com", "live.com", "outlook.de", "msn.com"], "api", _chk_outlook,
    ),
    "proton": ProviderCheck(
        "proton", "Proton Mail",
        ["proton.me", "protonmail.com", "protonmail.ch", "pm.me"], "api", _chk_proton,
    ),
    "mailru": ProviderCheck(
        "mailru", "Mail.ru",
        ["mail.ru", "bk.ru", "inbox.ru", "list.ru", "internet.ru"], "api", _chk_mailru,
    ),
    "rambler": ProviderCheck(
        "rambler", "Rambler",
        ["rambler.ru", "lenta.ru", "autorambler.ru", "myrambler.ru", "ro.ru", "rambler.ua"], "api", _chk_rambler,
    ),
    "tuta": ProviderCheck(
        "tuta", "Tuta / Tutanota",
        ["tuta.com", "tutanota.com", "tutamail.com", "tuta.io", "keemail.me"], "api", _chk_tuta,
    ),
    "yahoo": ProviderCheck("yahoo", "Yahoo Mail", ["yahoo.com"], "api", _chk_yahoo),
    "zoho": ProviderCheck("zoho", "Zoho Mail", ["zohomail.com"], "api", _chk_zoho),
    "firemail": ProviderCheck(
        "firemail", "Firemail", ["firemail.de", "firemail.at", "firemail.eu"], "api", _chk_firemail,
    ),
    "lycos": ProviderCheck("lycos", "Lycos", ["lycos.com"], "api", _chk_lycos),
    "gmx": ProviderCheck("gmx", "GMX", ["gmx.com", "gmx.net", "gmx.de"], "smtp", _chk_gmx),
    "webde": ProviderCheck("webde", "web.de", ["web.de"], "smtp", _chk_webde),
    "mailde": ProviderCheck("mailde", "mail.de", ["mail.de"], "smtp", _chk_mailde),
}

# iCloud is intentionally omitted: Apple's iforgot endpoint now returns 403 and
# requires anti-bot tokens harvested from a headless browser (see the upstream
# mailcat `iCloud` deprecation note).

_CONFIDENCE = {Status.FOUND: 0.8, Status.NOT_FOUND: 0.6}


async def _run_provider(pc: ProviderCheck, username: str, http: Http, timeout: float) -> Finding:
    base = dict(
        query=username,
        query_type="username",
        site=pc.name,
        site_id="mailcat-" + pc.key,
        category="mail",
        source="mailcat",
        method=pc.method,
    )
    if pc.method == "smtp" and _smtp_proxy_configured(http.proxy):
        return Finding(status=Status.SKIPPED, error="SMTP checks cannot use the configured proxy", **base)
    if pc.disabled_reason:
        return Finding(status=Status.SKIPPED, error=pc.disabled_reason, **base)
    try:
        status, email, extra = await asyncio.wait_for(pc.check(username, http, timeout), timeout=timeout + 5)
    except asyncio.TimeoutError:
        return Finding(status=Status.UNKNOWN, url="mailto:" + f"{username}@{pc.domains[0]}",
                       error="timed out", extra={"provider": pc.key,
                                                 "email": f"{username}@{pc.domains[0]}"}, **base)
    except Exception as exc:  # noqa: BLE001
        log.debug("provider %s raised", pc.key, exc_info=True)
        return Finding(status=Status.ERROR, url="mailto:" + f"{username}@{pc.domains[0]}",
                       error=f"{type(exc).__name__}: {exc}"[:200],
                       extra={"provider": pc.key, "email": f"{username}@{pc.domains[0]}"}, **base)

    extra = dict(extra or {})
    extra["email"] = email
    extra["provider"] = pc.key
    return Finding(
        status=status,
        url="mailto:" + email,
        confidence=_CONFIDENCE.get(status),
        extra=extra,
        **base,
    )


async def find_emails(
    username: str,
    http: Http,
    *,
    providers: list[str] | None = None,
    timeout: float = 10.0,
) -> list[Finding]:
    """Check ``<username>@<provider>`` existence across providers.

    Returns one :class:`Finding` per provider (FOUND / NOT_FOUND / UNKNOWN /
    RATE_LIMITED / ERROR).  Unknown provider names are ignored.  SMTP-based
    checks require outbound TCP/25 (often blocked); they degrade to UNKNOWN.
    SMTP providers are skipped when an explicit or inherited HTTP/HTTPS/ALL proxy
    is configured, before DNS or TCP activity, even with NO_PROXY exceptions.
    """
    _validate_smtp_fields(username)
    username = username.split("@")[0].strip()
    selected = providers if providers is not None else list(PROVIDERS)
    chosen = [PROVIDERS[k] for k in selected if k in PROVIDERS]

    findings = await asyncio.gather(
        *(_run_provider(pc, username, http, timeout) for pc in chosen)
    )
    return list(findings)
