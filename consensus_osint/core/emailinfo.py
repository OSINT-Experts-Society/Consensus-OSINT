"""Local (offline / DNS-only) analysis of an e-mail address."""
from __future__ import annotations

import hashlib
import re

from .models import Finding, Status

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-']+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$")

PROVIDERS = {
    "gmail.com": "Google", "googlemail.com": "Google", "outlook.com": "Microsoft", "hotmail.com": "Microsoft",
    "hotmail.co.uk": "Microsoft", "live.com": "Microsoft", "msn.com": "Microsoft", "yahoo.com": "Yahoo",
    "yahoo.co.uk": "Yahoo", "ymail.com": "Yahoo", "aol.com": "AOL", "icloud.com": "Apple", "me.com": "Apple",
    "mac.com": "Apple", "protonmail.com": "Proton", "proton.me": "Proton", "pm.me": "Proton", "tutanota.com": "Tuta",
    "tuta.io": "Tuta", "tuta.com": "Tuta", "gmx.com": "GMX", "gmx.de": "GMX", "gmx.net": "GMX", "web.de": "web.de",
    "mail.ru": "Mail.ru", "bk.ru": "Mail.ru", "inbox.ru": "Mail.ru", "list.ru": "Mail.ru", "yandex.ru": "Yandex",
    "yandex.com": "Yandex", "ya.ru": "Yandex", "rambler.ru": "Rambler", "zoho.com": "Zoho", "fastmail.com": "Fastmail",
    "hey.com": "HEY", "qq.com": "Tencent QQ", "163.com": "NetEase", "126.com": "NetEase", "naver.com": "Naver",
    "daum.net": "Daum", "seznam.cz": "Seznam", "wp.pl": "WP", "o2.pl": "O2", "interia.pl": "Interia", "libero.it": "Libero",
    "orange.fr": "Orange", "free.fr": "Free", "laposte.net": "La Poste", "sfr.fr": "SFR", "t-online.de": "T-Online",
    "btinternet.com": "BT", "sky.com": "Sky", "virginmedia.com": "Virgin Media", "comcast.net": "Comcast",
    "att.net": "AT&T", "verizon.net": "Verizon", "sbcglobal.net": "AT&T", "cox.net": "Cox", "rediffmail.com": "Rediff",
}

# Small built-in list; the full disposable-domain list can be dropped into
# data/disposable_domains.txt (one domain per line) to extend it.
DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org", "yopmail.com",
    "trashmail.com", "getnada.com", "dispostable.com", "maildrop.cc", "sharklasers.com", "throwawaymail.com",
    "fakeinbox.com", "mohmal.com", "emailondeck.com", "tempr.email", "mintemail.com", "mytemp.email", "tmpmail.org",
    "burnermail.io", "spamgourmet.com", "33mail.com", "harakirimail.com", "mailnesia.com", "tempail.com",
}


def _load_disposable_file() -> set:
    try:
        from pathlib import Path

        p = Path(__file__).resolve().parent.parent / "data" / "disposable_domains.txt"
        if p.exists():
            return {ln.strip().lower() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")}
    except Exception:  # noqa: BLE001
        pass
    return set()


_DISPOSABLE_EXTRA = None


def is_disposable(domain: str) -> bool:
    global _DISPOSABLE_EXTRA
    if _DISPOSABLE_EXTRA is None:
        _DISPOSABLE_EXTRA = _load_disposable_file()
    d = domain.lower()
    return d in DISPOSABLE or d in _DISPOSABLE_EXTRA


def normalise(email: str) -> str:
    return email.strip().lower()


def gravatar_hashes(email: str) -> dict:
    e = normalise(email).encode()
    return {"md5": hashlib.md5(e).hexdigest(), "sha256": hashlib.sha256(e).hexdigest()}


def valid_syntax(email: str) -> bool:
    """Validate the supported unquoted ASCII address syntax, without I/O."""
    if not isinstance(email, str) or len(email) > 254 or EMAIL_RE.fullmatch(email) is None:
        return False
    local, _, domain = email.partition("@")
    return (len(local) <= 64 and not local.startswith(".") and not local.endswith(".")
            and ".." not in local and all(
                1 <= len(label) <= 63 and not label.startswith("-") and not label.endswith("-")
                for label in domain.split(".")))


def local_analysis(email: str, resolve_dns: bool = True) -> dict:
    """Syntax, provider, disposable flag, Gravatar hashes and MX records."""
    e = normalise(email)
    valid = valid_syntax(e)
    local, _, domain = e.partition("@")
    info: dict = {"email": e, "valid_syntax": valid}
    if not valid:
        return info
    info["local_part"] = local
    info["domain"] = domain
    info["provider"] = PROVIDERS.get(domain)
    info["disposable"] = is_disposable(domain)
    info["plus_alias"] = "+" in local
    base_local = local
    if domain in ("gmail.com", "googlemail.com"):
        base_local = base_local.split("+", 1)[0].replace(".", "")
    info["canonical"] = f"{base_local}@{domain}"
    info["gravatar"] = gravatar_hashes(e)
    info["gravatar_url"] = f"https://gravatar.com/avatar/{info['gravatar']['md5']}?d=404"
    if resolve_dns:
        info.update(dns_info(domain))
    return info


def dns_info(domain: str) -> dict:
    out: dict = {}
    try:
        import dns.resolver  # type: ignore

        res = dns.resolver.Resolver()
        res.lifetime = 5.0
        try:
            answers = res.resolve(domain, "MX")
            mx = sorted((r.preference, str(r.exchange).rstrip(".")) for r in answers)
            out["mx"] = [h for _, h in mx]
            out["mx_provider"] = guess_mx_provider(out["mx"])
        except Exception as exc:  # noqa: BLE001
            out["mx"] = []
            out["mx_error"] = type(exc).__name__
        try:
            txt = res.resolve(domain, "TXT")
            spf = [str(r).strip('"') for r in txt if "v=spf1" in str(r)]
            out["spf"] = spf[0] if spf else None
        except Exception:  # noqa: BLE001
            pass
        try:
            dm = res.resolve(f"_dmarc.{domain}", "TXT")
            out["dmarc"] = str(list(dm)[0]).strip('"')
        except Exception:  # noqa: BLE001
            out["dmarc"] = None
    except Exception:  # noqa: BLE001
        pass
    return out


def guess_mx_provider(mx: list) -> str | None:
    joined = " ".join(mx).lower()
    for needle, name in (
        ("google", "Google Workspace / Gmail"), ("outlook", "Microsoft 365 / Outlook"), ("protection.outlook", "Microsoft 365"),
        ("yahoodns", "Yahoo"), ("icloud", "Apple iCloud"), ("protonmail", "Proton"), ("zoho", "Zoho"), ("mail.ru", "Mail.ru"),
        ("yandex", "Yandex"), ("mimecast", "Mimecast"), ("pphosted", "Proofpoint"), ("messagelabs", "Symantec"),
        ("secureserver", "GoDaddy"), ("ovh", "OVH"), ("fastmail", "Fastmail"), ("tutanota", "Tuta"), ("gmx", "GMX"),
        ("emailsrvr", "Rackspace"), ("mailgun", "Mailgun"), ("amazonaws", "Amazon SES"),
    ):
        if needle in joined:
            return name
    return None


async def async_dns_info(domain: str) -> dict:
    """Cancellable parallel DNS; independent site checks never wait for this."""
    import asyncio

    import dns.asyncresolver

    async def lookup(name, kind):
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 5.0
            return await asyncio.wait_for(resolver.resolve(name, kind), timeout=5)
        except Exception as exc:
            return exc

    mx, txt, dmarc = await asyncio.gather(lookup(domain, "MX"), lookup(domain, "TXT"), lookup("_dmarc." + domain, "TXT"))
    out = {}
    if isinstance(mx, Exception):
        out.update(mx=[], mx_error=type(mx).__name__)
    else:
        out["mx"] = [host for _, host in sorted((r.preference, str(r.exchange).rstrip(".")) for r in mx)]
        out["mx_provider"] = guess_mx_provider(out["mx"])
    if not isinstance(txt, Exception):
        spf = [str(r).strip('"') for r in txt if "v=spf1" in str(r)]
        out["spf"] = spf[0] if spf else None
    out["dmarc"] = str(list(dmarc)[0]).strip('"') if not isinstance(dmarc, Exception) and dmarc else None
    return out


def to_finding(info: dict, query: str) -> Finding:
    status = Status.FOUND if info.get("valid_syntax") and info.get("mx", [None]) else Status.NOT_FOUND
    if info.get("valid_syntax") and "mx" in info and not info["mx"]:
        status = Status.UNKNOWN
    extra = {k: v for k, v in info.items() if k not in ("email", "gravatar")}
    return Finding(query=query, query_type="email", site="Address analysis", site_id="email-local", status=status,
                   url=None, category="analysis", source="email", method="syntax+dns", extra=extra)
