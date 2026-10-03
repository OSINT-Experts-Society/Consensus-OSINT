from urllib.parse import quote

from consensus_osint.core.profile_page_contracts import native_guard

from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate, make_request, Result
import html
from decimal import Decimal, InvalidOperation

from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.provider_contracts import has_service_error
import re

# Liberapay connects an "elsewhere" account through OAuth only, so the block the
# profile renders is the site vouching for ownership rather than free text the
# owner typed. /<user>/public.json omits it, leaving the page as the only source.
ACCOUNTS_MARKER = "owns the following accounts on other platforms"
ACCOUNTS_BLOCK_OPEN = '<div class="accounts">'
DIV_TAG_RE = re.compile(r"</?div\b", re.I)
ACCOUNT_ANCHOR_RE = re.compile(r'<a\b([^>]*\bclass="account-link"[^>]*)>(.*?)</a>', re.S)
HREF_RE = re.compile(r'href="([^"]+)"')
PLATFORM_RE = re.compile(r'<span class="sr-only">\s*([^<:]+?)\s*:?\s*</span>')


def validate_liberapay(user):
    encoded_user = quote(user, safe="")
    url = f"https://en.liberapay.com/{encoded_user}"
    show_url = f"https://en.liberapay.com/{encoded_user}"

    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept-language": "en-Us,pt;q=0.6",
        "cache-control": "no-cache",
        "pragma": "no-cache",
        "priority": "u=0, i",
        "sec-ch-ua": '"Chromium";v="142", "Brave";v="142", "Not_A Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "sec-gpc": "1",
        "upgrade-insecure-requests": "1",
    }

    def process(response):
        guarded = native_guard("liberapay", response, user)
        if guarded is not None:
            return guarded
        if response.status_code == 200:
            extra = {}
            media = {}
            title_match = re.search(r'<title>([^<]+)</title>', response.text)
            if title_match:
                name = title_match.group(1).split("&#39;s profile")[0].split("'s profile")[0].strip()
                if name.lower() != user.lower():
                    extra["name"] = name
            accounts = _verified_accounts(response.text)
            if accounts:
                extra["verified_accounts"] = ", ".join(accounts)

            # Enrich profile metadata via public.json API
            try:
                json_url = f"https://liberapay.com/{encoded_user}/public.json"
                json_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
                json_resp = make_request(json_url, headers=json_headers)
                issue, _ = http_issue(json_resp.status_code, json_resp.headers, json_resp.text)
                if issue is None:
                    api_extra, api_media = _profile_fields(json_resp.json(), user)
                    extra.update(api_extra)
                    media.update(api_media)
            except Exception:
                pass

            return Result.taken(extra=extra, media=media)
        elif response.status_code in (404, 410):
            return Result.available()
        return Result.error(f"Unexpected status {response.status_code}")

    return generic_validate(url, process, show_url=show_url, headers=headers, follow_redirects=True)


def _verified_accounts(page):
    accounts = []
    seen = set()
    for match in ACCOUNT_ANCHOR_RE.finditer(_accounts_block(page)):
        href = HREF_RE.search(match.group(1))
        if not href:
            continue
        # Mastodon renders the visible name as user@instance, so the href is the
        # only place a usable profile URL appears.
        url = html.unescape(href.group(1)).strip()
        if not url.startswith(("http://", "https://")) or url in seen:
            continue
        seen.add(url)
        platform = PLATFORM_RE.search(match.group(2))
        label = html.unescape(platform.group(1)).strip() if platform else "Account"
        accounts.append(f"{label}: {url}")
    return accounts


def _accounts_block(page):
    """The linked-accounts markup only, empty when the profile lists none.

    The rest of the page renders donation relationships and patron lists naming
    other people, so a document-wide sweep would harvest strangers.
    """
    marker = page.find(ACCOUNTS_MARKER)
    if marker < 0:
        return ""
    start = page.find(ACCOUNTS_BLOCK_OPEN, marker)
    if start < 0:
        return ""
    depth = 0
    for tag in DIV_TAG_RE.finditer(page, start):
        depth += -1 if tag.group(0).startswith("</") else 1
        if depth == 0:
            return page[start : tag.start()]
    return ""


def _profile_fields(data, user):
    # The provider's public.json serializer includes id and username. Optional
    # details cannot replace a matched page with a different participant.
    if (not isinstance(data, dict) or has_service_error(data)
            or type(data.get("id")) is not int or data["id"] <= 0
            or not isinstance(data.get("username"), str) or data["username"].casefold() != user.casefold()):
        return {}, {}
    extra, media = {"id": data["id"]}, {}
    for source, target in (("display_name", "name"), ("kind", "kind")):
        if isinstance(data.get(source), str) and data[source].strip():
            extra[target] = data[source]
    if isinstance(data.get("avatar"), str) and data["avatar"].strip():
        media["avatar"] = data["avatar"]
    if type(data.get("npatrons")) is int and data["npatrons"] >= 0:
        extra["patrons"] = data["npatrons"]
    for field in ("receiving", "giving"):
        amount = _money(data.get(field))
        if amount is not None:
            extra[field] = amount
    summaries = data.get("summaries")
    if isinstance(summaries, list):
        valid = [s for s in summaries if isinstance(s, dict) and isinstance(s.get("content"), str) and s["content"].strip()]
        summary = next((s for s in valid if s.get("lang") == "en"), valid[0] if valid else None)
        if summary:
            extra["summary"] = summary["content"]
    return extra, media


def _money(value):
    if not isinstance(value, dict) or not isinstance(value.get("currency"), str) or not re.fullmatch(r"[A-Z]{3}", value["currency"]):
        return None
    amount = value.get("amount")
    if type(amount) not in (str, int, float):
        return None
    try:
        parsed = Decimal(str(amount))
        if parsed.is_finite() and parsed >= 0:
            return str(amount) + " " + value["currency"]
    except InvalidOperation:
        pass
    return None
