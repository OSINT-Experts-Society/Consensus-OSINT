import html
import re
from urllib.parse import parse_qs, quote, urljoin, urlsplit

from bs4 import BeautifulSoup

from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.named_user_contracts import _url
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request
from consensus_osint.vendor.user_scanner.core.result import Result

BASE_URL = "https://www.osta.ee"
DEFAULT_AVATAR_PATH = "/assets/gfx/images/avatar_"


def validate_osta(user: str) -> Result:
    seller = _canonical_name(user) or user
    url = _seller_url(seller)

    try:
        response = impersonate_request(url, allow_redirects=False)
    except Exception as exc:
        return Result.error(exc, url=url)

    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason, url=url)
    page = _active_page(response.text)
    if not _matches(page, seller):
        return Result.error("No unique matching seller name", url=url)
    extra = _extract_profile(str(page))
    extra["username"] = seller
    user_id = _user_id(page, seller)
    profile_url = f"{BASE_URL}/en/user/{user_id}" if user_id else ""
    if profile_url:
        extra.update(_fetch(profile_url, _extract_profile, seller) or {})
        about_url = f"{BASE_URL}/en?fuseaction=listing.aboutseller&user={user_id}"
        extra.update(_fetch(about_url, _extract_about, seller) or {})
    media = {"avatar": extra.pop("avatar")} if "avatar" in extra else {}
    return Result.taken(extra=extra, media=media, url=profile_url or url)


def _canonical_name(user: str) -> str | None:
    """The seller listing is case-sensitive, so ``kristjan123`` misses the real
    ``Kristjan123``. The search route resolves a name case-insensitively and
    redirects to the canonical spelling; a name that resolves to nothing gets a
    plain 200 search page instead, which carries no verdict of its own.
    """
    search_url = (
        f"{BASE_URL}/en?fuseaction=search.search&q%5Bseller%5D="
        f"{quote(user, safe='')}"
    )
    try:
        response = impersonate_request(search_url, allow_redirects=False)
    except Exception:
        return None

    location = response.headers.get("location") or ""
    if response.status_code not in (301, 302):
        return None
    try:
        parsed = urlsplit(urljoin(BASE_URL + "/en", location))
        params = parse_qs(parsed.query, keep_blank_values=True)
        if (parsed.scheme != "https" or parsed.netloc != "www.osta.ee" or parsed.path != "/en"
                or parsed.fragment or params.get("fuseaction") != ["listing.seller"]):
            return None
        names = params.get("q[seller]", [])
        return names[0] if len(names) == 1 and names[0].casefold() == user.casefold() else None
    except ValueError:
        return None


def _seller_url(seller: str) -> str:
    return (
        f"{BASE_URL}/en?fuseaction=listing.seller&q%5Bseller%5D="
        f"{quote(seller, safe='')}"
    )


def _active_page(text):
    page = BeautifulSoup(text, "html.parser")
    for node in page(["script", "style", "template", "noscript"]):
        node.decompose()
    return page


def _matches(page, seller):
    names = page.select("strong.username")
    return len(names) == 1 and names[0].get_text(" ", strip=True).casefold() == seller.casefold()


def _user_id(page, seller):
    ids = set()
    for node in page.select("a[href]"):
        if node.get_text(" ", strip=True).casefold() != seller.casefold():
            continue
        try:
            url = urlsplit(urljoin(BASE_URL, node["href"]))
        except ValueError:
            continue
        match = re.fullmatch(r"/(?:en/)?user/([0-9]+)", url.path)
        if url.scheme == "https" and url.netloc == "www.osta.ee" and not url.query and not url.fragment and match:
            ids.add(match.group(1))
    return next(iter(ids)) if len(ids) == 1 else None


def _fetch(url: str, extract, seller):
    try:
        response = impersonate_request(url, allow_redirects=False)
        issue, _ = http_issue(response.status_code, response.headers, response.text)
        page = _active_page(response.text)
        if issue is not None or not _matches(page, seller):
            return None
        return extract(str(page))
    except Exception:
        return None


def _extract_profile(html_text: str) -> dict:
    text = _text(html_text)
    extra: dict[str, str | bool | int] = {}

    business = re.search(
        r'<div[^>]*class="[^"]*user-business-auth[^"]*"[^>]*>(.*?)</div>',
        html_text,
        re.IGNORECASE | re.DOTALL,
    )
    if business and re.search(r"\bCompany\b", _text(business.group(1)), re.IGNORECASE):
        extra["company"] = True
    if re.search(r'class="[^"]*id-card-logo-short', html_text, re.IGNORECASE):
        extra["identified"] = True

    if membership := re.search(
        r"User since\s+(\d{2}\.\d{2}\.\d{4}|\d{4})",
        text,
        re.IGNORECASE,
    ):
        extra["member_since"] = membership.group(1)

    fields = (
        (r"([\d,.]+)\s+Successful sales per year\b", "successful_sales_per_year"),
        (r"([\d,.]+)\s+Followers\b", "followers"),
        (r"\bActive sales\s+([\d,.]+)", "active_sales"),
        (r"\bFeedback\s+([\d,.]+)", "feedback_total"),
    )
    for pattern, key in fields:
        if match := re.search(pattern, text, re.IGNORECASE):
            extra[key] = _count(match.group(1))

    feedback = re.search(
        r"Feedback\s+positive\s+neutral\s+negative\b.*?\bAll\s+"
        r"([\d,.]+)\s+([\d,.]+)\s+([\d,.]+)",
        text,
        re.IGNORECASE,
    )
    if feedback:
        extra.update(
            feedback_positive=_count(feedback.group(1)),
            feedback_neutral=_count(feedback.group(2)),
            feedback_negative=_count(feedback.group(3)),
        )

    avatar = re.search(
        r'class="[^"]*user-avatar[^"]*"[^>]*style="[^"]*'
        r"background-image:\s*url\(['\"]?([^'\")]+)",
        html_text,
        re.IGNORECASE,
    )
    if avatar and DEFAULT_AVATAR_PATH not in (url := html.unescape(avatar.group(1))):
        if safe := _url(urljoin(BASE_URL, url)):
            extra["avatar"] = safe

    return extra


def _extract_about(html_text: str) -> dict | None:
    if not re.search(r'class="[^"]*seller-profile-box', html_text, re.IGNORECASE):
        return None

    extra = {}

    for role, key in (
        ("seller", "seller_reliability"),
        ("bidder", "buyer_reliability"),
    ):
        rating = re.search(
            rf'class="[^"]*{role}-rating[^"]*"[^>]*>\s*'
            rf'(?:<span[^>]*>\s*)?<b[^>]*>\s*(\d+(?:\.\d+)?%)',
            html_text,
            re.IGNORECASE,
        )
        if rating:
            extra[key] = rating.group(1)

    meta = re.search(
        r'<div[^>]*class="[^"]*seller-meta-info[^"]*"[^>]*>(.*?)</div>',
        html_text,
        re.IGNORECASE | re.DOTALL,
    )
    if meta:
        meta_text = _text(meta.group(1))
        if name := re.match(r"(.+?)\s*\|\s*User since\b", meta_text, re.IGNORECASE):
            extra["company_name"] = name.group(1).strip()
        if registration := re.search(r"\bReg\.\s*code:\s*([^|\s]+)", meta_text, re.IGNORECASE):
            extra["registration_code"] = registration.group(1)

    description = re.search(
        r'<div[^>]*id="show-profile-descr"[^>]*>.*?'
        r'<div[^>]*class="[^"]*description[^"]*"[^>]*>(.*?)</div>',
        html_text,
        re.IGNORECASE | re.DOTALL,
    )
    if description and (value := _text(description.group(1))):
        extra["description"] = value

    return extra


def _text(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", value))).strip()


def _count(value: str) -> int | None:
    if re.fullmatch(r"[0-9]+(?:[,.][0-9]{3})*", value):
        return int(re.sub(r"\D", "", value))
    return None
