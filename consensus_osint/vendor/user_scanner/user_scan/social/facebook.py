import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.named_user_contracts import _text
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result

COUNTS_RE = re.compile(
    r"^.*?\.\s*(?P<likes>[\d,.]+) likes"
    r"(?:\s*\u00b7\s*(?P<talking>[\d,.]+) talking about this)?\.\s*(?P<bio>.*)$",
    re.DOTALL,
)
UNAVAILABLE_RE = re.compile(r"This content isn\\?'t available")


def _profile_url(url, user):
    if not isinstance(url, str) or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in url):
        return False
    try:
        parts = urlsplit(url)
        return (parts.scheme == "https" and parts.hostname == "www.facebook.com"
                and parts.port in (None, 443) and parts.username is None and parts.password is None
                and not parts.query and not parts.fragment
                and parts.path.rstrip("/").casefold() == "/" + user.casefold())
    except ValueError:
        return False


def validate_facebook(user):
    if (not isinstance(user, str) or not re.fullmatch(r"[a-zA-Z0-9.]{1,50}", user)
            or user.isdigit() or user.startswith(".") or user.endswith(".")):
        return Result.error("Invalid Facebook username")
    show_url = "https://www.facebook.com/" + user

    def process(response):
        if response.status_code in (301, 302, 303, 307, 308):
            issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=(301, 302, 303, 307, 308))
            if issue is not None:
                return Result.error(reason)
            location = response.headers.get("location", "")
            # Validate before URL joining, which otherwise strips whitespace.
            if not location or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in location):
                return Result.error("Unrecognised Facebook redirect")
            target = urljoin(show_url, location)
            if not _profile_url(target, user):
                return Result.error("Facebook redirect does not identify the requested handle")
            return impersonate_validate(target, lambda reply: _process_profile_response(reply, user),
                                        show_url=show_url, allow_redirects=False)
        return _process_profile_response(response, user)

    return impersonate_validate(show_url, process, show_url=show_url, allow_redirects=False)


def _process_profile_response(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    soup = BeautifulSoup(response.text, "html.parser")
    for node in soup.find_all(["script", "style", "template", "noscript"]):
        node.decompose()
    titles = [_text(node.get("content")) for node in soup.select('meta[property="og:title"]')]
    urls = [node.get("content") for node in soup.select('meta[property="og:url"]')]
    if (len(titles) != 1 or not titles[0] or titles[0].casefold() == "facebook"
            or not urls or not all(_profile_url(url, user) for url in urls)
            or UNAVAILABLE_RE.search(response.text)):
        return Result.error("No successful matching Facebook public page")
    extra = {"name": titles[0], "handle": urlsplit(urls[0]).path.strip("/"),
             "scope": "Facebook public page; may be a profile or Page, not proof of ownership"}
    descriptions = [_text(node.get("content")) for node in soup.select('meta[property="og:description"]')]
    if len(descriptions) == 1 and descriptions[0] and (counts := COUNTS_RE.match(descriptions[0])):
        extra["likes"] = counts["likes"]
        if counts["talking"]:
            extra["talking_about"] = counts["talking"]
        if bio := counts["bio"].strip():
            extra["bio"] = bio
    return Result.taken(extra=extra)
