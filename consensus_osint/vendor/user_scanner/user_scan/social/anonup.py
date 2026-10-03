from urllib.parse import quote

from bs4 import BeautifulSoup

from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_anonup(user):
    url = f"https://anonup.com/@{quote(user, safe='')}"

    def process(response):
        issue, reason = http_issue(response.status_code, response.headers, response.text)
        if issue is not None:
            return Result.error(reason)
        page = BeautifulSoup(response.text, "html.parser")
        for node in page(["script", "style", "template", "noscript"]):
            node.decompose()
        urls = [node.get("href", "") for node in page.select('link[rel~="canonical"]')]
        urls += [node.get("content", "") for node in page.select('meta[property="og:url"]')]
        if not urls or any(value.rstrip("/").casefold() != url.casefold() for value in urls):
            return Result.error("No matching Anonup profile URL")
        controls = page.select('a, button, [role="button"]')
        for node in controls:
            labels = [node.get_text(" ", strip=True)]
            labels += [node.get(attr, "") for attr in ("title", "aria-label", "data-original-title")]
            if any(value.strip() == "Show followings" for value in labels):
                return Result.taken(extra={"username": user})
        return Result.error("No active Anonup profile followings control")

    return generic_validate(url, process, show_url=url, follow_redirects=False)
