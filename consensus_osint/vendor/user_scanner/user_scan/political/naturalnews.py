from urllib.parse import quote

from bs4 import BeautifulSoup

from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_naturalnews(user):
    url = "https://naturalnews.com/author/" + quote(user, safe="") + "/"

    def process(response):
        issue, reason = http_issue(response.status_code, response.headers, response.text)
        if issue is not None:
            return Result.error(reason)
        page = BeautifulSoup(response.text, "html.parser")
        for node in page(["script", "style", "template", "noscript"]):
            node.decompose()
        urls = [n.get("href", "") for n in page.select('link[rel~="canonical"]')]
        urls += [n.get("content", "") for n in page.select('meta[property="og:url"]')]
        if not urls or any(value.rstrip("/").casefold() != url.rstrip("/").casefold() for value in urls):
            return Result.error("No matching NaturalNews author URL")
        if not page.select("div.VideoPosts"):
            return Result.error("No active NaturalNews author content")
        titles = page.select("title")
        suffix = " - NaturalNews.com"
        title = titles[0].get_text().strip() if len(titles) == 1 else ""
        if not title.endswith(suffix) or not title[:-len(suffix)].strip():
            return Result.error("No unique NaturalNews author-page title")
        return Result.taken(extra={"title": title[:-len(suffix)].strip(), "scope": "Author archive; not proof of a user account or ownership"})

    return generic_validate(url, process, show_url=url, follow_redirects=False)
