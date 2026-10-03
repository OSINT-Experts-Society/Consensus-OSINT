import re
from urllib.parse import quote

from bs4 import BeautifulSoup

from consensus_osint.core.profile_page_contracts import native_guard
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_letterboxd(user: str) -> Result:
    encoded_user = quote(user, safe="")
    url = f"https://letterboxd.com/{encoded_user}/"

    def process(response) -> Result:
        guarded = native_guard("letterboxd", response, user)
        if guarded is not None:
            return guarded
        page = BeautifulSoup(response.text, "html.parser")
        for node in page(["script", "style", "template"]):
            node.decompose()
        extra, media = {}, {}
        for key, target, destination in (("og:title", "name", extra),
                                         ("og:description", "bio", extra),
                                         ("og:image", "avatar", media)):
            node = page.find("meta", property=key)
            value = node.get("content", "").strip() if node else ""
            if key == "og:title":
                value = re.sub(r"['’]s profile(?:\s+(?:on|•)\s+Letterboxd)?\s*$", "", value).strip()
            if value:
                destination[target] = value
        return Result.taken(extra=extra, media=media)

    return impersonate_validate(url, process, warmup_url="https://letterboxd.com/",
                               impersonate="chrome120", show_url=url)
