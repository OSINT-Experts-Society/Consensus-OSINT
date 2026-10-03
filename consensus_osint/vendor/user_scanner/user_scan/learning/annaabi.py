from bs4 import BeautifulSoup

from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_annaabi(user: str) -> Result:
    show_url = "https://annaabi.ee"

    def process(response):
        issue, reason = http_issue(response.status_code, response.headers, response.text)
        if issue is not None:
            return Result.error(reason)
        page = BeautifulSoup(response.text, "html.parser")
        for tag in page.find_all(["script", "style", "template", "noscript"]):
            tag.decompose()
        fields = page.find_all("input", id="psname")
        if len(fields) != 1:
            return Result.error("Missing or ambiguous username validation field")
        body = page.get_text(" ", strip=True)
        taken_message = "Selline kasutajanimi on juba v\u00f5etud" in body
        available_message = "See kasutajanimi on vaba" in body
        value = fields[0].get("value")
        extra = {"scope": "Username availability response; not verification of a public profile"}
        if value == "2" and taken_message and not available_message:
            return Result.taken(extra=extra)
        if value == "1" and available_message and not taken_message:
            return Result.available(extra=extra)
        return Result.error("Unexpected or contradictory username validation response")

    return impersonate_validate(
        f"{show_url}/register.php", process,
        params={"go": "1", "usernamecheck": user},
        headers={"Referer": f"{show_url}/register.php"},
        show_url=show_url, allow_redirects=False,
    )
