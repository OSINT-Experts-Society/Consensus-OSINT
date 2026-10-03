from bs4 import BeautifulSoup

from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request_async
from consensus_osint.vendor.user_scanner.core.result import Result


async def validate_annaabi(email: str) -> Result:
    show_url = "https://annaabi.ee"

    try:
        response = await impersonate_request_async(
            f"{show_url}/register.php",
            params={"go": "1", "emailcheck": email},
            headers={"Referer": f"{show_url}/register.php"},
            allow_redirects=False,
        )

        issue, reason = http_issue(response.status_code, response.headers, response.text)
        if issue is not None:
            return Result.error(reason, url=show_url)
        page = BeautifulSoup(response.text, "html.parser")
        for tag in page.find_all(["script", "style", "template", "noscript"]):
            tag.decompose()
        inputs = page.find_all("input", id="psemail")
        if len(inputs) != 1:
            return Result.error("Missing or ambiguous email validation field", url=show_url)
        body = page.get_text(" ", strip=True)
        value = inputs[0].get("value")
        taken_message = "Sellise emailiga kasutaja on juba registreerinud" in body
        available_message = "See email on vaba" in body
        taken = (
            value == "2" and taken_message and not available_message
        )
        available = (
            value == "1" and available_message and not taken_message
        )
        if taken != available:
            return (
                Result.taken(url=show_url)
                if taken
                else Result.available(url=show_url)
            )
        return Result.error("Unexpected response body", url=show_url)
    except Exception as exc:
        return Result.error(exc, url=show_url)
