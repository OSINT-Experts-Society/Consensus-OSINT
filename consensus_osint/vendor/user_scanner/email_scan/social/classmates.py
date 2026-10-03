import re

from bs4 import BeautifulSoup

from consensus_osint.core.mailbox_contracts import http_issue, valid_token
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request_async
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://www.classmates.com"
    login_url = "https://www.classmates.com/auth/login"

    # No User-Agent or client hints: the impersonating transport supplies a set
    # that matches its TLS fingerprint, and overriding half of it re-trips the WAF.
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Origin": "https://www.classmates.com",
        "Referer": login_url,
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        # The login page is fetched as a plain navigation; sending the form's
        # Origin/Referer on it is what the WAF answers 403 to.
        r_init = await impersonate_request_async(login_url, allow_redirects=False)

        issue, reason = http_issue(r_init.status_code, r_init.headers, r_init.text)
        if issue is not None:
            return Result.error(reason)
        page = BeautifulSoup(r_init.text, "html.parser")
        for inert in page.select("script, style, template, noscript"):
            inert.decompose()
        tokens = page.select('input[name="_csrf"]')
        csrf = tokens[0].get("value") if len(tokens) == 1 else None
        if not valid_token(csrf):
            return Result.error("Login CSRF token is missing or ambiguous")

        payload = {
            "_csrf": csrf,
            "successUrl": "",
            "emailOrRegId": email,
            "password": "SafetyMismatch_123!",
            "rememberme": "no",
        }

        response = await impersonate_request_async(
            login_url, "POST", data=payload, headers=headers, allow_redirects=False
        )

        issue, reason = http_issue(response.status_code, response.headers, response.text)
        if issue is not None:
            return Result.error(reason, url=show_url)
        page = BeautifulSoup(response.text, "html.parser")
        for inert in page.select("script, style, template, noscript"):
            inert.decompose()
        message = " ".join(page.stripped_strings)
        # Invalid registration/password is ambiguous about which credential failed.
        # Only a whole visible missing-account statement is retained as evidence.
        if re.fullmatch(r"(?:we )?did not find an account for the email address[.!]?", message, re.I):
            return Result.available(url=show_url)
        return Result.error("No unambiguous account response", url=show_url)

    except Exception as e:
        return Result.error(e)


async def validate_classmates(email: str) -> Result:
    return await _check(email)
