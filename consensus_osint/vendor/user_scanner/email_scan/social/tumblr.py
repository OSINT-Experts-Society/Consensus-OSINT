import asyncio
import json
import re
import urllib.error
import urllib.request

from bs4 import BeautifulSoup

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue, valid_token
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.result import Result

# The public web app's bearer token, embedded in the homepage HTML.
API_TOKEN_RE = re.compile(r'"API_TOKEN":"([^"]+)"')
VALIDATE_URL = "https://www.tumblr.com/api/v2/register/account/validate"

# The route validates registration fields; short-password errors do not
# establish whether the submitted email is available.
USER_EXISTS = 2


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _check_sync(email: str) -> Result:
    show_url = "https://tumblr.com"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    try:
        opener = urllib.request.build_opener(_NoRedirect())
        # 1. Get Home Page
        req = urllib.request.Request("https://www.tumblr.com/", headers=headers)
        with opener.open(req, timeout=15.0) as response:
            html = response.read().decode("utf-8")
            issue, reason = http_issue(response.status, response.headers, html)
            if issue is not None:
                return Result.error(reason)

        page = BeautifulSoup(html, "html.parser")
        tokens = []
        for script in page.find_all("script"):
            if not script.find_parent(["template", "noscript"]):
                tokens.extend(API_TOKEN_RE.findall(script.get_text()))
        if len(tokens) != 1 or not valid_token(tokens[0]):
            return Result.error("Missing or ambiguous public API token")
        token = tokens[0]

        # 2. Get Radar to extract CSRF
        req2 = urllib.request.Request(
            "https://www.tumblr.com/api/v2/radar", headers={**headers, "Authorization": f"Bearer {token}"}
        )
        with opener.open(req2, timeout=15.0) as response2:
            body = response2.read().decode("utf-8")
            issue, reason = http_issue(response2.status, response2.headers, body)
            if issue is not None:
                return Result.error(reason)
            csrf = response2.headers.get("X-Csrf")
        if not valid_token(csrf):
            return Result.error("CSRF extraction failed, report it via GitHub issues")

        # 3. Post Account Validate
        req3 = urllib.request.Request(
            VALIDATE_URL,
            headers={
                **headers,
                "Authorization": f"Bearer {token}",
                "X-CSRF": csrf,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Origin": "https://www.tumblr.com",
                "Referer": "https://www.tumblr.com/register",
            },
            data=json.dumps({"email": email, "password": "x", "tumblelog": "osintuserprobe"}).encode("utf-8"),
            method="POST",
        )

        try:
            with opener.open(req3, timeout=15.0) as response3:
                res_body = response3.read().decode("utf-8")
                status, response_headers = response3.status, response3.headers
        except urllib.error.HTTPError as e:
            if e.code == 400:
                res_body = e.read().decode("utf-8")
                status, response_headers = e.code, e.headers
            else:
                return Result.error(f"Unexpected HTTP status: {e.code}")

        issue, reason = http_issue(status, response_headers, res_body, accepted=(200, 400))
        if issue is not None:
            return Result.error(reason)
        envelope = json.loads(res_body, object_pairs_hook=_unique_object)
        if not isinstance(envelope, dict) or has_service_error(envelope):
            return Result.error("Invalid validation envelope")
        data = envelope.get("response")
        if not isinstance(data, dict):
            return Result.error("Invalid validation result")
        meta = envelope.get("meta")
        if meta is not None and (
            not isinstance(meta, dict) or type(meta.get("status")) is not int or meta["status"] not in (200, 400)
        ):
            return Result.error("Conflicting validation status")
        for record in (envelope, data):
            if "email" in record and (
                not isinstance(record["email"], str) or record["email"].casefold() != email.casefold()
            ):
                return Result.error("Validation email mismatch")
        remainder = {k: v for k, v in data.items() if k != "error"}
        if (
            not has_service_error(remainder)
            and type(data.get("code")) is int
            and data["code"] == USER_EXISTS
            and data.get("error") == "User already exists"
        ):
            return Result.taken(url=show_url)
        return Result.error("Validation response does not establish account status", url=show_url)

    except Exception as e:
        return Result.error(f"unexpected exception: {e}")


async def validate_tumblr(email: str) -> Result:
    try:
        return await asyncio.to_thread(_check_sync, email)
    except Exception as e:
        return Result.error(f"unexpected exception: {e}")
