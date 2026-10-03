import json
import re

import httpx
from bs4 import BeautifulSoup

from consensus_osint.core.availability_contracts import outcome
from consensus_osint.core.mailbox_contracts import http_issue, valid_token
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    base_url = "https://www.fitnessblender.com"
    api_url = "https://www.fitnessblender.com/api/v1/validate/unique-email"
    show_url = "https://www.fitnessblender.com"

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36",
        'Accept': "application/json, text/plain, */*",
        'Accept-Encoding': "identity",
        'sec-ch-ua-platform': '"Android"',
        'Origin': "https://www.fitnessblender.com",
        'Referer': "https://www.fitnessblender.com/join",
        'X-Requested-With': "XMLHttpRequest",
        'Priority': "u=1, i"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            # Step 1: Visit homepage to get cookies (XSRF-TOKEN and FB_SESSION)
            # Laravel sets these in the Set-Cookie header
            r_init = await client.get(base_url, headers=headers, follow_redirects=False)

            issue, reason = http_issue(r_init.status_code, r_init.headers, r_init.text)
            if issue is not None:
                return Result.error(reason)
            csrf_token = client.cookies.get("XSRF-TOKEN")
            if not csrf_token:
                page = BeautifulSoup(r_init.text, "html.parser")
                candidates = []
                for script in page.find_all("script"):
                    if not script.find_parent(["template", "noscript"]):
                        candidates.extend(re.findall(r'csrfToken:\s*"([^"\r\n]+)"', script.get_text()))
                csrf_token = candidates[0] if len(candidates) == 1 else None
            if not valid_token(csrf_token):
                return Result.error("CSRF token is missing or ambiguous")

            # Step 2: Post to the validation API
            headers['x-csrf-token'] = csrf_token
            headers['Content-Type'] = "application/json"

            payload = {
                "email": email,
                "force": 0
            }

            response = await client.post(
                api_url,
                content=json.dumps(payload),
                headers=headers, follow_redirects=False
            )

            status, _, reason = outcome(response, "fitnessblender", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except Exception as e:
        return Result.error(e)

async def validate_fitnessblender(email: str) -> Result:
    return await _check(email)
