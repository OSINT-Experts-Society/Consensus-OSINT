import re

import httpx
from bs4 import BeautifulSoup

from consensus_osint.core.mailbox_contracts import http_issue, valid_token
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url_login = "https://luarocks.org/login"
    url_forgot = "https://luarocks.org/user/forgot_password"
    show_url = "https://luarocks.org"

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Mobile Safari/537.36",
        'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        'Accept-Encoding': "gzip, deflate, br, zstd",
        'sec-ch-ua': '"Brave";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
        'sec-ch-ua-mobile': "?1",
        'sec-ch-ua-platform': '"Android"',
        'Upgrade-Insecure-Requests': "1",
        'Sec-GPC': "1",
        'Accept-Language': "en-US,en;q=0.9",
        'Origin': "https://luarocks.org",
        'Referer': url_forgot
    }

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:

            # Hit login endpoint directly to grab token cookie and search form csrf
            init_res = await client.get(url_login, headers=headers)
            issue, reason = http_issue(init_res.status_code, init_res.headers, init_res.text)
            if issue is not None:
                return Result.error(reason)
            page = BeautifulSoup(init_res.text, "html.parser")
            for inert in page.select("script, style, template, noscript"):
                inert.decompose()
            tokens = page.select('input[name="csrf_token"]')
            csrf_token = tokens[0].get("value") if len(tokens) == 1 else None
            if not valid_token(csrf_token):
                return Result.error("LuaRocks CSRF token is unavailable or ambiguous")

            # Push password reset form validation check
            payload = {
                'csrf_token': csrf_token,
                'email': email
            }

            response = await client.post(url_forgot, data=payload, headers=headers)
            issue, reason = http_issue(response.status_code, response.headers, response.text)
            if issue is not None:
                return Result.error(reason, url=show_url)
            page = BeautifulSoup(response.text, "html.parser")
            for inert in page.select("script, style, template, noscript"):
                inert.decompose()
            message = " ".join(page.stripped_strings)
            # A reset acknowledgment is not evidence of account existence.
            # Retain only a whole explicit missing-email statement, not a
            # fragment embedded in scripts, examples, or conflicting content.
            if re.fullmatch(r"(?:we )?don't know anyone with that email[.!]?", message, re.I):
                return Result.available(url=show_url)
            return Result.error("No unambiguous missing-account response; a reset acknowledgment does not prove an account", url=show_url)

    except Exception as e:
        return Result.error(str(e))

async def validate_luarocks(email: str) -> Result:
    return await _check(email)
