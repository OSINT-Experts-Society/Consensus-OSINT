import json
import re
from urllib.parse import quote, urlsplit

from bs4 import BeautifulSoup

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue, valid_token
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_request_async
from consensus_osint.vendor.user_scanner.core.result import Result

SHOW_URL = "https://github.com"
SEARCH_API = "https://api.github.com/search/users"
SIGNUP_URL = "https://github.com/signup"
VALIDITY_URL = "https://github.com/email_validity_checks"


def _document(response):
    issue, _ = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return None
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) and not has_service_error(data) else None


async def _check(email: str) -> Result:
    found = await _search_public_profiles(email)
    if found is not None:
        return found
    return await _check_signup_availability(email)


async def _search_public_profiles(email: str) -> Result | None:
    # Search returns candidates, not a verified email association. Bound the
    # additional work and verify the public profile on a fixed API origin.
    try:
        response = await impersonate_request_async(
            f"{SEARCH_API}?q={quote(email, safe='')}+in:email",
            headers={"accept": "application/vnd.github+json"}, allow_redirects=False,
        )
        data = _document(response)
        if data is None or not isinstance(data.get("items"), list):
            return None
        for candidate in data["items"][:5]:
            if not isinstance(candidate, dict):
                continue
            login, user_id = candidate.get("login"), candidate.get("id")
            if (not isinstance(login, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", login)
                    or type(user_id) is not int or user_id <= 0 or has_service_error(candidate)):
                continue
            profile = _document(await impersonate_request_async(
                f"https://api.github.com/users/{login}",
                headers={"accept": "application/vnd.github+json"}, allow_redirects=False,
            ))
            if (profile is None or type(profile.get("id")) is not int or profile["id"] != user_id
                    or not isinstance(profile.get("login"), str) or profile["login"].casefold() != login.casefold()
                    or not isinstance(profile.get("email"), str) or profile["email"].casefold() != email.casefold()):
                continue
            media = {}
            avatar = profile.get("avatar_url")
            if isinstance(avatar, str):
                try:
                    parsed = urlsplit(avatar)
                    if (parsed.scheme == "https" and parsed.netloc == "avatars.githubusercontent.com"
                            and not any(ord(c) <= 32 or ord(c) == 127 for c in avatar)):
                        media["avatar"] = avatar
                except ValueError:
                    pass
            account_type = profile.get("type")
            return Result.taken(url=SHOW_URL, media=media, extra={
                "account_type": account_type if account_type in ("User", "Organization", "Bot") else None,
                "login": login, "user_id": user_id, "profile": f"{SHOW_URL}/{login}",
                "matched_by": "public profile email",
            })
    except Exception:
        return None
    return None


async def _check_signup_availability(email: str) -> Result:
    try:
        signup = await impersonate_request_async(SIGNUP_URL, allow_redirects=False)
        issue, reason = http_issue(signup.status_code, signup.headers, signup.text)
        if issue is not None:
            return Result.error(reason, url=SHOW_URL)
        page = BeautifulSoup(signup.text, "html.parser")
        for inert in page.select("script, style, template, noscript"):
            inert.decompose()
        blocks = page.select('auto-check[src="/email_validity_checks"]')
        tokens = blocks[0].select('input[data-csrf="true"]') if len(blocks) == 1 else []
        token = tokens[0].get("value") if len(tokens) == 1 else None
        if not valid_token(token):
            return Result.error("GitHub email-validation form was unavailable or ambiguous", url=SHOW_URL)
        response = await impersonate_request_async(
            VALIDITY_URL, "POST", allow_redirects=False,
            data={"authenticity_token": token, "value": email},
            headers={"origin": SHOW_URL, "referer": SIGNUP_URL, "accept": "*/*"},
        )
        issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=(200, 422))
        if issue is not None:
            return Result.error(reason, url=SHOW_URL)
        # Only whole plain validation messages are evidence. HTML examples and
        # unfamiliar wording are inconclusive until their structure is known.
        body = response.text.strip()
        if re.fullmatch(r"(?:Email is )?already associated with an account[.]?", body):
            return Result.taken(url=SHOW_URL)
        if response.status_code == 200 and body == "Email is available":
            return Result.available(url=SHOW_URL)
        return Result.error("No unambiguous GitHub email-validation response", url=SHOW_URL)
    except Exception as e:
        return Result.error(e, url=SHOW_URL)


async def validate_github(email: str) -> Result:
    return await _check(email)
