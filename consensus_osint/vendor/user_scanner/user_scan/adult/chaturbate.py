import json
import re
from urllib.parse import parse_qs, quote, urlsplit

import httpx
from bs4 import BeautifulSoup

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.named_user_contracts import _text, _url
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.result import Result

BASE_URL = "https://chaturbate.com"
SCOPE = "Username availability; not proof of a current Chaturbate profile or ownership"


def _body(response):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        raise ValueError(reason)
    data = json.loads(response.text, object_pairs_hook=_unique_object)
    if not isinstance(data, dict):
        raise ValueError("No Chaturbate response object")
    return data


def _token(response):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        raise ValueError(reason)
    soup = BeautifulSoup(response.text, "html.parser")
    for node in soup.find_all(["script", "style", "template", "noscript"]):
        node.decompose()
    inputs = soup.select('input[name="csrfmiddlewaretoken"][type="hidden"]')
    if len(inputs) != 1:
        raise ValueError("No unique active Chaturbate CSRF input")
    token = inputs[0].get("value")
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9]+", token):
        raise ValueError("Invalid Chaturbate CSRF token")
    return token


def _availability(response, user):
    try:
        data = _body(response)
    except (TypeError, ValueError):
        return Result.error("No successful Chaturbate validation response")
    errors = data.get("errors")
    if not isinstance(errors, dict) or has_service_error({key: value for key, value in data.items() if key != "errors"}):
        return Result.error("Missing or failed Chaturbate validation envelope")
    if "username" in data and (not isinstance(data["username"], str) or data["username"].casefold() != user.casefold()):
        return Result.error("Chaturbate validation identifies another username")
    messages = {}
    for key, value in errors.items():
        if key not in ("username", "email", "password", "password1", "password2", "password_confirm", "birthday", "gender", "terms"):
            return Result.error("Unrecognized Chaturbate form error")
        if isinstance(value, str):
            messages[key] = [value] if value else []
        elif isinstance(value, list) and all(isinstance(item, str) and item for item in value):
            messages[key] = value
        else:
            return Result.error("Malformed Chaturbate field error")
    username_errors = messages.get("username", [])
    if not username_errors:
        return Result.available(extra={"available": True, "scope": SCOPE})
    if len(username_errors) == 1 and re.fullmatch(r"(?:this )?username (?:is )?already taken\.?", username_errors[0], re.IGNORECASE):
        return Result.taken(extra={"available": False, "scope": SCOPE})
    return Result.error("Username validation failed without a recognized availability result")


async def validate_chaturbate(user: str) -> Result:
    show_url = BASE_URL + "/" + quote(user, safe="") + "/"
    register_url = BASE_URL + "/accounts/register/"
    check_api = BASE_URL + "/accounts/ajax_validate_register_form/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Mobile Safari/537.36",
        "X-Requested-With": "XMLHttpRequest", "Origin": BASE_URL, "Referer": register_url,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }
    async with httpx.AsyncClient(http2=True, follow_redirects=False, timeout=15.0) as client:
        try:
            landing = await client.get(register_url, headers={"User-Agent": headers["User-Agent"]}, follow_redirects=False)
            payload = {"csrfmiddlewaretoken": _token(landing), "username": user}
            response = await client.post(check_api, data=payload, headers=headers, follow_redirects=False)
            result = _availability(response, user)
            if result.is_found():
                extra = await _fetch_biocontext(client, user, headers["User-Agent"])
                if extra:
                    result.extra.update(extra)
            return result.update(url=show_url)
        except Exception as exc:
            return Result.error(exc, url=show_url)


async def _fetch_biocontext(client, user, user_agent):
    try:
        response = await client.get(BASE_URL + "/api/biocontext/" + quote(user, safe="") + "/",
                                    headers={"User-Agent": user_agent, "X-Requested-With": "XMLHttpRequest"}, follow_redirects=False)
        return _extract_biocontext(_body(response), user)
    except Exception:
        return {}


def _extract_biocontext(data, user):
    handle = data.get("username")
    if has_service_error(data) or not isinstance(handle, str) or not handle or handle.casefold() != user.casefold():
        return {}
    extra = {"username": handle, "profile_confirmed": True,
             "scope": "Matching Chaturbate public profile; not proof of ownership"}
    for key, target in (("real_name", "fullname"), ("location", "location"), ("display_birthday", "birthday"),
                        ("sex", "gender"), ("subgender", "subgender"), ("body_type", "body_type"),
                        ("time_since_last_broadcast", "last_broadcast")):
        if value := _text(data.get(key)):
            extra[target] = value
    age = data.get("display_age")
    if type(age) is int and age > 0 or isinstance(age, str) and re.fullmatch(r"[0-9]+", age):
        extra["age"] = str(age)
    followers = data.get("follower_count")
    if type(followers) is int and followers >= 0:
        extra["followers"] = followers
    for key in ("interested_in", "languages"):
        value = data.get(key)
        if isinstance(value, list):
            value = ", ".join(item.strip() for item in value if isinstance(item, str) and item.strip())
        elif key == "interested_in":
            value = None
        if value := _text(value):
            extra[key] = value
    if about := _text(data.get("about_me")):
        soup = BeautifulSoup(about, "html.parser")
        for node in soup.find_all(["script", "style", "template", "noscript"]):
            node.decompose()
        if bio := soup.get_text(" ", strip=True):
            extra["bio"] = bio
    links = []
    socials = data.get("social_medias")
    if isinstance(socials, list):
        for social in socials:
            raw = social.get("link") if isinstance(social, dict) else None
            if not isinstance(raw, str):
                continue
            try:
                targets = parse_qs(urlsplit(raw).query).get("url", [])
            except ValueError:
                continue
            if len(targets) == 1 and "\\" not in targets[0] and (link := _url(targets[0])):
                links.append(link)
    if links:
        extra["links"] = ", ".join(dict.fromkeys(links))
    return extra
