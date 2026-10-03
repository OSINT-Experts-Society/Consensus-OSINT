"""Stripchat profile identity and separate username availability evidence."""
import json
import re

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error
from .soundcloud_contracts import _Scripts

FIELDS = {
    "id": "user_id",
    "name": "name",
    "previousUsername": "previous_username",
    "age": "age",
    "birthDate": "birth_date",
    "gender": "gender",
    "genderDoc": "gender_doc",
    "country": "country",
    "region": "region",
    "city": "city",
    "ethnicity": "ethnicity",
    "hairColor": "hair_color",
    "eyeColor": "eye_color",
    "bodyType": "body_type",
    "interestedIn": "interested_in",
    "subculture": "subculture",
    "description": "bio",
    "offlineStatus": "status_message",
    "favoritedCount": "favorites",
    "isOnline": "is_online",
    "isLive": "is_live",
    "isPornStar": "is_pornstar",
    "createdAt": "created_at",
    "avatarUrl": "avatar",
}


def _state(document):
    quoted = r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`'''
    pattern = (r"//[^\n]*|/\*[\s\S]*?\*/|" + quoted
               + r"|/(?![*/])(?:\\.|[^/\\\r\n])+/[dgimsuvy]*"
               + r"|(?P<assignment>(?<![\w$.])(?:__PRELOADED_STATE__|window\s*(?:\.\s*__PRELOADED_STATE__|\[\s*(?:'__PRELOADED_STATE__'|\"__PRELOADED_STATE__\")\s*\]))\s*=)")
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
    states = []
    for script in _Scripts(document).scripts:
        for match in re.finditer(pattern, script):
            if match["assignment"] is None:
                continue
            start = match.end()
            while start < len(script) and script[start].isspace():
                start += 1
            data, end = decoder.raw_decode(script, start)
            tail = script[end:].lstrip()
            if tail and not tail.startswith(";"):
                raise ValueError("Unsupported Stripchat state")
            states.append(data)
    if len(states) != 1 or not isinstance(states[0], dict) or has_service_error(states[0]):
        raise ValueError("Missing or ambiguous Stripchat state")
    return states[0]



def body(response):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        raise ValueError(reason)
    data = json.loads(response.text, object_pairs_hook=_unique_object)
    if not isinstance(data, dict) or has_service_error(data):
        raise ValueError("No successful Stripchat response object")
    return data


def identity(data, user, expected_id=None):
    return (isinstance(data, dict) and not has_service_error(data)
            and type(data.get("id")) is int and data["id"] > 0
            and (expected_id is None or data["id"] == expected_id)
            and isinstance(data.get("username"), str) and bool(data["username"])
            and data["username"].casefold() == user.casefold())


def extract(data):
    extra = {"user_id": data["id"], "username": data["username"]}
    enum_fields = {"gender", "genderDoc", "ethnicity", "hairColor", "eyeColor", "bodyType", "interestedIn", "subculture"}
    flags = {"isOnline", "isLive", "isPornStar"}
    for key, target in FIELDS.items():
        value = data.get(key)
        if key == "id":
            continue
        if key in flags:
            if type(value) is bool:
                extra[target] = value
        elif key in ("age", "favoritedCount"):
            if type(value) is int and value >= (1 if key == "age" else 0):
                extra[target] = value
        elif key == "avatarUrl":
            if isinstance(value, str) and "\\" not in value and _url(value):
                extra[target] = value
        elif value := _text(value):
            if key in enum_fields and value.casefold().startswith(key.casefold()):
                value = value[len(key):]
            if value:
                extra[target] = value
    for key in ("languages", "specifics", "interests"):
        values = data.get(key)
        if not isinstance(values, list):
            continue
        values = [value.strip() for value in values if isinstance(value, str) and value.strip()]
        if key == "specifics":
            values = [re.sub(r"^(?:specifics?|hairLength)", "", value) for value in values]
        if any(values):
            extra[key] = ", ".join(value for value in values if value)
    return extra


def model_page(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    try:
        state = _state(response.text)
        view = state.get("viewCam")
        model = view.get("model") if isinstance(view, dict) and not has_service_error(view) else None
    except (TypeError, ValueError):
        return Result.error("Invalid Stripchat preloaded state")
    if not identity(model, user):
        return Result.error("No matching Stripchat model identity")
    return Result.taken(extra={"type": "model", **extract(model)})


def availability(code, text, user, headers):
    issue, reason = http_issue(code, headers, text, accepted=(200, 400))
    if issue is not None:
        return issue, {}, reason
    try:
        data = json.loads(text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return Status.UNKNOWN, {}, "Invalid Stripchat availability JSON"
    scope = "Username availability; not proof of a current Stripchat profile or ownership"
    if code == 200 and data == []:
        return Status.NOT_FOUND, {"available": True, "scope": scope}, None
    if code == 400 and data == {"error": "This username already exists"}:
        return Status.FOUND, {"available": False, "scope": scope}, None
    return Status.UNKNOWN, {}, "No recognized Stripchat availability response"
