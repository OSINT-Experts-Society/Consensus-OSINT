'Parse jobs and learning responses with query-bound enrichment.'
from __future__ import annotations

from urllib.parse import urlsplit

from .crm_contracts import http_problem
from .models import Status
from .provider_contracts import has_service_error


def _text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


def duolingo_profile(data, query, *, kind="email"):
    unknown = "Missing, ambiguous or unbound Duolingo profile; account status is unknown."
    if not isinstance(data, dict) or has_service_error(data) or not isinstance(data.get("users"), list):
        return Status.UNKNOWN, {}, unknown
    users = data["users"]
    if not users:
        return Status.NOT_FOUND, {}, None
    if len(users) != 1 or not isinstance(users[0], dict) or has_service_error(users[0]):
        return Status.UNKNOWN, {}, unknown
    user = users[0]
    username = _text(user.get("username"))
    if username is None:
        return Status.UNKNOWN, {}, unknown
    if kind == "username":
        if username.casefold() != query.strip().casefold():
            return Status.UNKNOWN, {}, unknown
    elif kind != "email" or "email" in user and (_text(user["email"]) or "").casefold() != query.strip().casefold():
        return Status.UNKNOWN, {}, unknown
    extra = {"username": username}
    for key in ("name", "bio"):
        if _text(user.get(key)):
            extra[key] = user[key].strip()
    for source, target in (("id", "id"), ("creationDate", "created"), ("totalXp", "total_xp"), ("streak", "streak")):
        if type(user.get(source)) is int and user[source] >= 0:
            extra[target] = user[source]
    for source, target in (("hasPlus", "has_plus"), ("hasGoogleId", "has_google_id"), ("hasFacebookId", "has_facebook_id")):
        if type(user.get(source)) is bool:
            extra[target] = user[source]
    picture = _text(user.get("picture"))
    if picture:
        picture = "https:" + picture if picture.startswith("//") else picture
        try:
            parsed = urlsplit(picture)
            valid = parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username and not parsed.password
        except ValueError:
            valid = False
        if valid and not any(ord(char) < 32 or char == "\\" for char in picture):
            extra["avatar"] = picture
    courses = user.get("courses")
    if isinstance(courses, list) and all(isinstance(course, dict) for course in courses):
        extra["courses"] = len(courses)
        titles = [_text(course.get("title")) for course in courses]
        if titles and all(titles):
            extra["course_titles"] = titles
    return Status.FOUND, extra, None


def outcome(site, response, query, *, kind="email"):
    status, reason = http_problem(response, accepted=(200, 409) if site == "freelancer" else (200,),
                                  html=site in ("diigo", "quora"))
    if status is not None:
        return status, {}, reason
    unknown = (Status.UNKNOWN, {}, "No supported account marker was returned; account status is unknown.")
    if site == "diigo":
        if response.text in ("0", "1"):
            return (Status.FOUND if response.text == "0" else Status.NOT_FOUND), {}, None
        return unknown
    if site == "quora":
        return Status.UNKNOWN, {}, "The retained Quora validation response has no verified account marker."
    try:
        data = response.json()
    except ValueError:
        return Status.UNKNOWN, {}, "Malformed provider JSON; account status is unknown."
    if not isinstance(data, dict):
        return unknown
    if site == "freelancer":
        if (response.status_code == 409 and data.get("error_code") == "EMAIL_ALREADY_IN_USE"
                and data.get("status") in (None, "error") and data.get("result") is None
                and not has_service_error({key: value for key, value in data.items() if key not in ("error_code", "status")})):
            return Status.FOUND, {}, None
        return unknown
    if has_service_error(data):
        return unknown
    if site == "duolingo":
        return duolingo_profile(data, query, kind=kind)
    if site == "coroflot":
        envelope, code = data.get("status"), data.get("data")
        good = (type(envelope) is int and envelope in (1, 200)
                or isinstance(envelope, str) and envelope in ("ok", "1", "200"))
        if good and type(code) is int and code in (-2, -3, 0):
            return (Status.NOT_FOUND if code == 0 else Status.FOUND), ({"activation_required": True} if code == -3 else {}), None
    elif site == "seoclerks":
        duplicate = "The email address you entered is already taken."
        if data.get("message") in (duplicate, [duplicate]):
            return Status.FOUND, {}, None
    return unknown
