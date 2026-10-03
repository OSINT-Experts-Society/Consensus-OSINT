"""Retained lastfm flow; offline parser repairs do not change execution policy."""
from consensus_osint.core.http import random_user_agent
from consensus_osint.core.mailbox_contracts import http_issue, valid_token
from consensus_osint.core.media_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def lastfm(email, client, out):
    name = "lastfm"
    domain = "last.fm"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {"User-Agent": random_user_agent(), "Accept": "application/json, text/html;q=0.9"}
    try:
        response = await client.get("https://www.last.fm/join", headers=headers)
        status, reason = http_issue(response.status_code, response.headers, response.text)
        if status is not None:
            apply_mailbox_outcome(result, (status, {}, reason), http_status=response.status_code)
            return
        token = response.cookies.get("csrftoken")
        if not valid_token(token):
            result["reason"] = "Lookup prerequisite is missing or ambiguous; no identifier lookup was submitted."
            return
        headers.update(Referer="https://www.last.fm/join", **{"X-Requested-With": "XMLHttpRequest"})
        headers["Cookie"] = "csrftoken=" + token
        response = await client.post("https://www.last.fm/join/partial/validate", headers=headers,
            data={"csrfmiddlewaretoken": token, "userName": "", "email": email})
        apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
    except Exception:
        apply_mailbox_outcome(result, (Status.ERROR, {}, "Provider request or prerequisite failed; account status is unknown."))


# Sample response from valid email on last.fm:
# {
#     "userName": {
#         "valid": false,
#         "success_message": "Ok, that username can be yours!",
#         "error_messages": [
#             "Please enter a username."
#         ]
#     },
#     "email": {
#         "valid": false,
#         "success_message": "Looking good!",
#         "error_messages": [
#             "Sorry, that email address is already registered to another account."
#         ]
#     },
#     "password": {
#         "valid": false,
#         "success_message": "Ok.",
#         "error_messages": [
#             "Please choose a password."
#         ]
#     },
#     "passwordConf": {
#         "valid": false,
#         "success_message": "Ok.",
#         "error_messages": [
#             "Please type your password again."
#         ]
#     },
#     "recaptcha": {
#         "valid": false,
#         "error_messages": [
#             "You didn't complete the captcha properly. Try again?"
#         ]
#     },
#     "backto": {
#         "valid": true
#     },
#     "terms": {
#         "valid": false,
#         "error_messages": [
#             "Not quite so fast! Please agree to these terms first."
#         ]
#     }
# }
