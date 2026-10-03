"""Retained soundcloud flow; offline parser repairs do not change execution policy."""
from consensus_osint.core.http import random_user_agent
from consensus_osint.core.mailbox_contracts import http_issue, valid_token
from consensus_osint.core.media_contracts import outcome, soundcloud_client
from consensus_osint.core.models import Status
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def soundcloud(email, client, out):
    name = "soundcloud"
    domain = "soundcloud.com"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {"User-Agent": random_user_agent(), "Accept": "application/json, text/html;q=0.9"}
    try:
        response = await client.get("https://soundcloud.com/octobersveryown", headers=headers)
        status, reason = http_issue(response.status_code, response.headers, response.text)
        if status is not None:
            apply_mailbox_outcome(result, (status, {}, reason), http_status=response.status_code)
            return
        token = soundcloud_client(response.text)
        if not valid_token(token):
            result["reason"] = "Lookup prerequisite is missing or ambiguous; no identifier lookup was submitted."
            return
        response = await client.get("https://api-auth.soundcloud.com/web-auth/identifier", headers=headers,
            params={"q": email, "client_id": token})
        apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
    except Exception:
        apply_mailbox_outcome(result, (Status.ERROR, {}, "Provider request or prerequisite failed; account status is unknown."))
