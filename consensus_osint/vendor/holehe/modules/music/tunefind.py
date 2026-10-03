"""Retained tunefind flow; offline parser repairs do not change execution policy."""
from consensus_osint.core.http import random_user_agent
from consensus_osint.core.mailbox_contracts import http_issue, valid_token
from consensus_osint.core.media_contracts import meta_token, outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def tunefind(email, client, out):
    name = "tunefind"
    domain = "tunefind.com"
    method = "register"
    frequent_rate_limit = True
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {"User-Agent": random_user_agent(), "Accept": "application/json, text/html;q=0.9"}
    try:
        headers.update(Referer="https://www.tunefind.com/", Origin="https://www.tunefind.com", **{"x-tf-react": "true"})
        response = await client.get("https://www.tunefind.com/user/join", headers=headers)
        status, reason = http_issue(response.status_code, response.headers, response.text)
        if status is not None:
            apply_mailbox_outcome(result, (status, {}, reason), http_status=response.status_code)
            return
        token = meta_token(response.text, "csrf-token")
        if not valid_token(token):
            result["reason"] = "Lookup prerequisite is missing or ambiguous; no identifier lookup was submitted."
            return
        # Retain the upstream request fields. The precise CSRF submission
        # contract remains unverified; this account-creation flow stays held.
        response = await client.post("https://www.tunefind.com/user/join", headers=headers,
            files=[("username", (None, "")), ("email", (None, email)), ("password", (None, ""))])
        apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
    except Exception:
        apply_mailbox_outcome(result, (Status.ERROR, {}, "Provider request or prerequisite failed; account status is unknown."))
