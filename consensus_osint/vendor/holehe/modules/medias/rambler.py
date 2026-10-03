"""Retained rambler flow; offline parser repairs do not change execution policy."""
from consensus_osint.core.http import random_user_agent
from consensus_osint.core.media_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def rambler(email, client, out):
    name = "rambler"
    domain = "rambler.ru"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {"User-Agent": random_user_agent(), "Accept": "application/json, text/html;q=0.9"}
    try:
        headers.update(Origin="https://id.rambler.ru", Referer="https://id.rambler.ru/champ/registration")
        response = await client.post("https://id.rambler.ru/jsonrpc", headers=headers,
            json={"method": "Rambler::Id::get_email_account_info", "params": [{"email": email}], "rpc": "2.0"})
        apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
    except Exception:
        apply_mailbox_outcome(result, (Status.ERROR, {}, "Provider request or prerequisite failed; account status is unknown."))
