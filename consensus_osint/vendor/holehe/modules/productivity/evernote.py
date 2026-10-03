from consensus_osint.core.http import random_user_agent
from consensus_osint.core.software_email_contracts import outcome, prerequisite
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def evernote(email, client, out):
    name = "evernote"
    domain = "evernote.com"
    method = "login"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'en,en-US;q=0.5',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://www.evernote.com',
        'Referer': 'https://www.evernote.com/Login.action',
    }
    headers["User-Agent"] = random_user_agent()
    response = await client.get("https://www.evernote.com/Login.action", headers=headers)
    fields, issue = prerequisite(name, response)
    if issue is not None:
        apply_mailbox_outcome(result, issue, http_status=response.status_code)
        return
    data = {"username": email, "evaluateUsername": "", **fields,
            "analyticsLoginOrigin": "login_action", "clipperFlow": "false",
            "showSwitchService": "true", "usernameImmutable": "false"}
    response = await client.post("https://www.evernote.com/Login.action", data=data,
                                 headers=headers, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
