from consensus_osint.core.email_validation import csrf_setup, duplicate_message
from consensus_osint.core.http import random_user_agent
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def codepen(email, client, out):
    name = "codepen"
    domain = "codepen.io"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        "User-Agent": random_user_agent(), "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "en,en-US;q=0.5", "Referer": "https://codepen.io/accounts/signup/user/free",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest", "Origin": "https://codepen.io",
    }
    response = await client.get("https://codepen.io/accounts/signup/user/free", headers=headers)
    token, issue = csrf_setup(response, "codepen")
    if issue is not None:
        apply_mailbox_outcome(result, issue, http_status=response.status_code)
        return
    headers["X-CSRF-Token"] = token
    response = await client.post("https://codepen.io/accounts/duplicate_check",
                                 headers=headers, data={"attribute": "email", "value": email, "context": "user"}, follow_redirects=False)
    apply_mailbox_outcome(result, duplicate_message(response, "That Email is already taken."),
                         http_status=response.status_code)
