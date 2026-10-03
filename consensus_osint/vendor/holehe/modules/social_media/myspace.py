from consensus_osint.core.http import random_user_agent
from consensus_osint.core.mailbox_contracts import hidden_fields, http_issue
from consensus_osint.core.social_email_contracts import outcome
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def myspace(email, client, out):
    name = "myspace"
    domain = "myspace.com"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.5',
        'Origin': 'https://myspace.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Referer': 'https://myspace.com/signup/email',
    }
    headers["User-Agent"] = random_user_agent()
    response = await client.get("https://myspace.com/signup/email", headers=headers, timeout=2)
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        apply_mailbox_outcome(result, (issue, {}, reason), http_status=response.status_code)
        return
    fields = hidden_fields(response.text, ("csrf",))
    if fields is None:
        result["reason"] = "Missing or ambiguous CSRF token; no email was submitted."
        return
    headers["Hash"] = fields["csrf"]
    headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
    headers["X-Requested-With"] = "XMLHttpRequest"
    response = await client.post("https://myspace.com/ajax/account/validateemail", headers=headers,
                                 data={"email": email}, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
