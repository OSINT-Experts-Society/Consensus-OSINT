"""Retained Yahoo sign-in flow; a redirect is not an account verdict."""
from consensus_osint.core.http import random_user_agent
from consensus_osint.core.mailbox_contracts import hidden_fields, http_issue, yahoo_login
from consensus_osint.core.models import Status
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def yahoo(email, client, out):
    name = "yahoo"
    domain = "yahoo.com"
    method = "login"
    frequent_rate_limit = True
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {"User-Agent": random_user_agent(), "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5",
               "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Origin": "https://login.yahoo.com",
               "DNT": "1", "Connection": "keep-alive"}
    try:
        page = await client.get("https://login.yahoo.com", headers=headers)
        status, reason = http_issue(page.status_code, page.headers, page.text)
        if status is not None:
            apply_mailbox_outcome(result, (status, {}, reason), http_status=page.status_code)
            return
        tokens = hidden_fields(page.text, ("acrumb", "sessionIndex"))
        if tokens is None:
            result["reason"] = "Yahoo's sign-in prerequisites are missing or ambiguous; account status is unknown."
            result["http_status"] = page.status_code
            return
        response = await client.post("https://login.yahoo.com/",
            headers=headers | {"bucket": "mbr-fe-merge-manage-account", "X-Requested-With": "XMLHttpRequest"},
            params={".src": "fpctx", ".intl": "ca", ".lang": "en-CA", ".done": "https://ca.yahoo.com"},
            data=tokens | {"username": email, "passwd": "", "signin": "Next", "persistent": "y"})
        status, reason = http_issue(response.status_code, response.headers, response.text)
        if status is not None:
            outcome = status, {}, reason
        else:
            try:
                outcome = yahoo_login(response.json())
            except ValueError:
                outcome = Status.UNKNOWN, {}, "Malformed Yahoo JSON; account status is unknown."
        apply_mailbox_outcome(result, outcome, http_status=response.status_code)
    except Exception:
        apply_mailbox_outcome(result, (Status.ERROR, {}, "Yahoo lookup request failed; account status is unknown."))
