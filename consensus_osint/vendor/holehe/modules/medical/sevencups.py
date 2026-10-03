"""Retained sevencups flow; offline parser repairs do not change execution policy."""
from consensus_osint.core.http import random_user_agent
from consensus_osint.core.media_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def sevencups(email, client, out):
    name = "sevencups"
    domain = "7cups.com"
    method = "register"
    frequent_rate_limit = True
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {"User-Agent": random_user_agent(), "Accept": "application/json, text/html;q=0.9"}
    try:
        headers.update(Origin="https://www.7cups.com", Referer="https://www.7cups.com/listener/CreateAccount.php",
                       **{"X-Requested-With": "XMLHttpRequest"})
        fields = {"email": email, "passwd": "", "dobMonth": "12", "dobDay": "11", "dobYear": "2010",
                  "orgPass": "", "data-request-datatype": "json", "submit-value": "null"}
        response = await client.post("https://www.7cups.com/listener/CreateAccount.php", headers=headers,
            files=[(key, (None, value)) for key, value in fields.items()])
        apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
    except Exception:
        apply_mailbox_outcome(result, (Status.ERROR, {}, "Provider request or prerequisite failed; account status is unknown."))
