import json

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.http import random_user_agent
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.models import Status
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def wattpad(email, client, out):
    name = "wattpad"
    domain = "wattpad.com"
    method = "register"
    frequent_rate_limit = True
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'User-Agent': random_user_agent(),
        'Accept': '*/*',
        'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
        'Connection': 'keep-alive',
        'Referer': 'https://www.wattpad.com/',
        'TE': 'Trailers',
    }
    response = await client.get("https://www.wattpad.com", headers=headers)
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        apply_mailbox_outcome(result, (issue, {}, reason), http_status=response.status_code)
        return
    headers["X-Requested-With"] = "XMLHttpRequest"
    response = await client.get("https://www.wattpad.com/api/v3/users/validate", headers=headers,
                                params={"email": email}, follow_redirects=False)
    issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=(200, 400))
    if issue is not None:
        apply_mailbox_outcome(result, (issue, {}, reason), http_status=response.status_code)
        return
    try:
        data = json.loads(response.text, object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        data = None
    # Retain the upstream's exact successful validation response. Its positive
    # test was merely "Cette adresse" ("this address"), which also matches
    # invalid-address errors. No verified complete positive marker is bundled.
    if response.status_code == 200 and data == {"message": "OK", "code": 200}:
        outcome = (Status.NOT_FOUND, {}, None)
    else:
        outcome = (Status.UNKNOWN, {}, "Wattpad did not return the supported validation-success response; a reliable account-positive marker is not established.")
    apply_mailbox_outcome(result, outcome, http_status=response.status_code)
