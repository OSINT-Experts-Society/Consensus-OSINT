from consensus_osint.core.http import random_user_agent
from consensus_osint.core.software_email_contracts import outcome
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def lastpass(email, client, out):
    name = "lastpass"
    domain = "lastpass.com"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.5',
        'Referer': 'https://lastpass.com/',
        'X-Requested-With': 'XMLHttpRequest',
    }
    headers["User-Agent"] = random_user_agent()
    response = await client.get("https://lastpass.com/create_account.php",
                                params={"check": "avail", "skipcontent": "1", "mistype": "1", "username": email},
                                headers=headers, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
