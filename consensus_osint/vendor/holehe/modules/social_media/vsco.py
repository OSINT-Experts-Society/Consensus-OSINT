from consensus_osint.core.social_email_contracts import outcome
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def vsco(email, client, out):
    name = "vsco"
    domain = "vsco.co"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Authorization': 'Bearer 7356455548d0a1d886db010883388d08be84d0c9',
    }
    response = await client.get("https://api.vsco.co/2.0/users/email", params={"email": email},
                                headers=headers, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
