from consensus_osint.core.twitter_email_contracts import outcome
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def twitter(email, client, out):
    name = "twitter"
    domain = "twitter.com"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    response = await client.get("https://api.twitter.com/i/users/email_available.json",
                                params={"email": email}, follow_redirects=False)
    apply_mailbox_outcome(result, outcome(response, email), http_status=response.status_code)
