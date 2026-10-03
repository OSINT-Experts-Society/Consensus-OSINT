"""Retain the known migration signal without guessing undocumented negatives."""
import random

from consensus_osint.vendor.holehe.localuseragent import ua
from consensus_osint.vendor.holehe.core import read_lookup_response


async def flickr(email, client, out):
    name = "flickr"
    domain = "flickr.com"
    method = "login"
    result = dict(name=name, domain=domain, method=method, frequent_rate_limit=False,
                  rateLimit=False, exists=None, unknown=True,
                  reason="Unrecognised migration response; no validated account-absence signal")
    out.append(result)
    response = await client.get(
        "https://identity-api.flickr.com/migration", params={"email": email},
        headers={"User-Agent": random.choice(ua["browsers"]["chrome"]),
                 "Accept": "application/json", "Referer": "https://identity.flickr.com/login",
                 "Origin": "https://identity.flickr.com"},
    )
    data = read_lookup_response(response, result)
    if isinstance(data, dict) and data.get("state_code") == "5":
        result.update(exists=True, unknown=False, reason=None)
