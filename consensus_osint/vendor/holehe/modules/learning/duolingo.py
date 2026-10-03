from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def duolingo(email, client, out):
    name = "duolingo"
    domain = "duolingo.com"
    method= "other"
    frequent_rate_limit=False

    response = await client.get('https://www.duolingo.com/2017-06-30/users', params={'email': email})
    append_jobs_learning_outcome(response, out, name, domain, method, email)
