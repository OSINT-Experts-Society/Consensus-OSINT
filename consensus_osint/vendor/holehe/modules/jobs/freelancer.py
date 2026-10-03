from consensus_osint.vendor.holehe.core import *
from consensus_osint.vendor.holehe.localuseragent import *


async def freelancer(email, client, out):
    name = "freelancer"
    domain = "freelancer.com"
    method= "register"
    frequent_rate_limit=False

    headers = {
        'User-Agent': random.choice(ua["browsers"]["firefox"]),
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
        'Content-Type': 'application/json',
        'Origin': 'https://www.freelancer.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }
    response = await client.post('https://www.freelancer.com/api/users/0.1/users/check?compact=true&new_errors=true',
        json={'user': {'email': email}}, headers=headers)
    append_jobs_learning_outcome(response, out, name, domain, method, email)
