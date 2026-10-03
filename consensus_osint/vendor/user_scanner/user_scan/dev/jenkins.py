from urllib.parse import quote

from consensus_osint.core.discourse_contracts import lookup
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent


def validate_jenkins(user: str):
    query = user
    user = quote(user, safe="")
    url = f'https://community.jenkins.io/u/{user}.json'
    show_url = f'https://community.jenkins.io/u/{user}'
    headers = {'User-Agent': get_random_user_agent(), 'Accept': 'application/json'}
    return lookup(query, url, show_url, style="rich", headers=headers, follow_redirects=True)
