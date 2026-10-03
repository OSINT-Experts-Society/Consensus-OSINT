from urllib.parse import quote

from consensus_osint.core.discourse_contracts import lookup
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent


def validate_mozilladiscourse(user: str):
    query = user
    user = quote(user, safe="")
    url = f'https://discourse.mozilla.org/u/{user}.json'
    show_url = f'https://discourse.mozilla.org/u/{user}'
    headers = {'User-Agent': get_random_user_agent(), 'Accept': 'application/json'}
    return lookup(query, url, show_url, style="mozilla", headers=headers, http2=True)
