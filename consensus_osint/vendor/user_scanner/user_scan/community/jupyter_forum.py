from urllib.parse import quote

from consensus_osint.core.discourse_contracts import lookup


def validate_jupyter_forum(user: str):
    query = user
    user = quote(user, safe="")
    url = f'https://discourse.jupyter.org/u/{user}.json'
    show_url = f'https://discourse.jupyter.org/u/{user}'
    headers = {'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0'}
    return lookup(query, url, show_url, style="standard", headers=headers)
