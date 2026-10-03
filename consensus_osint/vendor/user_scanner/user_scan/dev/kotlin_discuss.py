from urllib.parse import quote

from consensus_osint.core.discourse_contracts import lookup


def validate_kotlin_discuss(user: str):
    query = user
    user = quote(user, safe="")
    url = f'https://discuss.kotlinlang.org/u/{user}.json'
    show_url = f'https://discuss.kotlinlang.org/u/{user}'
    headers = {'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0'}
    return lookup(query, url, show_url, style="standard", headers=headers)
