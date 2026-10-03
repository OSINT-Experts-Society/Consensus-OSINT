from urllib.parse import quote

from consensus_osint.core.discourse_contracts import lookup


def validate_elixir_forum(user: str):
    query = user
    user = quote(user, safe="")
    url = f'https://forum.elixirforum.com/u/{user}.json'
    show_url = f'https://forum.elixirforum.com/u/{user}'
    headers = {'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36'}
    return lookup(query, url, show_url, style="standard", headers=headers, follow_redirects=True)
