from urllib.parse import quote

from consensus_osint.core.discourse_contracts import lookup


def validate_arduino(user: str):
    query = user
    user = quote(user, safe="")
    url = f'https://forum.arduino.cc/u/{user}.json'
    show_url = f'https://forum.arduino.cc/u/{user}'
    return lookup(query, url, show_url, style="checker")
