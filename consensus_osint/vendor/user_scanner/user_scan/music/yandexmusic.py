from urllib.parse import quote

from consensus_osint.core.yandexmusic_contracts import result
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_yandexmusic(user: str) -> Result:
    url = f"https://music.yandex.ru/users/{quote(user, safe='')}"
    headers = {"User-Agent": get_random_user_agent(), "Referer": url + "/playlists", "Accept": "application/json"}
    return generic_validate(
        "https://music.yandex.ru/handlers/library.jsx", lambda response: result(response, user),
        params={"owner": user}, headers=headers, show_url=url, follow_redirects=False,
    )
