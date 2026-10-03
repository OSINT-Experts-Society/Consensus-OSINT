import json
import re

from consensus_osint.core.twitch_contracts import result
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, generic_validate


def validate_twitch(user: str) -> Result:
    if not (4 <= len(user) <= 25):
        return Result.error("Username must be between 4 and 25 characters long")

    if not re.fullmatch(r"[a-zA-Z0-9_]+", user):
        return Result.error(
            "Username can only contain letters, numbers and underscores"
        )

    url = "https://gql.twitch.tv/gql"
    show_url = f"https://twitch.tv/{user}"

    payload = [
        {
            "operationName": "ChannelLayout",
            "variables": {"channelLogin": user, "includeIsDJ": True},
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "4c361fa1874dc8f6a49e62b56aa1032eccb31311bdb653918a924f96a8b2d1a6",
                }
            },
        }
    ]

    headers = {
        "User-Agent": get_random_user_agent(),
        "Accept-Encoding": "identity",
        "Content-Type": "application/json",
        "sec-ch-ua-platform": '"Android"',
        "accept-language": "en-US",
        "client-id": "kimne78kx3ncx6brgo4mv6wki5h1ko",
        "client-version": "7bb0442d-1175-4ab5-9d32-b1f370536cbf",
        "origin": "https://m.twitch.tv",
        "referer": "https://m.twitch.tv/",
    }

    return generic_validate(
        url,
        lambda response: result(response, user),
        show_url=show_url,
        headers=headers,
        method="POST",
        content=json.dumps(payload),
        follow_redirects=False,
    )
