from consensus_osint.core.discord_contracts import availability
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_discord(user):
    url = "https://discord.com/api/v9/unique-username/username-attempt-unauthed"
    show_url = "https://discord.com"

    headers = {
        "authority": "discord.com",
        "accept": "application/json",
        "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
        "content-type": "application/json",
        "origin": "https://discord.com",
        "referer": "https://discord.com/register",
    }

    data = {"username": user}


    return generic_validate(
        url,
        lambda response: availability(response, user),
        show_url=show_url,
        method="POST",
        json=data,
        headers=headers,
        timeout=3.0,
        follow_redirects=False,
    )
