"""Validation-only check adapted from User Scanner; no notification request."""
from consensus_osint.core.selected_email_checks import validate


async def validate_medal(email):
    show_url = "https://medal.tv"
    return (await validate("medal", email)).update(url=show_url)
