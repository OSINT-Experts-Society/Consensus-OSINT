"""Validation-only check adapted from User Scanner; no notification request."""
from consensus_osint.core.selected_email_checks import validate


async def validate_wisio(email):
    show_url = "https://www.wisio.com"
    return (await validate("wisio", email)).update(url=show_url)
