"""Validation-only check adapted from User Scanner; no notification request."""
from consensus_osint.core.selected_email_checks import validate


async def validate_tindie(email):
    show_url = "https://www.tindie.com"
    return (await validate("tindie", email)).update(url=show_url)
