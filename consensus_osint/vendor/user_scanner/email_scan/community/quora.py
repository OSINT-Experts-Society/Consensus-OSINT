"""Validation-only check adapted from User Scanner; no notification request."""
from consensus_osint.core.selected_email_checks import validate


async def validate_quora(email):
    show_url = "https://www.quora.com"
    return (await validate("quora", email)).update(url=show_url)
