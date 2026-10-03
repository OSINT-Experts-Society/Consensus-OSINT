"""Validation-only check adapted from User Scanner; no notification request."""
from consensus_osint.core.selected_email_checks import validate


async def validate_codepen(email):
    show_url = "https://codepen.io"
    return (await validate("codepen", email)).update(url=show_url)
