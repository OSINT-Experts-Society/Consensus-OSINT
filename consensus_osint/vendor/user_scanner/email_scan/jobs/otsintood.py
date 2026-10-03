"""Validation-only adaptation from User Scanner (MIT); no notification action."""
from consensus_osint.core.registration_checks import validate


async def validate_otsintood(email):
    show_url = "https://www.otsintood.ee"
    return (await validate("otsintood", email)).update(url=show_url)
