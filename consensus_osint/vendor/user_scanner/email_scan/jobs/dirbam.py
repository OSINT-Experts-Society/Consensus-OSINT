"""Validation-only adaptation from User Scanner (MIT); no notification action."""
from consensus_osint.core.registration_checks import validate


async def validate_dirbam(email):
    show_url = "https://www.dirbam.lt"
    return (await validate("dirbam", email)).update(url=show_url)
