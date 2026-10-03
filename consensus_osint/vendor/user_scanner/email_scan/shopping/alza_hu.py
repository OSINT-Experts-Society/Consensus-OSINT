"""Validation-only adaptation from User Scanner (MIT); no notification action."""
from consensus_osint.core.registration_checks import validate


async def validate_alza_hu(email):
    show_url = "https://www.alza.hu"
    return (await validate("alza_hu", email)).update(url=show_url)
