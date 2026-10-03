"""Validation-only adaptation from User Scanner (MIT); no notification action."""
from consensus_osint.core.registration_checks import validate


async def validate_alza_at(email):
    show_url = "https://www.alza.at"
    return (await validate("alza_at", email)).update(url=show_url)
