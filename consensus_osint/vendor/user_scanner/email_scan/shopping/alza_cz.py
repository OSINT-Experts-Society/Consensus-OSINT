"""Validation-only adaptation from User Scanner (MIT); no notification action."""
from consensus_osint.core.registration_checks import validate


async def validate_alza_cz(email):
    show_url = "https://www.alza.cz"
    return (await validate("alza_cz", email)).update(url=show_url)
