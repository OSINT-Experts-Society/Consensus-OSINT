"""Validation-only adaptation from User Scanner (MIT); no notification action."""
from consensus_osint.core.registration_checks import validate


async def validate_alza_de(email):
    show_url = "https://www.alza.de"
    return (await validate("alza_de", email)).update(url=show_url)
