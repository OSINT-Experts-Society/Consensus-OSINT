"""Validation-only adaptation from User Scanner (MIT); no notification action."""
from consensus_osint.core.registration_checks import validate


async def validate_alza_sk(email):
    show_url = "https://www.alza.sk"
    return (await validate("alza_sk", email)).update(url=show_url)
