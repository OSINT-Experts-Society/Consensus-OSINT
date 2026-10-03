"""Validation-only adaptation from User Scanner (MIT); no notification action."""
from consensus_osint.core.registration_checks import validate


async def validate_visidarbi(email):
    show_url = "https://www.visidarbi.lv"
    return (await validate("visidarbi", email)).update(url=show_url)
