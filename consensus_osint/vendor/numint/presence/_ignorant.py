"""Consensus bridge to the maintained GPL-3.0 Ignorant phone implementations.

Numint's original copies were derived from Ignorant. Keep their public result
shape and registry entries while sharing response/number fixes. This bridge is
Consensus code; the original Numint MIT notice and Ignorant licence remain.
"""
import phonenumbers

from ..core.models import PresenceResult


async def run_ignorant(check, number, client, *, site, method):
    parsed = phonenumbers.parse(number.e164, None)
    out = []
    await check(phonenumbers.national_significant_number(parsed), str(parsed.country_code), client, out)
    if not out:
        return PresenceResult(site=site, method=method, error="Phone lookup returned no result.")
    raw = out[-1]
    error = raw.get("reason")
    if raw.get("rateLimit") is True:
        registered = "rate_limited"
    elif raw.get("blocked") is True:
        registered, error = "error", "Blocked: " + (error or "Provider access was denied.")
    elif raw.get("error") is True:
        registered = "error"
    elif raw.get("unknown") is True:
        registered = "unknown"
    elif raw.get("exists") is True:
        registered = "yes"
    elif raw.get("exists") is False:
        registered = "no"
    else:
        registered = "unknown"
    result = PresenceResult(site=site, method=method, registered=registered, error=error)
    if registered == "yes":
        result.masked_email = raw.get("emailrecovery")
        result.masked_phone = raw.get("phoneNumber")
        result.hint = (raw.get("others") or {}).get("username")
    return result
