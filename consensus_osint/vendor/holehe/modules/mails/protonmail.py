from consensus_osint.core.pgp_index import parse_index
from consensus_osint.vendor.holehe.core import append_http_error, lookup_result


async def protonmail(email, client, out):
    # Original lookup credit: https://github.com/pixelbubble/ProtOSINT
    name = "protonmail"
    domain = "protonmail.ch"
    method = "other"

    response = await client.get("https://api.protonmail.ch/pks/lookup",
        params={"op": "index", "search": email, "options": "mr"})
    if append_http_error(response, out, name, domain, method):
        return
    result = lookup_result(name, domain, method)
    exists, extra, reason = parse_index(response.text, email)
    result.update(http_status=response.status_code, exists=exists, unknown=exists is None, reason=reason)
    if extra:
        # Public index certificate metadata, not account creation or verified
        # cryptographic properties. Only complete matching email UIDs survive.
        result["others"] = extra
    out.append(result)
