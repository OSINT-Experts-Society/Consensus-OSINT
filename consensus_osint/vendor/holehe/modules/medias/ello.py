"""Retained ello flow; offline parser repairs do not change execution policy."""
from consensus_osint.core.http import random_user_agent
from consensus_osint.core.media_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def ello(email, client, out):
    name = "ello"
    domain = "ello.co"
    method = "register"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {"User-Agent": random_user_agent(), "Accept": "application/json, text/html;q=0.9"}
    try:
        response = await client.post("https://ello.co/api/v2/availability", headers=headers, json={"email": email})
        answer = outcome(name, response, email)
        if answer[0] is Status.FOUND:
            import secrets

            local, separator, domain_part = email.rpartition("@")
            if not local or not separator or not domain_part:
                answer = Status.UNKNOWN, {}, "A valid email domain is required for the availability control."
            else:
                control_email = secrets.token_hex(12) + "@" + domain_part
                control = await client.post("https://ello.co/api/v2/availability", headers=headers, json={"email": control_email})
                control_answer = outcome(name, control, control_email)
                if control_answer[0] is Status.FOUND:
                    answer = Status.UNKNOWN, {}, "The control address was also unavailable; account status is unknown."
                elif control_answer[0] is not Status.NOT_FOUND:
                    apply_mailbox_outcome(result, control_answer, http_status=control.status_code)
                    result["reason"] = "Availability control did not succeed; " + (control_answer[2] or "account status is unknown.")
                    return
        apply_mailbox_outcome(result, answer, http_status=response.status_code)
    except Exception:
        apply_mailbox_outcome(result, (Status.ERROR, {}, "Provider request or prerequisite failed; account status is unknown."))
