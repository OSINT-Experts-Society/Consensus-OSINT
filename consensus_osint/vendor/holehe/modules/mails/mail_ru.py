"""Retained recovery parser. The module remains disabled and potentially loud."""
from urllib.parse import quote

from consensus_osint.core.http import random_user_agent
from consensus_osint.core.mailbox_contracts import http_issue, mailru
from consensus_osint.core.models import Status
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def mail_ru(email, client, out):
    name = "mail_ru"
    domain = "mail.ru"
    method = "password recovery"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    try:
        response = await client.post("https://account.mail.ru/api/v1/user/password/restore",
            headers={"User-Agent": random_user_agent(), "Accept": "application/json, text/javascript, */*; q=0.01",
                     "X-Requested-With": "XMLHttpRequest", "Origin": "https://account.mail.ru",
                     "authority": "account.mail.ru", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                     "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty", "accept-language": "ru",
                     "Referer": "https://account.mail.ru/recovery?email=" + quote(email, safe="")},
            data={"email": email, "htmlencoded": "false"})
        status, reason = http_issue(response.status_code, response.headers, response.text)
        if status is not None:
            outcome = status, {}, reason
        else:
            try:
                outcome = mailru(response.json(), email, recovery=True)
            except ValueError:
                outcome = Status.UNKNOWN, {}, "Malformed Mail.ru JSON; account status is unknown."
        apply_mailbox_outcome(result, outcome, http_status=response.status_code)
    except Exception:
        apply_mailbox_outcome(result, (Status.ERROR, {}, "Mail.ru lookup request failed; account status is unknown."))
