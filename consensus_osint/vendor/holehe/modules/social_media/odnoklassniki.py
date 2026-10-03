from bs4 import BeautifulSoup, Comment

from consensus_osint.core.http import random_user_agent
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.models import Status
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


# Original recovery flow: https://github.com/shllwrld/ok_checker/
def recovery_card(response):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return issue, {}, reason
    unknown = (Status.UNKNOWN, {}, "No unambiguous recovery account card; account status is unknown.")
    page = BeautifulSoup(response.text, "html.parser")
    for element in page.find_all(["script", "style", "template", "noscript"]):
        element.decompose()
    for comment in page.find_all(string=lambda value: isinstance(value, Comment)):
        comment.extract()
    cards = page.find_all("div", attrs={"data-l": "registrationContainer,offer_contact_rest"})
    if len(cards) != 1 or page.find("div", attrs={"data-l": "registrationContainer,home_rest"}):
        return unknown
    accounts = cards[0].select("div.ext-registration_tx.taCenter")
    if len(accounts) != 1:
        return unknown
    names = accounts[0].select("div.ext-registration_username_header")
    if len(names) != 1 or not names[0].get_text(" ", strip=True):
        return unknown
    parts = [names[0].get_text(" ", strip=True)]
    parts.extend(item.get_text(" ", strip=True) for item in accounts[0].select("div.lstp-t"))
    extra = {"FullName": "; ".join(part for part in parts if part)}
    for marker, key in [("t,email", "recovery_email"), ("t,phone", "phone_hint")]:
        buttons = cards[0].find_all("button", attrs={"data-l": marker})
        if len(buttons) != 1:
            continue
        hints = buttons[0].select("div.ext-registration_stub_small_header")
        if len(hints) == 1 and hints[0].get_text(" ", strip=True):
            extra[key] = hints[0].get_text(" ", strip=True)
    return Status.FOUND, extra, None


async def odnoklassniki(email, client, out):
    name = "odnoklassniki"
    domain = "ok.ru"
    method = "password recovery"
    frequent_rate_limit = False
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        "User-Agent": random_user_agent(),
        "Accept": "*/*",
        "Accept-Language": "en,en-US;q=0.5",
        "Referer": "https://ok.ru/",
        "DNT": "1",
        "Connection": "keep-alive",
    }
    response = await client.get("https://www.ok.ru/dk", headers=headers, follow_redirects=False,
                                params={"st.cmd": "anonymMain", "st.accRecovery": "on",
                                        "st.error": "errors.password.wrong", "st.email": email})
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        apply_mailbox_outcome(result, (issue, {}, reason), http_status=response.status_code)
        return
    response = await client.get("https://www.ok.ru/dk", headers=headers, follow_redirects=False,
                                params={"st.cmd": "anonymRecoveryAfterFailedLogin",
                                        "st._aid": "LeftColumn_Login_ForgotPassword"})
    apply_mailbox_outcome(result, recovery_card(response), http_status=response.status_code)
