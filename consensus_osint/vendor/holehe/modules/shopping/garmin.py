from consensus_osint.core.http import random_user_agent
from consensus_osint.core.transport_email_contracts import outcome, page_token
from consensus_osint.vendor.holehe.core import apply_mailbox_outcome, lookup_result


async def garmin(email, client, out):
    name = "garmin"
    domain = "garmin.com"
    method = "register"
    frequent_rate_limit = True
    result = lookup_result(name, domain, method)
    result["frequent_rate_limit"] = frequent_rate_limit
    out.append(result)
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en,en-US;q=0.5',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'TE': 'Trailers',
    }
    headers["User-Agent"] = random_user_agent()
    params = {
        'service': 'https://www.garmin.com/fr-FR/account/profile/',
        'webhost': 'https://www.garmin.com/fr-FR/account/create/',
        'source': 'https://www.garmin.com/fr-FR/account/create/',
        'redirectAfterAccountLoginUrl': 'https://www.garmin.com/fr-FR/account/profile/',
        'redirectAfterAccountCreationUrl': 'https://www.garmin.com/fr-FR/account/profile/',
        'gauthHost': 'https://sso.garmin.com/sso',
        'id': 'js__app__create__gauth-widget',
        'cssUrl': 'https://www.garmin.com/account/ui/css/create-account-v1.12.3-min.css',
        'clientId': 'ACCOUNT_MANAGEMENT_CENTER',
        'rememberMeShown': 'true',
        'rememberMeChecked': 'undefined',
        'createAccountShown': 'true',
        'openCreateAccount': 'true',
        'displayNameShown': 'false',
        'consumeServiceTicket': 'true',
        'initialFocus': 'true',
        'embedWidget': 'false',
        'generateExtraServiceTicket': 'true',
        'generateTwoExtraServiceTickets': 'false',
        'generateNoServiceTicket': 'false',
        'globalOptInShown': 'true',
        'globalOptInChecked': 'false',
        'mobile': 'false',
        'connectLegalTerms': 'false',
        'showTermsOfUse': 'false',
        'showPrivacyPolicy': 'false',
        'showConnectLegalAge': 'false',
        'locationPromptShown': 'false',
        'showPassword': 'true',
        'useCustomHeader': 'false',
        'mfaRequired': 'false',
        'rememberMyDeviceShown': 'false',
        'rememberMyDeviceChecked': 'false',
    }
    response = await client.get("https://sso.garmin.com/sso/createNewAccount", headers=headers, params=params)
    token, issue = page_token(response, "token")
    if issue is not None:
        apply_mailbox_outcome(result, issue, http_status=response.status_code)
        return
    headers.update({"Origin": "https://sso.garmin.com", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
    response = await client.post("https://sso.garmin.com/sso/validateNewAccount", headers=headers,
                                 params={"clientId": "", "locale": ""}, data={"email": email, "token": token},
                                 follow_redirects=False)
    apply_mailbox_outcome(result, outcome(name, response, email), http_status=response.status_code)
