import httpx

from consensus_osint.core.models import Status
from consensus_osint.core.news_login_contracts import outcome, setup
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://bbc.com"
    login_url = "https://account.bbc.com/auth/identifier/signin?realm=%2F&clientId=Account&action=register&ptrt=https%3A%2F%2Fwww.bbc.com%2F&userOrigin=BBCS_BBC&purpose=free"
    check_url = "https://account.bbc.com/auth/identifier/check"

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36",
        'Accept': "application/json",
        'Origin': "https://account.bbc.com",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            nonce, reason = await setup(client, login_url, headers, "bbc")
            if nonce is None:
                return Result.error(reason, url=show_url)

            params = {
                'action': "sign-in",
                'clientId': "Account",
                'context': "international",
                'isCasso': "false",
                'journeyGroupType': "sign-in",
                'nonce': nonce,
                'ptrt': "https://www.bbc.com/",
                'purpose': "free",
                'realm': "/",
                'redirectUri': "https://session.bbc.com/session/callback?realm=/",
                'service': "IdRegisterService",
                'userOrigin': "BBCS_BBC"
            }

            payload = {"userIdentifier": email}

            check_res = await client.post(check_url, params=params, json=payload, headers=headers, follow_redirects=False)
            status, extra, reason = outcome(check_res, "bbc", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.ConnectTimeout:
        return Result.error("Connection timed out!")
    except httpx.ReadTimeout:
        return Result.error("Server took too long to respond (Read Timeout)")
    except Exception as e:
        return Result.error(e)


async def validate_bbc(email: str) -> Result:
    return await _check(email)
