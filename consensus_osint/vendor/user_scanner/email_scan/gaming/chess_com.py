import httpx

from consensus_osint.core.availability_contracts import outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    async with httpx.AsyncClient(timeout=15.0, http2=True) as client:
        try:
            url = "https://www.chess.com/rpc/chesscom.authentication.v1.EmailValidationService/Validate"
            show_url = "https://chess.com"

            payload = {
                "email": email
            }

            headers = {
                'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36",
                'Accept': "application/json, text/plain, */*",
                'Accept-Encoding': "identity",
                'Content-Type': "application/json",
                'sec-ch-ua-platform': '"Android"',
                'accept-language': "en_US",
                'connect-protocol-version': "1",
                'origin': "https://www.chess.com",
                'sec-fetch-site': "same-origin",
                'sec-fetch-mode': "cors",
                'referer': "https://www.chess.com/register",
                'priority': "u=1, i"
            }

            response = await client.post(url, json=payload, headers=headers, follow_redirects=False)

            status, _, reason = outcome(response, "chess_com", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(f"unexpected exception: {e}")


async def validate_chess_com(email: str) -> Result:
    return await _check(email)
