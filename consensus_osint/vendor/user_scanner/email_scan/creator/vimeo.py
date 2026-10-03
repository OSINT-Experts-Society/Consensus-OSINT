import httpx

from consensus_osint.core.creator_email_contracts import outcome, vimeo_token
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://vimeo.com"
    async with httpx.AsyncClient(timeout=15.0, http2=True, follow_redirects=True) as client:
        try:
            headers = {
                'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
                'Accept-Encoding': "gzip, deflate, br",
                'accept-language': "en-US,en;q=0.9",
                'sec-ch-ua-platform': '"Linux"',
                'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
                'sec-ch-ua-mobile': "?0",
            }

            viewer = await client.get(
                "https://vimeo.com/_next/viewer",
                headers={**headers, 'Accept': "application/json", 'referer': "https://vimeo.com/join"},
            )
            token, reason = vimeo_token(viewer)
            if not token:
                return Result.error(reason, url=show_url)

            payload = {
                'email': email,
                'token': token,
                'action': "join",
                'service': "vimeo",
                'email_validation': "true",
            }
            response = await client.post(
                "https://vimeo.com/join",
                data=payload,
                follow_redirects=False,
                headers={
                    **headers,
                    'Accept': "application/json",
                    'X-Requested-With': "XMLHttpRequest",
                    'content-type': "application/x-www-form-urlencoded",
                    'origin': "https://vimeo.com",
                    'referer': "https://vimeo.com/join",
                },
            )

            status, extra, reason = outcome(response, "vimeo", email)
            if status is Status.FOUND:
                return Result.taken(url=show_url, extra=extra)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(f"unexpected exception: {e}")


async def validate_vimeo(email: str) -> Result:
    return await _check(email)
