import httpx

from consensus_osint.core.models import Status
from consensus_osint.core.provider_contracts import email_flag_outcome
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://naturabuy.fr"
    headers = {
        'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        'Accept': '*/*',
        'Accept-Language': 'fr,fr-FR;q=0.9,en;q=0.8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://www.naturabuy.fr',
        'Referer': 'https://www.naturabuy.fr/register.php',
    }

    files = {
        'jsref': (None, 'email'),
        'jsvalue': (None, email),
        'registerMode': (None, 'full')
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                'https://www.naturabuy.fr/includes/ajax/register.php',
                headers=headers,
                files=files,
                follow_redirects=False,
            )

            status, _, reason = email_flag_outcome(response, "free", email, true_means_available=True)
            if status is Status.FOUND:
                return Result.taken(url=show_url)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

    except httpx.TimeoutException:
        return Result.error("Connection timed out")
    except Exception as e:
        return Result.error(str(e))


async def validate_naturabuy(email: str) -> Result:
    return await _check(email)
