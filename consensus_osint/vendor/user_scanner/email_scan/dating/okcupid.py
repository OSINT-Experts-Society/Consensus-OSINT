import secrets

import httpx

from consensus_osint.core.dating_email_contracts import anonymous_token, outcome
from consensus_osint.core.models import Status
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    token_url = "https://e2p-okapi.api.okcupid.com/graphql/AnonAuthToken"
    validate_url = "https://e2p-okapi.api.okcupid.com/graphql/ValidateEmail"
    show_url = "https://okcupid.com"

    device_id = secrets.token_hex(11)

    headers = {
        "User-Agent": "Android 115.1.0",
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/json",
        "x-apollo-operation": "AnonAuthToken",
        "x-okcupid-device-id": f"Android; Pixel 6; 13; {device_id};",
        "x-okcupid-app": "OkCupid Android App 115.1.0",
        "x-okcupid-platform": "Android",
        "x-okcupid-version": "115.1.0",
        "x-okcupid-locale": "en-US",
        "x-match-useragent": "OkCupid/115.1.0 REL/13",
        "x-okcupid-auth-v": "1",
        "x-okcupid-emulator": "false",
        "x-emb-path": "/graphql/AnonAuthToken",
    }

    payload_token = {
        "operationName": "AnonAuthToken",
        "variables": {
            "input": {
                "deviceId": device_id,
                "siteCode": 36,
            }
        },
        "query": "mutation AnonAuthToken($input: AuthAnonymousInput!) { authAnonymous(input: $input) { token } }",
        "extensions": {
            "clientLibrary": {
                "name": "apollo-kotlin",
                "version": "4.4.3",
            }
        },
    }

    async with httpx.AsyncClient() as client:
        try:
            token_resp = await client.post(token_url, json=payload_token, headers=headers, timeout=6.0, follow_redirects=False)

            token, reason = anonymous_token(token_resp)
            if token is None:
                return Result.error(reason, url=show_url)

            headers_validate = headers.copy()
            headers_validate["authorization"] = token
            headers_validate["x-apollo-operation"] = "ValidateEmail"
            headers_validate["x-emb-path"] = "/graphql/ValidateEmail"

            payload = {
                "operationName": "ValidateEmail",
                "variables": {"email": email},
                "query": "query ValidateEmail($email: String!) { auth { isEmailValid(email: $email) } }",
                "extensions": {
                    "clientLibrary": {
                        "name": "apollo-kotlin",
                        "version": "4.4.3",
                    }
                },
            }
            response = await client.post(validate_url, json=payload, headers=headers_validate,
                                         timeout=6.0, follow_redirects=False)
            status, _, reason = outcome(response, "okcupid", email)
            if status is Status.NOT_FOUND:
                return Result.available(url=show_url)
            return Result.error(reason, url=show_url)

        except Exception as e:
            return Result.error(e, url=show_url)


async def validate_okcupid(email: str) -> Result:
    """
    OkCupid dating app email validator.
    Fetches an anonymous token and checks the ValidateEmail GraphQL query.
    """
    return await _check(email)
