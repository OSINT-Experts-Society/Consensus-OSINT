import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    url = "https://www.etsy.com/api/v3/ajax/public/users/by-identity-optional"
    show_url = "https://www.etsy.com"

    params = {"identity": email}

    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "identity",
        "x-detected-locale": "INR|en-IN|IN",
        "sec-ch-ua-platform": '"Android"',
        "sec-ch-ua": '"Brave";v="147", "Not.A/Brand";v="8", "Chromium";v="147"',
        "sec-ch-ua-mobile": "?1",
        "Content-Type": "application/json",
        "Referer": "https://www.etsy.com/join/email",
        "Priority": "u=1, i",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, params=params, headers=headers, follow_redirects=False)

            issue, reason = http_issue(response.status_code, response.headers, response.text)
            if issue is not None:
                return Result.error(reason, url=show_url)
            data = json.loads(response.text, object_pairs_hook=_unique_object)
            if data is None:
                return Result.available(url=show_url)
            if not isinstance(data, dict) or has_service_error(data):
                return Result.error("Invalid or failed Etsy identity lookup", url=show_url)
            if any(
                key in data and (not isinstance(data[key], str) or data[key].casefold() != email.casefold())
                for key in ("email", "identity")
            ):
                return Result.error("Etsy response belongs to a different identity", url=show_url)
            user_id = data.get("user_id")
            if not (
                type(user_id) is int
                and user_id > 0
                or isinstance(user_id, str)
                and user_id.isascii()
                and user_id.isdigit()
                and int(user_id) > 0
            ):
                return Result.error("Missing valid Etsy user id", url=show_url)
            extras = {"id": user_id}
            for source, target in (
                ("display_name", "name"),
                ("real_name", "name"),
                ("login_name", "username"),
                ("gender", "gender"),
                ("location", "location"),
                ("bio", "bio"),
            ):
                value = data.get(source)
                if isinstance(value, str) and value.strip():
                    extras[target] = value.strip()
            for source, target in (("is_seller", "is seller"), ("has_page", "has public page")):
                if type(data.get(source)) is bool:
                    extras[target] = "Yes" if data[source] else "No"
            stats = []
            for source, label in (
                ("follower_count", "followers"),
                ("following_count", "following"),
                ("num_favorites", "favorites"),
            ):
                if type(data.get(source)) is int and data[source] >= 0:
                    stats.append(f"{data[source]} {label}")
            if stats:
                extras["stats"] = " | ".join(stats)
            privacy = []
            for source, label in (("favorite_items_public", "Items"), ("favorite_shops_public", "Shops")):
                if type(data.get(source)) is bool:
                    privacy.append(label + " are " + ("Public" if data[source] else "Private"))
            if privacy:
                extras["privacy"] = " | ".join(privacy)
            for source, target in (("create_date", "joined"), ("update_date", "last profile update")):
                value = data.get(source)
                if type(value) in (int, float) and 0 < value < 253402300800:
                    try:
                        extras[target] = datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    except (ValueError, OverflowError, OSError):
                        pass
            media = {}
            avatar = data.get("avatar")
            candidates = [avatar.get("url") if isinstance(avatar, dict) else None, data.get("avatar_url")]
            for candidate in candidates:
                if not isinstance(candidate, str) or any(ord(c) <= 32 or ord(c) == 127 for c in candidate):
                    continue
                try:
                    parsed = urlsplit(candidate)
                    host = parsed.hostname or ""
                    if (
                        parsed.scheme == "https"
                        and (host == "etsystatic.com" or host.endswith(".etsystatic.com"))
                        and not parsed.username
                        and not parsed.password
                    ):
                        media["avatar"] = candidate
                        break
                except ValueError:
                    continue
            return Result.taken(url=show_url, extra=extras, media=media)

    except Exception as e:
        return Result.error(e)


async def validate_etsy(email: str) -> Result:
    return await _check(email)
