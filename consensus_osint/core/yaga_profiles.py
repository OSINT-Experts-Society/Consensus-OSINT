"""Retained regional Yaga shop parser with explicit Next.js schema boundaries."""
from __future__ import annotations


def shop_result(response, query):
    from consensus_osint.vendor.user_scanner.core.nextjs import parse_next_pages_data
    from consensus_osint.vendor.user_scanner.core.result import Result

    if response.status_code not in (200, 404):
        if response.status_code == 403 and "configured to block access from your country" in response.text:
            return Result.error("CloudFront blocks this country; shop availability is unknown")
        return Result.error(f"Unexpected shop response (HTTP {response.status_code})")
    if response.headers.get("cf-mitigated", "").lower() == "challenge":
        return Result.error("Shop lookup was challenged")
    data = parse_next_pages_data(response.text)
    if not isinstance(data, dict) or data.get("err") or data.get("error"):
        return Result.error("Could not read shop data")
    props = data.get("props")
    page = props.get("pageProps") if isinstance(props, dict) else None
    if (not isinstance(page, dict) or "initialShop" not in page or page.get("error")
            or page.get("statusCode") not in (None, 200, 404)
            or "__N_REDIRECT" in page or "__N_REDIRECT_STATUS" in page):
        return Result.error("Response lacks the expected shop schema or contains an error/redirect")
    shop = page["initialShop"]
    if shop is None:
        return Result.available()
    if (response.status_code != 200 or page.get("statusCode") == 404 or not isinstance(shop, dict)
            or not isinstance(shop.get("activeSlug"), str) or shop["activeSlug"] != query):
        return Result.error("Shop response does not match the requested slug")
    extra = {}
    ident = shop.get("id")
    if (type(ident) is int and ident > 0) or (isinstance(ident, str) and ident):
        extra["id"] = ident
    for key in ("name", "description"):
        if isinstance(shop.get(key), str) and shop[key]:
            extra[key] = shop[key]
    owner = shop.get("owner")
    if isinstance(owner, dict):
        for key, target in (("firstName", "owner_first_name"), ("lastName", "owner_last_name")):
            if isinstance(owner.get(key), str) and owner[key]:
                extra[target] = owner[key]
    return Result.taken(extra=extra)
