"""Consensus response guards shared by retained Ignorant/Numint phone checks.

These guards validate local contracts, not current provider reliability.
No response body or queried identifier is included in failure diagnostics.
"""
import phonenumbers


def phone_result(name, domain, method):
    return {"name": name, "domain": domain, "method": method,
            "frequent_rate_limit": False, "rateLimit": False, "exists": None,
            "unknown": True, "reason": "Unrecognised phone lookup response."}


def set_exists(result, exists):
    result.update(exists=exists, unknown=False)
    result.pop("reason", None)


def read_response(response, result, *, html=False):
    """Require HTTP 200 before reading provider evidence or prerequisites."""
    code = response.status_code
    result["http_status"] = code
    if code == 429:
        result.update(rateLimit=True, reason="HTTP 429: provider rate limit.")
        return None
    if code in {401, 403, 406, 407, 418, 451}:
        result.update(blocked=True, reason=f"HTTP {code}: provider access blocked.")
        return None
    if code != 200:
        result["reason"] = f"HTTP {code}: no usable phone lookup response."
        return None
    if response.headers.get("cf-mitigated", "").lower() == "challenge":
        result.update(blocked=True, reason="Provider challenge; account status is unknown.")
        return None
    if html:
        from bs4 import BeautifulSoup

        page = BeautifulSoup(response.text, "html.parser")
        if (page.select_one('#captchacharacters, input[name="cvf_captcha_input"], input[name="guess"]')
                or "robot check" in page.get_text(" ", strip=True).lower()):
            result.update(blocked=True, reason="Provider CAPTCHA; account status is unknown.")
            return None
        return page
    try:
        payload = response.json()
    except ValueError:
        result["reason"] = "Malformed JSON; account status is unknown."
        return None
    if not isinstance(payload, dict):
        result["reason"] = "Expected a JSON object; account status is unknown."
        return None
    return payload


def has_service_error(payload):
    """An explicit service error must take precedence over a lookup marker."""
    return any(key in payload and payload[key] is not None and payload[key] is not False
               and payload[key] != "" for key in
               ("error", "errors", "error_type", "error_message", "error_title", "challenge", "checkpoint_url"))


def phone_parts(phone, country_code):
    """Resolve a valid full number; preserve significant zeros and shared codes."""
    raw = str(country_code) + str(phone)
    if not raw.isascii() or not raw.isdigit():
        return None
    try:
        number = phonenumbers.parse("+" + raw, None)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_valid_number(number):
        return None
    return number
