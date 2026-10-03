"""Offline phone-number parsing built on Google's libphonenumber port.

This layer always runs and needs no API key. It guarantees the tool is useful
out of the box: validity, formats, type, country, region, carrier and timezones.
"""

from __future__ import annotations

import phonenumbers
from phonenumbers import (
    NumberParseException,
    PhoneNumberType,
    carrier,
    geocoder,
)
from phonenumbers import (
    timezone as pn_timezone,
)

from .models import NumberType, ParsedNumber

_PN_TYPE_MAP: dict[int, NumberType] = {
    PhoneNumberType.MOBILE: NumberType.MOBILE,
    PhoneNumberType.FIXED_LINE: NumberType.FIXED_LINE,
    PhoneNumberType.FIXED_LINE_OR_MOBILE: NumberType.FIXED_OR_MOBILE,
    PhoneNumberType.VOIP: NumberType.VOIP,
    PhoneNumberType.TOLL_FREE: NumberType.TOLL_FREE,
    PhoneNumberType.PREMIUM_RATE: NumberType.PREMIUM_RATE,
    PhoneNumberType.SHARED_COST: NumberType.SHARED_COST,
    PhoneNumberType.PERSONAL_NUMBER: NumberType.PERSONAL,
    PhoneNumberType.PAGER: NumberType.PAGER,
    PhoneNumberType.UAN: NumberType.UAN,
    PhoneNumberType.VOICEMAIL: NumberType.VOICEMAIL,
}


class ParseError(ValueError):
    """Raised when a number cannot be parsed even loosely."""


def parse_number(raw: str, default_region: str | None = None) -> ParsedNumber:
    """Parse `raw` into a `ParsedNumber`.

    `default_region` (an ISO-3166 alpha-2 code) is used when the number is given
    in national form without a country code.
    """

    raw = raw.strip()
    if not raw:
        raise ParseError("Empty phone number.")

    # phonenumbers needs a leading '+' or a default region. If the user passed a
    # bare international number without '+', try to be forgiving.
    candidate = raw
    if default_region is None and not raw.startswith("+"):
        candidate = "+" + raw.lstrip("0")

    try:
        proto = phonenumbers.parse(candidate, default_region)
    except NumberParseException:
        try:
            proto = phonenumbers.parse(raw, default_region)
        except NumberParseException as exc:  # pragma: no cover - passthrough
            raise ParseError(f"Could not parse '{raw}': {exc}") from exc

    is_valid = phonenumbers.is_valid_number(proto)
    is_possible = phonenumbers.is_possible_number(proto)

    number_type = _PN_TYPE_MAP.get(
        phonenumbers.number_type(proto), NumberType.UNKNOWN
    )

    region_code = phonenumbers.region_code_for_number(proto)
    country_name = None
    if region_code:
        country_name = geocoder.country_name_for_number(proto, "en") or None

    region = geocoder.description_for_number(proto, "en") or None
    carrier_name = carrier.name_for_number(proto, "en") or None
    tzs = list(pn_timezone.time_zones_for_number(proto))

    return ParsedNumber(
        raw=raw,
        e164=phonenumbers.format_number(
            proto, phonenumbers.PhoneNumberFormat.E164
        ),
        national=phonenumbers.format_number(
            proto, phonenumbers.PhoneNumberFormat.NATIONAL
        ),
        international=phonenumbers.format_number(
            proto, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
        rfc3966=phonenumbers.format_number(
            proto, phonenumbers.PhoneNumberFormat.RFC3966
        ),
        country_code=proto.country_code,
        country_iso=region_code,
        country_name=country_name,
        region=region,
        is_valid=is_valid,
        is_possible=is_possible,
        number_type=number_type,
        carrier=carrier_name,
        timezones=tzs,
    )
