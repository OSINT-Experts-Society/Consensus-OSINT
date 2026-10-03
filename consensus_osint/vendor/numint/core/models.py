"""Shared data models for Numint - trimmed for Consensus.

Upstream (https://github.com/whoamitang/numint, ``src/numint/core/models.py``,
commit 9186c35, 2026-07-18) defines these as pydantic ``BaseModel`` classes and
also carries the ``Profile`` / ``ProviderResult`` / ``FootprintGroup`` ...
models that the presence checks never touch.  Consensus does not depend on
pydantic, so the models the presence layer needs - ``ParsedNumber`` (returned
by ``core/parser.py`` and handed to every check), ``PresenceResult`` (returned
by every check) and the ``NumberType`` enum ``ParsedNumber`` references - are
re-implemented here as plain dataclasses with identical field names, defaults
and docstrings.  Nothing else from the upstream file is kept.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class NumberType(str, Enum):
    """Normalized line/number type across providers and libphonenumber."""

    MOBILE = "mobile"
    FIXED_LINE = "fixed_line"
    FIXED_OR_MOBILE = "fixed_or_mobile"
    VOIP = "voip"
    TOLL_FREE = "toll_free"
    PREMIUM_RATE = "premium_rate"
    SHARED_COST = "shared_cost"
    PERSONAL = "personal"
    PAGER = "pager"
    UAN = "uan"
    VOICEMAIL = "voicemail"
    UNKNOWN = "unknown"


@dataclass
class ParsedNumber:
    """Result of offline parsing with `phonenumbers`. Passed to every provider."""

    raw: str
    e164: str
    national: str
    international: str
    rfc3966: str
    country_code: int
    country_iso: str | None = None
    country_name: str | None = None
    region: str | None = None
    is_valid: bool = False
    is_possible: bool = False
    number_type: NumberType = NumberType.UNKNOWN
    carrier: str | None = None
    timezones: list[str] = field(default_factory=list)

    @property
    def digits(self) -> str:
        """E.164 without the leading '+', useful for URL templates."""
        return self.e164.lstrip("+")

    def model_dump(self) -> dict:
        """pydantic-compatible spelling kept for callers ported from upstream."""
        return asdict(self)


@dataclass
class PresenceResult:
    """Account-presence check for one site.

    Answers "is this number registered here?" by reading a site's own
    signup/reset/lookup response - never by logging in. `registered` is a
    coarse signal; `masked_*` capture any partial identifier the site leaks
    (e.g. `j**@gm***.com`) so an investigator can pivot.
    """

    site: str
    registered: str = "unknown"  # yes | no | unknown | rate_limited | error
    masked_email: str | None = None
    masked_phone: str | None = None
    hint: str | None = None  # username / display-name fragment
    method: str = "lookup"  # lookup | reset | signup - audit trail
    elapsed_ms: int | None = None
    error: str | None = None

    def model_dump(self) -> dict:
        """pydantic-compatible spelling kept for callers ported from upstream."""
        return asdict(self)
