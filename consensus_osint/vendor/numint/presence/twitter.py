"""Twitter / X presence check.

Uses X's public phone-availability endpoint, the same one the signup screen
calls to tell you whether a number can be used for a new account. If the number
is already tied to an account it comes back as "taken". No SMS is sent to the
target.

Same family of technique as ignorant: read a site's own signup/availability
response, never log in. Endpoints drift, so anything unrecognized degrades to
`unknown` instead of guessing.
"""

from __future__ import annotations

import httpx

from ..core.models import PresenceResult
from .base import CHROME_UAS, PresenceCheck, register_presence

_URL = "https://api.twitter.com/i/users/phone_available.json"


@register_presence
class TwitterPresence(PresenceCheck):
    site = "twitter/x"
    method = "signup"
    non_notifying = True

    async def _check(
        self, number, client: httpx.AsyncClient
    ) -> PresenceResult:
        headers = {"User-Agent": CHROME_UAS[0], "Accept": "application/json"}
        try:
            r = await client.get(
                _URL, params={"phone": number.e164}, headers=headers
            )
            body = r.json()
        except Exception:
            return PresenceResult(
                site=self.site, registered="rate_limited", method=self.method
            )

        taken = body.get("taken")
        if taken is True:
            return PresenceResult(
                site=self.site, registered="yes", method=self.method
            )
        if taken is False:
            return PresenceResult(
                site=self.site, registered="no", method=self.method
            )
        return PresenceResult(
            site=self.site, registered="unknown", method=self.method
        )
