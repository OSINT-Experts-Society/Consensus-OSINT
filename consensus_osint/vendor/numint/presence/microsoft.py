"""Microsoft account presence check.

Calls the same `GetCredentialType` endpoint the Microsoft sign-in page uses to
decide whether a username exists before asking for a password. It works for
accounts whose username is a phone number. Nothing is sent to the target.

Same idea as the other checks: read the site's own sign-in response, never log
in. Degrades to `unknown` on anything unexpected.
"""

from __future__ import annotations

import httpx

from ..core.models import PresenceResult
from .base import CHROME_UAS, PresenceCheck, register_presence

_LOGIN = "https://login.live.com/"
_GCT = "https://login.live.com/GetCredentialType.srf"


@register_presence
class MicrosoftPresence(PresenceCheck):
    site = "microsoft"
    method = "login"
    non_notifying = True

    async def _check(
        self, number, client: httpx.AsyncClient
    ) -> PresenceResult:
        ua = CHROME_UAS[0]
        try:
            # Prime cookies the endpoint expects.
            await client.get(_LOGIN, headers={"User-Agent": ua})
            resp = await client.post(
                _GCT,
                headers={
                    "User-Agent": ua,
                    "Accept": "application/json",
                    "Content-Type": "application/json; charset=UTF-8",
                },
                json={
                    "username": number.e164,
                    "isOtherIdpSupported": True,
                    "checkPhones": True,
                    "isRemoteNGCSupported": True,
                    "isCookieBannerShown": False,
                    "isFidoSupported": True,
                },
            )
            result = resp.json().get("IfExistsResult")
        except Exception:
            return PresenceResult(
                site=self.site, registered="rate_limited", method=self.method
            )

        # 0 = exists, 5/6 = exists via another identity provider, 1 = not found.
        if result in (0, 5, 6):
            return PresenceResult(
                site=self.site, registered="yes", method=self.method
            )
        if result == 1:
            return PresenceResult(
                site=self.site, registered="no", method=self.method
            )
        return PresenceResult(
            site=self.site, registered="unknown", method=self.method
        )
