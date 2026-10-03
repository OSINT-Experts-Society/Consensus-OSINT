"""Numint's Instagram entry, sharing Consensus's maintained Ignorant parser.

Original Numint port: MIT; the shared Ignorant implementation is GPL-3.0.
Offline parser checks do not establish live accuracy or notification behaviour.
Consensus policy continues to hold this adapter pending provider evidence.
"""
from consensus_osint.vendor.ignorant.modules.social_media.instagram import instagram

from ._ignorant import run_ignorant
from .base import PresenceCheck, register_presence


@register_presence
class InstagramPresence(PresenceCheck):
    site = "instagram"
    method = "lookup"
    non_notifying = True  # Original metadata; Consensus enforces its reviewed policy.

    async def _check(self, number, client):
        return await run_ignorant(instagram, number, client, site=self.site, method=self.method)
