"""Numint's Amazon entry, sharing Consensus's maintained Ignorant parser.

Original Numint port: MIT; the shared Ignorant implementation is GPL-3.0.
Offline parser checks do not establish live accuracy or notification behaviour.
Consensus policy continues to hold this adapter pending provider evidence.
"""
from consensus_osint.vendor.ignorant.modules.shopping.amazon import amazon

from ._ignorant import run_ignorant
from .base import PresenceCheck, register_presence


@register_presence
class AmazonPresence(PresenceCheck):
    site = "amazon"
    method = "login"
    non_notifying = False  # A phone sign-in may deliver an OTP.

    async def _check(self, number, client):
        return await run_ignorant(amazon, number, client, site=self.site, method=self.method)
