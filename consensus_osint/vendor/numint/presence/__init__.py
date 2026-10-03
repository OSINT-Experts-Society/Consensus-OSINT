"""Account-presence layer - "where is this number registered?".

Each site is one self-registering file (same ergonomics as `providers/`).
A check reads a site's own signup / password-reset / lookup response to decide
whether an identifier is registered, and captures any masked identifier the
site leaks. It NEVER logs in and - by policy for the bundled checks - only uses
endpoints that do not send an SMS/email to the target.

AUTHORIZED USE ONLY. This actively probes third-party services. Run it only
against numbers you are authorized to investigate.
"""

from .base import PresenceCheck, discover_presence, register_presence

__all__ = ["PresenceCheck", "discover_presence", "register_presence"]
