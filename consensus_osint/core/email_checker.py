"""Compatibility names for the e-mail rules, now served by :mod:`consensus_osint.core.rules`.

The data-driven e-mail checks used to be a family of their own; they are the
``kind: "email"`` rules of ``rules.json`` today and run through the same engine as
the username and phone rules.  Nothing here has behaviour of its own.
"""
from __future__ import annotations

from .rules import _evaluate, check_rule, load_rules  # noqa: F401  (public compatibility exports)


def load_email_sites(path: str | None = None) -> list[dict]:
    return load_rules(path, kind="email")


check_email_site = check_rule

__all__ = ["load_email_sites", "check_email_site"]
