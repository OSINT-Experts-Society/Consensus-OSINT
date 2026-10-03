"""Adapters exposing vendored upstream module families through :mod:`consensus_osint.core.modules`.

Each adapter module provides ``load_modules() -> list[Module]``; the registry in
``core.modules.ADAPTERS`` maps a family name to that function.
"""
