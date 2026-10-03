"""Attribute BeautifulSoup replacement warnings to their concurrent check."""
from __future__ import annotations

import logging
from contextlib import contextmanager
from contextvars import ContextVar

_active: ContextVar[list[int] | None] = ContextVar("consensus_decode_warnings", default=None)


class _ReplacementFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        tally = _active.get()
        if tally is not None and record.getMessage().startswith("Some characters could not be decoded"):
            tally[0] += 1
            return False
        return True


_filter = _ReplacementFilter()


@contextmanager
def capture_decoding():
    # This filter is a no-op outside an active check. Contexts propagate through
    # asyncio.to_thread, so unrelated checks do not inherit each other's tally.
    logging.getLogger("bs4.dammit").addFilter(_filter)
    tally = [0]
    token = _active.set(tally)
    try:
        yield tally
    finally:
        _active.reset(token)
