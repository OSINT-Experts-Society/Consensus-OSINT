"""A shared check allowance for one scan, inherited by its async tasks.

A check is one site/module/provider invocation, not an HTTP request. Its
internal requests and retries finish normally. Local analysis is not charged.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar

DEFAULT_MAX_CHECKS = 30_000
STOP_REASON = "Scan budget reached; this check was not run. This is not a negative result."
_active = ContextVar("consensus_scan_budget", default=None)


class ScanBudget:
    def __init__(self, limit=DEFAULT_MAX_CHECKS):
        if type(limit) is not int or limit < 0:
            raise ValueError("max checks must be a non-negative integer (0 means unlimited)")
        self.state = dict(limit=limit, used=0, not_run_checks=0, deferred_queries=0, stopped=False)

    @property
    def exhausted(self):
        return bool(self.state["limit"] and self.state["used"] >= self.state["limit"])

    def admit(self):
        # No await between testing and charging: concurrent asyncio tasks share
        # this allowance without overshooting or consuming each other's scans.
        if self.exhausted:
            self.state["not_run_checks"] += 1
            self.state["stopped"] = True
            return False
        self.state["used"] += 1
        return True

    def defer(self, count):
        self.state["deferred_queries"] += count
        self.state["stopped"] = True

    @contextmanager
    def activate(self):
        token = _active.set(self)
        try:
            yield self
        finally:
            _active.reset(token)


def admit_check():
    budget = _active.get()
    return budget is None or budget.admit()


def budget_exhausted():
    budget = _active.get()
    return budget is not None and budget.exhausted


def budget_notice(options):
    state = options.get("scan_budget", {})
    if not isinstance(state, dict) or not state.get("stopped"):
        return ""
    return (f"Partial scan: the scan budget of {state.get('limit')} checks was reached. "
            "Collected results were kept; remaining checks or queries were not run. "
            "This is not evidence of account absence. Use --max-checks to adjust the limit (0 means unlimited).")
