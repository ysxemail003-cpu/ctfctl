from __future__ import annotations


class CTFError(RuntimeError):
    """Base error for user-facing ctfctl failures."""


class StateError(CTFError):
    """Raised when challenge state is invalid or missing."""


class ScopeError(CTFError):
    """Raised when an action is outside the authorized target scope."""


class FlagError(CTFError):
    """Raised when a flag candidate cannot be validated."""
