"""Public error/event redaction (spec §6, §12, §13).

Errors carry only {code, retryable}; argv, env values, token strings,
signatures, and HTTP bodies never appear in errors, diagnostics, or public
events.
"""

from __future__ import annotations

from .errors import LexwattError


def public_error(err: LexwattError) -> dict:
    return {"code": err.code, "retryable": err.retryable}


def diagnostic(code: str, run_id: str | None = None, seq: str | None = None, component: str = "supervisor") -> dict:
    """Diagnostics contain code, run ID, event sequence, and component only."""
    return {
        "code": code,
        "run_id": run_id,
        "seq": seq,
        "component": component,
    }


def exec_public_fields(execv: dict) -> list[str]:
    """Fields of an Exec that may ever appear in public output: none beyond
    its existence.  (argv/env are private.)"""
    return []
