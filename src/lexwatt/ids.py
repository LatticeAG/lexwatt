"""Locked-prefix nanoid generation (spec §4.1).

Production IDs use a CSPRNG nanoid of 21 characters; tests inject a
deterministic generator.  Collision detection retries generation before any
durable write (the caller supplies ``exists``).
"""

from __future__ import annotations

import secrets

from .errors import LexwattError
from .scalars import ID_PREFIXES

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
SUFFIX_LEN = 21


class IdGenerator:
    """CSPRNG nanoid generator with collision retry."""

    def __init__(self, rng=None):
        self._rng = rng or secrets.SystemRandom()

    def suffix(self) -> str:
        return "".join(self._rng.choice(ALPHABET) for _ in range(SUFFIX_LEN))

    def new(self, kind: str, exists=None) -> str:
        prefix = ID_PREFIXES[kind]
        for _ in range(1000):
            candidate = f"{prefix}_{self.suffix()}"
            if exists is None or not exists(candidate):
                return candidate
        raise LexwattError("BUSY")


class DeterministicIds:
    """Counter-based generator for tests and conformance fixtures.

    Produces ``<prefix>_`` + a zero-padded 21-digit decimal counter, e.g.
    ``lwr_000000000000000000001``.
    """

    def __init__(self):
        self.counters: dict[str, int] = {}

    def new(self, kind: str, exists=None) -> str:
        prefix = ID_PREFIXES[kind]
        n = self.counters.get(prefix, 0) + 1
        while True:
            if n > 10**21 - 1:
                raise LexwattError("BUSY")
            candidate = f"{prefix}_{n:021d}"
            self.counters[prefix] = n
            n += 1
            if exists is None or not exists(candidate):
                return candidate
