"""Documented future-composition surfaces (spec §8.3, §16 P4).

Each adapter exposes the contract the named product will consume, and every
unshipped surface raises NotImplementedError with a link to the governing
spec section.  No fake working code: these are stub interfaces, not
functional implementations.
"""

from . import lexrapid, rollups, trellis

__all__ = ["lexrapid", "rollups", "trellis"]
