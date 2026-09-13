"""CLI unit parsing (spec §3.1, §8.1).

--max-joules: ``[0-9]+`` with an optional decimal point and one through six
decimal digits; parsing is exact decimal scaling to microjoules.
--max-flops / U positions: canonical integer strings only.
"""

from __future__ import annotations

import re

from .errors import LexwattError
from .scalars import check_u, u_str

_JOULES_RE = re.compile(r"^([0-9]+)(?:\.([0-9]{1,6}))?$")


def parse_joules(text: str) -> int:
    """Parse a decimal joule string to an integer microjoule count."""
    if not isinstance(text, str):
        raise LexwattError("INVALID_INPUT")
    m = _JOULES_RE.match(text)
    if not m:
        raise LexwattError("INVALID_INPUT")
    whole, frac = m.group(1), m.group(2) or ""
    # canonical form: no leading zeros beyond a single zero
    if len(whole) > 1 and whole.startswith("0"):
        raise LexwattError("INVALID_INPUT")
    uj = int(whole) * 1_000_000 + int(frac.ljust(6, "0") or "0")
    if uj > (1 << 127) - 1:
        raise LexwattError("INVALID_INPUT")
    return uj


def parse_flops(text: str) -> int:
    """--max-flops accepts canonical U strings only (1e12, 1TF, leading
    zeros, fractional FLOPs are all errors)."""
    check_u(text)
    return int(text)


def parse_int_range(text: str, lo: int, hi: int, name: str) -> int:
    """Bounded JSON-integer flag: canonical digits, no sign."""
    if not isinstance(text, str) or not re.match(r"^(0|[1-9][0-9]*)$", text):
        raise LexwattError("INVALID_INPUT")
    v = int(text)
    if not (lo <= v <= hi):
        raise LexwattError("INVALID_INPUT")
    return v


def wall_ms_to_us(text: str) -> int:
    """--max-wall-ms is 1..86400000, converted to microseconds exactly."""
    ms = parse_int_range(text, 1, 86400000, "max-wall-ms")
    return ms * 1000


def format_u(v: int) -> str:
    return u_str(v)
