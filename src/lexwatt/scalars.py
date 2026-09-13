"""Scalar validators and 127-bit unsigned resource arithmetic (spec §4.1).

U is a base-10 nonnegative integer string bounded by 2^127-1 after every
arithmetic operation.  A U literal that parses but exceeds the bound is
INVALID_INPUT; an arithmetic result that exceeds it is OVERFLOW.
"""

from __future__ import annotations

import base64
import binascii
import re

from .errors import LexwattError

U_MAX = (1 << 127) - 1  # 170141183460469231731687303715884105727

_U_RE = re.compile(r"^(0|[1-9][0-9]{0,38})$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_CHARS = re.compile(r"^[A-Za-z0-9_-]{21}$")
_MODEL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_ENV_KEY_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

ID_PREFIXES = {
    "run": "lwr",
    "event": "lwe",
    "request": "lwq",
    "token": "lwt",
    "action": "lwa",
    "compute": "lwc",
    "channel": "lwp",
    "key": "lwk",
}


def check_u(value) -> str:
    """Validate the lexical form of a U; returns the canonical string."""
    if not isinstance(value, str) or not _U_RE.match(value):
        raise LexwattError("INVALID_INPUT")
    v = int(value)
    if v > U_MAX:
        raise LexwattError("INVALID_INPUT")
    return value


def parse_u(value) -> int:
    """Parse a U to int after validation."""
    return int(check_u(value))


def u_str(v: int) -> str:
    if not isinstance(v, int) or v < 0 or v > U_MAX:
        raise LexwattError("OVERFLOW")
    return str(v)


def u_add(a: int, b: int) -> int:
    r = a + b
    if r > U_MAX:
        raise LexwattError("OVERFLOW")
    return r


def u_mul(a: int, b: int) -> int:
    r = a * b
    if r > U_MAX:
        raise LexwattError("OVERFLOW")
    return r


def u_sub(a: int, b: int) -> int:
    r = a - b
    if r < 0:
        raise LexwattError("OVERFLOW")
    return r


def check_hash(value) -> str:
    if not isinstance(value, str) or not _HASH_RE.match(value):
        raise LexwattError("INVALID_INPUT")
    return value


def _b64url_decode_exact(value: str, size: int) -> bytes:
    if not isinstance(value, str) or not _B64URL_RE.match(value):
        raise LexwattError("INVALID_INPUT")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        raise LexwattError("INVALID_INPUT")
    if len(raw) != size:
        raise LexwattError("INVALID_INPUT")
    # canonical re-encoding must match (rejects padded/noncanonical forms)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise LexwattError("INVALID_INPUT")
    return raw


def check_signature(value) -> str:
    _b64url_decode_exact(value, 64)
    return value


def decode_signature(value: str) -> bytes:
    check_signature(value)
    return _b64url_decode_exact(value, 64)


def check_public_key(value) -> str:
    _b64url_decode_exact(value, 32)
    return value


def decode_public_key(value: str) -> bytes:
    check_public_key(value)
    return _b64url_decode_exact(value, 32)


def encode_b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def check_id(value, kind: str | None = None) -> str:
    """Locked-prefix ID: ``<prefix>_`` + 21 chars from A-Za-z0-9_-."""
    if not isinstance(value, str):
        raise LexwattError("INVALID_INPUT")
    if kind is not None:
        prefix = ID_PREFIXES[kind] + "_"
        if not value.startswith(prefix):
            raise LexwattError("INVALID_INPUT")
        suffix = value[len(prefix) :]
        if not _ID_CHARS.match(suffix):
            raise LexwattError("INVALID_INPUT")
        return value
    # generic form: any locked prefix + 21-char suffix
    for p in ID_PREFIXES.values():
        if value.startswith(p + "_"):
            if _ID_CHARS.match(value[len(p) + 1 :]):
                return value
            raise LexwattError("INVALID_INPUT")
    raise LexwattError("INVALID_INPUT")


def check_model_name(value) -> str:
    if not isinstance(value, str) or not _MODEL_NAME_RE.match(value):
        raise LexwattError("INVALID_INPUT")
    return value


def check_path(value) -> str:
    """Absolute UTF-8 path, <=4096 bytes, no NUL."""
    if not isinstance(value, str) or not value.startswith("/"):
        raise LexwattError("INVALID_INPUT")
    if "\x00" in value or len(value.encode("utf-8")) > 4096:
        raise LexwattError("INVALID_INPUT")
    return value


def check_text(value, max_bytes: int = 4096) -> str:
    """Unicode scalar string, no NUL, bounded UTF-8 length."""
    if not isinstance(value, str) or "\x00" in value:
        raise LexwattError("INVALID_INPUT")
    for ch in value:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise LexwattError("INVALID_INPUT")
    if len(value.encode("utf-8")) > max_bytes:
        raise LexwattError("INVALID_INPUT")
    return value


def check_env_key(value) -> str:
    if not isinstance(value, str) or not _ENV_KEY_RE.match(value):
        raise LexwattError("INVALID_INPUT")
    return value


def check_body_b64(value) -> str:
    """body_b64: canonical unpadded base64url of at most 262144 raw bytes."""
    if value == "":
        return value
    if not isinstance(value, str) or not _B64URL_RE.match(value):
        raise LexwattError("INVALID_INPUT")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        raise LexwattError("INVALID_INPUT")
    if len(raw) > 262144:
        raise LexwattError("INVALID_INPUT")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise LexwattError("INVALID_INPUT")
    return value
