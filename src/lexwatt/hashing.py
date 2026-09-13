"""Domain-separated hashing and signing domains (spec §4.2).

D(label, x) = SHA256(UTF8(label) || 0x00 || J(x)) rendered lowercase hex.
"""

from __future__ import annotations

import hashlib

from . import jcs

D_CONFIG = "LEXWATT-CONFIG/1"
D_ACTION = "LEXWATT-ACTION/1"
D_EVENT = "LEXWATT-EVENT/1"
D_REQUEST = "LEXWATT-REQUEST/1"
SIGN_EVENT = "LEXWATT-SIGN/1"
SIGN_TOKEN = "LEXWATT-TOKEN/1"


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def d(label: str, value) -> str:
    return sha256_hex(label.encode("utf-8") + b"\x00" + jcs.dumps(value))


def event_hash(body) -> str:
    return d(D_EVENT, body)


def action_hash(action) -> str:
    return d(D_ACTION, action)


def config_hash(config) -> str:
    return d(D_CONFIG, config)


def request_digest(method: str, params) -> str:
    return d(D_REQUEST, {"method": method, "params": params})


def event_sign_message(event_hash_hex: str) -> bytes:
    return SIGN_EVENT.encode("utf-8") + b"\x00" + bytes.fromhex(event_hash_hex)


def token_sign_message(token_body) -> bytes:
    return SIGN_TOKEN.encode("utf-8") + b"\x00" + jcs.dumps(token_body)
