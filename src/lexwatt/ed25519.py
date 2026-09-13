"""Ed25519 signing via the ``cryptography`` package (audited provider).

Seeds are exactly 32 raw bytes; public keys are raw 32 bytes encoded as
canonical unpadded base64url on the wire.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import LexwattError
from .scalars import encode_b64url

SEED_LEN = 32


def generate_seed() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes_raw()


def public_key_from_seed(seed: bytes) -> bytes:
    if len(seed) != SEED_LEN:
        raise LexwattError("INVALID_INPUT")
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def public_key_b64_from_seed(seed: bytes) -> str:
    return encode_b64url(public_key_from_seed(seed))


def sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != SEED_LEN:
        raise LexwattError("INVALID_INPUT")
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def sign_b64(seed: bytes, message: bytes) -> str:
    return encode_b64url(sign(seed, message))


def verify(public_key_raw: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key_raw) != 32 or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except ValueError:
        return False
