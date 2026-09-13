"""Offline receipt verification (spec §7.5): the fixed 8-step pipeline.

Verification proves signed local observations only;
``physical_truth`` is always ``NOT_ATTESTED``.
"""

from __future__ import annotations

from . import hashing, jcs, scalars
from .ed25519 import verify as ed_verify
from .errors import LexwattError
from .replay import replay_events
from .schema import check_bundle

ZERO_HASH = "0" * 64


def verify_bundle(bundle: dict, pins: list[dict], require_complete: bool) -> dict:
    # (1) frame, schema, and limits
    check_bundle(bundle)
    entries = bundle["entries"]
    for p in pins:
        scalars.check_id(p["key_id"], "key")
        scalars.check_public_key(p["public_key"])
    if len(pins) > 32:
        raise LexwattError("INVALID_INPUT")

    # (2) recompute every entry's body hash
    for e in entries:
        if hashing.event_hash(e["body"]) != e["hash"]:
            raise LexwattError("HASH_MISMATCH")

    # (3) resolve each entry's key_id against supplied pins
    keymap = {p["key_id"]: p["public_key"] for p in pins}
    for e in entries:
        if e["body"]["key_id"] not in keymap:
            raise LexwattError("UNTRUSTED_KEY")

    # (4) verify each signature
    for e in entries:
        pub = scalars.decode_public_key(keymap[e["body"]["key_id"]])
        sig = scalars.decode_signature(e["sig"])
        if not ed_verify(pub, hashing.event_sign_message(e["hash"]), sig):
            raise LexwattError("SIGNATURE_INVALID")

    # (5) genesis prev_hash, seq continuity, linkage, time, single run/key
    if entries:
        run_id = entries[0]["body"]["run_id"]
        key_id = entries[0]["body"]["key_id"]
        prev = ZERO_HASH
        last_t = -1
        for i, e in enumerate(entries):
            b = e["body"]
            if int(b["seq"]) != i + 1:
                raise LexwattError("CHAIN_INVALID")
            if b["prev_hash"] != prev:
                raise LexwattError("CHAIN_INVALID")
            if b["run_id"] != run_id or b["key_id"] != key_id:
                raise LexwattError("CHAIN_INVALID")
            t = int(b["t_us"])
            if t < last_t:
                raise LexwattError("CHAIN_INVALID")
            last_t = t
            prev = e["hash"]

    # (6) §5 transition legality incl. token/reservation lifecycle
    state = replay_events([e["body"] for e in entries]) if entries else "CREATED"

    # (7) expected_head equality when non-null
    head = (
        {"seq": entries[-1]["body"]["seq"], "hash": entries[-1]["hash"]}
        if entries
        else {"seq": "0", "hash": ZERO_HASH}
    )
    if bundle["expected_head"] is not None and bundle["expected_head"] != head:
        raise LexwattError("CHAIN_INVALID")

    # (8) completeness
    complete = bool(entries) and entries[-1]["body"]["kind"] in ("RunRejected", "RunFinalized")
    completeness = "COMPLETE" if complete else "PREFIX"
    if require_complete and not complete:
        raise LexwattError("INCOMPLETE")

    return {
        "integrity": "VALID",
        "completeness": completeness,
        "physical_truth": "NOT_ATTESTED",
        "head": head,
        "state": state,
    }
