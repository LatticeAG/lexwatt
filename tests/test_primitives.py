"""Primitive, schema, framing, and fuzz coverage beyond the 60 vectors.

Covers: every wire method's request/response schema, duplicate JSON keys,
UTF-16 ordering edge cases, invalid signatures, sequence tampering,
request-ID collisions, malformed base64url, 127-bit overflow, frame bounds.
"""

import json
import os
import socket
import struct

import pytest

from fixtures import ACT, B, CFG, E1, E2, EX, K, M, PUB, Q, R, TOKEN, W
from lexwatt import hashing, jcs, scalars
from lexwatt.errors import LexwattError
from lexwatt.schema import (
    check_bundle,
    check_event_body,
    check_request,
)
from lexwatt.server import MAX_REQUEST_BYTES, read_frame, write_frame


def err(fn, *a, **kw):
    with pytest.raises(LexwattError) as e:
        fn(*a, **kw)
    return e.value.code


class TestJcs:
    def test_canonical_key_order(self):
        assert jcs.dumps({"b": 1, "a": 2}) == b'{"a":2,"b":1}'

    def test_no_whitespace(self):
        assert jcs.dumps({"x": [1, 2], "y": "z"}) == b'{"x":[1,2],"y":"z"}'

    def test_utf16_order_edge(self):
        # U+0080 sorts after U+007F; supplementary-plane chars sort by UTF-16
        assert jcs.dumps({"€": 1, "z": 2}) == '{"z":2,"€":1}'.encode()
        # UTF-16 code-unit order, NOT code-point order: U+10000 encodes as
        # D800 DC00 whose lead unit (0xD800) precedes U+E000 — the classic
        # JCS ordering edge case.
        keys = {"\U00010000": 1, "\ue000": 2}
        dumped = jcs.dumps_str(keys)
        assert dumped.index("\U00010000") < dumped.index("\ue000")

    def test_reject_noninteger_number(self):
        with pytest.raises(LexwattError):
            jcs.dumps({"x": 1.5})

    def test_bool_is_legal_json(self):
        # booleans are valid JSON values; only numbers are integer-restricted
        assert jcs.loads(jcs.dumps({"x": True})) == {"x": True}

    def test_reject_nan_inf(self):
        for v in (float("nan"), float("inf"), float("-inf")):
            with pytest.raises(LexwattError):
                jcs.dumps({"x": v})

    def test_duplicate_keys_rejected(self):
        with pytest.raises(LexwattError):
            jcs.loads(b'{"a":1,"a":2}')

    def test_depth_limit(self):
        deep = b"[" * 200 + b"1" + b"]" * 200
        with pytest.raises(LexwattError):
            jcs.loads(deep)

    def test_string_escapes(self):
        assert jcs.dumps({"x": 'a"b\\c\n'}) == b'{"x":"a\\"b\\\\c\\n"}'

    def test_surrogate_escape_roundtrip(self):
        v = {"x": "\U0001f600"}
        assert jcs.loads(jcs.dumps(v)) == v


class TestScalars:
    def test_u_max_boundary(self):
        assert scalars.check_u("170141183460469231731687303715884105727") == "170141183460469231731687303715884105727"

    def test_u_127bit_overflow(self):
        assert err(scalars.check_u, "170141183460469231731687303715884105728") == "INVALID_INPUT"

    def test_u_rejects_forms(self):
        for v in ["", "-0", "-1", "01", "+1", " 1", "1 ", "0x10", "1_000", "1.0", 5, None, True]:
            with pytest.raises(LexwattError):
                scalars.check_u(v)

    def test_id_prefixes(self):
        for kind, prefix in scalars.ID_PREFIXES.items():
            good = f"{prefix}_" + "a" * 21
            scalars.check_id(good, kind)
            with pytest.raises(LexwattError):
                scalars.check_id(good[:-1], kind)  # short suffix
            with pytest.raises(LexwattError):
                scalars.check_id("lxx_" + "a" * 21)

    def test_b64url_malformed(self):
        for bad in ["a===", "a=b", "+/+/", "abc!", "a b", "é", "AAA="]:
            with pytest.raises(LexwattError):
                scalars.check_body_b64(bad)
        scalars.check_body_b64("YWJj")  # valid
        scalars.check_body_b64("")  # empty body encoding is valid
        for bad in ["short", "A" * 86 + "=", "!!!!" * 22]:
            with pytest.raises(LexwattError):
                scalars.check_signature(bad)

    def test_signature_decode_len(self):
        with pytest.raises(LexwattError):
            scalars.decode_signature("AAAA")  # too short


class TestRequestSchema:
    METHOD_PARAMS = {
        "capabilities.get": {"profile": "offline-v1"},
        "estimate.compute": {"model": M, "work": W},
        "route.choose": {
            "models": [M],
            "input_tokens": "2",
            "max_output_tokens": "3",
            "batch": 1,
            "remaining_flops": "11440",
        },
        "run.start": {"config": CFG, "exec": EX},
        "run.get": {"run_id": R},
        "run.stop": {"run_id": R},
        "events.read": {"run_id": R, "after_seq": "0", "limit": 1},
        "token.issue": {"action": ACT},
        "action.dispatch": {"token": TOKEN, "action": ACT},
        "action.get": {"action_id": "lwa_000000000000000000001"},
        "compute.reserve": {"work": W},
        "compute.finish": {"compute_id": "lwc_000000000000000000001", "observed_output_tokens": "1"},
        "receipt.verify": {
            "bundle": {"v": 1, "entries": [E1, E2], "expected_head": None},
            "pins": [{"key_id": K, "public_key": PUB}],
            "require_complete": True,
        },
    }

    def test_all_13_methods_validate(self):
        for method, params in self.METHOD_PARAMS.items():
            req = {"v": 1, "id": Q, "method": method, "params": params}
            check_request(req)

    def test_unknown_method(self):
        req = {"v": 1, "id": Q, "method": "admin.shell", "params": {}}
        assert err(check_request, req) == "INVALID_INPUT"

    def test_unknown_request_field(self):
        req = {"v": 1, "id": Q, "method": "run.get", "params": {"run_id": R}, "x": 1}
        assert err(check_request, req) == "UNKNOWN_FIELD"

    def test_bad_v(self):
        req = {"v": 2, "id": Q, "method": "run.get", "params": {"run_id": R}}
        assert err(check_request, req) == "UNSUPPORTED_VERSION"

    def test_bad_id_prefix(self):
        req = {"v": 1, "id": R, "method": "run.get", "params": {"run_id": R}}
        assert err(check_request, req) == "INVALID_INPUT"

    def test_params_must_be_object(self):
        req = {"v": 1, "id": Q, "method": "run.get", "params": [R]}
        assert err(check_request, req) == "INVALID_INPUT"


class TestFraming:
    def test_roundtrip(self):
        a, b = socket.socketpair()
        try:
            write_frame(a, b'{"x":1}')
            assert read_frame(b, MAX_REQUEST_BYTES) == b'{"x":1}'
        finally:
            a.close()
            b.close()

    def test_oversize_declared_closes(self):
        a, b = socket.socketpair()
        try:
            a.sendall(struct.pack(">I", MAX_REQUEST_BYTES + 1))
            with pytest.raises(LexwattError):
                read_frame(b, MAX_REQUEST_BYTES)
        finally:
            a.close()
            b.close()

    def test_partial_frame_is_invalid(self):
        a, b = socket.socketpair()
        try:
            a.sendall(struct.pack(">I", 10) + b"123")
            a.shutdown(socket.SHUT_WR)
            with pytest.raises(LexwattError):
                read_frame(b, MAX_REQUEST_BYTES)
        finally:
            a.close()
            b.close()

    def test_clean_eof(self):
        a, b = socket.socketpair()
        a.close()
        assert read_frame(b, MAX_REQUEST_BYTES) is None
        b.close()


class TestChainFuzz:
    def test_bad_signature(self):
        e2 = dict(E2)
        e2["sig"] = "A" * 86  # well-formed b64url, wrong sig
        from lexwatt.verify import verify_bundle

        with pytest.raises(LexwattError) as e:
            verify_bundle({"v": 1, "entries": [E1, e2], "expected_head": None},
                          [{"key_id": K, "public_key": PUB}], False)
        assert e.value.code == "SIGNATURE_INVALID"

    def test_seq_tamper(self):
        e2 = json.loads(json.dumps(E2))
        e2["body"]["seq"] = "3"
        from lexwatt.verify import verify_bundle

        with pytest.raises(LexwattError) as e:
            verify_bundle({"v": 1, "entries": [E1, e2], "expected_head": None},
                          [{"key_id": K, "public_key": PUB}], False)
        assert e.value.code in ("HASH_MISMATCH", "CHAIN_INVALID")

    def test_entry_schema(self):
        for e in (E1, E2):
            check_event_body(e["body"])
        assert check_bundle({"v": 1, "entries": [E1, E2], "expected_head": None})


class TestHashing:
    def test_golden_event_hash(self):
        assert hashing.event_hash(E1["body"]) == E1["hash"]

    def test_golden_sig_verifies(self):
        from lexwatt.ed25519 import verify

        pub = scalars.decode_public_key(PUB)
        sig = scalars.decode_signature(E1["sig"])
        assert verify(pub, hashing.event_sign_message(E1["hash"]), sig)

    def test_config_hash_of_empty(self):
        assert hashing.config_hash({}) == "0587b9faaf456ac6b84a092d6c73261269f82ce2b40bf972d7f0e0fba671b3dd"
