import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyBundle } from "../src/verify.ts";
import { LexwattError } from "../src/errors.ts";
import { eventHash, eventSignMessage } from "../src/hashing.ts";
import { sign } from "../src/ed25519.ts";
import { E1, E2, K, PUB, R, SEED, Z } from "./fixtures.ts";

const PINS = [{ key_id: K, public_key: PUB }];

function bundle(entries: any[], head: any = null) {
  return { v: 1, run_id: R, entries, expected_head: head };
}

function makeEvent(body: any) {
  const hash = eventHash(body);
  const sig = Buffer.from(sign(new Uint8Array(SEED), eventSignMessage(hash))).toString("base64url");
  return { body, hash, sig };
}

test("golden E1+E2 bundle verifies VALID/COMPLETE/REJECTED", () => {
  const r = verifyBundle(bundle([E1, E2]), PINS, true);
  assert.equal(r.integrity, "VALID");
  assert.equal(r.completeness, "COMPLETE");
  assert.equal(r.physical_truth, "NOT_ATTESTED");
  assert.equal(r.state, "REJECTED");
  assert.equal(r.head.seq, "2");
  assert.equal(r.head.hash, E2.hash);
});

test("prefix without terminal event is PREFIX; require_complete raises INCOMPLETE", () => {
  const r = verifyBundle(bundle([E1]), PINS, false);
  assert.equal(r.completeness, "PREFIX");
  assert.equal(r.state, "CREATED");
  assert.throws(
    () => verifyBundle(bundle([E1]), PINS, true),
    (e) => e instanceof LexwattError && e.code === "INCOMPLETE",
  );
});

test("tampered hash -> HASH_MISMATCH", () => {
  const bad = { ...E1, hash: "f".repeat(64) };
  assert.throws(
    () => verifyBundle(bundle([bad]), PINS, false),
    (e) => e instanceof LexwattError && e.code === "HASH_MISMATCH",
  );
});

test("unpinned key -> UNTRUSTED_KEY", () => {
  assert.throws(
    () => verifyBundle(bundle([E1]), [{ key_id: "lwk_000000000000000000099", public_key: PUB }], false),
    (e) => e instanceof LexwattError && e.code === "UNTRUSTED_KEY",
  );
});

test("bad signature -> SIGNATURE_INVALID", () => {
  const bad = { ...E1, sig: E2.sig };
  assert.throws(
    () => verifyBundle(bundle([bad]), PINS, false),
    (e) => e instanceof LexwattError && e.code === "SIGNATURE_INVALID",
  );
});

test("chain linkage violation -> CHAIN_INVALID", () => {
  const e2 = makeEvent({
    ...E2.body,
    prev_hash: "1".repeat(64), // wrong prev
  });
  assert.throws(
    () => verifyBundle(bundle([E1, e2]), PINS, false),
    (e) => e instanceof LexwattError && e.code === "CHAIN_INVALID",
  );
});

test("seq gap -> CHAIN_INVALID", () => {
  const e2 = makeEvent({ ...E2.body, seq: "3" });
  assert.throws(
    () => verifyBundle(bundle([E1, e2]), PINS, false),
    (e) => e instanceof LexwattError && e.code === "CHAIN_INVALID",
  );
});

test("expected_head mismatch -> CHAIN_INVALID; match passes", () => {
  const wrong = bundle([E1, E2], { seq: "2", hash: Z });
  assert.throws(
    () => verifyBundle(wrong, PINS, false),
    (e) => e instanceof LexwattError && e.code === "CHAIN_INVALID",
  );
  const right = bundle([E1, E2], { seq: "2", hash: E2.hash });
  assert.equal(verifyBundle(right, PINS, false).integrity, "VALID");
});

test("illegal transition -> TRANSITION_INVALID", () => {
  // TokenIssued while state=CREATED is illegal
  const tok = makeEvent({
    v: 1, run_id: R, event_id: "lwe_000000000000000000099", key_id: K,
    seq: "2", prev_hash: E1.hash, t_us: "1", kind: "TokenIssued",
    data: { token_id: "lwt_000000000000000000001" },
  });
  assert.throws(
    () => verifyBundle(bundle([E1, tok]), PINS, false),
    (e) => e instanceof LexwattError && e.code === "TRANSITION_INVALID",
  );
});

test("non-monotonic time -> CHAIN_INVALID", () => {
  const e2 = makeEvent({ ...E2.body, t_us: "-1" });
  // t_us is a U string; negative is also schema-invalid, but replay order matters —
  // craft a positive but earlier time:
  const e3 = makeEvent({ ...E2.body, t_us: "0" });
  // E1 t=0, e3 t=0 is ok (>=). Use t decreasing via forged event with seq 2, t=-1? t_us can't be "-1".
  // Instead: two events, second with t less than first requires first t>0.
  const a = makeEvent({ ...E1.body, t_us: "5" });
  const b = makeEvent({ ...E2.body, seq: "2", prev_hash: a.hash, t_us: "4" });
  assert.throws(
    () => verifyBundle(bundle([a, b]), PINS, false),
    (e) => e instanceof LexwattError && e.code === "CHAIN_INVALID",
  );
});
