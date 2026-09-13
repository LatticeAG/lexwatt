import { test } from "node:test";
import assert from "node:assert/strict";
import { eventHash, eventSignMessage, tokenSignMessage, actionHash, sha256Hex, d } from "../src/hashing.ts";
import { sign, verify, publicKeyFromSeed } from "../src/ed25519.ts";
import { E1, E2, ACT, SEED, PUB, TOKEN, TOKEN_BODY } from "./fixtures.ts";
import { dumpsBytes } from "../src/jcs.ts";

test("golden E1/E2 hash reproduction (cross-language parity)", () => {
  assert.equal(eventHash(E1.body), E1.hash);
  assert.equal(eventHash(E2.body), E2.hash);
});

test("golden E1/E2 signatures verify against public seed key", () => {
  assert.equal(publicKeyFromSeed(new Uint8Array(SEED)), PUB);
  assert.equal(verify(PUB, eventSignMessage(E1.hash), E1.sig), true);
  assert.equal(verify(PUB, eventSignMessage(E2.hash), E2.sig), true);
  // wrong message fails
  assert.equal(verify(PUB, eventSignMessage(E2.hash), E1.sig), false);
});

test("golden sigs reproduce from seed (deterministic Ed25519)", () => {
  const sig1 = Buffer.from(sign(new Uint8Array(SEED), eventSignMessage(E1.hash))).toString("base64url");
  assert.equal(sig1, E1.sig);
  const sig2 = Buffer.from(sign(new Uint8Array(SEED), eventSignMessage(E2.hash))).toString("base64url");
  assert.equal(sig2, E2.sig);
});

test("domain separation: D(label,x) = sha256(label || 0x00 || J(x))", () => {
  const enc = new TextEncoder();
  const expect = sha256Hex(new Uint8Array([...enc.encode("LEXWATT-EVENT/1"), 0, ...dumpsBytes(E1.body)]));
  assert.equal(eventHash(E1.body), expect);
  // different label -> different digest
  assert.notEqual(d("LEXWATT-EVENT/1", E1.body), d("LEXWATT-CONFIG/1", E1.body));
});

test("token signature verifies (TV-31 fixture)", () => {
  assert.equal(verify(PUB, tokenSignMessage(TOKEN_BODY), TOKEN.sig), true);
});

test("action hash is domain-separated over canonical action", () => {
  const h = actionHash(ACT);
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.notEqual(h, sha256Hex(dumpsBytes(ACT))); // not raw JCS hash
});
