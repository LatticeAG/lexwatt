import { test } from "node:test";
import assert from "node:assert/strict";
import {
  checkU, checkId, checkHash, checkSignature, checkPublicKey, checkBodyB64,
  checkModelName, parseU, uStr, U_MAX, b64u,
} from "../src/scalars.ts";
import { LexwattError } from "../src/errors.ts";
import { K, R, T } from "./fixtures.ts";

test("U: decimal strings, no leading zeros, u127 max", () => {
  assert.equal(checkU("0"), "0");
  assert.equal(checkU("123"), "123");
  for (const bad of ["01", "-1", "1.0", "", "0x10", " 1", "1e9", 12, null]) {
    assert.throws(() => checkU(bad), LexwattError);
  }
  assert.throws(() => checkU((U_MAX + 1n).toString()), LexwattError);
  assert.equal(checkU(U_MAX.toString()), U_MAX.toString());
});

test("uStr overflow bounds", () => {
  assert.equal(uStr(0n), "0");
  assert.equal(uStr(U_MAX), U_MAX.toString());
  assert.throws(() => uStr(-1n), LexwattError);
  assert.throws(() => uStr(U_MAX + 1n), LexwattError);
  assert.equal(parseU("42"), 42n);
});

test("locked-prefix IDs", () => {
  assert.equal(checkId(R, "run"), R);
  assert.throws(() => checkId(R, "key"), LexwattError);
  assert.throws(() => checkId("lwr_short"), LexwattError);
  assert.throws(() => checkId("lwr_" + "!".repeat(21)), LexwattError);
  assert.equal(checkId(K), K);
  assert.equal(checkId(T), T);
  assert.throws(() => checkId("xyz_000000000000000000001"), LexwattError);
});

test("hash format", () => {
  assert.equal(checkHash("a".repeat(64)), "a".repeat(64));
  assert.throws(() => checkHash("A".repeat(64)), LexwattError);
  assert.throws(() => checkHash("a".repeat(63)), LexwattError);
});

test("signature: 64-byte canonical b64url", () => {
  const sig = b64u(new Uint8Array(64));
  assert.equal(checkSignature(sig), sig);
  assert.throws(() => checkSignature(b64u(new Uint8Array(63))), LexwattError);
  assert.throws(() => checkSignature(sig + "="), LexwattError);
  assert.throws(() => checkSignature(sig + "+"), LexwattError);
});

test("public key: 32-byte canonical b64url", () => {
  const pk = b64u(new Uint8Array(32));
  assert.equal(checkPublicKey(pk), pk);
  assert.throws(() => checkPublicKey(b64u(new Uint8Array(31))), LexwattError);
});

test("body_b64: canonical, <=256KiB decoded", () => {
  assert.equal(checkBodyB64(""), "");
  assert.equal(checkBodyB64(b64u(new Uint8Array([1, 2, 3]))), "AQID");
  assert.throws(() => checkBodyB64("AAA="), LexwattError);
  assert.throws(() => checkBodyB64("AQID\n"), LexwattError);
  assert.throws(() => checkBodyB64(b64u(new Uint8Array(262145))), LexwattError);
});

test("model name regex", () => {
  assert.equal(checkModelName("dense-v1"), "dense-v1");
  assert.throws(() => checkModelName("Dense"), LexwattError);
  assert.throws(() => checkModelName("-x"), LexwattError);
  assert.throws(() => checkModelName("a".repeat(65)), LexwattError);
});
