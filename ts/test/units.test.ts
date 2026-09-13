import { test } from "node:test";
import assert from "node:assert/strict";
import { parseJoules, parseFlops, parseIntRange, wallMsToUs } from "../src/units.ts";
import { LexwattError } from "../src/errors.ts";

test("joules -> microjoules, exact 6-digit fraction", () => {
  assert.equal(parseJoules("0"), 0n);
  assert.equal(parseJoules("1"), 1000000n);
  assert.equal(parseJoules("1.000001"), 1000001n);
  assert.equal(parseJoules("0.5"), 500000n);
  assert.equal(parseJoules("0.000001"), 1n);
  assert.equal(parseJoules("12.345678"), 12345678n);
});

test("joules rejects >6 fractional digits, negatives, junk", () => {
  for (const s of ["0.0000001", "-1", "1.", ".5", "1.5.5", "abc", "", "1e3", " 1"]) {
    assert.throws(() => parseJoules(s), LexwattError);
  }
});

test("flops: decimal U string", () => {
  assert.equal(parseFlops("0"), 0n);
  assert.equal(parseFlops("11440"), 11440n);
  assert.throws(() => parseFlops("1e9"), LexwattError);
  assert.throws(() => parseFlops("-5"), LexwattError);
});

test("int range and wall ms->us", () => {
  assert.equal(parseIntRange("64", 1, 1024, "pids"), 64);
  assert.throws(() => parseIntRange("0", 1, 1024, "pids"), LexwattError);
  assert.throws(() => parseIntRange("2000", 1, 1024, "pids"), LexwattError);
  assert.equal(wallMsToUs("1000"), 1000000n);
  assert.throws(() => wallMsToUs("0"), LexwattError);
  assert.throws(() => wallMsToUs("86400001"), LexwattError);
});
