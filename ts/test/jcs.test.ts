import { test } from "node:test";
import assert from "node:assert/strict";
import { dumps, loads, MAX_JSON_INT } from "../src/jcs.ts";
import { LexwattError } from "../src/errors.ts";

test("JCS: object key order is UTF-16 code-unit order", () => {
  assert.equal(dumps({ b: 1, a: 2 }), '{"a":2,"b":1}');
  // U+10000's leading surrogate D800 sorts before U+E000 in UTF-16
  const astral: Record<string, number> = {};
  astral["\uE000"] = 1;
  astral["\u{10000}"] = 2;
  assert.equal(dumps(astral), `{"${"\u{10000}"}":2,"${"\uE000"}":1}`);
});

test("JCS: escapes are minimal and lowercase hex", () => {
  assert.equal(dumps("a\"b\\c\nd"), '"a\\"b\\\\c\\nd"');
  assert.equal(dumps("\u0001"), '"\\u0001"');
});


test("JCS: scalars", () => {
  assert.equal(dumps(null), "null");
  assert.equal(dumps(true), "true");
  assert.equal(dumps([1, "x", null]), '[1,"x",null]');
});

test("JCS: non-integer and out-of-range numbers rejected", () => {
  assert.throws(() => dumps(1.5), LexwattError);
  assert.throws(() => dumps(MAX_JSON_INT + 1), LexwattError);
  assert.throws(() => dumps(-MAX_JSON_INT - 1), LexwattError);
  assert.equal(dumps(MAX_JSON_INT), "2147483647");
  assert.throws(() => dumps(NaN), LexwattError);
  assert.throws(() => dumps(Infinity), LexwattError);
});

test("JCS: parse rejects duplicate keys", () => {
  assert.throws(() => loads('{"a":1,"a":2}'), LexwattError);
  assert.deepEqual(loads('{"a":1,"b":2}'), { a: 1, b: 2 });
});

test("JCS: parse rejects fractions/exponents/leading zeros", () => {
  for (const s of ["1.0", "1e3", "01", "-0.5", "+1", ".5"]) {
    assert.throws(() => loads(s), LexwattError);
  }
  assert.equal(loads("-0"), -0);
  assert.equal(loads("100"), 100);
});

test("JCS: depth limit 32 (contained value may nest 32 deep)", () => {
  assert.doesNotThrow(() => loads("[".repeat(32) + "1" + "]".repeat(32)));
  assert.throws(() => loads("[".repeat(33) + "1" + "]".repeat(33)), LexwattError);
});

test("JCS: malformed strings rejected", () => {
  for (const s of ['"\\x"', '"unterminated', '"\\u12zz"', '"\\ud800"', '"\\udc00"', '{"a"}', "[1,]", "{,}"]) {
    assert.throws(() => loads(s), LexwattError);
  }
});

test("JCS: round-trip canonical form", () => {
  const v = { b: [1, 2, { z: null }], a: "x\n" };
  assert.equal(loads(dumps(v)) && dumps(loads(dumps(v))), dumps(v));
});
