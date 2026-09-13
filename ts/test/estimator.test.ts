import { test } from "node:test";
import assert from "node:assert/strict";
import {
  estimateDecomposition, estimateForModelWork, estimateFromParts, chooseRoute,
} from "../src/estimator.ts";
import { LexwattError } from "../src/errors.ts";
import { EST, M, W } from "./fixtures.ts";

test("golden estimate decomposition", () => {
  // base = 2*P*B*(I+O) = 2*1000*1*5 = 10000
  // pairs = I*(I-1)/2 + I*O + O*(O-1)/2 = 1 + 6 + 3 = 10
  // att = 4*L*H*B*pairs = 4*1*10*1*10 = 400
  // charged = ceil((10400)*1100/1000) = 11440
  const d = estimateDecomposition(1000n, 1, 10, 2n, 3n, 1, 1100);
  assert.equal(d.base_flops, "10000");
  assert.equal(d.attention_flops, "400");
  assert.equal(d.charged_flops, "11440");
});

test("estimateForModelWork matches golden EST", () => {
  const est = estimateForModelWork(M, W);
  assert.deepEqual(est, EST);
});

test("model/work dims enforced", () => {
  assert.throws(() => estimateDecomposition(0n, 1, 10, 2n, 3n, 1, 1100), LexwattError);
  assert.throws(() => estimateDecomposition(10n ** 13n + 1n, 1, 10, 2n, 3n, 1, 1100), LexwattError);
  assert.throws(() => estimateDecomposition(1000n, 0, 10, 2n, 3n, 1, 1100), LexwattError);
  assert.throws(() => estimateDecomposition(1000n, 1, 10, 0n, 3n, 1, 1100), LexwattError);
  assert.throws(() => estimateDecomposition(1000n, 1, 10, 2n, 3n, 0, 1100), LexwattError);
  assert.throws(() => estimateDecomposition(1000n, 1, 10, 2n, 3n, 1, 999), LexwattError);
  assert.throws(() => estimateDecomposition(1000n, 1, 10, 2n, 3n, 1, 10001), LexwattError);
});

test("O=0 allowed; I+O<=1048576", () => {
  const d = estimateDecomposition(1000n, 1, 10, 1n, 0n, 1, 1000);
  assert.equal(d.attention_flops, "0");
  assert.throws(() => estimateDecomposition(1000n, 1, 10, 1048576n, 1n, 1, 1000), LexwattError);
});

test("unsupported model kind", () => {
  assert.throws(
    () => estimateFromParts("moe-v1", 1000n, 1, 10, 2n, 3n, 1, 1100),
    (e) => e instanceof LexwattError && e.code === "UNSUPPORTED_MODEL",
  );
});

test("model_id mismatch rejected", () => {
  assert.throws(() => estimateForModelWork(M, { ...W, model_id: "other" }), LexwattError);
});

test("route.choose: lowest charged then ASCII id; budget excludes", () => {
  const m2 = { ...M, id: "dense-tiny", parameters: "500" };
  const w = { input_tokens: "2", max_output_tokens: "3", batch: 1 };
  const r = chooseRoute([M, m2], w, 10n ** 18n);
  assert.equal(r.model_id, "dense-tiny"); // smaller P -> smaller charged
  const r0 = chooseRoute([M], w, 100n);
  assert.equal(r0.model_id, null); // charged 11440 > remaining 100
  const rtie = chooseRoute([{ ...M, id: "zzz" }, { ...M, id: "aaa" }], w, 10n ** 18n);
  assert.equal(rtie.model_id, "aaa"); // ASCII tie-break
});

test("route.choose catalog cap 32", () => {
  const many = Array.from({ length: 33 }, (_, i) => ({ ...M, id: `m${i}` }));
  assert.throws(() => chooseRoute(many, { input_tokens: "2", max_output_tokens: "3", batch: 1 }, 1n), LexwattError);
});
