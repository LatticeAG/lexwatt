/** dense-v1 work estimator (spec §3.2) — BigInt arithmetic, byte-identical
 * to the Python implementation.  The estimate is a cooperative envelope,
 * never a proved hardware bound. */

import { LexwattError } from "./errors.ts";
import { U_MAX } from "./scalars.ts";

const P_MAX = 10n ** 13n;
const L_MAX = 1000;
const H_MAX = 1000000;
const I_MAX = 1048576n;
const O_MAX = 1048576n;
const IO_MAX = 1048576n;
const B_MAX = 256;
const S_MIN = 1000;
const S_MAX = 10000;

export const ESTIMATOR_KIND = "dense-v1";

export interface Model {
  id: string;
  kind: string;
  parameters: string;
  layers: number;
  hidden: number;
  tokenizer_hash: string;
  artifact_hash: string;
  safety_milli: number;
}

export interface Work {
  model_id: string;
  input_tokens: string;
  max_output_tokens: string;
  batch: number;
}

export interface Estimate {
  estimator: string;
  base_flops: string;
  attention_flops: string;
  charged_flops: string;
  coverage: string;
}

function checkModelDims(P: bigint, L: number, H: number, S: number): void {
  if (P < 1n || P > P_MAX) throw new LexwattError("INVALID_INPUT");
  if (L < 1 || L > L_MAX) throw new LexwattError("INVALID_INPUT");
  if (H < 1 || H > H_MAX) throw new LexwattError("INVALID_INPUT");
  if (S < S_MIN || S > S_MAX) throw new LexwattError("INVALID_INPUT");
}

function checkWorkDims(I: bigint, O: bigint, B: number): void {
  if (I < 1n || I > I_MAX) throw new LexwattError("INVALID_INPUT");
  if (O < 0n || O > O_MAX) throw new LexwattError("INVALID_INPUT");
  if (I + O > IO_MAX) throw new LexwattError("INVALID_INPUT");
  if (B < 1 || B > B_MAX) throw new LexwattError("INVALID_INPUT");
}

export function estimateDecomposition(
  P: bigint, L: number, H: number, I: bigint, O: bigint, B: number, S: number,
): { base_flops: string; attention_flops: string; charged_flops: string } {
  checkModelDims(P, L, H, S);
  checkWorkDims(I, O, B);
  const base = 2n * P * BigInt(B) * (I + O);
  const pairs = (I * (I - 1n)) / 2n + I * O + (O * (O - 1n)) / 2n;
  const attention = 4n * BigInt(L) * BigInt(H) * BigInt(B) * pairs;
  const total = (base + attention) * BigInt(S);
  if (total / 1000n + 1n > U_MAX) throw new LexwattError("OVERFLOW");
  const charged = (total + 999n) / 1000n;
  if (base > U_MAX || attention > U_MAX || charged > U_MAX) throw new LexwattError("OVERFLOW");
  return {
    base_flops: base.toString(),
    attention_flops: attention.toString(),
    charged_flops: charged.toString(),
  };
}

export function estimateFromParts(
  kind: string, parameters: bigint, layers: number, hidden: number,
  inputTokens: bigint, maxOutputTokens: bigint, batch: number, safetyMilli: number,
): Estimate {
  if (kind !== ESTIMATOR_KIND) throw new LexwattError("UNSUPPORTED_MODEL");
  const parts = estimateDecomposition(parameters, layers, hidden, inputTokens, maxOutputTokens, batch, safetyMilli);
  return { estimator: ESTIMATOR_KIND, ...parts, coverage: "cooperative_estimate" };
}

export function estimateForModelWork(model: Model, work: Work): Estimate {
  if (work.model_id !== model.id) throw new LexwattError("INVALID_INPUT");
  return estimateFromParts(
    model.kind,
    BigInt(model.parameters),
    model.layers,
    model.hidden,
    BigInt(work.input_tokens),
    BigInt(work.max_output_tokens),
    work.batch,
    model.safety_milli,
  );
}

/** route.choose (spec §7.2): lowest estimated cost, then model ID in ASCII
 * byte order; no reservation is made. */
export function chooseRoute(models: Model[], workFields: Omit<Work, "model_id">, remainingFlops: bigint): {
  model_id: string | null;
  estimate: Estimate | null;
} {
  if (models.length > 32) throw new LexwattError("INVALID_INPUT");
  let best: Model | null = null;
  let bestEst: Estimate | null = null;
  for (const m of models) {
    const est = estimateForModelWork(m, { ...workFields, model_id: m.id });
    if (BigInt(est.charged_flops) > remainingFlops) continue;
    if (
      bestEst === null ||
      BigInt(est.charged_flops) < BigInt(bestEst.charged_flops) ||
      (est.charged_flops === bestEst.charged_flops && m.id < best!.id)
    ) {
      best = m;
      bestEst = est;
    }
  }
  return { model_id: best ? best.id : null, estimate: bestEst };
}
