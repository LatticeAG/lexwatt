/** Exact CLI unit parsing (spec §8.1): joules to microjoules, FLOPs to U.
 * No floats: decimal strings are split and assembled as integers. */

import { LexwattError } from "./errors.ts";
import { U_MAX, uStr } from "./scalars.ts";

const JOULE_RE = /^([0-9]+)(\.([0-9]{1,6}))?$/;

/** "1.000001" J -> 1000001 uJ.  More than 6 fractional digits: invalid. */
export function parseJoules(text: string): bigint {
  if (typeof text !== "string") throw new LexwattError("INVALID_INPUT");
  const m = JOULE_RE.exec(text);
  if (!m) throw new LexwattError("INVALID_INPUT");
  const whole = BigInt(m[1]!);
  const frac = (m[3] ?? "").padEnd(6, "0");
  const uj = whole * 1000000n + (frac ? BigInt(frac) : 0n);
  if (uj > U_MAX) throw new LexwattError("INVALID_INPUT");
  return uj;
}

export function parseFlops(text: string): bigint {
  if (typeof text !== "string" || !/^(0|[1-9][0-9]*)$/.test(text)) {
    throw new LexwattError("INVALID_INPUT");
  }
  const v = BigInt(text);
  if (v > U_MAX) throw new LexwattError("INVALID_INPUT");
  return v;
}

export function parseIntRange(text: string, lo: number, hi: number, name: string): number {
  if (typeof text !== "string" || !/^(0|[1-9][0-9]*)$/.test(text)) {
    throw new LexwattError("INVALID_INPUT");
  }
  const v = Number(text);
  if (!Number.isInteger(v) || v < lo || v > hi) throw new LexwattError("INVALID_INPUT");
  return v;
}

export function wallMsToUs(text: string): bigint {
  const ms = parseIntRange(text, 1, 86400000, "max-wall-ms");
  return BigInt(ms) * 1000n;
}
