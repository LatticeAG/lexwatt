/** Scalar validators (spec §4.1): U decimal strings, locked-prefix IDs,
 * hashes, canonical base64url.  All U arithmetic is BigInt. */

import { LexwattError } from "./errors.ts";

export const U_MAX = (1n << 127n) - 1n;

const U_RE = /^(0|[1-9][0-9]*)$/;
const ID_CHARS = /^[A-Za-z0-9_-]{21}$/;
const MODEL_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const B64URL_RE = /^[A-Za-z0-9_-]*$/;

export const ID_PREFIXES: Record<string, string> = {
  run: "lwr",
  event: "lwe",
  request: "lwq",
  token: "lwt",
  action: "lwa",
  compute: "lwc",
  channel: "lwp",
  key: "lwk",
};

export function checkU(v: unknown): string {
  if (typeof v !== "string" || !U_RE.test(v)) throw new LexwattError("INVALID_INPUT");
  if (BigInt(v) > U_MAX) throw new LexwattError("INVALID_INPUT");
  return v;
}

export function parseU(v: unknown): bigint {
  return BigInt(checkU(v));
}

export function uStr(v: bigint): string {
  if (v < 0n || v > U_MAX) throw new LexwattError("OVERFLOW");
  return v.toString();
}

export function checkId(v: unknown, kind?: string): string {
  if (typeof v !== "string") throw new LexwattError("INVALID_INPUT");
  if (kind !== undefined) {
    const prefix = ID_PREFIXES[kind] + "_";
    if (!v.startsWith(prefix)) throw new LexwattError("INVALID_INPUT");
    if (!ID_CHARS.test(v.slice(prefix.length))) throw new LexwattError("INVALID_INPUT");
    return v;
  }
  for (const p of Object.values(ID_PREFIXES)) {
    if (v.startsWith(p + "_") && ID_CHARS.test(v.slice(p.length + 1))) return v;
  }
  throw new LexwattError("INVALID_INPUT");
}

export function checkHash(v: unknown): string {
  if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v)) throw new LexwattError("INVALID_INPUT");
  return v;
}

export function checkModelName(v: unknown): string {
  if (typeof v !== "string" || !MODEL_NAME_RE.test(v)) throw new LexwattError("INVALID_INPUT");
  return v;
}

function b64urlDecodeExact(v: string, size: number): Uint8Array {
  if (typeof v !== "string" || !B64URL_RE.test(v)) throw new LexwattError("INVALID_INPUT");
  const raw = Buffer.from(v, "base64url");
  if (raw.length !== size) throw new LexwattError("INVALID_INPUT");
  if (raw.toString("base64url") !== v) throw new LexwattError("INVALID_INPUT");
  return raw;
}

export function checkSignature(v: unknown): string {
  if (typeof v !== "string") throw new LexwattError("INVALID_INPUT");
  b64urlDecodeExact(v, 64);
  return v;
}

export function decodeSignature(v: string): Uint8Array {
  return b64urlDecodeExact(v, 64);
}

export function checkPublicKey(v: unknown): string {
  if (typeof v !== "string") throw new LexwattError("INVALID_INPUT");
  b64urlDecodeExact(v, 32);
  return v;
}

export function decodePublicKey(v: string): Uint8Array {
  return b64urlDecodeExact(v, 32);
}

export function checkBodyB64(v: unknown): string {
  if (typeof v !== "string" || !B64URL_RE.test(v)) throw new LexwattError("INVALID_INPUT");
  const raw = Buffer.from(v, "base64url");
  if (raw.length > 262144) throw new LexwattError("INVALID_INPUT");
  if (raw.toString("base64url") !== v) throw new LexwattError("INVALID_INPUT");
  return v;
}

export function b64u(raw: Uint8Array): string {
  return Buffer.from(raw).toString("base64url");
}
