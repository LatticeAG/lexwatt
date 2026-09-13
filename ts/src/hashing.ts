/** Domain-separated hashing (spec §4.2): D(label, x) =
 * SHA256(UTF8(label) || 0x00 || J(x)) as lowercase hex. */

import { createHash } from "node:crypto";
import { dumpsBytes } from "./jcs.ts";

export const D_CONFIG = "LEXWATT-CONFIG/1";
export const D_ACTION = "LEXWATT-ACTION/1";
export const D_EVENT = "LEXWATT-EVENT/1";
export const D_REQUEST = "LEXWATT-REQUEST/1";
export const SIGN_EVENT = "LEXWATT-SIGN/1";
export const SIGN_TOKEN = "LEXWATT-TOKEN/1";

export function sha256Hex(raw: Uint8Array): string {
  return createHash("sha256").update(raw).digest("hex");
}

export function d(label: string, value: unknown): string {
  const enc = new TextEncoder();
  return sha256Hex(
    new Uint8Array([...enc.encode(label), 0, ...dumpsBytes(value as never)]),
  );
}

export function eventHash(body: unknown): string {
  return d(D_EVENT, body);
}

export function actionHash(action: unknown): string {
  return d(D_ACTION, action);
}

export function configHash(config: unknown): string {
  return d(D_CONFIG, config);
}

export function requestDigest(method: string, params: unknown): string {
  return d(D_REQUEST, { method, params });
}

export function eventSignMessage(eventHashHex: string): Uint8Array {
  const enc = new TextEncoder();
  return new Uint8Array([...enc.encode(SIGN_EVENT), 0, ...Buffer.from(eventHashHex, "hex")]);
}

export function tokenSignMessage(tokenBody: unknown): Uint8Array {
  const enc = new TextEncoder();
  return new Uint8Array([...enc.encode(SIGN_TOKEN), 0, ...dumpsBytes(tokenBody as never)]);
}
