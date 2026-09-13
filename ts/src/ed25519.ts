/** Ed25519 verify via node:crypto (spec §4.2).  Public keys are the 32-byte
 * canonical base64url form; JWK import wraps them for verify. */

import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { decodePublicKey, decodeSignature } from "./scalars.ts";

// Ed25519 PKCS8/SPKI DER prefixes (fixed 32-byte key material).
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function pubFromRaw(raw: Uint8Array) {
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, Buffer.from(raw)]),
    format: "der",
    type: "spki",
  });
}

function privFromSeed(seedRaw: Uint8Array) {
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seedRaw)]),
    format: "der",
    type: "pkcs8",
  });
}

export function verify(publicKeyB64: string, message: Uint8Array, signatureB64: string): boolean {
  try {
    const key = pubFromRaw(decodePublicKey(publicKeyB64));
    return cryptoVerify(null, Buffer.from(message), key, Buffer.from(decodeSignature(signatureB64)));
  } catch {
    return false;
  }
}

export function sign(seedRaw: Uint8Array, message: Uint8Array): Uint8Array {
  return new Uint8Array(cryptoSign(null, Buffer.from(message), privFromSeed(seedRaw)));
}

export function publicKeyFromSeed(seedRaw: Uint8Array): string {
  const spki = createPublicKey(privFromSeed(seedRaw)).export({ format: "der", type: "spki" });
  return Buffer.from(spki).subarray(-32).toString("base64url");
}
