/** Offline receipt verification (spec §7.5): the fixed 8-step pipeline.
 * Mirrors src/lexwatt/verify.py.  physical_truth is always NOT_ATTESTED. */

import { LexwattError } from "./errors.ts";
import { eventHash, eventSignMessage } from "./hashing.ts";
import { verify as edVerify } from "./ed25519.ts";
import { checkId, checkPublicKey, decodePublicKey, decodeSignature } from "./scalars.ts";
import { replayEvents } from "./replay.ts";

export const ZERO_HASH = "0".repeat(64);

export interface Pin {
  key_id: string;
  public_key: string;
}

export interface VerifyResult {
  integrity: string;
  completeness: string;
  physical_truth: string;
  head: { seq: string; hash: string };
  state: string;
}

interface Entry {
  hash: string;
  sig: string;
  body: {
    event_id: string;
    run_id: string;
    seq: string;
    t_us: string;
    kind: string;
    key_id: string;
    prev_hash: string;
    data: unknown;
    [k: string]: unknown;
  };
}

interface Bundle {
  v: number;
  run_id: string;
  entries: Entry[];
  expected_head: { seq: string; hash: string } | null;
}

function checkBundleShape(b: Bundle): void {
  if (typeof b !== "object" || b === null || Array.isArray(b)) throw new LexwattError("INVALID_INPUT");
  if (b.v !== 1) throw new LexwattError("UNSUPPORTED_VERSION");
  checkId(b.run_id, "run");
  if (!Array.isArray(b.entries)) throw new LexwattError("INVALID_INPUT");
  for (const e of b.entries) {
    if (typeof e !== "object" || e === null) throw new LexwattError("INVALID_INPUT");
    if (typeof e.body !== "object" || e.body === null) throw new LexwattError("INVALID_INPUT");
    checkId(e.body.event_id, "event");
    checkId(e.body.run_id, "run");
    if (!/^[0-9a-f]{64}$/.test(e.hash)) throw new LexwattError("INVALID_INPUT");
    checkId(e.body.key_id, "key");
  }
}

export function verifyBundle(bundle: Bundle, pins: Pin[], requireComplete: boolean): VerifyResult {
  // (1) frame, schema, limits
  checkBundleShape(bundle);
  const entries = bundle.entries;
  if (pins.length > 32) throw new LexwattError("INVALID_INPUT");
  for (const p of pins) {
    checkId(p.key_id, "key");
    checkPublicKey(p.public_key);
  }

  // (2) recompute every entry's body hash
  for (const e of entries) {
    if (eventHash(e.body) !== e.hash) throw new LexwattError("HASH_MISMATCH");
  }

  // (3) resolve key_id against supplied pins
  const keymap = new Map(pins.map((p) => [p.key_id, p.public_key]));
  for (const e of entries) {
    if (!keymap.has(e.body.key_id)) throw new LexwattError("UNTRUSTED_KEY");
  }

  // (4) verify each signature
  for (const e of entries) {
    const pub = keymap.get(e.body.key_id)!;
    if (!edVerify(pub, eventSignMessage(e.hash), e.sig)) {
      throw new LexwattError("SIGNATURE_INVALID");
    }
  }

  // (5) genesis prev_hash, seq continuity, linkage, time, single run/key
  if (entries.length) {
    const runId = entries[0]!.body.run_id;
    const keyId = entries[0]!.body.key_id;
    let prev = ZERO_HASH;
    let lastT = -1n;
    entries.forEach((e, i) => {
      const b = e.body;
      if (BigInt(b.seq) !== BigInt(i + 1)) throw new LexwattError("CHAIN_INVALID");
      if (b.prev_hash !== prev) throw new LexwattError("CHAIN_INVALID");
      if (b.run_id !== runId || b.key_id !== keyId) throw new LexwattError("CHAIN_INVALID");
      const t = BigInt(b.t_us);
      if (t < lastT) throw new LexwattError("CHAIN_INVALID");
      lastT = t;
      prev = e.hash;
    });
  }

  // (6) §5 transition legality
  const state = entries.length ? replayEvents(entries.map((e) => e.body as never)) : "CREATED";

  // (7) expected_head equality when non-null
  const head = entries.length
    ? { seq: entries[entries.length - 1]!.body.seq, hash: entries[entries.length - 1]!.hash }
    : { seq: "0", hash: ZERO_HASH };
  const eh = bundle.expected_head;
  if (eh !== null && (eh.seq !== head.seq || eh.hash !== head.hash)) {
    throw new LexwattError("CHAIN_INVALID");
  }

  // (8) completeness
  const complete =
    entries.length > 0 &&
    (entries[entries.length - 1]!.body.kind === "RunRejected" ||
      entries[entries.length - 1]!.body.kind === "RunFinalized");
  if (requireComplete && !complete) throw new LexwattError("INCOMPLETE");

  return {
    integrity: "VALID",
    completeness: complete ? "COMPLETE" : "PREFIX",
    physical_truth: "NOT_ATTESTED",
    head,
    state,
  };
}
