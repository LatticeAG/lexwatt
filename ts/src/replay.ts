/** §5 transition legality replay for offline verification step 6.
 * Mirrors src/lexwatt/replay.py exactly. */

import { LexwattError } from "./errors.ts";

const TERMINAL = new Set(["COMPLETED", "KILLED", "FAILED", "REJECTED"]);

// kind -> set of source states in which the event may appear
const TRANSITIONS: Record<string, Set<string>> = {
  RunCreated: new Set(["START"]),
  RunArming: new Set(["CREATED"]),
  RunStarted: new Set(["ARMING"]),
  RunRejected: new Set(["CREATED", "ARMING"]),
  SampleRecorded: new Set(["RUNNING", "STOPPING", "UNCONFIRMED"]),
  TokenIssued: new Set(["RUNNING"]),
  TokenExpired: new Set(["RUNNING"]),
  TokenSpent: new Set(["RUNNING"]),
  ActionFinished: new Set(["RUNNING", "STOPPING", "UNCONFIRMED"]),
  ActionUnknown: new Set(["RUNNING", "STOPPING", "UNCONFIRMED"]),
  ComputeReserved: new Set(["RUNNING"]),
  ComputeFinished: new Set(["RUNNING"]),
  RequestDenied: new Set(["CREATED", "ARMING", "RUNNING", "STOPPING", "UNCONFIRMED"]),
  StopLatched: new Set(["ARMING", "RUNNING"]),
  FaultObserved: new Set(["ARMING", "RUNNING", "STOPPING", "UNCONFIRMED", "FINALIZING"]),
  KillIssued: new Set(["STOPPING", "UNCONFIRMED"]),
  KillUnconfirmed: new Set(["STOPPING"]),
  ContainmentEmpty: new Set(["STOPPING", "UNCONFIRMED"]),
  RunFinalized: new Set(["FINALIZING"]),
};

const POST_STATE: Record<string, string> = {
  RunCreated: "CREATED",
  RunArming: "ARMING",
  RunStarted: "RUNNING",
  RunRejected: "REJECTED",
  StopLatched: "STOPPING",
  KillUnconfirmed: "UNCONFIRMED",
  ContainmentEmpty: "FINALIZING",
};

interface EvBody {
  kind: string;
  data: any;
  [k: string]: unknown;
}

export function replayEvents(bodies: EvBody[]): string {
  let state = "START";
  const tokens = new Map<string, string>();
  const actions = new Map<string, string>();
  const computes = new Map<string, string>();
  const seenRequests = new Set<string>();
  for (const b of bodies) {
    const kind = b.kind;
    const allowed = TRANSITIONS[kind];
    if (allowed === undefined) throw new LexwattError("TRANSITION_INVALID");
    if (state !== "START" && !allowed.has(state)) {
      if (!(state === "START" && kind === "RunCreated")) {
        throw new LexwattError("TRANSITION_INVALID");
      }
    }
    if (kind === "RunCreated" && state !== "START") throw new LexwattError("TRANSITION_INVALID");
    const d = b.data ?? {};
    if (kind === "TokenIssued") {
      if (tokens.has(d.token_id)) throw new LexwattError("TRANSITION_INVALID");
      tokens.set(d.token_id, "ISSUED");
    } else if (kind === "TokenExpired") {
      if (tokens.get(d.token_id) !== "ISSUED") throw new LexwattError("TRANSITION_INVALID");
      tokens.set(d.token_id, "EXPIRED");
    } else if (kind === "TokenSpent") {
      if (tokens.get(d.token_id) !== "ISSUED") throw new LexwattError("TRANSITION_INVALID");
      tokens.set(d.token_id, "SPENT");
      actions.set(d.action_id, "DISPATCHED");
    } else if (kind === "ActionFinished") {
      const a = d.action ?? {};
      if (actions.get(a.action_id) !== "DISPATCHED") throw new LexwattError("TRANSITION_INVALID");
      actions.set(a.action_id, a.state);
    } else if (kind === "ActionUnknown") {
      if (actions.get(d.action_id) !== "DISPATCHED") throw new LexwattError("TRANSITION_INVALID");
      actions.set(d.action_id, "UNKNOWN");
    } else if (kind === "ComputeReserved") {
      const r = d.reservation ?? {};
      if (computes.has(r.compute_id)) throw new LexwattError("TRANSITION_INVALID");
      computes.set(r.compute_id, "CHARGED");
    } else if (kind === "ComputeFinished") {
      const r = d.reservation ?? {};
      if (computes.get(r.compute_id) !== "CHARGED") throw new LexwattError("TRANSITION_INVALID");
      computes.set(r.compute_id, "FINISHED");
    } else if (kind === "RequestDenied") {
      if (seenRequests.has(d.request_id)) throw new LexwattError("TRANSITION_INVALID");
      seenRequests.add(d.request_id);
    }
    if (kind in POST_STATE) state = POST_STATE[kind]!;
    if (kind === "RunFinalized") state = (d.state as string) ?? state;
  }
  if (state === "START") return "CREATED";
  return state;
}
