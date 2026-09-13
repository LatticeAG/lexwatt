"""Event-stream replay legality (spec §5 tables, §7.5 step 6).

Used by the offline verifier and by journal replay checks.  Tracks the run
state machine plus token/action/reservation lifecycle consistency.
"""

from __future__ import annotations

from .errors import LexwattError

# Event kind -> set of source states (spec §5.1).
TRANSITIONS: dict[str, frozenset[str]] = {
    "RunCreated": frozenset(),  # only legal at seq 1 (checked separately)
    "RunArming": frozenset({"CREATED"}),
    "RunRejected": frozenset({"CREATED", "ARMING"}),
    "RunStarted": frozenset({"ARMING"}),
    "SampleRecorded": frozenset({"RUNNING", "STOPPING", "UNCONFIRMED"}),
    "ComputeReserved": frozenset({"RUNNING"}),
    "ComputeFinished": frozenset({"RUNNING"}),
    "TokenIssued": frozenset({"RUNNING"}),
    "TokenExpired": frozenset({"RUNNING"}),
    "TokenSpent": frozenset({"RUNNING"}),
    "ActionFinished": frozenset({"RUNNING", "STOPPING", "UNCONFIRMED"}),
    "ActionUnknown": frozenset({"RUNNING", "STOPPING", "UNCONFIRMED"}),
    "RequestDenied": frozenset({"CREATED", "ARMING", "RUNNING", "STOPPING", "UNCONFIRMED"}),
    "StopLatched": frozenset({"ARMING", "RUNNING"}),
    "FaultObserved": frozenset({"STOPPING", "UNCONFIRMED", "FINALIZING"}),
    "KillIssued": frozenset({"STOPPING", "UNCONFIRMED"}),
    "KillUnconfirmed": frozenset({"STOPPING"}),
    "ContainmentEmpty": frozenset({"STOPPING", "UNCONFIRMED"}),
    "RunFinalized": frozenset({"FINALIZING"}),
}

POST_STATE = {
    "RunCreated": "CREATED",
    "RunArming": "ARMING",
    "RunStarted": "RUNNING",
    "RunRejected": "REJECTED",
    "StopLatched": "STOPPING",
    "KillUnconfirmed": "UNCONFIRMED",
    "ContainmentEmpty": "FINALIZING",
}


def replay_events(bodies: list[dict]) -> str:
    """Replay a run's event bodies (already chain-verified).  Returns the
    resulting run state; raises TRANSITION_INVALID on any illegal step."""
    state = "CREATED"
    tokens: dict[str, str] = {}
    actions: dict[str, str] = {}
    computes: dict[str, str] = {}
    for i, body in enumerate(bodies):
        kind = body["kind"]
        seq = int(body["seq"])
        if seq == 1:
            if kind != "RunCreated":
                raise LexwattError("TRANSITION_INVALID")
        else:
            if kind == "RunCreated":
                raise LexwattError("TRANSITION_INVALID")
            if state not in TRANSITIONS[kind]:
                raise LexwattError("TRANSITION_INVALID")
        data = body["data"]
        if kind == "TokenIssued":
            tid = data["token_id"]
            if tid in tokens:
                raise LexwattError("TRANSITION_INVALID")
            tokens[tid] = "ISSUED"
        elif kind == "TokenExpired":
            if tokens.get(data["token_id"]) != "ISSUED":
                raise LexwattError("TRANSITION_INVALID")
            tokens[data["token_id"]] = "EXPIRED"
        elif kind == "TokenSpent":
            if tokens.get(data["token_id"]) != "ISSUED":
                raise LexwattError("TRANSITION_INVALID")
            tokens[data["token_id"]] = "SPENT"
            if data["action_id"] in actions:
                raise LexwattError("TRANSITION_INVALID")
            actions[data["action_id"]] = "DISPATCHED"
        elif kind == "ActionFinished":
            aid = data["action"]["action_id"]
            if actions.get(aid) != "DISPATCHED":
                raise LexwattError("TRANSITION_INVALID")
            actions[aid] = data["action"]["state"]
        elif kind == "ActionUnknown":
            if actions.get(data["action_id"]) != "DISPATCHED":
                raise LexwattError("TRANSITION_INVALID")
            actions[data["action_id"]] = "UNKNOWN"
        elif kind == "ComputeReserved":
            cid = data["reservation"]["compute_id"]
            if cid in computes:
                raise LexwattError("TRANSITION_INVALID")
            computes[cid] = "CHARGED"
        elif kind == "ComputeFinished":
            cid = data["reservation"]["compute_id"]
            if computes.get(cid) != "CHARGED":
                raise LexwattError("TRANSITION_INVALID")
            computes[cid] = "FINISHED"
        elif kind == "RunFinalized":
            state = data["state"]
            continue
        if kind in POST_STATE:
            state = POST_STATE[kind]
    return state
