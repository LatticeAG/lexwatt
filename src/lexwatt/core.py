"""Deterministic run-state reducer (spec §5).

RunCore is the pure, serializer-owned state machine for one run.  It owns
no I/O: every method returns an ``Outcome`` listing the events that must be
durably appended (in order) plus the reply result or error.  The engine
commits them inside one writer transaction; the conformance harness drives
the same methods through injectable clocks and IDs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import hashing, scalars
from .errors import FAULT_REASONS, LexwattError
from .estimator import estimate_for_model_work, estimate_from_parts

TOKEN_TTL_US = 1_000_000
MAX_INFLIGHT_ACTIONS = 32
ROUTE_MAX_MODELS = 32

TOKEN_STATES = ("ISSUED", "EXPIRED", "SPENT")
ACTION_STATES = ("DISPATCHED", "SUCCEEDED", "FAILED", "UNKNOWN")


@dataclass
class Outcome:
    events: list = field(default_factory=list)  # list of (kind, data)
    result: object = None
    error: LexwattError | None = None


@dataclass
class TokenRec:
    token: dict
    channel_id: str
    action_hash: str
    expires_us: int
    state: str = "ISSUED"
    action_id: str | None = None


@dataclass
class ActionRec:
    action_id: str
    channel_id: str
    kind: str
    token_id: str
    state: str = "DISPATCHED"
    result: dict | None = None
    error: str | None = None
    exit: dict | None = None


@dataclass
class ComputeRec:
    reservation: dict
    channel_id: str


class RunCore:
    """One run's authoritative ledger state."""

    def __init__(self, run_id: str, key_id: str, config: dict):
        self.run_id = run_id
        self.key_id = key_id
        self.config = config
        self.budgets = config["budgets"]
        self.state = "CREATED"
        self.stop_reason: str | None = None
        self.charged_flops = 0
        self.spawn_issued = 0
        self.tokens: dict[str, TokenRec] = {}
        self.actions: dict[str, ActionRec] = {}
        self.computes: dict[str, ComputeRec] = {}
        self.channels: set[str] = set()
        self.issue_seq = 0
        self.root_exit: dict | None = None
        self.energy_uj: int | None = None
        self.energy_complete = False
        self.kill_issued_at_us: int | None = None
        self.stop_latched_us: int | None = None
        self.inflight = 0
        self._catalog = {m["id"]: m for m in config["model_catalog"]}
        self._network = {(d["origin"], d["path"]): d for d in config["network"]}
        self._final_state: str | None = None

    # -- helpers -----------------------------------------------------------

    def _live(self) -> bool:
        return self.state in ("CREATED", "ARMING", "RUNNING", "STOPPING", "UNCONFIRMED")

    def _deny(self, request_id: str, code: str) -> Outcome:
        """A committed denial occupies its request key; RequestDenied is
        appended whenever the run is in a state that permits the event."""
        out = Outcome(error=LexwattError(code))
        if self._live():
            out.events.append(("RequestDenied", {"request_id": request_id, "code": code}))
        return out

    def _latch(self, reason: str, out: Outcome) -> None:
        if self.state in ("ARMING", "RUNNING") and self.stop_reason is None:
            self.stop_reason = reason
            self.state = "STOPPING"
            out.events.append(("StopLatched", {"reason": reason}))

    def _fault_or_latch(self, reason: str, out: Outcome) -> None:
        """Infrastructure faults after a committed stop are diagnostics."""
        if self.stop_reason is None and self.state in ("ARMING", "RUNNING"):
            self._latch(reason, out)
        elif self.state in ("STOPPING", "UNCONFIRMED", "FINALIZING"):
            out.events.append(("FaultObserved", {"reason": reason}))

    # -- admission policy ---------------------------------------------------

    def _action_policy(self, action: dict) -> None:
        """Static action policy (pre-capacity).  Raises ACTION_DENIED."""
        if action["kind"] == "spawn":
            execv = action["exec"]
            argv0, cwd = execv["argv"][0], execv["cwd"]
            if not (self._in_approved_roots(argv0) and self._in_approved_roots(cwd)):
                raise LexwattError("ACTION_DENIED")
        else:  # http_get
            key = (action["origin"], action["path"])
            dest = self._network.get(key)
            if dest is None:
                raise LexwattError("ACTION_DENIED")
            if action["max_response_bytes"] > dest["max_response_bytes"]:
                raise LexwattError("ACTION_DENIED")
            # every pinned IP must be public; loopback/link-local/metadata
            # pins are denied at the broker, not just at config load
            from .schema import check_public_ip

            for ip in dest.get("ips", []):
                try:
                    check_public_ip(ip)
                except LexwattError:
                    raise LexwattError("ACTION_DENIED") from None

    def _in_approved_roots(self, path: str) -> bool:
        """argv[0]/cwd must resolve under the approved image or workspace.

        The supervisor supplies the approved roots through the config and
        host policy; the core enforces the path-prefix shape.  Symbolic
        resolution happens in the host layer before dispatch.
        """
        allowed = self.config.get("_approved_roots", ["/work", "/usr", "/bin", "/lib", "/opt"])
        return any(path == r or path.startswith(r.rstrip("/") + "/") for r in allowed)

    # -- §5.2 token lifecycle ------------------------------------------------

    def token_issue(self, channel_id: str, action: dict, now_us: int, token_id: str, request_id: str) -> Outcome:
        out = Outcome()
        if self.state != "RUNNING":
            out.error = LexwattError("STOPPED")
            return out
        try:
            self._action_policy(action)
        except LexwattError as e:
            return self._deny(request_id, e.code)
        cap = self.budgets["spawns"]
        if self.spawn_issued >= cap:
            out = self._deny(request_id, "SPAWN_CAP")
            self._latch("SPAWN_CAP", out)
            return out
        # issue: slot is irreversibly charged
        self.spawn_issued += 1
        self.issue_seq += 1
        body = {
            "v": 1,
            "key_id": self.key_id,
            "token_id": token_id,
            "run_id": self.run_id,
            "channel_id": channel_id,
            "action_hash": hashing.action_hash(action),
            "issued_us": scalars.u_str(now_us),
            "expires_us": scalars.u_str(now_us + TOKEN_TTL_US),
            "issue_seq": scalars.u_str(self.issue_seq),
        }
        rec = TokenRec(
            token={"body": body, "sig": None},  # engine fills sig before commit
            channel_id=channel_id,
            action_hash=body["action_hash"],
            expires_us=now_us + TOKEN_TTL_US,
        )
        self.tokens[token_id] = rec
        out.events.append(
            (
                "TokenIssued",
                {
                    "token_id": token_id,
                    "channel_id": channel_id,
                    "kind": action["kind"],
                    "action_hash": body["action_hash"],
                    "issued_us": body["issued_us"],
                    "expires_us": body["expires_us"],
                    "issue_seq": body["issue_seq"],
                },
            )
        )
        out.result = {"token_body": body, "remaining_spawns": cap - self.spawn_issued, "_rec": rec}
        return out

    def dispatch(self, channel_id: str, token: dict, action: dict, now_us: int, action_id: str, request_id: str) -> Outcome:
        out = Outcome()
        if self.state != "RUNNING":
            out.error = LexwattError("STOPPED")
            return out
        # token schema/signature verified by engine (needs key); rec lookup:
        body = token["body"]
        rec = self.tokens.get(body["token_id"])
        if (
            body["run_id"] != self.run_id
            or body["channel_id"] != channel_id
            or body["action_hash"] != hashing.action_hash(action)
            or rec is None
        ):
            return self._deny(request_id, "TOKEN_BINDING")
        if rec.state == "SPENT":
            return self._deny(request_id, "TOKEN_USED")
        if rec.state == "EXPIRED":
            return self._deny(request_id, "TOKEN_EXPIRED")
        if now_us >= rec.expires_us:
            rec.state = "EXPIRED"
            out = self._deny(request_id, "TOKEN_EXPIRED")
            out.events.insert(0, ("TokenExpired", {"token_id": rec.token["body"]["token_id"]}))
            return out
        if self.inflight >= MAX_INFLIGHT_ACTIONS:
            out.error = LexwattError("BUSY")
            return out  # BUSY rejections before commit leave the request key free
        rec.state = "SPENT"
        rec.action_id = action_id
        self.inflight += 1
        arec = ActionRec(
            action_id=action_id,
            channel_id=channel_id,
            kind=action["kind"],
            token_id=body["token_id"],
        )
        self.actions[action_id] = arec
        out.events.append(("TokenSpent", {"token_id": body["token_id"], "action_id": action_id}))
        out.result = {"action_id": action_id, "state": "DISPATCHED", "_action": action, "_arec": arec}
        return out

    def expire_tokens(self, now_us: int) -> Outcome:
        """Periodic sweep at sample cadence while RUNNING; at most one
        TokenExpired per token, no refund."""
        out = Outcome()
        if self.state != "RUNNING":
            return out
        for rec in self.tokens.values():
            if rec.state == "ISSUED" and now_us >= rec.expires_us:
                rec.state = "EXPIRED"
                out.events.append(("TokenExpired", {"token_id": rec.token["body"]["token_id"]}))
        return out

    # -- §5.2 action lifecycle ------------------------------------------------

    def action_view(self, channel_id: str, action_id: str, request_id: str) -> Outcome:
        arec = self.actions.get(action_id)
        if arec is None:
            return self._deny(request_id, "NOT_FOUND")
        if arec.channel_id != channel_id:
            return self._deny(request_id, "UNAUTHORIZED")
        out = Outcome()
        out.result = {
            "action_id": action_id,
            "state": arec.state,
            "result": arec.result,
            "error": arec.error,
        }
        return out

    def action_finish(self, action_id: str, result: dict | None, error: str | None, exit_: dict | None = None) -> Outcome:
        """Resolve a dispatched effect; legal while RUNNING/STOPPING/UNCONFIRMED."""
        out = Outcome()
        arec = self.actions.get(action_id)
        if arec is None or arec.state != "DISPATCHED":
            return out
        if self.state not in ("RUNNING", "STOPPING", "UNCONFIRMED"):
            return out
        self.inflight -= 1
        if error is None and result is not None:
            arec.state = "SUCCEEDED"
            arec.result = result
            audit = self._audit(arec, "SUCCEEDED", exit_, result, None)
        else:
            arec.state = "FAILED"
            arec.error = error or "ACTION_FAILED"
            arec.result = result
            arec.exit = exit_
            audit = self._audit(arec, "FAILED", exit_, result, arec.error)
        out.events.append(("ActionFinished", {"action": audit}))
        return out

    def action_unknown(self, action_id: str, code: str) -> Outcome:
        out = Outcome()
        arec = self.actions.get(action_id)
        if arec is None or arec.state != "DISPATCHED":
            return out
        if self.state not in ("RUNNING", "STOPPING", "UNCONFIRMED"):
            return out
        self.inflight -= 1
        arec.state = "UNKNOWN"
        arec.error = code
        out.events.append(("ActionUnknown", {"action_id": action_id, "code": code}))
        return out

    @staticmethod
    def _audit(arec: ActionRec, state: str, exit_: dict | None, result: dict | None, error) -> dict:
        """Sanitized audit: no argv/env, no token, no HTTP body."""
        audit = {
            "action_id": arec.action_id,
            "state": state,
            "kind": arec.kind,
            "root_exit": exit_ if arec.kind == "spawn" else None,
            "http_status": result.get("status") if (arec.kind == "http_get" and result) else None,
            "body_hash": result.get("body_hash") if (arec.kind == "http_get" and result) else None,
            "error": error,
        }
        return audit

    # -- §5.2 compute lifecycle ------------------------------------------------

    def compute_reserve(self, channel_id: str, work: dict, now_us: int, compute_id: str, request_id: str) -> Outcome:
        from .schema import check_work

        if self.state != "RUNNING":
            return Outcome(error=LexwattError("STOPPED"))
        check_work(work)
        model = self._catalog.get(work["model_id"])
        if model is None:
            return self._deny(request_id, "UNSUPPORTED_MODEL")
        est = estimate_for_model_work(model, work)
        charge = int(est["charged_flops"])
        out = Outcome()
        if not self.admit_flops(charge):
            out = self._deny(request_id, "FLOPS_CAP")
            self._latch("FLOPS_CAP", out)
            return out
        self.charged_flops += charge
        res = {
            "compute_id": compute_id,
            "work": work,
            "charged_flops": scalars.u_str(charge),
            "state": "CHARGED",
            "observed_output_tokens": None,
            "observed_flops": None,
        }
        self.computes[compute_id] = ComputeRec(reservation=res, channel_id=channel_id)
        out.events.append(("ComputeReserved", {"reservation": res}))
        out.result = res
        return out

    def admit_flops(self, charge: int) -> bool:
        cap = self.budgets["max_flops"]
        if cap is None:
            return True
        return self.charged_flops + charge <= int(cap)

    def compute_finish(self, channel_id: str, compute_id: str, observed_output_tokens, request_id: str) -> Outcome:
        scalars.check_u(observed_output_tokens)
        rec = self.computes.get(compute_id)
        if rec is None:
            return self._deny(request_id, "NOT_FOUND")
        if rec.channel_id != channel_id:
            return self._deny(request_id, "UNAUTHORIZED")
        res = rec.reservation
        work = res["work"]
        model = self._catalog[work["model_id"]]
        observed = int(observed_output_tokens)
        if res["state"] == "FINISHED":
            if res["observed_output_tokens"] == observed_output_tokens:
                return Outcome(result=dict(res))  # exact idempotent finish
            if observed > int(work["max_output_tokens"]):
                out = self._deny(request_id, "ENVELOPE_EXCEEDED")
                self._latch("FLOPS_CAP", out)
                return out
            return self._deny(request_id, "CONFLICT")
        # CHARGED
        if self.state != "RUNNING":
            return Outcome(error=LexwattError("STOPPED"))
        if observed > int(work["max_output_tokens"]):
            out = self._deny(request_id, "ENVELOPE_EXCEEDED")
            self._latch("FLOPS_CAP", out)
            return out
        est = estimate_from_parts(
            model["kind"],
            int(model["parameters"]),
            model["layers"],
            model["hidden"],
            int(work["input_tokens"]),
            observed,
            work["batch"],
            model["safety_milli"],
        )
        res["state"] = "FINISHED"
        res["observed_output_tokens"] = observed_output_tokens
        res["observed_flops"] = est["charged_flops"]
        out = Outcome()
        out.events.append(("ComputeFinished", {"reservation": dict(res)}))
        out.result = dict(res)
        return out

    # -- stop / containment ---------------------------------------------------

    def stop(self, reason: str) -> Outcome:
        """Stop latch: first committed source wins; repeats are idempotent."""
        out = Outcome()
        if self.stop_reason is not None:
            out.result = {"state": self.state, "stop_reason": self.stop_reason}
            return out
        if self.state in ("ARMING", "RUNNING"):
            self._latch(reason, out)
        out.result = {"state": self.state, "stop_reason": self.stop_reason}
        return out

    def kill_issued(self, cgroup_attempted: bool, group_attempted: bool, now_us: int) -> Outcome:
        out = Outcome()
        if self.state in ("STOPPING", "UNCONFIRMED"):
            if self.kill_issued_at_us is None:
                self.kill_issued_at_us = now_us
            out.events.append(
                (
                    "KillIssued",
                    {
                        "cgroup_attempted": cgroup_attempted,
                        "group_attempted": group_attempted,
                    },
                )
            )
        return out

    def kill_unconfirmed(self, elapsed_us: int) -> Outcome:
        out = Outcome()
        if self.state == "STOPPING":
            self.state = "UNCONFIRMED"
            out.events.append(("KillUnconfirmed", {"elapsed_us": scalars.u_str(elapsed_us)}))
        return out

    def containment_empty(self, final_sample: dict | None, root_exit: dict | None) -> Outcome:
        out = Outcome()
        if self.state in ("STOPPING", "UNCONFIRMED"):
            self.state = "FINALIZING"
            if root_exit is not None:
                self.root_exit = root_exit
            out.events.append(
                (
                    "ContainmentEmpty",
                    {"final_sample": final_sample, "root_exit": self.root_exit},
                )
            )
        return out

    def finalize(self, coverage: dict, now_us: int) -> Outcome:
        """FINALIZING -> terminal; state depends on first stop source."""
        out = Outcome()
        if self.state != "FINALIZING":
            return out
        reason = self.stop_reason or "ROOT_EXIT"
        if reason in FAULT_REASONS:
            self._final_state = "FAILED"
        elif reason == "ROOT_EXIT":
            self._final_state = "COMPLETED"
        else:
            self._final_state = "KILLED"
        kill_latency = (
            scalars.u_str(self.kill_issued_at_us - self.stop_latched_us)
            if (self.kill_issued_at_us is not None and self.stop_latched_us is not None)
            else "0"
        )
        out.events.append(
            (
                "RunFinalized",
                {
                    "state": self._final_state,
                    "charged_flops": scalars.u_str(self.charged_flops),
                    "energy_uj": scalars.u_str(self.energy_uj) if self.energy_uj is not None else None,
                    "spawn_tokens_issued": self.spawn_issued,
                    "coverage": coverage,
                    "root_exit": self.root_exit,
                    "stop_reason": reason,
                    "kill_latency_us": kill_latency,
                    "closed_effects": True,
                },
            )
        )
        self.state = self._final_state
        return out

    def reject(self, code: str) -> Outcome:
        """CREATED/ARMING -> REJECTED; no workload exec ever occurred."""
        out = Outcome()
        if self.state in ("CREATED", "ARMING"):
            self.state = "REJECTED"
            self._final_state = "REJECTED"
            out.events.append(("RunRejected", {"code": code}))
        return out

    def fault(self, reason: str) -> Outcome:
        """Infrastructure fault: latch if live, FaultObserved if stopping."""
        out = Outcome()
        if self.state in ("ARMING", "RUNNING"):
            self._latch(reason, out)
        elif self.state in ("STOPPING", "UNCONFIRMED", "FINALIZING"):
            out.events.append(("FaultObserved", {"reason": reason}))
        return out


def choose_route(models: list, work_fields: dict, remaining_flops: int) -> dict:
    """Pure affordability hint: lowest estimated cost, then model ID in
    ASCII byte order; no reservation is made."""
    if len(models) > ROUTE_MAX_MODELS:
        raise LexwattError("INVALID_INPUT")
    best = None
    best_est = None
    for m in models:
        work = {
            "model_id": m["id"],
            "input_tokens": work_fields["input_tokens"],
            "max_output_tokens": work_fields["max_output_tokens"],
            "batch": work_fields["batch"],
        }
        try:
            est = estimate_for_model_work(m, work)
        except LexwattError:
            continue
        cost = int(est["charged_flops"])
        if cost > remaining_flops:
            continue
        if best is None or cost < int(best_est["charged_flops"]) or (
            cost == int(best_est["charged_flops"]) and m["id"].encode("ascii") < best["id"].encode("ascii")
        ):
            best, best_est = m, est
    if best is None:
        return {"model_id": None, "estimate": None}
    return {"model_id": best["id"], "estimate": best_est}
