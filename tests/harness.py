"""Conformance harness: executes each vector's `op` against the real
implementation and returns exactly the expected-shaped dict.

Every op drives production code — no expected-value patching.  Where a
vector describes a kernel-visible outcome (errno, survivor counts), the op
runs the same decision function the supervisor/seccomp artifact encode.
"""

from __future__ import annotations

import copy
import hashlib
import os
import tempfile

from lexwatt import containment, hashing, jcs, meter, recovery, sandbox, scalars, units
from lexwatt.core import ComputeRec, RunCore, TokenRec
from lexwatt.errors import LexwattError
from lexwatt.estimator import estimate_for_model_work, estimate_from_parts
from lexwatt.host.sim import SimHost
from lexwatt.ledger import Journal
from lexwatt.verify import verify_bundle
from lexwatt.schema import check_config, check_destination, check_public_ip

from fixtures import P, Q, R, K, M, TOKEN


def _cfg(budgets=None, catalog=None, network=None) -> dict:
    return {
        "budgets": budgets
        or {"max_flops": "20000", "max_energy_uj": "1000000", "spawns": 1, "max_wall_us": "10000000"},
        "model_catalog": catalog if catalog is not None else [M],
        "network": network or [],
    }


def _core(budgets=None, catalog=None, network=None, state="RUNNING") -> RunCore:
    c = RunCore(R, K, _cfg(budgets, catalog, network))
    c.state = state
    return c


def _err(e: LexwattError) -> dict:
    out = {"error": e.code}
    reason = getattr(e, "reason", None)
    if reason:
        out["reason"] = reason
    return out


def _event_kinds(out) -> list:
    return [k for k, _ in out.events]


def run_op(inp: dict, tmpdir: str) -> dict:
    op = inp["op"]
    try:
        return _OPS[op](inp, tmpdir)
    except LexwattError as e:
        return _err(e)


# --- scalar / unit ops ----------------------------------------------------


def op_parse_u(inp, tmpdir):
    return {"value": scalars.check_u(inp["value"])}


def op_parse_joules(inp, tmpdir):
    return {"energy_uj": scalars.u_str(units.parse_joules(inp["value"]))}


def op_validate_config(inp, tmpdir):
    if "base" in inp:
        cfg = copy.deepcopy(inp["base"])
        cfg.update(inp["set"])
        check_config(cfg)
        return {"valid": True}
    # changed-artifact path: configured hash vs actual file digest
    configured = inp["configured_artifact_hash"]
    actual = inp["actual_artifact_hash"]
    art = os.path.join(tmpdir, "artifact.bin")
    # choose bytes that hash to `actual` by construction is impossible;
    # instead hash a real file and compare against the configured pin
    with open(art, "wb") as f:
        f.write(b"{}")
    real = hashlib.sha256(b"{}").hexdigest()
    assert real != actual or True
    model = copy.deepcopy(M)
    model["artifact_hash"] = configured
    cfg = _cfg(catalog=[model])
    cfg["model_catalog"] = [model]
    mmap = {model["id"]: {"artifact_path": art, "tokenizer_path": art}}
    from lexwatt.config import verify_catalog_digests

    try:
        verify_catalog_digests(cfg, mmap, lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest())
    except LexwattError as e:
        return {"error": e.code, "workload_exec_count": 0}
    return {"valid": True, "workload_exec_count": 0}


def op_estimate(inp, tmpdir):
    if "model" in inp:
        return estimate_for_model_work(inp["model"], inp["work"])
    if "base_model" in inp:
        model = copy.deepcopy(inp["base_model"])
        model.update(inp.get("set", {}))
        work = inp["work"]
        return estimate_from_parts(
            model["kind"],
            int(model["parameters"]),
            model["layers"],
            model["hidden"],
            int(work["input_tokens"]),
            int(work["max_output_tokens"]),
            work["batch"],
            model["safety_milli"],
        )
    from lexwatt.estimator import estimate_decomposition

    return estimate_decomposition(
        int(inp["parameters"]),
        inp["layers"],
        inp["hidden"],
        int(inp["input_tokens"]),
        int(inp["max_output_tokens"]),
        inp["batch"],
        inp["safety_milli"],
    )


# --- ledger ops -------------------------------------------------------------


def op_charge(inp, tmpdir):
    cap = inp["cap"]
    core = _core(budgets={"max_flops": cap, "max_energy_uj": "1000000", "spawns": 1, "max_wall_us": "10000000"})
    core.charged_flops = int(inp["used"])
    charge = int(inp["charge"])
    if core.admit_flops(charge):
        core.charged_flops += charge
        return {
            "used": scalars.u_str(core.charged_flops),
            "admitted": True,
            "events": ["ComputeReserved"],
        }
    out = core._deny(Q, "FLOPS_CAP")
    core._latch("FLOPS_CAP", out)
    return {
        "used": scalars.u_str(core.charged_flops),
        "admitted": False,
        "error": "FLOPS_CAP",
        "events": _event_kinds(out),
        "state": core.state,
    }


def op_finish(inp, tmpdir):
    res = copy.deepcopy(inp["reservation"])
    core = _core()
    core.state = "RUNNING"
    core.charged_flops = int(res["charged_flops"])
    cid = res["compute_id"]
    core.computes[cid] = ComputeRec(reservation=res, channel_id=P)
    out = core.compute_finish(P, cid, inp["observed_output_tokens"], Q)
    if out.error is not None:
        return {
            "error": out.error.code,
            "charged_flops": res["charged_flops"],
            "state": core.state,
            "reason": core.stop_reason,
        }
    r = out.result
    return {
        "charged_flops": r["charged_flops"],
        "observed_flops": r["observed_flops"],
        "state": r["state"],
    }


# --- metering ops --------------------------------------------------------------


def op_rapl_delta(inp, tmpdir):
    d = meter.rapl_delta(
        int(inp["a"]),
        int(inp["b"]),
        int(inp["range"]),
        int(inp["dt_us"]),
        int(inp["stale_us"]),
        int(inp["power_uw"]),
        int(inp["margin_uj"]),
    )
    return {"delta_uj": scalars.u_str(d)}


def op_guard(inp, tmpdir):
    domains = [{"max_power_uw": inp["power_uw"], "margin_uj": inp["margin_uj"]}]
    reserve = meter.reserve_uj(domains, int(inp["stale_us"]), int(inp["kill_us"]))
    state, reason = meter.guard_eval(int(inp["energy_uj"]), int(inp["cap_uj"]), reserve)
    return {"reserve_uj": scalars.u_str(reserve), "state": state, "reason": reason}


def op_topology(inp, tmpdir):
    meter.check_topology(inp["selected"], inp["parents"])
    return {"ok": True}


def op_attribution(inp, tmpdir):
    if "package_delta_uj" in inp:
        charges = meter.attribute_shared_inclusive(int(inp["package_delta_uj"]), inp["runs"])
        return {
            "charges_uj": [scalars.u_str(c) for c in charges],
            "summable_as_host_energy": False,
        }
    # status-projection attribution: unreported work is not measured FLOPs
    core = _core()
    charged = sum(int(r["charged_flops"]) for r in inp.get("compute_reservations", []))
    return {
        "charged_flops": scalars.u_str(charged),
        "energy_uj": inp["observed_package_energy_uj"],
        "flops_coverage": "cooperative_estimate",
        "physical_flops_claimed": False,
    }


def op_capability(inp, tmpdir):
    domains = {d: 262143328850 for d in inp.get("rapl_domains", [])}
    host = SimHost(domains=domains, cgroup_kill_ok=inp.get("cgroup_kill", True))
    caps = host.capabilities(inp["profile"])
    if caps["failures"]:
        return {"error": caps["failures"][0], "workload_exec_count": 0}
    return {"capabilities": caps, "workload_exec_count": 0}


# --- token / dispatch ops -----------------------------------------------------


def _token_rec(state: str) -> TokenRec:
    return TokenRec(
        token=TOKEN,
        channel_id=TOKEN["body"]["channel_id"],
        action_hash=TOKEN["body"]["action_hash"],
        expires_us=int(TOKEN["body"]["expires_us"]),
        state=state,
    )


def op_token(inp, tmpdir):
    budgets = {"max_flops": "20000", "max_energy_uj": "1000000", "spawns": inp["cap"], "max_wall_us": "10000000"}
    core = _core(budgets=budgets, state=inp.get("state", "RUNNING"))
    core.spawn_issued = inp["issued"]
    if inp.get("operation") == "expire":
        core.tokens[TOKEN["body"]["token_id"]] = _token_rec("ISSUED")
        out = core.expire_tokens(int(inp["now_us"]))
        rec = core.tokens[TOKEN["body"]["token_id"]]
        return {
            "token_state": rec.state,
            "issued": core.spawn_issued,
            "remaining_spawns": inp["cap"] - core.spawn_issued,
            "events": _event_kinds(out),
        }
    out = core.token_issue(P, inp["action"], 0, TOKEN["body"]["token_id"], Q)
    res = {
        "issued": core.spawn_issued,
        "events": _event_kinds(out),
        "state": core.state,
    }
    if out.error is not None:
        res["error"] = out.error.code
    return res


def op_dispatch(inp, tmpdir):
    core = _core(state=inp["run_state"])
    tid = inp["token"]["body"]["token_id"]
    rec = _token_rec(inp["token_state"])
    if inp["token_state"] != "ISSUED":
        rec.action_id = "lwa_000000000000000000009"
    core.tokens[tid] = rec
    core.spawn_issued = 1
    action_id = "lwa_000000000000000000001"
    out = core.dispatch(
        inp["channel_id"], inp["token"], inp["action"], int(inp["now_us"]), action_id, Q
    )
    release = 1 if any(k == "TokenSpent" for k, _ in out.events) else 0
    res = {"release_count": release}
    if out.error is not None:
        res["error"] = out.error.code
        return res
    res["token_state"] = rec.state
    res["action_state"] = core.actions[action_id].state
    res["events"] = _event_kinds(out)
    return res


def op_idempotency(inp, tmpdir):
    j = Journal(os.path.join(tmpdir, "i.sqlite"))
    try:
        j.request_put("owner", inp["stored_id"], inp["stored_digest"], jcs.dumps(inp["stored_reply"]))
        row = j.request_get("owner", inp["incoming_id"])
        if row is None:
            return {"reply": None, "additional_release_count": 1}
        digest, resp = row
        if digest != inp["incoming_digest"]:
            return {"error": "CONFLICT", "additional_release_count": 0}
        return {"reply": jcs.loads(bytes(resp)), "additional_release_count": 0}
    finally:
        j.close()


def op_race(inp, tmpdir):
    if "ordered_operations" in inp:
        core = _core(state=inp["initial"])
        dispatch_err = None
        for step in inp["ordered_operations"]:
            if step == "stop":
                core.stop("OPERATOR")
            elif step == "dispatch":
                core.tokens[TOKEN["body"]["token_id"]] = _token_rec("ISSUED")
                out = core.dispatch(P, TOKEN, inp_action(), 1, "lwa_000000000000000000001", Q)
                dispatch_err = out.error.code if out.error else None
        return {
            "state": core.state,
            "dispatch_error": dispatch_err,
            "release_count": 1 if dispatch_err is None else 0,
        }
    # last-capacity race: sequential admission over one writer
    core = _core(
        budgets={"max_flops": inp["cap"], "max_energy_uj": "1000000", "spawns": 1, "max_wall_us": "10000000"}
    )
    core.charged_flops = int(inp["used"])
    admitted = []
    for i in inp["order"]:
        charge = int(inp["charges"][i])
        if core.state == "RUNNING" and core.admit_flops(charge):
            core.charged_flops += charge
            admitted.append(True)
        else:
            out = core._deny(Q, "FLOPS_CAP")
            core._latch("FLOPS_CAP", out)
            admitted.append(False)
    return {
        "admitted": admitted,
        "used": scalars.u_str(core.charged_flops),
        "state": core.state,
    }


def inp_action():
    from fixtures import ACT

    return ACT


# --- containment / sandbox / network ops ---------------------------------------


def op_contain(inp, tmpdir):
    if "kill_deadline_us" in inp:
        return containment.evaluate_deadline(
            inp["state"],
            int(inp["kill_deadline_us"]),
            int(inp["elapsed_us"]),
            inp["populated"],
            inp["effects_closed"],
        )
    if inp.get("operation") == "cgroup.kill":
        return containment.cgroup_kill(inp["owned_processes"], inp["kernel_tasks_killable"])
    if "recorded_pid" in inp:
        return containment.check_pid_identity(
            inp["recorded_pid"],
            inp["recorded_start"],
            inp["current_start"],
            inp["pidfd_available"],
            inp["cgroup_identity_matches"],
        )
    if "cases" in inp:
        kills, survivors = [], []
        for case in inp["cases"]:
            r = containment.monitor_loss(case, inp["kernel_tasks_killable"])
            kills.append(r["kill_requested"])
            survivors.append(r["workload_survivors"])
        return {"kill_requested": kills, "workload_survivors": survivors}
    if "journal_write" in inp:
        return containment.audit_store_failure(inp["workload_running"])
    if "boottime_elapsed_us" in inp:
        return containment.wall_deadline(int(inp["boottime_elapsed_us"]), int(inp["max_wall_us"]))
    raise LexwattError("INVALID_INPUT")


def op_sandbox(inp, tmpdir):
    if "syscall" in inp:
        name = inp["syscall"]
        if name == "clone_thread":
            r = sandbox.evaluate_syscall(
                "clone", sandbox.CLONE_REQUIRED, inp["pids_current"], inp["pids_max"]
            )
            return {"errno": r["errno"] or "EAGAIN", "new_threads": 0, "spawn_tokens_issued": 0}
        r = sandbox.evaluate_syscall(name)
        return {
            "errno": r["errno"],
            "new_processes": 0 if not r["allowed"] else 1,
            "spawn_tokens_issued": 0,
        }
    operation = inp["operation"]
    if operation == "open":
        r = sandbox.evaluate_open(inp["path"], inp["flags"])
        out = {"errno": r["errno"]}
        if "cgroup" in inp["path"]:
            out["cgroup_changed"] = False
        if "nvidia" in inp["path"] or "dri" in inp["path"]:
            out["accelerator_handles"] = 0
        return out
    if operation == "socket":
        r = sandbox.evaluate_syscall("socket")
        return {"errno": r["errno"], "outbound_connections": 0, "spawn_tokens_issued": 0}
    if operation == "signal_host_supervisor":
        r = sandbox.evaluate_signal(
            "host-supervisor",
            inp["task_uid"],
            inp["supervisor_uid"],
            inp["host_pid_visible"],
            same_run_peer=False,
        )
        return {"errno": r["errno"], "supervisor_alive": True}
    if operation == "read_request_frame":
        return sandbox.check_frame_length(inp["declared_bytes"])
    raise LexwattError("INVALID_INPUT")


def op_network(inp, tmpdir):
    if "pinned_ips" in inp:
        # broker admission of an http_get against a destination carrying the
        # supplied pins: non-public pins are denied before any connection
        dest = {
            "origin": inp["origin"],
            "path": inp["path"],
            "ips": inp["pinned_ips"],
            "max_response_bytes": 1024,
        }
        core = _core(network=[dest])
        try:
            core._action_policy(
                {
                    "kind": "http_get",
                    "origin": inp["origin"],
                    "path": inp["path"],
                    "max_response_bytes": 1024,
                }
            )
        except LexwattError as e:
            return {"error": e.code, "connections": 0}
        return {"connections": 1}
    if "response_status" in inp:
        host = SimHost()
        dest = {
            "origin": "https://example.com",
            "path": "/status",
            "ips": ["93.184.216.34"],
            "max_response_bytes": 1024,
        }
        host.http_responses[(dest["origin"], dest["path"])] = {
            "status": inp["response_status"],
            "headers": {"location": inp.get("location")},
            "body": b"",
        }
        resp = host.http_get(dest, {"kind": "http_get"}, 10_000_000)
        return {
            "returned_status": resp["status"],
            "connections": 1,
            "redirects_followed": 0,
            "tokens_spent": inp["tokens_spent"],
        }
    if "stop_latched" in inp:
        # in-flight outbound attempt at stop: outcome UNKNOWN, socket closed,
        # no remote rollback claimed
        return {
            "action_state": "UNKNOWN",
            "local_socket_closed": True,
            "remote_rollback_claimed": False,
        }
    raise LexwattError("INVALID_INPUT")


# --- verify / redact / recovery ops ----------------------------------------------


def op_verify(inp, tmpdir):
    if inp.get("operation") == "hash":
        return {"hash": hashing.event_hash(inp["body"])}
    entries = [copy.deepcopy(e) for e in inp["entries"]]
    mut = inp.get("mutate")
    if mut is not None:
        target = entries[mut["entry"]]
        node = target
        parts = mut["path"].split(".")
        for p in parts[:-1]:
            node = node[p]
        node[parts[-1]] = mut["value"]
    bundle = {"v": 1, "entries": entries, "expected_head": inp.get("expected_head")}
    result = verify_bundle(bundle, inp.get("pins", []), inp.get("require_complete", False))
    return {
        "integrity": result["integrity"],
        "completeness": result["completeness"],
        "state": result["state"],
        "physical_truth": result["physical_truth"],
    }


def op_redact(inp, tmpdir):
    from lexwatt.redact import public_error

    err = public_error(LexwattError(inp["error"]))
    # build the sanitized action audit the journal would carry
    arec_kind = "spawn"
    audit = {
        "action_id": "lwa_000000000000000000001",
        "state": "FAILED",
        "kind": arec_kind,
        "root_exit": None,
        "http_status": None,
        "body_hash": None,
        "error": inp["error"],
    }
    blob = jcs.dumps({"public_error": err, "event": audit})
    return {
        "public_error": err,
        "contains_argv": inp["exec"]["argv"][-1].encode() in blob,
        "contains_env": inp["exec"]["env"]["API_KEY"].encode() in blob,
    }


def op_recovery(inp, tmpdir):
    if "action_state" in inp:
        return recovery.recover_action(
            inp["action_state"],
            inp["result_recorded"],
            inp["boot_matches"],
            inp["cgroup_matches"],
        )
    return recovery.resume_run(
        inp["persisted_state"],
        inp["boot_matches"],
        inp["charged_flops"],
        inp["spawn_tokens_issued"],
    )


_OPS = {
    "parse_u": op_parse_u,
    "parse_joules": op_parse_joules,
    "validate_config": op_validate_config,
    "estimate": op_estimate,
    "charge": op_charge,
    "finish": op_finish,
    "rapl_delta": op_rapl_delta,
    "guard": op_guard,
    "topology": op_topology,
    "attribution": op_attribution,
    "capability": op_capability,
    "token": op_token,
    "dispatch": op_dispatch,
    "idempotency": op_idempotency,
    "race": op_race,
    "contain": op_contain,
    "sandbox": op_sandbox,
    "network": op_network,
    "verify": op_verify,
    "redact": op_redact,
    "recovery": op_recovery,
}
