"""Closed-world wire schema validators (spec §4.1).

Every field shown in the §4.1 algebra is required, including explicit nulls;
unexpected fields are UNKNOWN_FIELD; malformed values are INVALID_INPUT.
"""

from __future__ import annotations

import ipaddress
import re

from .errors import (
    CODES,
    EVENT_KINDS,
    METHODS,
    REASONS,
    STATES,
    LexwattError,
)
from .scalars import (
    check_body_b64,
    check_env_key,
    check_hash,
    check_id,
    check_model_name,
    check_path,
    check_public_key,
    check_signature,
    check_text,
    check_u,
    parse_u,
)

_HOST_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_CPULIST_RE = re.compile(r"^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$")


def _is_obj(v) -> dict:
    if not isinstance(v, dict):
        raise LexwattError("INVALID_INPUT")
    return v


def _is_arr(v) -> list:
    if not isinstance(v, list):
        raise LexwattError("INVALID_INPUT")
    return v


def _is_bool(v) -> bool:
    if not isinstance(v, bool):
        raise LexwattError("INVALID_INPUT")
    return v


def _is_int_or_null(v):
    if v is None:
        return None
    return _is_int(v)


def _is_int(v) -> int:
    # JSON integers only; bool is not an int here
    if not isinstance(v, int) or isinstance(v, bool):
        raise LexwattError("INVALID_INPUT")
    if abs(v) > 2147483647:
        raise LexwattError("INVALID_INPUT")
    return v


def _int_range(v, lo: int, hi: int) -> int:
    v = _is_int(v)
    if not (lo <= v <= hi):
        raise LexwattError("INVALID_INPUT")
    return v


def _enum(v, allowed) -> str:
    if not isinstance(v, str) or v not in allowed:
        raise LexwattError("INVALID_INPUT")
    return v


def _closed(obj: dict, fields: dict) -> dict:
    """Closed-object check: all fields required, none extra."""
    _is_obj(obj)
    for k in obj:
        if k not in fields:
            raise LexwattError("UNKNOWN_FIELD")
    for k, fn in fields.items():
        if k not in obj:
            raise LexwattError("INVALID_INPUT")
        fn(obj[k])
    return obj


def check_version(v, expected: int = 1) -> int:
    """``v`` mismatch is UNSUPPORTED_VERSION (spec §6)."""
    if not isinstance(v, int) or isinstance(v, bool):
        raise LexwattError("INVALID_INPUT")
    if v != expected:
        raise LexwattError("UNSUPPORTED_VERSION")
    return v


def check_u_or_null(v):
    if v is None:
        return None
    return check_u(v)


# --- scalars-as-objects -------------------------------------------------


def check_head(v) -> dict:
    return _closed(v, {"seq": check_u, "hash": check_hash})


def check_exit(v) -> dict:
    _closed(v, {"code": _is_int_or_null, "signal": _is_int_or_null})
    code, sig = v["code"], v["signal"]
    if (code is None) == (sig is None):
        raise LexwattError("INVALID_INPUT")
    if code is not None and not (0 <= code <= 255):
        raise LexwattError("INVALID_INPUT")
    if sig is not None and not (1 <= sig <= 64):
        raise LexwattError("INVALID_INPUT")
    return v


def check_exit_or_null(v):
    if v is None:
        return None
    return check_exit(v)


# --- configuration ------------------------------------------------------


def check_budget(v) -> dict:
    _closed(
        v,
        {"max_flops": check_u_or_null, "max_energy_uj": check_u_or_null, "spawns": _is_int, "max_wall_us": check_u},
    )
    _int_range(v["spawns"], 0, 1024)
    wall = parse_u(v["max_wall_us"])
    if not (1000 <= wall <= 86400000000):
        raise LexwattError("INVALID_INPUT")
    return v


def check_model(v) -> dict:
    _closed(
        v,
        {
            "id": check_model_name,
            "kind": lambda x: _enum(x, ("dense-v1",)),
            "parameters": check_u,
            "layers": _is_int,
            "hidden": _is_int,
            "tokenizer_hash": check_hash,
            "artifact_hash": check_hash,
            "safety_milli": _is_int,
        },
    )
    from .estimator import check_model_dims

    check_model_dims(parse_u(v["parameters"]), v["layers"], v["hidden"], v["safety_milli"])
    return v


def check_work(v) -> dict:
    _closed(
        v,
        {
            "model_id": check_model_name,
            "input_tokens": check_u,
            "max_output_tokens": check_u,
            "batch": _is_int,
        },
    )
    from .estimator import check_work_dims

    check_work_dims(parse_u(v["input_tokens"]), parse_u(v["max_output_tokens"]), v["batch"])
    return v


def check_estimate(v) -> dict:
    _closed(
        v,
        {
            "estimator": lambda x: _enum(x, ("dense-v1",)),
            "base_flops": check_u,
            "attention_flops": check_u,
            "charged_flops": check_u,
            "coverage": lambda x: _enum(x, ("cooperative_estimate",)),
        },
    )
    return v


def check_exec(v) -> dict:
    _closed(
        v,
        {
            "argv": lambda x: _is_arr(x),
            "cwd": check_path,
            "env": _is_obj,
        },
    )
    argv = v["argv"]
    if not (1 <= len(argv) <= 256):
        raise LexwattError("INVALID_INPUT")
    total = 0
    for a in argv:
        check_text(a, 4096)
        total += len(a.encode("utf-8"))
    if total > 32768:
        raise LexwattError("INVALID_INPUT")
    if not argv[0].startswith("/"):
        raise LexwattError("INVALID_INPUT")
    env = v["env"]
    if len(env) > 64:
        raise LexwattError("INVALID_INPUT")
    esize = 0
    for k, val in env.items():
        check_env_key(k)
        check_text(val)
        esize += len(k) + 1 + len(val.encode("utf-8"))
    if esize > 16384:
        raise LexwattError("INVALID_INPUT")
    return v


def check_origin(v) -> str:
    """Canonical https:// DNS hostname, implicit 443, no extras."""
    check_text(v)
    if not v.startswith("https://"):
        raise LexwattError("INVALID_INPUT")
    host = v[len("https://") :]
    if not host or len(host) > 253 or "/" in host or ":" in host or "@" in host:
        raise LexwattError("INVALID_INPUT")
    labels = host.split(".")
    for lab in labels:
        if not _HOST_LABEL_RE.match(lab):
            raise LexwattError("INVALID_INPUT")
    try:  # literal IPs are forbidden
        ipaddress.ip_address(host)
        raise LexwattError("INVALID_INPUT")
    except ValueError:
        pass
    return v


def check_http_path(v) -> str:
    """ASCII origin-form: /-prefixed, no query/%/backslash/dot/dup-slash."""
    if not isinstance(v, str) or not v.startswith("/") or len(v) > 1024:
        raise LexwattError("INVALID_INPUT")
    if not v.isascii() or "?" in v or "%" in v or "\\" in v or "//" in v:
        raise LexwattError("INVALID_INPUT")
    for seg in v.split("/"):
        if seg in (".", ".."):
            raise LexwattError("INVALID_INPUT")
    return v


def check_public_ip(v) -> str:
    if not isinstance(v, str):
        raise LexwattError("INVALID_INPUT")
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        raise LexwattError("INVALID_INPUT")
    if not ip.is_global:
        raise LexwattError("INVALID_INPUT")
    return v


def ip_sort_key(ip_text: str):
    ip = ipaddress.ip_address(ip_text)
    return (0 if ip.version == 4 else 1, int(ip))


def check_destination(v) -> dict:
    _closed(
        v,
        {
            "origin": check_origin,
            "path": check_http_path,
            "ips": _is_arr,
            "max_response_bytes": _is_int,
        },
    )
    ips = v["ips"]
    if not (1 <= len(ips) <= 16):
        raise LexwattError("INVALID_INPUT")
    canon = [str(ipaddress.ip_address(check_public_ip(x))) for x in ips]
    if sorted(canon, key=ip_sort_key) != canon:
        raise LexwattError("INVALID_INPUT")
    if len(set(canon)) != len(canon):
        raise LexwattError("INVALID_INPUT")
    v["ips"][:] = canon
    _int_range(v["max_response_bytes"], 1, 262144)
    return v


def check_meter(v) -> dict:
    _closed(
        v,
        {"interval_us": check_u, "stale_us": check_u, "kill_deadline_us": check_u},
    )
    interval = parse_u(v["interval_us"])
    stale = parse_u(v["stale_us"])
    kill = parse_u(v["kill_deadline_us"])
    if not (10000 <= interval <= 1000000):
        raise LexwattError("INVALID_INPUT")
    if not (2 * interval <= stale <= 5000000):
        raise LexwattError("INVALID_INPUT")
    if not (1000 <= kill <= 5000000):
        raise LexwattError("INVALID_INPUT")
    return v


def check_config(v) -> dict:
    _closed(
        v,
        {
            "v": lambda x: check_version(x),
            "profile": lambda x: _enum(x, ("linux-rapl-v1", "linux-ledger-v1")),
            "workspace_root": check_path,
            "budgets": check_budget,
            "meter": check_meter,
            "pids_max": _is_int,
            "memory_max_bytes": check_u,
            "log_max_bytes": check_u,
            "model_catalog": _is_arr,
            "network": _is_arr,
            "flops_trust": lambda x: _enum(x, ("cooperative",)),
        },
    )
    _int_range(v["pids_max"], 2, 4096)
    if parse_u(v["memory_max_bytes"]) < 67108864:
        raise LexwattError("INVALID_INPUT")
    if not (4194304 <= parse_u(v["log_max_bytes"]) <= 1073741824):
        raise LexwattError("INVALID_INPUT")
    cat = v["model_catalog"]
    if len(cat) > 32:
        raise LexwattError("INVALID_INPUT")
    ids = set()
    for m in cat:
        check_model(m)
        if m["id"] in ids:
            raise LexwattError("INVALID_INPUT")
        ids.add(m["id"])
    net = v["network"]
    if len(net) > 32:
        raise LexwattError("INVALID_INPUT")
    pairs = set()
    for d in net:
        check_destination(d)
        if (d["origin"], d["path"]) in pairs:
            raise LexwattError("INVALID_INPUT")
        pairs.add((d["origin"], d["path"]))
    budgets = v["budgets"]
    if budgets["max_flops"] is None and budgets["max_energy_uj"] is None:
        raise LexwattError("INVALID_INPUT")
    if v["profile"] == "linux-rapl-v1" and budgets["max_energy_uj"] is None:
        raise LexwattError("INVALID_INPUT")
    if v["profile"] == "linux-ledger-v1" and budgets["max_energy_uj"] is not None:
        raise LexwattError("INVALID_INPUT")
    if budgets["max_flops"] is not None and parse_u(budgets["max_flops"]) == 0:
        raise LexwattError("BUDGET_TOO_SMALL")
    if budgets["max_energy_uj"] is not None and parse_u(budgets["max_energy_uj"]) == 0:
        raise LexwattError("BUDGET_TOO_SMALL")
    if budgets["max_flops"] is not None and len(cat) == 0:
        raise LexwattError("INVALID_INPUT")
    return v


def check_cpus(v) -> str:
    if not isinstance(v, str) or not _CPULIST_RE.match(v):
        raise LexwattError("INVALID_INPUT")
    for part in v.split(","):
        if "-" in part:
            a, b = part.split("-")
            if int(a) > int(b):
                raise LexwattError("INVALID_INPUT")
    return v


def check_domain_policy(v) -> dict:
    _closed(
        v,
        {
            "id": check_text,
            "sysfs_dir": check_path,
            "cpus": check_cpus,
            "max_power_uw": check_u,
            "margin_uj": check_u,
        },
    )
    return v


def check_host_policy(v) -> dict:
    _closed(
        v,
        {
            "v": lambda x: check_version(x),
            "runtime_image": check_path,
            "workspace_roots": _is_arr,
            "state_root": check_path,
            "task_uid_min": _is_int,
            "task_uid_max": _is_int,
            "domains": _is_arr,
        },
    )
    roots = v["workspace_roots"]
    if not (1 <= len(roots) <= 32):
        raise LexwattError("INVALID_INPUT")
    seen = set()
    for r in roots:
        check_path(r)
        if r in seen:
            raise LexwattError("INVALID_INPUT")
        seen.add(r)
    lo, hi = v["task_uid_min"], v["task_uid_max"]
    if not (1000 <= lo <= hi <= 2147483647):
        raise LexwattError("INVALID_INPUT")
    domains = v["domains"]
    if len(domains) > 64:
        raise LexwattError("INVALID_INPUT")
    ids = set()
    for d in domains:
        check_domain_policy(d)
        if d["id"] in ids:
            raise LexwattError("INVALID_INPUT")
        ids.add(d["id"])
    return v


def check_capabilities(v) -> dict:
    _closed(
        v,
        {
            "profile": lambda x: _enum(x, ("linux-rapl-v1", "linux-ledger-v1", "offline-v1")),
            "cgroup_kill": _is_bool,
            "task_uid_isolation": _is_bool,
            "seccomp": _is_bool,
            "namespaces": _is_bool,
            "rapl_domains": _is_arr,
            "failures": _is_arr,
        },
    )
    for d in v["rapl_domains"]:
        check_text(d)
    for c in v["failures"]:
        _enum(c, CODES)
    return v


# --- actions, tokens, compute -------------------------------------------


def check_action(v) -> dict:
    _is_obj(v)
    kind = v.get("kind")
    if kind == "spawn":
        _closed(v, {"kind": _is_obj_or_str, "exec": check_exec})
    elif kind == "http_get":
        _closed(
            v,
            {
                "kind": _is_obj_or_str,
                "origin": check_origin,
                "path": check_http_path,
                "max_response_bytes": _is_int,
            },
        )
        _int_range(v["max_response_bytes"], 1, 262144)
    else:
        raise LexwattError("INVALID_INPUT")
    return v


def _is_obj_or_str(v):
    if not isinstance(v, (dict, str)):
        raise LexwattError("INVALID_INPUT")
    return v


def check_token_body(v) -> dict:
    return _closed(
        v,
        {
            "v": lambda x: check_version(x),
            "key_id": lambda x: check_id(x, "key"),
            "token_id": lambda x: check_id(x, "token"),
            "run_id": lambda x: check_id(x, "run"),
            "channel_id": lambda x: check_id(x, "channel"),
            "action_hash": check_hash,
            "issued_us": check_u,
            "expires_us": check_u,
            "issue_seq": check_u,
        },
    )


def check_token(v) -> dict:
    _closed(v, {"body": check_token_body, "sig": check_signature})
    from . import jcs

    if len(jcs.dumps(v)) > 8192:
        raise LexwattError("INVALID_INPUT")
    return v


def check_action_result(v) -> dict:
    _is_obj(v)
    kind = v.get("kind")
    if kind == "spawn":
        _closed(v, {"kind": _is_obj_or_str, "exit": check_exit_or_null})
    elif kind == "http_get":
        _closed(
            v,
            {
                "kind": _is_obj_or_str,
                "status": _is_int,
                "body_b64": check_body_b64,
                "body_hash": check_hash,
                "truncated": _is_bool,
            },
        )
        _int_range(v["status"], 100, 599)
        if v["truncated"] is not False:
            raise LexwattError("INVALID_INPUT")
    else:
        raise LexwattError("INVALID_INPUT")
    return v


def check_action_view(v) -> dict:
    _closed(
        v,
        {
            "action_id": lambda x: check_id(x, "action"),
            "state": lambda x: _enum(x, ("DISPATCHED", "SUCCEEDED", "FAILED", "UNKNOWN")),
            "result": lambda x: None if x is None else check_action_result(x),
            "error": lambda x: None if x is None else _enum(x, CODES),
        },
    )
    st, res, err = v["state"], v["result"], v["error"]
    if st == "DISPATCHED" and (res is not None or err is not None):
        raise LexwattError("INVALID_INPUT")
    if st == "UNKNOWN" and (res is not None or err is None):
        raise LexwattError("INVALID_INPUT")
    if st == "SUCCEEDED" and (res is None or err is not None):
        raise LexwattError("INVALID_INPUT")
    if st == "FAILED" and err is None:
        raise LexwattError("INVALID_INPUT")
    return v


def check_reservation(v) -> dict:
    _closed(
        v,
        {
            "compute_id": lambda x: check_id(x, "compute"),
            "work": check_work,
            "charged_flops": check_u,
            "state": lambda x: _enum(x, ("CHARGED", "FINISHED")),
            "observed_output_tokens": check_u_or_null,
            "observed_flops": check_u_or_null,
        },
    )
    finished = v["state"] == "FINISHED"
    have = v["observed_output_tokens"] is not None and v["observed_flops"] is not None
    if finished != have:
        raise LexwattError("INVALID_INPUT")
    return v


# --- evidence / receipt ---------------------------------------------------


def check_pin(v) -> dict:
    return _closed(
        v, {"key_id": lambda x: check_id(x, "key"), "public_key": check_public_key}
    )


def check_coverage(v) -> dict:
    _closed(
        v,
        {
            "flops": lambda x: _enum(x, ("cooperative_estimate",)),
            "energy": lambda x: _enum(x, ("package_measured", "unavailable")),
            "domains": _is_arr,
            "energy_complete": _is_bool,
            "reserve_uj": check_u,
            "host_power_assumption": _is_bool,
            "assumptions": lambda x: None if x is None else check_energy_assumptions(x),
        },
    )
    for d in v["domains"]:
        check_text(d)
    if v["energy"] == "package_measured":
        if v["assumptions"] is None:
            raise LexwattError("INVALID_INPUT")
        power_domains = sorted(p["domain"] for p in v["assumptions"]["power"])
        if power_domains != sorted(v["domains"]):
            raise LexwattError("INVALID_INPUT")
    else:
        if v["assumptions"] is not None:
            raise LexwattError("INVALID_INPUT")
        if v["domains"] != [] or v["reserve_uj"] != "0":
            raise LexwattError("INVALID_INPUT")
    return v


def check_power_assumption(v) -> dict:
    return _closed(
        v, {"domain": check_text, "max_power_uw": check_u, "margin_uj": check_u}
    )


def check_energy_assumptions(v) -> dict:
    _closed(v, {"meter": check_meter, "power": _is_arr})
    for p in v["power"]:
        check_power_assumption(p)
    return v


def check_reading(v) -> dict:
    return _closed(
        v,
        {
            "domain": check_text,
            "counter_uj": check_u,
            "range_uj": check_u,
            "read_t_us": check_u,
        },
    )


def check_sample(v) -> dict:
    _closed(
        v,
        {
            "index": check_u,
            "t_us": check_u,
            "cpu_us": check_u,
            "readings": _is_arr,
            "delta_uj": check_u,
            "total_uj": check_u,
            "max_gap_us": check_u,
        },
    )
    for r in v["readings"]:
        check_reading(r)
    return v


def check_status(v) -> dict:
    _closed(
        v,
        {
            "run_id": lambda x: check_id(x, "run"),
            "state": lambda x: _enum(x, STATES),
            "budgets": check_budget,
            "charged_flops": check_u,
            "energy_uj": check_u_or_null,
            "spawn_tokens_issued": _is_int,
            "elapsed_us": check_u,
            "root_exit": check_exit_or_null,
            "stop_reason": lambda x: None if x is None else _enum(x, REASONS),
            "coverage": check_coverage,
            "head": check_head,
        },
    )
    return v


def check_action_audit(v) -> dict:
    return _closed(
        v,
        {
            "action_id": lambda x: check_id(x, "action"),
            "state": lambda x: _enum(x, ("SUCCEEDED", "FAILED")),
            "kind": lambda x: _enum(x, ("spawn", "http_get")),
            "root_exit": check_exit_or_null,
            "http_status": lambda x: None if x is None else _int_range(x, 100, 599),
            "body_hash": lambda x: None if x is None else check_hash(x),
            "error": lambda x: None if x is None else _enum(x, CODES),
        },
    )


def check_event_body(v) -> dict:
    """Validate an EventBody: shape + kind-specific data payload."""
    _is_obj(v)
    if "kind" not in v:
        raise LexwattError("INVALID_INPUT")
    kind = v["kind"]
    if kind not in EVENT_KINDS:
        raise LexwattError("INVALID_INPUT")
    _closed(
        v,
        {
            "v": lambda x: check_version(x),
            "run_id": lambda x: check_id(x, "run"),
            "event_id": lambda x: check_id(x, "event"),
            "key_id": lambda x: check_id(x, "key"),
            "seq": check_u,
            "prev_hash": check_hash,
            "t_us": check_u,
            "kind": _is_obj_or_str,
            "data": _is_obj,
        },
    )
    _check_event_data(kind, v["data"])
    return v


def _check_event_data(kind: str, d: dict) -> None:
    if kind == "RunCreated":
        _closed(d, {"config_hash": check_hash})
    elif kind == "RunArming":
        _closed(d, {"profile": lambda x: _enum(x, ("linux-rapl-v1", "linux-ledger-v1"))})
    elif kind == "RunStarted":
        _closed(
            d,
            {
                "budgets": check_budget,
                "models": _is_arr,
                "coverage": check_coverage,
                "baseline": check_sample,
            },
        )
        for m in d["models"]:
            check_model(m)
    elif kind == "RunRejected":
        _closed(d, {"code": lambda x: _enum(x, CODES)})
    elif kind == "SampleRecorded":
        _closed(d, {"sample": check_sample})
    elif kind == "ComputeReserved" or kind == "ComputeFinished":
        _closed(d, {"reservation": check_reservation})
    elif kind == "TokenIssued":
        _closed(
            d,
            {
                "token_id": lambda x: check_id(x, "token"),
                "channel_id": lambda x: check_id(x, "channel"),
                "kind": lambda x: _enum(x, ("spawn", "http_get")),
                "action_hash": check_hash,
                "issued_us": check_u,
                "expires_us": check_u,
                "issue_seq": check_u,
            },
        )
    elif kind == "TokenExpired":
        _closed(d, {"token_id": lambda x: check_id(x, "token")})
    elif kind == "TokenSpent":
        _closed(
            d,
            {
                "token_id": lambda x: check_id(x, "token"),
                "action_id": lambda x: check_id(x, "action"),
            },
        )
    elif kind == "ActionFinished":
        _closed(d, {"action": check_action_audit})
    elif kind == "ActionUnknown":
        _closed(
            d,
            {
                "action_id": lambda x: check_id(x, "action"),
                "code": lambda x: _enum(x, CODES),
            },
        )
    elif kind == "RequestDenied":
        _closed(
            d,
            {
                "request_id": lambda x: check_id(x, "request"),
                "code": lambda x: _enum(x, CODES),
            },
        )
    elif kind == "StopLatched":
        _closed(d, {"reason": lambda x: _enum(x, REASONS)})
    elif kind == "FaultObserved":
        _closed(d, {"reason": lambda x: _enum(x, REASONS)})
    elif kind == "KillIssued":
        _closed(d, {"cgroup_attempted": _is_bool, "group_attempted": _is_bool})
    elif kind == "KillUnconfirmed":
        _closed(d, {"elapsed_us": check_u})
    elif kind == "ContainmentEmpty":
        _closed(
            d,
            {
                "final_sample": lambda x: None if x is None else check_sample(x),
                "root_exit": check_exit_or_null,
            },
        )
    elif kind == "RunFinalized":
        _closed(
            d,
            {
                "state": lambda x: _enum(x, ("COMPLETED", "KILLED", "FAILED")),
                "charged_flops": check_u,
                "energy_uj": check_u_or_null,
                "spawn_tokens_issued": _is_int,
                "coverage": check_coverage,
                "root_exit": check_exit_or_null,
                "stop_reason": lambda x: _enum(x, REASONS),
                "kill_latency_us": check_u,
                "closed_effects": _is_bool,
            },
        )


def check_entry(v) -> dict:
    _closed(
        v,
        {
            "body": check_event_body,
            "hash": check_hash,
            "sig": check_signature,
        },
    )
    return v


def check_bundle(v) -> dict:
    _closed(
        v,
        {
            "v": lambda x: check_version(x),
            "entries": _is_arr,
            "expected_head": lambda x: None if x is None else check_head(x),
        },
    )
    if len(v["entries"]) > 1000000:
        raise LexwattError("INVALID_INPUT")
    for e in v["entries"]:
        check_entry(e)
    return v


def check_verify_result(v) -> dict:
    return _closed(
        v,
        {
            "integrity": lambda x: _enum(x, ("VALID",)),
            "completeness": lambda x: _enum(x, ("COMPLETE", "PREFIX")),
            "physical_truth": lambda x: _enum(x, ("NOT_ATTESTED",)),
            "head": check_head,
            "state": lambda x: _enum(x, STATES),
        },
    )


# --- outcomes and misc ----------------------------------------------------


def check_model_file(v) -> dict:
    return _closed(
        v,
        {
            "model_id": check_model_name,
            "artifact_path": check_path,
            "tokenizer_path": check_path,
        },
    )


def check_launch_manifest(v) -> dict:
    _closed(
        v,
        {
            "v": lambda x: check_version(x),
            "run_id": lambda x: check_id(x, "run"),
            "config_hash": check_hash,
            "host_policy_hash": check_hash,
            "boot_id": check_text,
            "cgroup_inode": check_u,
            "cgroup_path": check_path,
            "task_uid": _is_int,
            "owner_uid": _is_int,
            "root_exec_hash": check_hash,
            "model_files": _is_arr,
        },
    )
    if v["owner_uid"] != 0:
        raise LexwattError("INVALID_INPUT")
    for f in v["model_files"]:
        check_model_file(f)
    return v


def check_emergency(v) -> dict:
    return _closed(
        v,
        {
            "v": lambda x: check_version(x),
            "run_id": lambda x: check_id(x, "run"),
            "last_head": check_head,
            "reason": lambda x: _enum(x, REASONS),
            "kill_attempted": _is_bool,
            "empty_observed": _is_bool,
            "boot_id": check_text,
        },
    )


def check_run_outcome(v) -> dict:
    _closed(
        v,
        {
            "v": lambda x: check_version(x),
            "run_id": lambda x: check_id(x, "run"),
            "state": lambda x: _enum(x, STATES),
            "exit_code": _is_int,
            "root_exit": check_exit_or_null,
            "head": check_head,
            "completeness": lambda x: _enum(x, ("COMPLETE", "PREFIX")),
            "confirmed": _is_bool,
        },
    )
    return v


def check_kill_outcome(v) -> dict:
    return _closed(
        v,
        {
            "v": lambda x: check_version(x),
            "run_id": lambda x: check_id(x, "run"),
            "state": lambda x: _enum(x, STATES),
            "confirmed": _is_bool,
            "stop_reason": lambda x: None if x is None else _enum(x, REASONS),
        },
    )
    return v


def check_recovery_report(v) -> dict:
    _closed(v, {"v": lambda x: check_version(x), "runs": _is_arr})
    for r in v["runs"]:
        _closed(
            r,
            {
                "run_id": lambda x: check_id(x, "run"),
                "result": lambda x: _enum(x, ("CONTAINED", "INCOMPLETE", "UNCONFIRMED")),
                "head": lambda x: None if x is None else check_head(x),
            },
        )
    return v


def check_config_validation(v) -> dict:
    return _closed(
        v,
        {
            "v": lambda x: check_version(x),
            "valid": _is_bool,
            "config_hash": check_hash,
            "preflight": lambda x: _enum(x, ("NOT_RUN", "PASSED")),
        },
    )


def check_version_info(v) -> dict:
    _closed(
        v,
        {
            "v": lambda x: check_version(x),
            "cli": lambda x: _enum(x, ("1.0.0",)),
            "protocol": lambda x: _enum(x, (1,)),
            "storage": lambda x: _enum(x, (1,)),
            "estimator": lambda x: _enum(x, ("dense-v1",)),
            "profiles": _is_arr,
        },
    )
    if v["profiles"] != ["linux-rapl-v1", "linux-ledger-v1", "offline-v1"]:
        raise LexwattError("INVALID_INPUT")
    return v


def check_cli_error(v) -> dict:
    return _closed(
        v,
        {
            "v": lambda x: check_version(x),
            "error": lambda x: _closed(
                x, {"code": lambda c: _enum(c, CODES), "retryable": _is_bool}
            ),
        },
    )


def check_model_path_map(v) -> dict:
    _is_obj(v)
    for k, val in v.items():
        check_model_name(k)
        _closed(val, {"artifact_path": check_path, "tokenizer_path": check_path})
    return v


# --- envelopes ------------------------------------------------------------


def check_request(v) -> dict:
    _closed(
        v,
        {
            "v": lambda x: check_version(x),
            "id": lambda x: check_id(x, "request"),
            "method": lambda x: _enum(x, METHODS),
            "params": _is_obj,
        },
    )
    return v


def check_response(v) -> dict:
    _is_obj(v)
    for k in v:
        if k not in ("v", "id", "ok", "result", "error"):
            raise LexwattError("UNKNOWN_FIELD")
    check_version(v.get("v"))
    check_id(v.get("id"), "request")
    okv = v.get("ok")
    if not isinstance(okv, bool):
        raise LexwattError("INVALID_INPUT")
    if okv:
        if "result" not in v or "error" in v:
            raise LexwattError("INVALID_INPUT")
    else:
        if "error" not in v or "result" in v:
            raise LexwattError("INVALID_INPUT")
        _closed(v["error"], {"code": lambda c: _enum(c, CODES), "retryable": _is_bool})
    return v
