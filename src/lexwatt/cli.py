"""agent-cap CLI (spec §8.1, §8.2, §13).

Commands: doctor, estimate, run, meter, kill, receipt, verify,
config validate, recover, version.  Unknown commands/flags, repeated scalar
flags, and unexpected positionals exit 64.  All commands accept --help.
"""

from __future__ import annotations

import json
import os
import signal
import sys

from . import jcs
from .config import (
    apply_overrides,
    effective_config_hash,
    load_config,
    load_host_policy,
    load_model_map,
)
from .engine import Launcher
from .errors import LexwattError, exit_code_for
from .estimator import estimate_for_model_work
from .host.linux import LinuxHost
from .ids import IdGenerator
from .schema import check_config, check_host_policy
from .units import parse_flops, parse_int_range, parse_joules, wall_ms_to_us
from .verify import verify_bundle

DEFAULT_STATE_ROOT = "/var/lib/lexwatt"
DEFAULT_RUNTIME_ROOT = "/run/lexwatt"
DEFAULT_HOST_POLICY = "/etc/lexwatt/host.json"
DEFAULT_MODEL_MAP = "/etc/lexwatt/models.json"

USAGE = """agent-cap — estimate model work, meter package energy, stop on budget

usage:
  agent-cap doctor [--profile PROFILE] [--json]
  agent-cap estimate --model-file PATH --model ID --input-tokens U --output-tokens U [--batch N] [--json]
  agent-cap run --config PATH [--max-flops U] [--max-joules J] [--spawns N] [--max-wall-ms N]
                [--cwd PATH] [--env-file PATH] [--receipt PATH] [--json] -- COMMAND [ARG...]
  agent-cap meter RUN_ID [--follow] [--interval-ms N] [--json]
  agent-cap kill RUN_ID [--wait-ms N] [--json]
  agent-cap receipt RUN_ID [--output PATH] [--json]
  agent-cap verify PATH [--key KEY_ID=PUBLIC_KEY]... [--require-complete|--allow-prefix] [--json]
  agent-cap config validate PATH [--host-policy PATH] [--json]
  agent-cap recover (--run RUN_ID|--all) [--json]
  agent-cap version [--json]
"""


class UsageError(Exception):
    pass


def _emit(obj, json_mode: bool, out=None) -> None:
    out = out or sys.stdout
    if json_mode:
        out.write(jcs.dumps_str(obj) + "\n")
    else:
        out.write(str(obj) + "\n")


def _cli_error(code: str, retryable: bool = False) -> dict:
    return {"v": 1, "error": {"code": code, "retryable": retryable}}


def _fail(code: str, json_mode: bool, exit_code: int | None = None, retryable: bool = False) -> int:
    if json_mode:
        sys.stdout.write(jcs.dumps_str(_cli_error(code, retryable)) + "\n")
    else:
        sys.stderr.write(f"agent-cap: {code}\n")
    return exit_code if exit_code is not None else exit_code_for(code)


def _parse_flags(args: list[str], spec_flags: dict[str, tuple[bool, bool]], allow_positionals: int):
    """spec_flags: name -> (takes_value, repeatable)."""
    flags: dict[str, object] = {}
    pos: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--help", "-h"):
            raise UsageError("help")
        if a == "--":
            pos.extend(args[i + 1 :])
            break
        if a.startswith("--"):
            name, eq, val = a[2:].partition("=")
            if name not in spec_flags:
                raise UsageError(f"unknown flag --{name}")
            takes, repeatable = spec_flags[name]
            if name in flags and not repeatable:
                raise UsageError(f"repeated flag --{name}")
            if takes:
                if not eq:
                    i += 1
                    if i >= len(args):
                        raise UsageError(f"missing value for --{name}")
                    val = args[i]
                if repeatable:
                    flags.setdefault(name, []).append(val)
                else:
                    flags[name] = val
            else:
                if eq:
                    raise UsageError(f"flag --{name} takes no value")
                flags[name] = True
            i += 1
            continue
        pos.append(a)
        i += 1
    if len(pos) > allow_positionals:
        raise UsageError("unexpected positional arguments")
    return flags, pos


def _json(flags: dict) -> bool:
    return bool(flags.get("json"))


def _require_root() -> None:
    if os.geteuid() != 0:
        raise LexwattError("UNSUPPORTED_PROFILE")


def _paths():
    return {
        "state_root": os.environ.get("LEXWATT_STATE_ROOT", DEFAULT_STATE_ROOT),
        "runtime_root": os.environ.get("LEXWATT_RUNTIME_ROOT", DEFAULT_RUNTIME_ROOT),
        "host_policy": os.environ.get("LEXWATT_HOST_POLICY", DEFAULT_HOST_POLICY),
        "model_map": os.environ.get("LEXWATT_MODEL_MAP", DEFAULT_MODEL_MAP),
    }


def _launcher(host_policy_path: str | None = None) -> Launcher:
    p = _paths()
    hp_path = host_policy_path or p["host_policy"]
    try:
        host_policy = load_host_policy(hp_path)
    except LexwattError as e:
        raise LexwattError("UNSUPPORTED_PROFILE") from e
    model_map = {}
    try:
        model_map = load_model_map(p["model_map"])
    except LexwattError:
        pass
    return Launcher(
        p["state_root"], p["runtime_root"], LinuxHost(), host_policy, model_map
    )


# --- commands -------------------------------------------------------------


def cmd_doctor(args: list[str]) -> int:
    flags, pos = _parse_flags(args, {"profile": (True, False), "json": (False, False)}, 0)
    profile = flags.get("profile", "linux-rapl-v1")
    if profile not in ("linux-rapl-v1", "linux-ledger-v1", "offline-v1"):
        return _fail("INVALID_INPUT", _json(flags))
    host = LinuxHost()
    if profile == "offline-v1":
        caps = {
            "profile": "offline-v1",
            "cgroup_kill": False,
            "task_uid_isolation": False,
            "seccomp": False,
            "namespaces": False,
            "rapl_domains": [],
            "failures": [],
        }
    else:
        caps = host.capabilities(profile)
    if _json(flags):
        _emit(caps, True)
    else:
        print(f"profile: {caps['profile']}")
        print(f"cgroup_kill: {'yes' if caps['cgroup_kill'] else 'no'}")
        print(f"task_uid_isolation: {'yes' if caps['task_uid_isolation'] else 'no'}")
        print(f"seccomp: {'yes' if caps['seccomp'] else 'no'}")
        print(f"namespaces: {'yes' if caps['namespaces'] else 'no'}")
        print(f"RAPL domains: {', '.join(caps['rapl_domains']) or 'none'}")
        for f in caps["failures"]:
            print(f"failure: {f}")
    return 0 if not caps["failures"] else 65


def cmd_estimate(args: list[str]) -> int:
    flags, pos = _parse_flags(
        args,
        {
            "model-file": (True, False),
            "model": (True, False),
            "input-tokens": (True, False),
            "output-tokens": (True, False),
            "batch": (True, False),
            "json": (False, False),
        },
        0,
    )
    jm = _json(flags)
    for req in ("model-file", "model", "input-tokens", "output-tokens"):
        if req not in flags:
            raise UsageError(f"missing --{req}")
    try:
        catalog = jcs.loads(open(flags["model-file"], "rb").read())
        if not isinstance(catalog, list) or len(catalog) > 32:
            raise LexwattError("INVALID_INPUT")
        model = next((m for m in catalog if isinstance(m, dict) and m.get("id") == flags["model"]), None)
        if model is None:
            return _fail("UNSUPPORTED_MODEL", jm)
        batch = 1
        if "batch" in flags:
            batch = parse_int_range(flags["batch"], 1, 256, "batch")
        work = {
            "model_id": model["id"],
            "input_tokens": flags["input-tokens"],
            "max_output_tokens": flags["output-tokens"],
            "batch": batch,
        }
        est = estimate_for_model_work(model, work)
    except LexwattError as e:
        return _fail(e.code, jm)
    except OSError:
        return _fail("INVALID_INPUT", jm, 74)
    if jm:
        _emit(est, True)
    else:
        print(f"estimated FLOPs (cooperative): {est['charged_flops']}")
        print(f"  base: {est['base_flops']}  attention: {est['attention_flops']}")
    return 0


def cmd_run(args: list[str]) -> int:
    jm = "--json" in args
    # find the mandatory -- delimiter
    if "--" not in args:
        raise UsageError("missing -- delimiter")
    sep = args.index("--")
    flag_args, cmd = args[:sep], args[sep + 1 :]
    if not cmd:
        raise UsageError("missing command after --")
    flags, pos = _parse_flags(
        flag_args,
        {
            "config": (True, False),
            "max-flops": (True, False),
            "max-joules": (True, False),
            "spawns": (True, False),
            "max-wall-ms": (True, False),
            "cwd": (True, False),
            "env-file": (True, False),
            "receipt": (True, False),
            "json": (False, False),
        },
        0,
    )
    jm = _json(flags)
    if pos:
        raise UsageError("unexpected positional arguments")
    if "config" not in flags:
        raise UsageError("missing --config")
    try:
        cfg = load_config(flags["config"])
        overrides = {}
        if "max-flops" in flags:
            overrides["max_flops"] = str(parse_flops(flags["max-flops"]))
        if "max-joules" in flags:
            overrides["max_energy_uj"] = str(parse_joules(flags["max-joules"]))
        if "spawns" in flags:
            overrides["spawns"] = parse_int_range(flags["spawns"], 0, 1024, "spawns")
        if "max-wall-ms" in flags:
            overrides["max_wall_us"] = str(wall_ms_to_us(flags["max-wall-ms"]))
        if overrides:
            cfg = apply_overrides(cfg, overrides)
        env = {"LANG": "C.UTF-8"}
        if "env-file" in flags:
            raw = jcs.loads(open(flags["env-file"], "rb").read())
            if not isinstance(raw, dict):
                raise LexwattError("INVALID_INPUT")
            env = dict(raw)
        cwd = flags.get("cwd", "/work")
        if not isinstance(cwd, str) or not cwd.startswith("/"):
            raise LexwattError("INVALID_INPUT")
        execv = {"argv": cmd, "cwd": cwd, "env": env}
        _require_root()
        launcher = _launcher()
        ids = launcher.ids
        req_id = ids.new("request")
        result = launcher.run_start({"config": cfg, "exec": execv}, req_id, os.geteuid())
    except LexwattError as e:
        return _fail(e.code, jm)
    except OSError:
        return _fail("INVALID_INPUT", jm, 74)
    run_id = result["run_id"]
    if result["state"] == "REJECTED":
        return _fail(result["error"], jm)
    run = launcher.runs[run_id]
    exit_code = _drive_run(launcher, run, jm)
    if "receipt" in flags:
        try:
            _export_receipt(run, flags["receipt"])
        except OSError:
            pass
    return exit_code


def _drive_run(launcher: Launcher, run, json_mode: bool) -> int:
    """Foreground lifetime-bound run loop (spec §8.1: detaching the client
    stops the workload)."""
    import time

    interval = int(run.config["meter"]["interval_us"]) / 1e6
    deadline_note = False

    def on_sigint(_s, _f):
        run._latch("SIGNAL")

    old = signal.signal(signal.SIGINT, on_sigint)
    try:
        while True:
            launcher.tick_all()
            st = run.core.state
            if st in ("COMPLETED", "KILLED", "FAILED", "REJECTED"):
                break
            if st == "UNCONFIRMED":
                # bounded shutdown wait: exit 70 while containment continues
                kd = int(run.config["meter"]["kill_deadline_us"]) / 1e6
                waited = 0.0
                while run.core.state == "UNCONFIRMED" and waited < kd:
                    launcher.tick_all()
                    time.sleep(min(interval, 0.05))
                    waited += min(interval, 0.05)
                break
            time.sleep(min(interval, 0.05))
    finally:
        signal.signal(signal.SIGINT, old)
    outcome = _run_outcome(run)
    if json_mode:
        _emit(outcome, True)
    else:
        print(
            f"run {run.run_id}: {outcome['state']} exit={outcome['exit_code']} "
            f"confirmed={outcome['confirmed']} completeness={outcome['completeness']}",
            file=sys.stderr,
        )
    return outcome["exit_code"]


def _run_outcome(run) -> dict:
    """RunOutcome: exit_code is the exact status `agent-cap run` uses."""
    seq, h = run.journal.event_head()
    head = {"seq": str(seq), "hash": h}
    st = run.core.state
    confirmed = run.containment_empty or st in ("COMPLETED", "KILLED", "REJECTED")
    if st == "REJECTED":
        confirmed = True
    completeness = (
        "COMPLETE"
        if st in ("COMPLETED", "KILLED", "FAILED", "REJECTED")
        else "PREFIX"
    )
    if st == "COMPLETED":
        re_ = run.core.root_exit
        if re_ and re_.get("code") is not None:
            exit_code = re_["code"]
        elif re_ and re_.get("signal") is not None:
            exit_code = 128 + re_["signal"]
        else:
            exit_code = 0
    elif st == "KILLED":
        reason = run.core.stop_reason
        if reason in ("ENERGY_GUARD", "FLOPS_CAP", "SPAWN_CAP", "WALL_CAP", "MEASUREMENT_OVERRUN"):
            exit_code = 124
        elif reason == "OPERATOR":
            exit_code = 125
        elif reason == "SIGNAL":
            exit_code = 130
        else:
            exit_code = 124
    elif st == "FAILED":
        exit_code = 70
    elif st == "REJECTED":
        exit_code = exit_code_for(run.rejected_code or "CONTAINMENT_FAULT")
    else:  # UNCONFIRMED
        exit_code = 70
    return {
        "v": 1,
        "run_id": run.run_id,
        "state": st,
        "exit_code": exit_code,
        "root_exit": run.core.root_exit,
        "head": head,
        "completeness": completeness,
        "confirmed": confirmed,
    }


def _export_receipt(run, out_path: str) -> None:
    bundle = run.bundle()
    data = jcs.dumps(bundle)
    if out_path in ("-", None):
        sys.stdout.write(data.decode() + "\n")
        return
    # create-exclusive, fsync, atomic install; never overwrite silently
    fd = os.open(out_path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.link(out_path + ".tmp", out_path)  # fails if destination exists
    os.unlink(out_path + ".tmp")


def _status_for(launcher: Launcher, run_id: str):
    run = launcher.open_run(run_id)
    return run, run.status_object()


def cmd_meter(args: list[str]) -> int:
    flags, pos = _parse_flags(
        args,
        {"follow": (False, False), "interval-ms": (True, False), "json": (False, False)},
        1,
    )
    jm = _json(flags)
    if not pos:
        raise UsageError("missing RUN_ID")
    run_id = pos[0]
    interval_ms = 1000
    if "interval-ms" in flags:
        interval_ms = parse_int_range(flags["interval-ms"], 100, 60000, "interval-ms")
    try:
        _require_root()
        launcher = _launcher()
        import time

        while True:
            launcher.tick_all()
            run, status = _status_for(launcher, run_id)
            if jm:
                _emit(status, True)
            else:
                _print_status(status)
            if not flags.get("follow") or run.core.state in (
                "COMPLETED",
                "KILLED",
                "FAILED",
                "REJECTED",
            ):
                break
            time.sleep(interval_ms / 1000)
    except LexwattError as e:
        return _fail(e.code, jm)
    return 0


def _print_status(st: dict) -> None:
    energy = st["energy_uj"]
    energy_s = f"{int(energy) / 1e6:.6f}" if energy is not None else "unavailable"
    print(
        f"{st['run_id']} {st['state']} "
        f"estimated FLOPs (cooperative): {st['charged_flops']} "
        f"CPU package joules (shared-inclusive): {energy_s} "
        f"spawns used: {st['spawn_tokens_issued']}/{st['budgets']['spawns']} "
        f"elapsed_us: {st['elapsed_us']}"
    )


def cmd_kill(args: list[str]) -> int:
    flags, pos = _parse_flags(
        args, {"wait-ms": (True, False), "json": (False, False)}, 1
    )
    jm = _json(flags)
    if not pos:
        raise UsageError("missing RUN_ID")
    run_id = pos[0]
    wait_ms = 1000
    if "wait-ms" in flags:
        wait_ms = parse_int_range(flags["wait-ms"], 0, 60000, "wait-ms")
    try:
        _require_root()
        launcher = _launcher()
        run = launcher.open_run(run_id)
        import time

        resp = run.handle(
            "owner",
            {"v": 1, "id": launcher.ids.new("request"), "method": "run.stop", "params": {"run_id": run_id}},
            None,
        )
        deadline = time.monotonic() + wait_ms / 1000
        while time.monotonic() < deadline and run.core.state not in (
            "COMPLETED",
            "KILLED",
            "FAILED",
            "REJECTED",
        ):
            launcher.tick_all()
            time.sleep(0.01)
        confirmed = run.containment_empty or run.core.state in (
            "COMPLETED",
            "KILLED",
            "FAILED",
            "REJECTED",
        )
        out = {
            "v": 1,
            "run_id": run_id,
            "state": run.core.state,
            "confirmed": confirmed,
            "stop_reason": run.core.stop_reason,
        }
        _emit(out, True) if jm else print(
            f"{run_id}: {out['state']} confirmed={confirmed}", file=sys.stderr
        )
        if jm:
            pass
        return 0 if resp.get("ok") and (confirmed or wait_ms == 0) else (0 if confirmed else 70)
    except LexwattError as e:
        return _fail(e.code, jm)


def cmd_receipt(args: list[str]) -> int:
    flags, pos = _parse_flags(
        args, {"output": (True, False), "json": (False, False)}, 1
    )
    jm = _json(flags)
    if not pos:
        raise UsageError("missing RUN_ID")
    try:
        _require_root()
        launcher = _launcher()
        run = launcher.open_run(pos[0])
        bundle = run.bundle()
        data = jcs.dumps(bundle)
        if "output" in flags:
            _export_receipt(run, flags["output"])
        else:
            sys.stdout.write(data.decode() + "\n")
    except LexwattError as e:
        return _fail(e.code, jm)
    except OSError:
        return _fail("INVALID_INPUT", jm, 74)
    return 0


def cmd_verify(args: list[str]) -> int:
    flags, pos = _parse_flags(
        args,
        {
            "key": (True, True),
            "require-complete": (False, False),
            "allow-prefix": (False, False),
            "json": (False, False),
        },
        1,
    )
    jm = _json(flags)
    if not pos:
        raise UsageError("missing PATH")
    if flags.get("require-complete") and flags.get("allow-prefix"):
        return _fail("INVALID_INPUT", jm)
    require_complete = not bool(flags.get("allow-prefix"))
    pins = []
    for kv in flags.get("key", []) or []:
        kid, eq, pub = kv.partition("=")
        if not eq:
            return _fail("INVALID_INPUT", jm)
        pins.append({"key_id": kid, "public_key": pub})
    try:
        bundle = jcs.loads(open(pos[0], "rb").read())
        result = verify_bundle(bundle, pins, require_complete)
    except LexwattError as e:
        return _fail(e.code, jm, 76 if e.code in (
            "HASH_MISMATCH",
            "SIGNATURE_INVALID",
            "UNTRUSTED_KEY",
            "CHAIN_INVALID",
            "TRANSITION_INVALID",
            "INCOMPLETE",
        ) else None)
    except OSError:
        return _fail("INVALID_INPUT", jm, 74)
    if jm:
        _emit(result, True)
    else:
        print(
            f"integrity={result['integrity']} completeness={result['completeness']} "
            f"state={result['state']} physical_truth={result['physical_truth']}"
        )
    return 0


def cmd_config(args: list[str]) -> int:
    if not args or args[0] != "validate":
        raise UsageError("expected 'validate'")
    flags, pos = _parse_flags(
        args[1:],
        {"host-policy": (True, False), "json": (False, False)},
        1,
    )
    jm = _json(flags)
    if not pos:
        raise UsageError("missing PATH")
    try:
        cfg = load_config(pos[0])
        preflight = "NOT_RUN"
        if "host-policy" in flags:
            _require_root()
            hp = load_host_policy(flags["host-policy"])
            from . import meter as _meter

            if cfg["budgets"]["max_energy_uj"] is not None:
                m = cfg["meter"]
                reserve = _meter.reserve_uj(
                    hp["domains"], int(m["stale_us"]), int(m["kill_deadline_us"])
                )
                if int(cfg["budgets"]["max_energy_uj"]) <= reserve:
                    raise LexwattError("BUDGET_TOO_SMALL")
            preflight = "PASSED"
        out = {
            "v": 1,
            "valid": True,
            "config_hash": effective_config_hash(cfg),
            "preflight": preflight,
        }
    except LexwattError as e:
        return _fail(e.code, jm)
    except OSError:
        return _fail("INVALID_INPUT", jm, 74)
    if jm:
        _emit(out, True)
    else:
        print(f"valid: {out['valid']} config_hash={out['config_hash']} preflight={out['preflight']}")
    return 0


def cmd_recover(args: list[str]) -> int:
    flags, pos = _parse_flags(
        args, {"run": (True, False), "all": (False, False), "json": (False, False)}, 0
    )
    jm = _json(flags)
    if ("run" in flags) == bool(flags.get("all")):
        raise UsageError("exactly one of --run/--all")
    try:
        _require_root()
        launcher = _launcher()
        from .recovery import recover_all
        from .host.linux import boot_id

        report = recover_all(
            launcher.state_root, launcher.host, boot_id(), flags.get("run")
        )
    except LexwattError as e:
        return _fail(e.code, jm)
    if jm:
        _emit(report, True)
    else:
        for r in report["runs"]:
            print(f"{r['run_id']}: {r['result']}")
    return 0


def cmd_version(args: list[str]) -> int:
    flags, pos = _parse_flags(args, {"json": (False, False)}, 0)
    info = {
        "v": 1,
        "cli": "1.0.0",
        "protocol": 1,
        "storage": 1,
        "estimator": "dense-v1",
        "profiles": ["linux-rapl-v1", "linux-ledger-v1", "offline-v1"],
    }
    if _json(flags):
        _emit(info, True)
    else:
        print(
            f"agent-cap {info['cli']} protocol={info['protocol']} "
            f"storage={info['storage']} estimator={info['estimator']} "
            f"profiles={','.join(info['profiles'])}"
        )
    return 0


COMMANDS = {
    "doctor": cmd_doctor,
    "estimate": cmd_estimate,
    "run": cmd_run,
    "meter": cmd_meter,
    "kill": cmd_kill,
    "receipt": cmd_receipt,
    "verify": cmd_verify,
    "config": cmd_config,
    "recover": cmd_recover,
    "version": cmd_version,
}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("--help", "-h", "help"):
        sys.stdout.write(USAGE)
        return 0 if args else 64
    cmd = args[0]
    fn = COMMANDS.get(cmd)
    if fn is None:
        sys.stderr.write(f"agent-cap: unknown command {cmd}\n")
        return 64
    try:
        return fn(args[1:])
    except UsageError as e:
        if str(e) == "help":
            sys.stdout.write(USAGE)
            return 0
        sys.stderr.write(f"agent-cap: {e}\n")
        return 64
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
