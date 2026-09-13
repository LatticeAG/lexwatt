"""Engine-level integration tests on the mocked reference host (SimHost).

These drive the real supervisor: run.start, workload channel methods,
idempotent retries, stop/kill/finalize, and offline receipt verification.
"""

import hashlib
import json
import os

import pytest

from fixtures import ACT, B, M, P, Q, W
from lexwatt import jcs
from lexwatt.engine import Launcher
from lexwatt.errors import LexwattError
from lexwatt.host.sim import SimHost
from lexwatt.ids import DeterministicIds
from lexwatt.verify import verify_bundle


def make_host(**kw):
    return SimHost(domains={"package0": 262143328850}, **kw)


def make_policy(tmp):
    return {
        "v": 1,
        "runtime_image": "/opt/lexwatt/rootfs",
        "workspace_roots": ["/work"],
        "state_root": str(tmp),
        "domains": [
            {
                "id": "package0",
                "sysfs_dir": "/sys/class/powercap/intel-rapl:0",
                "cpus": "0-7",
                "max_power_uw": "15000000",
                "margin_uj": "500000",
            }
        ],
        "task_uid_min": 62000,
        "task_uid_max": 62031,
    }


def make_cfg(tmp, **over):
    art = os.path.join(tmp, "artifact.bin")
    tok = os.path.join(tmp, "tokenizer.bin")
    if not os.path.exists(art):
        open(art, "wb").write(b"{}")
        open(tok, "wb").write(b'{"a":"1","b":2}')
    cfg = {
        "v": 1,
        "profile": "linux-rapl-v1",
        "workspace_root": "/work",
        "budgets": dict(B, max_flops="1000000000000000000", max_energy_uj="10000000"),
        "meter": {"interval_us": "100000", "stale_us": "200000", "kill_deadline_us": "100000"},
        "pids_max": 64,
        "memory_max_bytes": "1073741824",
        "log_max_bytes": "67108864",
        "model_catalog": [M],
        "network": [],
        "flops_trust": "cooperative",
    }
    cfg["budgets"].update(over)
    return cfg


def make_map(tmp):
    return {
        "dense-small": {
            "artifact_path": os.path.join(tmp, "artifact.bin"),
            "tokenizer_path": os.path.join(tmp, "tokenizer.bin"),
        }
    }


@pytest.fixture
def env(tmp_path):
    tmp = str(tmp_path)
    make_cfg(tmp)  # ensures artifact files exist
    ids = DeterministicIds()
    host = make_host()
    launcher = Launcher(
        os.path.join(tmp, "state"),
        os.path.join(tmp, "run"),
        host,
        make_policy(tmp),
        make_map(tmp),
        ids=ids,
    )
    return Simple(tmp=tmp, ids=ids, host=host, launcher=launcher)


class Simple:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def start_run(env, execv=None):
    res = env.launcher.run_start(
        {"config": make_cfg(env.tmp), "exec": execv or {"argv": ["/work/job.py"], "cwd": "/work", "env": {}}},
        env.ids.new("request"),
        0,
    )
    return env.launcher.runs[res["run_id"]], res


def wl(env, run, method, params, channel=None):
    return env.launcher.workload(
        channel or run.root_channel_id,
        {"v": 1, "id": env.ids.new("request"), "method": method, "params": params},
    )


def ctl(env, method, params):
    return env.launcher.control(
        {"v": 1, "id": env.ids.new("request"), "method": method, "params": params}, 0
    )


class TestLifecycle:
    def test_run_start_reaches_running(self, env):
        run, res = start_run(env)
        assert res["state"] == "ARMING"
        assert run.core.state == "RUNNING"
        assert run.root_channel_id is not None

    def test_run_get_status(self, env):
        run, _ = start_run(env)
        r = ctl(env, "run.get", {"run_id": run.run_id})
        assert r["ok"] and r["result"]["state"] == "RUNNING"
        assert r["result"]["charged_flops"] == "0"
        assert r["result"]["head"]["seq"] != "0"

    def test_run_get_wrong_id(self, env):
        start_run(env)
        r = ctl(env, "run.get", {"run_id": "lwr_999999999999999999999"})
        assert r["ok"] is False and r["error"]["code"] == "NOT_FOUND"

    def test_operator_stop_finalizes(self, env):
        run, _ = start_run(env)
        r = ctl(env, "run.stop", {"run_id": run.run_id})
        assert r["result"]["state"] == "STOPPING"
        assert r["result"]["stop_reason"] == "OPERATOR"
        env.launcher.tick_all()
        assert run.core.state == "KILLED"
        assert run.containment_empty

    def test_root_exit_completes(self, env):
        run, _ = start_run(env)
        run.ctx.root_proc.request_exit({"code": 0, "signal": None})
        env.launcher.tick_all()
        env.launcher.tick_all()
        assert run.core.state == "COMPLETED"
        assert run.core.root_exit == {"code": 0, "signal": None}

    def test_stop_idempotent_first_reason_wins(self, env):
        run, _ = start_run(env)
        r1 = ctl(env, "run.stop", {"run_id": run.run_id})
        r2 = ctl(env, "run.stop", {"run_id": run.run_id})
        assert r1["result"]["stop_reason"] == r2["result"]["stop_reason"] == "OPERATOR"
        env.launcher.tick_all()
        assert run.core.state == "KILLED"


class TestWorkloadMethods:
    def test_token_issue_burns_slot(self, env):
        run, _ = start_run(env)
        r = wl(env, run, "token.issue", {"action": ACT})
        assert r["ok"] and r["result"]["remaining_spawns"] == 0
        assert run.core.spawn_issued == 1

    def test_token_issue_denied_action(self, env):
        run, _ = start_run(env)
        r = wl(
            env,
            run,
            "token.issue",
            {"action": {"kind": "http_get", "origin": "https://x.example", "path": "/a", "max_response_bytes": 8}},
        )
        assert r["ok"] is False and r["error"]["code"] == "ACTION_DENIED"
        assert run.core.spawn_issued == 0  # denial does not consume capacity

    def test_dispatch_then_spawn_succeeds(self, env):
        run, _ = start_run(env)
        tok = wl(env, run, "token.issue", {"action": ACT})["result"]["token"]
        r = wl(env, run, "action.dispatch", {"token": tok, "action": ACT})
        aid = r["result"]["action_id"]
        assert r["result"]["state"] == "DISPATCHED"
        run.child_procs[aid].request_exit({"code": 0, "signal": None})
        env.launcher.tick_all()
        v = wl(env, run, "action.get", {"action_id": aid})
        assert v["result"]["state"] == "SUCCEEDED"
        assert v["result"]["result"]["exit"] == {"code": 0, "signal": None}

    def test_dispatch_replay_same_token(self, env):
        run, _ = start_run(env)
        tok = wl(env, run, "token.issue", {"action": ACT})["result"]["token"]
        wl(env, run, "action.dispatch", {"token": tok, "action": ACT})
        r2 = wl(env, run, "action.dispatch", {"token": tok, "action": ACT})
        assert r2["error"]["code"] == "TOKEN_USED"

    def test_spawn_cap_latches(self, env):
        run, _ = start_run(env)  # spawns=1
        wl(env, run, "token.issue", {"action": ACT})
        r = wl(env, run, "token.issue", {"action": ACT})
        assert r["error"]["code"] == "SPAWN_CAP"
        env.launcher.tick_all()
        assert run.core.state == "KILLED"

    def test_compute_reserve_finish(self, env):
        run, _ = start_run(env)
        r = wl(env, run, "compute.reserve", {"work": W})
        assert r["ok"] and r["result"]["charged_flops"] == "11440"
        cid = r["result"]["compute_id"]
        f = wl(env, run, "compute.finish", {"compute_id": cid, "observed_output_tokens": "1"})
        assert f["result"]["state"] == "FINISHED"
        assert f["result"]["observed_flops"] == "6732"
        # exact idempotent finish returns the same record
        f2 = wl(env, run, "compute.finish", {"compute_id": cid, "observed_output_tokens": "1"})
        assert f2["result"] == f["result"]

    def test_finish_over_envelope_kills(self, env):
        run, _ = start_run(env)
        cid = wl(env, run, "compute.reserve", {"work": W})["result"]["compute_id"]
        f = wl(env, run, "compute.finish", {"compute_id": cid, "observed_output_tokens": "4"})
        assert f["error"]["code"] == "ENVELOPE_EXCEEDED"
        env.launcher.tick_all()
        assert run.core.state == "KILLED"
        assert run.core.stop_reason == "FLOPS_CAP"

    def test_flops_cap_hard_stop(self, env):
        run, _ = start_run(env, )
        run.core.budgets["max_flops"] = "11440"
        wl(env, run, "compute.reserve", {"work": W})
        r = wl(env, run, "compute.reserve", {"work": W})
        assert r["error"]["code"] == "FLOPS_CAP"
        env.launcher.tick_all()
        assert run.core.state == "KILLED"

    def test_workload_surface_rejects_control(self, env):
        run, _ = start_run(env)
        r = wl(env, run, "run.stop", {"run_id": run.run_id})
        assert r["ok"] is False and r["error"]["code"] == "UNAUTHORIZED"

    def test_control_surface_rejects_workload(self, env):
        run, _ = start_run(env)
        r = ctl(env, "token.issue", {"action": ACT})
        assert r["ok"] is False and r["error"]["code"] == "UNAUTHORIZED"

    def test_cross_channel_action_denied(self, env):
        run, _ = start_run(env)
        tok = wl(env, run, "token.issue", {"action": ACT})["result"]["token"]
        # a sibling channel presenting the token is bound out
        other = "lwp_000000000000000000099"
        run.channels.add(other)
        r = wl(env, run, "action.dispatch", {"token": tok, "action": ACT}, channel=other)
        assert r["ok"] is False and r["error"]["code"] == "TOKEN_BINDING"


class TestIdempotency:
    def test_same_id_same_digest_replays(self, env):
        run, _ = start_run(env)
        req = {"v": 1, "id": env.ids.new("request"), "method": "run.get", "params": {"run_id": run.run_id}}
        r1 = env.launcher.control(req, 0)
        r2 = env.launcher.control(dict(req), 0)
        assert r1 == r2

    def test_same_id_different_params_conflicts(self, env):
        run, _ = start_run(env)
        rid = env.ids.new("request")
        env.launcher.control({"v": 1, "id": rid, "method": "run.get", "params": {"run_id": run.run_id}}, 0)
        r = env.launcher.control(
            {"v": 1, "id": rid, "method": "run.stop", "params": {"run_id": run.run_id}}, 0
        )
        assert r["ok"] is False and r["error"]["code"] == "CONFLICT"


class TestReceipt:
    def test_bundle_verifies_complete(self, env):
        run, _ = start_run(env)
        ctl(env, "run.stop", {"run_id": run.run_id})
        env.launcher.tick_all()
        assert run.core.state == "KILLED"
        pin = json.loads(
            open(os.path.join(env.launcher.state_root, "keys", f"{run.key_id}.pub.json")).read()
        )
        vr = verify_bundle(run.bundle(), [pin], True)
        assert vr["integrity"] == "VALID" and vr["completeness"] == "COMPLETE"
        assert vr["state"] == "KILLED"
        assert vr["physical_truth"] == "NOT_ATTESTED"

    def test_events_read_pagination(self, env):
        run, _ = start_run(env)
        r = ctl(env, "events.read", {"run_id": run.run_id, "after_seq": "0", "limit": 2})
        assert r["ok"]
        assert len(r["result"]["entries"]) == 2
        assert r["result"]["more"] is True
        r2 = ctl(env, "events.read", {"run_id": run.run_id, "after_seq": "2", "limit": 128})
        assert r2["result"]["entries"][0]["body"]["seq"] == "3"

    def test_events_read_beyond_head_invalid(self, env):
        run, _ = start_run(env)
        r = ctl(env, "events.read", {"run_id": run.run_id, "after_seq": "999", "limit": 1})
        assert r["ok"] is False and r["error"]["code"] == "INVALID_INPUT"


class TestRejection:
    def test_sensor_unavailable_rejects(self, tmp_path):
        tmp = str(tmp_path)
        make_cfg(tmp)
        ids = DeterministicIds()
        host = SimHost(domains={})  # no RAPL domains
        launcher = Launcher(
            os.path.join(tmp, "state"), os.path.join(tmp, "run"),
            host, make_policy(tmp), make_map(tmp), ids=ids,
        )
        res = launcher.run_start(
            {"config": make_cfg(tmp), "exec": {"argv": ["/x"], "cwd": "/work", "env": {}}},
            ids.new("request"), 0,
        )
        assert res["state"] == "REJECTED"
        assert res["error"] == "SENSOR_UNAVAILABLE"
        run = launcher.runs[res["run_id"]]
        # rejection receipt is retrievable and verifiable
        pin = json.loads(
            open(os.path.join(tmp, "state", "keys", f"{run.key_id}.pub.json")).read()
        )
        vr = verify_bundle(run.bundle(), [pin], True)
        assert vr["state"] == "REJECTED"


class TestRecovery:
    def test_reopen_terminal_run(self, env):
        run, _ = start_run(env)
        ctl(env, "run.stop", {"run_id": run.run_id})
        env.launcher.tick_all()
        run.journal.close()
        env.launcher.runs.clear()
        run2 = env.launcher.open_run(run.run_id)
        assert run2.core.state == "KILLED"
