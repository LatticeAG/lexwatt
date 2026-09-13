"""The per-run supervisor and the run.start launcher (spec §2.2, §5, §6).

The launcher owns the global launch index and run registry; each ``Run`` is
an event-sourced supervisor: every mutation is one writer transaction that
appends signed events, updates projections, and stores the idempotent
reply.  Host operations go through a HostBackend; the same engine drives
the Linux backend in production and the simulated reference host under the
conformance harness.
"""

from __future__ import annotations

import os

from . import ed25519, hashing, jcs, meter, scalars
from .config import (
    canonicalize_config,
    canonicalize_host_policy,
    effective_config_hash,
    model_files_for,
    resolve_workspace_root,
    verify_catalog_digests,
)
from .core import RunCore
from .errors import (
    CONTROL_METHODS,
    PURE_METHODS,
    TERMINAL_STATES,
    WORKLOAD_METHODS,
    LexwattError,
)
from .ids import IdGenerator
from .ledger import AuditFault, Journal, LaunchIndex
from .schema import (
    check_action,
    check_config,
    check_exec,
    check_request,
    check_work,
)

CONTROL_PRINCIPAL = "owner"


class RunContext:
    """Host-side allocation attached to a run."""

    def __init__(self):
        self.cgroup = None
        self.domain_handles = []
        self.root_proc = None
        self.task_uid = None
        self.workspace_path = None


def _zero_head() -> dict:
    return {"seq": "0", "hash": "0" * 64}


class Run:
    """One run's supervisor: journal + core reducer + host handles."""

    def __init__(
        self,
        launcher: "Launcher",
        run_id: str,
        key_id: str,
        seed: bytes,
        config: dict,
        execv: dict,
        journal: Journal,
    ):
        self.launcher = launcher
        self.run_id = run_id
        self.key_id = key_id
        self.seed = seed
        self.config = canonicalize_config(config)
        self.execv = execv
        self.journal = journal
        self.core = RunCore(run_id, key_id, self.config)
        self.ctx = RunContext()
        self.origin_us = 0
        self.started_us: int | None = None
        self.prev_readings: dict[str, tuple[int, int, int]] = {}
        self.baseline_cpu_us = 0
        self.sample_index = 0
        self.energy_uj = 0
        self.energy_valid = False
        self.energy_complete = False
        self.unchanged_since_us: int | None = None
        self.unchanged_cpu_at_us = 0
        self.last_cpu_us = 0
        self.final_sample: dict | None = None
        self.channels: set[str] = set()
        self.kill_confirmed = False
        self.containment_empty = False
        self.rejected_code: str | None = None
        self.root_channel_id: str | None = None
        self.child_procs: dict[str, object] = {}  # action_id -> host proc
        self.child_channels: dict[str, str] = {}  # action_id -> channel_id
        self._exec_after_commit: tuple | None = None
        self._pending_meta: dict[str, bytes] = {}

    # -- time -----------------------------------------------------------------

    @property
    def host(self):
        return self.launcher.host

    @property
    def ids(self):
        return self.launcher.ids

    def now_us(self) -> int:
        return self.host.boottime_us()

    def t_us(self, now_us: int | None = None) -> int:
        return (now_us if now_us is not None else self.now_us()) - self.origin_us

    def elapsed_us(self) -> int:
        if self.started_us is None:
            return 0
        return self.now_us() - self.started_us

    # -- journal --------------------------------------------------------------

    def _commit(self, out, principal: str | None, req_id: str | None, digest: str | None, result, error):
        """One writer transaction: append signed events, update projection,
        store the idempotent reply."""
        j = self.journal
        try:
            j.begin()
            seq, last_hash = j.event_head()
            for kind, data in out.events:
                seq += 1
                eid = self.ids.new("event")
                body = {
                    "v": 1,
                    "run_id": self.run_id,
                    "event_id": eid,
                    "key_id": self.key_id,
                    "seq": scalars.u_str(seq),
                    "prev_hash": last_hash,
                    "t_us": scalars.u_str(self.t_us()),
                    "kind": kind,
                    "data": data,
                }
                # engine fills token sigs produced by this transaction
                h = hashing.event_hash(body)
                sig = ed25519.sign_b64(self.seed, hashing.event_sign_message(h))
                entry = {"body": body, "hash": h, "sig": sig}
                j.event_append(seq, eid, h, jcs.dumps(entry))
                last_hash = h
            if any(k == "StopLatched" for k, _ in out.events):
                self.core.stop_latched_us = self.t_us()
            self._persist_side_effects(out)
            if self._pending_meta:
                for k, v in self._pending_meta.items():
                    j.meta_set(k, v)
                self._pending_meta = {}
            proj = jcs.dumps(self._projection())
            j.run_update(
                self.run_id,
                self.core.state,
                proj,
                seq,
                last_hash,
                self.core.stop_reason,
            )
            if principal is not None and req_id is not None and digest is not None:
                resp = self._envelope(req_id, result, error)
                j.request_put(principal, req_id, digest, jcs.dumps(resp))
            j.commit()
        except AuditFault:
            j.rollback()
            raise
        except Exception as e:
            j.rollback()
            raise AuditFault() from e

    def _envelope(self, req_id: str, result, error) -> dict:
        if error is not None:
            return error.to_response(req_id)
        return {"v": 1, "id": req_id, "ok": True, "result": result}

    def _projection(self) -> dict:
        seq, last_hash = self.journal.event_head()
        # head after the transaction's events: use updated values when inside
        # a commit; the caller recomputes before writing.
        return self.status_object({"seq": scalars.u_str(seq), "hash": last_hash})

    def status_object(self, head: dict | None = None) -> dict:
        if head is None:
            seq, h = self.journal.event_head()
            head = {"seq": scalars.u_str(seq), "hash": h}
        cov = self.coverage()
        return {
            "run_id": self.run_id,
            "state": self.core.state,
            "budgets": self.config["budgets"],
            "charged_flops": scalars.u_str(self.core.charged_flops),
            "energy_uj": scalars.u_str(self.energy_uj) if self.energy_valid else None,
            "spawn_tokens_issued": self.core.spawn_issued,
            "elapsed_us": scalars.u_str(self.elapsed_us()),
            "root_exit": self.core.root_exit,
            "stop_reason": self.core.stop_reason,
            "coverage": cov,
            "head": head,
        }

    def coverage(self) -> dict:
        cfg = self.config
        if cfg["profile"] == "linux-ledger-v1":
            return {
                "flops": "cooperative_estimate",
                "energy": "unavailable",
                "domains": [],
                "energy_complete": False,
                "reserve_uj": "0",
                "host_power_assumption": False,
                "assumptions": None,
            }
        power = sorted(
            (
                {
                    "domain": d["id"],
                    "max_power_uw": d["max_power_uw"],
                    "margin_uj": d["margin_uj"],
                }
                for d in self.launcher.host_policy["domains"]
            ),
            key=lambda p: p["domain"],
        )
        domains = sorted(d["id"] for d in self.launcher.host_policy["domains"])
        return {
            "flops": "cooperative_estimate",
            "energy": "package_measured",
            "domains": domains,
            "energy_complete": self.energy_complete,
            "reserve_uj": scalars.u_str(self.reserve_uj()),
            "host_power_assumption": True,
            "assumptions": {
                "meter": cfg["meter"],
                "power": power,
            },
        }

    def reserve_uj(self) -> int:
        if self.config["profile"] == "linux-ledger-v1":
            return 0
        m = self.config["meter"]
        return meter.reserve_uj(
            self.launcher.host_policy["domains"],
            int(m["stale_us"]),
            int(m["kill_deadline_us"]),
        )

    # -- lifecycle ------------------------------------------------------------

    def created(self, request_id: str, config_hash: str) -> None:
        self.origin_us = self.now_us()
        self._pending_meta = {
            "storage_major": b"1",
            "boot_id": self.host.boot_id().encode(),
            "key_id": self.key_id.encode(),
            "config": jcs.dumps(self.config),
            "exec": jcs.dumps(self.execv),
            "config_hash": config_hash.encode(),
        }
        out = self.core_out(("RunCreated", {"config_hash": config_hash}))
        self._commit(out, None, None, None, None, None)

    def arming(self) -> None:
        out = self.core_out(("RunArming", {"profile": self.config["profile"]}))
        self.core.state = "ARMING"
        self._commit(out, None, None, None, None, None)

    def core_out(self, *events):
        from .core import Outcome

        return Outcome(events=list(events))

    def reject(self, code: str) -> None:
        self.rejected_code = code
        out = self.core.reject(code)
        self._commit(out, None, None, None, None, None)

    def arm(self) -> None:
        """Preflight probing: workspace lease, task UID, cgroup, domains,
        baseline sample, then release the exec barrier."""
        cfg = self.config
        hp = self.launcher.host_policy
        try:
            self.ctx.workspace_path = resolve_workspace_root(cfg["workspace_root"], hp)
            self.host.workspace_lease(self.ctx.workspace_path, self.run_id)
            self.ctx.task_uid = self.host.task_uid_alloc(
                hp["task_uid_min"], hp["task_uid_max"], set()
            )
            domain_ids = sorted(d["id"] for d in hp["domains"])
            cpu_union = domain_cpus(hp)
            self.ctx.cfg = cfg
            self.ctx.cgroup = self.host.cgroup_create(self.run_id, cfg, cpu_union)
            if cfg["profile"] == "linux-rapl-v1":
                self.ctx.domain_handles = self.host.open_domains(domain_ids)
            # baseline sample before any workload instruction
            baseline = self._read_sample(index=0)
            self.baseline_cpu_us = self.host.cgroup_usage_us(self.ctx.cgroup)
            self.energy_valid = cfg["profile"] == "linux-rapl-v1"
            self.energy_uj = 0
            self.energy_complete = self.energy_valid
            self.sample_index = 0
            out = self.core_out(
                (
                    "RunStarted",
                    {
                        "budgets": cfg["budgets"],
                        "models": cfg["model_catalog"],
                        "coverage": self.coverage(),
                        "baseline": baseline,
                    },
                )
            )
            self.core.state = "RUNNING"
            self.started_us = self.now_us()
            self._commit(out, None, None, None, None, None)
            # release the root exec barrier
            channel_id = self.ids.new("channel")
            self.channels.add(channel_id)
            self.root_channel_id = channel_id
            self.ctx.root_proc = self.host.spawn_root(self.ctx, self.execv, channel_id)
            self._write_manifest()
        except LexwattError as e:
            # an ARMING failure with uncertain bootstrap containment uses
            # STOPPING, not a premature REJECTED (spec §5.1)
            if self.ctx.cgroup is not None and not self._bootstrap_clean():
                self._fault("CONTAINMENT_FAULT")
            else:
                self._cleanup_arming()
                self.reject(e.code)
            return

    def _bootstrap_clean(self) -> bool:
        try:
            return self.host.cgroup_populated(self.ctx.cgroup) == 0
        except Exception:
            return False

    def _cleanup_arming(self) -> None:
        if self.ctx.cgroup is not None:
            try:
                self.host.cgroup_kill(self.ctx.cgroup)
            except Exception:
                pass
        if self.ctx.workspace_path:
            self.host.workspace_release(self.ctx.workspace_path, self.run_id)
        if self.ctx.task_uid is not None:
            self.host.task_uid_free(self.ctx.task_uid)

    def _write_manifest(self) -> None:
        """launch-manifest.json (spec §10.1): closed JSON; digests use
        D("LEXWATT-CONFIG/1", object); file digests are raw SHA-256."""
        cg = self.ctx.cgroup
        manifest = {
            "v": 1,
            "run_id": self.run_id,
            "config_hash": effective_config_hash(self.config),
            "host_policy_hash": hashing.config_hash(canonicalize_host_policy(self.launcher.host_policy)),
            "boot_id": self.host.boot_id(),
            "cgroup_inode": scalars.u_str(getattr(cg, "inode", 0)),
            "cgroup_path": getattr(cg, "path", ""),
            "task_uid": self.ctx.task_uid or 0,
            "owner_uid": 0,
            "root_exec_hash": hashing.sha256_hex(jcs.dumps(self.execv)),
            "model_files": model_files_for(self.config, self.launcher.model_map)
            if self.config["model_catalog"]
            else [],
        }
        from .schema import check_launch_manifest

        check_launch_manifest(manifest)
        path = os.path.join(self.launcher.state_root, "runs", self.run_id, "launch-manifest.json")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, jcs.dumps(manifest))
            os.fsync(fd)
        finally:
            os.close(fd)

    def _read_sample(self, index: int) -> dict:
        now = self.now_us()
        readings = []
        for h in self.ctx.domain_handles:
            counter, rng, rt = self.host.read_domain(h)
            readings.append(
                {
                    "domain": h.id if hasattr(h, "id") else h.dom_id,
                    "counter_uj": scalars.u_str(counter),
                    "range_uj": scalars.u_str(rng),
                    "read_t_us": scalars.u_str(rt - self.origin_us),
                }
            )
        readings.sort(key=lambda r: r["domain"])
        cpu_us = self.host.cgroup_usage_us(self.ctx.cgroup) - self.baseline_cpu_us
        ts = [int(r["read_t_us"]) for r in readings]
        gap = max(ts) - min(ts) if len(ts) >= 2 else 0
        return {
            "index": scalars.u_str(index),
            "t_us": scalars.u_str(self.t_us(now)),
            "cpu_us": scalars.u_str(max(cpu_us, 0)),
            "readings": readings,
            "delta_uj": "0",
            "total_uj": scalars.u_str(self.energy_uj),
            "max_gap_us": scalars.u_str(gap),
        }

    # -- sampling / guard --------------------------------------------------------

    def tick(self) -> None:
        """One writer-owned scheduling step: safety events before ordinary
        admissions (spec §11)."""
        if self.core.state in ("RUNNING", "STOPPING", "UNCONFIRMED"):
            self._safety_pass()

    def _safety_pass(self) -> None:
        cfg = self.config
        now = self.now_us()
        state = self.core.state
        m = cfg["meter"]
        stale = int(m["stale_us"])
        kill_deadline = int(m["kill_deadline_us"])

        # root-exit observation
        if (
            state == "RUNNING"
            and self.ctx.root_proc is not None
            and self.core.stop_reason is None
        ):
            ex = self.host.proc_exited(self.ctx.root_proc)
            if ex is not None:
                self._latch("ROOT_EXIT", root_exit=ex)
                state = self.core.state

        # wall deadline (BOOTTIME domain)
        if state == "RUNNING" and self.started_us is not None:
            if now - self.started_us >= int(cfg["budgets"]["max_wall_us"]):
                self._latch("WALL_CAP")
                state = self.core.state

        # sampling
        if cfg["profile"] == "linux-rapl-v1" and state in ("RUNNING", "STOPPING", "UNCONFIRMED"):
            try:
                self._sample(now, stale)
            except LexwattError as e:
                self._fault(e.code if e.code == "SENSOR_FAULT" else "SENSOR_FAULT")
            state = self.core.state

        # child exit observation (dispatched spawn effects resolve here)
        if state in ("RUNNING", "STOPPING", "UNCONFIRMED") and self.child_procs:
            self._observe_children()
            state = self.core.state

        # token expiry sweep at sample cadence while RUNNING
        if state == "RUNNING":
            out = self.core.expire_tokens(self.t_us(now))
            if out.events:
                self._commit(out, None, None, None, None, None)

        # stop progress
        if self.core.state in ("STOPPING", "UNCONFIRMED"):
            self._stop_progress(now, kill_deadline)

    def _sample(self, now: int, stale: int) -> None:
        idx = self.sample_index + 1
        readings = []
        any_change = False
        delta_total = 0
        prev_all_same = True
        for h in self.ctx.domain_handles:
            counter, rng, rt = self.host.read_domain(h)
            dom_id = h.id if hasattr(h, "id") else h.dom_id
            prev = self.prev_readings.get(dom_id)
            if prev is not None:
                pa, prange, pt = prev
                dt = rt - pt
                d = meter.rapl_delta(
                    pa,
                    counter,
                    rng,
                    dt,
                    stale,
                    self._domain_power(dom_id),
                    self._domain_margin(dom_id),
                )
                if rng != prange:
                    raise LexwattError("SENSOR_FAULT")
                delta_total += d
                if d != 0:
                    any_change = True
            self.prev_readings[dom_id] = (counter, rng, rt)
            readings.append(
                {
                    "domain": dom_id,
                    "counter_uj": scalars.u_str(counter),
                    "range_uj": scalars.u_str(rng),
                    "read_t_us": scalars.u_str(rt - self.origin_us),
                }
            )
        readings.sort(key=lambda r: r["domain"])
        cpu_now = self.host.cgroup_usage_us(self.ctx.cgroup) - self.baseline_cpu_us
        if cpu_now < self.last_cpu_us:
            raise LexwattError("SENSOR_FAULT")  # backwards CPU usage
        # stuck-sensor detection
        if not any_change and self.prev_readings:
            if self.unchanged_since_us is None:
                self.unchanged_since_us = now
                self.unchanged_cpu_at_us = cpu_now
            elif (
                now - self.unchanged_since_us >= meter.STUCK_ENERGY_WINDOW_US
                and cpu_now - self.unchanged_cpu_at_us >= meter.STUCK_CPU_ADVANCE_US
            ):
                raise LexwattError("SENSOR_FAULT")
        else:
            self.unchanged_since_us = None
        self.last_cpu_us = cpu_now
        self.energy_uj += delta_total
        self.energy_valid = True
        self.sample_index = idx
        ts = [int(r["read_t_us"]) for r in readings]
        gap = max(ts) - min(ts) if len(ts) >= 2 else 0
        sample = {
            "index": scalars.u_str(idx),
            "t_us": scalars.u_str(self.t_us(now)),
            "cpu_us": scalars.u_str(cpu_now),
            "readings": readings,
            "delta_uj": scalars.u_str(delta_total),
            "total_uj": scalars.u_str(self.energy_uj),
            "max_gap_us": scalars.u_str(gap),
        }
        out = self.core_out(("SampleRecorded", {"sample": sample}))
        self._commit(out, None, None, None, None, None)
        if self.core.state == "RUNNING":
            cap = self.config["budgets"]["max_energy_uj"]
            if cap is not None:
                new_state, reason = meter.guard_eval(
                    self.energy_uj, int(cap), self.reserve_uj()
                )
                if new_state == "STOPPING":
                    self._latch(reason)

    def _domain_power(self, dom_id: str) -> int:
        for d in self.launcher.host_policy["domains"]:
            if d["id"] == dom_id:
                return int(d["max_power_uw"])
        return 0

    def _domain_margin(self, dom_id: str) -> int:
        for d in self.launcher.host_policy["domains"]:
            if d["id"] == dom_id:
                return int(d["margin_uj"])
        return 0

    # -- stop / containment -----------------------------------------------------

    def _latch(self, reason: str, root_exit: dict | None = None) -> None:
        out = self.core.stop(reason)
        if root_exit is not None:
            self.core.root_exit = root_exit
        if out.events:
            self._commit(out, None, None, None, None, None)
        if self.core.state == "STOPPING":
            self._issue_kill()

    def _fault(self, reason: str) -> None:
        out = self.core.fault(reason)
        if out.events:
            try:
                self._commit(out, None, None, None, None, None)
            except AuditFault:
                pass
        if self.core.state == "STOPPING":
            self._issue_kill()

    def _issue_kill(self) -> None:
        """Hard stop: cgroup.kill + process-group SIGKILL, no grace."""
        cg_ok = False
        grp_ok = False
        try:
            cg_ok = self.host.cgroup_kill(self.ctx.cgroup)
        except Exception:
            cg_ok = False
        try:
            grp_ok = self.host.group_kill(self.ctx.cgroup)
        except Exception:
            grp_ok = False
        out = self.core.kill_issued(cg_ok, grp_ok, self.t_us())
        try:
            self._commit(out, None, None, None, None, None)
        except AuditFault:
            pass  # kill never waits for audit

    def _stop_progress(self, now: int, kill_deadline: int) -> None:
        if self.core.stop_latched_us is None:
            self.core.stop_latched_us = self.t_us(now)
        empty = self._check_empty()
        if not empty:
            elapsed = now - (self.origin_us + (self.core.stop_latched_us or 0))
            if self.core.state == "STOPPING" and elapsed >= kill_deadline:
                out = self.core.kill_unconfirmed(elapsed)
                self._commit(out, None, None, None, None, None)
            else:
                # keep attempting kill/reap
                try:
                    self.host.cgroup_kill(self.ctx.cgroup)
                except Exception:
                    pass
            return
        # containment confirmed
        final_sample = None
        if self.config["profile"] == "linux-rapl-v1" and self.energy_valid:
            try:
                idx = self.sample_index + 1
                final_sample = self._read_final_sample(idx)
            except LexwattError:
                self.energy_complete = False
                out = self.core.fault("SENSOR_FAULT")
                self._commit(out, None, None, None, None, None)
                final_sample = None
        out = self.core.containment_empty(final_sample, self.core.root_exit)
        if out.events:
            self._commit(out, None, None, None, None, None)
        self.containment_empty = True
        self._finalize()

    def _check_empty(self) -> bool:
        if self.ctx.cgroup is None:
            return True
        try:
            if self.host.cgroup_populated(self.ctx.cgroup) != 0:
                return False
        except Exception:
            return False
        pending: list = []
        for arec in self.core.actions.values():
            if arec.state != "DISPATCHED":
                continue
            proc = self.child_procs.pop(arec.action_id, None)
            ex = None
            if proc is not None:
                try:
                    ex = self.host.proc_exited(proc)
                except Exception:
                    ex = None
            if ex is not None:
                # exit observed (e.g. killed): FAILED, retaining the Exit
                pending.append(
                    self.core.action_finish(
                        arec.action_id, {"kind": "spawn", "exit": ex}, "ACTION_FAILED", exit_=ex
                    )
                )
            elif proc is not None:
                # released, result unavailable after stop: UNKNOWN
                pending.append(self.core.action_unknown(arec.action_id, "ACTION_FAILED"))
            else:
                # canceled before any release: FAILED
                pending.append(self.core.action_finish(arec.action_id, None, "ACTION_FAILED"))
        if pending:
            from .core import Outcome

            merged = Outcome(events=[e for o in pending for e in o.events])
            if merged.events:
                self._commit(merged, None, None, None, None, None)
        return all(a.state != "DISPATCHED" for a in self.core.actions.values())

    def _read_final_sample(self, idx: int) -> dict:
        now = self.now_us()
        readings = []
        delta_total = 0
        stale = int(self.config["meter"]["stale_us"])
        for h in self.ctx.domain_handles:
            counter, rng, rt = self.host.read_domain(h)
            dom_id = h.id if hasattr(h, "id") else h.dom_id
            prev = self.prev_readings.get(dom_id)
            if prev is not None:
                pa, prange, pt = prev
                delta_total += meter.rapl_delta(
                    pa, counter, rng, rt - pt, stale,
                    self._domain_power(dom_id), self._domain_margin(dom_id),
                )
            self.prev_readings[dom_id] = (counter, rng, rt)
            readings.append(
                {
                    "domain": dom_id,
                    "counter_uj": scalars.u_str(counter),
                    "range_uj": scalars.u_str(rng),
                    "read_t_us": scalars.u_str(rt - self.origin_us),
                }
            )
        readings.sort(key=lambda r: r["domain"])
        cpu_now = max(self.host.cgroup_usage_us(self.ctx.cgroup) - self.baseline_cpu_us, 0)
        self.energy_uj += delta_total
        ts = [int(r["read_t_us"]) for r in readings]
        gap = max(ts) - min(ts) if len(ts) >= 2 else 0
        return {
            "index": scalars.u_str(idx),
            "t_us": scalars.u_str(self.t_us(now)),
            "cpu_us": scalars.u_str(cpu_now),
            "readings": readings,
            "delta_uj": scalars.u_str(delta_total),
            "total_uj": scalars.u_str(self.energy_uj),
            "max_gap_us": scalars.u_str(gap),
        }

    def _finalize(self) -> None:
        out = self.core.finalize(self.coverage(), self.t_us())
        if out.events:
            self._commit(out, None, None, None, None, None)
        self.kill_confirmed = True
        # destroy the per-run seed after durable finalization (§10.1)
        self.launcher.destroy_seed(self.key_id)
        self.host.workspace_release(self.ctx.workspace_path or "", self.run_id)
        if self.ctx.task_uid is not None:
            self.host.task_uid_free(self.ctx.task_uid)
        if self.ctx.cgroup is not None:
            self.host.cgroup_teardown(self.ctx.cgroup)

    # -- RPC handling ----------------------------------------------------------

    def handle(self, principal: str, req: dict, channel_id: str | None) -> dict:
        """Surface-checked, idempotent request handling (spec §6)."""
        check_request(req)
        req_id = req["id"]
        try:
            return self._handle_checked(principal, req, channel_id)
        except LexwattError as e:
            return e.to_response(req_id)

    def _handle_checked(self, principal: str, req: dict, channel_id: str | None) -> dict:
        req_id = req["id"]
        method = req["method"]
        params = req["params"]
        # surface authorization: control connections accept only the three
        # control methods; workload channels only the five workload methods;
        # pure methods are in-process (spec §6)
        if channel_id is None:
            if method not in CONTROL_METHODS:
                raise LexwattError("UNAUTHORIZED")
        else:
            if method not in WORKLOAD_METHODS:
                raise LexwattError("UNAUTHORIZED")
        digest = hashing.request_digest(method, params)
        # idempotency: same ID/digest returns the stored reply; same ID with a
        # different digest is CONFLICT
        row = self.journal.request_get(principal, req_id)
        if row is not None:
            stored_digest, stored_resp = row
            if stored_digest != digest:
                raise LexwattError("CONFLICT")
            return jcs.loads(bytes(stored_resp))
        out = self._dispatch(method, params, channel_id, req_id)
        result, error = out.result, out.error
        if error is not None and error.code == "BUSY":
            return self._envelope(req_id, None, error)  # pre-commit: key stays free
        self._commit(out, principal, req_id, digest, result, error)
        if any(k == "StopLatched" for k, _ in out.events):
            self._issue_kill()
        if self._exec_after_commit is not None:
            action_id, action, channel_id = self._exec_after_commit
            self._exec_after_commit = None
            self._execute_action(action_id, action, channel_id)
        return self._envelope(req_id, result, error)

    def _dispatch(self, method: str, params: dict, channel_id: str | None, req_id: str):
        from .core import Outcome

        if self.core.state in TERMINAL_STATES or self.core.state == "FINALIZING":
            # after terminal/FINALIZING, failed API requests return errors
            # without appending RequestDenied; reads still succeed
            if method == "run.get":
                return Outcome(result=self.status_object())
            if method == "run.stop":
                return Outcome(
                    result={"state": self.core.state, "stop_reason": self.core.stop_reason}
                )
            if method == "events.read":
                return self._events_read(params)
            return Outcome(error=LexwattError("STOPPED"))

        try:
            if method == "run.get":
                for k in params:
                    if k != "run_id":
                        raise LexwattError("UNKNOWN_FIELD")
                if params.get("run_id") != self.run_id:
                    raise LexwattError("NOT_FOUND")
                return Outcome(result=self.status_object())
            if method == "run.stop":
                for k in params:
                    if k != "run_id":
                        raise LexwattError("UNKNOWN_FIELD")
                if params.get("run_id") != self.run_id:
                    raise LexwattError("NOT_FOUND")
                return self._run_stop()
            if method == "events.read":
                return self._events_read(params)
            if method == "token.issue":
                return self._token_issue(params, channel_id, req_id)
            if method == "action.dispatch":
                return self._action_dispatch(params, channel_id, req_id)
            if method == "action.get":
                return self._action_get(params, channel_id, req_id)
            if method == "compute.reserve":
                return self._compute_reserve(params, channel_id, req_id)
            if method == "compute.finish":
                return self._compute_finish(params, channel_id, req_id)
            return Outcome(error=LexwattError("INVALID_INPUT"))
        except LexwattError as e:
            return self.core._deny(req_id, e.code)

    def _run_stop(self):
        # handle() commits the latch and fires _issue_kill on the committed
        # StopLatched; a repeated stop returns current state + first reason
        return self.core.stop("OPERATOR")

    def _events_read(self, params):
        from .core import Outcome

        for k in params:
            if k not in ("run_id", "after_seq", "limit"):
                raise LexwattError("UNKNOWN_FIELD")
        if params.get("run_id") != self.run_id:
            raise LexwattError("NOT_FOUND")
        after = scalars.parse_u(params.get("after_seq"))
        limit = params.get("limit")
        if not isinstance(limit, int) or not (1 <= limit <= 128):
            raise LexwattError("INVALID_INPUT")
        head_seq, head_hash = self.journal.event_head()
        if after > head_seq:
            raise LexwattError("INVALID_INPUT")
        raw = self.journal.events_after(after, limit)
        entries = [jcs.loads(bytes(r)) for r in raw]
        # frame-byte bound for responses (<=1048576)
        while entries and len(jcs.dumps(entries)) + 256 > 1048576:
            entries.pop()
        more = after + len(entries) < head_seq
        return Outcome(
            result={
                "entries": entries,
                "head": {"seq": scalars.u_str(head_seq), "hash": head_hash},
                "more": more,
            }
        )

    # -- workload methods --------------------------------------------------------

    def _token_issue(self, params, channel_id, req_id):
        for k in params:
            if k != "action":
                raise LexwattError("UNKNOWN_FIELD")
        action = check_action(params["action"])
        token_id = self.ids.new("token", exists=lambda i: i in self.core.tokens)
        out = self.core.token_issue(channel_id, action, self.t_us(), token_id, req_id)
        if out.error is None:
            body = out.result["token_body"]
            sig = ed25519.sign_b64(self.seed, hashing.token_sign_message(body))
            token = {"body": body, "sig": sig}
            rec = self.core.tokens[token_id]
            rec.token = token
            # persist token row inside the same transaction
            out.events = list(out.events)
            out.result = {"token": token, "remaining_spawns": out.result["remaining_spawns"]}
            # hook: journal row written in _commit via post-commit hook
            self._pending_token = (token, action)
        return out

    def _action_dispatch(self, params, channel_id, req_id):
        from .schema import check_token

        for k in params:
            if k not in ("token", "action"):
                raise LexwattError("UNKNOWN_FIELD")
        token = params["token"]
        action = params["action"]
        check_token(token)
        check_action(action)
        # signature validity precedes binding (spec §6)
        body = token["body"]
        if body["run_id"] != self.run_id:
            raise LexwattError("TOKEN_BINDING")
        if body["key_id"] != self.key_id or not ed25519.verify(
            ed25519.public_key_from_seed(self.seed),
            hashing.token_sign_message(body),
            scalars.decode_signature(token["sig"]),
        ):
            raise LexwattError("TOKEN_INVALID")
        action_id = self.ids.new("action", exists=lambda i: i in self.core.actions)
        out = self.core.dispatch(channel_id, token, action, self.t_us(), action_id, req_id)
        if out.error is None:
            self._pending_dispatch = (action_id, action, channel_id)
            self._exec_after_commit = (action_id, action, channel_id)
            out.result = {"action_id": action_id, "state": "DISPATCHED"}
        return out

    def _execute_action(self, action_id: str, action: dict, channel_id: str) -> None:
        """The one allowed attempt for a durably-dispatched action.  Spawn
        release is asynchronous (completion observed at sample cadence or
        containment drain); http_get is synchronous and bounded."""
        if action["kind"] == "spawn":
            child_channel = self.ids.new("channel")
            try:
                proc = self.host.spawn_child(self.ctx, action["exec"], child_channel)
            except LexwattError:
                # launch failure before exec: FAILED with null result
                out = self.core.action_finish(action_id, None, "ACTION_FAILED")
                self._commit(out, None, None, None, None, None)
                return
            self.channels.add(child_channel)
            self.child_procs[action_id] = proc
            self.child_channels[action_id] = child_channel
            return
        # http_get: synchronous, bounded by remaining wall budget
        dest = self.core._network.get((action["origin"], action["path"]))
        remaining = int(self.config["budgets"]["max_wall_us"]) - self.elapsed_us()
        deadline_us = max(min(remaining, 10_000_000), 0)
        try:
            resp = self.host.http_get(dest, action, deadline_us)
        except LexwattError:
            out = self.core.action_finish(action_id, None, "ACTION_FAILED")
            self._commit(out, None, None, None, None, None)
            return
        body = resp.get("body", b"")
        limit = action["max_response_bytes"]
        if len(body) > limit:
            body = body[:limit]  # transferred bound is the action's value
        result = {
            "kind": "http_get",
            "status": resp["status"],
            "body_b64": scalars.b64u(body),
            "body_hash": hashing.sha256_hex(body),
            "truncated": False,
        }
        out = self.core.action_finish(action_id, result, None)
        self._commit(out, None, None, None, None, None)

    def _observe_children(self) -> None:
        """Poll dispatched spawn children for exits; resolve each to
        ActionFinished (SUCCEEDED on exit 0, else FAILED retaining Exit)."""
        for action_id, proc in list(self.child_procs.items()):
            try:
                ex = self.host.proc_exited(proc)
            except Exception:
                ex = None
            if ex is None:
                continue
            del self.child_procs[action_id]
            code = ex.get("code")
            ok = ex.get("signal") is None and code == 0
            result = {"kind": "spawn", "exit": ex}
            out = self.core.action_finish(
                action_id, result, None if ok else "ACTION_FAILED", exit_=ex
            )
            if out.events:
                self._commit(out, None, None, None, None, None)

    def _action_get(self, params, channel_id, req_id):
        for k in params:
            if k != "action_id":
                raise LexwattError("UNKNOWN_FIELD")
        return self.core.action_view(channel_id, scalars.check_id(params["action_id"], "action"), req_id)

    def _compute_reserve(self, params, channel_id, req_id):
        for k in params:
            if k != "work":
                raise LexwattError("UNKNOWN_FIELD")
        work = check_work(params["work"])
        compute_id = self.ids.new("compute", exists=lambda i: i in self.core.computes)
        out = self.core.compute_reserve(channel_id, work, self.t_us(), compute_id, req_id)
        if out.error is None:
            self._pending_reservation = (compute_id, out.result)
        return out

    def _compute_finish(self, params, channel_id, req_id):
        for k in params:
            if k not in ("compute_id", "observed_output_tokens"):
                raise LexwattError("UNKNOWN_FIELD")
        cid = scalars.check_id(params["compute_id"], "compute")
        return self.core.compute_finish(channel_id, cid, params["observed_output_tokens"], req_id)

    # -- pending row persistence (inside _commit) --------------------------------

    def _persist_side_effects(self, out) -> None:
        """Called inside the writer transaction to persist token/action/
        compute rows that accompany committed events."""
        if getattr(self, "_pending_token", None) is not None:
            token, action = self._pending_token
            self._pending_token = None
            self.journal.token_put(
                token, "ISSUED", action, jcs.dumps(token), jcs.dumps(action)
            )
        if getattr(self, "_pending_dispatch", None) is not None:
            action_id, action, channel_id = self._pending_dispatch
            self._pending_dispatch = None
            arec = self.core.actions[action_id]
            view = {
                "action_id": action_id,
                "state": "DISPATCHED",
                "result": None,
                "error": None,
            }
            self.journal.action_put(
                action_id,
                arec.token_id,
                channel_id,
                "DISPATCHED",
                jcs.dumps(view),
            )
        if getattr(self, "_pending_reservation", None) is not None:
            compute_id, res = self._pending_reservation
            self._pending_reservation = None
            self.journal.compute_put(compute_id, self._res_channel(res), jcs.dumps(res))
        # sync token/action/compute state rows mutated by this transaction
        for tid, rec in self.core.tokens.items():
            cur = self.journal.token_state(tid)
            if cur is not None and cur != rec.state:
                self.journal.token_set_state(tid, rec.state)
        for aid, arec in self.core.actions.items():
            row = self.journal.action_row(aid)
            if row is not None and row[3] != arec.state:
                view = {
                    "action_id": aid,
                    "state": arec.state,
                    "result": arec.result,
                    "error": arec.error,
                }
                self.journal.action_set(aid, arec.state, jcs.dumps(view))
        for cid, crec in self.core.computes.items():
            row = self.journal.compute_row(cid)
            if row is not None:
                stored = jcs.loads(bytes(row[2]))
                if stored != crec.reservation:
                    self.journal.compute_set(cid, jcs.dumps(crec.reservation))

    def _res_channel(self, res: dict) -> str:
        return self.core.computes[res["compute_id"]].channel_id

    # -- export ---------------------------------------------------------------------

    def bundle(self, expected_head=None) -> dict:
        """Materialize the public receipt bundle from the committed event
        stream (§10.3: regenerable without changing event IDs)."""
        raw = self.journal.events_after(0, 1000000)
        entries = [jcs.loads(bytes(r)) for r in raw]
        return {"v": 1, "entries": entries, "expected_head": expected_head}


def domain_cpus(host_policy: dict) -> str:
    out: set[int] = set()
    from .host.linux import cpulist_to_set

    for d in host_policy["domains"]:
        out |= cpulist_to_set(d["cpus"])
    if not out:
        return ""
    # compact back to cpulist form
    cpus = sorted(out)
    parts = []
    start = prev = cpus[0]
    for c in cpus[1:]:
        if c == prev + 1:
            prev = c
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = c
    parts.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(parts)


class Launcher:
    """The run.start launcher: global index, per-run supervisors."""

    def __init__(
        self,
        state_root: str,
        runtime_root: str,
        host,
        host_policy: dict,
        model_map: dict | None = None,
        ids=None,
        hash_file=None,
    ):
        self.state_root = state_root
        self.runtime_root = runtime_root
        self.host = host
        self.host_policy = host_policy
        self.model_map = model_map or {}
        self.ids = ids or IdGenerator()
        self._hash_file = hash_file or self._default_hash_file
        os.makedirs(state_root, mode=0o700, exist_ok=True)
        os.makedirs(os.path.join(state_root, "keys"), mode=0o700, exist_ok=True)
        os.makedirs(os.path.join(state_root, "runs"), mode=0o700, exist_ok=True)
        os.makedirs(runtime_root, mode=0o700, exist_ok=True)
        self.index = LaunchIndex(os.path.join(state_root, "launches.sqlite"))
        self.runs: dict[str, Run] = {}
        self.seeds: dict[str, bytes] = {}
        self._run_lock = __import__("threading").Lock()

    @staticmethod
    def _default_hash_file(path: str) -> str:
        import hashlib

        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    # -- keys -----------------------------------------------------------------

    def _new_key(self) -> tuple[str, bytes, str]:
        seed = ed25519.generate_seed()
        key_id = self.ids.new("key", exists=lambda i: i in self.seeds)
        pub = ed25519.public_key_b64_from_seed(seed)
        seed_path = os.path.join(self.state_root, "keys", f"{key_id}.seed")
        pub_path = os.path.join(self.state_root, "keys", f"{key_id}.pub.json")
        fd = os.open(seed_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, seed)
        finally:
            os.close(fd)
        with open(pub_path, "wb") as f:
            f.write(jcs.dumps({"key_id": key_id, "public_key": pub}))
        os.chmod(pub_path, 0o600)
        self.seeds[key_id] = seed
        return key_id, seed, pub

    def destroy_seed(self, key_id: str) -> None:
        self.seeds.pop(key_id, None)
        try:
            os.unlink(os.path.join(self.state_root, "keys", f"{key_id}.seed"))
        except OSError:
            pass

    def public_key(self, key_id: str) -> str:
        with open(os.path.join(self.state_root, "keys", f"{key_id}.pub.json"), "rb") as f:
            return jcs.loads(f.read())["public_key"]

    # -- run.start ---------------------------------------------------------------

    def run_start(self, params: dict, request_id: str, owner_uid: int = 0) -> dict:
        """Implements run.start.  Pre-allocation failures raise LexwattError
        (error envelope); probing failures produce a REJECTED run record."""
        for k in params:
            if k not in ("config", "exec"):
                raise LexwattError("UNKNOWN_FIELD")
        cfg = check_config(params["config"])
        execv = check_exec(params["exec"])
        cfg = canonicalize_config(cfg)
        chash = effective_config_hash(cfg)
        # budget-versus-reserve arithmetic before any allocation
        if cfg["budgets"]["max_energy_uj"] is not None:
            m = cfg["meter"]
            reserve = meter.reserve_uj(
                self.host_policy["domains"],
                int(m["stale_us"]),
                int(m["kill_deadline_us"]),
            )
            if int(cfg["budgets"]["max_energy_uj"]) <= reserve:
                raise LexwattError("BUDGET_TOO_SMALL")
        # profile/capability gate before creation
        caps = self.host.capabilities(cfg["profile"])
        if "UNSUPPORTED_PROFILE" in caps["failures"]:
            raise LexwattError("UNSUPPORTED_PROFILE")
        # catalog digest verification is detectable before host allocation
        if cfg["model_catalog"]:
            verify_catalog_digests(cfg, self.model_map, self._hash_file)
        digest = hashing.request_digest("run.start", params)
        run_id = self.ids.new("run", exists=lambda i: i in self.runs)
        idx = self.index
        idx.begin()
        try:
            row = idx.get(owner_uid, request_id)
            if row is not None:
                stored_digest, _ch, stored_run, stored_resp = row
                if stored_digest != digest:
                    idx.rollback()
                    raise LexwattError("CONFLICT")
                if stored_resp is not None:
                    resp = jcs.loads(bytes(stored_resp))
                    idx.commit()
                    return resp["result"]
                # reservation without a response: reconcile from the run journal
                idx.commit()
                return self._reconcile_launch(stored_run)
            idx.reserve(owner_uid, request_id, digest, chash, run_id)
            idx.commit()
        except LexwattError:
            raise
        # create the run record
        run_dir = os.path.join(self.state_root, "runs", run_id)
        os.makedirs(run_dir, mode=0o700)
        journal = Journal(os.path.join(run_dir, "journal.sqlite"))
        key_id, seed, _pub = self._new_key()
        run = Run(self, run_id, key_id, seed, cfg, execv, journal)
        self.runs[run_id] = run
        try:
            run.created(request_id, chash)
            run.arming()
            run.arm()
        except AuditFault:
            # audit store unavailable: reject via index, nothing executed
            raise LexwattError("AUDIT_FAULT")
        state = run.core.state
        if state == "REJECTED":
            result = {"run_id": run_id, "state": "REJECTED", "error": run.rejected_code}
        else:
            result = {"run_id": run_id, "state": "ARMING", "error": None}
        idx.begin()
        try:
            idx.store_response(owner_uid, request_id, jcs.dumps({"v": 1, "id": request_id, "ok": True, "result": result}))
            idx.commit()
        except Exception:
            idx.rollback()
        return result

    def _reconcile_launch(self, run_id: str) -> dict:
        """A reserved launch without a stored response: the run journal is
        authoritative; missing journal evidence rejects without re-executing."""
        run = self.runs.get(run_id)
        if run is not None:
            state = run.core.state
            if state == "REJECTED":
                return {"run_id": run_id, "state": "REJECTED", "error": run.rejected_code}
            return {"run_id": run_id, "state": "ARMING", "error": None}
        # journal may exist on disk even if not in memory (recovery path)
        jpath = os.path.join(self.state_root, "runs", run_id, "journal.sqlite")
        if not os.path.exists(jpath):
            return {"run_id": run_id, "state": "REJECTED", "error": "CONTAINMENT_FAULT"}
        run = self.open_run(run_id)
        if run.core.state == "REJECTED":
            return {"run_id": run_id, "state": "REJECTED", "error": run.rejected_code}
        return {"run_id": run_id, "state": "ARMING", "error": None}

    # -- open an existing run (meter/kill/receipt after supervisor exit) ---------

    def open_run(self, run_id: str) -> "Run":
        run = self.runs.get(run_id)
        if run is not None:
            return run
        scalars.check_id(run_id, "run")
        run_dir = os.path.join(self.state_root, "runs", run_id)
        jpath = os.path.join(run_dir, "journal.sqlite")
        if not os.path.exists(jpath):
            raise LexwattError("NOT_FOUND")
        journal = Journal(jpath)
        # rebuild core state by replaying events
        cfg_bytes = journal.meta_get("config")
        if cfg_bytes is None:
            raise LexwattError("CONTAINMENT_FAULT")
        cfg = jcs.loads(bytes(cfg_bytes))
        key_id = journal.meta_get("key_id").decode()
        exec_bytes = journal.meta_get("exec")
        execv = jcs.loads(bytes(exec_bytes)) if exec_bytes else {"argv": [], "cwd": "/", "env": {}}
        run = Run(self, run_id, key_id, b"\x00" * 32, cfg, execv, journal)
        self._rebuild(run)
        self.runs[run_id] = run
        return run

    def _rebuild(self, run: "Run") -> None:
        """Replay committed events to rebuild the projection; disagreement
        with the stored projection is an integrity fault."""
        from .replay import replay_events

        raw = run.journal.events_after(0, 1000000)
        entries = [jcs.loads(bytes(r)) for r in raw]
        bodies = [e["body"] for e in entries]
        state = replay_events(bodies)
        run.core.state = state
        row = run.journal.run_row(run.run_id)
        if row is not None and row[1] != state and state not in TERMINAL_STATES:
            raise LexwattError("CONTAINMENT_FAULT")
        run.started_us = 0
        for b in bodies:
            d = b["data"]
            if b["kind"] == "RunStarted":
                run.energy_valid = d["coverage"]["energy"] == "package_measured"
                run.energy_complete = d["coverage"]["energy_complete"]
                run.energy_uj = 0
                run.started_us = int(b["t_us"])
            elif b["kind"] == "SampleRecorded":
                run.energy_uj = int(d["sample"]["total_uj"])
            elif b["kind"] == "StopLatched":
                run.core.stop_reason = d["reason"]
                run.core.stop_latched_us = int(b["t_us"])
            elif b["kind"] == "TokenIssued":
                run.core.spawn_issued += 1
                run.core.issue_seq = int(d["issue_seq"])
            elif b["kind"] == "ComputeReserved":
                run.core.charged_flops += int(d["reservation"]["charged_flops"])
            elif b["kind"] == "ContainmentEmpty":
                run.containment_empty = True
            elif b["kind"] == "RunFinalized":
                run.kill_confirmed = True

    # -- control dispatch -------------------------------------------------------

    def control(self, req: dict, owner_uid: int = 0) -> dict:
        check_request(req)
        try:
            return self._control_checked(req, owner_uid)
        except LexwattError as e:
            return e.to_response(req["id"])

    def _control_checked(self, req: dict, owner_uid: int) -> dict:
        method = req["method"]
        if method not in CONTROL_METHODS and method != "run.start":
            raise LexwattError("UNAUTHORIZED")
        if method == "run.start":
            res = self.run_start(req["params"], req["id"], owner_uid)
            return {"v": 1, "id": req["id"], "ok": True, "result": res}
        run_id = req["params"].get("run_id")
        run = self.runs.get(run_id)
        if run is None:
            try:
                run = self.open_run(run_id)
            except LexwattError:
                raise LexwattError("NOT_FOUND")
        return run.handle(CONTROL_PRINCIPAL, req, None)

    def workload(self, channel_id: str, req: dict) -> dict:
        check_request(req)
        try:
            return self._workload_checked(channel_id, req)
        except LexwattError as e:
            return e.to_response(req["id"])

    def _workload_checked(self, channel_id: str, req: dict) -> dict:
        run = self._run_for_channel(channel_id)
        if run is None:
            raise LexwattError("NOT_FOUND")
        return run.handle(f"ch:{channel_id}", req, channel_id)

    def _run_for_channel(self, channel_id: str) -> Run | None:
        for r in self.runs.values():
            if channel_id in r.channels:
                return r
        return None

    def tick_all(self) -> None:
        for r in self.runs.values():
            r.tick()

    # -- pure methods (in-process only; no run context needed) --------------------

    def pure_call(self, req: dict) -> dict:
        """In-process execution of the four pure methods with the same
        request/response envelopes."""
        check_request(req)
        method = req["method"]
        if method not in PURE_METHODS:
            raise LexwattError("UNAUTHORIZED")
        result = self.pure(method, req["params"])
        return {"v": 1, "id": req["id"], "ok": True, "result": result}

    def pure(self, method: str, params: dict):
        from .estimator import estimate_for_model_work
        from .verify import verify_bundle
        from .core import choose_route
        from .schema import check_model, check_pin, check_bundle

        if method == "capabilities.get":
            for k in params:
                if k != "profile":
                    raise LexwattError("UNKNOWN_FIELD")
            profile = params.get("profile")
            if profile not in ("linux-rapl-v1", "linux-ledger-v1", "offline-v1"):
                raise LexwattError("INVALID_INPUT")
            return self.host.capabilities(profile)
        if method == "estimate.compute":
            for k in params:
                if k not in ("model", "work"):
                    raise LexwattError("UNKNOWN_FIELD")
            return estimate_for_model_work(params["model"], params["work"])
        if method == "route.choose":
            for k in params:
                if k not in ("models", "input_tokens", "max_output_tokens", "batch", "remaining_flops"):
                    raise LexwattError("UNKNOWN_FIELD")
            models = params["models"]
            if not isinstance(models, list) or len(models) > 32:
                raise LexwattError("INVALID_INPUT")
            for m in models:
                check_model(m)
            batch = params["batch"]
            if not isinstance(batch, int) or isinstance(batch, bool):
                raise LexwattError("INVALID_INPUT")
            work_fields = {
                "input_tokens": scalars.check_u(params["input_tokens"]),
                "max_output_tokens": scalars.check_u(params["max_output_tokens"]),
                "batch": batch,
            }
            remaining = scalars.parse_u(params["remaining_flops"])
            return choose_route(models, work_fields, remaining)
        if method == "receipt.verify":
            for k in params:
                if k not in ("bundle", "pins", "require_complete"):
                    raise LexwattError("UNKNOWN_FIELD")
            bundle = params["bundle"]
            check_bundle(bundle)
            pins = params["pins"]
            if not isinstance(pins, list) or len(pins) > 32:
                raise LexwattError("INVALID_INPUT")
            for p in pins:
                check_pin(p)
            rc = params["require_complete"]
            if not isinstance(rc, bool):
                raise LexwattError("INVALID_INPUT")
            return verify_bundle(bundle, pins, rc)
        raise LexwattError("INVALID_INPUT")
