"""Deterministic simulated host backend — the spec's "mocked reference
host" (§7.1) used by the conformance suite and unit tests.

It models the same semantics the Linux backend enforces for real:
nonoverlapping package domains, wrap-around counters, cgroup kill that
empties all owned processes regardless of process group, and task-UID
pooling.  Sensor traces and clocks are injected.
"""

from __future__ import annotations

from ..errors import LexwattError


class SimDomain:
    def __init__(self, dom_id: str, range_uj: int):
        self.id = dom_id
        self.range_uj = range_uj
        self.counter = 0
        self.enabled = True
        self.trace: list[int] = []  # optional scripted counter values
        self.trace_pos = 0

    def read(self, now_us: int) -> tuple[int, int, int]:
        if not self.enabled:
            raise LexwattError("SENSOR_FAULT")
        if self.trace_pos < len(self.trace):
            self.counter = self.trace[self.trace_pos]
            self.trace_pos += 1
        return (self.counter, self.range_uj, now_us)


class SimProc:
    _next_pid = 1000

    def __init__(self, execv: dict, channel_id: str):
        SimProc._next_pid += 1
        self.pid = SimProc._next_pid
        self.execv = execv
        self.channel_id = channel_id
        self.alive = True
        self.exit: dict | None = None
        # scripted exit: {exit: {"code": n} or {"signal": n}}
        self.script_exit: dict | None = None

    def request_exit(self, exit_obj: dict):
        """The workload exits on its own (root exit observation)."""
        if self.alive:
            self.alive = False
            self.exit = exit_obj

    def sigkill(self):
        if self.alive:
            self.alive = False
            self.exit = {"code": None, "signal": 9}


class SimCgroup:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.procs: list[SimProc] = []
        self.usage_us = 0
        self.inode = 70000 + SimProc._next_pid
        self.path = f"/sys/fs/cgroup/lexwatt/{run_id}"
        self.destroyed = False

    def populated(self) -> int:
        return 1 if any(p.alive for p in self.procs) else 0


class SimHost:
    name = "sim"

    def __init__(
        self,
        domains: dict[str, int] | None = None,  # id -> range_uj
        cgroup_kill_ok: bool = True,
        task_uid_pool: tuple[int, int] = (62000, 62031),
        namespace_ok: bool = True,
        seccomp_ok: bool = True,
    ):
        self._domains = {k: SimDomain(k, v) for k, v in (domains or {}).items()}
        self._cgroup_kill_ok = cgroup_kill_ok
        self._uid_pool = task_uid_pool
        self._namespace_ok = namespace_ok
        self._seccomp_ok = seccomp_ok
        self._allocated_uids: set[int] = set()
        self._cgroups: dict[str, SimCgroup] = {}
        self._workspace_leases: dict[str, str] = {}
        self._now_us = 0
        self._boot_id = "00000000-0000-0000-0000-000000000000"
        self.kernel_tasks_killable = True
        self.spawned: list[SimProc] = []
        self.http_responses: dict[tuple[str, str], dict] = {}
        self.kill_calls = 0

    # --- clocks / identity --------------------------------------------------
    def set_time(self, us: int) -> None:
        self._now_us = us

    def advance(self, us: int) -> None:
        self._now_us += us

    def boottime_us(self) -> int:
        return self._now_us

    def boot_id(self) -> str:
        return self._boot_id

    # --- capabilities ---------------------------------------------------------
    def capabilities(self, profile: str) -> dict:
        failures = []
        cgroup_kill = self._cgroup_kill_ok
        namespaces = self._namespace_ok
        seccomp = self._seccomp_ok
        uid_iso = True
        domains = sorted(self._domains.keys())
        if not cgroup_kill:
            failures.append("UNSUPPORTED_PROFILE")
        if not namespaces or not seccomp or not uid_iso:
            failures.append("UNSUPPORTED_PROFILE")
        if profile == "linux-rapl-v1" and not domains:
            failures.append("SENSOR_UNAVAILABLE")
        return {
            "profile": profile,
            "cgroup_kill": cgroup_kill,
            "task_uid_isolation": uid_iso,
            "seccomp": seccomp,
            "namespaces": namespaces,
            "rapl_domains": domains,
            "failures": failures,
        }

    def task_uid_alloc(self, lo: int, hi: int, in_use: set[int]) -> int:
        for u in range(lo, hi + 1):
            if u not in in_use and u not in self._allocated_uids:
                self._allocated_uids.add(u)
                return u
        raise LexwattError("BUSY")

    def task_uid_free(self, uid: int) -> None:
        self._allocated_uids.discard(uid)

    def workspace_lease(self, path: str, run_id: str) -> None:
        holder = self._workspace_leases.get(path)
        if holder is not None and holder != run_id:
            raise LexwattError("BUSY")
        self._workspace_leases[path] = run_id

    def workspace_release(self, path: str, run_id: str) -> None:
        if self._workspace_leases.get(path) == run_id:
            del self._workspace_leases[path]

    # --- cgroups -----------------------------------------------------------------
    def cgroup_create(self, run_id: str, cfg: dict, domain_cpus: str) -> SimCgroup:
        if not self._cgroup_kill_ok:
            raise LexwattError("CONTAINMENT_FAULT")
        cg = SimCgroup(run_id)
        self._cgroups[run_id] = cg
        return cg

    def cgroup_usage_us(self, cg: SimCgroup) -> int:
        return cg.usage_us

    def set_usage(self, cg: SimCgroup, usage_us: int) -> None:
        cg.usage_us = usage_us

    def cgroup_populated(self, cg: SimCgroup) -> int:
        return cg.populated()

    def cgroup_kill(self, cg: SimCgroup) -> bool:
        self.kill_calls += 1
        if self.kernel_tasks_killable:
            for p in cg.procs:
                p.sigkill()
        else:
            for p in cg.procs:
                if p.alive and not getattr(p, "unkillable", False):
                    p.sigkill()
        return True

    def group_kill(self, cg: SimCgroup) -> bool:
        for p in cg.procs:
            p.sigkill()
        return True

    def cgroup_teardown(self, cg: SimCgroup) -> None:
        cg.destroyed = True

    # --- domains --------------------------------------------------------------------
    def open_domains(self, domain_ids: list[str]) -> list[SimDomain]:
        out = []
        for d in domain_ids:
            if d not in self._domains:
                raise LexwattError("SENSOR_UNAVAILABLE")
            out.append(self._domains[d])
        return out

    def read_domain(self, handle: SimDomain) -> tuple[int, int, int]:
        return handle.read(self._now_us)

    def set_domain_counter(self, dom_id: str, value: int) -> None:
        self._domains[dom_id].counter = value

    def advance_domain(self, dom_id: str, delta: int) -> None:
        self._domains[dom_id].counter = (self._domains[dom_id].counter + delta) % self._domains[dom_id].range_uj

    # --- processes ---------------------------------------------------------------------
    def _spawn(self, execv: dict, channel_id: str) -> SimProc:
        p = SimProc(execv, channel_id)
        self.spawned.append(p)
        return p

    def spawn_root(self, run_ctx, execv: dict, channel_id: str) -> SimProc:
        p = self._spawn(execv, channel_id)
        run_ctx.cgroup.procs.append(p)
        return p

    def spawn_child(self, run_ctx, execv: dict, channel_id: str) -> SimProc:
        p = self._spawn(execv, channel_id)
        run_ctx.cgroup.procs.append(p)
        if len([x for x in run_ctx.cgroup.procs if x.alive]) > run_ctx.cfg["pids_max"]:
            p.sigkill()
            raise LexwattError("ACTION_FAILED")
        return p

    def proc_exited(self, proc: SimProc) -> dict | None:
        return proc.exit if not proc.alive else None

    def proc_alive(self, proc: SimProc) -> bool:
        return proc.alive

    # --- network -----------------------------------------------------------------------
    def http_get(self, dest: dict, action: dict, deadline_us: int) -> dict:
        key = (dest["origin"], dest["path"])
        resp = self.http_responses.get(key)
        if resp is None:
            raise LexwattError("ACTION_FAILED")
        return resp
