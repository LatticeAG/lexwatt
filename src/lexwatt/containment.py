"""Containment and kill semantics (spec §2.4, §5.1).

Cgroup membership, not a snapshot of descendant PIDs, is authoritative.
These are the decision functions used by the supervisor, the guardian, and
the conformance harness; the Linux backend executes the same decisions
through real kernel interfaces.
"""

from __future__ import annotations

from .errors import LexwattError


def cgroup_kill(owned_processes: list[dict], kernel_tasks_killable: bool) -> dict:
    """cgroup.kill kills every member of the owned cgroup regardless of
    process group; setsid/double-fork does not escape."""
    if not kernel_tasks_killable:
        return {"surviving_owned_processes": list(owned_processes), "populated": 1}
    return {"surviving_owned_processes": [], "populated": 0}


def evaluate_deadline(
    state: str, kill_deadline_us: int, elapsed_us: int, populated: int, effects_closed: bool
) -> dict:
    """After kill_deadline_us without empty containment the run is
    UNCONFIRMED, exit 70, kill/reap attempts continue."""
    empty = populated == 0 and effects_closed
    if state == "STOPPING" and not empty and elapsed_us >= kill_deadline_us:
        return {
            "state": "UNCONFIRMED",
            "cli_exit": 70,
            "receipt_completeness": "PREFIX",
            "continue_kill_attempts": True,
        }
    if empty:
        return {
            "state": "FINALIZING",
            "cli_exit": 0,
            "receipt_completeness": "COMPLETE",
            "continue_kill_attempts": False,
        }
    return {
        "state": state,
        "cli_exit": None,
        "receipt_completeness": "PREFIX",
        "continue_kill_attempts": True,
    }


def check_pid_identity(
    recorded_pid: int,
    recorded_start: str,
    current_start: str,
    pidfd_available: bool,
    cgroup_identity_matches: bool,
) -> dict:
    """A process-group signal is used only while its pinned group leader
    remains owned; an uncertain group identifier is never signaled."""
    if pidfd_available and cgroup_identity_matches and recorded_start == current_start:
        return {"signals_sent": 1, "error": None}
    return {"signals_sent": 0, "error": "CONTAINMENT_FAULT"}


def monitor_loss(case: str, kernel_tasks_killable: bool = True) -> dict:
    """Guardian kills on lifetime-pipe EOF, supervisor EOF, or stale pulse;
    the supervisor kills if its guardian channel disappears."""
    if case not in ("supervisor_eof", "guardian_eof", "client_lifetime_eof"):
        raise LexwattError("INVALID_INPUT")
    return {"kill_requested": True, "workload_survivors": 0 if kernel_tasks_killable else 1}


def audit_store_failure(workload_running: bool) -> dict:
    """Kill issuance never waits for a successful receipt write; an audit
    failure is a reason to stop, not to defer stopping."""
    return {
        "kill_requested": True if workload_running else True,
        "new_dispatches": 0,
        "receipt_completeness": "PREFIX",
        "cli_exit": 70,
    }


def wall_deadline(boottime_elapsed_us: int, max_wall_us: int) -> dict:
    """The wall deadline trips when elapsed_us >= max_wall_us; wall-clock
    adjustments cannot extend it (BOOTTIME domain only)."""
    if boottime_elapsed_us >= max_wall_us:
        return {"state": "STOPPING", "reason": "WALL_CAP"}
    return {"state": "RUNNING", "reason": None}
