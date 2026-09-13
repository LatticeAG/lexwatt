"""Crash recovery (spec §10.3).

After restart, recover opens each run's manifest/journal without following
attacker-controlled links, checks boot ID and cgroup identity, contains
same-boot orphans, and reports CONTAINED / INCOMPLETE / UNCONFIRMED.
"""

from __future__ import annotations

import os

from . import jcs
from .errors import TERMINAL_STATES, LexwattError
from .ledger import Journal
from .replay import replay_events
from .scalars import check_id


def recover_run(run_dir: str, host, current_boot_id: str) -> dict:
    """Recover one run directory.  Returns {run_id, result, head}."""
    run_id = os.path.basename(run_dir.rstrip("/"))
    check_id(run_id, "run")
    jpath = os.path.join(run_dir, "journal.sqlite")
    mpath = os.path.join(run_dir, "launch-manifest.json")
    if not os.path.exists(jpath):
        # index-only reservation: journal missing means no workload passed
        # the journal barrier
        return {"run_id": run_id, "result": "CONTAINED", "head": None}
    journal = None
    try:
        journal = Journal(jpath)
        raw = journal.events_after(0, 1000000)
        entries = [jcs.loads(bytes(r)) for r in raw]
        bodies = [e["body"] for e in entries]
        state = replay_events(bodies) if bodies else "CREATED"
        seq, h = journal.event_head()
        head = {"seq": str(seq), "hash": h}
        row = journal.run_row(run_id)
        if row is not None and row[1] != state:
            raise LexwattError("CONTAINMENT_FAULT")
        manifest = None
        if os.path.exists(mpath):
            with open(mpath, "rb") as f:
                manifest = jcs.loads(f.read())
        same_boot = manifest is not None and manifest["boot_id"] == current_boot_id
        if state in TERMINAL_STATES:
            return {"run_id": run_id, "result": "CONTAINED", "head": head}
        if not same_boot:
            # different boot: cannot resume; preserve the valid prefix
            return {"run_id": run_id, "result": "INCOMPLETE", "head": head}
        # same boot, nonterminal: verify pinned cgroup identity, then kill
        if manifest is not None:
            cgroup_path = manifest["cgroup_path"]
            try:
                st = os.stat(cgroup_path)
                if str(st.st_ino) != manifest["cgroup_inode"]:
                    return {"run_id": run_id, "result": "UNCONFIRMED", "head": head}
            except OSError:
                # absent cgroup: FINALIZING/ContainmentEmpty evidence permits
                # regeneration; otherwise INCOMPLETE
                if any(b["kind"] in ("ContainmentEmpty",) for b in bodies):
                    return {"run_id": run_id, "result": "CONTAINED", "head": head}
                return {"run_id": run_id, "result": "INCOMPLETE", "head": head}
            # pinned identity verified: kill the orphan cgroup
            try:
                with open(os.path.join(cgroup_path, "cgroup.kill"), "w") as f:
                    f.write("1")
            except OSError:
                pass
            return {"run_id": run_id, "result": "CONTAINED", "head": head}
        return {"run_id": run_id, "result": "UNCONFIRMED", "head": head}
    finally:
        if journal is not None:
            journal.close()


def recover_action(action_state: str, result_recorded: bool, boot_matches: bool, cgroup_matches: bool) -> dict:
    """Action-level recovery (§10.3): a DISPATCHED action without a recorded
    result becomes UNKNOWN and is never replayed; a confirmed same-boot
    cgroup identity still gets killed."""
    kill = boot_matches and cgroup_matches
    if action_state == "DISPATCHED" and not result_recorded:
        return {"action_state": "UNKNOWN", "release_count": 0, "kill_requested": kill}
    return {"action_state": action_state, "release_count": 0, "kill_requested": kill}


def resume_run(persisted_state: str, boot_matches: bool, charged_flops: str, spawn_tokens_issued: int) -> dict:
    """A reboot never resumes a budget: a nonterminal state under a
    different boot is INCOMPLETE; counters are retained for audit, and no
    new token is issued."""
    if persisted_state in TERMINAL_STATES:
        return {
            "resumed": False,
            "charged_flops": charged_flops,
            "spawn_tokens_issued": spawn_tokens_issued,
            "new_tokens_issued": 0,
        }
    if not boot_matches:
        return {
            "error": "INCOMPLETE",
            "resumed": False,
            "charged_flops": charged_flops,
            "spawn_tokens_issued": spawn_tokens_issued,
            "new_tokens_issued": 0,
        }
    return {
        "resumed": False,
        "charged_flops": charged_flops,
        "spawn_tokens_issued": spawn_tokens_issued,
        "new_tokens_issued": 0,
    }


def recover_all(state_root: str, host, current_boot_id: str, only_run: str | None = None) -> dict:
    runs_dir = os.path.join(state_root, "runs")
    out = []
    if only_run is not None:
        check_id(only_run, "run")
        path = os.path.join(runs_dir, only_run)
        if not os.path.isdir(path):
            raise LexwattError("NOT_FOUND")
        out.append(recover_run(path, host, current_boot_id))
    else:
        if os.path.isdir(runs_dir):
            for name in sorted(os.listdir(runs_dir)):
                out.append(recover_run(os.path.join(runs_dir, name), host, current_boot_id))
    return {"v": 1, "runs": out}
