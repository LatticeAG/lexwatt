"""RAPL sampling arithmetic, energy guard, topology, attribution (§3.4/§3.5).

All arithmetic is integer.  Harness diagnostic reasons (WRAP_AMBIGUOUS,
COUNTER_RANGE, DELTA_IMPLAUSIBLE, STALE_SAMPLE, OVERLAPPING_DOMAINS) are
surfaced through ``SensorFault.reason``.
"""

from __future__ import annotations

from .errors import LexwattError


class SensorFault(LexwattError):
    """SENSOR_FAULT with a machine-readable diagnostic reason."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__("SENSOR_FAULT")


def rapl_delta(a: int, b: int, range_uj: int, dt_us: int, stale_us: int, power_uw: int, margin_uj: int) -> int:
    """Delta between consecutive counter readings with wrap plausibility.

    Require 0<=a,b<R and unchanged range/domain identity; use the actual
    BOOTTIME interval dt; reject stale intervals, intervals where the
    physically possible draw reaches the counter range (ambiguous wraps),
    and deltas beyond the possible draw.
    """
    if range_uj <= 0:
        raise SensorFault("COUNTER_RANGE")
    if not (0 <= a < range_uj) or not (0 <= b < range_uj):
        raise SensorFault("COUNTER_RANGE")
    if dt_us > stale_us:
        raise SensorFault("STALE_SAMPLE")
    possible = (power_uw * dt_us + 999_999) // 1_000_000 + margin_uj
    if possible >= range_uj:
        raise SensorFault("WRAP_AMBIGUOUS")
    delta = (b - a + range_uj) % range_uj
    if delta > possible:
        raise SensorFault("DELTA_IMPLAUSIBLE")
    return delta


def reserve_uj(power_domains: list[dict], stale_us: int, kill_deadline_us: int) -> int:
    """sum(ceil(P_d*(stale_us+kill_deadline_us)/1e6) + margin_d)."""
    total = 0
    for d in power_domains:
        p = int(d["max_power_uw"])
        margin = int(d["margin_uj"])
        total += (p * (stale_us + kill_deadline_us) + 999_999) // 1_000_000 + margin
    return total


def guard_eval(
    energy_uj: int,
    cap_uj: int,
    reserve: int,
) -> tuple[str, str | None]:
    """Energy guard: returns (state, reason).

    A valid sample showing E >= cap latches MEASUREMENT_OVERRUN; equality of
    E+reserve with cap latches ENERGY_GUARD; otherwise the run continues.
    """
    if energy_uj >= cap_uj:
        return ("STOPPING", "MEASUREMENT_OVERRUN")
    if energy_uj + reserve >= cap_uj:
        return ("STOPPING", "ENERGY_GUARD")
    return ("RUNNING", None)


def check_topology(selected: list[str], parents: dict[str, str], cpus: dict[str, set[int]] | None = None) -> None:
    """Reject parent/child overlap or duplicate physical package coverage."""
    if len(set(selected)) != len(selected):
        raise LexwattError("INVALID_INPUT")  # duplicate domain id
    sel = set(selected)
    for d in selected:
        anc = parents.get(d)
        seen = set()
        while anc is not None and anc not in seen:
            seen.add(anc)
            if anc in sel:
                err = LexwattError("INVALID_INPUT")
                err.reason = "OVERLAPPING_DOMAINS"
                raise err
            anc = parents.get(anc)
    if cpus is not None:
        covered: set[int] = set()
        for d in selected:
            for c in cpus.get(d, set()):
                if c in covered:
                    err = LexwattError("INVALID_INPUT")
                    err.reason = "OVERLAPPING_DOMAINS"
                    raise err
                covered.add(c)


def attribute_shared_inclusive(package_delta_uj: int, runs: list[str]) -> list[int]:
    """A shared package's entire measured delta is charged to each run
    pinned to it; no idle subtraction or CPU-share attribution."""
    return [package_delta_uj for _ in runs]


STUCK_ENERGY_WINDOW_US = 1_000_000
STUCK_CPU_ADVANCE_US = 10_000


def stuck_sensor(unchanged_us: int, cpu_advance_us: int) -> bool:
    """All selected energy counters unchanged for 1000000 us while cgroup
    CPU usage advanced at least 10000 us latches SENSOR_FAULT."""
    return unchanged_us >= STUCK_ENERGY_WINDOW_US and cpu_advance_us >= STUCK_CPU_ADVANCE_US
