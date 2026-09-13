"""Team rollups — a later paid/hosted surface (spec §1.2, §16 P4).

Only a local export contract ships: receipts are Bundle JSON verified
offline.  There is no rollup service, hosted key service, or commercial
entitlement in v1.  Overlapping package observations must not be summed as
host energy (spec §3.4, INTERFACES.md E45).
"""

from __future__ import annotations

SPEC_REF = "lexwatt/LEXWATT_SPEC_EXTREME.md §§1.2, 8.3"


class RollupsUnavailable(NotImplementedError):
    def __init__(self):
        super().__init__(
            "Team rollups are not implemented: v1 ships only the local "
            "receipt export contract. See " + SPEC_REF
        )


def submit_rollup(bundle: dict):
    """Hosted team-rollup submission — not shipped."""
    raise RollupsUnavailable()


def aggregate_host_energy(bundles: list):
    """Summing overlapping package observations as host energy is explicitly
    forbidden; no aggregation endpoint exists in v1."""
    raise RollupsUnavailable()
