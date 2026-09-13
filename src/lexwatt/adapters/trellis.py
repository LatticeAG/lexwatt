"""Trellis cap-engine adapter boundary (spec §8.3, INTERFACES.md E28).

A future Trellis adapter maps start=config+exec, status=run.get,
events=events.read, stop=run.stop onto a dedicated authenticated control
channel.  Protocol 1 has no detach/lease-transfer method and no certified
joint containment: the controlling channel must assume the CLI lifetime
lease explicitly, so integration cannot be claimed shipped.

Per INTERFACES.md E28 the honest current answer is
CAP_ADAPTER_UNAVAILABLE.
"""

from __future__ import annotations

SPEC_REF = "lexwatt/LEXWATT_SPEC_EXTREME.md §8.3"


class TrellisAdapterUnavailable(NotImplementedError):
    """Returned wherever a Trellis joint-containment call would go."""

    def __init__(self):
        super().__init__(
            "Trellis adapter is not implemented: protocol 1 has no "
            "lease-transfer or certified joint containment. See " + SPEC_REF
        )


def start(config: dict, execv: dict):
    """Trellis start=config+exec mapping — not shipped (E28: V4)."""
    raise TrellisAdapterUnavailable()


def status(run_id: str):
    """Trellis status=run.get mapping — not shipped (E28: V4)."""
    raise TrellisAdapterUnavailable()


def events(run_id: str, after_seq: str, limit: int):
    """Trellis events=events.read mapping — not shipped (E28: V4)."""
    raise TrellisAdapterUnavailable()


def stop(run_id: str):
    """Trellis stop=run.stop mapping — not shipped (E28: V4)."""
    raise TrellisAdapterUnavailable()


def assume_lifetime_lease(run_id: str):
    """Ownership transfer needed before any joint containment — there is no
    such method in protocol 1 (INTERFACES.md C31)."""
    raise TrellisAdapterUnavailable()
