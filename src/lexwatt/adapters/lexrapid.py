"""LexRapid composition boundary (spec §8.3, G7).

The OSS-shippable part is real: route.choose plus remaining capacity derived
from run.get gives LexRapid-style affordable-candidate selection.  The
hosted catalog/routing backend, remote credentials, and model-download path
are not shipped — those raise LexRapidHostedUnavailable.
"""

from __future__ import annotations

from ..core import choose_route
from ..errors import LexwattError
from ..scalars import parse_u

SPEC_REF = "lexwatt/LEXWATT_SPEC_EXTREME.md §8.3"


class LexRapidHostedUnavailable(NotImplementedError):
    def __init__(self):
        super().__init__(
            "LexRapid hosted catalog/routing is not implemented: only "
            "route.choose + compute.reserve composition ships. See " + SPEC_REF
        )


def remaining_flops(status: dict) -> int | None:
    """LexRapid's remaining estimate capacity: max_flops - charged_flops."""
    cap = status["budgets"]["max_flops"]
    if cap is None:
        return None
    return parse_u(cap) - parse_u(status["charged_flops"])


def select(models: list, work_fields: dict, status: dict) -> dict:
    """Return the affordable candidate with the lowest estimated cost, then
    model ID in ASCII byte order.  Selection does not reserve capacity; the
    winner must still pass compute.reserve under the live ledger."""
    rem = remaining_flops(status)
    if rem is None:
        raise LexwattError("INVALID_INPUT")  # no FLOP cap: nothing to route under
    return choose_route(models, work_fields, rem)


def hosted_catalog():
    """LexRapid hosted model catalog — not shipped."""
    raise LexRapidHostedUnavailable()


def routing_backend():
    """LexRapid routing backend — not shipped."""
    raise LexRapidHostedUnavailable()


def model_download(model_id: str):
    """Remote model download path — not shipped."""
    raise LexRapidHostedUnavailable()
