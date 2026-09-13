"""dense-v1 work estimator (spec §3.2).

The estimate is a cooperative heuristic work envelope, never a proved
hardware bound.  Bounds are checked before the formula is evaluated; the
formula itself is fixed arithmetic.
"""

from __future__ import annotations

from .errors import LexwattError
from .scalars import U_MAX

# Wire-level estimator bounds (spec §3.2 / §4.1).
P_MAX = 10**13
L_MAX = 1000
H_MAX = 10**6
I_MAX = 1048576
O_MAX = 1048576
IO_MAX = 1048576
B_MAX = 256
S_MIN = 1000
S_MAX = 10000

ESTIMATOR_KIND = "dense-v1"


def check_model_dims(parameters: int, layers: int, hidden: int, safety_milli: int) -> None:
    if not (1 <= parameters <= P_MAX):
        raise LexwattError("INVALID_INPUT")
    if not (1 <= layers <= L_MAX):
        raise LexwattError("INVALID_INPUT")
    if not (1 <= hidden <= H_MAX):
        raise LexwattError("INVALID_INPUT")
    if not (S_MIN <= safety_milli <= S_MAX):
        raise LexwattError("INVALID_INPUT")


def check_work_dims(input_tokens: int, max_output_tokens: int, batch: int) -> None:
    if not (1 <= input_tokens <= I_MAX):
        raise LexwattError("INVALID_INPUT")
    if not (0 <= max_output_tokens <= O_MAX):
        raise LexwattError("INVALID_INPUT")
    if input_tokens + max_output_tokens > IO_MAX:
        raise LexwattError("INVALID_INPUT")
    if not (1 <= batch <= B_MAX):
        raise LexwattError("INVALID_INPUT")


def dense_v1(P: int, L: int, H: int, I: int, O: int, B: int, S: int) -> int:
    """Exact dense-v1 arithmetic (spec §3.2).  Bounds checked by callers."""
    base = 2 * P * B * (I + O)
    pairs = I * (I - 1) // 2 + I * O + O * (O - 1) // 2
    attention = 4 * L * H * B * pairs
    result = ((base + attention) * S + 999) // 1000
    if result > U_MAX:
        raise LexwattError("OVERFLOW")
    return result


def estimate_decomposition(P: int, L: int, H: int, I: int, O: int, B: int, S: int) -> dict:
    """Return {base_flops, attention_flops, charged_flops} as U strings."""
    check_model_dims(P, L, H, S)
    check_work_dims(I, O, B)
    base = 2 * P * B * (I + O)
    pairs = I * (I - 1) // 2 + I * O + O * (O - 1) // 2
    attention = 4 * L * H * B * pairs
    total = (base + attention) * S
    if total // 1000 + 1 > U_MAX:
        raise LexwattError("OVERFLOW")
    charged = (total + 999) // 1000
    if base > U_MAX or attention > U_MAX or charged > U_MAX:
        raise LexwattError("OVERFLOW")
    return {
        "base_flops": str(base),
        "attention_flops": str(attention),
        "charged_flops": str(charged),
    }


def estimate_from_parts(
    kind: str,
    parameters: int,
    layers: int,
    hidden: int,
    input_tokens: int,
    max_output_tokens: int,
    batch: int,
    safety_milli: int,
) -> dict:
    """Estimator-level guard: an unrecognized kind is UNSUPPORTED_MODEL here
    (the production wire rejects the same value earlier as INVALID_INPUT)."""
    if kind != ESTIMATOR_KIND:
        raise LexwattError("UNSUPPORTED_MODEL")
    parts = estimate_decomposition(
        parameters, layers, hidden, input_tokens, max_output_tokens, batch, safety_milli
    )
    return {
        "estimator": ESTIMATOR_KIND,
        "base_flops": parts["base_flops"],
        "attention_flops": parts["attention_flops"],
        "charged_flops": parts["charged_flops"],
        "coverage": "cooperative_estimate",
    }


def estimate_for_model_work(model: dict, work: dict) -> dict:
    """estimate.compute semantics: model/work ids must match."""
    from .schema import check_model, check_work  # local import avoids a cycle

    check_model(model)
    check_work(work)
    if work["model_id"] != model["id"]:
        raise LexwattError("INVALID_INPUT")
    return estimate_from_parts(
        model["kind"],
        int(model["parameters"]),
        model["layers"],
        model["hidden"],
        int(work["input_tokens"]),
        int(work["max_output_tokens"]),
        work["batch"],
        model["safety_milli"],
    )
