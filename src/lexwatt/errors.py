"""LexWatt error codes, run states, stop reasons, and CLI exit mapping.

All enumerations are the closed sets from LEXWATT_SPEC_EXTREME.md §4.1.
"""

from __future__ import annotations

CODES: tuple[str, ...] = (
    "INVALID_INPUT",
    "UNKNOWN_FIELD",
    "UNSUPPORTED_VERSION",
    "UNSUPPORTED_PROFILE",
    "UNSUPPORTED_MODEL",
    "UNAUTHORIZED",
    "NOT_FOUND",
    "CONFLICT",
    "BUDGET_TOO_SMALL",
    "FLOPS_CAP",
    "SPAWN_CAP",
    "ENVELOPE_EXCEEDED",
    "SENSOR_UNAVAILABLE",
    "SENSOR_FAULT",
    "OVERFLOW",
    "STOPPED",
    "TOKEN_EXPIRED",
    "TOKEN_USED",
    "TOKEN_BINDING",
    "TOKEN_INVALID",
    "ACTION_DENIED",
    "ACTION_FAILED",
    "BUSY",
    "AUDIT_FAULT",
    "CONTAINMENT_FAULT",
    "INCOMPLETE",
    "HASH_MISMATCH",
    "SIGNATURE_INVALID",
    "UNTRUSTED_KEY",
    "CHAIN_INVALID",
    "TRANSITION_INVALID",
    "OUTPUT_LIMIT",
)

STATES: tuple[str, ...] = (
    "CREATED",
    "ARMING",
    "RUNNING",
    "STOPPING",
    "UNCONFIRMED",
    "FINALIZING",
    "REJECTED",
    "COMPLETED",
    "KILLED",
    "FAILED",
)

TERMINAL_STATES: frozenset[str] = frozenset({"REJECTED", "COMPLETED", "KILLED", "FAILED"})

REASONS: tuple[str, ...] = (
    "ENERGY_GUARD",
    "FLOPS_CAP",
    "SPAWN_CAP",
    "WALL_CAP",
    "SENSOR_FAULT",
    "AUDIT_FAULT",
    "WATCHDOG_LOST",
    "OPERATOR",
    "SIGNAL",
    "ROOT_EXIT",
    "CONTAINMENT_FAULT",
    "MEASUREMENT_OVERRUN",
    "RESOURCE_LIMIT",
)

BUDGET_REASONS: frozenset[str] = frozenset(
    {"ENERGY_GUARD", "FLOPS_CAP", "SPAWN_CAP", "WALL_CAP", "MEASUREMENT_OVERRUN"}
)
FAULT_REASONS: frozenset[str] = frozenset(
    {"SENSOR_FAULT", "AUDIT_FAULT", "WATCHDOG_LOST", "CONTAINMENT_FAULT", "RESOURCE_LIMIT"}
)
OPERATOR_REASONS: frozenset[str] = frozenset({"OPERATOR", "SIGNAL", "ROOT_EXIT"})

EVENT_KINDS: tuple[str, ...] = (
    "RunCreated",
    "RunArming",
    "RunStarted",
    "RunRejected",
    "SampleRecorded",
    "ComputeReserved",
    "ComputeFinished",
    "TokenIssued",
    "TokenExpired",
    "TokenSpent",
    "ActionFinished",
    "ActionUnknown",
    "RequestDenied",
    "StopLatched",
    "FaultObserved",
    "KillIssued",
    "KillUnconfirmed",
    "ContainmentEmpty",
    "RunFinalized",
)

METHODS: tuple[str, ...] = (
    "capabilities.get",
    "estimate.compute",
    "route.choose",
    "run.start",
    "run.get",
    "run.stop",
    "events.read",
    "token.issue",
    "action.dispatch",
    "action.get",
    "compute.reserve",
    "compute.finish",
    "receipt.verify",
)

# Method -> surface.  Control methods run on the owner-authenticated Unix
# stream; workload methods on the preopened fd-3 socketpair channel.  The four
# pure methods are permitted on either surface and in-process.
CONTROL_METHODS: frozenset[str] = frozenset({"run.get", "run.stop", "events.read"})
WORKLOAD_METHODS: frozenset[str] = frozenset(
    {"token.issue", "action.dispatch", "action.get", "compute.reserve", "compute.finish"}
)
PURE_METHODS: frozenset[str] = frozenset(
    {"capabilities.get", "estimate.compute", "route.choose", "receipt.verify"}
)


class LexwattError(Exception):
    """Structured protocol/CLI error.  ``code`` is a member of CODES."""

    def __init__(self, code: str, retryable: bool = False):
        if code not in CODES:
            raise ValueError(f"unknown code {code!r}")
        self.code = code
        self.retryable = retryable or code == "BUSY"
        super().__init__(code)

    def to_error_obj(self) -> dict:
        return {"v": 1, "error": {"code": self.code, "retryable": self.retryable}}

    def to_response(self, request_id: str) -> dict:
        return {
            "v": 1,
            "id": request_id,
            "ok": False,
            "error": {"code": self.code, "retryable": self.retryable},
        }


def ok(request_id: str, result) -> dict:
    """Response envelope constructor; no field is ever omitted."""
    return {"v": 1, "id": request_id, "ok": True, "result": result}


# CLI exit mapping per spec §8.2.  Codes absent from every bucket exit 64.
_EXIT_64 = {
    "INVALID_INPUT",
    "UNKNOWN_FIELD",
    "OVERFLOW",
    "NOT_FOUND",
    "CONFLICT",
    "UNAUTHORIZED",
    "UNSUPPORTED_VERSION",
    "TOKEN_EXPIRED",
    "TOKEN_USED",
    "TOKEN_BINDING",
    "TOKEN_INVALID",
    "ACTION_DENIED",
    "ACTION_FAILED",
    "ENVELOPE_EXCEEDED",
    "OUTPUT_LIMIT",
}
_EXIT_65 = {"UNSUPPORTED_PROFILE", "UNSUPPORTED_MODEL", "SENSOR_UNAVAILABLE", "BUDGET_TOO_SMALL"}
_EXIT_70 = {"SENSOR_FAULT", "AUDIT_FAULT", "CONTAINMENT_FAULT", "STOPPED"}
_EXIT_75 = {"BUSY"}
_EXIT_76 = {
    "HASH_MISMATCH",
    "SIGNATURE_INVALID",
    "UNTRUSTED_KEY",
    "CHAIN_INVALID",
    "TRANSITION_INVALID",
    "INCOMPLETE",
}
_EXIT_124 = {"FLOPS_CAP", "SPAWN_CAP"}


def exit_code_for(code: str) -> int:
    """Map a protocol Code to the §8.2 CLI exit status."""
    if code in _EXIT_65:
        return 65
    if code in _EXIT_70:
        return 70
    if code in _EXIT_75:
        return 75
    if code in _EXIT_76:
        return 76
    if code in _EXIT_124:
        return 124
    return 64
