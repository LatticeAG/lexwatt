"""Named conformance fixtures (spec §7.1, §15.2).

The `$NAME` substitution convention belongs to the test harness only.
TOKEN is constructed exactly per spec: body signed with the public RFC 8032
test seed (never deployed).
"""

from lexwatt import ed25519, hashing

R = "lwr_000000000000000000001"
Q = "lwq_000000000000000000001"
C = "lwc_000000000000000000001"
A = "lwa_000000000000000000001"
T = "lwt_000000000000000000001"
P = "lwp_000000000000000000001"
K = "lwk_000000000000000000001"
Z = "0" * 64

M = {
    "id": "dense-small",
    "kind": "dense-v1",
    "parameters": "1000",
    "layers": 1,
    "hidden": 10,
    "tokenizer_hash": "d79684d992c6150eea853d790cdef25f804d994cfe3a9198a5b012132dc46ec6",
    "artifact_hash": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "safety_milli": 1100,
}

W = {"model_id": "dense-small", "input_tokens": "2", "max_output_tokens": "3", "batch": 1}

EST = {
    "estimator": "dense-v1",
    "base_flops": "10000",
    "attention_flops": "400",
    "charged_flops": "11440",
    "coverage": "cooperative_estimate",
}

B = {"max_flops": "20000", "max_energy_uj": "1000000", "spawns": 1, "max_wall_us": "10000000"}

COV = {
    "flops": "cooperative_estimate",
    "energy": "package_measured",
    "domains": ["package-0"],
    "energy_complete": False,
    "reserve_uj": "300000",
    "host_power_assumption": True,
    "assumptions": {
        "meter": {"interval_us": "100000", "stale_us": "200000", "kill_deadline_us": "100000"},
        "power": [{"domain": "package-0", "max_power_uw": "1000000", "margin_uj": "0"}],
    },
}

EX = {"argv": ["/usr/bin/python3", "/work/job.py"], "cwd": "/work", "env": {"LANG": "C.UTF-8"}}

ACT = {"kind": "spawn", "exec": {"argv": ["/usr/bin/true"], "cwd": "/work", "env": {}}}

CFG = {
    "v": 1,
    "profile": "linux-rapl-v1",
    "workspace_root": "/srv/lexwatt/work",
    "budgets": B,
    "meter": {"interval_us": "100000", "stale_us": "200000", "kill_deadline_us": "100000"},
    "pids_max": 64,
    "memory_max_bytes": "1073741824",
    "log_max_bytes": "67108864",
    "model_catalog": [M],
    "network": [],
    "flops_trust": "cooperative",
}

RES = {
    "compute_id": C,
    "work": W,
    "charged_flops": "11440",
    "state": "CHARGED",
    "observed_output_tokens": None,
    "observed_flops": None,
}

# §15.2 public test key material (RFC 8032; never deployed).
SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
SEED = bytes.fromhex(SEED_HEX)
PUB = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"

TOKEN_BODY = {
    "v": 1,
    "key_id": K,
    "token_id": T,
    "run_id": R,
    "channel_id": P,
    "action_hash": hashing.action_hash(ACT),
    "issued_us": "0",
    "expires_us": "1000000",
    "issue_seq": "4",
}
TOKEN = {
    "body": TOKEN_BODY,
    "sig": ed25519.sign_b64(SEED, hashing.token_sign_message(TOKEN_BODY)),
}

E1 = {
    "body": {
        "v": 1,
        "run_id": R,
        "event_id": "lwe_000000000000000000001",
        "key_id": K,
        "seq": "1",
        "prev_hash": Z,
        "t_us": "0",
        "kind": "RunCreated",
        "data": {"config_hash": "0587b9faaf456ac6b84a092d6c73261269f82ce2b40bf972d7f0e0fba671b3dd"},
    },
    "hash": "8289323c2e35432dd855b87a9e38b9890d74b9b476c439e19d48cfb55a499c1f",
    "sig": "l34fqScQFAVOMVFMQBwh3CzD87c90R8dFoQKuBOKaBWl2sOZQIApvVu_6PHofB_fiT7kMrdO45Uxs3LMoG4TBw",
}

E2 = {
    "body": {
        "v": 1,
        "run_id": R,
        "event_id": "lwe_000000000000000000002",
        "key_id": K,
        "seq": "2",
        "prev_hash": "8289323c2e35432dd855b87a9e38b9890d74b9b476c439e19d48cfb55a499c1f",
        "t_us": "1",
        "kind": "RunRejected",
        "data": {"code": "SENSOR_UNAVAILABLE"},
    },
    "hash": "19c47ef3490cf77f7df075b58ec06009191f74830080a3aefd1ad7a299f776ed",
    "sig": "D0gESWxAizRsoEtGHf0U2meKDoMHk44NwK1nQ-kZZk6UXiRQt4wTsZQ7Y49XJQ9bRwCaQPYQduMUQI5NeqWQCw",
}

H1 = E1["hash"]
H2 = E2["hash"]

STATUS = {
    "run_id": R,
    "state": "RUNNING",
    "budgets": B,
    "charged_flops": "0",
    "energy_uj": "0",
    "spawn_tokens_issued": 0,
    "elapsed_us": "0",
    "root_exit": None,
    "stop_reason": None,
    "coverage": COV,
    "head": {"seq": "3", "hash": Z},
}

# The synthetic artifact/tokenizer bytes whose digests appear in M.
ARTIFACT_BYTES = b"{}"
TOKENIZER_BYTES = b'{"a":"1","b":2}'

NAMED = {
    "R": R, "Q": Q, "C": C, "A": A, "T": T, "P": P, "K": K, "Z": Z,
    "M": M, "W": W, "EST": EST, "B": B, "COV": COV, "EX": EX, "ACT": ACT,
    "CFG": CFG, "RES": RES, "TOKEN": TOKEN, "E1": E1, "E2": E2,
    "H1": H1, "H2": H2, "PUB": PUB, "STATUS": STATUS,
    "E1.body": E1["body"],
}


def substitute(value):
    """Recursively replace whole-string `$NAME` references; no interpolation
    inside other strings (spec §7 convention)."""
    if isinstance(value, str) and value.startswith("$") and value[1:] in NAMED:
        return NAMED[value[1:]]
    if isinstance(value, list):
        return [substitute(v) for v in value]
    if isinstance(value, dict):
        return {k: substitute(v) for k, v in value.items()}
    return value
