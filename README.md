# LexWatt

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-%3E%3D3.12-blue.svg)](https://www.python.org/)
[![Node](https://img.shields.io/badge/node-%3E%3D22.6-blue.svg)](https://nodejs.org/)
[![CI](https://github.com/LatticeAG/lexwatt/actions/workflows/ci.yml/badge.svg)](https://github.com/LatticeAG/lexwatt/actions/workflows/ci.yml)
[![status: local-first OSS core](https://img.shields.io/badge/status-local--first_OSS_core-green.svg)]()

**Estimate model work, meter local package energy, stop the contained workload when its budget is exhausted.**

LexWatt (`agent-cap`) is a local-first resource-cap supervisor for long-running agent
workloads. It gives a process a physical kill switch: a cooperative FLOP budget, a
RAPL package-energy budget, a spawn-token allowance, and a wall-clock deadline —
enforced through Linux cgroup v2 containment, with every observation written to an
Ed25519-signed, hash-chained audit receipt that verifies offline.

No backend. No HTTP listener. No login, no telemetry, no hosted key service.

## What it does

- `agent-cap estimate` — deterministic integer FLOP envelope (`dense-v1`) for a
  pinned model catalog entry and token envelope. Identical output in Python and
  TypeScript.
- `agent-cap run --config cfg.json -- ./workload` — arms a cgroup v2 sandbox
  (namespaces, private workspace, generated seccomp artifact), meters RAPL package
  energy, and issues SIGKILL to the owned cgroup the moment a committed stop latch
  fires. No grace period.
- `agent-cap receipt` / `agent-cap verify` — export the signed, hash-chained event
  journal as a portable `Bundle` and check it offline against a pinned key:
  integrity, transition legality, and completeness (`COMPLETE` vs `PREFIX`).
- `agent-cap doctor` — honest capability report. Unsupported hosts
  (non-x86_64, no cgroup v2 write access, missing RAPL, non-root) fail closed
  with exit 65 instead of silently downgrading.
- `agent-cap meter`, `kill`, `recover`, `config validate`, `version` — the full
  local operator surface; see `agent-cap <cmd> --help`.

## What it does not do

- `--max-flops` limits a **cooperative estimated-work ledger**, not all
  instructions executed. A joule cap and a wall deadline are the physical
  backstops.
- RAPL reports selected CPU-package energy — not whole-machine electricity,
  battery discharge, carbon, or cloud energy. Receipts carry explicit coverage.
- Receipts prove signed local observations; `physical_truth` is always
  `NOT_ATTESTED`. A signature is not a hardware measurement guarantee.
- No GPU/NPU accounting, no model training, no arbitrary-PID attach, no sparse
  or MoE estimation in v1.
- Team rollups, Trellis fleet control, and LexRapid composition are defined as
  **export-only adapter interfaces** that raise `NotImplementedError` with a
  pointer to the contract — they are not implemented services.

## Install

```sh
pip install .            # Python package, provides `agent-cap`
```

Requirements: Linux, Python ≥ 3.12, root for enforced profiles.
The TypeScript pure functions and SDK live under `ts/` and run natively on
Node ≥ 22.6 (`npm test`).

## Quick start

```sh
agent-cap doctor --json
agent-cap estimate --model-file models.json --model dense-small \
    --input-tokens 512 --output-tokens 256 --json
agent-cap run --config run.json --receipt receipt.json -- /opt/work/job.py
agent-cap verify receipt.json --key lwk_…=<public-key> --json
```

## Wire protocol in one paragraph

All surfaces speak a 13-method JSON-RPC-ish protocol over a local socket:
canonical RFC 8785 (JCS) JSON under an integer-only numeric profile,
decimal-string `U` quantities bounded to u127, locked-prefix IDs
(`lwr_`, `lwe_`, `lwq_`, `lwt_`, `lwa_`, `lwc_`, `lwp_`, `lwk_`), and
domain-separated SHA-256 over `label || 0x00 || J(x)`. Audit events are
Ed25519-signed and hash-chained; verification recomputes every hash,
checks every signature against operator-pinned keys, and replays the §5
state machine for legality.

## Testing

```sh
python -m pytest tests/ -q     # conformance vectors + engine + primitives
npm test                       # TypeScript pure-function + SDK suite
```

## License

MIT — see [LICENSE](LICENSE).
