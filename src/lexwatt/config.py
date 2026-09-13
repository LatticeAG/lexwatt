"""Operator run configuration and host policy handling (spec §9).

Config files are strict canonical-profile JSON; validation depends on
contents, not file extension.  The effective (post-override) config is
canonicalized — set-valued fields sorted — before hashing.
"""

from __future__ import annotations

import os

from . import jcs
from .errors import LexwattError
from .hashing import config_hash
from .schema import check_config, check_host_policy, check_model_path_map
from .scalars import parse_u

DEFAULT_HOST_POLICY_PATH = "/etc/lexwatt/host.json"
DEFAULT_MODEL_MAP_PATH = "/etc/lexwatt/models.json"


def load_json_file(path: str):
    """Read and strictly decode a JSON config file."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise LexwattError("INVALID_INPUT") from e
    return jcs.loads(data)


def load_config(path: str) -> dict:
    cfg = load_json_file(path)
    return check_config(cfg)


def load_host_policy(path: str = DEFAULT_HOST_POLICY_PATH) -> dict:
    hp = load_json_file(path)
    return check_host_policy(hp)


def load_model_map(path: str = DEFAULT_MODEL_MAP_PATH) -> dict:
    mm = load_json_file(path)
    return check_model_path_map(mm)


def canonicalize_config(cfg: dict) -> dict:
    """Return the canonical form hashed as LEXWATT-CONFIG/1.

    Set-valued fields (model_catalog, network) are sorted; each
    Destination's ips are already canonicalized by check_destination.
    """
    cfg = dict(cfg)
    cfg["model_catalog"] = sorted(cfg["model_catalog"], key=lambda m: m["id"])
    cfg["network"] = sorted(cfg["network"], key=lambda d: (d["origin"], d["path"]))
    return cfg


def effective_config_hash(cfg: dict) -> str:
    return config_hash(canonicalize_config(cfg))


def canonicalize_host_policy(hp: dict) -> dict:
    """Canonical host-policy form for hashing: set fields sorted."""
    hp = dict(hp)
    hp["workspace_roots"] = sorted(hp["workspace_roots"])
    hp["domains"] = sorted(hp["domains"], key=lambda d: d["id"])
    return hp


def _tighten_u(cfg_val, override) -> str:
    """Override may only tighten a non-null cap; enabling a null cap is a
    profile question handled by the caller."""
    ov = parse_u(override)
    if cfg_val is None:
        return override
    if ov > parse_u(cfg_val):
        raise LexwattError("INVALID_INPUT")
    return override


def apply_overrides(cfg: dict, overrides: dict) -> dict:
    """Apply CLI budget overrides once, then revalidate.

    overrides keys: max_flops, max_energy_uj, spawns, max_wall_us — already
    lexically validated strings/ints.  Only tightening a non-null cap is
    permitted; enabling a null cap requires the profile to still validate.
    """
    out = dict(cfg)
    budgets = dict(cfg["budgets"])
    if "max_flops" in overrides:
        budgets["max_flops"] = _tighten_u(budgets["max_flops"], overrides["max_flops"])
    if "max_energy_uj" in overrides:
        budgets["max_energy_uj"] = _tighten_u(
            budgets["max_energy_uj"], overrides["max_energy_uj"]
        )
    if "spawns" in overrides:
        if overrides["spawns"] > budgets["spawns"]:
            raise LexwattError("INVALID_INPUT")
        budgets["spawns"] = overrides["spawns"]
    if "max_wall_us" in overrides:
        budgets["max_wall_us"] = _tighten_u(budgets["max_wall_us"], overrides["max_wall_us"])
    out["budgets"] = budgets
    return check_config(out)


def resolve_workspace_root(workspace_root: str, host_policy: dict) -> str:
    """Resolve without symlink components to exactly one workspace_roots
    entry; anything else is INVALID_INPUT."""
    try:
        real = os.path.realpath(workspace_root)
    except OSError as e:
        raise LexwattError("INVALID_INPUT") from e
    # reject symlinked resolution: every component must resolve literally
    canon = os.path.normpath(workspace_root)
    if canon != real:
        raise LexwattError("CONTAINMENT_FAULT")
    matches = [r for r in host_policy["workspace_roots"] if os.path.normpath(r) == real]
    if len(matches) != 1:
        raise LexwattError("CONTAINMENT_FAULT")
    return real


def verify_catalog_digests(cfg: dict, model_map: dict, hash_file) -> None:
    """Model manifest provisioning (spec §9.1): the map contains no extra
    IDs, and actual digests must equal the effective configuration."""
    catalog_ids = {m["id"] for m in cfg["model_catalog"]}
    if set(model_map.keys()) != catalog_ids:
        raise LexwattError("INVALID_INPUT")
    for m in cfg["model_catalog"]:
        paths = model_map[m["id"]]
        if hash_file(paths["artifact_path"]) != m["artifact_hash"]:
            raise LexwattError("INVALID_INPUT")
        if hash_file(paths["tokenizer_path"]) != m["tokenizer_hash"]:
            raise LexwattError("INVALID_INPUT")
    return None


def model_files_for(cfg: dict, model_map: dict) -> list[dict]:
    return sorted(
        (
            {
                "model_id": m["id"],
                "artifact_path": model_map[m["id"]]["artifact_path"],
                "tokenizer_path": model_map[m["id"]]["tokenizer_path"],
            }
            for m in cfg["model_catalog"]
        ),
        key=lambda f: f["model_id"],
    )
