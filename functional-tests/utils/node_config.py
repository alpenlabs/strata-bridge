import logging
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import toml

from utils.utils import snapshot_log_offsets


def _deep_merge(base: dict[str, Any], overrides: Mapping[str, Any]) -> dict[str, Any]:
    """Merge, never replace: ports, p2p addresses, mTLS paths, the FoundationDB namespace,
    mosaic peers and `dev` all live in these files and must survive a one-key override."""
    merged = dict(base)
    for key, value in overrides.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, Mapping):
            merged[key] = _deep_merge(existing, value)
        else:
            merged[key] = value
    return merged


def restart_bridge_node_with_overrides(
    node,
    *,
    config_overrides: Mapping[str, Any],
    params_overrides: Mapping[str, Any],
) -> dict[str, int]:
    """Stop `node`, deep-merge the overrides into its on-disk TOMLs, and restart it.

    The env-construction path gives every operator identical config/params, so a test that
    needs one node to differ restarts it against rewritten TOMLs. Returns log offsets taken
    just before the restart, for `wait_until_logs_match`. Returns as soon as the process is
    started; the caller waits for readiness (`wait_until_bridge_ready`).
    """
    logfile = node.props["logfile"]
    node_dir = Path(logfile).parent

    node.stop()
    time.sleep(5)  # ports need to be released before restarting

    for filename, overrides in (
        ("config.toml", config_overrides),
        ("params.toml", params_overrides),
    ):
        path = node_dir / filename
        merged = _deep_merge(toml.load(path), overrides)
        path.write_text(toml.dumps(merged))
        logging.info(f"Rewrote {path} with overrides: {overrides}")

    offsets = snapshot_log_offsets([logfile])
    node.start()
    return offsets
