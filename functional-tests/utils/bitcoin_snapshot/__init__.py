"""Bitcoin regtest snapshot fixture: validate, restore, write.

The snapshot is committed in-tree at ``functional-tests/.bitcoin-snapshot/``
so CI and new contributors get it for free on ``git clone``. Tests fail loudly
if the cache key in ``snapshot.json`` doesn't match the running ``bitcoind``
or the configured ``initial_blocks``; rebuilds happen via the explicit
``./build-bitcoin-snapshot.sh`` script.
"""

from __future__ import annotations

import contextlib
import json
import shutil
import subprocess
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

SNAPSHOT_DIR_NAME = ".bitcoin-snapshot"
SNAPSHOT_VERSION = 2
METADATA_FILENAME = "snapshot.json"
DATA_SUBDIR = "regtest"

REBUILD_HINT = (
    "rebuild it with `cd functional-tests && ./build-bitcoin-snapshot.sh` "
    "(see functional-tests/README.md)"
)


class SnapshotError(RuntimeError):
    """Base class for snapshot validation errors."""


class SnapshotMissingError(SnapshotError):
    """Snapshot directory or metadata file does not exist."""


class SnapshotStaleError(SnapshotError):
    """Snapshot exists but its cache key doesn't match the current environment."""


def functional_tests_root() -> Path:
    """Absolute path to the ``functional-tests/`` directory.

    This file lives at ``functional-tests/utils/bitcoin_snapshot/__init__.py``,
    so we walk up three levels.
    """
    return Path(__file__).resolve().parents[2]


def snapshot_path() -> Path:
    return functional_tests_root() / SNAPSHOT_DIR_NAME


def snapshot_data_path() -> Path:
    return snapshot_path() / DATA_SUBDIR


def snapshot_metadata_path() -> Path:
    return snapshot_path() / METADATA_FILENAME


@lru_cache(maxsize=1)
def bitcoind_version_string() -> str:
    """First non-empty line of ``bitcoind --version`` (used as the cache key)."""
    try:
        out = subprocess.check_output(["bitcoind", "--version"], text=True)
    except FileNotFoundError as ex:
        raise SnapshotError(
            "bitcoind not found on PATH; install it (see functional-tests/README.md)"
        ) from ex
    for line in out.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    raise RuntimeError("bitcoind --version produced no output")


def load_metadata() -> dict | None:
    """Read ``snapshot.json``; return ``None`` if missing or unparseable."""
    path = snapshot_metadata_path()
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def validate(initial_blocks: int) -> dict:
    """Raise if the snapshot is missing or stale; return metadata if valid.

    Cache key fields: ``version``, ``bitcoind_version``, ``chain_tip.height``.
    """
    if not snapshot_path().is_dir():
        raise SnapshotMissingError(
            f"bitcoin snapshot not found at {snapshot_path()}; {REBUILD_HINT}"
        )

    if not snapshot_data_path().is_dir():
        raise SnapshotMissingError(
            f"bitcoin snapshot is missing the {DATA_SUBDIR}/ datadir at "
            f"{snapshot_data_path()}; {REBUILD_HINT}"
        )

    meta = load_metadata()
    if meta is None:
        raise SnapshotMissingError(
            f"bitcoin snapshot metadata missing or unparseable at "
            f"{snapshot_metadata_path()}; {REBUILD_HINT}"
        )

    tip = meta.get("chain_tip") or {}
    checks = [
        ("version", meta.get("version"), SNAPSHOT_VERSION),
        ("bitcoind_version", meta.get("bitcoind_version"), bitcoind_version_string()),
        ("chain_tip.height", tip.get("height"), int(initial_blocks)),
    ]
    mismatches = [
        f"  {name}: snapshot={got!r}, expected={want!r}"
        for name, got, want in checks
        if got != want
    ]
    if mismatches:
        raise SnapshotStaleError(
            "bitcoin snapshot is stale:\n" + "\n".join(mismatches) + f"\n{REBUILD_HINT}"
        )
    return meta


def chain_tip() -> dict:
    """Return the snapshot's chain tip as ``{"height": int, "block_hash": str}``."""
    meta = load_metadata()
    if meta is None:
        raise SnapshotMissingError(
            f"bitcoin snapshot metadata missing at {snapshot_metadata_path()}; {REBUILD_HINT}"
        )
    tip = meta.get("chain_tip")
    if not tip or "height" not in tip or "block_hash" not in tip:
        raise SnapshotError(
            f"snapshot metadata is missing chain_tip.height/block_hash at "
            f"{snapshot_metadata_path()}; {REBUILD_HINT}"
        )
    return {"height": int(tip["height"]), "block_hash": str(tip["block_hash"])}


def write_snapshot(
    *,
    source_datadir: Path,
    miner_address: str,
    tip_height: int,
    tip_block_hash: str,
) -> Path:
    """Copy ``<source_datadir>/regtest/`` into the cache and write metadata.

    The caller is responsible for stopping bitcoind cleanly before calling
    this so LevelDB locks under ``chainstate/`` are released.
    """
    src_regtest = Path(source_datadir) / DATA_SUBDIR
    if not src_regtest.is_dir():
        raise FileNotFoundError(f"source datadir has no {DATA_SUBDIR}/: {src_regtest}")

    dst_root = snapshot_path()
    if dst_root.exists():
        shutil.rmtree(dst_root)
    dst_root.mkdir(parents=True)
    shutil.copytree(src_regtest, dst_root / DATA_SUBDIR)

    size_bytes = _du_bytes(dst_root)
    metadata = {
        "version": SNAPSHOT_VERSION,
        "bitcoind_version": bitcoind_version_string(),
        "network": "regtest",
        "chain_tip": {
            "height": int(tip_height),
            "block_hash": tip_block_hash,
        },
        "miner_wallet_name": "testwallet",
        "miner_address": miner_address,
        "size_bytes": size_bytes,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    snapshot_metadata_path().write_text(json.dumps(metadata, indent=2) + "\n")
    return dst_root


def restore_into(target_datadir: Path) -> str:
    """Copy ``<snapshot>/regtest/`` into ``<target_datadir>/regtest/``.

    Must run before ``bitcoind`` is started against ``target_datadir``.
    Returns the saved miner address from snapshot metadata.
    """
    target_datadir = Path(target_datadir)
    target_regtest = target_datadir / DATA_SUBDIR
    if target_regtest.exists():
        raise FileExistsError(
            f"refusing to overwrite existing {target_regtest}; "
            f"snapshot must be restored into a fresh datadir"
        )
    shutil.copytree(snapshot_data_path(), target_regtest)

    meta = load_metadata()
    if meta is None or "miner_address" not in meta:
        raise SnapshotError(
            f"snapshot metadata is missing miner_address at "
            f"{snapshot_metadata_path()}; {REBUILD_HINT}"
        )
    return meta["miner_address"]


def _du_bytes(root: Path) -> int:
    total = 0
    for entry in root.rglob("*"):
        if entry.is_file():
            with contextlib.suppress(OSError):
                total += entry.stat().st_size
    return total
