#!/usr/bin/env python3
"""ci_common.py — Shared helpers for the .github/scripts publish/circuit scripts.

Imported as a sibling module by guest_publish.py and circuit_gen.py: both are
invoked as `python3 .github/scripts/<name>.py`, so the script's directory is on
sys.path and a plain `import ci_common` resolves. Pure-stdlib, no install step.
"""

import hashlib
import os
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    """Print a GHA `::error::` annotation and exit non-zero."""
    print(f"::error::{message}", file=sys.stderr)
    sys.exit(1)


def set_outputs(**outputs: str) -> None:
    """Append `name=value` step outputs to the $GITHUB_OUTPUT file."""
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
        for name, value in outputs.items():
            f.write(f"{name}={value}\n")


def sha256_hex(path: Path) -> str:
    """Return the SHA-256 of `path` as a lowercase hex digest, read in chunks so
    the 142 GB v5c circuit doesn't have to fit in memory."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_sha256_sidecar(digest: str, s3_name: str, dest_dir: Path) -> Path:
    """Write `<dest_dir>/<s3_name>.sha256` in `sha256sum -c` format (two spaces).

    Records the *S3 object* name, not the local one: the circuit is `v5c.ckt` on
    disk but `g16.v5c` in the bucket, and the check runs against the download.
    """
    sidecar = dest_dir / f"{s3_name}.sha256"
    sidecar.write_text(f"{digest}  {s3_name}\n", encoding="utf-8")
    return sidecar


# `<genesis>-<sha8>` / `<tag>-<sha8>` — the components are numeric/hex/tag chars,
# so this is the full legal set for an S3 key segment. Reject anything else.
VERSION_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def genesis_l1_height(asm_params: dict) -> int:
    """asm-params.json shape: subprotocols is a list of single-key objects; the
    Checkpoint subprotocol carries `genesis_l1_height`. Keeps the ELF and circuit
    version strings derived from the same source in lockstep."""
    for entry in asm_params.get("subprotocols", []):
        if isinstance(entry, dict) and "Checkpoint" in entry:
            height = entry["Checkpoint"].get("genesis_l1_height")
            if height is None:
                fail("Checkpoint subprotocol has no genesis_l1_height")
            return int(height)
    fail("no Checkpoint subprotocol in asm-params.json")
