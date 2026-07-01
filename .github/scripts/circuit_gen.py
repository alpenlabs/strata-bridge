#!/usr/bin/env python3
"""circuit_gen.py — Helpers for the "Generate g16 Circuit" workflow.

Drives the g16 boolean-circuit generation that runs *after* the "Publish SP1
Bridge Guests" guest build in the same pipeline run: it validates disk and
tooling, derives the S3 version string from the guest-build artifact, uploads
the (~142 GB) `v5c.ckt` to S3, and writes a traceability summary.

Pure-stdlib so it runs on any runner without an install step, mirroring
`guest_publish.py`. Each subcommand reads its inputs from environment variables
documented on the per-command function.

Subcommands:
    preflight   Check free disk on the runs-dir mount and required CLIs.
    version     Validate the vkey and derive `<genesis_l1_height>-<bridge_sha8>`.
    upload      Copy `v5c.ckt` to s3://<bucket>/<prefix>/<version>/g16.v5c.
    summarize   Append a traceability block to $GITHUB_STEP_SUMMARY.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
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


# `<genesis>-<sha8>` — both components are numeric/hex, so this is the full
# legal set. Reject anything else before it becomes an S3 key segment.
VERSION_RE = re.compile(r"^[A-Za-z0-9._-]+$")
VKEY_NAME = "counterproof-vkey.bin"
MANIFEST_NAME = "manifest.json"
ASM_PARAMS_NAME = "asm-params.json"
VKEY_LEN = 32


# ---- preflight -------------------------------------------------------------

REQUIRED_CLIS = ("gh", "jq", "aws", "rustup")


def cmd_preflight() -> None:
    """Env: RUNS_DIR, MIN_FREE_GB (default 300).

    Fail fast if the runs-dir mount can't hold the ~142 GB output plus the v5a
    intermediate and caches, or if a required CLI is missing — both surface
    *before* the multi-hour build instead of after.
    """
    runs_dir = Path(os.environ["RUNS_DIR"])
    min_free_gb = int(os.environ.get("MIN_FREE_GB", "300"))

    # disk_usage needs an existing path; walk up to the nearest live ancestor.
    runs_dir.mkdir(parents=True, exist_ok=True)
    probe = runs_dir
    while not probe.exists():
        probe = probe.parent
    free_gb = shutil.disk_usage(probe).free / (1024**3)
    print(f"free space on {probe}: {free_gb:.1f} GB (need >= {min_free_gb} GB)")
    if free_gb < min_free_gb:
        fail(
            f"insufficient disk on {probe}: {free_gb:.1f} GB free, "
            f"need >= {min_free_gb} GB for v5c.ckt (~142 GB) + intermediates"
        )

    missing = [c for c in REQUIRED_CLIS if shutil.which(c) is None]
    if missing:
        fail(f"required CLI(s) not found on PATH: {', '.join(missing)}")


# ---- version ---------------------------------------------------------------


def _find_one(root: Path, name: str) -> Path:
    """Locate `name` anywhere under `root` (the gh-download subdir name embeds
    the asm tag + run id, so we don't know it up front)."""
    matches = sorted(root.rglob(name))
    if not matches:
        fail(f"{name} not found under artifact dir {root}")
    return matches[0]


def _genesis_l1_height(asm_params: dict) -> int:
    """asm-params.json shape: subprotocols is a list of single-key objects;
    the Checkpoint subprotocol carries `genesis_l1_height`."""
    for entry in asm_params.get("subprotocols", []):
        if isinstance(entry, dict) and "Checkpoint" in entry:
            height = entry["Checkpoint"].get("genesis_l1_height")
            if height is None:
                fail("Checkpoint subprotocol has no genesis_l1_height")
            return int(height)
    fail("no Checkpoint subprotocol in asm-params.json")


def cmd_version() -> None:
    """Env: ARTIFACT_DIR, GITHUB_OUTPUT.

    Validate the counterproof vkey and derive the S3 version string from the
    publish run's bundled manifest + asm-params.
    """
    artifact_dir = Path(os.environ["ARTIFACT_DIR"])
    if not artifact_dir.is_dir():
        fail(f"artifact dir does not exist: {artifact_dir}")

    vkey_path = _find_one(artifact_dir, VKEY_NAME)
    vkey_bytes = vkey_path.read_bytes()
    if len(vkey_bytes) != VKEY_LEN:
        fail(f"{VKEY_NAME} must be exactly {VKEY_LEN} bytes (got {len(vkey_bytes)} at {vkey_path})")

    manifest = json.loads(_find_one(artifact_dir, MANIFEST_NAME).read_text())
    bridge_sha_full = (manifest.get("strata_bridge") or {}).get("sha", "")
    bridge_sha = bridge_sha_full[:8]
    if not bridge_sha:
        fail("manifest.json missing strata_bridge.sha")

    asm_params = json.loads(_find_one(artifact_dir, ASM_PARAMS_NAME).read_text())
    genesis = _genesis_l1_height(asm_params)

    version = f"{genesis}-{bridge_sha}"
    if not VERSION_RE.fullmatch(version):
        fail(f"derived version is not S3-key-safe: {version!r}")

    set_outputs(
        version=version,
        bridge_sha=bridge_sha,
        genesis_l1_height=str(genesis),
        vkey_sha256=hashlib.sha256(vkey_bytes).hexdigest(),
        vkey_path=str(vkey_path),
    )


# ---- upload ----------------------------------------------------------------


def _locate_v5c(runs_dir: Path) -> Path:
    """Prefer the pipeline's `latest` symlink; else the newest run dir."""
    latest = runs_dir / "latest" / "v5c.ckt"
    if latest.exists():
        return latest.resolve()
    runs = sorted(runs_dir.glob("run-*/v5c.ckt"))
    if not runs:
        fail(f"no v5c.ckt under {runs_dir} (latest/ or run-*/)")
    return runs[-1]


def cmd_upload() -> None:
    """Env: RUNS_DIR, VERSION, S3_BUCKET, S3_PREFIX (default mosaic-circuits),
    MULTIPART_CHUNKSIZE (default 64MB), GITHUB_OUTPUT."""
    runs_dir = Path(os.environ["RUNS_DIR"])
    version = os.environ["VERSION"]
    bucket = os.environ["S3_BUCKET"]
    prefix = os.environ.get("S3_PREFIX", "mosaic-circuits")
    chunk = os.environ.get("MULTIPART_CHUNKSIZE", "64MB")

    if not VERSION_RE.fullmatch(version):
        fail(f"version is not S3-key-safe: {version!r}")

    v5c = _locate_v5c(runs_dir)
    size_bytes = v5c.stat().st_size
    if size_bytes == 0:
        fail(f"v5c.ckt is empty: {v5c}")

    s3_uri = f"s3://{bucket}/{prefix}/{version}/g16.v5c"

    # Default 8 MB parts would exceed the 10,000-part cap for a 142 GB file;
    # a larger part size keeps the upload to a few thousand parts.
    subprocess.run(
        ["aws", "configure", "set", "default.s3.multipart_chunksize", chunk],
        check=True,
    )
    print(f"uploading {v5c} ({size_bytes} bytes) -> {s3_uri}")
    subprocess.run(["aws", "s3", "cp", str(v5c), s3_uri], check=True)

    set_outputs(s3_uri=s3_uri, circuit_size_bytes=str(size_bytes))


# ---- summarize -------------------------------------------------------------


def cmd_summarize() -> None:
    """Env: VERSION, S3_URI, PUBLISH_RUN_ID, G16_REF, VKEY_SHA256,
    GENESIS_L1_HEIGHT, BRIDGE_SHA, CIRCUIT_SIZE_BYTES, GITHUB_STEP_SUMMARY.

    Runs with `if: always()`, so upstream step outputs may be empty on failure.
    """
    version = os.environ.get("VERSION", "")
    s3_uri = os.environ.get("S3_URI", "")
    publish_run_id = os.environ.get("PUBLISH_RUN_ID", "")
    g16_ref = os.environ.get("G16_REF", "")
    vkey_sha256 = os.environ.get("VKEY_SHA256", "")
    genesis = os.environ.get("GENESIS_L1_HEIGHT", "")
    bridge_sha = os.environ.get("BRIDGE_SHA", "")
    size_bytes = os.environ.get("CIRCUIT_SIZE_BYTES", "")
    size_gib = f"{int(size_bytes) / (1024**3):.1f} GiB" if size_bytes.isdigit() else "n/a"

    lines = [
        "## g16 circuit generation",
        "",
        f"- version: `{version}`",
        f"- S3 object: `{s3_uri or '(not uploaded — see step logs)'}`",
        f"- circuit size: {size_gib}",
        "",
        "### Provenance",
        "",
        f"- source publish run: `{publish_run_id}`",
        f"- g16 ref: `{g16_ref}`",
        f"- asm genesis_l1_height: `{genesis}`",
        f"- strata-bridge sha: `{bridge_sha}`",
        f"- counterproof vkey sha256: `{vkey_sha256}`",
        "",
    ]

    summary_path = Path(os.environ["GITHUB_STEP_SUMMARY"])
    with summary_path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ---- entry point -----------------------------------------------------------

COMMANDS = {
    "preflight": cmd_preflight,
    "version": cmd_version,
    "upload": cmd_upload,
    "summarize": cmd_summarize,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Helpers for the Generate g16 Circuit workflow.",
    )
    parser.add_argument(
        "command",
        choices=sorted(COMMANDS),
        help="Which step to run; inputs come from env vars (see module docstring).",
    )
    args = parser.parse_args()
    COMMANDS[args.command]()


if __name__ == "__main__":
    main()
