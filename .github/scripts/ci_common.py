#!/usr/bin/env python3
"""ci_common.py — Shared helpers for the .github/scripts publish/circuit scripts.

Imported as a sibling module by guest_publish.py and circuit_gen.py: both are
invoked as `python3 .github/scripts/<name>.py`, so the script's directory is on
sys.path and a plain `import ci_common` resolves. Pure-stdlib, no install step.
"""

import hashlib
import json
import mimetypes
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn


def fail(message: str) -> NoReturn:
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


# `<env>-<genesis>-<sha8>-<ts>` / `<env>-<tag>-<sha8>` — the components are
# numeric/hex/tag chars, so this is the full legal set for an S3 key segment.
VERSION_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# UTC, second resolution, no separators that need escaping in an S3 key.
TIMESTAMP_FMT = "%Y%m%dT%H%M%SZ"
TIMESTAMP_RE = re.compile(r"^\d{8}T\d{6}Z$")


def publish_timestamp() -> str:
    """This run's `YYYYMMDDTHHMMSSZ`; `PUBLISH_TIMESTAMP` pins it for dry runs."""
    pinned = os.environ.get("PUBLISH_TIMESTAMP")
    return pinned or datetime.now(timezone.utc).strftime(TIMESTAMP_FMT)


def publish_version(env: str, genesis: int, bridge_sha8: str, timestamp: str) -> str:
    """`<env>-<genesis>-<bridge_sha8>-<timestamp>`: one S3 prefix per publish run."""
    if not TIMESTAMP_RE.fullmatch(timestamp):
        fail(f"timestamp must match YYYYMMDDTHHMMSSZ (got {timestamp!r})")
    version = f"{env}-{genesis}-{bridge_sha8}-{timestamp}"
    if not VERSION_RE.fullmatch(version):
        fail(f"version is not S3-key-safe: {version!r}")
    return version


def manifest_version(manifest: dict) -> str:
    """The version `summarize` recorded, checked against the manifest's own fields."""
    try:
        version = manifest["version"]
        expected = publish_version(
            validate_env(manifest["env"]),
            manifest["asm_genesis_l1_height"],
            manifest["strata_bridge"]["sha"][:8],
            manifest["published_at"],
        )
    except (KeyError, TypeError) as e:
        fail(f"manifest.json is not a schema-5 publish manifest ({e!r})")
    if version != expected:
        fail(f"manifest version {version!r} does not match its fields ({expected!r})")
    return version


def _bucket_key(uri: str) -> tuple[str, str]:
    if not uri.startswith("s3://"):
        fail(f"not an s3:// URI: {uri}")
    bucket, _, key = uri.removeprefix("s3://").partition("/")
    return bucket, key


def require_conditional_put() -> None:
    """Fail fast if the aws CLI predates `put-object --if-none-match` (2.17.34).

    Offline probe: an unknown option is rejected before any request, and a known
    one stops on the missing `--body` file, so no credentials are needed.
    """
    cmd = ["aws", "s3api", "put-object", "--bucket", "probe", "--key", "probe"]
    cmd += ["--if-none-match", "*", "--body", "/nonexistent/probe"]
    probe = subprocess.run(cmd, capture_output=True, text=True)
    if "Unknown options" in probe.stdout + probe.stderr:
        fail("aws CLI lacks put-object --if-none-match; need aws-cli >= 2.17.34")


def s3_try_put_new(src: Path, dst: str) -> bool:
    """Create `dst` (an s3:// URI) from `src`; False if the key is already taken.

    S3 enforces the condition itself, so a concurrent run can't slip past it.
    Single-request PUT, so `src` must be under 5 GB.
    """
    if not src.is_file() or src.stat().st_size == 0:
        fail(f"expected upload artifact missing or empty: {src}")
    bucket, key = _bucket_key(dst)
    cmd = ["aws", "s3api", "put-object", "--bucket", bucket, "--key", key]
    cmd += ["--body", str(src), "--if-none-match", "*"]
    # Same guess `aws s3 cp` makes, so manifest.json stays application/json.
    content_type, _ = mimetypes.guess_type(key)
    if content_type:
        cmd += ["--content-type", content_type]
    print(f"uploading {src} -> {dst} (create-only)")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        return True
    err = result.stderr.strip()
    # 412: an object is already there; 409: another conditional write is racing.
    if "PreconditionFailed" in err or "ConditionalRequestConflict" in err:
        return False
    fail(f"upload of {dst} failed: {err}")


def s3_put_new(src: Path, dst: str) -> None:
    """`s3_try_put_new`, but a key that is already taken fails the run."""
    if not s3_try_put_new(src, dst):
        fail(
            f"refusing to overwrite existing {dst}; publish to a fresh version instead"
        )


def s3_object_exists(uri: str) -> bool | None:
    """Whether `uri` exists, or None when S3 won't say: without `s3:ListBucket` a
    missing key answers 403, not 404."""
    bucket, key = _bucket_key(uri)
    result = subprocess.run(
        ["aws", "s3api", "head-object", "--bucket", bucket, "--key", key],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return True
    if "(404)" in result.stderr or "Not Found" in result.stderr:
        return False
    return None


def s3_read_json(uri: str) -> dict | None:
    """The JSON object at `uri`, or None if it can't be fetched or isn't one."""
    result = subprocess.run(
        ["aws", "s3", "cp", uri, "-"], capture_output=True, text=True
    )
    try:
        body = json.loads(result.stdout) if result.returncode == 0 else None
    except json.JSONDecodeError:
        body = None
    return body if isinstance(body, dict) else None


ENVIRONMENTS = ("dev", "staging", "prod")


def validate_env(env: str) -> str:
    """Reject anything outside the known environments before it reaches an S3 key.

    `workflow_call` inputs can't be `type: choice`, so the reusable-workflow path has
    no dropdown to lean on — this is the only guard there.
    """
    if env not in ENVIRONMENTS:
        fail(f"env must be one of {', '.join(ENVIRONMENTS)} (got {env!r})")
    return env


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
