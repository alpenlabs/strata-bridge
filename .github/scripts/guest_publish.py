#!/usr/bin/env python3
"""guest_publish.py — Helpers for the "Publish SP1 Bridge Guests" workflow.

Bundles the concerns that the workflow chains together so each workflow step
is one line. Pure-stdlib so it runs on every GitHub-hosted runner without an
install step.

Subcommands:
    validate    Verify workflow_dispatch inputs before any network/build work.
    fetch       Download asm-vk.json, moho-vk.json, asm.elf, moho.elf, asm-params.json
                into $OUTPUT_DIR and resolve the asm tag's commit (asm_rev).
    summarize   Verify built artifacts, write the bridge + asm-runner manifests, and
                append a traceability block to $GITHUB_STEP_SUMMARY.
    upload      Copy the bridge guests (+vkeys) and the asm-runner ELFs to
                s3://<bucket>/<prefix>/{bridge,asm-runner}/<version>/.

Each subcommand reads its inputs from environment variables documented on the
per-command function. Shared helpers live in ci_common.py.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from ci_common import VERSION_RE, fail, genesis_l1_height, set_outputs


# ---- validate --------------------------------------------------------------

# No `/` — git tags and `gh release download` accept it, but
# actions/upload-artifact rejects names containing `/`, and the artifact name
# embeds asm_tag directly. Reject here so the failure is fast, not after the
# ~90-minute guest build.
ASM_TAG_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
REF_RE = re.compile(r"^[A-Za-z0-9._/@:-]+$")
WHITESPACE_RE = re.compile(r"\s")
# github.com /blob/ URLs serve HTML, not raw JSON — reject early so the
# JSON-validation step doesn't fail later with a more confusing error.
BLOB_URL_RE = re.compile(r"^https://github\.com/[^/]+/[^/]+/blob/")

BLOB_HINT = (
    "asm_params_url is a github.com /blob/ view URL (returns HTML). "
    "Use the raw URL: replace 'github.com' with 'raw.githubusercontent.com' "
    "and drop '/blob' (or click the 'Raw' button on GitHub)."
)


def cmd_validate() -> None:
    """Env: INPUT_ASM_TAG, INPUT_ASM_PARAMS_URL, INPUT_REF (optional)."""
    asm_tag = os.environ["INPUT_ASM_TAG"]
    asm_params_url = os.environ["INPUT_ASM_PARAMS_URL"]
    ref = os.environ.get("INPUT_REF", "")

    if WHITESPACE_RE.search(asm_tag):
        fail("asm_tag must not contain whitespace")
    if not ASM_TAG_RE.fullmatch(asm_tag):
        fail("asm_tag contains unsupported characters (allowed: [A-Za-z0-9._-])")

    if WHITESPACE_RE.search(asm_params_url):
        fail("asm_params_url must not contain whitespace")
    if not asm_params_url.startswith("https://"):
        fail("asm_params_url must start with https://")
    if len(asm_params_url) > 2048:
        fail("asm_params_url exceeds 2048 chars")
    if BLOB_URL_RE.match(asm_params_url):
        fail(BLOB_HINT)

    if ref:
        if WHITESPACE_RE.search(ref):
            fail("ref must not contain whitespace")
        if not REF_RE.fullmatch(ref):
            fail("ref contains unsupported characters")


# ---- fetch -----------------------------------------------------------------

ASM_REPO = "alpenlabs/asm"
VK_FILES = ("asm-vk.json", "moho-vk.json")
# asm.elf / moho.elf ship as release assets next to the vk JSONs; we republish
# them verbatim under elfs/asm-runner/ so consumers get a stable durable URL.
ELF_FILES = ("asm.elf", "moho.elf")
RELEASE_FILES = VK_FILES + ELF_FILES
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")


def fetch_release_assets(asm_tag: str, output_dir: Path) -> None:
    """Pull the vk JSONs and guest ELFs from the alpenlabs/asm release via `gh`.

    Assumes alpenlabs/asm is public. If this 404s on a tag known to exist, the
    repo is likely private — provision a PAT/App installation token with
    `Contents: read` on alpenlabs/asm and route it via GH_TOKEN.
    """
    cmd = ["gh", "release", "download", asm_tag, "--repo", ASM_REPO]
    for name in RELEASE_FILES:
        cmd += ["--pattern", name]
    cmd += ["--dir", str(output_dir)]
    subprocess.run(cmd, check=True)
    for name in RELEASE_FILES:
        p = output_dir / name
        if not p.is_file() or p.stat().st_size == 0:
            fail(f"missing or empty {name} in {ASM_REPO} release {asm_tag}")


def resolve_asm_rev(asm_tag: str) -> str:
    """Resolve the alpenlabs/asm tag to its full commit SHA via the GitHub API.

    The commits endpoint dereferences both lightweight and annotated tags, so it
    returns the underlying commit regardless of tag kind.
    """
    result = subprocess.run(
        ["gh", "api", f"repos/{ASM_REPO}/commits/{asm_tag}", "--jq", ".sha"],
        check=True,
        capture_output=True,
        text=True,
    )
    sha = result.stdout.strip()
    if not SHA1_RE.fullmatch(sha):
        fail(
            f"could not resolve {ASM_REPO} tag {asm_tag} to a commit sha (got {sha!r})"
        )
    return sha


def fetch_asm_params(asm_params_url: str, output_path: Path) -> None:
    """Download asm-params.json from $ASM_PARAMS_URL and JSON-validate it.

    A github.com /blob/ URL would 200 OK with HTML; the JSON decode below catches
    that and fails with a clear error rather than letting build.rs panic on it.
    """
    # Defense in depth — `validate` already enforces https://, but re-check here
    # so this subcommand is safe to run outside the workflow too.
    if urlparse(asm_params_url).scheme != "https":
        fail("asm_params_url must be https")

    req = urllib.request.Request(
        asm_params_url,
        headers={"User-Agent": "strata-bridge-ci/1"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read()
    if not body:
        fail(f"asm-params.json from {asm_params_url} is empty")
    try:
        json.loads(body)
    except json.JSONDecodeError as e:
        fail(
            f"asm-params.json is not valid JSON ({e}); a github.com /blob/ URL "
            "returns HTML — use the raw URL instead"
        )
    output_path.write_bytes(body)


def cmd_fetch() -> None:
    """Env: ASM_TAG, ASM_PARAMS_URL, OUTPUT_DIR, GH_TOKEN, GITHUB_OUTPUT."""
    asm_tag = os.environ["ASM_TAG"]
    asm_params_url = os.environ["ASM_PARAMS_URL"]
    output_dir = Path(os.environ["OUTPUT_DIR"])
    # `gh` reads GH_TOKEN itself; we only verify it's present so a missing token
    # fails fast with a clear error instead of an interactive gh auth prompt.
    if not os.environ.get("GH_TOKEN"):
        fail("GH_TOKEN must be set")

    output_dir.mkdir(parents=True, exist_ok=True)
    fetch_release_assets(asm_tag, output_dir)
    fetch_asm_params(asm_params_url, output_dir / "asm-params.json")
    # Emit the asm commit so summarize/upload can key the asm-runner tree by it.
    set_outputs(asm_rev=resolve_asm_rev(asm_tag))


# ---- summarize -------------------------------------------------------------

EXPECTED_ARTIFACTS = (
    "bridge-proof.elf",
    "bridge-proof.predicate",
    "bridge-proof-vkey.bin",
    "counterproof.elf",
    "counterproof.predicate",
    "counterproof-vkey.bin",
)

# Copied verbatim into the artifact so the bundle is self-describing after GHA retention evicts the run page.
BUNDLED_INPUTS = ("asm-params.json", "asm-vk.json", "moho-vk.json")


def sha256_hex(path: Path) -> str:
    """Return the SHA-256 of `path` as a lowercase hex digest."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_summarize() -> None:
    """Env: ELF_DIR, INPUTS_DIR, ASM_TAG, ASM_REV, ASM_PARAMS_URL, BRIDGE_REF, BRIDGE_SHA,
    GITHUB_STEP_SUMMARY."""
    elf_dir = Path(os.environ["ELF_DIR"])
    inputs_dir = Path(os.environ["INPUTS_DIR"])
    asm_tag = os.environ["ASM_TAG"]
    asm_rev = os.environ["ASM_REV"]
    asm_params_url = os.environ["ASM_PARAMS_URL"]
    # Caller resolves these from `inputs.ref || github.ref` + `git rev-parse HEAD`
    # post-checkout. We can't fall back to GITHUB_REF/GITHUB_SHA because those
    # always describe the dispatch event, not the (possibly overridden) build ref.
    bridge_ref = os.environ["BRIDGE_REF"]
    bridge_sha = os.environ["BRIDGE_SHA"]
    summary_path = Path(os.environ["GITHUB_STEP_SUMMARY"])

    for name in EXPECTED_ARTIFACTS:
        p = elf_dir / name
        if not p.is_file() or p.stat().st_size == 0:
            fail(f"expected artifact missing or empty: {p}")

    bridge_predicate = (elf_dir / "bridge-proof.predicate").read_text().strip()
    counter_predicate = (elf_dir / "counterproof.predicate").read_text().strip()
    # The `-vkey.bin` files are the raw 32-byte SP1 program vkey hashes. Log them
    # as hex so consumers can grab the vkey without parsing the predicate blob.
    bridge_vkey_hex = (elf_dir / "bridge-proof-vkey.bin").read_bytes().hex()
    counter_vkey_hex = (elf_dir / "counterproof-vkey.bin").read_bytes().hex()
    digests = dict((name, sha256_hex(elf_dir / name)) for name in EXPECTED_ARTIFACTS)

    # asm genesis L1 height + run id go into the manifest so `upload` can derive the
    # S3 version (`<genesis>-<bridge_sha8>`) from a single source of truth.
    asm_params = json.loads((inputs_dir / "asm-params.json").read_text())
    genesis = genesis_l1_height(asm_params)
    run_id = os.environ.get("GITHUB_RUN_ID", "")

    # Copy the exact input bytes alongside the ELFs so the bundle is
    # self-describing — a consumer can rebuild from these to verify.
    for name in BUNDLED_INPUTS:
        src = inputs_dir / name
        if not src.is_file():
            fail(f"expected input missing: {src}")
        shutil.copyfile(src, elf_dir / name)
    input_digests = {name: sha256_hex(elf_dir / name) for name in BUNDLED_INPUTS}

    manifest = {
        "schema": 2,
        "asm_tag": asm_tag,
        "asm_params_url": asm_params_url,
        "asm_genesis_l1_height": genesis,
        "run_id": run_id,
        "strata_bridge": {"ref": bridge_ref, "sha": bridge_sha},
        "predicates": {
            "bridge_proof": bridge_predicate,
            "counterproof": counter_predicate,
        },
        "vkeys": {
            "bridge_proof": bridge_vkey_hex,
            "counterproof": counter_vkey_hex,
        },
        "sha256": {**digests, **input_digests},
    }
    (elf_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    # asm-runner manifest — provenance for the asm ELFs fetched from the release.
    # Written into INPUTS_DIR; `upload` copies it to the asm-runner tree as
    # manifest.json (keyed by <asm_tag>-<asm_sha8>, independent of the bridge version).
    for name in ELF_FILES:
        p = inputs_dir / name
        if not p.is_file() or p.stat().st_size == 0:
            fail(f"expected asm artifact missing or empty: {p}")
    asm_manifest = {
        "schema": 1,
        "asm_tag": asm_tag,
        "asm_rev": asm_rev,
        "run_id": run_id,
        "sha256": {name: sha256_hex(inputs_dir / name) for name in ELF_FILES},
    }
    (inputs_dir / "asm-runner-manifest.json").write_text(
        json.dumps(asm_manifest, indent=2) + "\n", encoding="utf-8"
    )

    lines: list[str] = [
        "## SP1 bridge guest publish",
        "",
        f"- asm tag (alpenlabs/asm): `{asm_tag}`",
        f"- asm-params source: `{asm_params_url}`",
        f"- strata-bridge ref: `{bridge_ref}` @ `{bridge_sha}`",
        "",
        "Artifact also contains `manifest.json` plus the verbatim input JSONs"
        f" ({', '.join(f'`{n}`' for n in BUNDLED_INPUTS)}) so the bundle is"
        " self-describing once the run page expires.",
        "",
        "### Predicates",
        "",
        f"- bridge-proof: `{bridge_predicate}`",
        f"- counterproof: `{counter_predicate}`",
        "",
        "### Verifying keys (vkey hash, hex)",
        "",
        f"- bridge-proof: `{bridge_vkey_hex}`",
        f"- counterproof: `{counter_vkey_hex}`",
        "",
        "### SHA-256",
        "",
        "```",
        *(f"{digest}  {name}" for name, digest in digests.items()),
        *(f"{digest}  {name}" for name, digest in input_digests.items()),
        "```",
        "",
    ]

    with summary_path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ---- upload ----------------------------------------------------------------

BRIDGE_UPLOAD_FILES = (
    "bridge-proof.elf",
    "counterproof.elf",
    "bridge-proof-vkey.bin",
    "counterproof-vkey.bin",
    "manifest.json",
)


def s3_cp(src: Path, dst: str) -> None:
    """Copy a single non-empty file to S3, failing fast if it's missing/empty."""
    if not src.is_file() or src.stat().st_size == 0:
        fail(f"expected upload artifact missing or empty: {src}")
    print(f"uploading {src} -> {dst}")
    subprocess.run(["aws", "s3", "cp", str(src), dst], check=True)


def cmd_upload() -> None:
    """Env: ELF_DIR, INPUTS_DIR, ASM_TAG, ASM_REV, S3_BUCKET, S3_PREFIX (default elfs),
    GITHUB_OUTPUT, GITHUB_STEP_SUMMARY.

    Uploads two independently-versioned trees:
      <prefix>/bridge/<genesis>-<bridge_sha8>/   built guests + vkeys + manifest
      <prefix>/asm-runner/<asm_tag>-<asm_sha8>/  asm.elf, moho.elf + manifest
    """
    elf_dir = Path(os.environ["ELF_DIR"])
    inputs_dir = Path(os.environ["INPUTS_DIR"])
    asm_tag = os.environ["ASM_TAG"]
    asm_rev = os.environ["ASM_REV"]
    bucket = os.environ["S3_BUCKET"]
    prefix = os.environ.get("S3_PREFIX", "elfs")

    # bridge tree — version from the manifest summarize wrote (single source of truth).
    manifest = json.loads((elf_dir / "manifest.json").read_text())
    genesis = manifest.get("asm_genesis_l1_height")
    bridge_sha = (manifest.get("strata_bridge") or {}).get("sha", "")[:8]
    if genesis is None or not bridge_sha:
        fail("manifest.json missing asm_genesis_l1_height or strata_bridge.sha")
    bridge_version = f"{genesis}-{bridge_sha}"
    if not VERSION_RE.fullmatch(bridge_version):
        fail(f"bridge version is not S3-key-safe: {bridge_version!r}")

    # asm-runner tree — version pins the asm release the ELFs came from.
    asm_version = f"{asm_tag}-{asm_rev[:8]}"
    if not VERSION_RE.fullmatch(asm_version):
        fail(f"asm-runner version is not S3-key-safe: {asm_version!r}")

    bridge_base = f"s3://{bucket}/{prefix}/bridge/{bridge_version}"
    asm_base = f"s3://{bucket}/{prefix}/asm-runner/{asm_version}"

    uris: list[str] = []
    for name in BRIDGE_UPLOAD_FILES:
        dst = f"{bridge_base}/{name}"
        s3_cp(elf_dir / name, dst)
        uris.append(dst)
    for name in ELF_FILES:
        dst = f"{asm_base}/{name}"
        s3_cp(inputs_dir / name, dst)
        uris.append(dst)
    # The asm-runner manifest is staged under a distinct local name to avoid
    # colliding with the bridge manifest; it lands in S3 as manifest.json.
    asm_manifest_dst = f"{asm_base}/manifest.json"
    s3_cp(inputs_dir / "asm-runner-manifest.json", asm_manifest_dst)
    uris.append(asm_manifest_dst)

    set_outputs(
        bridge_version=bridge_version,
        asm_version=asm_version,
        bridge_s3_base=bridge_base,
        asm_s3_base=asm_base,
    )

    summary_path = Path(os.environ["GITHUB_STEP_SUMMARY"])
    lines = [
        "### S3 upload",
        "",
        f"- bridge: `{bridge_base}/`",
        f"- asm-runner: `{asm_base}/`",
        "",
        *(f"- `{uri}`" for uri in uris),
        "",
    ]
    with summary_path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ---- entry point -----------------------------------------------------------

COMMANDS = {
    "validate": cmd_validate,
    "fetch": cmd_fetch,
    "summarize": cmd_summarize,
    "upload": cmd_upload,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Helpers for the Publish SP1 Bridge Guests workflow.",
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
