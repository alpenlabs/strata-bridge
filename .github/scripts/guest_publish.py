#!/usr/bin/env python3
"""guest_publish.py — Helpers for the "Publish SP1 Bridge Guests" workflow.

Bundles three concerns that the workflow chains together so each workflow step
is one line. Pure-stdlib so it runs on every GitHub-hosted runner without an
install step.

Subcommands:
    validate    Verify workflow_dispatch inputs before any network/build work.
    fetch       Download asm-vk.json, moho-vk.json, asm-params.json into $OUTPUT_DIR.
    summarize   Verify built artifacts and append a traceability block to
                $GITHUB_STEP_SUMMARY.

Each subcommand reads its inputs from environment variables documented on the
per-command function.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


def fail(message: str) -> None:
    """Print a GHA `::error::` annotation and exit non-zero."""
    print(f"::error::{message}", file=sys.stderr)
    sys.exit(1)


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


def fetch_vks(asm_tag: str, output_dir: Path) -> None:
    """Pull the two `*-vk.json` files from the alpenlabs/asm release via `gh`.

    Assumes alpenlabs/asm is public. If this 404s on a tag known to exist, the
    repo is likely private — provision a PAT/App installation token with
    `Contents: read` on alpenlabs/asm and route it via GH_TOKEN.
    """
    cmd = ["gh", "release", "download", asm_tag, "--repo", ASM_REPO]
    for name in VK_FILES:
        cmd += ["--pattern", name]
    cmd += ["--dir", str(output_dir)]
    subprocess.run(cmd, check=True)
    for name in VK_FILES:
        if not (output_dir / name).is_file():
            fail(f"missing {name} in {ASM_REPO} release {asm_tag}")


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
    """Env: ASM_TAG, ASM_PARAMS_URL, OUTPUT_DIR, GH_TOKEN."""
    asm_tag = os.environ["ASM_TAG"]
    asm_params_url = os.environ["ASM_PARAMS_URL"]
    output_dir = Path(os.environ["OUTPUT_DIR"])
    # `gh` reads GH_TOKEN itself; we only verify it's present so a missing token
    # fails fast with a clear error instead of an interactive gh auth prompt.
    if not os.environ.get("GH_TOKEN"):
        fail("GH_TOKEN must be set")

    output_dir.mkdir(parents=True, exist_ok=True)
    fetch_vks(asm_tag, output_dir)
    fetch_asm_params(asm_params_url, output_dir / "asm-params.json")


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
    """Env: ELF_DIR, INPUTS_DIR, ASM_TAG, ASM_PARAMS_URL, BRIDGE_REF, BRIDGE_SHA, GITHUB_STEP_SUMMARY."""
    elf_dir = Path(os.environ["ELF_DIR"])
    inputs_dir = Path(os.environ["INPUTS_DIR"])
    asm_tag = os.environ["ASM_TAG"]
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
    digests = dict((name, sha256_hex(elf_dir / name)) for name in EXPECTED_ARTIFACTS)

    # Copy the exact input bytes alongside the ELFs so the bundle is
    # self-describing — a consumer can rebuild from these to verify.
    for name in BUNDLED_INPUTS:
        src = inputs_dir / name
        if not src.is_file():
            fail(f"expected input missing: {src}")
        shutil.copyfile(src, elf_dir / name)
    input_digests = {name: sha256_hex(elf_dir / name) for name in BUNDLED_INPUTS}

    manifest = {
        "schema": 1,
        "asm_tag": asm_tag,
        "asm_params_url": asm_params_url,
        "strata_bridge": {"ref": bridge_ref, "sha": bridge_sha},
        "predicates": {
            "bridge_proof": bridge_predicate,
            "counterproof": counter_predicate,
        },
        "sha256": {**digests, **input_digests},
    }
    (elf_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
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


# ---- entry point -----------------------------------------------------------

COMMANDS = {
    "validate": cmd_validate,
    "fetch": cmd_fetch,
    "summarize": cmd_summarize,
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
