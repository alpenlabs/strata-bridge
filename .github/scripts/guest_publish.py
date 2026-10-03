#!/usr/bin/env python3
"""guest_publish.py — Helpers for the "Publish SP1 Bridge Guests" workflow.

Bundles the concerns that the workflow chains together so each workflow step
is one line. Pure-stdlib so it runs on every GitHub-hosted runner without an
install step.

Subcommands:
    validate    Verify workflow_dispatch inputs before any network/build work.
    fetch       Download asm.elf from the alpenlabs/asm release and moho.elf from the
                alpenlabs/moho release, check them against each release's SHA256SUMS,
                write asm-vk.json / moho-vk.json from the published predicates, and fetch
                asm-params.json, all into $OUTPUT_DIR.
    summarize   Verify built artifacts, write the bridge manifest, and append a
                traceability block to $GITHUB_STEP_SUMMARY.
    upload      Copy the bridge guests (+vkeys) to
                s3://<bucket>/<prefix>/bridge/<env>-<version>/, each with a
                `<name>.sha256` sidecar in `sha256sum -c` format.

Each subcommand reads its inputs from environment variables documented on the
per-command function. Shared helpers live in ci_common.py.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from ci_common import (
    VERSION_RE,
    fail,
    genesis_l1_height,
    set_outputs,
    sha256_hex,
    validate_env,
    write_sha256_sidecar,
)


# ---- validate --------------------------------------------------------------

# No `/` — git tags and `gh release download` accept it, but
# actions/upload-artifact rejects names containing `/`, and the artifact name
# embeds the tags directly. Reject here so the failure is fast, not after the
# ~90-minute guest build.
TAG_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
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
    """Env: INPUT_ENV, INPUT_ASM_TAG, INPUT_MOHO_TAG, INPUT_ASM_PARAMS_URL, INPUT_REF (optional)."""
    env = os.environ["INPUT_ENV"]
    asm_params_url = os.environ["INPUT_ASM_PARAMS_URL"]
    ref = os.environ.get("INPUT_REF", "")

    validate_env(env)

    for name in ("asm_tag", "moho_tag"):
        tag = os.environ[f"INPUT_{name.upper()}"]
        if WHITESPACE_RE.search(tag):
            fail(f"{name} must not contain whitespace")
        if not TAG_RE.fullmatch(tag):
            fail(f"{name} contains unsupported characters (allowed: [A-Za-z0-9._-])")

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

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256SUMS = "SHA256SUMS"
# Each guest ships from the alpenlabs/<guest> release as <guest>.elf + <guest>-predicate.txt.
GUESTS = ("asm", "moho")
# Release provenance of the guest ELFs, written by `fetch` into OUTPUT_DIR.
GUESTS_FILE = "guests.json"


def parse_sha256sums(path: Path) -> dict[str, str]:
    """Parse a `sha256sum` listing (text or `*` binary mode) into {file name: digest}."""
    pairs = (
        line.split(maxsplit=1) for line in path.read_text().splitlines() if line.strip()
    )
    return {name.lstrip("*"): digest for digest, name in pairs}


def fetch_release(guest: str, tag: str, output_dir: Path) -> dict[str, str]:
    """Download <guest>.elf, its predicate and SHA256SUMS from the release via `gh`,
    check both files against SHA256SUMS, and return the release metadata.

    Assumes the repo is public. If this 404s on a tag known to exist, the repo is
    likely private: route a token with `Contents: read` on it via GH_TOKEN.
    """
    repo = f"alpenlabs/{guest}"
    elf, predicate_file = f"{guest}.elf", f"{guest}-predicate.txt"
    release_dir = output_dir / guest
    release_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "gh",
        "release",
        "download",
        tag,
        "--repo",
        repo,
        "--clobber",
        "--dir",
        str(release_dir),
    ]
    for name in (elf, predicate_file, SHA256SUMS):
        cmd += ["--pattern", name]
    subprocess.run(cmd, check=True)

    published = parse_sha256sums(release_dir / SHA256SUMS)
    for name in (elf, predicate_file):
        if not (release_dir / name).is_file():
            fail(f"missing {name} in {repo} release {tag}")
        actual = sha256_hex(release_dir / name)
        if published.get(name) != actual:
            fail(
                f"{repo} {tag}: {name} sha256 {actual} does not match SHA256SUMS ({published.get(name)})"
            )

    shutil.copyfile(release_dir / elf, output_dir / elf)
    predicate = (release_dir / predicate_file).read_text().strip()
    # The genesis loader reads the vk file as a JSON string holding the predicate.
    (output_dir / f"{guest}-vk.json").write_text(json.dumps(predicate) + "\n")

    rev = resolve_rev(repo, tag)
    print(f"{elf}: sha256 {published[elf]} ({repo} {tag} @ {rev})")
    print(f"{guest} predicate: {predicate}")
    return {"repo": repo, "tag": tag, "rev": rev, "elf_sha256": published[elf]}


def resolve_rev(repo: str, tag: str) -> str:
    """Resolve a tag to its full commit SHA via the GitHub API.

    The commits endpoint dereferences both lightweight and annotated tags, so it
    returns the underlying commit regardless of tag kind.
    """
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/commits/{tag}", "--jq", ".sha"],
        check=True,
        capture_output=True,
        text=True,
    )
    sha = result.stdout.strip()
    if not SHA1_RE.fullmatch(sha):
        fail(f"could not resolve {repo} tag {tag} to a commit sha (got {sha!r})")
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
    """Env: ASM_TAG, MOHO_TAG, ASM_PARAMS_URL, OUTPUT_DIR, GH_TOKEN."""
    asm_params_url = os.environ["ASM_PARAMS_URL"]
    output_dir = Path(os.environ["OUTPUT_DIR"])
    # `gh` reads GH_TOKEN itself; we only verify it's present so a missing token
    # fails fast with a clear error instead of an interactive gh auth prompt.
    if not os.environ.get("GH_TOKEN"):
        fail("GH_TOKEN must be set")

    output_dir.mkdir(parents=True, exist_ok=True)
    guests = {
        g: fetch_release(g, os.environ[f"{g.upper()}_TAG"], output_dir) for g in GUESTS
    }
    (output_dir / GUESTS_FILE).write_text(json.dumps(guests, indent=2) + "\n")
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


def cmd_summarize() -> None:
    """Env: ELF_DIR, INPUTS_DIR, DEPLOY_ENV, ASM_PARAMS_URL, BRIDGE_REF, BRIDGE_SHA,
    GITHUB_STEP_SUMMARY."""
    elf_dir = Path(os.environ["ELF_DIR"])
    inputs_dir = Path(os.environ["INPUTS_DIR"])
    # DEPLOY_ENV, not ENV: POSIX reserves `ENV` as a shell startup-file path, so keep
    # it out of the environment of steps that shell out.
    env = validate_env(os.environ["DEPLOY_ENV"])
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
    digests = {name: sha256_hex(elf_dir / name) for name in EXPECTED_ARTIFACTS}

    # The manifest carries env + genesis + run id so `upload` and the circuit job both
    # derive `<env>-<genesis>-<bridge_sha8>` from one source of truth.
    asm_params = json.loads((inputs_dir / "asm-params.json").read_text())
    genesis = genesis_l1_height(asm_params)
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    guests = json.loads((inputs_dir / GUESTS_FILE).read_text())

    # Copy the exact input bytes alongside the ELFs so the bundle is
    # self-describing — a consumer can rebuild from these to verify.
    for name in BUNDLED_INPUTS:
        src = inputs_dir / name
        if not src.is_file():
            fail(f"expected input missing: {src}")
        shutil.copyfile(src, elf_dir / name)
    input_digests = {name: sha256_hex(elf_dir / name) for name in BUNDLED_INPUTS}

    manifest = {
        "schema": 4,
        "env": env,
        "guests": guests,
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

    lines: list[str] = [
        "## SP1 bridge guest publish",
        "",
        f"- env: `{env}`",
        *(
            f"- {name}.elf: `{g['elf_sha256']}` ({g['repo']} `{g['tag']}` @ `{g['rev']}`)"
            for name, g in guests.items()
        ),
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

# A manifest needs no sidecar: it already carries the digest of every file beside it.
NO_SIDECAR = frozenset({"manifest.json"})


def s3_cp(src: Path, dst: str) -> None:
    """Copy a single non-empty file to S3, failing fast if it's missing/empty."""
    if not src.is_file() or src.stat().st_size == 0:
        fail(f"expected upload artifact missing or empty: {src}")
    print(f"uploading {src} -> {dst}")
    subprocess.run(["aws", "s3", "cp", str(src), dst], check=True)


def upload_tree(
    names: tuple[str, ...], src_dir: Path, base: str, digests: dict[str, str]
) -> list[str]:
    """Upload each of `names` from `src_dir` to `<base>/<name>`, following every
    non-manifest object with its `<name>.sha256` sidecar.

    Digests come from the manifest `summarize` already wrote, so a sidecar can
    never disagree with the manifest that sits next to it.
    """
    # Resolve every digest up front: a missing one means summarize and upload
    # disagree about what was built, and failing mid-loop would half-publish the tree.
    missing = [n for n in names if n not in NO_SIDECAR and not digests.get(n)]
    if missing:
        fail(f"manifest has no sha256 for {', '.join(missing)}; cannot write sidecars")

    uris: list[str] = []
    for name in names:
        dst = f"{base}/{name}"
        s3_cp(src_dir / name, dst)
        uris.append(dst)
        if name in NO_SIDECAR:
            continue
        sidecar = write_sha256_sidecar(digests[name], name, src_dir)
        s3_cp(sidecar, f"{dst}.sha256")
        uris.append(f"{dst}.sha256")
    return uris


def cmd_upload() -> None:
    """Env: ELF_DIR, S3_BUCKET, S3_PREFIX (default elfs), GITHUB_OUTPUT,
    GITHUB_STEP_SUMMARY.

    Uploads <prefix>/bridge/<env>-<genesis>-<bridge_sha8>/ (built guests + vkeys +
    manifest), each ELF/vkey followed by its `<name>.sha256` sidecar. The asm and
    moho ELFs are not republished; their releases are the source of truth.
    """
    elf_dir = Path(os.environ["ELF_DIR"])
    bucket = os.environ["S3_BUCKET"]
    prefix = os.environ.get("S3_PREFIX", "elfs")

    # bridge tree — version from the manifest summarize wrote (single source of truth).
    manifest = json.loads((elf_dir / "manifest.json").read_text())
    genesis = manifest.get("asm_genesis_l1_height")
    bridge_sha = (manifest.get("strata_bridge") or {}).get("sha", "")[:8]
    if genesis is None or not bridge_sha:
        fail("manifest.json missing asm_genesis_l1_height or strata_bridge.sha")
    # Read env back from the manifest rather than the environment, so the published
    # key can only ever be the one summarize recorded.
    env = validate_env(manifest.get("env", ""))
    bridge_version = f"{env}-{genesis}-{bridge_sha}"
    if not VERSION_RE.fullmatch(bridge_version):
        fail(f"bridge version is not S3-key-safe: {bridge_version!r}")

    bridge_base = f"s3://{bucket}/{prefix}/bridge/{bridge_version}"

    uris = upload_tree(
        BRIDGE_UPLOAD_FILES, elf_dir, bridge_base, manifest.get("sha256") or {}
    )

    set_outputs(
        bridge_version=bridge_version,
        bridge_s3_base=bridge_base,
    )

    summary_path = Path(os.environ["GITHUB_STEP_SUMMARY"])
    lines = [
        "### S3 upload",
        "",
        f"- bridge: `{bridge_base}/`",
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
