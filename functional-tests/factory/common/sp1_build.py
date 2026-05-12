"""SP1-mode bridge rebuild hook.

The bridge-proof SP1 guest ELF bakes `asm-params.json` at compile time
(see guest-builder/sp1/README.md). The functional-test harness generates
`asm-params.json` against the live bitcoin chain *during* env setup, so
the bridge must be rebuilt with `--features sp1 --release` after the
params file is written but before any bridge process starts.

`maybe_rebuild_bridge_with_sp1` is called from `BaseEnv._ensure_rollup_params`
and is a no-op unless `BRIDGE_SP1=1`.
"""

import logging
import os
import pathlib
import subprocess


def maybe_rebuild_bridge_with_sp1(asm_params_path: pathlib.Path) -> None:
    """Rebuild `strata-bridge` with the SP1 backend when `BRIDGE_SP1=1`.

    The freshly written `asm_params_path` is plumbed in via
    `BRIDGE_PROOF_ASM_PARAMS_PATH`; the Moho VK falls back to the stub
    `AlwaysAccept` predicate bundled at `guest-builder/sp1/stub/moho-vk.json`
    (sufficient for functional tests — see the warning in
    guest-builder/sp1/README.md).
    """
    if os.environ.get("BRIDGE_SP1") != "1":
        return

    repo_root = pathlib.Path(__file__).resolve().parents[3]
    stub_moho_vk = repo_root / "guest-builder" / "sp1" / "stub" / "moho-vk.json"

    if not asm_params_path.is_file():
        raise FileNotFoundError(
            f"asm-params.json not found at {asm_params_path}; "
            "_ensure_rollup_params should have written it before this call."
        )
    if not stub_moho_vk.is_file():
        raise FileNotFoundError(f"stub moho-vk.json not found at {stub_moho_vk}")

    env = {
        **os.environ,
        "BRIDGE_PROOF_ASM_PARAMS_PATH": str(asm_params_path),
        "BRIDGE_PROOF_MOHO_VK_PATH": str(stub_moho_vk),
    }
    logging.info(
        "BRIDGE_SP1=1: rebuilding strata-bridge with --features sp1 (this may take 10+ min)"
    )
    subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "--features",
            "sp1",
            "--bin",
            "strata-bridge",
        ],
        cwd=repo_root,
        env=env,
        check=True,
    )
