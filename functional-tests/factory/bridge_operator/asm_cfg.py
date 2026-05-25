from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from constants import (
    ASM_PARAMS_FILE,
    ASM_VK_FILE,
    MOHO_VK_FILE,
    NATIVE_TEST_ASM_VERIFYING_KEY,
    NATIVE_TEST_MOHO_VERIFYING_KEY,
)
from envs.asm_config import AsmEnvConfig
from utils.utils import OperatorKeyInfo

from ..common.asm_params import AsmParams, write_asm_params_json
from ..common.asm_params import build_asm_params as build_asm_params_common


def build_asm_params(
    bitcoind_rpc: Any,
    operator_key_infos: list[OperatorKeyInfo],
    genesis_height: int,
    asm_config: AsmEnvConfig | None = None,
) -> AsmParams:
    """Create AsmParams aligned with the current regtest chain."""
    cfg = asm_config or AsmEnvConfig()
    musig2_keys = [key.MUSIG2_KEY for key in operator_key_infos]

    def get_block_header(height: int) -> dict[str, Any]:
        block_hash = bitcoind_rpc.proxy.getblockhash(height)
        return bitcoind_rpc.proxy.getblockheader(block_hash)

    return build_asm_params_common(
        musig2_keys=musig2_keys,
        genesis_height=genesis_height,
        get_block_header=get_block_header,
        magic=cfg.magic,
        denomination=cfg.denomination,
        assignment_duration=cfg.assignment_duration,
        operator_fee=cfg.operator_fee,
        recovery_delay=cfg.recovery_delay,
    )


def write_asm_params(
    bitcoind_rpc: Any,
    operator_key_infos: list[OperatorKeyInfo],
    genesis_height: int,
    asm_config: AsmEnvConfig | None,
    generated_dir: str | Path,
    asm_vk: str | None = None,
    moho_vk: str | None = None,
) -> tuple[str, str, str]:
    """Write asm-params.json (derived from the live L1), asm-vk.json, and moho-vk.json
    into ``generated_dir`` and return their paths.

    By default the asm/moho hosts sign with NATIVE_TEST_{ASM,MOHO}_SIGNING_KEY, so the
    verifying-key files carry the matching ``Bip340Schnorr`` x-only pubkeys. When
    ``asm_vk`` / ``moho_vk`` are given (full predicate strings such as
    ``"Sp1Groth16:<hex>"``, used when the asm-runner produces real SP1 Groth16 proofs),
    they are written verbatim instead.
    """
    generated_dir = Path(generated_dir)
    generated_dir.mkdir(parents=True, exist_ok=True)

    asm_params = build_asm_params(bitcoind_rpc, operator_key_infos, genesis_height, asm_config)
    params_path = write_asm_params_json(generated_dir / ASM_PARAMS_FILE, asm_params)

    asm_vk = asm_vk or f"Bip340Schnorr:{NATIVE_TEST_ASM_VERIFYING_KEY}"
    asm_vk_path = generated_dir / ASM_VK_FILE
    asm_vk_path.write_text(f'"{asm_vk}"\n')

    moho_vk = moho_vk or f"Bip340Schnorr:{NATIVE_TEST_MOHO_VERIFYING_KEY}"
    moho_vk_path = generated_dir / MOHO_VK_FILE
    moho_vk_path.write_text(f'"{moho_vk}"\n')

    return params_path, asm_vk_path.as_posix(), moho_vk_path.as_posix()


def copy_asm_params(src_dir: str | Path, generated_dir: str | Path) -> tuple[str, str, str]:
    """Copy pre-generated asm-params.json/asm-vk.json/moho-vk.json from ``src_dir`` into
    ``generated_dir`` and return the destination paths.

    Used in SP1 proving mode so the runtime asm-runner anchors to the exact params baked
    into the guest ELF by ``run_test.sh`` (see gen_asm_params_external.py).
    """
    src_dir = Path(src_dir)
    generated_dir = Path(generated_dir)
    generated_dir.mkdir(parents=True, exist_ok=True)

    dests = []
    for name in (ASM_PARAMS_FILE, ASM_VK_FILE, MOHO_VK_FILE):
        dest = generated_dir / name
        shutil.copyfile(src_dir / name, dest)
        dests.append(dest.as_posix())
    return dests[0], dests[1], dests[2]
