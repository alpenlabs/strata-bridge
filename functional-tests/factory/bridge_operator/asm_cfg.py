from __future__ import annotations

from typing import Any

from utils.utils import OperatorKeyInfo

from ..common.asm_params import AsmParams
from ..common.asm_params import build_asm_params as build_asm_params_common


def build_asm_params(
    bitcoind_rpc: Any,
    operator_key_infos: list[OperatorKeyInfo],
    genesis_height: int,
) -> AsmParams:
    """Create AsmParams aligned with the current regtest chain."""
    musig2_keys = [key.MUSIG2_KEY for key in operator_key_infos]
    block_hash = bitcoind_rpc.proxy.getblockhash(genesis_height)
    header = bitcoind_rpc.proxy.getblockheader(block_hash)
    return build_asm_params_common(
        musig2_keys=musig2_keys,
        genesis_height=genesis_height,
        block_hash=block_hash,
        header=header,
    )
