from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from utils.utils import OperatorKeyInfo


@dataclass
class Block:
    height: int
    blkid: str


@dataclass
class GenesisL1View:
    blk: Block
    next_target: int
    epoch_start_timestamp: int
    last_11_timestamps: list[int]


@dataclass
class Sidesystem:
    magic_bytes: str
    block_time: int
    cred_rule: str | dict[str, str]
    l1_reorg_safe_depth: int
    target_l2_batch_size: int
    deposit_amount: int
    dispatch_assignment_dur: int
    proof_publish_mode: str
    checkpoint_predicate: str
    max_deposits_in_block: int
    network: str
    evm_genesis_block_hash: str
    evm_genesis_block_state_root: str
    recovery_delay: int
    operators: list[str]
    genesis_l1_view: GenesisL1View

    @classmethod
    def default(cls) -> Sidesystem:
        # These defaults are intentionally test-friendly (small safety depths and
        # durations) to allow the ASM runner to progress quickly on regtest.
        return cls(
            magic_bytes="ALPN",
            block_time=1_000,
            cred_rule="unchecked",
            l1_reorg_safe_depth=4,
            target_l2_batch_size=64,
            deposit_amount=1_000_000_000,
            dispatch_assignment_dur=64,
            proof_publish_mode="strict",
            checkpoint_predicate="AlwaysAccept",
            max_deposits_in_block=16,
            recovery_delay=1_008,
            network="regtest",
            evm_genesis_block_hash="0x46c0dc60fb131be4ccc55306a345fcc20e44233324950f978ba5f185aa2af4dc",
            evm_genesis_block_state_root="0x351714af72d74259f45cd7eab0b04527cd40e74836a45abcae50f92d919d988f",
            operators=[],
            genesis_l1_view=GenesisL1View(
                blk=Block(height=0, blkid=""),
                next_target=0,
                epoch_start_timestamp=0,
                last_11_timestamps=[0] * 11,
            ),
        )


def _parse_bits_to_target(bits: int | str) -> int:
    if isinstance(bits, str):
        # `getblockheader` returns a hex string like "207fffff" on regtest.
        return int(bits, 16)
    return int(bits)


def _reverse_hex_bytes(hex_str: str) -> str:
    """Reverse a hex string by bytes (Bitcoin displays hashes in reverse order)."""
    s = hex_str[2:] if hex_str.startswith("0x") else hex_str
    try:
        return bytes.fromhex(s)[::-1].hex()
    except ValueError:
        # Fall back to the original string if it is not valid hex.
        return s


def build_genesis_l1_view(bitcoind_rpc: Any, genesis_height: int) -> GenesisL1View:
    """Build a GenesisL1View using the live bitcoind RPC."""
    block_hash = bitcoind_rpc.proxy.getblockhash(genesis_height)
    header = bitcoind_rpc.proxy.getblockheader(block_hash)

    header_time = int(header["time"])
    next_target = _parse_bits_to_target(header["bits"])

    # Use a slightly older timestamp history so the median time is strictly
    # less than the genesis block's time.
    history_time = header_time - 1 if header_time > 0 else header_time
    last_11_timestamps = [history_time] * 11
    blkid = _reverse_hex_bytes(block_hash)

    return GenesisL1View(
        blk=Block(height=genesis_height, blkid=blkid),
        next_target=next_target,
        epoch_start_timestamp=header_time,
        last_11_timestamps=last_11_timestamps,
    )


def build_sidesystem(
    bitcoind_rpc: Any,
    operator_key_infos: list[OperatorKeyInfo],
    genesis_height: int,
) -> Sidesystem:
    """Create sidesystem params aligned with the current regtest chain."""
    sidesystem = Sidesystem.default()
    sidesystem.genesis_l1_view = build_genesis_l1_view(bitcoind_rpc, genesis_height)
    sidesystem.operators = [key.MUSIG2_KEY for key in operator_key_infos]
    return sidesystem


def write_rollup_params_json(output_path: str | Path, sidesystem: Sidesystem) -> str:
    """Write rollup params JSON to disk and return the path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(asdict(sidesystem), f, indent=4)
    return path.as_posix()
