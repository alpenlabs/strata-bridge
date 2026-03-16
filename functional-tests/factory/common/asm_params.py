from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from constants import ASM_MAGIC_BYTES


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
class ThresholdConfig:
    keys: list[str]
    threshold: int


@dataclass
class AdminSubprotocol:
    strata_administrator: ThresholdConfig
    strata_sequencer_manager: ThresholdConfig
    confirmation_depth: int
    max_seqno_gap: int


@dataclass
class CheckpointSubprotocol:
    sequencer_predicate: str
    checkpoint_predicate: str
    genesis_l1_height: int
    genesis_ol_blkid: str


@dataclass
class BridgeSubprotocol:
    operators: list[str]
    denomination: int
    assignment_duration: int
    operator_fee: int
    recovery_delay: int


@dataclass
class AsmParams:
    magic: str
    l1_view: GenesisL1View
    subprotocols: list[dict[str, Any]]

    def to_dict(self) -> dict:
        return {
            "magic": self.magic,
            "l1_view": asdict(self.l1_view),
            "subprotocols": self.subprotocols,
        }


def parse_bits_to_target(bits: int | str) -> int:
    if isinstance(bits, str):
        return int(bits, 16)
    return int(bits)


def build_genesis_l1_view(
    genesis_height: int,
    block_hash: str,
    header: dict[str, Any],
) -> GenesisL1View:
    header_time = int(header["time"])
    next_target = parse_bits_to_target(header["bits"])
    history_time = header_time - 1 if header_time > 0 else header_time

    return GenesisL1View(
        blk=Block(height=genesis_height, blkid=block_hash),
        next_target=next_target,
        epoch_start_timestamp=header_time,
        last_11_timestamps=[history_time] * 11,
    )


def build_subprotocols(
    musig2_keys: list[str],
    genesis_height: int,
    denomination: int = 1_000_000_000,
    assignment_duration: int = 100_000,
    operator_fee: int = 100_000_000,
    recovery_delay: int = 1_008,
) -> list[dict[str, Any]]:
    compressed_keys = [f"02{key}" for key in musig2_keys]

    admin = {
        "Admin": asdict(
            AdminSubprotocol(
                strata_administrator=ThresholdConfig(keys=compressed_keys, threshold=1),
                strata_sequencer_manager=ThresholdConfig(keys=compressed_keys, threshold=1),
                confirmation_depth=144,
                max_seqno_gap=10,
            )
        )
    }

    checkpoint = {
        "Checkpoint": asdict(
            CheckpointSubprotocol(
                sequencer_predicate="AlwaysAccept",
                checkpoint_predicate="AlwaysAccept",
                genesis_l1_height=genesis_height,
                genesis_ol_blkid="0" * 64,
            )
        )
    }

    bridge = {
        "Bridge": asdict(
            BridgeSubprotocol(
                operators=compressed_keys,
                denomination=denomination,
                assignment_duration=assignment_duration,
                operator_fee=operator_fee,
                recovery_delay=recovery_delay,
            )
        )
    }

    return [admin, checkpoint, bridge]


def build_asm_params(
    musig2_keys: list[str],
    genesis_height: int,
    block_hash: str,
    header: dict[str, Any],
    magic: str = ASM_MAGIC_BYTES,
    denomination: int = 1_000_000_000,
    assignment_duration: int = 10_000,
    operator_fee: int = 100_000_000,
    recovery_delay: int = 1_008,
) -> AsmParams:
    l1_view = build_genesis_l1_view(genesis_height, block_hash, header)
    subprotocols = build_subprotocols(
        musig2_keys,
        genesis_height,
        denomination=denomination,
        assignment_duration=assignment_duration,
        operator_fee=operator_fee,
        recovery_delay=recovery_delay,
    )
    return AsmParams(
        magic=magic,
        l1_view=l1_view,
        subprotocols=subprotocols,
    )


def write_asm_params_json(output_path: str | Path, asm_params: AsmParams) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asm_params.to_dict(), indent=4) + "\n")
    return path.as_posix()
