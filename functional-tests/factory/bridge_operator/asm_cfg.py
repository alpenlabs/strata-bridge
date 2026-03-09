from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from utils.utils import OperatorKeyInfo

from .sidesystem_cfg import GenesisL1View, build_genesis_l1_view


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


def _build_subprotocols(
    operator_key_infos: list[OperatorKeyInfo],
    genesis_height: int,
) -> list[dict[str, Any]]:
    """Build the subprotocols list in the tagged-enum format expected by Rust serde."""
    # MUSIG2_KEY is 32-byte x-only; EvenPublicKey/CompressedPublicKey need 33-byte
    # compressed format with 02 prefix (even parity).
    musig2_keys = ["02" + key.MUSIG2_KEY for key in operator_key_infos]

    admin = {
        "Admin": asdict(
            AdminSubprotocol(
                strata_administrator=ThresholdConfig(keys=musig2_keys, threshold=1),
                strata_sequencer_manager=ThresholdConfig(keys=musig2_keys, threshold=1),
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
                operators=musig2_keys,
                denomination=1_000_000_000,
                assignment_duration=64,
                operator_fee=50_000_000,
                recovery_delay=1_008,
            )
        )
    }

    return [admin, checkpoint, bridge]


def build_asm_params(
    bitcoind_rpc: Any,
    operator_key_infos: list[OperatorKeyInfo],
    genesis_height: int,
) -> AsmParams:
    """Create AsmParams aligned with the current regtest chain."""
    l1_view = build_genesis_l1_view(bitcoind_rpc, genesis_height)
    subprotocols = _build_subprotocols(operator_key_infos, genesis_height)
    return AsmParams(
        magic="ALPN",
        l1_view=l1_view,
        subprotocols=subprotocols,
    )


def write_asm_params_json(output_path: str | Path, asm_params: AsmParams) -> str:
    """Write AsmParams JSON to disk and return the path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(asm_params.to_dict(), f, indent=4)
    return path.as_posix()
