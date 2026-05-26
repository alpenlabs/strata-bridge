from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from constants import ASM_MAGIC_BYTES

# Bitcoin's difficulty adjustment interval, in blocks. Identical across all networks
# (mainnet, testnet, signet, regtest) per Bitcoin Core's consensus params.
DIFFICULTY_ADJUSTMENT_INTERVAL = 2016

# A callable that returns the verbose ``getblockheader`` response (a dict with at least
# ``hash``, ``bits``, and ``time`` fields) for the block at a given height.
BlockHeaderFetcher = Callable[[int], dict[str, Any]]


@dataclass
class Block:
    height: int
    blkid: str


@dataclass
class L1Anchor:
    block: Block
    next_target: int
    epoch_start_timestamp: int
    network: str


@dataclass
class ThresholdConfig:
    keys: list[str]
    threshold: int


@dataclass
class ConfirmationDepths:
    strata_admin_multisig_update: int
    strata_seq_manager_multisig_update: int
    alpen_admin_multisig_update: int
    operator_update: int
    sequencer_update: int
    ol_stf_vk_update: int
    asm_stf_vk_update: int
    ee_stf_vk_update: int


@dataclass
class AdminSubprotocol:
    strata_administrator: ThresholdConfig
    strata_sequencer_manager: ThresholdConfig
    alpen_administrator: ThresholdConfig
    confirmation_depths: ConfirmationDepths
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
    """Typed mirror of ``asm-params.json``. Round-trips via ``to_dict`` /
    ``from_dict``; the on-disk JSON keeps its Rust-enum-style ``subprotocols`` list
    so the asm-runner deserializer is unchanged."""

    magic: str
    anchor: L1Anchor
    admin: AdminSubprotocol
    checkpoint: CheckpointSubprotocol
    bridge: BridgeSubprotocol

    def to_dict(self) -> dict[str, Any]:
        return {
            "magic": self.magic,
            "anchor": asdict(self.anchor),
            "subprotocols": [
                {"Admin": asdict(self.admin)},
                {"Checkpoint": asdict(self.checkpoint)},
                {"Bridge": asdict(self.bridge)},
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AsmParams:
        anchor_d = data["anchor"]
        anchor = L1Anchor(
            block=Block(**anchor_d["block"]),
            next_target=anchor_d["next_target"],
            epoch_start_timestamp=anchor_d["epoch_start_timestamp"],
            network=anchor_d["network"],
        )

        # ``subprotocols`` is a list of single-key dicts (Rust enum discriminant
        # encoding); flatten to {"Admin": {...}, "Checkpoint": {...}, "Bridge": {...}}.
        subs = {tag: body for entry in data["subprotocols"] for tag, body in entry.items()}

        admin_d = subs["Admin"]
        admin = AdminSubprotocol(
            strata_administrator=ThresholdConfig(**admin_d["strata_administrator"]),
            strata_sequencer_manager=ThresholdConfig(**admin_d["strata_sequencer_manager"]),
            alpen_administrator=ThresholdConfig(**admin_d["alpen_administrator"]),
            confirmation_depths=ConfirmationDepths(**admin_d["confirmation_depths"]),
            max_seqno_gap=admin_d["max_seqno_gap"],
        )
        checkpoint = CheckpointSubprotocol(**subs["Checkpoint"])
        bridge = BridgeSubprotocol(**subs["Bridge"])
        return cls(
            magic=data["magic"],
            anchor=anchor,
            admin=admin,
            checkpoint=checkpoint,
            bridge=bridge,
        )

    @classmethod
    def load(cls, path: str | Path) -> AsmParams:
        return cls.from_dict(json.loads(Path(path).read_text()))


def parse_bits_to_target(bits: int | str) -> int:
    if isinstance(bits, str):
        return int(bits, 16)
    return int(bits)


def build_l1_anchor(
    genesis_height: int,
    get_block_header: BlockHeaderFetcher,
    network: str = "regtest",
) -> L1Anchor:
    """Constructs the L1 anchor for the ASM parameters by sourcing the chain context for
    ``genesis_height`` through ``get_block_header``.

    The callable is invoked twice: once for ``genesis_height`` (whose hash and ``bits`` are
    recorded on the anchor) and once for the block at the start of the containing difficulty
    epoch (whose ``time`` is recorded as ``epoch_start_timestamp``, matching how the ASM
    recomputes the next difficulty target).
    """
    epoch_start_height = (
        genesis_height // DIFFICULTY_ADJUSTMENT_INTERVAL
    ) * DIFFICULTY_ADJUSTMENT_INTERVAL
    epoch_start_header = get_block_header(epoch_start_height)
    genesis_header = get_block_header(genesis_height)

    return L1Anchor(
        block=Block(height=genesis_height, blkid=genesis_header["hash"]),
        next_target=parse_bits_to_target(genesis_header["bits"]),
        epoch_start_timestamp=int(epoch_start_header["time"]),
        network=network,
    )


def build_asm_params(
    musig2_keys: list[str],
    genesis_height: int,
    get_block_header: BlockHeaderFetcher,
    magic: str = ASM_MAGIC_BYTES,
    denomination: int = 1_000_000_000,
    assignment_duration: int = 10_000,
    operator_fee: int = 100_000_000,
    recovery_delay: int = 1_008,
) -> AsmParams:
    compressed_keys = [f"02{key}" for key in musig2_keys]
    admin = AdminSubprotocol(
        strata_administrator=ThresholdConfig(keys=compressed_keys, threshold=1),
        strata_sequencer_manager=ThresholdConfig(keys=compressed_keys, threshold=1),
        alpen_administrator=ThresholdConfig(keys=compressed_keys, threshold=1),
        confirmation_depths=ConfirmationDepths(
            strata_admin_multisig_update=144,
            strata_seq_manager_multisig_update=144,
            alpen_admin_multisig_update=144,
            operator_update=144,
            sequencer_update=144,
            ol_stf_vk_update=144,
            asm_stf_vk_update=144,
            ee_stf_vk_update=144,
        ),
        max_seqno_gap=10,
    )
    checkpoint = CheckpointSubprotocol(
        sequencer_predicate="AlwaysAccept",
        checkpoint_predicate="AlwaysAccept",
        genesis_l1_height=genesis_height,
        genesis_ol_blkid="0" * 64,
    )
    bridge = BridgeSubprotocol(
        operators=compressed_keys,
        denomination=denomination,
        assignment_duration=assignment_duration,
        operator_fee=operator_fee,
        recovery_delay=recovery_delay,
    )
    return AsmParams(
        magic=magic,
        anchor=build_l1_anchor(genesis_height, get_block_header),
        admin=admin,
        checkpoint=checkpoint,
        bridge=bridge,
    )


def write_asm_params_json(output_path: str | Path, asm_params: AsmParams) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asm_params.to_dict(), indent=4) + "\n")
    return path.as_posix()
