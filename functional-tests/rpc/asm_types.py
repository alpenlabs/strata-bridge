from __future__ import annotations

from dataclasses import dataclass


@dataclass
class L1BlockCommitment:
    """L1 block commitment identifying a Bitcoin block.

    Corresponds to `strata_primitives::L1BlockCommitment`.
    """

    height: int
    blkid: str

    @classmethod
    def from_dict(cls, data: dict) -> L1BlockCommitment:
        return cls(height=data["height"], blkid=data["blkid"])


@dataclass
class AsmWorkerStatus:
    """Status information for the ASM worker service.

    Corresponds to `strata_asm_worker::AsmWorkerStatus`.
    """

    is_initialized: bool
    cur_block: L1BlockCommitment | None
    cur_state: dict | None

    @classmethod
    def from_dict(cls, data: dict) -> AsmWorkerStatus:
        cur_block = None
        if data.get("cur_block") is not None:
            cur_block = L1BlockCommitment.from_dict(data["cur_block"])
        return cls(
            is_initialized=data["is_initialized"],
            cur_block=cur_block,
            cur_state=data.get("cur_state"),
        )


@dataclass
class OperatorBitmap:
    """Memory-efficient bitmap for tracking active operators in a multisig set."""

    bits: list[bool]

    @classmethod
    def from_dict(cls, data: dict) -> OperatorBitmap:
        inner = data["bits"]
        bit_count = inner["bits"]
        raw_bytes = inner["data"]

        # Decode Lsb0-ordered bitvec: least significant bit first within each byte
        decoded = []
        for byte_val in raw_bytes:
            for bit_pos in range(8):
                decoded.append(bool(byte_val & (1 << bit_pos)))

        # Truncate to actual bit count
        return cls(bits=decoded[:bit_count])


@dataclass
class DepositEntry:
    """Deposit entry recorded in ASM.

    Corresponds to `strata_asm_proto_bridge_v1::DepositEntry`.
    """

    deposit_idx: int
    notary_operators: OperatorBitmap
    amt: int

    @classmethod
    def from_dict(cls, data: dict) -> DepositEntry:
        return cls(
            deposit_idx=data["deposit_idx"],
            notary_operators=OperatorBitmap.from_dict(data["notary_operators"]),
            amt=data["amt"],
        )


@dataclass
class WithdrawOutput:
    """Bitcoin output for a withdrawal operation.

    Corresponds to `strata_asm_bridge_msgs::WithdrawOutput`.
    """

    destination: str
    amt: int


@dataclass
class WithdrawalCommand:
    """Command specifying a Bitcoin output for a withdrawal operation.

    Corresponds to `strata_asm_proto_bridge_v1::WithdrawalCommand`.
    """

    output: WithdrawOutput
    operator_fee: int


@dataclass
class AssignmentEntry:
    """Assignment entry linking a deposit to an operator for withdrawal processing.

    Corresponds to `strata_asm_proto_bridge_v1::AssignmentEntry`.
    """

    deposit_entry: DepositEntry
    withdrawal_cmd: WithdrawalCommand
    current_assignee: int
    previous_assignees: dict
    fulfillment_deadline: int
