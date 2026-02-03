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
class DepositEntry:
    """Bitcoin deposit entry containing UTXO reference and historical multisig operators.

    Corresponds to `strata_asm_proto_bridge_v1::DepositEntry`.
    """

    deposit_idx: int
    notary_operators: dict
    amt: int


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
