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
class OLBlockCommitment:
    """OL block commitment with slot and block ID.

    Corresponds to `strata_identifiers::OLBlockCommitment`.
    """

    slot: int
    blkid: str

    @classmethod
    def from_dict(cls, data: dict) -> OLBlockCommitment:
        return cls(slot=data["slot"], blkid=data["blkid"])


@dataclass
class CheckpointTip:
    """Verified checkpoint tip position.

    Corresponds to `strata_checkpoint_types_ssz::CheckpointTip`.
    """

    epoch: int
    l1_height: int
    l2_commitment: OLBlockCommitment

    @classmethod
    def from_dict(cls, data: dict) -> CheckpointTip:
        return cls(
            epoch=data["epoch"],
            l1_height=data["l1_height"],
            l2_commitment=OLBlockCommitment.from_dict(data["l2_commitment"]),
        )


@dataclass
class DepositEntry:
    """Deposit entry recorded in ASM.

    Corresponds to `strata_asm_proto_bridge_v1::DepositEntry`.
    """

    deposit_idx: int
    notary_set: int
    amt: int

    @classmethod
    def from_dict(cls, data: dict) -> DepositEntry:
        return cls(
            deposit_idx=data["deposit_idx"],
            notary_set=data["notary_set"],
            amt=data["amt"],
        )


@dataclass
class WithdrawalOutput:
    """Bitcoin output a fulfilled withdrawal must create: a destination and an amount.

    Corresponds to `strata_asm_proto_bridge_v1::WithdrawalOutput`.
    """

    destination: str
    amt: int


@dataclass
class AssignmentEntry:
    """Assignment entry linking a deposit to an operator for withdrawal processing.

    Corresponds to `strata_asm_proto_bridge_v1::AssignmentEntry`.
    """

    deposit_entry: DepositEntry
    withdrawal_output: WithdrawalOutput
    operator_fee: int
    current_assignee: int
    previous_assignees: dict
    fulfillment_deadline: int

    @classmethod
    def from_dict(cls, data: dict) -> AssignmentEntry:
        withdrawal_output = WithdrawalOutput(
            destination=data["withdrawal_output"]["destination"],
            amt=data["withdrawal_output"]["amt"],
        )
        return cls(
            deposit_entry=DepositEntry.from_dict(data["deposit_entry"]),
            withdrawal_output=withdrawal_output,
            operator_fee=data["operator_fee"],
            current_assignee=data["current_assignee"],
            previous_assignees=data["previous_assignees"],
            fulfillment_deadline=data["fulfillment_deadline"],
        )
