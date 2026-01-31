from dataclasses import dataclass


@dataclass
class L1BlockCommitment:
    """L1 block commitment identifying a Bitcoin block.

    Corresponds to `strata_primitives::L1BlockCommitment`.
    """

    height: int
    blkid: str


@dataclass
class AsmWorkerStatus:
    """Status information for the ASM worker service.

    Corresponds to `strata_asm_worker::AsmWorkerStatus`.
    """

    is_initialized: bool
    cur_block: L1BlockCommitment | None
    cur_state: dict | None


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
