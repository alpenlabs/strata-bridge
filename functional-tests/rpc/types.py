from dataclasses import dataclass
from enum import Enum


class RpcOperatorStatus(Enum):
    """Enum representing the status of a bridge operator."""

    ONLINE = "online"
    OFFLINE = "offline"


class ChallengeStep(Enum):
    """Challenge step states for claims."""

    CLAIM = "claim"
    CHALLENGE = "challenge"
    ASSERT = "assert"


@dataclass
class RpcDepositStatusInProgress:
    """Deposit exists, but minting hasn't happened yet."""

    status: str = "in_progress"


@dataclass
class RpcDepositStatusFailed:
    """Deposit exists, but was never completed (can be reclaimed)."""

    status: str = "failed"
    reason: str = ""


@dataclass
class RpcDepositStatusComplete:
    """Deposit has been fully processed and minted."""

    status: str = "complete"
    deposit_txid: str = ""


RpcDepositStatus = RpcDepositStatusInProgress | RpcDepositStatusFailed | RpcDepositStatusComplete


@dataclass
class RpcWithdrawalStatusInProgress:
    """Withdrawal is in progress."""

    status: str = "in_progress"


@dataclass
class RpcWithdrawalStatusComplete:
    """Withdrawal has been fully processed and fulfilled."""

    status: str = "complete"
    fulfillment_txid: str = ""


RpcWithdrawalStatus = RpcWithdrawalStatusInProgress | RpcWithdrawalStatusComplete


@dataclass
class RpcReimbursementStatusNotStarted:
    """Claim does not exist on-chain."""

    status: str = "not_started"


@dataclass
class RpcReimbursementStatusInProgress:
    """Claim exists, challenge step is 'Claim', no payout."""

    status: str = "in_progress"
    challenge_step: str = ""


@dataclass
class RpcReimbursementStatusChallenged:
    """Claim exists, challenge step is 'Challenge' or 'Assert', no payout."""

    status: str = "challenged"
    challenge_step: str = ""


@dataclass
class RpcReimbursementStatusCancelled:
    """Operator was slashed, claim is no longer valid."""

    status: str = "cancelled"


@dataclass
class RpcReimbursementStatusComplete:
    """Claim has been successfully reimbursed."""

    status: str = "complete"
    payout_txid: str = ""


RpcReimbursementStatus = (
    RpcReimbursementStatusNotStarted
    | RpcReimbursementStatusInProgress
    | RpcReimbursementStatusChallenged
    | RpcReimbursementStatusCancelled
    | RpcReimbursementStatusComplete
)


@dataclass
class RpcDepositInfo:
    """Represents deposit transaction details."""

    status: RpcDepositStatus
    deposit_request_txid: str


@dataclass
class RpcWithdrawalInfo:
    """Represents withdrawal transaction details."""

    status: RpcWithdrawalStatus
    withdrawal_request_txid: str


@dataclass
class RpcClaimInfo:
    """Represents reimbursement transaction details."""

    claim_txid: str
    status: RpcReimbursementStatus


@dataclass
class RpcBridgeDutyDeposit:
    """Deposit duty."""

    deposit_request_txid: str


@dataclass
class RpcBridgeDutyWithdrawal:
    """Withdrawal duty."""

    withdrawal_request_txid: str
    assigned_operator_idx: int


RpcBridgeDutyStatus = RpcBridgeDutyDeposit | RpcBridgeDutyWithdrawal


@dataclass
class RpcDisproveData:
    """The data shared during deposit setup required to construct a disprove transaction."""

    post_assert_txid: str
    deposit_txid: str
    stake_outpoint: str
    stake_hash: str
    operator_descriptor: str
    wots_public_keys: dict
    n_of_n_sig: str
