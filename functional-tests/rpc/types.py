from dataclasses import dataclass
from enum import Enum


class RpcOperatorStatus(Enum):
    """Enum representing the status of a bridge operator."""

    ONLINE = "online"
    OFFLINE = "offline"


class RpcClaimPhase(Enum):
    """Where an active claim sits in the challenge-response game."""

    CLAIMED = "claimed"
    CONTESTED = "contested"
    BRIDGE_PROOF_POSTED = "bridge_proof_posted"
    BRIDGE_PROOF_TIMEDOUT = "bridge_proof_timedout"
    COUNTER_PROOF_POSTED = "counter_proof_posted"
    ALL_NACKD = "all_nackd"
    ACKED = "acked"


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
    """Withdrawal is assigned or being processed, with no known fulfillment tx."""

    status: str = "in_progress"


@dataclass
class RpcWithdrawalStatusComplete:
    """Withdrawal has been fulfilled."""

    status: str = "complete"
    fulfillment_txid: str = ""


RpcWithdrawalStatus = RpcWithdrawalStatusInProgress | RpcWithdrawalStatusComplete


@dataclass
class RpcReimbursementStatusNotStarted:
    """No reimbursement claim has been observed for the assigned operator."""

    status: str = "not_started"


@dataclass
class RpcReimbursementStatusInProgress:
    """Reimbursement claim is in a non-terminal challenge-response phase."""

    status: str = "in_progress"
    claim_txid: str = ""
    phase: str = ""


@dataclass
class RpcReimbursementStatusSlashed:
    """Operator was slashed for this reimbursement claim."""

    status: str = "slashed"
    claim_txid: str = ""


@dataclass
class RpcReimbursementStatusAborted:
    """Reimbursement claim path was aborted before payout or slashing completed."""

    status: str = "aborted"
    claim_txid: str = ""


@dataclass
class RpcReimbursementStatusComplete:
    """Reimbursement claim completed and paid out."""

    status: str = "complete"
    claim_txid: str = ""
    payout_txid: str = ""


RpcReimbursementStatus = (
    RpcReimbursementStatusNotStarted
    | RpcReimbursementStatusInProgress
    | RpcReimbursementStatusSlashed
    | RpcReimbursementStatusAborted
    | RpcReimbursementStatusComplete
)


@dataclass
class RpcDepositInfo:
    """Represents deposit transaction details."""

    status: RpcDepositStatus
    deposit_idx: int
    deposit_request_txid: str


@dataclass
class RpcActiveClaim:
    """A single active reimbursement process for a deposit."""

    operator: int
    claim_txid: str
    fulfilled: bool
    phase: RpcClaimPhase

    @classmethod
    def from_json(cls, data: dict) -> "RpcActiveClaim":
        return cls(
            operator=int(data["operator"]),
            claim_txid=data["claim_txid"],
            fulfilled=bool(data["fulfilled"]),
            phase=RpcClaimPhase(data["phase"]),
        )


@dataclass
class RpcPendingWithdrawalInfo:
    """Info about a pending withdrawal for a deposit."""

    assigned_operator: int
    assigned_claim: RpcActiveClaim | None
    competing_claims: list[RpcActiveClaim]

    @classmethod
    def from_json(cls, data: dict) -> "RpcPendingWithdrawalInfo":
        assigned_claim = None
        if data.get("assigned_claim") is not None:
            assigned_claim = RpcActiveClaim.from_json(data["assigned_claim"])

        competing_claims = [RpcActiveClaim.from_json(c) for c in data.get("competing_claims", [])]

        return cls(
            assigned_operator=int(data["assigned_operator"]),
            assigned_claim=assigned_claim,
            competing_claims=competing_claims,
        )


@dataclass
class RpcBridgeDutyDeposit:
    """Deposit duty."""

    deposit_idx: int
    deposit_request_txid: str


@dataclass
class RpcBridgeDutyWithdrawal:
    """Withdrawal duty."""

    deposit_idx: int
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


class RpcStakeStateLabel(Enum):
    """Lifecycle state of an operator's stake."""

    CREATED = "created"
    STAKE_GRAPH_GENERATED = "stake_graph_generated"
    UNSTAKING_NONCES_COLLECTED = "unstaking_nonces_collected"
    UNSTAKING_SIGNED = "unstaking_signed"
    CONFIRMED = "confirmed"
    PREIMAGE_REVEALED = "preimage_revealed"
    UNSTAKED = "unstaked"


@dataclass
class RpcOperatorStakeInfo:
    """Per-operator stake status returned by `stratabridge_stakeStatus`."""

    operator_idx: int
    state: RpcStakeStateLabel
    stake_txid: str | None = None
    unstaking_txid: str | None = None

    @classmethod
    def from_json(cls, data: dict) -> "RpcOperatorStakeInfo":
        return cls(
            operator_idx=int(data["operator_idx"]),
            state=RpcStakeStateLabel(data["state"]),
            stake_txid=data.get("stake_txid"),
            unstaking_txid=data.get("unstaking_txid"),
        )
