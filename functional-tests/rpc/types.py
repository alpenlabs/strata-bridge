from dataclasses import dataclass, field
from enum import Enum


class RpcOperatorStatus(Enum):
    """Enum representing the status of a bridge operator."""

    ONLINE = "online"
    OFFLINE = "offline"


class RpcClaimPhaseKind(Enum):
    """Discriminator for a claim's phase payload."""

    CLAIMED = "claimed"
    CONTESTED = "contested"
    BRIDGE_PROOF_POSTED = "bridge_proof_posted"
    BRIDGE_PROOF_TIMEDOUT = "bridge_proof_timedout"
    COUNTER_PROOF_POSTED = "counter_proof_posted"
    ALL_NACKD = "all_nackd"
    ACKED = "acked"
    BLOCKED = "blocked"


@dataclass
class RpcClaimPhaseClaimed:
    phase: RpcClaimPhaseKind = field(init=False, default=RpcClaimPhaseKind.CLAIMED)


@dataclass
class RpcClaimPhaseContested:
    contest_txid: str
    phase: RpcClaimPhaseKind = field(init=False, default=RpcClaimPhaseKind.CONTESTED)


@dataclass
class RpcClaimPhaseBridgeProofPosted:
    contest_txid: str
    phase: RpcClaimPhaseKind = field(init=False, default=RpcClaimPhaseKind.BRIDGE_PROOF_POSTED)


@dataclass
class RpcClaimPhaseBridgeProofTimedout:
    contest_txid: str
    phase: RpcClaimPhaseKind = field(init=False, default=RpcClaimPhaseKind.BRIDGE_PROOF_TIMEDOUT)


@dataclass
class RpcClaimPhaseCounterProofPosted:
    contest_txid: str
    phase: RpcClaimPhaseKind = field(init=False, default=RpcClaimPhaseKind.COUNTER_PROOF_POSTED)


@dataclass
class RpcClaimPhaseAllNackd:
    contest_txid: str
    phase: RpcClaimPhaseKind = field(init=False, default=RpcClaimPhaseKind.ALL_NACKD)


@dataclass
class RpcClaimPhaseAcked:
    contest_txid: str
    phase: RpcClaimPhaseKind = field(init=False, default=RpcClaimPhaseKind.ACKED)


class RpcPayoutBlock(Enum):
    """The classified paths that prevent a reimbursement payout."""

    ADMIN = "admin"
    UNSTAKING = "unstaking"
    ADMIN_AND_UNSTAKING = "admin_and_unstaking"


@dataclass
class RpcClaimPhaseBlocked:
    contest_txid: str | None
    reason: RpcPayoutBlock
    phase: RpcClaimPhaseKind = field(init=False, default=RpcClaimPhaseKind.BLOCKED)


RpcClaimPhase = (
    RpcClaimPhaseClaimed
    | RpcClaimPhaseContested
    | RpcClaimPhaseBridgeProofPosted
    | RpcClaimPhaseBridgeProofTimedout
    | RpcClaimPhaseCounterProofPosted
    | RpcClaimPhaseAllNackd
    | RpcClaimPhaseAcked
    | RpcClaimPhaseBlocked
)


def claim_phase_from_json(data: dict) -> RpcClaimPhase:
    """Decode the current phase and its contest transaction, when challenged."""
    kind = RpcClaimPhaseKind(data["phase"])
    match kind:
        case RpcClaimPhaseKind.CLAIMED:
            return RpcClaimPhaseClaimed()
        case RpcClaimPhaseKind.CONTESTED:
            return RpcClaimPhaseContested(data["contest_txid"])
        case RpcClaimPhaseKind.BRIDGE_PROOF_POSTED:
            return RpcClaimPhaseBridgeProofPosted(data["contest_txid"])
        case RpcClaimPhaseKind.BRIDGE_PROOF_TIMEDOUT:
            return RpcClaimPhaseBridgeProofTimedout(data["contest_txid"])
        case RpcClaimPhaseKind.COUNTER_PROOF_POSTED:
            return RpcClaimPhaseCounterProofPosted(data["contest_txid"])
        case RpcClaimPhaseKind.ALL_NACKD:
            return RpcClaimPhaseAllNackd(data["contest_txid"])
        case RpcClaimPhaseKind.ACKED:
            return RpcClaimPhaseAcked(data["contest_txid"])
        case RpcClaimPhaseKind.BLOCKED:
            return RpcClaimPhaseBlocked(data["contest_txid"], RpcPayoutBlock(data["reason"]))


@dataclass
class RpcDepositStatusInProgress:
    """Deposit exists, but minting hasn't happened yet."""

    status: str = "in_progress"


@dataclass
class RpcDepositStatusReclaimable:
    """Deposit was not completed and can be reclaimed."""

    status: str = "reclaimable"
    reason: str = ""


@dataclass
class RpcDepositStatusComplete:
    """Deposit has been fully processed and minted."""

    status: str = "complete"
    deposit_txid: str = ""


RpcDepositStatus = (
    RpcDepositStatusInProgress | RpcDepositStatusReclaimable | RpcDepositStatusComplete
)


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

    claim_txid: str
    phase: RpcClaimPhase
    status: str = field(init=False, default="in_progress")


@dataclass
class RpcReimbursementStatusSlashed:
    """Operator was slashed for this reimbursement claim."""

    claim_txid: str
    contest_txid: str
    slash_txid: str
    status: str = field(init=False, default="slashed")


@dataclass
class RpcReimbursementStatusAborted:
    """Reimbursement claim path was aborted before payout or slashing completed."""

    claim_txid: str
    status: str = field(init=False, default="aborted")


class RpcPayoutKind(Enum):
    """The payout path for a reimbursement claim."""

    UNCONTESTED = "uncontested"
    CONTESTED = "contested"


@dataclass
class RpcReimbursementStatusComplete:
    """Reimbursement completed, with no claim for a cooperative payout."""

    claim_txid: str | None
    payout_txid: str
    payout_kind: RpcPayoutKind | None
    status: str = field(init=False, default="complete")


RpcReimbursementStatus = (
    RpcReimbursementStatusNotStarted
    | RpcReimbursementStatusInProgress
    | RpcReimbursementStatusSlashed
    | RpcReimbursementStatusAborted
    | RpcReimbursementStatusComplete
)


def reimbursement_status_from_json(data: dict) -> RpcReimbursementStatus:
    """Decode reimbursement status and its phase-specific evidence."""
    match data["status"]:
        case "not_started":
            return RpcReimbursementStatusNotStarted()
        case "in_progress":
            return RpcReimbursementStatusInProgress(
                data["claim_txid"], claim_phase_from_json(data["phase"])
            )
        case "slashed":
            return RpcReimbursementStatusSlashed(
                data["claim_txid"], data["contest_txid"], data["slash_txid"]
            )
        case "aborted":
            return RpcReimbursementStatusAborted(data["claim_txid"])
        case "complete":
            return RpcReimbursementStatusComplete(
                data["claim_txid"],
                data["payout_txid"],
                RpcPayoutKind(data["payout_kind"]) if data["payout_kind"] is not None else None,
            )
        case _:
            raise ValueError(f"Unknown reimbursement status: {data['status']}")


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
            phase=claim_phase_from_json(data["phase"]),
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
    SLASHED = "slashed"


@dataclass(frozen=True)
class RpcCovenantId:
    """A covenant's identity: its aggregate key and the height of its last admin change."""

    aggregate_pubkey: str
    activation_height: int

    @classmethod
    def from_json(cls, data: dict) -> "RpcCovenantId":
        return cls(
            aggregate_pubkey=data["aggregate_pubkey"],
            activation_height=int(data["activation_height"]),
        )


@dataclass
class RpcCurrentCovenant:
    """The current covenant and its deposit admission, returned by `currentCovenant`."""

    processed_height: int
    covenant: RpcCovenantId
    members: list[int]
    admission: dict

    @property
    def admission_status(self) -> str:
        return self.admission["status"]

    @classmethod
    def from_json(cls, data: dict) -> "RpcCurrentCovenant":
        return cls(
            processed_height=int(data["processed_height"]),
            covenant=RpcCovenantId.from_json(data["covenant"]),
            members=[int(member) for member in data["members"]],
            admission=data["admission"],
        )


@dataclass
class RpcOperatorStakeInfo:
    """Per-operator stake status returned by `stratabridge_stakeStatus`."""

    covenant: RpcCovenantId
    operator_idx: int
    state: RpcStakeStateLabel
    stake_txid: str | None = None
    unstaking_txid: str | None = None
    slash_txid: str | None = None

    @classmethod
    def from_json(cls, data: dict) -> "RpcOperatorStakeInfo":
        return cls(
            covenant=RpcCovenantId.from_json(data["covenant"]),
            operator_idx=int(data["operator_idx"]),
            state=RpcStakeStateLabel(data["state"]),
            stake_txid=data.get("stake_txid"),
            unstaking_txid=data.get("unstaking_txid"),
            slash_txid=data.get("slash_txid"),
        )
