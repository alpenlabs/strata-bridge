from dataclasses import dataclass

from constants import ASM_MAGIC_BYTES


class ProofPredicate:
    """Identifiers for the `strata_predicate::PredicateTypeId` variants used as the
    bridge proof predicate."""

    ALWAYS_ACCEPT = "AlwaysAccept"
    NEVER_ACCEPT = "NeverAccept"


@dataclass
class ScheduledOperator:
    index: int
    signing_key: str
    p2p_key: str
    payout_descriptor: str
    activation_height: int
    deactivation_height: int | None = None


@dataclass
class Keys:
    admin: str
    operators: list[ScheduledOperator]


@dataclass
class BridgeProtocolParams:
    bury_depth: int = 2
    magic_bytes: str = ASM_MAGIC_BYTES
    deposit_amount: int = 1_000_000_000
    stake_amount: int = 100_000_000
    operator_fee: int = 10_000_000
    recovery_delay: int = 1_008
    contest_timelock: int = 45
    proof_timelock: int = 15
    ack_timelock: int = 35
    nack_timelock: int = 30
    contested_payout_timelock: int = 60
    bridge_proof_predicate: str | None = None
    counterproof_predicate: str | None = None


@dataclass
class BridgeOperatorParams:
    network: str
    genesis_height: int
    keys: Keys
    protocol: BridgeProtocolParams
