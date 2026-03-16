from dataclasses import dataclass

from constants import ASM_MAGIC_BYTES


@dataclass
class CovenantKeys:
    musig2: str
    p2p: str
    adaptor: str
    watchtower_fault: str
    payout_descriptor: str


@dataclass
class Keys:
    admin: str
    covenant: list[CovenantKeys]


@dataclass
class BridgeProtocolParams:
    magic_bytes: str = ASM_MAGIC_BYTES
    deposit_amount: int = 1_000_000_000
    stake_amount: int = 100_000_000
    operator_fee: int = 10_000_000
    recovery_delay: int = 1_008
    contest_timelock: int = 144
    proof_timelock: int = 144
    ack_timelock: int = 144
    nack_timelock: int = 144
    contested_payout_timelock: int = 1_008


@dataclass
class BridgeOperatorParams:
    network: str
    genesis_height: int
    keys: Keys
    protocol: BridgeProtocolParams
