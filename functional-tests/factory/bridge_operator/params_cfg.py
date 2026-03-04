from dataclasses import dataclass


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
class Protocol:
    magic_bytes: str
    deposit_amount: int
    stake_amount: int
    operator_fee: int
    recovery_delay: int
    contest_timelock: int
    proof_timelock: int
    ack_timelock: int
    nack_timelock: int
    contested_payout_timelock: int


@dataclass
class BridgeOperatorParams:
    network: str
    genesis_height: int
    keys: Keys
    protocol: Protocol
