from dataclasses import dataclass

from .sidesystem_cfg import Sidesystem


@dataclass
class Keys:
    musig2: list[str]
    p2p: list[str]


@dataclass
class TxGraph:
    tag: str
    deposit_amount: int
    operator_fee: int
    challenge_cost: int
    refund_delay: int


@dataclass
class StakeChain:
    stake_amount: int
    burn_amount: int
    delta: dict[str, int]  # {"Blocks": 6}
    slash_stake_count: int


@dataclass
class Connectors:
    payout_optimistic_timelock: int
    pre_assert_timelock: int
    payout_timelock: int


@dataclass
class BridgeOperatorParams:
    network: str
    genesis_height: int
    keys: Keys
    tx_graph: TxGraph
    stake_chain: StakeChain
    connectors: Connectors
    sidesystem: Sidesystem
