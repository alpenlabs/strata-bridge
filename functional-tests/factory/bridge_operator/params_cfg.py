from dataclasses import dataclass


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
class RollupVk:
    native: str


@dataclass
class OperatorInfo:
    signing_pk: str
    wallet_pk: str


@dataclass
class OperatorConfig:
    static: list[OperatorInfo]


@dataclass
class Block:
    height: int
    blkid: str


@dataclass
class GenesisL1View:
    blk: Block
    next_target: int
    epoch_start_timestamp: int
    last_11_timestamps: list[int]


@dataclass
class Sidesystem:
    magic_bytes: list[int]
    block_time: int
    da_tag: str
    checkpoint_tag: str
    cred_rule: str
    horizon_l1_height: int
    genesis_l1_height: int
    l1_reorg_safe_depth: int
    target_l2_batch_size: int
    max_address_length: int
    deposit_amount: int
    dispatch_assignment_dur: int
    proof_publish_mode: str
    checkpoint_predicate: str
    max_deposits_in_block: int
    network: str
    evm_genesis_block_hash: str
    evm_genesis_block_state_root: str
    rollup_vk: RollupVk
    operator_config: OperatorConfig
    genesis_l1_view: GenesisL1View

    @classmethod
    def default(cls) -> "Sidesystem":
        return cls(
            magic_bytes=[65, 76, 80, 78],
            block_time=1000,
            da_tag="alpen-bridge-da",
            checkpoint_tag="alpen-bridge-checkpoint",
            cred_rule="unchecked",
            horizon_l1_height=1000,
            genesis_l1_height=1000,
            l1_reorg_safe_depth=1000,
            target_l2_batch_size=1000,
            max_address_length=20,
            deposit_amount=1_000_000_000,
            dispatch_assignment_dur=1000,
            proof_publish_mode="strict",
            checkpoint_predicate="AlwaysAccept",
            max_deposits_in_block=20,
            network="signet",
            evm_genesis_block_hash="0x46c0dc60fb131be4ccc55306a345fcc20e44233324950f978ba5f185aa2af4dc",
            evm_genesis_block_state_root="0x351714af72d74259f45cd7eab0b04527cd40e74836a45abcae50f92d919d988f",
            rollup_vk=RollupVk(
                native="0x0000000000000000000000000000000000000000000000000000000000000000"
            ),
            operator_config=OperatorConfig(static=[]),
            genesis_l1_view=GenesisL1View(
                blk=Block(
                    height=100,
                    blkid="f2c22acbe3b24e429349296b958c40b692356436086750bd7564ebfceb915100",
                ),
                next_target=545259519,
                epoch_start_timestamp=1296688602,
                last_11_timestamps=[
                    1764086031,
                    1764086031,
                    1764086032,
                    1764086032,
                    1764086032,
                    1764086032,
                    1764086032,
                    1764086032,
                    1764086033,
                    1764086033,
                    1764086033,
                ],
            ),
        )


@dataclass
class BridgeOperatorParams:
    network: str
    genesis_height: int
    keys: Keys
    tx_graph: TxGraph
    stake_chain: StakeChain
    connectors: Connectors
    sidesystem: Sidesystem
