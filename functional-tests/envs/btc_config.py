from dataclasses import dataclass

from constants import BLOCK_GENERATION_INTERVAL_SECS


@dataclass
class BitcoinEnvConfig:
    """Per-test configuration for the Bitcoin regtest environment.

    Attributes:
        initial_blocks: Blocks mined at startup for mature, spendable coinbase funds.
        block_generation_interval_secs: Seconds between auto-mined blocks.
        auto_mine: Whether to run the background miner thread.
        finalization_blocks: Protocol finality depth; also mined to confirm funding.
        funding_amount: BTC sent to each operator's general wallet.
        external: Attach to an already-running bitcoind instead of spawning regtest.
        mine_on_demand: Mine only when the mempool is non-empty.
        mine_on_demand_trailing_blocks: Empty blocks mined after the mempool clears;
            must exceed the largest confirmation gap a flow waits on before broadcast.
    """

    initial_blocks: int = 101
    block_generation_interval_secs: int = BLOCK_GENERATION_INTERVAL_SECS
    auto_mine: bool = True
    finalization_blocks: int = 4
    funding_amount: float = 30
    external: bool = False
    mine_on_demand: bool = False
    mine_on_demand_trailing_blocks: int = 4
