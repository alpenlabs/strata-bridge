from dataclasses import dataclass

from constants import BLOCK_GENERATION_INTERVAL_SECS


@dataclass
class BitcoinEnvConfig:
    """Per-test configuration for the Bitcoin regtest environment."""

    initial_blocks: int = 101
    block_generation_interval_secs: int = BLOCK_GENERATION_INTERVAL_SECS
    auto_mine: bool = True
    finalization_blocks: int = 10
    funding_amount: float = 10.01
