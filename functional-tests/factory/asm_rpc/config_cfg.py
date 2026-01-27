"""Configuration dataclasses for ASM RPC service.

These dataclasses mirror the Rust configuration structures in bin/asm-rpc/src/config.rs
"""

from dataclasses import dataclass


@dataclass
class RpcConfig:
    """RPC server configuration."""

    host: str
    port: int


@dataclass
class DatabaseConfig:
    """Database configuration."""

    path: str


@dataclass
class BitcoinConfig:
    """Bitcoin node configuration."""

    rpc_url: str
    rpc_user: str
    rpc_password: str
    retry_count: int | None = None
    retry_interval: int | None = None


@dataclass
class BtcNotifyConfig:
    """BTC tracker/notify configuration."""

    bury_depth: int
    hashblock_connection_string: str | None = None
    hashtx_connection_string: str | None = None
    rawblock_connection_string: str | None = None
    rawtx_connection_string: str | None = None
    sequence_connection_string: str | None = None


@dataclass
class ParamsConfig:
    """Rollup parameters configuration."""

    params_file: str | None
    network: str


@dataclass
class AsmRpcConfig:
    """Main ASM RPC configuration structure."""

    rpc: RpcConfig
    database: DatabaseConfig
    bitcoin: BitcoinConfig
    btc_tracker: BtcNotifyConfig
