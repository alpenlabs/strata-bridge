"""Configuration dataclasses for ASM RPC service.

These dataclasses mirror the Rust configuration structures in bin/asm-rpc/src/config.rs
"""

from dataclasses import dataclass
from typing import Optional


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
    retry_count: Optional[int] = None
    retry_interval: Optional[int] = None


@dataclass
class BtcNotifyConfig:
    """BTC tracker/notify configuration."""

    bury_depth: int
    hashblock_connection_string: Optional[str] = None
    hashtx_connection_string: Optional[str] = None
    rawblock_connection_string: Optional[str] = None
    rawtx_connection_string: Optional[str] = None
    sequence_connection_string: Optional[str] = None


@dataclass
class ParamsConfig:
    """Rollup parameters configuration."""

    params_file: Optional[str]
    network: str


@dataclass
class AsmRpcConfig:
    """Main ASM RPC configuration structure."""

    rpc: RpcConfig
    database: DatabaseConfig
    bitcoin: BitcoinConfig
    btc_tracker: BtcNotifyConfig
