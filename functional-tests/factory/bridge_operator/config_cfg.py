from dataclasses import dataclass

from factory.common_cfg import Duration


@dataclass
class SecretServiceClientConfig:
    server_addr: str
    server_hostname: str
    timeout: int
    cert: str
    key: str
    service_ca: str


@dataclass
class BtcClientConfig:
    url: str
    user: str
    pass_: str
    retry_count: int | None
    retry_interval: int | None


@dataclass
class FdbRetryConfig:
    retry_limit: int | None
    timeout: Duration | None


@dataclass
class DbConfig:
    cluster_file_path: str
    root_directory: str
    tls: dict | None
    retry: FdbRetryConfig


@dataclass
class P2pConfig:
    idle_connection_timeout: Duration | None
    listening_addr: str
    connect_to: list[str]
    num_threads: int | None
    dial_timeout: Duration | None
    general_timeout: Duration | None
    connection_check_interval: Duration | None
    gossipsub_mesh_n: int | None
    gossipsub_mesh_n_low: int | None
    gossipsub_mesh_n_high: int | None
    gossipsub_scoring_preset: str | None
    gossipsub_heartbeat_initial_delay: Duration | None
    gossipsub_publish_queue_duration: Duration | None
    gossipsub_forward_queue_duration: Duration | None


@dataclass
class RpcConfig:
    rpc_addr: str
    refresh_interval: Duration | None


@dataclass
class BtcZmqConfig:
    bury_depth: int
    hashblock_connection_string: str
    hashtx_connection_string: str
    rawblock_connection_string: str
    rawtx_connection_string: str
    sequence_connection_string: str


@dataclass
class AsmRpcConfig:
    rpc_url: str
    request_timeout: Duration
    max_retries: int
    retry_initial_delay: Duration
    retry_max_delay: Duration
    retry_multiplier: int


@dataclass
class OperatorWalletConfig:
    claim_funding_pool_size: int


@dataclass
class BridgeConfigParams:
    min_withdrawal_fulfillment_window: int = 144
    cooperative_payout_timeout: int = 144
    max_fee_rate: int = 10


@dataclass
class BridgeOperatorConfig:
    num_threads: int | None
    thread_stack_size: int | None
    nag_interval: Duration
    retry_interval: Duration
    min_withdrawal_fulfillment_window: int
    shutdown_timeout: Duration
    cooperative_payout_timeout: int
    max_fee_rate: int
    secret_service_client: SecretServiceClientConfig
    btc_client: BtcClientConfig
    db: DbConfig
    p2p: P2pConfig
    rpc: RpcConfig
    asm_rpc: AsmRpcConfig
    btc_zmq: BtcZmqConfig
    operator_wallet: OperatorWalletConfig
