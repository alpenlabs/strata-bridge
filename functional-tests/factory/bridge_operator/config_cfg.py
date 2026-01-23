from dataclasses import dataclass


@dataclass
class Duration:
    secs: int
    nanos: int


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
    retry_count: int
    retry_interval: int


@dataclass
class DbConfig:
    max_retry_count: int
    backoff_period: Duration


@dataclass
class P2pConfig:
    idle_connection_timeout: Duration
    listening_addr: str
    connect_to: list[str]
    num_threads: int
    dial_timeout: Duration
    general_timeout: Duration
    connection_check_interval: Duration
    gossipsub_mesh_n: int | None = None
    gossipsub_mesh_n_low: int | None = None
    gossipsub_mesh_n_high: int | None = None
    gossipsub_scoring_preset: str | None = None
    gossipsub_heartbeat_initial_delay: Duration | None = None
    gossipsub_forward_queue_duration: Duration | None = None
    gossipsub_publish_queue_duration: Duration | None = None


@dataclass
class RpcConfig:
    rpc_addr: str
    refresh_interval: Duration


@dataclass
class BtcZmqConfig:
    bury_depth: int
    hashblock_connection_string: str
    hashtx_connection_string: str
    rawblock_connection_string: str
    rawtx_connection_string: str
    sequence_connection_string: str


@dataclass
class StakeTxConfig:
    max_retries: int
    retry_delay: Duration


@dataclass
class AsmRpcConfig:
    rpc_url: str
    request_timeout: Duration
    max_retries: int | None
    retry_initial_delay: Duration
    retry_max_delay: Duration
    retry_multiplier: int


@dataclass
class BridgeOperatorConfig:
    datadir: str
    is_faulty: bool
    nag_interval: Duration
    min_withdrawal_fulfillment_window: int
    stake_funding_pool_size: int
    shutdown_timeout: Duration
    secret_service_client: SecretServiceClientConfig
    btc_client: BtcClientConfig
    db: DbConfig
    p2p: P2pConfig
    rpc: RpcConfig
    asm_rpc: AsmRpcConfig
    btc_zmq: BtcZmqConfig
    stake_tx: StakeTxConfig
