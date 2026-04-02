from dataclasses import (
    dataclass,
    field,
)

# Defaults matching mosaic config.rs constants
DEFAULT_LOG_FILTER = "debug"
DEFAULT_KEEP_ALIVE_INTERVAL_SECS = 5
DEFAULT_IDLE_TIMEOUT_SECS = 30
DEFAULT_RECONNECT_BACKOFF_SECS = 1
DEFAULT_OPEN_TIMEOUT_SECS = 5
DEFAULT_ACK_TIMEOUT_SECS = 10
DEFAULT_POOL_THREADS = 1
DEFAULT_POOL_CONCURRENCY = 32
DEFAULT_HEAVY_POOL_THREADS = 2
DEFAULT_HEAVY_POOL_CONCURRENCY = 8
DEFAULT_GARBLING_WORKER_THREADS = 4
DEFAULT_GARBLING_MAX_CONCURRENT = 8
DEFAULT_BATCH_TIMEOUT_MS = 500
DEFAULT_CHUNK_TIMEOUT_SECS = 30
DEFAULT_SUBMISSION_QUEUE_SIZE = 256
DEFAULT_COMPLETION_QUEUE_SIZE = 256
DEFAULT_COMMAND_QUEUE_SIZE = 256
DEFAULT_RESTORE_INTERVAL_SEC = 30


@dataclass
class LoggingConfig:
    filter: str = DEFAULT_LOG_FILTER


@dataclass
class CircuitConfig:
    path: str


@dataclass
class PeerEntry:
    peer_id_hex: str
    addr: str


@dataclass
class NetworkClientConfig:
    open_timeout_secs: int = DEFAULT_OPEN_TIMEOUT_SECS
    ack_timeout_secs: int = DEFAULT_ACK_TIMEOUT_SECS


@dataclass
class NetworkConfig:
    signing_key_hex: str
    bind_addr: str
    peers: list[PeerEntry]
    keep_alive_interval_secs: int = DEFAULT_KEEP_ALIVE_INTERVAL_SECS
    idle_timeout_secs: int = DEFAULT_IDLE_TIMEOUT_SECS
    reconnect_backoff_secs: int = DEFAULT_RECONNECT_BACKOFF_SECS
    client: NetworkClientConfig = field(default_factory=NetworkClientConfig)


@dataclass
class StorageConfig:
    cluster_file: str
    global_path: list[str]


@dataclass
class LocalFilesystemBackend:
    root: str
    backend: str = "local_filesystem"
    prefix: str = "garbling-tables"


@dataclass
class S3CompatibleBackend:
    pass


@dataclass
class PoolSection:
    threads: int = DEFAULT_POOL_THREADS
    concurrency_per_worker: int = DEFAULT_POOL_CONCURRENCY


@dataclass
class GarblingSection:
    worker_threads: int = DEFAULT_GARBLING_WORKER_THREADS
    max_concurrent: int = DEFAULT_GARBLING_MAX_CONCURRENT
    batch_timeout_ms: int = DEFAULT_BATCH_TIMEOUT_MS
    chunk_timeout_secs: int = DEFAULT_CHUNK_TIMEOUT_SECS


@dataclass
class JobSchedulerSection:
    light: PoolSection = field(default_factory=PoolSection)
    heavy: PoolSection = field(
        default_factory=lambda: PoolSection(
            threads=DEFAULT_HEAVY_POOL_THREADS,
            concurrency_per_worker=DEFAULT_HEAVY_POOL_CONCURRENCY,
        )
    )
    garbling: GarblingSection = field(default_factory=GarblingSection)
    submission_queue_size: int = DEFAULT_SUBMISSION_QUEUE_SIZE
    completion_queue_size: int = DEFAULT_COMPLETION_QUEUE_SIZE


@dataclass
class SmExecutorSection:
    command_queue_size: int = DEFAULT_COMMAND_QUEUE_SIZE
    restore_interval_secs: int | None = DEFAULT_RESTORE_INTERVAL_SEC


@dataclass
class RpcConfig:
    bind_addr: str


@dataclass
class MosaicConfig:
    circuit: CircuitConfig
    network: NetworkConfig
    storage: StorageConfig
    rpc: RpcConfig
    table_store: LocalFilesystemBackend | S3CompatibleBackend
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    job_scheduler: JobSchedulerSection = field(default_factory=JobSchedulerSection)
    sm_executor: SmExecutorSection = field(default_factory=SmExecutorSection)
