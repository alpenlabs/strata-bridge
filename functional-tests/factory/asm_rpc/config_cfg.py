"""Configuration dataclasses for ASM RPC service.

These dataclasses mirror the Rust configuration structures in bin/asm-runner/src/config.rs
"""

from dataclasses import dataclass

from factory.common_cfg import Duration


@dataclass
class RpcConfig:
    """RPC server configuration."""

    host: str
    port: int


@dataclass
class DatabaseConfig:
    """Database configuration.

    The ASM stores and Moho stores live in two separate sled DBs.
    """

    asm_path: str
    moho_path: str
    num_threads: int | None = None
    retry_count: int | None = None
    delay: Duration | None = None


@dataclass
class BitcoinConfig:
    """Bitcoin node configuration."""

    rpc_url: str
    rpc_user: str
    rpc_password: str
    hashblock_connection_string: str


@dataclass
class ParamsConfig:
    """ASM parameters configuration."""

    params_file: str | None
    network: str


@dataclass
class NativeSource:
    """Native (in-process) proof host that signs BIP-340 Schnorr attestations (no real proving)."""

    signing_key: str
    kind: str = "native"


@dataclass
class Sp1Source:
    """SP1 proof host built from a guest ELF.

    Requires the asm-runner to be built with the `sp1` cargo feature. Mirrors the Rust
    `ArtifactSource::Sp1` variant (serde tag `kind = "sp1"`).
    """

    elf_path: str
    kind: str = "sp1"


@dataclass
class AsmArtifactConfig:
    """An ASM program the prover can prove; its host must resolve to the predicate
    `[[execution.targets]]` lists for `spec_id`."""

    spec_id: int
    source: NativeSource | Sp1Source


@dataclass
class OrchestratorConfig:
    """Proof orchestrator configuration.

    When set, the asm-runner opens its proof DB and instantiates the proof
    backend, which is the gate for `MohoStorage` and the export-entries index
    that backs `strata_asm_getExportEntryMMRProof`.
    """

    tick_interval: Duration
    max_concurrent_proofs: int
    proof_db_path: str
    moho: NativeSource | Sp1Source
    asm_artifacts: list[AsmArtifactConfig]


@dataclass
class ExecutionTargetConfig:
    """Binds an ASM program predicate to the spec it implements."""

    predicate: str
    spec_id: int


@dataclass
class ExecutionConfig:
    """Genesis ASM spec and the programs this runner can execute."""

    genesis_spec_id: int
    targets: list[ExecutionTargetConfig]

    @classmethod
    def single(cls, predicate: str) -> "ExecutionConfig":
        """A chain that starts on, and only runs, `predicate` as spec 0."""
        return cls(0, [ExecutionTargetConfig(predicate, spec_id=0)])


@dataclass
class AsmRpcConfig:
    """Main ASM RPC configuration structure."""

    rpc: RpcConfig
    database: DatabaseConfig
    bitcoin: BitcoinConfig
    execution: ExecutionConfig
    orchestrator: OrchestratorConfig | None = None
