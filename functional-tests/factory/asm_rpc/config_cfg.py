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
    """Database configuration."""

    path: str
    num_threads: int | None = None
    retry_count: int | None = None
    delay: Duration | None = None


@dataclass
class BitcoinConfig:
    """Bitcoin node configuration."""

    rpc_url: str
    rpc_user: str
    rpc_password: str
    rawblock_connection_string: str
    retry_count: int | None = None
    retry_interval: Duration | None = None


@dataclass
class ParamsConfig:
    """ASM parameters configuration."""

    params_file: str | None
    network: str


@dataclass
class NativeBackend:
    """Native (in-process) proof backend configuration.

    Produces BIP-340 Schnorr-signed ASM-STF / Moho attestations (no real proving).
    """

    asm_schnorr_signing_key: str
    moho_schnorr_signing_key: str
    kind: str = "native"


@dataclass
class Sp1Backend:
    """SP1 proof backend configuration.

    Produces real SP1 Groth16 ASM-STF / Moho proofs from the given guest ELFs. Requires
    the asm-runner to be built with the `sp1` cargo feature. Mirrors the Rust
    `BackendConfig::Sp1` variant (serde tag `kind = "sp1"`).
    """

    asm_elf_path: str
    moho_elf_path: str
    kind: str = "sp1"


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
    backend: NativeBackend | Sp1Backend


@dataclass
class AsmRpcConfig:
    """Main ASM RPC configuration structure."""

    rpc: RpcConfig
    database: DatabaseConfig
    bitcoin: BitcoinConfig
    orchestrator: OrchestratorConfig | None = None
