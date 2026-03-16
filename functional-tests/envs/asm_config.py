from dataclasses import dataclass


@dataclass
class AsmEnvConfig:
    """Per-test configuration for ASM (Alpen State Machine) parameters."""

    magic: str = "ALPN"
    denomination: int = 1_000_000_000
    assignment_duration: int = 10_000
    operator_fee: int = 100_000_000
    recovery_delay: int = 1_008
