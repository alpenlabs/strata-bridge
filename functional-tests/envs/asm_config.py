from dataclasses import dataclass

from constants import ASM_MAGIC_BYTES
from factory.common.asm_params import DEFAULT_SAFE_HARBOUR_ADDRESS


@dataclass
class AsmEnvConfig:
    """Per-test configuration for ASM (Alpen State Machine) parameters."""

    magic: str = ASM_MAGIC_BYTES
    denomination: int = 1_000_000_000
    assignment_duration: int = 10_000
    operator_fee: int = 10_000_000
    recovery_delay: int = 1_008
    # Hex-encoded bitcoin-bosd Descriptor. The new asm requires a P2TR (type tag 0x04)
    # descriptor; the address is held deactivated at init and toggled by the security
    # council via Defcon signals.
    safe_harbour_address: str = DEFAULT_SAFE_HARBOUR_ADDRESS
