#[cfg(not(skip_guest_build))]
use sp1_sdk::include_elf;

#[cfg(skip_guest_build)]
pub const GUEST_BRIDGE_ELF: &[u8] = &[];

#[cfg(not(skip_guest_build))]
pub const GUEST_BRIDGE_ELF: &[u8] = include_elf!("strata-bridge-guest");
