//! Build script for the bridge guest.

use sp1_sdk as _;
#[cfg(not(skip_guest_build))]
use sp1_sdk::include_elf;

/// The guest bridge ELF.
#[cfg(skip_guest_build)]
pub const GUEST_BRIDGE_ELF: &[u8] = &[];

/// The guest bridge ELF.
#[cfg(not(skip_guest_build))]
pub const GUEST_BRIDGE_ELF: &[u8] = include_elf!("strata-bridge-guest");
