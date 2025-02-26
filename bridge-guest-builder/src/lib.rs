#![expect(incomplete_features)] // the generic_const_exprs feature is incomplete
#![feature(generic_const_exprs)] // but necessary for using const generic bounds in

#[cfg(not(skip_guest_build))]
use sp1_sdk::include_elf;

#[cfg(skip_guest_build)]
pub const GUEST_BRIDGE_ELF: &[u8] = &[];

#[cfg(not(skip_guest_build))]
pub const GUEST_BRIDGE_ELF: &[u8] = include_elf!("strata-bridge-guest");
