//! The CPFP fee-bump implementation behind [`btc_tracker::cpfp::CpfpBumper`].

pub mod ladder;
pub mod observability;
pub mod submitpackage;

/// One vbyte is four weight units, and one kiloweight unit is 1000 weight units, so one sat/vB is
/// 250 sat per kiloweight unit.
const SAT_PER_KWU_PER_SAT_PER_VB: u64 = 250;
