pub(super) use strata_bridge_primitives::constants::BRIDGE_TAG;
use strata_identifiers::AccountSerial;

/// Bridge gateway account serial.
pub(super) const BRIDGE_GATEWAY_ACCT_SERIAL: AccountSerial = AccountSerial::reserved(0x10);

/// Fixed arbitrary private key for mock checkpoints. ASM under `AlwaysAccept` predicate accepts any
/// schnorr signing key.
pub(super) const MOCK_PREDICATE_KEY: [u8; 32] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

/// Transaction fee for the envelope reveal tx (in sats).
pub(super) const ENVELOPE_FEE_SATS: u64 = 2_000;

/// Change output value for the envelope commit tx (in sats).
/// This is above the dust threshold for P2TR outputs (~330 sats).
pub(super) const ENVELOPE_CHANGE_SATS: u64 = 1_000;
