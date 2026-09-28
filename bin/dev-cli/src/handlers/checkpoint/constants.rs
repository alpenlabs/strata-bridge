use strata_identifiers::AccountSerial;

/// Bridge gateway account serial.
pub(super) const BRIDGE_GATEWAY_ACCT_SERIAL: AccountSerial = AccountSerial::reserved(0x10);

/// Fixed arbitrary private key for mock checkpoints. ASM under `AlwaysAccept` predicate accepts any
/// schnorr signing key.
pub(super) const MOCK_PREDICATE_KEY: [u8; 32] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

/// Fixed arbitrary private key for the mock sequencer. ASM only accepts checkpoint envelopes whose
/// reveal script commits to the configured `sequencer_key`, so the fn-test asm params set that to
/// this key's x-only pubkey, `29e5b5ad2a50b343407817f231ade1e6349bf6bc42ff457468f6eb774600bf64`.
pub(crate) const MOCK_SEQUENCER_KEY: [u8; 32] = [
    0x5e, 0x9c, 0x0d, 0x3a, 0x77, 0x21, 0xb4, 0x6f, 0x18, 0xe2, 0x4c, 0x90, 0x3b, 0xd5, 0x6a, 0x07,
    0x5e, 0x9c, 0x0d, 0x3a, 0x77, 0x21, 0xb4, 0x6f, 0x18, 0xe2, 0x4c, 0x90, 0x3b, 0xd5, 0x6a, 0x07,
];

/// Transaction fee for the envelope reveal tx (in sats).
pub(super) const ENVELOPE_FEE_SATS: u64 = 2_000;

/// Change output value for the envelope commit tx (in sats).
/// This is above the dust threshold for P2TR outputs (~330 sats).
pub(super) const ENVELOPE_CHANGE_SATS: u64 = 1_000;

#[cfg(test)]
mod tests {
    use secp256k1::{Keypair, SECP256K1};

    use super::*;

    #[test]
    fn mock_sequencer_key_matches_fn_test_params() {
        let keypair = Keypair::from_seckey_slice(SECP256K1, &MOCK_SEQUENCER_KEY).unwrap();
        assert_eq!(
            hex::encode(keypair.x_only_public_key().0.serialize()),
            "29e5b5ad2a50b343407817f231ade1e6349bf6bc42ff457468f6eb774600bf64",
            "must match MOCK_SEQUENCER_KEY in functional-tests/factory/common/asm_params.py"
        );
    }
}
