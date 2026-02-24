//! Crate-agnostic test fixtures for the Strata Bridge.
//!
//! Provides shared constants and helpers (operator tables, descriptors) that multiple crates
//! (bridge-sm, orchestrator, etc.) need for testing. SM-specific config construction stays
//! local to each consumer crate.

use bitcoin::Amount;
use bitcoin_bosd::Descriptor;
use secp256k1::{SecretKey, SECP256K1};
use strata_bridge_p2p_types::P2POperatorPubKey;
use strata_bridge_primitives::{
    operator_table::OperatorTable, secp::EvenSecretKey, types::OperatorIdx,
};

use crate::bitcoin::generate_xonly_pubkey;

// ===== Shared Test Constants =====

/// Operator index of the POV (point-of-view) operator in tests.
pub const TEST_POV_IDX: OperatorIdx = 0;

/// Magic bytes used in tests (`"TEST"`).
pub const TEST_MAGIC_BYTES: [u8; 4] = [0x54, 0x45, 0x53, 0x54];

/// Deposit amount used in tests.
pub const TEST_DEPOSIT_AMOUNT: Amount = Amount::from_sat(10_000_000);

/// Operator fee used in tests.
pub const TEST_OPERATOR_FEE: Amount = Amount::from_sat(10_000);

/// Recovery delay (in blocks) used in tests.
pub const TEST_RECOVERY_DELAY: u16 = 1008;

// ===== Shared Test Helpers =====

/// Creates a random P2TR descriptor for use in tests.
pub fn random_p2tr_desc() -> Descriptor {
    Descriptor::new_p2tr(&generate_xonly_pubkey().serialize())
        .expect("Failed to generate descriptor")
}

/// Creates a deterministic test operator table with `n` operators, marking `pov_idx` as POV.
pub fn test_operator_table(n: usize, pov_idx: OperatorIdx) -> OperatorTable {
    let operators = (0..n as OperatorIdx)
        .map(|idx| {
            let byte =
                u8::try_from(idx + 1).expect("operator index too large for test key derivation");
            let sk = EvenSecretKey::from(SecretKey::from_slice(&[byte; 32]).unwrap());
            let pk = sk.public_key(SECP256K1);
            let p2p = P2POperatorPubKey::from(pk.serialize().to_vec());

            (idx, p2p, pk)
        })
        .collect();

    OperatorTable::new(operators, move |entry| entry.0 == pov_idx)
        .expect("Failed to create test operator table")
}
