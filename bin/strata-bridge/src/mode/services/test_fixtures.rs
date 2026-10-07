//! Shared fixtures for service tests.

use bitcoin_bosd::Descriptor;
use strata_bridge_common::params::Params;

// Valid x-only/ed25519 test keys, same fixtures as `strata_bridge_common::params` tests.
const XONLY_KEY_1: &str = "b49092f76d06f8002e0b7f1c63b5058db23fd4465b4f6954b53e1f352a04754d";
const XONLY_KEY_2: &str = "1e62d54af30569fd7269c14b6766f74d85ea00c911c4e1a423d4ba2ae4c34dc4";
const P2P_KEY_1: &str = "0de7729dcbeb5069136ee4bff1c4f2fd822fe8fbc9b518df434d4f0c6312d8f5";
const P2P_KEY_2: &str = "255ab0da6d468a22910a7cf54021763417c63c28bbafd4e2359daf103bb61e9d";

/// Shared params fixture for tests.
pub(in crate::mode) fn test_params() -> Params {
    let p2tr = |xonly_hex: &str| {
        let pk: [u8; 32] = hex::decode(xonly_hex).unwrap().try_into().unwrap();
        Descriptor::new_p2tr(&pk).unwrap().to_string()
    };
    let (desc_1, desc_2) = (p2tr(XONLY_KEY_1), p2tr(XONLY_KEY_2));

    toml::from_str(&format!(
        r#"
        network = "signet"
        genesis_height = 101

        [keys.admin]
        pubkeys = ["{XONLY_KEY_1}", "{XONLY_KEY_2}"]
        threshold = 2

        [[keys.operators]]
        index = 0
        covenant_key = "{XONLY_KEY_1}"
        p2p_key = "{P2P_KEY_1}"
        payout_descriptor = "{desc_1}"
        activation_height = 101

        [[keys.operators]]
        index = 1
        covenant_key = "{XONLY_KEY_2}"
        p2p_key = "{P2P_KEY_2}"
        payout_descriptor = "{desc_2}"
        activation_height = 101

        [protocol]
        bury_depth = 6
        magic_bytes = "ALPN"
        deposit_amount = 100_000_000
        stake_amount = 100_000_000
        operator_fee = 1_000_000
        recovery_delay = 1_008
        contest_timelock = 144
        proof_timelock = 144
        ack_timelock = 144
        nack_timelock = 144
        contested_payout_timelock = 1_008
        unstaking_timelock = 2_016
        sweep_fee_rate = 10
        "#
    ))
    .expect("valid test params")
}
