//! Configuration of graph state machines.

use std::collections::BTreeMap;

use bitcoin::Amount;
use bitcoin_bosd::Descriptor;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_tx_graph::game_graph::{AdminMultisig, ProtocolParams};
use strata_predicate::PredicateKey;

/// Configuration for a graph state machine.
///
/// Serializable so that the params a graph was created under can be persisted beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphSMCfg {
    /// Parameters of the Game Graph that are inherent to the protocol.
    pub game_graph_params: ProtocolParams,

    /// Fees paid to the operator for fronting a user.
    pub operator_fee: Amount,

    /// Admin multisig that locks the payout connector output.
    ///
    /// Signatures satisfying this threshold can be used to block payouts to the operator.
    pub admin: AdminMultisig,

    /// Each registered operator's payout descriptor, keyed by permanent operator index.
    ///
    /// Registrations are never removed and their descriptors never change, so a graph built
    /// from this map keeps the same scripts as registrations are added.
    pub payout_descs: BTreeMap<OperatorIdx, Descriptor>,

    /// Predicate key used to verify bridge proof.
    pub bridge_proof_predicate: PredicateKey,

    /// Predicate key used to verify bridge counterproof.
    pub counterproof_predicate: PredicateKey,
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use bitcoin::{Network, relative};
    use strata_bridge_test_utils::{
        bitcoin::generate_xonly_pubkey,
        bridge_fixtures::{
            TEST_DEPOSIT_AMOUNT, TEST_MAGIC_BYTES, TEST_OPERATOR_FEE, random_p2tr_desc,
        },
    };

    use super::*;

    /// `Network`, `MagicBytes`, `PredicateKey` and `Descriptor` all serialize differently depending
    /// on `is_human_readable`, and this config is persisted with postcard (non-human-readable). An
    /// upstream bump that switched any of them to a string-only impl would otherwise only surface
    /// when a node failed to recover its state machines.
    #[test]
    fn postcard_roundtrip() {
        let cfg = GraphSMCfg {
            game_graph_params: ProtocolParams {
                network: Network::Regtest,
                magic_bytes: TEST_MAGIC_BYTES.into(),
                contest_timelock: relative::Height::from_height(45),
                proof_timelock: relative::Height::from_height(15),
                ack_timelock: relative::Height::from_height(35),
                nack_timelock: relative::Height::from_height(30),
                contested_payout_timelock: relative::Height::from_height(60),
                counterproof_n_data: NonZero::new(128 + 4).unwrap(),
                deposit_amount: TEST_DEPOSIT_AMOUNT,
                stake_amount: Amount::from_sat(100_000_000),
            },
            operator_fee: TEST_OPERATOR_FEE,
            admin: AdminMultisig {
                pubkeys: vec![generate_xonly_pubkey(), generate_xonly_pubkey()],
                threshold: 2,
            },
            payout_descs: BTreeMap::from([(0, random_p2tr_desc()), (1, random_p2tr_desc())]),
            bridge_proof_predicate: PredicateKey::always_accept(),
            counterproof_predicate: PredicateKey::always_accept(),
        };

        let bytes = postcard::to_allocvec(&cfg).expect("config must serialize");
        let decoded: GraphSMCfg = postcard::from_bytes(&bytes).expect("config must deserialize");

        assert_eq!(cfg, decoded);
    }
}
