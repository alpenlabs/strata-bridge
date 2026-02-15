//! Configuration shared across all graph state machines.

use bitcoin::{XOnlyPublicKey, hashes::sha256};
use bitcoin_bosd::Descriptor;
use strata_bridge_tx_graph2::game_graph::{KeyData, ProtocolParams, SetupParams};

use crate::graph::context::GraphSMCtx;

/// Bridge-wide configuration shared across all graph state machines.
///
/// These configurations are static over the lifetime of the bridge protocol
/// and apply uniformly to all graph state machine instances.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GraphSMCfg {
    /// Parameters of the Game Graph that are inherent to the protocol.
    pub game_graph_params: ProtocolParams,

    /// Key used in the locking script of a contest transaction.
    // NOTE: (@Rajil1213) we might need to get this from `Mosaic` per deposit at runtime instead.
    pub operator_adaptor_key: XOnlyPublicKey,

    /// Keys used to lock the claim-contest output.
    ///
    /// Signature corresponding to one of these keys can be used to initiate a contest on an
    /// operator's claim.
    pub watchtower_pubkeys: Vec<XOnlyPublicKey>,

    /// Key that locks the payout connector output.
    ///
    /// Signature corresponding to this key can be used to block payouts to the operator.
    pub admin_pubkey: XOnlyPublicKey,

    /// Key used to lock the counterproof-nack output.
    ///
    /// Signature corresponding to this key can be used by an operator to defend against a
    /// counterproof. This signature is produced by Mosaic as a result of a successful GC
    /// evaluation.
    // NOTE: (@Rail1213) we might need to get this from `Mosaic` per deposit at runtime instead.
    pub watchtower_fault_pubkeys: Vec<XOnlyPublicKey>,

    /// Descriptor to which payouts are to be sent in case of a successful peg out.
    pub payout_desc: Descriptor,

    /// Descriptors where slashed stake funds are to be disbursed.
    pub slash_watchtower_descriptors: Vec<Descriptor>,
}

impl GraphSMCfg {
    /// Generate the [`SetupParams`] required for graph generation.
    pub fn generate_setup_params(&self, graph_ctx: &GraphSMCtx) -> SetupParams {
        let n_of_n_pubkey = graph_ctx
            .operator_table()
            .aggregated_btc_key()
            .x_only_public_key()
            .0;
        let operator_index = graph_ctx.operator_table().pov_idx();
        let stake_outpoint = graph_ctx.stake_outpoint();
        let unstaking_image = graph_ctx.unstaking_image();

        SetupParams {
            operator_index,
            stake_outpoint,
            keys: self.generate_key_data(n_of_n_pubkey, unstaking_image),
        }
    }

    /// Generates the [`KeyData`] required for graph generation using the configuration parameters
    /// and external values.
    pub fn generate_key_data(
        &self,
        n_of_n_pubkey: XOnlyPublicKey,
        unstaking_image: sha256::Hash,
    ) -> KeyData {
        KeyData {
            n_of_n_pubkey,
            unstaking_image,
            operator_pubkey: self.operator_adaptor_key,
            watchtower_pubkeys: self.watchtower_pubkeys.clone(),
            admin_pubkey: self.admin_pubkey,
            wt_fault_pubkeys: self.watchtower_fault_pubkeys.clone(),
            payout_operator_descriptor: self.payout_desc.clone(),
            slash_watchtower_descriptors: self.slash_watchtower_descriptors.clone(),
        }
    }
}
