use bitcoin::{Amount, Network, Txid};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use strata_bridge_db::public::PublicDb;
use strata_bridge_primitives::{
    build_context::BuildContext,
    params::connectors::{
        NUM_PKS_A160, NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A256, NUM_PKS_A256_PER_CONNECTOR,
    },
    types::OperatorIdx,
    wots::{self, Groth16PublicKeys},
};
use tracing::{debug, info};

use crate::{
    connectors::prelude::*,
    errors::{TxGraphError, TxGraphResult},
    transactions::prelude::*,
};

/// The input data required to generate a peg-out graph.
///
/// This data is shared between various operators and verifiers and is used to construct the peg out
/// graph deterministically. This assumes that the WOTS public keys have already been shared.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegOutGraphInput {
    /// The bitcoin network on which the peg-out graph is being constructed.
    pub network: Network,

    /// The deposit amount for the peg-out graph.
    ///
    /// This is kept as an input instead of a constant to allow for flexibility in the future.
    pub deposit_amount: Amount,

    /// The public key of the operator.
    pub operator_pubkey: XOnlyPublicKey,

    /// The data required to construct the kickoff transaction.
    ///
    /// This data is generated uniquely by each operator and shared with others.
    pub kickoff_data: KickoffTxData,
}

/// A container for the transactions in the peg-out graph.
///
/// Each transaction is a wrapper around [`bitcoin::Psbt`] and some auxillary data required to
/// construct the fully signed transaction provided a signature.
#[derive(Debug, Clone)]
pub struct PegOutGraph {
    pub kickoff_tx: KickOffTx,

    pub claim_tx: ClaimTx,

    pub assert_chain: AssertChain,

    pub payout_tx: PayoutTx,

    pub disprove_tx: DisproveTx,
}

impl PegOutGraph {
    /// Generate the peg-out graph for a given operator.
    ///
    /// Each graph can be generated deterministically provided that the WOTS public keys are
    /// available for the operator for the given deposit transaction, and the input data is
    /// available.
    pub async fn generate<Db, DbRef, Context>(
        input: PegOutGraphInput,
        public_db: DbRef,
        context: &Context,
        deposit_txid: Txid,
        operator_idx: OperatorIdx,
    ) -> TxGraphResult<(Self, PegOutGraphConnectors)>
    where
        Db: PublicDb,
        DbRef: AsRef<Db>,
        Context: BuildContext,
    {
        let wots_public_keys = public_db
            .as_ref()
            .get_wots_public_keys(operator_idx, deposit_txid)
            .await?
            .ok_or(TxGraphError::MissingWotsPublicKeys(
                operator_idx,
                deposit_txid,
            ))?;

        let connectors = PegOutGraphConnectors::new(context, wots_public_keys);

        let kickoff_tx = KickOffTx::new(input.kickoff_data, connectors.kickoff)?;
        let kickoff_txid = kickoff_tx.compute_txid();
        debug!(event = "created kickoff tx", %operator_idx, %kickoff_txid);

        let claim_data = ClaimData {
            kickoff_txid,
            deposit_txid,
        };

        let claim_tx = ClaimTx::new(
            claim_data,
            connectors.kickoff,
            connectors.claim_out_0,
            connectors.claim_out_1,
        );
        let claim_txid = claim_tx.compute_txid();
        debug!(event = "created claim tx", %operator_idx, %claim_txid);

        info!(action = "registering claim txid for bitcoin watcher", %claim_txid, own_index = %operator_idx);

        let assert_chain_data = AssertChainData {
            pre_assert_data: PreAssertData {
                claim_txid,
                input_stake: claim_tx.remaining_stake(),
            },
            deposit_txid,
        };

        let assert_chain = AssertChain::new(
            assert_chain_data,
            operator_idx,
            connectors.claim_out_0,
            connectors.stake,
            connectors.post_assert_out_0,
            connectors.post_assert_out_1,
            connectors.assert_data160_factory,
            connectors.assert_data256_factory,
        );

        let post_assert_txid = assert_chain.post_assert.compute_txid();
        let post_assert_out_stake = assert_chain.post_assert.remaining_stake();

        debug!(event = "created assert chain", %operator_idx, %post_assert_txid);

        let payout_data = PayoutData {
            post_assert_txid,
            deposit_txid,
            input_stake: post_assert_out_stake,
            deposit_amount: input.deposit_amount,
            operator_key: input.operator_pubkey,
            network: input.network,
        };

        let payout_tx = PayoutTx::new(payout_data, connectors.post_assert_out_0, connectors.stake);
        let payout_txid = payout_tx.compute_txid();
        debug!(event = "created payout tx", %operator_idx, %payout_txid);

        let disprove_data = DisproveData {
            post_assert_txid,
            deposit_txid,
            input_stake: post_assert_out_stake,
            network: input.network,
        };

        let disprove_tx = DisproveTx::new(
            disprove_data,
            connectors.post_assert_out_0,
            connectors.post_assert_out_1,
        );
        let disprove_txid = disprove_tx.compute_txid();
        debug!(event = "created disprove tx", %operator_idx, %disprove_txid);

        Ok((
            Self {
                kickoff_tx,
                claim_tx,
                assert_chain,
                payout_tx,
                disprove_tx,
            },
            connectors,
        ))
    }
}

/// Connectors represent UTXOs in the peg-out graph.
///
/// These UTXOs have specific spending conditions to emulate covenants.
#[derive(Debug, Clone, Copy)]
pub struct PegOutGraphConnectors {
    pub kickoff: ConnectorK,

    pub claim_out_0: ConnectorC0,

    pub claim_out_1: ConnectorC1,

    pub stake: ConnectorS,

    pub post_assert_out_0: ConnectorA30,

    pub post_assert_out_1: ConnectorA31,

    pub assert_data160_factory: ConnectorA160Factory<NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A160>,

    pub assert_data256_factory: ConnectorA256Factory<NUM_PKS_A256_PER_CONNECTOR, NUM_PKS_A256>,
}

impl PegOutGraphConnectors {
    /// Create a new set of connectors for the peg-out graph.
    pub(crate) fn new(
        build_context: &impl BuildContext,
        wots_public_keys: wots::PublicKeys,
    ) -> Self {
        let n_of_n_agg_pubkey = build_context.aggregated_pubkey();
        let network = build_context.network();

        let kickoff = ConnectorK::new(n_of_n_agg_pubkey, network, wots_public_keys);

        let claim_out_0 = ConnectorC0::new(n_of_n_agg_pubkey, network);

        let claim_out_1 = ConnectorC1::new(n_of_n_agg_pubkey, network);

        let stake = ConnectorS::new(n_of_n_agg_pubkey, network);

        let post_assert_out_0 = ConnectorA30::new(n_of_n_agg_pubkey, network);
        let post_assert_out_1 = ConnectorA31::new(network, wots_public_keys);

        let wots::PublicKeys {
            bridge_out_txid: _,
            superblock_hash: superblock_hash_public_key,
            superblock_period_start_ts: _,
            groth16:
                Groth16PublicKeys(([public_inputs_hash_public_key], public_keys_256, public_keys_160)),
        } = wots_public_keys;
        let assert_data160_factory: ConnectorA160Factory<NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A160> =
            ConnectorA160Factory {
                network,
                public_keys: public_keys_160,
            };

        let public_keys_256 = std::array::from_fn(|i| match i {
            0 => superblock_hash_public_key.0,
            1 => public_inputs_hash_public_key,
            _ => public_keys_256[i - 2],
        });

        let assert_data256_factory: ConnectorA256Factory<NUM_PKS_A256_PER_CONNECTOR, NUM_PKS_A256> =
            ConnectorA256Factory {
                network,
                public_keys: public_keys_256,
            };

        Self {
            kickoff,
            claim_out_0,
            claim_out_1,
            stake,
            post_assert_out_0,
            post_assert_out_1,
            assert_data160_factory,
            assert_data256_factory,
        }
    }
}
