use std::sync::Arc;

use bitcoin::{Amount, Network, Txid};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use strata_bridge_db::public::PublicDb;
use strata_bridge_primitives::{
    build_context::BuildContext,
    params::connectors::{
        NUM_PKS_A160, NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A256, NUM_PKS_A256_PER_CONNECTOR,
    },
    scripts::wots::{self, Groth16PublicKeys},
    types::OperatorIdx,
};
use tracing::{debug, info};

use crate::{connectors::prelude::*, transactions::prelude::*};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegOutGraphInput {
    pub network: Network,

    pub deposit_amount: Amount,

    pub operator_pubkey: XOnlyPublicKey,

    pub kickoff_data: KickoffTxData,
}

#[derive(Debug, Clone)]
pub struct PegOutGraph {
    pub kickoff_tx: KickOffTx,

    pub claim_tx: ClaimTx,

    pub assert_chain: AssertChain,

    pub payout_tx: PayoutTx,

    pub disprove_tx: DisproveTx,
}

impl PegOutGraph {
    pub async fn generate<Db: PublicDb + Clone>(
        input: PegOutGraphInput,
        deposit_txid: Txid,
        connectors: PegOutGraphConnectors<Db>,
        operator_idx: OperatorIdx,
        db: Arc<Db>,
    ) -> Self {
        let kickoff_tx = KickOffTx::new(input.kickoff_data, connectors.kickoff.clone()).await;
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
        )
        .await;
        let claim_txid = claim_tx.compute_txid();
        debug!(event = "created claim tx", %operator_idx, %claim_txid);

        info!(action = "registering claim txid for bitcoin watcher", %claim_txid, own_index = %operator_idx);
        db.register_claim_txid(claim_txid, operator_idx, deposit_txid)
            .await
            .unwrap(); // FIXME: Handle me

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
            connectors.post_assert_out_0.clone(),
            connectors.post_assert_out_1.clone(),
            connectors.assert_data160_factory,
            connectors.assert_data256_factory,
        )
        .await;

        info!(action = "registering pre-assert txid for bitcoin watcher", %claim_txid, own_index = %operator_idx);
        db.register_pre_assert_txid(
            assert_chain.pre_assert.compute_txid(),
            operator_idx,
            deposit_txid,
        )
        .await
        .unwrap(); // FIXME: Handle me

        info!(action = "registering assert data txids for bitcoin watcher", %claim_txid, own_index = %operator_idx);
        let assert_data_txids = assert_chain.assert_data.compute_txids();
        db.register_assert_data_txids(assert_data_txids, operator_idx, deposit_txid)
            .await
            .unwrap(); // FIXME: Handle me

        let post_assert_txid = assert_chain.post_assert.compute_txid();
        let post_assert_out_stake = assert_chain.post_assert.remaining_stake();

        debug!(event = "created assert chain", %operator_idx, %post_assert_txid);

        info!(action = "registering post assert txid for bitcoin watcher", %post_assert_txid, own_index = %operator_idx);
        db.register_post_assert_txid(post_assert_txid, operator_idx, deposit_txid)
            .await
            .unwrap(); // FIXME: Handle me

        let payout_data = PayoutData {
            post_assert_txid,
            deposit_txid,
            input_stake: post_assert_out_stake,
            deposit_amount: input.deposit_amount,
            operator_key: input.operator_pubkey,
            network: input.network,
        };

        let payout_tx = PayoutTx::new(
            payout_data,
            connectors.post_assert_out_0.clone(),
            connectors.stake,
        );
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
            operator_idx,
            connectors.post_assert_out_0,
            connectors.post_assert_out_1,
        )
        .await;
        let disprove_txid = disprove_tx.compute_txid();
        debug!(event = "created disprove tx", %operator_idx, %disprove_txid);

        Self {
            kickoff_tx,
            claim_tx,
            assert_chain,
            payout_tx,
            disprove_tx,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PegOutGraphConnectors<Db: PublicDb> {
    pub kickoff: ConnectorK<Db>,

    pub claim_out_0: ConnectorC0,

    pub claim_out_1: ConnectorC1,

    pub stake: ConnectorS,

    pub post_assert_out_0: ConnectorA30<Db>,

    pub post_assert_out_1: ConnectorA31<Db>,

    pub assert_data160_factory: ConnectorA160Factory<NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A160>,

    pub assert_data256_factory: ConnectorA256Factory<NUM_PKS_A256_PER_CONNECTOR, NUM_PKS_A256>,
}

impl<Db: PublicDb> PegOutGraphConnectors<Db> {
    pub async fn new(
        db: Arc<Db>,
        build_context: &impl BuildContext,
        deposit_txid: Txid,
        operator_idx: OperatorIdx,
    ) -> Self {
        let n_of_n_agg_pubkey = build_context.aggregated_pubkey();
        let network = build_context.network();

        let kickoff = ConnectorK::new(n_of_n_agg_pubkey, network, operator_idx, db.clone());

        let claim_out_0 = ConnectorC0::new(n_of_n_agg_pubkey, network);

        let claim_out_1 = ConnectorC1::new(n_of_n_agg_pubkey, network);

        let stake = ConnectorS::new(n_of_n_agg_pubkey, network);

        let post_assert_out_0 = ConnectorA30::new(n_of_n_agg_pubkey, network, db.clone());
        let post_assert_out_1 = ConnectorA31::new(network, db.clone());

        let wots::PublicKeys {
            bridge_out_txid: _,
            superblock_hash: superblock_hash_public_key,
            superblock_period_start_ts: _,
            groth16:
                Groth16PublicKeys(([public_inputs_hash_public_key], public_keys_256, public_keys_160)),
        } = db
            .get_wots_public_keys(operator_idx, deposit_txid)
            .await
            .unwrap(); // FIXME:  Handle me
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
