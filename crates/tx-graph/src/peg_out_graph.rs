//! This module constructs the peg-out graph which is a series of transactions that allow for the
//! withdrawal of funds from the bridge address given a valid claim.

use alpen_bridge_params::{connectors::*, prelude::StakeChainParams, tx_graph::PegOutGraphParams};
use bitcoin::{hashes::sha256, relative, OutPoint, TxIn, Txid};
use secp256k1::{Message, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use strata_bridge_connectors::prelude::*;
use strata_bridge_primitives::{
    build_context::BuildContext,
    constants::*,
    scripts::taproot::TaprootWitness,
    wots::{self, Groth16PublicKeys},
};
use tracing::debug;

use crate::{
    pog_musig_functor::PogMusigF,
    transactions::{
        payout_optimistic::{PayoutOptimisticData, PayoutOptimisticTx},
        prelude::*,
        slash_stake::{SlashStakeData, SlashStakeTx},
    },
};

/// The input data required to generate a peg-out graph.
///
/// This data is shared between various operators and verifiers and is used to construct the peg out
/// graph deterministically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegOutGraphInput {
    /// The [`OutPoint`] of the stake transaction
    pub stake_outpoint: OutPoint,

    /// The [`OutPoint`] of the stake transaction used to commit to the withdrawal fulfillment
    /// txid.
    pub withdrawal_fulfillment_outpoint: OutPoint,

    /// The hash for the hashlock used in the Stake Transaction.
    pub stake_hash: sha256::Hash,

    /// The WOTS public keys used to verify commitments to the withdrawal fulfillment txid and the
    /// Groth16 proof.
    pub wots_public_keys: strata_p2p_types::WotsPublicKeys,

    /// The public key of the operator.
    ///
    /// This key is used for CPFP outputs and for receiving reimbursements.
    // TODO: Make this a [`descriptor`](bitcoin_bosd::Descriptor).
    pub operator_pubkey: XOnlyPublicKey,
}
/// The minimum necessary information to recognize all of the relevant transactions in a given
/// [`PegOutGraph`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegOutGraphSummary {
    /// Txid of the stake transaction that this graph is associated with.
    pub stake_txid: Txid,

    /// Txid of [`PegOutGraph::claim_tx`]
    pub claim_txid: Txid,

    /// Txid of [`PegOutGraph::payout_optimistic`]
    pub payout_optimistic_txid: Txid,

    /// Txid of [`AssertChain::pre_assert`] contained in [`PegOutGraph::assert_chain`]
    pub pre_assert_txid: Txid,

    /// Txids of [`AssertChain::assert_data`] contained in [`PegOutGraph::assert_chain`]
    #[serde(serialize_with = "serialize_assert_vector")]
    #[serde(deserialize_with = "deserialize_assert_vector")]
    pub assert_data_txids: [Txid; NUM_ASSERT_DATA_TX],

    /// Txid of [`AssertChain::post_assert`] contained in [`PegOutGraph::assert_chain`]
    pub post_assert_txid: Txid,

    /// Txid of [`PegOutGraph::payout_tx`]
    pub payout_txid: Txid,

    /// Txids of the [`PegOutGraph::slash_stake_txs`].
    pub slash_stake_txids: Vec<Txid>,
}

/// A container for the transactions in the peg-out graph.
///
/// Each transaction is a wrapper around [`bitcoin::Psbt`] and some auxiliary data required to
/// construct the fully signed transaction provided a signature.
#[derive(Debug, Clone)]
pub struct PegOutGraph {
    /// The claim transaction that commits to a valid withdrawal fulfillment txid.
    pub claim_tx: ClaimTx,

    /// The transaction used to challenge an operator's claim.
    pub challenge_tx: ChallengeTx,

    /// The transaction used to reimburse operators when no challenge occurs.
    pub payout_optimistic: PayoutOptimisticTx,

    /// The assert chain that commits to the proof of a valid claim.
    pub assert_chain: AssertChain,

    /// The payout transaction that reimburses the operator.
    pub payout_tx: PayoutTx,

    /// The disprove transaction that invalidates a claim and slashes the operator's stake.
    pub disprove_tx: DisproveTx,

    /// The slash stake transactions that slash the operator's stake upon faulty advancement of
    /// the stake chain.
    ///
    /// This is a vector of transactions since the number of these transactions can vary depending
    /// upon the consensus params for the bridge and the current deposit index. In general, the
    /// number of slash stake transactions should be `min(deposit_index,
    /// stake_chain_params.slash_stake_count)` (assuming that the deposit index is zero-indexed).
    pub slash_stake_txs: Vec<SlashStakeTx>,
}

impl PegOutGraph {
    /// Generate the peg-out graph for a given operator.
    ///
    /// Each graph can be generated deterministically provided that the WOTS public keys
    /// for the operator for the given deposit transaction, and the input data are
    /// available.
    ///
    /// # Parameters
    ///
    /// * `input` - The input data required to construct the peg-out graph deterministically that
    ///   are made available by an operator during a deposit.
    /// * `context` - The build context that contains the information related to the MuSig2 context.
    /// * `deposit_txid` - The transaction ID of the deposit transaction.
    /// * `graph_params` - The consensus-critical parameters required to construct the peg-out
    ///   graph.
    /// * `stake_chain_params` - The consensus-critical parameters required to construct the stake
    ///   chain.
    /// * `prev_claim_txids` - The transaction IDs of the previous claim transactions that can be
    ///   used to slash the operator's stake in case of a faulty advancement of the stake chain
    ///   i.e., if the operator advances the stake chain without fully executing the previous
    ///   claims. In general, the number of these transactions should be `min(deposit_index,
    ///   slash_stake_count)` (assuming that the deposit index is zero-indexed). As an optimization,
    ///   only claim txids corresponding to unclaimed deposits need to be specified.
    pub fn generate(
        input: PegOutGraphInput,
        context: &impl BuildContext,
        deposit_txid: Txid,
        graph_params: PegOutGraphParams,
        connector_params: ConnectorParams,
        stake_chain_params: StakeChainParams,
        prev_claim_txids: Vec<Txid>,
    ) -> (Self, PegOutGraphConnectors) {
        let connectors = PegOutGraphConnectors::new(
            context,
            deposit_txid,
            connector_params,
            input.operator_pubkey,
            input.stake_hash,
            stake_chain_params.delta,
            input.wots_public_keys,
        );

        let claim_data = ClaimData {
            stake_outpoint: input.withdrawal_fulfillment_outpoint,
            input_amount: FUNDING_AMOUNT,
            deposit_txid,
        };

        let claim_tx = ClaimTx::new(
            claim_data,
            connectors.kickoff,
            connectors.claim_out_0,
            connectors.claim_out_1,
            connectors.n_of_n,
            connectors.connector_cpfp,
        );
        let claim_txid = claim_tx.compute_txid();
        debug!(event = "created claim tx", %claim_txid);

        let challenge_input = ChallengeTxInput {
            claim_outpoint: OutPoint::new(claim_txid, 1),
            challenge_amt: graph_params.challenge_cost,
            operator_pubkey: input.operator_pubkey,
            network: context.network(),
        };
        let challenge_tx = ChallengeTx::new(challenge_input, connectors.claim_out_1);

        let payout_optimistic_data = PayoutOptimisticData {
            claim_txid,
            deposit_txid,
            stake_outpoint: OutPoint {
                txid: input.stake_outpoint.txid,
                vout: 1,
            },
            input_amount: claim_tx.output_amount(),
            deposit_amount: graph_params.deposit_amount,
            operator_key: input.operator_pubkey,
            network: context.network(),
        };

        let payout_optimistic = PayoutOptimisticTx::new(
            payout_optimistic_data,
            connectors.claim_out_0,
            connectors.claim_out_1,
            connectors.n_of_n,
            connectors.hashlock_payout,
            connectors.connector_cpfp,
        );

        let assert_chain_data = AssertChainData {
            pre_assert_data: PreAssertData {
                claim_txid,
                input_amount: claim_tx.output_amount(),
            },
            deposit_txid,
        };

        let assert_chain = AssertChain::new(
            assert_chain_data,
            connectors.claim_out_0,
            connectors.n_of_n,
            connectors.post_assert_out_0,
            connectors.connector_cpfp,
            connectors.assert_data_hash_factory,
            connectors.assert_data256_factory,
        );

        let post_assert_txid = assert_chain.post_assert.compute_txid();
        let post_assert_out_amt = assert_chain.post_assert.output_amount();

        debug!(event = "created assert chain", %post_assert_txid);

        let payout_data = PayoutData {
            post_assert_txid,
            deposit_txid,
            stake_outpoint: OutPoint {
                txid: input.stake_outpoint.txid,
                vout: 1,
            },
            claim_outpoint: OutPoint {
                txid: claim_txid,
                vout: claim_tx.slash_stake_vout(),
            },
            input_amount: post_assert_out_amt,
            deposit_amount: graph_params.deposit_amount,
            operator_key: input.operator_pubkey,
            network: context.network(),
        };

        let payout_tx = PayoutTx::new(
            payout_data,
            connectors.post_assert_out_0,
            connectors.n_of_n,
            connectors.hashlock_payout,
            connectors.connector_cpfp,
        );
        let payout_txid = payout_tx.compute_txid();
        debug!(event = "created payout tx", %payout_txid);

        let disprove_data = DisproveData {
            post_assert_txid,
            deposit_txid,
            input_amount: post_assert_out_amt,
            stake_outpoint: input.stake_outpoint,
            network: context.network(),
        };

        let disprove_tx = DisproveTx::new(
            disprove_data,
            stake_chain_params,
            connectors.post_assert_out_0,
            connectors.stake,
        );
        let disprove_txid = disprove_tx.compute_txid();
        debug!(event = "created disprove tx", %disprove_txid);

        let slash_stake_txs = prev_claim_txids
            .iter()
            .map(|claim_txid| SlashStakeData {
                stake_outpoint: input.stake_outpoint,
                network: context.network(),
                claim_outpoint: OutPoint {
                    txid: *claim_txid,
                    vout: claim_tx.slash_stake_vout(),
                },
            })
            .map(|stake_data| {
                SlashStakeTx::new(
                    stake_data,
                    stake_chain_params,
                    connectors.n_of_n,
                    connectors.stake,
                )
            })
            .collect();

        (
            Self {
                claim_tx,
                challenge_tx,
                payout_optimistic,
                assert_chain,
                payout_tx,
                disprove_tx,
                slash_stake_txs,
            },
            connectors,
        )
    }

    pub fn summarize(&self) -> PegOutGraphSummary {
        PegOutGraphSummary {
            stake_txid: self.claim_tx.psbt().unsigned_tx.input[0]
                .previous_output
                .txid,
            claim_txid: self.claim_tx.compute_txid(),
            payout_optimistic_txid: self.payout_optimistic.compute_txid(),
            pre_assert_txid: self.assert_chain.pre_assert.compute_txid(),
            assert_data_txids: self.assert_chain.assert_data.compute_txids(),
            post_assert_txid: self.assert_chain.post_assert.compute_txid(),
            payout_txid: self.payout_tx.compute_txid(),
            slash_stake_txids: self
                .slash_stake_txs
                .iter()
                .map(|tx| tx.compute_txid())
                .collect(),
        }
    }

    /// Generates the sighash messages.
    pub fn sighashes(&self) -> PogMusigF<Message> {
        let challenge = self.challenge_tx.sighashes()[0];

        let AssertChain {
            pre_assert,
            post_assert,
            ..
        } = &self.assert_chain;

        let pre_assert = pre_assert.sighashes()[0];

        let post_assert = post_assert.sighashes();

        let payout_optimistic = self.payout_optimistic.sighashes();

        let payout = self.payout_tx.sighashes();

        let disprove = self.disprove_tx.sighashes()[0];

        let slash_stake = self
            .slash_stake_txs
            .iter()
            .map(|slash_stake| slash_stake.sighashes())
            .collect();

        PogMusigF {
            challenge,
            pre_assert,
            post_assert,
            payout_optimistic,
            payout,
            disprove,
            slash_stake,
        }
    }

    pub fn musig_inputs(&self) -> PogMusigF<&TxIn> {
        PogMusigF {
            challenge: self.challenge_tx.psbt().unsigned_tx.input.first().unwrap(),
            pre_assert: self
                .assert_chain
                .pre_assert
                .psbt()
                .unsigned_tx
                .input
                .first()
                .unwrap(),
            post_assert: std::array::from_fn(|i| {
                self.assert_chain
                    .post_assert
                    .psbt()
                    .unsigned_tx
                    .input
                    .get(i)
                    .unwrap()
            }),
            payout_optimistic: std::array::from_fn(|i| {
                self.payout_optimistic
                    .psbt()
                    .unsigned_tx
                    .input
                    .get(i)
                    .unwrap()
            }),
            payout: std::array::from_fn(|i| {
                self.payout_tx.psbt().unsigned_tx.input.get(i).unwrap()
            }),
            disprove: self.disprove_tx.psbt().unsigned_tx.input.first().unwrap(),
            slash_stake: self
                .slash_stake_txs
                .iter()
                .map(|tx| {
                    let inputs = &tx.psbt().unsigned_tx.input;
                    [inputs.first().unwrap(), inputs.get(1).unwrap()]
                })
                .collect(),
        }
    }

    pub fn musig_witnesses(&self) -> PogMusigF<TaprootWitness> {
        PogMusigF {
            challenge: self.challenge_tx.witnesses()[0].clone(),
            pre_assert: self.assert_chain.pre_assert.witnesses()[0].clone(),
            post_assert: self.assert_chain.post_assert.witnesses().clone(),
            payout_optimistic: self.payout_optimistic.witnesses().clone(),
            payout: self.payout_tx.witnesses().clone(),
            disprove: self.disprove_tx.witnesses()[0].clone(),
            slash_stake: self
                .slash_stake_txs
                .iter()
                .map(|ss| ss.witnesses().clone())
                .collect(),
        }
    }
}

/// Connectors represent UTXOs in the peg-out graph.
///
/// These UTXOs have specific spending conditions to emulate covenants.
///
/// Note that this does not include the stake chain connectors as those are shared at setup time at
/// regular intervals and not during the peg-out graph generation.
#[derive(Debug, Clone, Copy)]
pub struct PegOutGraphConnectors {
    /// The first output of the stake transaction that kicks off the peg out graph.
    pub kickoff: ConnectorK,

    /// The first output of the claim tx.
    pub claim_out_0: ConnectorC0,

    /// The second output of the claim tx.
    pub claim_out_1: ConnectorC1,

    /// The connector that locks funds in an N-of-N keyspend path.
    pub n_of_n: ConnectorNOfN,

    /// The connector for the CPFP output.
    pub connector_cpfp: ConnectorCpfp,

    /// The first output of the post-assert tx used to get the stake.
    pub post_assert_out_0: ConnectorA3,

    /// The factory for the assertion data connectors for hashes.
    pub assert_data_hash_factory: ConnectorAHashFactory<
        NUM_HASH_CONNECTORS_BATCH_1,
        NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1,
        NUM_HASH_CONNECTORS_BATCH_2,
        NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2,
    >,

    /// The factory for the 256-bit assertion data connectors.
    pub assert_data256_factory: ConnectorA256Factory<
        NUM_FIELD_CONNECTORS_BATCH_1,
        NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1,
        NUM_FIELD_CONNECTORS_BATCH_2,
        NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2,
    >,

    pub stake: ConnectorStake,

    pub hashlock_payout: ConnectorP,
}

impl PegOutGraphConnectors {
    /// Create a new set of connectors for the peg-out graph.
    ///
    /// Note that the operator public key is used for the CPFP connector for fee bumping.
    pub(crate) fn new(
        build_context: &impl BuildContext,
        deposit_txid: Txid,
        params: ConnectorParams,
        operator_pubkey: XOnlyPublicKey,
        stake_hash: sha256::Hash,
        delta: relative::LockTime,
        wots_public_keys: strata_p2p_types::WotsPublicKeys,
    ) -> Self {
        let n_of_n_agg_pubkey = build_context.aggregated_pubkey();
        let network = build_context.network();
        let wots_public_keys: wots::PublicKeys = wots_public_keys.try_into().expect(
            "wots keys from strata-p2p must be compatible with those in the bridge primitives",
        );

        let kickoff = ConnectorK::new(
            n_of_n_agg_pubkey,
            network,
            wots_public_keys.withdrawal_fulfillment,
        );

        let claim_out_0 = ConnectorC0::new(n_of_n_agg_pubkey, network, params.pre_assert_timelock);

        let claim_out_1 = ConnectorC1::new(
            n_of_n_agg_pubkey,
            network,
            params.payout_optimistic_timelock,
        );

        let n_of_n = ConnectorNOfN::new(n_of_n_agg_pubkey, network);

        let connector_cpfp = ConnectorCpfp::new(operator_pubkey, network);
        let post_assert_out_1 = ConnectorA3::new(
            network,
            deposit_txid,
            n_of_n_agg_pubkey,
            wots_public_keys,
            params.payout_timelock,
        );

        let wots::PublicKeys {
            withdrawal_fulfillment: _,
            groth16:
                Groth16PublicKeys(([public_inputs_hash_public_key], public_keys_256, public_keys_hash)),
        } = wots_public_keys;

        let assert_data_hash_factory = ConnectorAHashFactory {
            network,
            public_keys: public_keys_hash,
        };

        let public_keys_256 = std::array::from_fn(|i| match i {
            0 => public_inputs_hash_public_key,
            _ => public_keys_256[i - 1],
        });

        let assert_data256_factory = ConnectorA256Factory {
            network,
            public_keys: public_keys_256,
        };

        let stake = ConnectorStake::new(
            n_of_n_agg_pubkey,
            operator_pubkey,
            stake_hash,
            delta,
            network,
        );

        let hashlock_payout = ConnectorP::new(n_of_n_agg_pubkey, stake_hash, network);

        Self {
            kickoff,
            claim_out_0,
            claim_out_1,
            n_of_n,
            connector_cpfp,
            post_assert_out_0: post_assert_out_1,
            assert_data_hash_factory,
            assert_data256_factory,

            // stake chain connectors
            stake,
            hashlock_payout,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashSet},
        fs,
        str::FromStr,
    };

    use alpen_bridge_params::prelude::StakeChainParams;
    use bitcoin::{
        consensus,
        hashes::{self, Hash},
        key::TapTweak,
        policy::MAX_STANDARD_TX_WEIGHT,
        sighash::{Prevouts, SighashCache},
        taproot, transaction, Address, Amount, FeeRate, Network, OutPoint, TapSighashType,
        Transaction, TxOut,
    };
    use bitcoind_async_client::types::GetTxOut;
    use bitvm::signatures::wots_api::HASH_LEN;
    use corepc_node::{serde_json::json, Client, Conf, Node};
    use rkyv::rancor::Error;
    use secp256k1::{
        rand::{rngs::OsRng, Rng},
        Keypair, SECP256K1,
    };
    use strata_bridge_common::logging;
    use strata_bridge_db::{inmemory::public::PublicDbInMemory, public::PublicDb};
    use strata_bridge_primitives::{
        build_context::TxBuildContext,
        constants::*,
        scripts::taproot::{create_message_hash, TaprootWitness},
        wots::{Assertions, Wots256Signature},
    };
    use strata_bridge_stake_chain::{
        prelude::{StakeTx, OPERATOR_FUNDS, STAKE_VOUT, WITHDRAWAL_FULFILLMENT_VOUT},
        transactions::stake::StakeTxData,
    };
    use strata_bridge_test_utils::{
        bitcoin_rpc::fund_and_sign_raw_tx,
        musig2::generate_agg_signature,
        prelude::{
            find_funding_utxo, generate_keypair, generate_txid, sign_cpfp_child, wait_for_blocks,
        },
        tx::get_mock_deposit,
    };
    use tracing::{info, warn};

    use super::*;
    use crate::transactions::challenge::{ChallengeTx, ChallengeTxInput};

    const DEPOSIT_AMOUNT: Amount = Amount::from_int_btc(10);
    const MSK: &str = "test_msk";
    const FEE_RATE: FeeRate = FeeRate::from_sat_per_kwu(5000);
    const CHALLENGE_COST: Amount = Amount::from_int_btc(1);
    const DISPROVER_REWARD: Amount = Amount::from_int_btc(1);
    const OPERATOR_STAKE: Amount = Amount::from_int_btc(3);
    const SLASH_STAKE_REWARD: Amount = Amount::from_sat(199_999_000); // 2 BTC - 1000 sats

    #[test]
    fn test_assert_vector_roundtrip_serialization() {
        // Create test data
        #[derive(Serialize, Deserialize)]
        struct Container {
            #[serde(serialize_with = "serialize_assert_vector")]
            #[serde(deserialize_with = "deserialize_assert_vector")]
            assert_vector: [i32; NUM_ASSERT_DATA_TX],
        }
        let assert_vector: [i32; NUM_ASSERT_DATA_TX] = std::array::from_fn(|i| i as i32);

        // Serialize to string
        let serialized =
            serde_json::to_string(&Container { assert_vector }).expect("Failed to serialize");

        // Deserialize back to array
        let deserialized: Container =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Compare
        assert_eq!(assert_vector, deserialized.assert_vector);
    }

    #[tokio::test]
    async fn test_payout_optimistic() {
        let SetupOutput {
            bitcoind,
            n_of_n_keypair,
            context,
            deposit_txid,
            public_db,
        } = setup().await;

        let btc_client = &bitcoind.client;
        let operator_idx = 0;
        let wots_public_keys = public_db
            .get_wots_public_keys(operator_idx, deposit_txid)
            .await
            .expect("must be able to get wots public keys")
            .expect("must have wots public keys");

        let btc_addr = btc_client.new_address().expect("must generate new address");
        let operator_pubkey = n_of_n_keypair.x_only_public_key().0;

        let (input, _, _) =
            create_tx_graph_input(btc_client, &context, n_of_n_keypair, wots_public_keys);
        let stake_chain_params = StakeChainParams::default();
        let graph_params = PegOutGraphParams {
            deposit_amount: DEPOSIT_AMOUNT,
            ..Default::default()
        };
        let connector_params = ConnectorParams {
            payout_optimistic_timelock: 10,
            pre_assert_timelock: 11,
            payout_timelock: 10,
        };

        let prev_claim_txids = vec![generate_txid(); stake_chain_params.slash_stake_count];
        let (graph, connectors) = PegOutGraph::generate(
            input,
            &context,
            deposit_txid,
            graph_params,
            connector_params,
            stake_chain_params,
            prev_claim_txids,
        );

        let PegOutGraph {
            claim_tx,
            payout_optimistic,
            ..
        } = graph;

        let PegOutGraphConnectors {
            kickoff,
            claim_out_0,
            claim_out_1,
            n_of_n: claim_out_2,
            hashlock_payout,
            connector_cpfp,
            ..
        } = connectors;

        let withdrawal_fulfillment_txid = generate_txid();

        let claim_input_amount = claim_tx.input_amount();
        let claim_cpfp_vout = claim_tx.cpfp_vout();

        let claim_sig = Wots256Signature::new(
            MSK,
            deposit_txid,
            withdrawal_fulfillment_txid.as_byte_array(),
        );
        let signed_claim_tx = claim_tx.finalize(*claim_sig, kickoff);
        info!(
            vsize = signed_claim_tx.vsize(),
            action = "broadcasting claim tx",
        );

        let claim_child_tx = create_cpfp_child(
            btc_client,
            &n_of_n_keypair,
            connector_cpfp,
            &signed_claim_tx,
            claim_input_amount,
            claim_cpfp_vout,
        );

        let result = btc_client
            .submit_package(&[signed_claim_tx, claim_child_tx], None, None)
            .expect("must be able to send claim tx");

        assert_eq!(
            result.package_msg, "success",
            "must have successful package submission but got: {:?}",
            result
        );
        assert_eq!(
            result.tx_results.len(),
            2,
            "must have two transactions in package"
        );

        btc_client
            .generate_to_address(6, &btc_addr)
            .expect("must be able to mine blocks");

        let witnesses = payout_optimistic.witnesses();

        let mut signatures = witnesses
            .iter()
            .zip(payout_optimistic.sighashes())
            .map(|(witness, sighash)| generate_agg_signature(&sighash, &n_of_n_keypair, witness));

        assert_eq!(
            signatures.len(),
            payout_optimistic.psbt().inputs.len(),
            "must have signatures for all inputs"
        );

        let deposit_signature = signatures.next().expect("must have deposit signature");
        let n_of_n_sig_c0 = signatures
            .next()
            .expect("must have n-of-n signature for c0");
        let n_of_n_sig_c1 = signatures
            .next()
            .expect("must have n-of-n signature for c1");
        let n_of_n_sig_c2 = signatures
            .next()
            .expect("must have n-of-n signature for c2");
        let n_of_n_sig_p = signatures.next().expect("must have n-of-n signature for p");

        let payout_input_amount = payout_optimistic.input_amount();
        let payout_cpfp_vout = payout_optimistic.cpfp_vout();

        let signed_payout_tx = payout_optimistic.finalize(
            deposit_signature,
            n_of_n_sig_c0,
            n_of_n_sig_c1,
            n_of_n_sig_c2,
            n_of_n_sig_p,
            claim_out_0,
            claim_out_1,
            claim_out_2,
            hashlock_payout,
        );
        let payout_amount = signed_payout_tx.output[0].value;
        let payout_txid = signed_payout_tx.compute_txid().to_string();

        let connector_cpfp = ConnectorCpfp::new(operator_pubkey, context.network());
        let signed_payout_cpfp_child = create_cpfp_child(
            btc_client,
            &n_of_n_keypair,
            connector_cpfp,
            &signed_payout_tx,
            payout_input_amount,
            payout_cpfp_vout,
        );

        info!(
            txid = payout_txid,
            "trying to submit payout before timelock"
        );
        let result = btc_client
            .submit_package(
                &[signed_payout_tx.clone(), signed_payout_cpfp_child.clone()],
                None,
                None,
            )
            .expect("must be able to submit package");

        assert_ne!(
            result.package_msg, "success",
            "submit package message must not be success"
        );
        info!(
            txid = payout_txid,
            "could not submit payout before timelock"
        );

        let n_blocks = connector_params.payout_optimistic_timelock as usize + 1;
        info!(%n_blocks, "waiting for blocks");

        wait_for_blocks(btc_client, n_blocks);

        info!(txid = payout_txid, "trying to submit payout after timelock");
        let result = btc_client
            .submit_package(&[signed_payout_tx, signed_payout_cpfp_child], None, None)
            .expect("must be able to send payout package");

        assert_eq!(
            result.package_msg, "success",
            "submit package message must be success but got: {:?}",
            result
        );
        assert_eq!(result.tx_results.len(), 2, "must have two tx results");

        let total_cpfp_amount = OPERATOR_STAKE + DEPOSIT_AMOUNT - payout_amount;
        let total_cpfp_amount = total_cpfp_amount.to_sat();
        info!(
            ?payout_amount,
            stake = OPERATOR_STAKE.to_sat(),
            deposit = DEPOSIT_AMOUNT.to_sat(),
            %total_cpfp_amount,
            "received_payout"
        );
    }

    #[tokio::test]
    async fn test_tx_graph_payout() {
        let SetupOutput {
            bitcoind,
            n_of_n_keypair,
            context,
            deposit_txid,
            public_db,
        } = setup().await;
        let operator_pubkey = n_of_n_keypair.x_only_public_key().0;
        let btc_client = &bitcoind.client;

        let wots_public_keys = public_db
            .get_wots_public_keys(0, deposit_txid)
            .await
            .expect("must be able to get wots public keys")
            .expect("must have wots public keys");

        let (input, _, _) =
            create_tx_graph_input(btc_client, &context, n_of_n_keypair, wots_public_keys);

        let graph_params = PegOutGraphParams {
            deposit_amount: DEPOSIT_AMOUNT,
            ..Default::default()
        };
        let connector_params = ConnectorParams {
            payout_optimistic_timelock: 11,
            pre_assert_timelock: 10,
            payout_timelock: 10,
        };
        let assertions = load_assertions();
        let SubmitAssertionsResult {
            payout_tx,
            post_assert_out_0,
            n_of_n: claim_out_2,
            hashlock_payout,
            ..
        } = submit_assertions(
            btc_client,
            &n_of_n_keypair,
            &context,
            deposit_txid,
            input,
            graph_params,
            connector_params,
            assertions,
        )
        .await;

        let witnesses = payout_tx.witnesses();

        let mut signatures = witnesses
            .iter()
            .zip(payout_tx.sighashes())
            .map(|(witness, sighash)| generate_agg_signature(&sighash, &n_of_n_keypair, witness));

        let deposit_signature = signatures.next().expect("must have deposit signature");
        let n_of_n_sig_a3 = signatures
            .next()
            .expect("must have n-of-n signature for post-assert prevout");
        let n_of_n_sig_c2 = signatures
            .next()
            .expect("must have n-of-n signature for c2");
        let n_of_n_sig_p = signatures
            .next()
            .expect("must have n-of-n signature for stake hashlock prevout");
        let payout_input_amount = payout_tx.input_amount();
        let payout_cpfp_vout = payout_tx.cpfp_vout();
        let signed_payout_tx = payout_tx.finalize(
            deposit_signature,
            n_of_n_sig_a3,
            n_of_n_sig_c2,
            n_of_n_sig_p,
            post_assert_out_0,
            claim_out_2,
            hashlock_payout,
        );
        let payout_amount = signed_payout_tx.output[0].value;
        let payout_txid = signed_payout_tx.compute_txid().to_string();

        let connector_cpfp = ConnectorCpfp::new(operator_pubkey, context.network());
        let signed_payout_cpfp_child = create_cpfp_child(
            btc_client,
            &n_of_n_keypair,
            connector_cpfp,
            &signed_payout_tx,
            payout_input_amount,
            payout_cpfp_vout,
        );

        info!(
            txid = payout_txid,
            "trying to submit payout before timelock"
        );
        let result = btc_client
            .submit_package(
                &[signed_payout_tx.clone(), signed_payout_cpfp_child.clone()],
                None,
                None,
            )
            .expect("must be able to submit package");
        assert_ne!(
            result.package_msg, "success",
            "submit package message must not be success"
        );
        info!(
            txid = payout_txid,
            "could not submit payout before timelock"
        );

        wait_for_blocks(btc_client, connector_params.payout_timelock as usize + 1);

        info!(txid = payout_txid, "trying to submit payout after timelock");
        let result = btc_client
            .submit_package(&[signed_payout_tx, signed_payout_cpfp_child], None, None)
            .expect("must be able to send payout package");

        assert_eq!(
            result.package_msg, "success",
            "submit package message must be success but got: {:?}",
            result
        );
        assert_eq!(result.tx_results.len(), 2, "must have two tx results");

        let total_cpfp_amount = OPERATOR_STAKE + DEPOSIT_AMOUNT - payout_amount;
        let total_cpfp_amount = total_cpfp_amount.to_sat();
        info!(
            ?payout_amount,
            stake = OPERATOR_STAKE.to_sat(),
            deposit = DEPOSIT_AMOUNT.to_sat(),
            %total_cpfp_amount,
            "received_payout"
        );
    }

    #[tokio::test]
    async fn test_tx_graph_disprove() {
        let SetupOutput {
            bitcoind,
            n_of_n_keypair,
            context,
            deposit_txid,
            public_db,
        } = setup().await;
        let btc_client = &bitcoind.client;

        let public_keys = public_db
            .get_wots_public_keys(0, deposit_txid)
            .await
            .expect("must be able to get wots public keys")
            .expect("must have wots public keys");

        let (input, _, _) =
            create_tx_graph_input(btc_client, &context, n_of_n_keypair, public_keys);
        let graph_params = PegOutGraphParams {
            deposit_amount: DEPOSIT_AMOUNT,
            ..Default::default()
        };
        let connector_params = ConnectorParams {
            payout_optimistic_timelock: 11,
            pre_assert_timelock: 10,
            payout_timelock: 10,
        };

        let mut faulty_assertions = load_assertions();
        for _ in 0..faulty_assertions.groth16.2.len() {
            let proof_index_to_tweak = OsRng.gen_range(0..faulty_assertions.groth16.2.len());
            warn!(action = "introducing faulty assertion", index=%proof_index_to_tweak);
            if faulty_assertions.groth16.2[proof_index_to_tweak] != [0u8; HASH_LEN as usize] {
                faulty_assertions.groth16.2[proof_index_to_tweak] = [0u8; HASH_LEN as usize];
                break;
            }
        }

        info!("submitting assertions");

        // HACK: this is ugly but fine for testing.
        let SubmitAssertionsResult {
            signed_claim_tx,
            signed_post_assert,
            post_assert_out_0,
            disprove_tx,
            stake,
            ..
        } = submit_assertions(
            btc_client,
            &n_of_n_keypair,
            &context,
            deposit_txid,
            input,
            graph_params,
            connector_params,
            faulty_assertions,
        )
        .await;

        let signed_assert_txs = signed_post_assert
            .input
            .iter()
            .map(|input| {
                let assert_txid = input.previous_output.txid;

                let assert_tx_raw = btc_client
                    .call::<String>("getrawtransaction", &[json!(assert_txid)])
                    .expect("must be able to get assert tx");

                consensus::encode::deserialize_hex::<Transaction>(&assert_tx_raw)
                    .expect("must be able to deserialize assert tx")
            })
            .collect::<Vec<_>>();

        info!("extracting assertion data from assert data transactions");
        let g16_proof = AssertDataTxBatch::parse_witnesses(
            &signed_assert_txs
                .try_into()
                .expect("the number of assert data txs must match"),
        )
        .expect("must be able to parse assert data txs")
        .expect("must have assertion witness");

        info!("extracting withdrawal fulfillment txid commitment from claim transaction");
        let sig_withdrawal_fulfillment_txid = ClaimTx::parse_witness(&signed_claim_tx)
            .expect("must be able to parse claim witness")
            .expect("must have claim witness");

        // TODO: find a way to get the groth16 disprove leaf without having to compile the actual
        // partial verification scripts (and vk).
        // For now the public inputs will always be wrong because the assertions are taken from a
        // static file in `test-data`.

        info!("constructing disprove leaf");
        let input_disprove_leaf = ConnectorA3Leaf::DisprovePublicInputsCommitment {
            deposit_txid,
            witness: Some(DisprovePublicInputsCommitmentWitness {
                sig_withdrawal_fulfillment_txid,
                sig_public_inputs_hash: g16_proof.0[0],
            }),
        };

        info!("finalizing disprove transaction");
        const INPUT_INDEX: usize = 0;

        let witness_type = &disprove_tx.witnesses()[INPUT_INDEX];
        assert!(
            matches!(witness_type, TaprootWitness::Tweaked { .. }),
            "witness on the first input must be tweaked"
        );

        let sighash_type = disprove_tx.psbt().inputs[INPUT_INDEX]
            .sighash_type
            .expect("sighash type must be set on the first index of the disprove tx")
            .taproot_hash_ty()
            .unwrap();
        assert_eq!(sighash_type, TapSighashType::Single);

        let disprove_msg = disprove_tx.sighashes()[INPUT_INDEX];
        let disprove_sig = generate_agg_signature(&disprove_msg, &n_of_n_keypair, witness_type);
        let disprove_sig = taproot::Signature {
            signature: disprove_sig,
            sighash_type,
        };

        let disprove_witness = StakeSpendPath::Disprove(disprove_sig);
        let btc_addr = btc_client.new_address().expect("must generate new address");
        let reward = TxOut {
            value: DISPROVER_REWARD,
            script_pubkey: btc_addr.script_pubkey(),
        };

        let signed_disprove_tx = disprove_tx.finalize(
            reward,
            disprove_witness,
            input_disprove_leaf,
            stake,
            post_assert_out_0,
        );

        info!(
            vsize = signed_disprove_tx.vsize(),
            reward = %DISPROVER_REWARD,
            "broadcasting disprove transaction"
        );
        btc_client
            .send_raw_transaction(&signed_disprove_tx)
            .expect("must be able to send disprove tx");
    }

    struct SetupOutput {
        bitcoind: Node,
        n_of_n_keypair: Keypair,
        context: TxBuildContext,
        deposit_txid: Txid,
        public_db: PublicDbInMemory,
    }

    async fn setup() -> SetupOutput {
        logging::init(logging::LoggerConfig::new("test-tx-graph".to_string()));

        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        conf.args.push("-acceptnonstdtxn=1");

        let bitcoind = Node::from_downloaded_with_conf(&conf).unwrap();
        let btc_client = &bitcoind.client;

        let network = btc_client
            .get_blockchain_info()
            .expect("must get blockchain info")
            .chain;
        let network = Network::from_str(&network).expect("network must be valid");

        let n_of_n_keypair = generate_keypair();
        let pubkey_table = BTreeMap::from([(0, n_of_n_keypair.public_key())]);
        let context = TxBuildContext::new(network, pubkey_table.into(), 0);

        let n_of_n_agg_pubkey = context.aggregated_pubkey();
        let bridge_address =
            ConnectorNOfN::new(n_of_n_agg_pubkey, network).create_taproot_address();

        let deposit_tx = get_mock_deposit(btc_client, DEPOSIT_AMOUNT, &bridge_address);
        let deposit_txid: Txid = deposit_tx.compute_txid();
        info!(?deposit_tx, %deposit_txid, %DEPOSIT_AMOUNT, "made a mock deposit");

        btc_client
            .call::<GetTxOut>("gettxout", &[json!(deposit_txid.to_string()), json!(0)])
            .expect("deposit txout must be present");

        let public_db = PublicDbInMemory::default();
        let wots_public_keys = wots::PublicKeys::new(MSK, deposit_txid);
        public_db
            .set_wots_public_keys(0, deposit_txid, &wots_public_keys)
            .await
            .expect("must be able to set wots public keys");

        SetupOutput {
            bitcoind,
            n_of_n_keypair,
            context,
            deposit_txid,
            public_db,
        }
    }

    fn create_tx_graph_input(
        btc_client: &Client,
        context: &TxBuildContext,
        operator_keypair: Keypair,
        wots_public_keys: wots::PublicKeys,
    ) -> (PegOutGraphInput, [u8; 32], Amount) {
        let operator_pubkey = operator_keypair.x_only_public_key().0;
        let wallet_addr = btc_client.new_address().expect("must generate new address");

        let stake_preimage: [u8; 32] = OsRng.gen();
        let stake_hash = hashes::sha256::Hash::hash(&stake_preimage);

        let stake_chain_params = StakeChainParams::default();

        let connector_cpfp = ConnectorCpfp::new(operator_pubkey, context.network());

        info!("creating transaction to fund dust outputs");
        let operator_address = Address::p2tr(SECP256K1, operator_pubkey, None, context.network());
        let result = btc_client
            .send_to_address(&operator_address, OPERATOR_FUNDS)
            .unwrap();
        btc_client.generate_to_address(1, &wallet_addr).unwrap();
        let operator_funds_tx = btc_client.get_transaction(result.txid().unwrap()).unwrap();
        let operator_funds_tx =
            consensus::encode::deserialize_hex::<Transaction>(&operator_funds_tx.hex).unwrap();
        let operator_funds = operator_funds_tx
            .output
            .iter()
            .enumerate()
            .find_map(|(i, o)| {
                if o.value == OPERATOR_FUNDS {
                    Some(OutPoint {
                        txid: operator_funds_tx.compute_txid(),
                        vout: i as u32,
                    })
                } else {
                    None
                }
            })
            .unwrap();

        info!("creating transaction for operator's stake");
        let result = btc_client
            .send_to_address(&operator_address, OPERATOR_STAKE)
            .unwrap();
        btc_client.generate_to_address(1, &wallet_addr).unwrap();
        let operator_stake_tx = btc_client.get_transaction(result.txid().unwrap()).unwrap();
        let operator_stake_tx =
            consensus::encode::deserialize_hex::<Transaction>(&operator_stake_tx.hex).unwrap();
        let pre_stake = operator_stake_tx
            .output
            .iter()
            .enumerate()
            .find_map(|(i, o)| {
                if o.value == OPERATOR_STAKE {
                    Some(OutPoint {
                        txid: operator_stake_tx.compute_txid(),
                        vout: i as u32,
                    })
                } else {
                    None
                }
            })
            .unwrap();

        let first_stake = StakeTx::create_initial(
            context,
            &stake_chain_params,
            stake_hash,
            wots_public_keys.withdrawal_fulfillment,
            pre_stake,
            operator_funds,
            operator_pubkey,
            connector_cpfp,
        );

        info!("signing and broadcasting the first stake tx");
        let prevouts = vec![
            TxOut {
                value: OPERATOR_FUNDS,
                script_pubkey: operator_address.script_pubkey(),
            },
            TxOut {
                value: OPERATOR_STAKE,
                script_pubkey: operator_address.script_pubkey(),
            },
        ];
        let prevouts = Prevouts::All(&prevouts);

        let mut sighash_cache = SighashCache::new(&first_stake.psbt.unsigned_tx);
        let witnesses = first_stake.witnesses();

        let message_hash_0 = create_message_hash(
            &mut sighash_cache,
            prevouts.clone(),
            &witnesses[0],
            TapSighashType::Default,
            0,
        )
        .unwrap();

        let tweaked_operator_keypair = operator_keypair.tap_tweak(SECP256K1, None);

        let op_signature_0 =
            SECP256K1.sign_schnorr(&message_hash_0, &tweaked_operator_keypair.to_inner());

        let message_hash_1 = create_message_hash(
            &mut sighash_cache,
            prevouts,
            &witnesses[1],
            TapSighashType::Default,
            1,
        )
        .unwrap();
        let op_signature_1 =
            SECP256K1.sign_schnorr(&message_hash_1, &tweaked_operator_keypair.to_inner());

        let signed_first_stake_tx = first_stake
            .clone()
            .finalize_initial(op_signature_0, op_signature_1);

        let input_amount = OPERATOR_FUNDS + OPERATOR_STAKE;
        let graph_funding_amount =
            signed_first_stake_tx.output[WITHDRAWAL_FULFILLMENT_VOUT as usize].value;
        let cpfp_child = create_cpfp_child(
            btc_client,
            &operator_keypair,
            connector_cpfp,
            &signed_first_stake_tx,
            input_amount,
            (signed_first_stake_tx.output.len() - 1) as u32,
        );

        let first_stake_txid = signed_first_stake_tx.compute_txid();
        info!(txid = %first_stake_txid, "submitting stake transaction");

        let result = btc_client
            .submit_package(&[signed_first_stake_tx, cpfp_child], None, None)
            .expect("must be able to submit first stake tx package");

        assert_eq!(
            result.package_msg, "success",
            "must be able to submit first stake package but got: {:?}",
            result
        );

        btc_client.generate_to_address(1, &wallet_addr).unwrap();

        (
            PegOutGraphInput {
                stake_outpoint: OutPoint {
                    txid: first_stake_txid,
                    vout: STAKE_VOUT,
                },
                withdrawal_fulfillment_outpoint: OutPoint {
                    txid: first_stake_txid,
                    vout: WITHDRAWAL_FULFILLMENT_VOUT,
                },
                stake_hash,
                wots_public_keys: wots_public_keys.into(),
                operator_pubkey,
            },
            stake_preimage,
            graph_funding_amount,
        )
    }

    struct SubmitAssertionsResult {
        signed_claim_tx: Transaction,
        signed_post_assert: Transaction,
        payout_tx: PayoutTx,
        post_assert_out_0: ConnectorA3,
        disprove_tx: DisproveTx,
        stake: ConnectorStake,
        n_of_n: ConnectorNOfN,
        hashlock_payout: ConnectorP,
    }

    #[expect(clippy::too_many_arguments)]
    async fn submit_assertions(
        btc_client: &Client,
        keypair: &Keypair,
        context: &TxBuildContext,
        deposit_txid: Txid,
        input: PegOutGraphInput,
        graph_params: PegOutGraphParams,
        connector_params: ConnectorParams,
        assertions: Assertions,
    ) -> SubmitAssertionsResult {
        let btc_addr = btc_client.new_address().expect("must generate new address");

        let stake_chain_params = StakeChainParams::default();

        let (graph, connectors) = PegOutGraph::generate(
            input,
            context,
            deposit_txid,
            graph_params,
            connector_params,
            stake_chain_params,
            vec![],
        );
        let PegOutGraph {
            claim_tx,
            assert_chain,
            payout_tx,
            disprove_tx,
            ..
        } = graph;

        let PegOutGraphConnectors {
            kickoff,
            claim_out_0,
            claim_out_1,
            n_of_n,
            connector_cpfp,
            post_assert_out_0,
            assert_data_hash_factory,
            assert_data256_factory,
            stake,
            hashlock_payout,
            ..
        } = connectors;

        let withdrawal_fulfillment_txid = generate_txid();
        let claim_input_amount = claim_tx.input_amount();
        let claim_cpfp_vout = claim_tx.cpfp_vout();

        let claim_sig = Wots256Signature::new(
            MSK,
            deposit_txid,
            withdrawal_fulfillment_txid.as_byte_array(),
        );
        let signed_claim_tx = claim_tx.finalize(*claim_sig, kickoff);
        info!(vsize = signed_claim_tx.vsize(), "broadcasting claim tx");

        let claim_child_tx = create_cpfp_child(
            btc_client,
            keypair,
            connector_cpfp,
            &signed_claim_tx,
            claim_input_amount,
            claim_cpfp_vout,
        );

        let result = btc_client
            .submit_package(&[signed_claim_tx.clone(), claim_child_tx], None, None)
            .expect("must be able to send claim tx");

        assert_eq!(
            result.package_msg, "success",
            "must have successful package submission for claim but got: {:?}",
            result
        );
        assert_eq!(
            result.tx_results.len(),
            2,
            "must have two transactions in package"
        );

        btc_client
            .generate_to_address(6, &btc_addr)
            .expect("must be able to mine blocks");

        info!("submitting a challenge");
        let challenge_leaf = ConnectorC1Path::Challenge(());
        let challenge_tx_input = ChallengeTxInput {
            claim_outpoint: OutPoint {
                txid: signed_claim_tx.compute_txid(),
                vout: 1, // challenge tx uses the second output of the claim tx
            },
            challenge_amt: CHALLENGE_COST,
            operator_pubkey: keypair.x_only_public_key().0,
            network: context.network(),
        };

        let challenge_tx = ChallengeTx::new(challenge_tx_input, claim_out_1);

        let input_index = challenge_leaf.get_input_index() as usize;
        let challenge_witness = &challenge_tx.witnesses()[input_index];
        let msg_hash = challenge_tx.sighashes()[input_index];

        let signature = generate_agg_signature(&msg_hash, keypair, challenge_witness);
        let signature = taproot::Signature {
            signature,
            sighash_type: challenge_leaf.get_sighash_type(),
        };
        let signed_challenge_leaf = challenge_leaf.add_witness_data(signature);
        let partially_signed_challenge_tx =
            challenge_tx.finalize_presigned(connectors.claim_out_1, signed_challenge_leaf);

        let signed_challenge_tx =
            fund_and_sign_raw_tx(btc_client, &partially_signed_challenge_tx, None, Some(true));

        info!(
            vsize = signed_challenge_tx.vsize(),
            txid = signed_challenge_tx.compute_txid().to_string(),
            "broadcasting challenge tx"
        );
        btc_client
            .send_raw_transaction(&signed_challenge_tx)
            .expect("must be able to send challenge tx");
        btc_client
            .generate_to_address(1, &btc_addr)
            .expect("must be able to mine blocks");

        let AssertChain {
            pre_assert,
            assert_data,
            post_assert,
        } = assert_chain;

        let witnesses = pre_assert.witnesses();
        let pre_assert_input_amount = pre_assert.input_amount();
        let pre_assert_cpfp_vout = pre_assert.cpfp_vout();
        let tx_hash = pre_assert.sighashes()[0];
        let n_of_n_sig = generate_agg_signature(&tx_hash, keypair, &witnesses[0]);
        let signed_pre_assert = pre_assert.finalize(claim_out_0, n_of_n_sig);
        assert_eq!(
            signed_pre_assert.version,
            transaction::Version(3),
            "pre-assert tx must be version 3"
        );

        let signed_pre_assert_cpfp = create_cpfp_child(
            btc_client,
            keypair,
            connector_cpfp,
            &signed_pre_assert,
            pre_assert_input_amount,
            pre_assert_cpfp_vout,
        );

        wait_for_blocks(
            btc_client,
            connector_params.pre_assert_timelock as usize + 1,
        );

        info!(
            vsize = signed_pre_assert.vsize(),
            "broadcasting pre-assert tx"
        );
        let result = btc_client
            .submit_package(&[signed_pre_assert, signed_pre_assert_cpfp], None, None)
            .expect("must be able to send pre-assert tx");

        assert_eq!(
            result.package_msg, "success",
            "must have successful package submission but got: {:?}",
            result
        );
        assert_eq!(
            result.tx_results.len(),
            2,
            "must have two transactions in package"
        );

        btc_client
            .generate_to_address(6, &btc_addr)
            .expect("must be able to mine blocks");

        let assert_sigs = wots::Signatures::new(MSK, deposit_txid, assertions);
        let assert_data_input_amounts = (0..assert_data.num_txs_in_batch())
            .map(|i| assert_data.total_input_amount(i).expect("input must exist"))
            .collect::<Vec<_>>();
        let assert_data_cpfp_vout = assert_data.cpfp_vout();

        let signed_assert_data_txs = assert_data.finalize(
            assert_data_hash_factory,
            assert_data256_factory,
            assert_sigs,
        );

        assert_eq!(
            signed_assert_data_txs.len(),
            NUM_ASSERT_DATA_TX,
            "number of assert data transactions must match"
        );

        let mut total_assert_vsize = 0;
        let mut total_assert_with_child_vsize = 0;

        assert_data_input_amounts.into_iter().zip(signed_assert_data_txs
            .into_iter())
            .enumerate()
            .for_each(|(i, (input_amount, tx))| {
                assert!(
                    tx.weight().to_wu() < MAX_STANDARD_TX_WEIGHT as u64,
                    "assert data tx {i} must be within standardness limit"
                );

                assert_eq!(tx.output.len(), 2, "assert data tx {i} must have 2 outputs -- one to consolidate, the other to CPFP");
                let assert_data_txid = tx.compute_txid();

                let signed_child_tx = create_cpfp_child(
                    btc_client,
                    keypair,
                    connector_cpfp,
                    &tx,
                    input_amount,
                    assert_data_cpfp_vout,
                );

                let vsize = tx.vsize();
                total_assert_vsize += vsize;
                total_assert_with_child_vsize += vsize + signed_child_tx.vsize();

                info!(
                    %vsize,
                    txid = tx.compute_txid().to_string(),
                    index = i,
                    "broadcasting assert data tx"
                );
                let result = btc_client
                    .submit_package(&[tx, signed_child_tx], None, None)
                    .expect("must be able to send assert data tx with cpfp");

                assert_eq!(result.package_msg, "success", "must have successful package submission but got: {result:?}");
                assert_eq!(result.tx_results.len(), 2, "must have two transactions in package");

                // generate a block so that the mempool size limit is not hit
                btc_client
                    .generate_to_address(1, &btc_addr)
                    .expect("must be able to mine assert data tx");

                btc_client.call::<String>("getrawtransaction", &[json!(assert_data_txid.to_string())]).expect("must be able to get assert data tx");
            });

        btc_client
            .generate_to_address(5, &btc_addr)
            .expect("must be able to mine blocks");

        info!(%total_assert_vsize, %total_assert_with_child_vsize, "submitted all assert data txs");

        let witnesses = post_assert.witnesses();
        let post_assert_sigs = witnesses
            .iter()
            .zip(post_assert.sighashes())
            .map(|(witness, sighash)| generate_agg_signature(&sighash, keypair, witness))
            .collect::<Vec<_>>();

        let post_assert_input_amount = post_assert.input_amount();
        let post_assert_cpf_vout = post_assert.cpfp_vout();
        let post_assert_output_amount = post_assert.output_amount();
        let signed_post_assert = post_assert.finalize(&post_assert_sigs);

        let signed_post_assert_child_tx = create_cpfp_child(
            btc_client,
            keypair,
            connector_cpfp,
            &signed_post_assert,
            post_assert_input_amount,
            post_assert_cpf_vout,
        );

        info!(
            txid = signed_post_assert.compute_txid().to_string(),
            final_output_amount = %post_assert_output_amount,
            "broadcasting post-assert tx"
        );
        let result = btc_client
            .submit_package(
                &[signed_post_assert.clone(), signed_post_assert_child_tx],
                None,
                None,
            )
            .expect("must be able to send post-assert tx");

        assert_eq!(
            result.package_msg, "success",
            "must have successful package submission but got: {:?}",
            result
        );
        assert_eq!(
            result.tx_results.len(),
            2,
            "must have two transactions in package"
        );

        btc_client
            .generate_to_address(6, &btc_addr)
            .expect("must be able to mine post-assert tx");

        SubmitAssertionsResult {
            signed_claim_tx,
            signed_post_assert,
            payout_tx,
            post_assert_out_0,
            disprove_tx,
            stake,
            n_of_n,
            hashlock_payout,
        }
    }

    /// Creates a funded child transaction for CPFP.
    fn create_cpfp_child(
        btc_client: &Client,
        operator_keypair: &Keypair,
        connector_cpfp: ConnectorCpfp,
        parent_tx: &Transaction,
        parent_input_amount: Amount,
        parent_output_index: u32,
    ) -> Transaction {
        let btc_addr = btc_client.new_address().expect("must generate new address");
        let cpfp_details = CpfpInput::new(parent_tx, parent_input_amount, parent_output_index)
            .expect("inputs must be valid");
        let assert_data_cpfp = Cpfp::new(cpfp_details, connector_cpfp);

        let funding_amount = assert_data_cpfp
            .estimate_package_fee(FEE_RATE)
            .expect("fee rate must be reasonable");

        let (funding_prevout, funding_utxo) =
            find_funding_utxo(btc_client, HashSet::new(), funding_amount);

        let funded_cpfp_tx = assert_data_cpfp
            .add_funding(funding_prevout, funding_utxo, btc_addr.clone(), FEE_RATE)
            .expect("must be able to fund assert data cpfp tx");

        let prevouts = funded_cpfp_tx
            .psbt()
            .inputs
            .iter()
            .filter_map(|input| input.witness_utxo.clone())
            .collect::<Vec<_>>();

        let mut unsigned_child_tx = funded_cpfp_tx.psbt().unsigned_tx.clone();
        let (funding_witness, parent_signature) = sign_cpfp_child(
            btc_client,
            operator_keypair,
            &prevouts,
            &mut unsigned_child_tx,
            Cpfp::FUNDING_INPUT_INDEX,
            Cpfp::PARENT_INPUT_INDEX,
        );

        funded_cpfp_tx
            .finalize(connector_cpfp, funding_witness, parent_signature)
            .expect("must be able to create signed child tx")
    }

    fn load_assertions() -> Assertions {
        const ASSERTION_FILE: &str = "../../test-data/assertions.bin";
        let assertions = fs::read(ASSERTION_FILE).expect("assertions file must exist");

        rkyv::from_bytes::<Assertions, Error>(&assertions)
            .expect("must be able to load assertions data")
    }

    #[tokio::test]
    async fn test_tx_graph_slash_stake() {
        let SetupOutput {
            bitcoind,
            n_of_n_keypair,
            context,
            deposit_txid,
            public_db,
        } = setup().await;

        let btc_client = &bitcoind.client;
        let operator_idx = 0;
        let wots_public_keys = public_db
            .get_wots_public_keys(operator_idx, deposit_txid)
            .await
            .expect("must be able to get wots public keys")
            .expect("must have wots public keys");

        let btc_addr = btc_client.new_address().expect("must generate new address");
        let operator_pubkey = n_of_n_keypair.x_only_public_key().0;

        let (input, stake_preimage, _) =
            create_tx_graph_input(btc_client, &context, n_of_n_keypair, wots_public_keys);
        let stake_chain_params = StakeChainParams::default();
        let graph_params = PegOutGraphParams {
            deposit_amount: DEPOSIT_AMOUNT,
            ..Default::default()
        };
        let connector_params = ConnectorParams {
            payout_optimistic_timelock: 11,
            pre_assert_timelock: 10,
            payout_timelock: 10,
        };

        let (graph, connectors) = PegOutGraph::generate(
            input.clone(),
            &context,
            deposit_txid,
            graph_params,
            connector_params,
            stake_chain_params,
            vec![],
        );

        let PegOutGraph {
            claim_tx: ongoing_claim_tx,
            ..
        } = graph;

        let PegOutGraphConnectors {
            kickoff,
            connector_cpfp,
            ..
        } = connectors;

        let withdrawal_fulfillment_txid = generate_txid();

        let claim_input_amount = ongoing_claim_tx.input_amount();
        let claim_cpfp_vout = ongoing_claim_tx.cpfp_vout();

        let claim_sig = Wots256Signature::new(
            MSK,
            deposit_txid,
            withdrawal_fulfillment_txid.as_byte_array(),
        );
        let signed_ongoing_claim_tx = ongoing_claim_tx.finalize(*claim_sig, kickoff);
        info!(
            action = "broadcasting claim tx",
            vsize = signed_ongoing_claim_tx.vsize(),
            txid = %signed_ongoing_claim_tx.compute_txid()
        );

        let claim_child_tx = create_cpfp_child(
            btc_client,
            &n_of_n_keypair,
            connector_cpfp,
            &signed_ongoing_claim_tx,
            claim_input_amount,
            claim_cpfp_vout,
        );

        let result = btc_client
            .submit_package(
                &[signed_ongoing_claim_tx.clone(), claim_child_tx],
                None,
                None,
            )
            .expect("must be able to send claim tx");

        assert_eq!(
            result.package_msg, "success",
            "must have successful package submission for claim but got: {:?}",
            result
        );
        assert_eq!(
            result.tx_results.len(),
            2,
            "must have two transactions in package"
        );

        btc_client
            .generate_to_address(6, &btc_addr)
            .expect("must be able to mine blocks");

        // create next peg-out graph instance
        let deposit_txid = generate_txid();
        let wots_public_keys = wots::PublicKeys::new(MSK, deposit_txid);
        public_db
            .set_wots_public_keys(0, deposit_txid, &wots_public_keys)
            .await
            .expect("must be able to set wots public keys");

        // create new stake tx
        let new_preimage = OsRng.gen::<[u8; 32]>();
        let new_hash = hashes::sha256::Hash::hash(&new_preimage);
        let new_withdrawal_fulfillment_pk = wots_public_keys.withdrawal_fulfillment;
        let prev_claim_txids = [signed_ongoing_claim_tx.compute_txid()];
        let funding_address = Address::p2tr_tweaked(
            operator_pubkey.dangerous_assume_tweaked(),
            context.network(),
        );
        let result = btc_client
            .send_to_address(&funding_address, OPERATOR_FUNDS)
            .unwrap();
        btc_client.generate_to_address(6, &btc_addr).unwrap();

        let funding_tx = btc_client.get_transaction(result.txid().unwrap()).unwrap();
        let funding_tx =
            consensus::encode::deserialize_hex::<Transaction>(&funding_tx.hex).unwrap();

        let funding_outpoint = OutPoint {
            txid: funding_tx.compute_txid(),
            vout: funding_tx
                .output
                .iter()
                .position(|o| o.value == OPERATOR_FUNDS)
                .unwrap() as u32,
        };

        let stake_data = StakeTxData {
            operator_funds: funding_outpoint,
            hash: new_hash,
            withdrawal_fulfillment_pk: new_withdrawal_fulfillment_pk,
        };

        let new_stake_tx = StakeTx::advance(
            &context,
            &stake_chain_params,
            stake_data,
            input.stake_hash,
            input.stake_outpoint,
            operator_pubkey,
            connector_cpfp,
        );

        let new_stake_txid = new_stake_tx.compute_txid();
        let input = PegOutGraphInput {
            stake_outpoint: OutPoint {
                txid: new_stake_txid,
                vout: STAKE_VOUT,
            },
            withdrawal_fulfillment_outpoint: OutPoint {
                txid: new_stake_txid,
                vout: WITHDRAWAL_FULFILLMENT_VOUT,
            },
            stake_hash: new_hash,
            wots_public_keys: wots_public_keys.into(),
            operator_pubkey,
        };

        let graph_params = PegOutGraphParams {
            deposit_amount: DEPOSIT_AMOUNT,
            ..Default::default()
        };
        let connector_params = ConnectorParams {
            payout_optimistic_timelock: 11,
            pre_assert_timelock: 10,
            payout_timelock: 10,
        };
        let (new_graph, new_connectors) = PegOutGraph::generate(
            input.clone(),
            &context,
            deposit_txid,
            graph_params,
            connector_params,
            stake_chain_params,
            prev_claim_txids.to_vec(),
        );

        assert_eq!(
            new_graph.slash_stake_txs.len(),
            prev_claim_txids.len(),
            "number of slash stake txids must match the number of prev claim txids but {} != {}",
            new_graph.slash_stake_txs.len(),
            prev_claim_txids.len()
        );

        info!(action = "advancing the stake while previous claim is present", txid = %new_stake_tx.compute_txid());

        let prev_connector_s = connectors.stake;
        let mut sighash_cache = SighashCache::new(&new_stake_tx.psbt.unsigned_tx);
        let prevouts = new_stake_tx
            .psbt
            .inputs
            .iter()
            .map(|input| input.witness_utxo.clone().unwrap())
            .collect::<Vec<_>>();
        let prevouts = Prevouts::All(&prevouts);

        let funds_witness = new_stake_tx.witnesses().first().unwrap();
        let funding_tx_msg = create_message_hash(
            &mut sighash_cache,
            prevouts.clone(),
            funds_witness,
            TapSighashType::Default,
            0,
        )
        .unwrap();
        let funds_signature = SECP256K1.sign_schnorr(&funding_tx_msg, &n_of_n_keypair);

        let stake_witness = new_stake_tx.witnesses().last().unwrap();
        let stake_msg_hash = create_message_hash(
            &mut sighash_cache,
            prevouts,
            stake_witness,
            TapSighashType::Default,
            1,
        )
        .unwrap();
        let stake_signature = SECP256K1.sign_schnorr(&stake_msg_hash, &n_of_n_keypair);

        let signed_new_stake_tx = new_stake_tx.finalize(
            &stake_preimage,
            funds_signature,
            stake_signature,
            prev_connector_s,
        );
        let cpfp_child = create_cpfp_child(
            btc_client,
            &n_of_n_keypair,
            connector_cpfp,
            &signed_new_stake_tx,
            OPERATOR_FUNDS + OPERATOR_STAKE,
            STAKE_VOUT + 1,
        );

        let result = btc_client
            .submit_package(&[signed_new_stake_tx, cpfp_child], None, None)
            .expect("must be able to send claim tx");

        assert_eq!(
            result.package_msg, "success",
            "must have successful package submission for new stake but got: {:?}",
            result
        );
        assert_eq!(
            result.tx_results.len(),
            2,
            "must have two transactions in package"
        );

        btc_client.generate_to_address(1, &btc_addr).unwrap();

        info!(action = "trying to spend slash stake tx");
        let slash_stake_tx = new_graph.slash_stake_txs[0].clone();

        let claim_out_conn = new_connectors.n_of_n;
        let stake_conn = new_connectors.stake;

        let prevouts = slash_stake_tx
            .psbt()
            .inputs
            .iter()
            .map(|input| input.witness_utxo.clone().expect("must have witness utxo"))
            .collect::<Vec<_>>();
        let prevouts = Prevouts::All(&prevouts);

        let claim_input_index = 0;
        let claim_witness = &slash_stake_tx.witnesses()[claim_input_index];
        let claim_sighash = slash_stake_tx.psbt().inputs[claim_input_index]
            .sighash_type
            .unwrap()
            .taproot_hash_ty()
            .unwrap();
        let mut sighash_cache = SighashCache::new(&slash_stake_tx.psbt().unsigned_tx);
        let claim_slash_stake_msg = create_message_hash(
            &mut sighash_cache,
            prevouts.clone(),
            claim_witness,
            claim_sighash,
            claim_input_index,
        )
        .unwrap();
        let claim_sig =
            generate_agg_signature(&claim_slash_stake_msg, &n_of_n_keypair, claim_witness);

        let stake_input_index = 1;
        let stake_witness = &slash_stake_tx.witnesses()[stake_input_index];
        let stake_sighash = slash_stake_tx.psbt().inputs[stake_input_index]
            .sighash_type
            .unwrap()
            .taproot_hash_ty()
            .unwrap();
        let stake_slash_stake_msg = create_message_hash(
            &mut sighash_cache,
            prevouts,
            stake_witness,
            stake_sighash,
            stake_input_index,
        )
        .unwrap();
        let stake_sig =
            generate_agg_signature(&stake_slash_stake_msg, &n_of_n_keypair, stake_witness);

        let mut signed_slash_stake_tx =
            slash_stake_tx.finalize(claim_sig, stake_sig, claim_out_conn, stake_conn);

        signed_slash_stake_tx.output.push(TxOut {
            value: SLASH_STAKE_REWARD,
            script_pubkey: btc_addr.script_pubkey(),
        });

        btc_client
            .send_raw_transaction(&signed_slash_stake_tx)
            .expect("must be able to broadcast slash stake transaction");
    }
}
