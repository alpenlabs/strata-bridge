//! This module constructs the peg-out graph which is a series of transactions that allow for the
//! withdrawal of funds from the bridge address given a valid claim.

use bitcoin::{hashes::sha256, relative, Amount, OutPoint, Txid};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use strata_bridge_connectors::prelude::*;
use strata_bridge_primitives::{
    build_context::BuildContext,
    params::connectors::*,
    types::OperatorIdx,
    wots::{self, Groth16PublicKeys},
};
use tracing::{debug, info};

use crate::{
    errors::TxGraphResult,
    transactions::{
        payout_optimistic::{PayoutOptimisticData, PayoutOptimisticTx},
        prelude::*,
    },
};

/// The input data required to generate a peg-out graph.
///
/// This data is shared between various operators and verifiers and is used to construct the peg out
/// graph deterministically. This assumes that the WOTS public keys have already been shared.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegOutGraphInput {
    /// The [`OutPoint`] of the stake transaction
    pub stake_outpoint: OutPoint,

    /// The [`OutPoint`] of the stake transaction used to commit to the withdrawal fulfillment
    /// txid.
    pub withdrawal_fulfillment_outpoint: OutPoint,

    /// The hash for the hashlock used in the Stake Transaction.
    pub stake_hash: sha256::Hash,

    /// The timelock between two successive stake transactions.
    pub delta: relative::LockTime,

    /// The amount used to fund all the dust outputs in the peg-out graph.
    pub funding_amount: Amount,

    /// The deposit amount for the peg-out graph.
    ///
    /// This is kept as an input instead of a constant to allow for flexibility in the future.
    pub deposit_amount: Amount,

    /// The public key of the operator.
    pub operator_pubkey: XOnlyPublicKey,
}

/// A container for the transactions in the peg-out graph.
///
/// Each transaction is a wrapper around [`bitcoin::Psbt`] and some auxiliary data required to
/// construct the fully signed transaction provided a signature.
#[derive(Debug, Clone)]
pub struct PegOutGraph {
    /// The claim transaction that commits to a valid withdrawal fulfillment txid.
    pub claim_tx: ClaimTx,

    /// The transaction used to reimburse operators when no challenge occurs.
    pub payout_optimistic: PayoutOptimisticTx,

    /// The assert chain that commits to the proof of a valid claim.
    pub assert_chain: AssertChain,

    /// The payout transaction that reimburses the operator.
    pub payout_tx: PayoutTx,

    /// The disprove transaction that invalidates a claim and slashes the operator's stake.
    pub disprove_tx: DisproveTx,
}

impl PegOutGraph {
    /// Generate the peg-out graph for a given operator.
    ///
    /// Each graph can be generated deterministically provided that the WOTS public keys are
    /// available for the operator for the given deposit transaction, and the input data is
    /// available.
    pub async fn generate<Context>(
        input: PegOutGraphInput,
        context: &Context,
        deposit_txid: Txid,
        operator_idx: OperatorIdx,
        wots_public_keys: wots::PublicKeys,
    ) -> TxGraphResult<(Self, PegOutGraphConnectors)>
    where
        Context: BuildContext,
    {
        let connectors = PegOutGraphConnectors::new(
            context,
            deposit_txid,
            operator_idx,
            input.stake_hash,
            input.delta,
            wots_public_keys,
        );

        let claim_data = ClaimData {
            stake_outpoint: input.withdrawal_fulfillment_outpoint,
            input_amount: input.funding_amount,
            deposit_txid,
        };

        let claim_tx = ClaimTx::new(
            claim_data,
            connectors.kickoff,
            connectors.claim_out_0,
            connectors.claim_out_1,
            connectors.connector_cpfp,
        );
        let claim_txid = claim_tx.compute_txid();
        debug!(event = "created claim tx", %operator_idx, %claim_txid);

        info!(action = "registering claim txid for bitcoin watcher", %claim_txid, own_index = %operator_idx);

        let payout_optimistic_data = PayoutOptimisticData {
            claim_txid,
            deposit_txid,
            input_stake: claim_tx.output_amount(),
            deposit_amount: input.deposit_amount,
            operator_key: input.operator_pubkey,
            network: context.network(),
        };

        let payout_optimistic = PayoutOptimisticTx::new(
            payout_optimistic_data,
            connectors.claim_out_0,
            connectors.claim_out_1,
            connectors.n_of_n,
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
            operator_idx,
            connectors.claim_out_0,
            connectors.n_of_n,
            connectors.post_assert_out_0,
            connectors.connector_cpfp,
            connectors.assert_data160_factory,
            connectors.assert_data256_factory,
        );

        let post_assert_txid = assert_chain.post_assert.compute_txid();
        let post_assert_out_amt = assert_chain.post_assert.output_amount();

        debug!(event = "created assert chain", %operator_idx, %post_assert_txid);

        let payout_data = PayoutData {
            post_assert_txid,
            deposit_txid,
            input_amount: post_assert_out_amt,
            deposit_amount: input.deposit_amount,
            operator_key: input.operator_pubkey,
            network: context.network(),
        };

        let payout_tx = PayoutTx::new(
            payout_data,
            connectors.post_assert_out_0,
            connectors.n_of_n,
            connectors.connector_cpfp,
        );
        let payout_txid = payout_tx.compute_txid();
        debug!(event = "created payout tx", %operator_idx, %payout_txid);

        let disprove_data = DisproveData {
            post_assert_txid,
            deposit_txid,
            input_amount: post_assert_out_amt,
            stake_outpoint: input.stake_outpoint,
            network: context.network(),
        };

        let disprove_tx = DisproveTx::new(
            disprove_data,
            connectors.post_assert_out_0,
            connectors.stake,
        );
        let disprove_txid = disprove_tx.compute_txid();
        debug!(event = "created disprove tx", %operator_idx, %disprove_txid);

        Ok((
            Self {
                claim_tx,
                payout_optimistic,
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
///
/// Note that this does not include the stake chain connectors as those are shared at setup time at
/// regular intervals and not during the peg-out graph generation.
#[derive(Debug, Clone, Copy)]
pub struct PegOutGraphConnectors {
    /// The output of the kickoff tx.
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

    /// The factory for the 160-bit assertion data connectors.
    pub assert_data160_factory: ConnectorA160Factory<
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
}

impl PegOutGraphConnectors {
    /// Create a new set of connectors for the peg-out graph.
    pub(crate) fn new(
        build_context: &impl BuildContext,
        deposit_txid: Txid,
        operator_idx: OperatorIdx,
        stake_hash: sha256::Hash,
        delta: relative::LockTime,
        wots_public_keys: wots::PublicKeys,
    ) -> Self {
        let n_of_n_agg_pubkey = build_context.aggregated_pubkey();
        let network = build_context.network();

        let kickoff = ConnectorK::new(
            n_of_n_agg_pubkey,
            network,
            wots_public_keys.withdrawal_fulfillment_pk,
        );

        let claim_out_0 = ConnectorC0::new(n_of_n_agg_pubkey, network);

        let claim_out_1 = ConnectorC1::new(n_of_n_agg_pubkey, network);

        let n_of_n = ConnectorNOfN::new(n_of_n_agg_pubkey, network);
        let operator_pubkey = build_context
            .pubkey_table()
            .0
            .get(&operator_idx)
            .expect("must have operator pubkey")
            .x_only_public_key()
            .0;

        let connector_cpfp = ConnectorCpfp::new(operator_pubkey, network);
        let post_assert_out_1 =
            ConnectorA3::new(network, deposit_txid, wots_public_keys, n_of_n_agg_pubkey);

        let wots::PublicKeys {
            withdrawal_fulfillment_pk: _,
            groth16:
                Groth16PublicKeys(([public_inputs_hash_public_key], public_keys_256, public_keys_160)),
        } = wots_public_keys;

        let assert_data160_factory = ConnectorA160Factory {
            network,
            public_keys: public_keys_160,
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

        Self {
            kickoff,
            claim_out_0,
            claim_out_1,
            n_of_n,
            connector_cpfp,
            post_assert_out_0: post_assert_out_1,
            assert_data160_factory,
            assert_data256_factory,
            stake,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashSet},
        fs,
        str::FromStr,
        sync::Arc,
    };

    use bitcoin::{
        consensus,
        hashes::{self, Hash},
        key::TapTweak,
        policy::MAX_STANDARD_TX_WEIGHT,
        psbt::PsbtSighashType,
        sighash::{Prevouts, SighashCache},
        taproot, transaction, Address, FeeRate, Network, OutPoint, TapSighashType, Transaction,
        TxOut,
    };
    use corepc_node::{serde_json::json, Client, Conf, Node};
    use rkyv::rancor::Error;
    use secp256k1::{
        rand::{rngs::OsRng, Rng},
        Keypair, SECP256K1,
    };
    use strata_bridge_db::{inmemory::public::PublicDbInMemory, public::PublicDb};
    use strata_bridge_primitives::{
        build_context::TxBuildContext,
        params::{
            prelude::{StakeChainParams, NUM_ASSERT_DATA_TX, PAYOUT_TIMELOCK},
            tx::{CHALLENGE_COST, DISPROVER_REWARD, NUM_SLASH_STAKE_TX, OPERATOR_STAKE},
        },
        scripts::taproot::{create_message_hash, TaprootWitness},
        wots::{
            Assertions, PublicKeys as WotsPublicKeys, Signatures as WotsSignatures,
            Wots256PublicKey,
        },
    };
    use strata_bridge_stake_chain::prelude::{
        StakeTx, OPERATOR_FUNDS, STAKE_VOUT, WITHDRAWAL_FULFILLMENT_VOUT,
    };
    use strata_bridge_test_utils::{
        musig2::generate_agg_signature,
        prelude::{
            find_funding_utxo, generate_keypair, generate_txid, get_funding_utxo_exact,
            sign_cpfp_child, wait_for_blocks,
        },
        tx::{get_mock_deposit, FEES},
    };
    use strata_btcio::rpc::types::{GetTxOut, SignRawTransactionWithWallet};
    use strata_common::logging;
    use tracing::warn;

    use super::*;
    use crate::transactions::challenge::{ChallengeTx, ChallengeTxInput};

    const DEPOSIT_AMOUNT: Amount = Amount::from_int_btc(10);
    const MSK: &str = "test_msk";
    const FEE_RATE: FeeRate = FeeRate::from_sat_per_kwu(5000);

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

        let input = create_tx_graph_input(
            btc_client,
            &context,
            n_of_n_keypair,
            wots_public_keys.withdrawal_fulfillment_pk,
        );
        let (graph, connectors) = PegOutGraph::generate(
            input,
            &context,
            deposit_txid,
            operator_idx,
            wots_public_keys,
        )
        .await
        .expect("must be able to generate peg-out graph");

        let PegOutGraph {
            claim_tx,
            payout_optimistic,
            ..
        } = graph;

        let PegOutGraphConnectors {
            kickoff,
            claim_out_0,
            claim_out_1,
            connector_cpfp,
            ..
        } = connectors;

        let withdrawal_fulfillment_txid = generate_txid();

        let claim_input_amount = claim_tx.input_amount();
        let claim_cpfp_vout = claim_tx.cpfp_vout();
        let signed_claim_tx =
            claim_tx.finalize(deposit_txid, &kickoff, MSK, withdrawal_fulfillment_txid);
        info!(vsize = signed_claim_tx.vsize(), "broadcasting claim tx");

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

        let mut sighash_cache = SighashCache::new(&payout_optimistic.psbt().unsigned_tx);

        let prevouts = payout_optimistic.prevouts();
        let witnesses = payout_optimistic.witnesses();

        let mut signatures = witnesses.iter().enumerate().map(|(i, witness)| {
            let message = create_message_hash(
                &mut sighash_cache,
                prevouts.clone(),
                witness,
                TapSighashType::Default,
                i,
            )
            .expect("must be able to create a message hash");

            generate_agg_signature(&message, &n_of_n_keypair, witness)
        });

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

        let payout_input_amount = payout_optimistic.input_amount();
        let payout_cpfp_vout = payout_optimistic.cpfp_vout();

        let signed_payout_tx = payout_optimistic.finalize(
            claim_out_0,
            claim_out_1,
            n_of_n_sig_c0,
            n_of_n_sig_c1,
            deposit_signature,
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

        let n_blocks = PAYOUT_OPTIMISTIC_TIMELOCK as usize + 1;
        info!(%n_blocks, "waiting for blocks");

        wait_for_blocks(btc_client, PAYOUT_OPTIMISTIC_TIMELOCK as usize + 1);

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

        let input = create_tx_graph_input(
            btc_client,
            &context,
            n_of_n_keypair,
            wots_public_keys.withdrawal_fulfillment_pk,
        );

        let assertions = load_assertions();
        let SubmitAssertionsResult {
            payout_tx,
            post_assert_out_0,
            ..
        } = submit_assertions(
            btc_client,
            &n_of_n_keypair,
            &context,
            deposit_txid,
            input,
            Arc::new(public_db),
            assertions,
        )
        .await;

        let mut sighash_cache = SighashCache::new(&payout_tx.psbt().unsigned_tx);

        let prevouts = payout_tx.prevouts();
        let witnesses = payout_tx.witnesses();

        let mut signatures = witnesses.iter().enumerate().map(|(i, witness)| {
            let message = create_message_hash(
                &mut sighash_cache,
                prevouts.clone(),
                witness,
                TapSighashType::Default,
                i,
            )
            .expect("must be able to create a message hash");

            generate_agg_signature(&message, &n_of_n_keypair, witness)
        });

        let deposit_signature = signatures.next().expect("must have deposit signature");
        let n_of_n_sig = signatures.next().expect("must have n-of-n signature");
        let payout_input_amount = payout_tx.input_amount();
        let payout_cpfp_vout = payout_tx.cpfp_vout();
        let signed_payout_tx = payout_tx.finalize(post_assert_out_0, deposit_signature, n_of_n_sig);
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

        wait_for_blocks(btc_client, PAYOUT_TIMELOCK as usize + 1);

        info!(txid = payout_txid, "trying to submit payout after timelock");
        let result = btc_client
            .submit_package(&[signed_payout_tx, signed_payout_cpfp_child], None, None)
            .expect("must be able to send payout package");

        assert_eq!(
            result.package_msg, "success",
            "submit package message must be success"
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

        let input = create_tx_graph_input(
            btc_client,
            &context,
            n_of_n_keypair,
            public_keys.withdrawal_fulfillment_pk,
        );

        let mut faulty_assertions = load_assertions();
        for _ in 0..faulty_assertions.groth16.2.len() {
            let proof_index_to_tweak = OsRng.gen_range(0..faulty_assertions.groth16.2.len());
            warn!(action = "introducing faulty assertion", index=%proof_index_to_tweak);
            if faulty_assertions.groth16.2[proof_index_to_tweak] != [0u8; 20] {
                faulty_assertions.groth16.2[proof_index_to_tweak] = [0u8; 20];
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
            public_db.into(),
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

        info!("extracting withdrawal fulfillment txid commitments from claim transactions");
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
        let mut sighash_cache = SighashCache::new(&disprove_tx.psbt().unsigned_tx);
        let prevouts = disprove_tx.prevouts();
        let input_index = 0;

        let witness_type = &disprove_tx.witnesses()[input_index];
        assert!(
            matches!(witness_type, TaprootWitness::Tweaked { .. }),
            "witness on the first input must be tweaked"
        );

        let sighash_type = disprove_tx.psbt().inputs[input_index]
            .sighash_type
            .expect("sighash type must be set on the first index of the disprove tx")
            .taproot_hash_ty()
            .unwrap();
        assert_eq!(sighash_type, TapSighashType::Single);

        let disprove_msg = create_message_hash(
            &mut sighash_cache,
            prevouts,
            witness_type,
            sighash_type,
            input_index,
        )
        .unwrap();
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
        let wots_public_keys = WotsPublicKeys::new(MSK, deposit_txid);
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
        withdrawal_fulfillment_pk: Wots256PublicKey,
    ) -> PegOutGraphInput {
        let operator_pubkey = operator_keypair.x_only_public_key().0;
        let wallet_addr = btc_client.new_address().expect("must generate new address");

        let stake_preimage: [u8; 32] = OsRng.gen();
        let stake_hash = hashes::sha256::Hash::hash(&stake_preimage);

        let delta = relative::LockTime::from_height(6);
        let stake_chain_params = StakeChainParams {
            stake_amount: OPERATOR_STAKE,
            delta,
            slash_stake_count: NUM_SLASH_STAKE_TX,
        };

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
            stake_chain_params,
            stake_hash,
            withdrawal_fulfillment_pk,
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
            TapSighashType::All,
            0,
        )
        .unwrap();

        let tweaked_operator_keypair = operator_keypair.tap_tweak(SECP256K1, None);

        let op_signature_0 =
            SECP256K1.sign_schnorr(&message_hash_0, &tweaked_operator_keypair.to_inner());
        let op_signature_0 = taproot::Signature {
            signature: op_signature_0,
            sighash_type: first_stake.psbt.inputs[0]
                .sighash_type
                .unwrap_or(PsbtSighashType::from(TapSighashType::All))
                .taproot_hash_ty()
                .unwrap(),
        };

        let message_hash_1 = create_message_hash(
            &mut sighash_cache,
            prevouts,
            &witnesses[1],
            TapSighashType::All,
            1,
        )
        .unwrap();
        let op_signature_1 =
            SECP256K1.sign_schnorr(&message_hash_1, &tweaked_operator_keypair.to_inner());
        let op_signature_1 = taproot::Signature {
            signature: op_signature_1,
            sighash_type: first_stake.psbt.inputs[1]
                .sighash_type
                .unwrap_or(PsbtSighashType::from(TapSighashType::All))
                .taproot_hash_ty()
                .unwrap(),
        };

        let signed_first_stake_tx = first_stake.finalize_initial(op_signature_0, op_signature_1);

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

        PegOutGraphInput {
            deposit_amount: DEPOSIT_AMOUNT,
            operator_pubkey,
            stake_outpoint: OutPoint {
                txid: first_stake_txid,
                vout: STAKE_VOUT,
            },
            withdrawal_fulfillment_outpoint: OutPoint {
                txid: first_stake_txid,
                vout: WITHDRAWAL_FULFILLMENT_VOUT,
            },
            stake_hash,
            delta,
            funding_amount: graph_funding_amount,
        }
    }

    struct SubmitAssertionsResult {
        signed_claim_tx: Transaction,
        signed_post_assert: Transaction,
        payout_tx: PayoutTx,
        post_assert_out_0: ConnectorA3,
        disprove_tx: DisproveTx,
        stake: ConnectorStake,
    }

    async fn submit_assertions(
        btc_client: &Client,
        keypair: &Keypair,
        context: &TxBuildContext,
        deposit_txid: Txid,
        input: PegOutGraphInput,
        public_db: Arc<PublicDbInMemory>,
        assertions: Assertions,
    ) -> SubmitAssertionsResult {
        let btc_addr = btc_client.new_address().expect("must generate new address");
        let operator_idx = 0;
        let wots_public_keys = public_db
            .as_ref()
            .get_wots_public_keys(operator_idx, deposit_txid)
            .await
            .expect("must be able to get wots public keys")
            .expect("must have wots public keys");
        let (graph, connectors) =
            PegOutGraph::generate(input, context, deposit_txid, operator_idx, wots_public_keys)
                .await
                .expect("must be able to generate peg-out graph");

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
            n_of_n: _,
            connector_cpfp,
            post_assert_out_0,
            assert_data160_factory,
            assert_data256_factory,
            stake,
            ..
        } = connectors;

        let withdrawal_fulfillment_txid = generate_txid();
        let claim_input_amount = claim_tx.input_amount();
        let claim_cpfp_vout = claim_tx.cpfp_vout();
        let signed_claim_tx =
            claim_tx.finalize(deposit_txid, &kickoff, MSK, withdrawal_fulfillment_txid);
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

        let unsigned_challenge_tx = challenge_tx.psbt().unsigned_tx.clone();
        let mut sighash_cache = SighashCache::new(&unsigned_challenge_tx);
        let input_index = challenge_leaf.get_input_index() as usize;
        let challenge_witness = &challenge_tx.witnesses()[input_index];
        let msg_hash = create_message_hash(
            &mut sighash_cache,
            challenge_tx.prevouts(),
            challenge_witness,
            challenge_leaf.get_sighash_type(),
            input_index,
        )
        .expect("should be able to create message hash");
        let signature = generate_agg_signature(&msg_hash, keypair, challenge_witness);
        let signature = taproot::Signature {
            signature,
            sighash_type: challenge_leaf.get_sighash_type(),
        };
        let signed_challenge_leaf = challenge_leaf.add_witness_data(signature);

        let (funding_input, funding_utxo) =
            get_funding_utxo_exact(btc_client, CHALLENGE_COST + FEES);

        let funded_challenge_tx = challenge_tx
            .add_funding_input(funding_utxo, funding_input)
            .expect("must be able to add funding input to challenge tx");
        let partially_signed_challenge_tx = funded_challenge_tx
            .finalize(claim_out_1, signed_challenge_leaf)
            .expect("must be able to finalize challenge tx");

        let raw_partially_signed_challenge_tx =
            consensus::encode::serialize_hex(&partially_signed_challenge_tx);
        let result = btc_client
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[json!(raw_partially_signed_challenge_tx)],
            )
            .expect("must be able to sign tx");
        let signed_challenge_tx = consensus::encode::deserialize_hex::<Transaction>(&result.hex)
            .expect("must be able to deserialize signed tx");

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

        let mut sighash_cache = SighashCache::new(&pre_assert.psbt().unsigned_tx);
        let prevouts = pre_assert.prevouts();
        let witnesses = pre_assert.witnesses();
        let pre_assert_input_amount = pre_assert.input_amount();
        let pre_assert_cpfp_vout = pre_assert.cpfp_vout();
        let tx_hash = create_message_hash(
            &mut sighash_cache,
            prevouts,
            &witnesses[0],
            TapSighashType::Default,
            0,
        )
        .expect("must be able create a message hash for tx");
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

        wait_for_blocks(btc_client, PRE_ASSERT_TIMELOCK as usize + 1);

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

        let wots_signatures = WotsSignatures::new(MSK, deposit_txid, assertions);
        let assert_data_input_amounts = (0..assert_data.num_txs_in_batch())
            .map(|i| assert_data.total_input_amount(i).expect("input must exist"))
            .collect::<Vec<_>>();
        let assert_data_cpfp_vout = assert_data.cpfp_vout();

        let signed_assert_data_txs = assert_data.finalize(
            assert_data160_factory,
            assert_data256_factory,
            wots_signatures,
        );

        assert_eq!(
            signed_assert_data_txs.len(),
            NUM_ASSERT_DATA_TX,
            "number of assert data transactions must match"
        );

        let num_signed_assert_data_txs = signed_assert_data_txs.len();
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

        let mut sighash_cache = SighashCache::new(&post_assert.psbt().unsigned_tx);

        let prevouts = post_assert.prevouts();
        let witnesses = post_assert.witnesses();
        let post_assert_sigs = (0..num_signed_assert_data_txs)
            .map(|i| {
                let message = create_message_hash(
                    &mut sighash_cache,
                    prevouts.clone(),
                    &witnesses[i],
                    TapSighashType::Default,
                    i,
                )
                .expect("must be able to create a message hash");

                generate_agg_signature(&message, keypair, &witnesses[i])
            })
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
}
