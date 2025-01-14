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
/// Each transaction is a wrapper around [`bitcoin::Psbt`] and some auxiliary data required to
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, str::FromStr, sync::Arc};

    use bitcoin::{consensus, sighash::SighashCache, OutPoint, ScriptBuf, TapSighashType, TxOut};
    use corepc_node::{
        serde_json::{self, json},
        Conf, Node,
    };
    use rkyv::rancor::Error;
    use strata_bridge_btcio::types::{GetTxOut, ListUnspent, SignRawTransactionWithWallet};
    use strata_bridge_db::inmemory::public::PublicDbInMemory;
    use strata_bridge_primitives::{
        bitcoin::BitcoinAddress,
        build_context::TxBuildContext,
        params::{
            prelude::{NUM_ASSERT_DATA_TX, PAYOUT_TIMELOCK},
            tx::OPERATOR_STAKE,
        },
        scripts::taproot::create_message_hash,
        wots::{Assertions, PublicKeys as WotsPublicKeys, Signatures as WotsSignatures},
    };
    use strata_bridge_test_utils::{
        musig2::generate_agg_signature,
        prelude::{generate_keypair, generate_txid},
        tx::get_mock_deposit,
    };
    use strata_common::logging;

    use super::*;

    const DEPOSIT_AMOUNT: Amount = Amount::from_int_btc(10);
    const MSK: &str = "test_msk";

    #[tokio::test]
    async fn test_tx_graph_payout() {
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

        let keypair = generate_keypair();
        let operator_pubkey = keypair.x_only_public_key().0;
        let pubkey_table = BTreeMap::from([(0, keypair.public_key())]);
        let context = TxBuildContext::new(network, pubkey_table.into(), 0);

        let n_of_n_agg_pubkey = context.aggregated_pubkey();
        let bridge_address = ConnectorS::new(n_of_n_agg_pubkey, network).create_taproot_address();

        let deposit_tx = get_mock_deposit(btc_client, DEPOSIT_AMOUNT, &bridge_address);
        let deposit_txid: Txid = deposit_tx.compute_txid();
        info!(?deposit_tx, %deposit_txid, %DEPOSIT_AMOUNT, "made a mock deposit");

        btc_client
            .call::<GetTxOut>("gettxout", &[json!(deposit_txid.to_string()), json!(0)])
            .expect("deposit txout must be present");

        let utxos = btc_client
            .call::<Vec<ListUnspent>>("listunspent", &[])
            .expect("must be able to get utxos");

        let utxo = utxos
            .iter()
            .find(|utxo| utxo.amount > DEPOSIT_AMOUNT)
            .expect("must have at least one valid utxo");

        let funding_inputs = vec![OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        }];
        let funding_utxos = vec![TxOut {
            value: utxo.amount,
            script_pubkey: ScriptBuf::from_hex(&utxo.script_pubkey).expect("must be valid hex"),
        }];

        let btc_addr = btc_client.new_address().expect("must generate new address");
        let input = PegOutGraphInput {
            network,
            deposit_amount: DEPOSIT_AMOUNT,
            operator_pubkey,
            kickoff_data: KickoffTxData {
                funding_inputs,
                funding_utxos,
                change_address: BitcoinAddress::parse(&btc_addr.to_string(), network)
                    .expect("address must be valid for network"),
                change_amt: utxo.amount - OPERATOR_STAKE - Amount::from_sat(1_000),
                deposit_txid,
            },
        };

        let public_db = PublicDbInMemory::default();
        let wots_public_keys = WotsPublicKeys::new(MSK, deposit_txid);
        public_db
            .set_wots_public_keys(0, deposit_txid, &wots_public_keys)
            .await
            .expect("must be able to set wots public keys");

        let (graph, connectors) =
            PegOutGraph::generate(input, Arc::new(public_db), &context, deposit_txid, 0)
                .await
                .expect("must be able to generate peg-out graph");

        let PegOutGraph {
            kickoff_tx,
            claim_tx,
            assert_chain,
            payout_tx,
            disprove_tx: _,
        } = graph;

        let signed_kickoff_tx = btc_client
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[serde_json::Value::String(consensus::encode::serialize_hex(
                    &kickoff_tx.psbt().unsigned_tx,
                ))],
            )
            .expect("must be able to sign kickoff tx");

        let signed_kickoff_tx = &consensus::encode::deserialize_hex(&signed_kickoff_tx.hex)
            .expect("must be able to deserialize raw signed kickoff tx");

        info!(?signed_kickoff_tx, "sending kickoff tx");
        btc_client
            .send_raw_transaction(signed_kickoff_tx)
            .expect("must be able to send kickoff tx");

        let PegOutGraphConnectors {
            kickoff,
            claim_out_0,
            claim_out_1: _,
            stake: _,
            post_assert_out_0,
            post_assert_out_1: _,
            assert_data160_factory,
            assert_data256_factory,
        } = connectors;

        let bridge_out_txid = generate_txid();
        let best_block_hash = btc_client
            .get_best_block_hash()
            .expect("must get block")
            .block_hash()
            .expect("must have block hash");
        let start_ts = btc_client
            .get_block_verbose_one(best_block_hash)
            .expect("must get block")
            .time;

        let signed_claim_tx = claim_tx.finalize(
            deposit_txid,
            &kickoff,
            MSK,
            bridge_out_txid,
            start_ts as u32,
        );
        btc_client
            .send_raw_transaction(&signed_claim_tx)
            .expect("must be able to send claim tx");

        let AssertChain {
            pre_assert,
            assert_data,
            post_assert,
        } = assert_chain;

        let mut sighash_cache = SighashCache::new(&pre_assert.psbt().unsigned_tx);
        let prevouts = pre_assert.prevouts();
        let witnesses = pre_assert.witnesses();
        let tx_hash = create_message_hash(
            &mut sighash_cache,
            prevouts,
            &witnesses[0],
            TapSighashType::Default,
            0,
        )
        .expect("must be able create a message hash for tx");
        let n_of_n_sig = generate_agg_signature(&tx_hash, &keypair, &witnesses[0]);
        let signed_pre_assert = pre_assert.finalize(n_of_n_sig, claim_out_0);

        btc_client
            .send_raw_transaction(&signed_pre_assert)
            .expect("must be able to send pre-assert tx");

        btc_client
            .generate_to_address(6, &btc_addr)
            .expect("must be able to mine blocks");

        let assertions = load_assertions();

        let wots_signatures = WotsSignatures::new(MSK, deposit_txid, assertions);
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

        signed_assert_data_txs.iter().for_each(|tx| {
            btc_client
                .send_raw_transaction(tx)
                .expect("must be able to send assert data tx");

            // generate a block so that the mempool size limit is not hit
            btc_client
                .generate_to_address(1, &btc_addr)
                .expect("must be able to mine assert data tx");
        });

        btc_client
            .generate_to_address(5, &btc_addr)
            .expect("must be able to mine blocks");

        let mut sighash_cache = SighashCache::new(&post_assert.psbt().unsigned_tx);

        let prevouts = post_assert.prevouts();
        let witnesses = post_assert.witnesses();
        let post_assert_sigs = (0..signed_assert_data_txs.len() + 1)
            .map(|i| {
                let message = create_message_hash(
                    &mut sighash_cache,
                    prevouts.clone(),
                    &witnesses[i],
                    TapSighashType::Default,
                    i,
                )
                .expect("must be able to create a message hash");

                generate_agg_signature(&message, &keypair, &witnesses[i])
            })
            .collect::<Vec<_>>();

        let signed_post_assert = post_assert.finalize(&post_assert_sigs);
        btc_client
            .send_raw_transaction(&signed_post_assert)
            .expect("must be able to send post-assert tx");

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

            generate_agg_signature(&message, &keypair, witness)
        });

        let deposit_signature = signatures.next().expect("must have deposit signature");
        let n_of_n_sig = signatures.next().expect("must have n-of-n signature");
        let signed_payout_tx = payout_tx.finalize(post_assert_out_0, deposit_signature, n_of_n_sig);
        assert!(
            btc_client
                .send_raw_transaction(&signed_payout_tx)
                .is_err_and(|e| { e.to_string().contains("non-BIP68-final") }),
            "must not be able to send payout tx immediately"
        );

        btc_client
            .generate_to_address(PAYOUT_TIMELOCK as usize + 6, &btc_addr)
            .expect("must be able to mine blocks");

        btc_client
            .send_raw_transaction(&signed_payout_tx)
            .expect("must be able to send payout tx after timelock");
    }

    fn load_assertions() -> Assertions {
        const ASSERTION_FILE: &str = "../../test-data/assertions.bin";
        let assertions = fs::read(ASSERTION_FILE).expect("assertions file must exist");

        rkyv::from_bytes::<Assertions, Error>(&assertions)
            .expect("must be able to load assertions data")
    }
}
