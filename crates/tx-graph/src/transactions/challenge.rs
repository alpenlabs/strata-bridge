//! Module to construct the Challenge Transaction.

use std::marker::PhantomData;

use bitcoin::{
    key::TapTweak, psbt::ExtractTxError, sighash::Prevouts, taproot, Address, Amount, Network,
    OutPoint, Psbt, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness,
};
use secp256k1::XOnlyPublicKey;
use strata_bridge_connectors::prelude::{ConnectorC1, ConnectorC1Path};
use strata_bridge_primitives::scripts::{
    prelude::{create_tx, create_tx_ins, create_tx_outs},
    taproot::TaprootWitness,
};

use super::{
    errors::{TxError, TxResult},
    prelude::CovenantTx,
};

/// Data needed to construct a [`ChallengeTx`].
#[derive(Debug, Clone)]
pub struct ChallengeTxInput {
    /// The outpoint of the claim transaction that the challenge tx spends.
    pub claim_outpoint: OutPoint,

    /// The output amount on the challenge transaction.
    pub challenge_amt: Amount,

    /// The public key of the operator that locks the output of the challenge transaction.
    pub operator_pubkey: XOnlyPublicKey,

    /// The network where the constructed challenge transaction is valid.
    pub network: Network,
}

/// Marker struct representing the unfunded state of the Challenge transaction.
#[derive(Debug, Clone)]
pub struct Unfunded;

/// Marker struct representing the funded state of the Challenge transaction.
#[derive(Debug, Clone)]
pub struct Funded;

/// The transaction used to challenge an operator's claim.
#[derive(Debug, Clone)]
pub struct ChallengeTx<Status = Unfunded> {
    psbt: Psbt,

    prevouts: Vec<TxOut>,
    witnesses: Vec<TaprootWitness>,

    status: PhantomData<Status>,
}

impl ChallengeTx<Unfunded> {
    /// Constructs a new Challenge transaction.
    pub fn new(input: ChallengeTxInput, challenge_connector: ConnectorC1) -> Self {
        let tx_ins = create_tx_ins([input.claim_outpoint]);

        let operator_address = Address::p2tr_tweaked(
            input.operator_pubkey.dangerous_assume_tweaked(),
            input.network,
        );
        let tx_outs = create_tx_outs([(operator_address.script_pubkey(), input.challenge_amt)]);

        let tx = create_tx(tx_ins, tx_outs);
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("must be able to create psbt");

        let tapleaf = ConnectorC1Path::Challenge(());
        let tweak = challenge_connector.generate_merkle_root();

        let witnesses = vec![TaprootWitness::Tweaked { tweak }];

        let script_pubkey = challenge_connector.generate_locking_script();
        let prevouts = vec![TxOut {
            value: script_pubkey.minimal_non_dust(),
            script_pubkey,
        }];

        let input_index = tapleaf.get_input_index() as usize;
        psbt.inputs[input_index].witness_utxo = Some(prevouts[0].clone());
        psbt.inputs[input_index].sighash_type = Some(TapSighashType::SinglePlusAnyoneCanPay.into());

        Self {
            psbt,

            prevouts,
            witnesses,

            status: PhantomData,
        }
    }

    /// Funds the Challenge transaction.
    ///
    /// Note that the witnesses are not updated in this method as the funding input needs to be
    /// finalized separately.
    pub fn add_funding_input(
        mut self,
        previous_output: OutPoint,
        prevout: TxOut,
    ) -> TxResult<ChallengeTx<Funded>> {
        let tx_in = TxIn {
            previous_output,
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
            script_sig: ScriptBuf::new(),
        };

        self.psbt.unsigned_tx.input.push(tx_in);
        self.prevouts.push(prevout.clone());

        self.psbt = Psbt::from_unsigned_tx(self.psbt.unsigned_tx).expect("tx must be unsigned");

        self.prevouts
            .iter()
            .zip(self.psbt.inputs.iter_mut())
            .for_each(|(prevout, input)| {
                input.witness_utxo = Some(prevout.clone());
            });

        let input_amount = self.input_amount();
        let output_amount = self
            .psbt
            .unsigned_tx
            .output
            .iter()
            .map(|output| output.value)
            .sum();

        if input_amount < output_amount {
            return Err(TxError::InsufficientInputAmount(
                input_amount,
                output_amount,
            ));
        }

        Ok(ChallengeTx::<Funded> {
            psbt: self.psbt,

            prevouts: self.prevouts,
            witnesses: self.witnesses,

            status: PhantomData,
        })
    }

    /// Finalizes the presigned input in the Challenge transaction.
    ///
    /// # Caution
    ///
    /// The transaction returned by this method cannot be broadcasted as is since its output value
    /// exceeds the input value. Therefore, the caller must ensure that the transaction is funded
    /// (for example, by calling the `fundrawtransaction` RPC method) and signed before it can be
    /// broadcasted.
    pub fn finalize_presigned(
        mut self,
        connector_c1: ConnectorC1,
        challenge_leaf: ConnectorC1Path<taproot::Signature>,
    ) -> Transaction {
        connector_c1.finalize_input(
            &mut self.psbt.inputs[challenge_leaf.get_input_index() as usize],
            challenge_leaf,
        );

        match self.psbt.extract_tx() {
            Ok(tx) => tx,
            // ignore the fact that the output is way beyond the input amount assuming that the
            // caller will fund this transaction later.
            Err(ExtractTxError::SendingTooMuch { psbt }) => psbt.extract_tx_unchecked_fee_rate(),

            Err(e) => unreachable!("unexpected error: {:?}", e),
        }
    }
}

impl ChallengeTx<Funded> {
    /// Finalizes the presigned input in the Challenge transaction.
    pub fn finalize(
        mut self,
        connector_c1: ConnectorC1,
        challenge_leaf: ConnectorC1Path<taproot::Signature>,
    ) -> TxResult<Transaction> {
        connector_c1.finalize_input(
            &mut self.psbt.inputs[challenge_leaf.get_input_index() as usize],
            challenge_leaf,
        );

        Ok(self.psbt.extract_tx()?)
    }
}

impl CovenantTx for ChallengeTx {
    fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    fn prevouts(&self) -> Prevouts<'_, TxOut> {
        Prevouts::All(&self.prevouts)
    }

    fn witnesses(&self) -> &[TaprootWitness] {
        &self.witnesses
    }

    fn input_amount(&self) -> Amount {
        self.psbt
            .inputs
            .iter()
            .map(|input| {
                input
                    .witness_utxo
                    .as_ref()
                    .expect("should have witness utxo")
                    .value
            })
            .sum()
    }

    fn compute_txid(&self) -> Txid {
        self.psbt.unsigned_tx.compute_txid()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use alpen_bridge_params::prelude::PegOutGraphParams;
    use bitcoin::{consensus, sighash::SighashCache, Network};
    use corepc_node::{serde_json::json, Client, Conf, Node};
    use strata_bridge_primitives::{
        build_context::{BuildContext, TxBuildContext},
        scripts::taproot::create_message_hash,
    };
    use strata_bridge_test_utils::{
        bitcoin_rpc::fund_and_sign_raw_tx,
        musig2::generate_agg_signature,
        prelude::{generate_keypair, generate_txid, get_funding_utxo_exact},
        tx::FEES,
    };
    use strata_btcio::rpc::types::SignRawTransactionWithWallet;

    use super::*;

    #[test]
    fn test_challenge_tx() {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");

        let bitcoind =
            Node::from_downloaded_with_conf(&conf).expect("must be able to start bitcoind");
        let btc_client = &bitcoind.client;
        let PrepareChallengeTxResult {
            operator_address,
            challenge_connector,
            input_amount,
            challenge_tx,
            signed_challenge_leaf,
        } = prepare_challenge_tx(btc_client);

        let insufficient_outpoint = OutPoint {
            txid: generate_txid(),
            vout: 0,
        };
        let insufficient_prevout = TxOut {
            value: Amount::from_sat(100),
            script_pubkey: operator_address.script_pubkey().clone(),
        };

        let pegout_graph_params = PegOutGraphParams::default();
        assert!(challenge_tx
            .clone()
            .add_funding_input(insufficient_outpoint, insufficient_prevout.clone())
            .is_err_and(|err| {
                match err {
                    TxError::InsufficientInputAmount(input, output) => {
                        assert_eq!(input, input_amount + insufficient_prevout.value);
                        assert_eq!(output, pegout_graph_params.challenge_cost);

                        true
                    }
                    _ => panic!("unexpected error: {:?}", err),
                }
            }));

        let required_amount: Amount = challenge_tx
            .psbt()
            .unsigned_tx
            .output
            .iter()
            .map(|output| output.value)
            .sum();
        let (funding_input, funding_outpoint) =
            get_funding_utxo_exact(btc_client, required_amount + FEES);

        let funded_challenge_tx = challenge_tx
            .add_funding_input(funding_outpoint, funding_input)
            .expect("must be able to fund the challenge");

        let signed_challenge_tx = funded_challenge_tx
            .finalize(challenge_connector, signed_challenge_leaf)
            .expect("must be able to finalize tx");

        let signed_challenge_tx_result = btc_client
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[json!(consensus::encode::serialize_hex(
                    &signed_challenge_tx
                )
                .to_string())],
            )
            .expect("must be able to sign tx");

        let signed_challenge_tx: Transaction =
            consensus::encode::deserialize_hex(&signed_challenge_tx_result.hex)
                .expect("must be able to deserialize tx");

        btc_client
            .send_raw_transaction(&signed_challenge_tx)
            .expect("must be able to send tx");
    }

    #[test]
    fn test_challenge_tx_psbt() {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");

        let bitcoind =
            Node::from_downloaded_with_conf(&conf).expect("must be able to start bitcoind");
        let btc_client = &bitcoind.client;
        let PrepareChallengeTxResult {
            challenge_connector,
            challenge_tx,
            signed_challenge_leaf,
            ..
        } = prepare_challenge_tx(btc_client);

        let finalized_challenge_tx =
            challenge_tx.finalize_presigned(challenge_connector, signed_challenge_leaf);

        let signed_challenge_tx =
            fund_and_sign_raw_tx(btc_client, &finalized_challenge_tx, None, Some(true));

        btc_client
            .send_raw_transaction(&signed_challenge_tx)
            .expect("must be able to send tx");
    }

    struct PrepareChallengeTxResult {
        operator_address: Address,
        challenge_connector: ConnectorC1,
        input_amount: Amount,
        challenge_tx: ChallengeTx,
        signed_challenge_leaf: ConnectorC1Path<taproot::Signature>,
    }

    fn prepare_challenge_tx(btc_client: &Client) -> PrepareChallengeTxResult {
        let network = btc_client
            .get_blockchain_info()
            .expect("must get blockchain info")
            .chain;
        let network = Network::from_str(&network).expect("network must be valid");

        let operator_address = btc_client.new_address().expect("must get new address");
        btc_client
            .generate_to_address(101, &operator_address)
            .expect("must be able to generate blocks");

        let n_of_n_keypair = generate_keypair();
        let operator_pubkey = n_of_n_keypair.public_key();

        let pubkey_table = BTreeMap::from([(0, operator_pubkey)]);
        let context = TxBuildContext::new(network, pubkey_table.into(), 0);
        let n_of_n_agg_pubkey = context.aggregated_pubkey();

        let challenge_leaf = ConnectorC1Path::Challenge(());

        let payout_optimistic_timelock = 10;
        let challenge_connector =
            ConnectorC1::new(n_of_n_agg_pubkey, network, payout_optimistic_timelock);
        let input_amount = challenge_connector
            .generate_locking_script()
            .minimal_non_dust();
        let challenge_address = challenge_connector.generate_taproot_address().0;

        let input_tx = btc_client
            .send_to_address(&challenge_address, input_amount)
            .expect("must be able to send funds to challenge tx");
        btc_client
            .generate_to_address(6, &challenge_address)
            .expect("must be able to settle input tx");
        let input_tx = btc_client
            .get_transaction(Txid::from_str(&input_tx.0).expect("must be valid txid"))
            .expect("must be able to get input tx");
        let input_tx: Transaction = consensus::encode::deserialize_hex(&input_tx.hex)
            .expect("must be able to deserialize tx");
        let input_index = input_tx
            .output
            .iter()
            .position(|output| output.value == input_amount)
            .expect("must be able to find output");

        let challenge_input = ChallengeTxInput {
            claim_outpoint: OutPoint {
                txid: input_tx.compute_txid(),
                vout: input_index as u32,
            },
            challenge_amt: PegOutGraphParams::default().challenge_cost,
            operator_pubkey: n_of_n_keypair.x_only_public_key().0,
            network,
        };

        let challenge_tx = ChallengeTx::new(challenge_input, challenge_connector);
        let input_index = challenge_leaf.get_input_index() as usize;

        let unsigned_challenged_tx = challenge_tx.psbt.unsigned_tx.clone();
        let mut sighasher = SighashCache::new(&unsigned_challenged_tx);
        let message = create_message_hash(
            &mut sighasher,
            challenge_tx.prevouts(),
            &challenge_tx.witnesses()[input_index],
            challenge_leaf.get_sighash_type(),
            input_index,
        )
        .expect("must be able to create message hash");

        let witness = challenge_tx.witnesses()[input_index].clone();
        let signature = generate_agg_signature(&message, &n_of_n_keypair, &witness);
        let n_of_n_sig = taproot::Signature {
            signature,
            sighash_type: challenge_leaf.get_sighash_type(),
        };
        let signed_challenge_leaf = challenge_leaf.add_witness_data(n_of_n_sig);

        PrepareChallengeTxResult {
            operator_address,
            challenge_connector,
            input_amount,
            challenge_tx,
            signed_challenge_leaf,
        }
    }
}
