use std::{collections::BTreeMap, marker::PhantomData};

use bitcoin::{
    hashes::Hash, transaction, Address, Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Transaction,
    TxOut, Txid, Weight, Witness,
};
use secp256k1::schnorr;
use strata_bridge_primitives::scripts::prelude::{create_tx, create_tx_ins, create_tx_outs};

use super::errors::{TxError, TxResult};
use crate::connectors::prelude::ConnectorCpfp;

/// The data required to create a child transaction in CPFP.
///
/// The generic parameter `INPUTS` is the number of inputs in the child transaction that are used to
/// fund the 1P1C package.
#[derive(Debug, Clone)]
pub struct CpfpInput {
    pub parent_prevout_amount: Amount,
    pub parent_utxo: OutPoint,
    pub parent_weight: Weight,
}

/// Marker for when the child transaction has not been funded.
#[derive(Debug, Clone)]
pub struct Unfunded;
/// Marker for when the child transaction has been funded.
#[derive(Debug, Clone)]
pub struct Funded;

/// Wrapper for a child-pays-for-parent transaction.
///
/// This child transaction has the first input that funds the 1P1C package and the second input that
/// spends the parent utxo.
#[derive(Debug, Clone)]
pub struct Cpfp<Status = Unfunded> {
    psbt: Psbt,

    parent_weight: Weight,

    status: PhantomData<Status>,
}

impl Cpfp {
    const PARENT_INPUT_INDEX: usize = 0;
    const FUNDING_INPUT_INDEX: usize = 1;
}

impl<Status> Cpfp<Status> {
    pub fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    pub fn estimate_package_fee(&self, fee_rate: FeeRate) -> TxResult<Amount> {
        let weight = self.psbt.unsigned_tx.weight() + self.parent_weight;

        fee_rate
            .checked_mul_by_weight(weight)
            .ok_or(TxError::InvalidFeeRate(fee_rate))
    }
}

impl Cpfp<Unfunded> {
    pub fn new(details: CpfpInput, connector_cpfp: ConnectorCpfp) -> Self {
        // set dummy funding input for fee calculation
        let dummy_funding_outpoint = OutPoint {
            txid: Txid::from_slice(&[0u8; 32]).expect("must be able to create txid"),
            vout: 0,
        };

        let mut utxos = vec![OutPoint::null(); 2];
        utxos[Self::PARENT_INPUT_INDEX] = details.parent_utxo;
        utxos[Self::FUNDING_INPUT_INDEX] = dummy_funding_outpoint;

        let tx_ins = create_tx_ins(utxos);
        let tx_outs = create_tx_outs([(ScriptBuf::new(), Amount::from_int_btc(0))]);

        let mut unsigned_child_tx = create_tx(tx_ins, tx_outs);
        unsigned_child_tx.version = transaction::Version(3);

        let mut psbt =
            Psbt::from_unsigned_tx(unsigned_child_tx).expect("must be able to create psbt");

        let parent_prevout = TxOut {
            value: details.parent_prevout_amount,
            script_pubkey: connector_cpfp.generate_taproot_address().script_pubkey(),
        };

        let mut prevouts: Vec<TxOut> = vec![TxOut::NULL; 2];
        prevouts[Self::PARENT_INPUT_INDEX] = parent_prevout;
        prevouts[Self::FUNDING_INPUT_INDEX] = TxOut {
            value: Amount::from_int_btc(0),
            script_pubkey: ScriptBuf::new(),
        };

        psbt.inputs
            .iter_mut()
            .zip(prevouts.clone())
            .for_each(|(psbt_in, prevout)| {
                psbt_in.witness_utxo = Some(prevout);
            });

        Self {
            psbt,
            parent_weight: details.parent_weight,

            status: PhantomData,
        }
    }

    pub fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    pub fn add_funding(
        mut self,
        funding_prevout: TxOut,
        funding_outpoint: OutPoint,
        change_address: Address,
        fee_rate: FeeRate,
    ) -> TxResult<Cpfp<Funded>> {
        let funding_amount = funding_prevout.value;
        let package_fee = self.estimate_package_fee(fee_rate)?;
        let change_amount = funding_amount - package_fee;

        let psbt = self.psbt_mut();
        psbt.inputs[1].witness_utxo = Some(funding_prevout);
        psbt.unsigned_tx.input[1].previous_output = funding_outpoint;

        psbt.unsigned_tx.output[0].value = change_amount;
        psbt.unsigned_tx.output[0].script_pubkey = change_address.script_pubkey();

        let Self {
            psbt,
            parent_weight,
            status: _,
        } = self;

        Ok(Cpfp::<Funded> {
            psbt,
            parent_weight,

            status: PhantomData,
        })
    }
}

impl Cpfp<Funded> {
    pub fn finalize(
        mut self,
        connector_cpfp: ConnectorCpfp,
        funding_witness: Witness,
        parent_signature: schnorr::Signature,
    ) -> TxResult<Transaction> {
        let funding_input = &mut self.psbt.inputs[Cpfp::FUNDING_INPUT_INDEX];
        funding_input.final_script_witness = Some(funding_witness);

        // reset the rest of the fields as per the spec
        funding_input.partial_sigs = BTreeMap::new();
        funding_input.sighash_type = None;
        funding_input.redeem_script = None;
        funding_input.witness_script = None;
        funding_input.bip32_derivation = BTreeMap::new();

        connector_cpfp.finalize_input(
            self.psbt
                .inputs
                .get_mut(Cpfp::PARENT_INPUT_INDEX)
                .ok_or(TxError::Unexpected(format!(
                    "missing input index {} for the parent",
                    Cpfp::PARENT_INPUT_INDEX
                )))?,
            parent_signature,
        );

        self.psbt
            .extract_tx()
            .map_err(|e| TxError::Unexpected(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{
        consensus,
        hashes::Hash,
        sighash::{Prevouts, SighashCache},
        Network, TapSighashType,
    };
    use corepc_node::{serde_json::json, Conf, Node};
    use secp256k1::{Message, SECP256K1};
    use strata_bridge_btcio::types::{ListUnspent, SignRawTransactionWithWallet};
    use strata_bridge_test_utils::prelude::generate_keypair;
    use strata_common::logging::{self, LoggerConfig};

    use super::*;

    #[test]
    fn test_cpfp_tx() {
        logging::init(LoggerConfig::new("test-cpfp-tx".to_string()));

        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        let bitcoind =
            Node::from_downloaded_with_conf(&conf).expect("must be able to start bitcoind");
        let btc_client = &bitcoind.client;

        let network = btc_client
            .get_blockchain_info()
            .expect("must be able to get network info")
            .chain;
        let network = Network::from_str(&network).expect("must be able to parse network");

        let wallet_addr = btc_client
            .new_address()
            .expect("must be able to create a new address");
        btc_client
            .generate_to_address(103, &wallet_addr)
            .expect("must be able to generate blocks");

        let keypair = generate_keypair();
        let pubkey = keypair.x_only_public_key().0;
        let connector_cpfp = ConnectorCpfp::new(network, pubkey);

        let unspent = btc_client
            .call::<Vec<ListUnspent>>("listunspent", &[])
            .expect("must be able to list unspent");

        let unspent = unspent.first().expect("must have at least one utxo");
        let parent_input_utxo = OutPoint {
            txid: unspent.txid,
            vout: unspent.vout,
        };

        let parent_prevout_amount = Amount::from_sat(500);

        let tx_ins = create_tx_ins([parent_input_utxo]);
        let tx_outs = create_tx_outs([
            (
                connector_cpfp.generate_taproot_address().script_pubkey(),
                parent_prevout_amount,
            ),
            (
                wallet_addr.script_pubkey(),
                unspent.amount - parent_prevout_amount,
            ),
        ]);

        let mut unsigned_parent_tx = create_tx(tx_ins, tx_outs);
        unsigned_parent_tx.version = transaction::Version(3);

        let signed_parent_tx = btc_client
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[json!(consensus::encode::serialize_hex(&unsigned_parent_tx))],
            )
            .expect("must be able to sign parent tx");
        let signed_parent_tx =
            consensus::encode::deserialize_hex::<Transaction>(&signed_parent_tx.hex)
                .expect("must be able to deserialize signed parent tx");
        assert!(
            signed_parent_tx.version == transaction::Version(3),
            "signed parent tx must have version 3"
        );

        let details = CpfpInput {
            parent_prevout_amount,
            parent_utxo: OutPoint {
                txid: unsigned_parent_tx.compute_txid(),
                vout: 0,
            },
            parent_weight: unsigned_parent_tx.weight(),
        };

        let cpfp = Cpfp::new(details, connector_cpfp);

        let fee_rate = FeeRate::from_sat_per_kwu(10);
        let total_fee = cpfp
            .estimate_package_fee(fee_rate)
            .expect("fee rate must be reasonable");

        let list_unspent = btc_client
            .call::<Vec<ListUnspent>>("listunspent", &[])
            .expect("must be able to list unspent");

        let (funding_prevout, funding_outpoint) = list_unspent
            .iter()
            .find_map(|utxo| {
                if utxo.amount > total_fee && utxo.txid != parent_input_utxo.txid {
                    Some((
                        TxOut {
                            value: utxo.amount,
                            script_pubkey: ScriptBuf::from_hex(&utxo.script_pubkey)
                                .expect("must be able to parse script pubkey"),
                        },
                        OutPoint {
                            txid: utxo.txid,
                            vout: utxo.vout,
                        },
                    ))
                } else {
                    None
                }
            })
            .expect("must have a utxo with enough funds");

        let mut cpfp = cpfp
            .add_funding(
                funding_prevout,
                funding_outpoint,
                wallet_addr.clone(),
                fee_rate,
            )
            .expect("fee rate must be reasonable");

        let mut unsigned_child_tx = cpfp.psbt().unsigned_tx.clone();
        let signed_child_tx = btc_client
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[json!(consensus::encode::serialize_hex(&unsigned_child_tx))],
            )
            .expect("must be able to sign child tx");
        let signed_child_tx =
            consensus::encode::deserialize_hex::<Transaction>(&signed_child_tx.hex)
                .expect("must be able to deserialize signed child tx");
        assert!(
            signed_child_tx.version == transaction::Version(3),
            "signed child tx must have version 3"
        );

        let funding_witness = signed_child_tx
            .input
            .get(Cpfp::FUNDING_INPUT_INDEX)
            .expect("must have funding input")
            .witness
            .clone();

        let prevouts = cpfp
            .psbt()
            .inputs
            .iter()
            .filter_map(|input| input.witness_utxo.clone())
            .collect::<Vec<_>>();
        let prevouts = Prevouts::All(&prevouts);

        let mut sighasher = SighashCache::new(&mut unsigned_child_tx);
        let child_tx_hash = sighasher
            .taproot_key_spend_signature_hash(
                Cpfp::PARENT_INPUT_INDEX,
                &prevouts,
                TapSighashType::Default,
            )
            .expect("sighash must be valid");

        let child_tx_msg = Message::from_digest_slice(child_tx_hash.as_byte_array())
            .expect("must be able to create tx message");
        let parent_signature = SECP256K1.sign_schnorr(&child_tx_msg, &keypair);

        let signed_child_tx = cpfp
            .finalize(connector_cpfp, funding_witness, parent_signature)
            .expect("must be able to create signed tx");

        // settle any unsettled transactions
        btc_client
            .generate_to_address(6, &wallet_addr)
            .expect("must be able to generate blocks");

        let result = btc_client
            .submit_package(&[signed_parent_tx, signed_child_tx], None, None)
            .expect("must be able to submit package");

        assert!(
            result.package_msg == "success",
            "package_msg must be success"
        );
        assert!(
            result.tx_results.len() == 2,
            "tx_results must have 2 elements"
        );
    }
}
