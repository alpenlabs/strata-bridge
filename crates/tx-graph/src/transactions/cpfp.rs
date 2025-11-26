//! Constructs the CPFP transaction.

use std::{collections::BTreeMap, marker::PhantomData};

use bitcoin::{
    hashes::Hash, transaction, Address, Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Transaction,
    TxOut, Txid, Weight, Witness,
};
use secp256k1::schnorr;
use strata_bridge_connectors::prelude::ConnectorCpfp;
use strata_bridge_primitives::scripts::prelude::{create_tx, create_tx_ins, create_tx_outs};

use super::errors::{TxError, TxResult};

/// The data required to create a child transaction in CPFP.
#[derive(Debug, Clone)]
pub struct CpfpInput<'input> {
    /// The parent transaction that is being CPFP'd.
    parent_tx: &'input Transaction,

    /// The input amount of the parent transaction that is being spent.
    ///
    /// This is used to calculate the fees already paid in the parent transaction.
    parent_input_amount: Amount,

    /// The output index of the parent transaction that is being spent.
    vout: u32,
}

impl<'input> CpfpInput<'input> {
    /// Creates a new instance of the CPFP input data.
    ///
    /// # Parameters
    ///
    /// - `parent_tx`: The signed parent transaction that is being CPFP'd.
    /// - `parent_input_amount`: The input amount of the parent transaction that is being spent,
    ///   used to compute the transaction fees in the parent transaction.
    /// - `vout`: The output index of the parent transaction that is being spent.
    ///
    /// # Errors
    ///
    /// If the output at index `vout` is not present in the parent transaction or if any witness
    /// field in the parent transaction is empty.
    pub fn new(
        parent_tx: &'input Transaction,
        parent_input_amount: Amount,
        vout: u32,
    ) -> TxResult<Self> {
        if vout >= parent_tx.output.len() as u32 {
            return Err(TxError::InvalidVout(vout));
        }

        if parent_tx.input.iter().any(|input| input.witness.is_empty()) {
            return Err(TxError::EmptyWitness(parent_tx.compute_txid()));
        }

        Ok(Self {
            parent_tx,
            parent_input_amount,
            vout,
        })
    }
}

/// Marker for when the child transaction has not been funded.
#[derive(Debug, Clone)]
pub struct Unfunded;

/// Marker for when the child transaction has been funded.
///
/// This is to ensure at compile-time that only funded psbts are signed and broadcasted.
#[derive(Debug, Clone)]
pub struct Funded;

/// Wrapper for a child-pays-for-parent transaction.
///
/// This child transaction has the first input that funds the 1P1C package and the second input that
/// spends the parent utxo.
#[derive(Debug, Clone)]
pub struct Cpfp<Status = Unfunded> {
    /// The underlying PSBT of the child transaction.
    psbt: Psbt,

    /// The weight of the parent transaction.
    parent_weight: Weight,

    /// The transaction fees paid by the parent transaction.
    parent_fees: Amount,

    /// Marker for the status of the child transaction to indicate whether it has been funded.
    status: PhantomData<Status>,
}

impl Cpfp {
    /// The index of the parent input in the child transaction.
    pub const PARENT_INPUT_INDEX: usize = 0;

    /// The index of the funding input in the child transaction.
    pub const FUNDING_INPUT_INDEX: usize = 1;
}

impl<Status> Cpfp<Status> {
    /// Returns the underlying PSBT of the child transaction.
    pub const fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    /// Estimate the package fee required to settle the package at the given [`FeeRate`].
    ///
    /// # Errors
    ///
    /// If the `fee_rate` is too high.
    ///
    /// # NOTE:
    ///
    /// The fee calculation does not take into account the witness field in the child transaction
    /// i.e., estimate assumes that the witness field in the child transaction is empty.
    pub fn estimate_package_fee(&self, fee_rate: FeeRate) -> TxResult<Amount> {
        let weight = self.psbt.unsigned_tx.weight() + self.parent_weight;

        let child_fees = fee_rate
            .checked_mul_by_weight(weight)
            .ok_or(TxError::InvalidFeeRate(fee_rate))?;

        Ok(child_fees - self.parent_fees)
    }
}

impl Cpfp<Unfunded> {
    /// Creates a new instance of the CPFP transaction.
    ///
    /// # NOTE:
    /// The created CPFP transaction is not yet funded and cannot be settled.
    pub fn new(details: CpfpInput<'_>, connector_cpfp: ConnectorCpfp) -> Self {
        // set dummy funding input for fee calculation
        let dummy_funding_outpoint = OutPoint {
            txid: Txid::from_slice(&[0u8; 32]).expect("must be able to create txid"),
            vout: 0,
        };

        let mut utxos = vec![OutPoint::null(); 2];
        utxos[Self::PARENT_INPUT_INDEX] = OutPoint {
            txid: details.parent_tx.compute_txid(),
            vout: details.vout,
        };
        utxos[Self::FUNDING_INPUT_INDEX] = dummy_funding_outpoint;

        let tx_ins = create_tx_ins(utxos);
        let tx_outs = create_tx_outs([(ScriptBuf::new(), Amount::from_int_btc(0))]);

        let mut unsigned_child_tx = create_tx(tx_ins, tx_outs);

        // An unconfirmed TRUC transaction can only be spent by a TRUC transaction.
        if details.parent_tx.version == transaction::Version(3) {
            unsigned_child_tx.version = transaction::Version(3);
        }

        let mut psbt =
            Psbt::from_unsigned_tx(unsigned_child_tx).expect("must be able to create psbt");

        let parent_prevout = TxOut {
            value: details.parent_tx.output[details.vout as usize].value,
            script_pubkey: connector_cpfp.generate_locking_script(),
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

        let parent_output_amount: Amount = details
            .parent_tx
            .output
            .iter()
            .map(|output| output.value)
            .sum();

        let parent_input_amount: Amount = details.parent_input_amount;

        let parent_fees = parent_input_amount
            .checked_sub(parent_output_amount)
            .expect("BUG: input amount must be at least equal to output amount");

        Self {
            psbt,
            parent_weight: details.parent_tx.weight(),
            parent_fees,

            status: PhantomData,
        }
    }

    /// A mutable reference to the underlying PSBT.
    pub const fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    /// Adds inputs/utxos used to fund the 1P1C package.
    ///
    /// NOTE: The funding input is the second input in the child transaction.
    // FIXME: Support multiple funding inputs in the future. This is to support cases where a single
    // available UTXO is not enough to fund the package. This is unlikely to happen in practice in
    // the present as operators are assumed to have high-liquidity.
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
            parent_fees,
            status: _,
        } = self;

        Ok(Cpfp::<Funded> {
            psbt,
            parent_weight,
            parent_fees,

            status: PhantomData,
        })
    }
}

impl Cpfp<Funded> {
    /// Finalizes the CPFP transaction by populating the witness fields.
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

        // Not having an input at this index is unexpected because
        // the underlying psbt cannot be mutated once it is `Funded`.
        // It is assumed that the programmer has correctly implemented the logic to populate the
        // inputs in the `add_funding_inputs` and `new` methods.
        let parent_input =
            self.psbt
                .inputs
                .get_mut(Cpfp::PARENT_INPUT_INDEX)
                .ok_or(TxError::Unexpected(format!(
                    "missing input index {} for the parent",
                    Cpfp::PARENT_INPUT_INDEX
                )))?;

        connector_cpfp.finalize_input(parent_input, parent_signature);

        self.psbt
            .extract_tx()
            .map_err(|e| TxError::Unexpected(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr};

    use bitcoin::{consensus, Network};
    use bitcoind_async_client::types::{ListUnspent, SignRawTransactionWithWallet};
    use corepc_node::{serde_json::json, Conf, Node};
    use strata_bridge_common::logging::{self, LoggerConfig};
    use strata_bridge_test_utils::prelude::{find_funding_utxo, generate_keypair, sign_cpfp_child};

    use super::*;

    #[test]
    fn test_cpfp_tx() {
        logging::init(LoggerConfig::new("test-cpfp-tx".to_string()));

        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        let bitcoind = Node::with_conf("bitcoind", &conf).expect("must be able to start bitcoind");
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
        let connector_cpfp = ConnectorCpfp::new(pubkey.into(), network);

        let unspent = btc_client
            .call::<Vec<ListUnspent>>("listunspent", &[])
            .expect("must be able to list unspent");

        let unspent = unspent.first().expect("must have at least one utxo");
        let parent_input_utxo = OutPoint {
            txid: unspent.txid,
            vout: unspent.vout,
        };

        let connector_cpfp_out = connector_cpfp.generate_locking_script();
        let parent_prevout_amount = connector_cpfp_out.minimal_non_dust();

        let tx_ins = create_tx_ins([parent_input_utxo]);
        let tx_outs = create_tx_outs([
            (connector_cpfp_out, parent_prevout_amount),
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

        let details =
            CpfpInput::new(&signed_parent_tx, unspent.amount, 0).expect("values must be valid");

        let cpfp = Cpfp::new(details, connector_cpfp.clone());

        let fee_rate = FeeRate::from_sat_per_kwu(10);
        let total_fee = cpfp
            .estimate_package_fee(fee_rate)
            .expect("fee rate must be reasonable");

        let (funding_prevout, funding_outpoint) =
            find_funding_utxo(btc_client, HashSet::from([parent_input_utxo]), total_fee);

        let cpfp = cpfp
            .add_funding(
                funding_prevout,
                funding_outpoint,
                wallet_addr.clone(),
                fee_rate,
            )
            .expect("fee rate must be reasonable");

        let mut unsigned_child_tx = cpfp.psbt().unsigned_tx.clone();
        let prevouts = cpfp
            .psbt()
            .inputs
            .iter()
            .filter_map(|input| input.witness_utxo.clone())
            .collect::<Vec<_>>();

        let (funding_witness, parent_signature) = sign_cpfp_child(
            btc_client,
            &keypair,
            &prevouts,
            &mut unsigned_child_tx,
            Cpfp::FUNDING_INPUT_INDEX,
            Cpfp::PARENT_INPUT_INDEX,
        );

        let signed_child_tx = cpfp
            .finalize(connector_cpfp, funding_witness, parent_signature)
            .expect("must be able to finalize cpfp tx");

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
