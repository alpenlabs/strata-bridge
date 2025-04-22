//! Module to construct the Challenge Transaction.

use bitcoin::{
    key::TapTweak, psbt::ExtractTxError, sighash::Prevouts, taproot, Address, Amount, Network,
    OutPoint, Psbt, Transaction, TxOut, Txid,
};
use secp256k1::XOnlyPublicKey;
use strata_bridge_connectors::prelude::{ConnectorC1, ConnectorC1Path};
use strata_bridge_primitives::scripts::{
    prelude::{create_tx, create_tx_ins, create_tx_outs},
    taproot::TaprootWitness,
};

use super::prelude::CovenantTx;

/// Data needed to construct a [`ChallengeTx`].
#[derive(Debug, Clone)]
pub struct ChallengeTxInput {
    pub claim_outpoint: OutPoint,
    pub challenge_amt: Amount,
    pub operator_pubkey: XOnlyPublicKey,
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
pub struct ChallengeTx {
    psbt: Psbt,

    prevouts: [TxOut; 1],
    witnesses: [TaprootWitness; 1],
}

impl ChallengeTx {
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

        let witnesses = [TaprootWitness::Tweaked { tweak }];

        let script_pubkey = challenge_connector.generate_locking_script();
        let prevouts = [TxOut {
            value: script_pubkey.minimal_non_dust(),
            script_pubkey,
        }];

        let input_index = tapleaf.get_input_index() as usize;
        psbt.inputs[input_index].witness_utxo = Some(prevouts[0].clone());
        psbt.inputs[input_index].sighash_type = Some(tapleaf.get_sighash_type().into());

        Self {
            psbt,

            prevouts,
            witnesses,
        }
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

impl CovenantTx<1> for ChallengeTx {
    fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    fn prevouts(&self) -> Prevouts<'_, TxOut> {
        // challenge is funded at the
        Prevouts::One(0, self.prevouts[0].clone())
    }

    fn witnesses(&self) -> &[TaprootWitness; 1] {
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
    use corepc_node::{Client, Conf, Node};
    use strata_bridge_primitives::{
        build_context::{BuildContext, TxBuildContext},
        scripts::taproot::create_message_hash,
    };
    use strata_bridge_test_utils::{
        bitcoin_rpc::fund_and_sign_raw_tx, musig2::generate_agg_signature,
        prelude::generate_keypair,
    };

    use super::*;

    #[test]
    fn test_challenge_tx_psbt() {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");

        let bitcoind =
            Node::from_downloaded_with_conf(&conf).expect("must be able to start bitcoind");
        let btc_client = &bitcoind.client;
        let partially_signed_challenge_tx = prepare_partially_signed_challenge_tx(btc_client);

        let signed_challenge_tx =
            fund_and_sign_raw_tx(btc_client, &partially_signed_challenge_tx, None, Some(true));

        btc_client
            .send_raw_transaction(&signed_challenge_tx)
            .expect("must be able to send tx");
    }

    fn prepare_partially_signed_challenge_tx(btc_client: &Client) -> Transaction {
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

        challenge_tx.finalize_presigned(challenge_connector, signed_challenge_leaf)
    }
}
