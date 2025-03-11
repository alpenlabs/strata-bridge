//! This module defines the [`BurnPayoutsTx`] transaction.
//!
//! This transaction is used to prevent an operator from getting the bridge funds using historical
//! claims even _after_ their stake has been slashed.

use alpen_bridge_params::tx::SEGWIT_MIN_AMOUNT;
use bitcoin::{sighash::Prevouts, Amount, Network, OutPoint, Psbt, Transaction, TxOut, Txid};
use bitcoin_bosd::Descriptor;
use strata_bridge_connectors::prelude::{ConnectorP, StakeSpendPath};
use strata_bridge_primitives::scripts::{
    prelude::{create_tx, create_tx_ins, create_tx_outs},
    taproot::TaprootWitness,
};

use super::prelude::CovenantTx;

/// The data required to create a [`BurnPayoutsTx`].
#[derive(Debug, Clone)]
pub struct BurnPayoutsTxInput {
    /// The outpoint of the stake transaction that is being spent.
    pub stake_out: OutPoint,

    /// The network that the transaction is valid on.
    pub network: Network,

    /// The [BOSD](bitcoin_bosd::Descriptor) that the locked funds are being sent to.
    pub recipient_addr: Descriptor,
}

/// The transaction used to prevent operator from getting the bridge funds using historical claims.
#[derive(Debug, Clone)]
pub struct BurnPayoutsTx {
    /// The psbt that contains the inputs and outputs for the transaction.
    psbt: Psbt,

    /// The prevouts that are being spent in the transaction.
    prevouts: Vec<TxOut>,

    /// The witnesses for the transaction used to spend a taproot output.
    witnesses: Vec<TaprootWitness>,
}

impl BurnPayoutsTx {
    /// Creates a new [`BurnPayoutsTx`] instance.
    ///
    /// The transaction it holds contains a single input that spends the output of the stake
    /// transaction with just the hashlock and a single output that spends the same amount to the
    /// recipient addr in [`BurnPayoutsTxInput`].
    pub fn new(input: BurnPayoutsTxInput, hashlock_connector: ConnectorP) -> Self {
        let tx_ins = create_tx_ins([input.stake_out]);
        let tx_outs = create_tx_outs([(input.recipient_addr.to_script(), SEGWIT_MIN_AMOUNT)]);

        let tx = create_tx(tx_ins, tx_outs);

        let mut psbt = Psbt::from_unsigned_tx(tx).expect("transaction must be unsigned");

        let prevout = TxOut {
            value: SEGWIT_MIN_AMOUNT,
            script_pubkey: hashlock_connector.generate_address().script_pubkey(),
        };

        psbt.inputs[0].witness_utxo = Some(prevout.clone());

        let (hashlock_script, control_block) = hashlock_connector.generate_spend_info();

        let witnesses = vec![TaprootWitness::Script {
            script_buf: hashlock_script,
            control_block,
        }];
        let prevouts = vec![prevout];

        Self {
            psbt,
            prevouts,
            witnesses,
        }
    }

    /// Finalizes the transaction with the preimage for the hashlock.
    ///
    /// NOTE: the returned transaction is not relay-safe as it has 0 fees. The caller must fund this
    /// transaction externally with the appropriate fees (for example, via the `fundrawtransaction`
    /// bitcoin RPC call).
    pub fn finalize(mut self, preimage: [u8; 32], hashlock_connector: ConnectorP) -> Transaction {
        let witness_data = StakeSpendPath::BurnPayouts(preimage);
        hashlock_connector.finalize(&mut self.psbt_mut().inputs[0], witness_data);

        self.psbt
            .extract_tx()
            .expect("transaction must be finalized")
    }
}

impl CovenantTx for BurnPayoutsTx {
    fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    fn prevouts(&self) -> Prevouts<'_, TxOut> {
        const INPUT_INDEX: usize = 0;
        Prevouts::One(INPUT_INDEX, self.prevouts[INPUT_INDEX].clone())
    }

    fn witnesses(&self) -> &[TaprootWitness] {
        &self.witnesses
    }

    fn input_amount(&self) -> Amount {
        self.prevouts.iter().map(|txout| txout.value).sum()
    }

    fn compute_txid(&self) -> Txid {
        self.psbt.unsigned_tx.compute_txid()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use bitcoin::hashes::{self, Hash};
    use corepc_node::{Conf, Node};
    use secp256k1::rand::{rngs::OsRng, Rng};
    use strata_bridge_primitives::build_context::{BuildContext, TxBuildContext};
    use strata_bridge_test_utils::{
        bitcoin_rpc::{fund_and_sign_raw_tx, get_raw_transaction},
        prelude::generate_keypair,
    };

    use super::*;

    #[test]
    fn test_burn_payouts_tx() {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        let bitcoind = Node::from_downloaded_with_conf(&conf).unwrap();
        let btc_client = &bitcoind.client;

        let network = btc_client.get_blockchain_info().unwrap().chain;
        let network = Network::from_str(&network).unwrap();

        let source_addr = btc_client.new_address().unwrap();
        btc_client.generate_to_address(101, &source_addr).unwrap();

        let n_of_n_keypair = generate_keypair();
        let operator_pubkey = n_of_n_keypair.public_key();
        let operator_pubkeys = BTreeMap::from([(0, operator_pubkey)]);
        let context = TxBuildContext::new(network, operator_pubkeys.into(), 0);
        let n_of_n_agg_pubkey = context.aggregated_pubkey();

        let preimage: [u8; 32] = OsRng.gen();
        let stake_hash = hashes::sha256::Hash::hash(&preimage);
        let hashlock_connector = ConnectorP::new(n_of_n_agg_pubkey, stake_hash, network);

        let hashlock_addr = hashlock_connector.generate_address();
        let source_tx = btc_client
            .send_to_address(&hashlock_addr, SEGWIT_MIN_AMOUNT)
            .unwrap();
        btc_client.generate_to_address(6, &hashlock_addr).unwrap();

        let source_txid = source_tx.txid().unwrap();
        let source_tx = get_raw_transaction(btc_client, &source_txid);

        let vout = source_tx
            .output
            .iter()
            .position(|txout| txout.script_pubkey == hashlock_addr.script_pubkey())
            .unwrap();

        let recipient_key = generate_keypair().x_only_public_key().0;
        let recipient_addr = Descriptor::new_p2tr_unchecked(&recipient_key.serialize());

        let burn_payouts_tx_input = BurnPayoutsTxInput {
            stake_out: OutPoint {
                txid: source_txid,
                vout: vout as u32,
            },
            network,
            recipient_addr,
        };

        let burn_payouts_tx = BurnPayoutsTx::new(burn_payouts_tx_input, hashlock_connector);
        let signed_burn_payouts_tx = burn_payouts_tx.finalize(preimage, hashlock_connector);

        let funded_burn_payouts_tx =
            fund_and_sign_raw_tx(btc_client, &signed_burn_payouts_tx, None, Some(true));

        btc_client
            .send_raw_transaction(&funded_burn_payouts_tx)
            .expect("must be able to settle the burn payouts tx");
    }
}
