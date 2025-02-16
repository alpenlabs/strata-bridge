//! This module contains connector for the first output of the PostAssert transaction.
// FIXME: remove this connector once the stake chain is integrated.
use bitcoin::{
    psbt::Input,
    taproot::{self, ControlBlock, LeafVersion, TaprootSpendInfo},
    Address, Network, ScriptBuf, TapSighashType, XOnlyPublicKey,
};
use secp256k1::schnorr;
use strata_bridge_primitives::{params::connectors::PAYOUT_TIMELOCK, scripts::prelude::*};

/// Connector from the PostAssert transaction.
///
/// This connector is spent either by the Payout transaction to recover the stake or by the Disprove
/// transaction to slash the stake.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorA30 {
    n_of_n_agg_pubkey: XOnlyPublicKey,

    network: Network,
}

/// Possible spending paths for the [`ConnectorA30`].
///
/// The witness may not be known (hence, `()`) in use cases where a locking script needs to be
/// generated corresponding to the leaf whereas it must be known ([`schnorr::Signature`]) when a
/// leaf is spent.
#[derive(Debug, Clone, Copy)]
pub enum ConnectorA30Leaf<Witness = ()> {
    /// The leaf used in the Payout transaction.
    Payout(Witness),
    /// The leaf used in the Disprove transaction.
    Disprove(Witness),
}

impl<W> ConnectorA30Leaf<W>
where
    W: Sized,
{
    /// Generates the locking script for this leaf.
    pub fn generate_locking_script(&self, n_of_n_agg_pubkey: &XOnlyPublicKey) -> ScriptBuf {
        match self {
            ConnectorA30Leaf::Payout(_) => n_of_n_with_timelock(n_of_n_agg_pubkey, PAYOUT_TIMELOCK),
            ConnectorA30Leaf::Disprove(_) => n_of_n_script(n_of_n_agg_pubkey),
        }
    }

    /// Returns the input index for the leaf.
    ///
    /// The `Payout` leaf is spent in the second input of the `Payout` transaction,
    /// whereas the `Disprove` leaf is spent in the first input of the `Disprove` transaction.
    pub fn get_input_index(&self) -> u32 {
        match self {
            ConnectorA30Leaf::Payout(_) => 1,
            ConnectorA30Leaf::Disprove(_) => 0,
        }
    }

    /// Returns the sighash type for each of the connector leaves.
    pub fn get_sighash_type(&self) -> TapSighashType {
        match self {
            ConnectorA30Leaf::Payout(_) => TapSighashType::Default,
            ConnectorA30Leaf::Disprove(_) => TapSighashType::Single,
        }
    }

    /// Adds the witness data to the leaf.
    pub fn add_witness_data<NW: Sized>(self, witness_data: NW) -> ConnectorA30Leaf<NW> {
        match self {
            ConnectorA30Leaf::Payout(_) => ConnectorA30Leaf::Payout(witness_data),
            ConnectorA30Leaf::Disprove(_) => ConnectorA30Leaf::Disprove(witness_data),
        }
    }

    /// Returns the witness data for the leaf.
    pub fn get_witness_data(&self) -> &W {
        match self {
            ConnectorA30Leaf::Payout(data) => data,
            ConnectorA30Leaf::Disprove(data) => data,
        }
    }
}

impl ConnectorA30 {
    /// Constructs a new instance of this connector.
    pub fn new(n_of_n_agg_pubkey: XOnlyPublicKey, network: Network) -> Self {
        Self {
            n_of_n_agg_pubkey,
            network,
        }
    }

    /// Creates the locking script for this connector.
    pub fn generate_locking_script(&self) -> ScriptBuf {
        let (address, _) = self.generate_taproot_address();

        address.script_pubkey()
    }

    /// Creates the tapoot spend info for the given leaf.
    ///
    /// The witness data is not required to generate this information. So, a unit type can be
    /// passed in place of the witness parameter.
    pub fn generate_spend_info<W: Sized>(
        &self,
        tapleaf: ConnectorA30Leaf<W>,
    ) -> (ScriptBuf, ControlBlock) {
        let (_, taproot_spend_info) = self.generate_taproot_address();

        let script = tapleaf.generate_locking_script(&self.n_of_n_agg_pubkey);
        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script is always present in the address");

        (script, control_block)
    }

    fn generate_taproot_address(&self) -> (Address, TaprootSpendInfo) {
        let scripts = &[ConnectorA30Leaf::Payout(()), ConnectorA30Leaf::Disprove(())]
            .map(|leaf| leaf.generate_locking_script(&self.n_of_n_agg_pubkey));

        create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
            .expect("should be able to create taproot address")
    }

    /// Finalizes the input for the psbt that spends this connector.
    ///
    /// This requires that the connector leaf contain the schnorr signature as the witness.
    pub fn finalize_input(&self, input: &mut Input, tapleaf: ConnectorA30Leaf<schnorr::Signature>) {
        let (script, control_block) = self.generate_spend_info(tapleaf);

        let sighash_type = tapleaf.get_sighash_type();
        let signature = *tapleaf.get_witness_data();

        let signature = taproot::Signature {
            signature,
            sighash_type,
        };

        finalize_input(
            input,
            [
                signature.serialize().to_vec(),
                script.to_bytes(),
                control_block.serialize(),
            ],
        );
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{
        sighash::{Prevouts, SighashCache},
        Amount, Psbt, Sequence, TxOut,
    };
    use corepc_node::{Conf, Node};
    use secp256k1::SECP256K1;
    use strata_bridge_test_utils::{prelude::generate_keypair, tx::get_connector_txs};
    use strata_common::logging::{self, LoggerConfig};
    use tracing::debug;

    use super::*;

    #[test]
    fn test_connector_a30() {
        logging::init(LoggerConfig::new("test-connector-a30".to_string()));

        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        let bitcoind = Node::from_downloaded_with_conf(&conf).unwrap();
        let btc_client = &bitcoind.client;

        let network = btc_client
            .get_blockchain_info()
            .expect("must get blockchain info")
            .chain;
        let network = Network::from_str(&network).expect("network must be valid");

        let keypair = generate_keypair();

        let n_of_n_agg_pubkey = keypair.x_only_public_key().0;
        let connector = ConnectorA30::new(n_of_n_agg_pubkey, network);

        const INPUT_AMOUNT: Amount = Amount::from_sat(1_000_000);
        const NUM_OUTPUTS: usize = 2;
        const LEAVES: [ConnectorA30Leaf; NUM_OUTPUTS] =
            [ConnectorA30Leaf::Payout(()), ConnectorA30Leaf::Disprove(())];
        let spend_connector_txs = get_connector_txs::<NUM_OUTPUTS>(
            btc_client,
            INPUT_AMOUNT,
            connector.generate_taproot_address().0,
        );

        let prevout = TxOut {
            value: INPUT_AMOUNT,
            script_pubkey: connector.generate_locking_script(),
        };

        LEAVES
            .iter()
            .zip(spend_connector_txs)
            .for_each(|(leaf, spend_connector_tx)| {
                debug!(?leaf, "testing leaf");

                let mut spend_connector_tx = spend_connector_tx;
                if let ConnectorA30Leaf::Payout(_) = leaf {
                    spend_connector_tx.input[0].sequence =
                        Sequence::from_height(PAYOUT_TIMELOCK as u16);
                }

                let mut psbt =
                    Psbt::from_unsigned_tx(spend_connector_tx.clone()).expect("must be unsigned");

                psbt.inputs[0].witness_utxo = Some(prevout.clone());
                let (script, control_block) = connector.generate_spend_info(*leaf);

                let tx_hash = create_message_hash(
                    &mut SighashCache::new(&spend_connector_tx),
                    Prevouts::All(&[prevout.clone()]),
                    &TaprootWitness::Script {
                        script_buf: script,
                        control_block,
                    },
                    leaf.get_sighash_type(),
                    0,
                )
                .expect("must be able create a message hash for tx");
                let signature = SECP256K1.sign_schnorr(&tx_hash, &keypair);
                let leaf_with_witness = leaf.add_witness_data(signature);

                connector.finalize_input(&mut psbt.inputs[0], leaf_with_witness);

                let signed_tx = psbt
                    .extract_tx()
                    .expect("must be able to extract signed tx from psbt");

                if let ConnectorA30Leaf::Payout(_) = leaf {
                    assert!(
                        btc_client.send_raw_transaction(&signed_tx).is_err(),
                        "must not be able to send tx before timelock"
                    );

                    let random_address = btc_client
                        .new_address()
                        .expect("must be able to generate new address");

                    [0; PAYOUT_TIMELOCK as usize].chunks(100).for_each(|chunk| {
                        btc_client
                            .generate_to_address(chunk.len(), &random_address)
                            .expect("must be able to mine blocks");
                    });
                }

                btc_client
                    .send_raw_transaction(&signed_tx)
                    .expect("must be able to send tx");
            });
    }
}
