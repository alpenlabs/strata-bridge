use bitcoin::{
    psbt::Input,
    taproot::{ControlBlock, LeafVersion, TaprootSpendInfo},
    Address, Network, ScriptBuf, XOnlyPublicKey,
};
use secp256k1::schnorr;
use strata_bridge_primitives::{
    params::{connectors::SUPERBLOCK_MEASUREMENT_PERIOD, prelude::PRE_ASSERT_TIMELOCK},
    scripts::prelude::*,
};

/// Connector from the claim transaction used in optimistic payouts or assertions.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorC0 {
    n_of_n_agg_pubkey: XOnlyPublicKey,
    network: Network,
}

/// Spend paths for the [`ConnectorC0`].
#[derive(Debug, Clone, Copy)]
pub enum ConnectorC0Leaf<Witness = ()> {
    /// Spend path for the optimistic payout.
    PayoutOptimistic(Witness),

    /// Spend path for the pre-assert transaction.
    Assert(Witness),

    /// Send path for the invalidate transaction.
    InvalidateTs(Witness),
}

impl<W> ConnectorC0Leaf<W>
where
    W: Sized,
{
    pub(super) fn generate_locking_script(&self, n_of_n_agg_pubkey: &XOnlyPublicKey) -> ScriptBuf {
        match self {
            ConnectorC0Leaf::PayoutOptimistic(_) => {
                n_of_n_with_timelock(n_of_n_agg_pubkey, PRE_ASSERT_TIMELOCK)
            }
            ConnectorC0Leaf::Assert(_) => n_of_n_script(n_of_n_agg_pubkey),
            ConnectorC0Leaf::InvalidateTs(_) => {
                n_of_n_with_timelock(n_of_n_agg_pubkey, SUPERBLOCK_MEASUREMENT_PERIOD)
            }
        }
    }

    pub fn add_witness_data<NW: Sized>(self, witness_data: NW) -> ConnectorC0Leaf<NW> {
        match self {
            ConnectorC0Leaf::PayoutOptimistic(_) => ConnectorC0Leaf::PayoutOptimistic(witness_data),
            ConnectorC0Leaf::Assert(_) => ConnectorC0Leaf::Assert(witness_data),
            ConnectorC0Leaf::InvalidateTs(_) => ConnectorC0Leaf::InvalidateTs(witness_data),
        }
    }

    pub fn get_witness_data(&self) -> &W {
        match self {
            ConnectorC0Leaf::PayoutOptimistic(witness_data) => witness_data,
            ConnectorC0Leaf::Assert(witness_data) => witness_data,
            ConnectorC0Leaf::InvalidateTs(witness_data) => witness_data,
        }
    }
}

impl ConnectorC0 {
    /// Constructs a new instance of this connector.
    pub fn new(n_of_n_agg_pubkey: XOnlyPublicKey, network: Network) -> Self {
        Self {
            n_of_n_agg_pubkey,
            network,
        }
    }

    /// Generates the locking script for this connector.
    pub fn generate_locking_script(&self) -> ScriptBuf {
        let (address, _) = self.generate_taproot_address();

        address.script_pubkey()
    }

    /// Generates the taproot spend info for the given leaf.
    ///
    /// The witness data is not required to generate this information. So, a unit type can be
    /// passed in place of the witness parameter.
    pub fn generate_spend_info<W: Sized>(
        &self,
        tapleaf: ConnectorC0Leaf<W>,
    ) -> (ScriptBuf, ControlBlock) {
        let (_, taproot_spend_info) = self.generate_taproot_address();

        let script = tapleaf.generate_locking_script(&self.n_of_n_agg_pubkey);
        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script is always present in the address");

        (script, control_block)
    }

    /// Constructs the taproot address for this connector along with the spending info.
    pub fn generate_taproot_address(&self) -> (Address, TaprootSpendInfo) {
        let scripts = &[
            ConnectorC0Leaf::PayoutOptimistic(()),
            ConnectorC0Leaf::Assert(()),
            ConnectorC0Leaf::InvalidateTs(()),
        ]
        .map(|leaf| leaf.generate_locking_script(&self.n_of_n_agg_pubkey));

        create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
            .expect("should be able to create taproot address")
    }

    /// Finalizes the psbt input that spends this connector.
    ///
    /// This requires that the connector leaf contain the schnorr signature as the witness.
    pub fn finalize_input(&self, input: &mut Input, tapleaf: ConnectorC0Leaf<schnorr::Signature>) {
        if let ConnectorC0Leaf::InvalidateTs(_) = tapleaf {
            // do nothing since this does not take an n_of_n sig
            return;
        }

        let (script, control_block) = self.generate_spend_info(tapleaf);
        let n_of_n_signature = *tapleaf.get_witness_data();

        finalize_input(
            input,
            [
                n_of_n_signature.serialize().to_vec(),
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
    fn test_connector_c0() {
        logging::init(LoggerConfig::new("test-connector-c0".to_string()));

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
        let connector = ConnectorC0::new(n_of_n_agg_pubkey, network);

        const INPUT_AMOUNT: Amount = Amount::from_sat(1_000_000);
        const NUM_OUTPUTS: usize = 2;
        const LEAVES: [ConnectorC0Leaf; NUM_OUTPUTS] = [
            ConnectorC0Leaf::PayoutOptimistic(()),
            ConnectorC0Leaf::Assert(()),
        ];
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
                if let ConnectorC0Leaf::PayoutOptimistic(_) = leaf {
                    spend_connector_tx.input[0].sequence =
                        Sequence::from_height(PRE_ASSERT_TIMELOCK as u16);
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
                    bitcoin::TapSighashType::Default,
                    0,
                )
                .expect("must be able create a message hash for tx");
                let signature = SECP256K1.sign_schnorr(&tx_hash, &keypair);
                let leaf_with_witness = leaf.add_witness_data(signature);

                connector.finalize_input(&mut psbt.inputs[0], leaf_with_witness);

                let signed_tx = psbt
                    .extract_tx()
                    .expect("must be able to extract signed tx from psbt");

                if let ConnectorC0Leaf::PayoutOptimistic(_) = leaf {
                    assert!(
                        btc_client.send_raw_transaction(&signed_tx).is_err(),
                        "must not be able to send tx before timelock"
                    );

                    let random_address = btc_client
                        .new_address()
                        .expect("must be able to generate new address");

                    [0; PRE_ASSERT_TIMELOCK as usize]
                        .chunks(100)
                        .for_each(|chunk| {
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
