//! This module contains the connector from the first output of the Claim transaction.
//!
//! This connector is spent by either the Pre-Assert transaction if challenged or the
//! PayoutOptimistic transaction if unchallenged.
use bitcoin::{
    psbt::Input,
    taproot::{ControlBlock, LeafVersion, TaprootSpendInfo},
    Address, Network, ScriptBuf, TapNodeHash, TapSighashType, XOnlyPublicKey,
};
use secp256k1::schnorr;
use strata_bridge_primitives::scripts::prelude::*;

/// Spend paths for the [`ConnectorC0`].
///
/// The witness may not be known (hence, `()`) in use cases where the input index or sighash type
/// needs to be retrieved corresponding to the leaf whereas the witness ([`schnorr::Signature`])
/// must be known when a path is used when spending the output.
#[derive(Debug, Clone, Copy)]
pub enum ConnectorC0Path<Witness = ()> {
    /// Spend path for the optimistic payout.
    PayoutOptimistic(Witness),

    /// Spend path for the pre-assert transaction.
    Assert(Witness),
}

impl<W> ConnectorC0Path<W>
where
    W: Sized,
{
    /// Returns the input index of the transaction for the given spend path.
    pub fn get_input_index(&self) -> u32 {
        match self {
            ConnectorC0Path::PayoutOptimistic(_) => 1,
            ConnectorC0Path::Assert(_) => 0,
        }
    }

    /// Returns the sighash type for the given spend path.
    pub fn get_sighash_type(&self) -> TapSighashType {
        match self {
            ConnectorC0Path::PayoutOptimistic(_) => TapSighashType::Default,
            ConnectorC0Path::Assert(_) => TapSighashType::Default,
        }
    }

    /// Adds a new witness to the path thereby creating a new path.
    pub fn add_witness_data<NW: Sized>(self, witness_data: NW) -> ConnectorC0Path<NW> {
        match self {
            ConnectorC0Path::PayoutOptimistic(_) => ConnectorC0Path::PayoutOptimistic(witness_data),
            ConnectorC0Path::Assert(_) => ConnectorC0Path::Assert(witness_data),
        }
    }

    /// Returns the witness data for the path.
    pub fn get_witness_data(&self) -> &W {
        match self {
            ConnectorC0Path::PayoutOptimistic(witness_data) => witness_data,
            ConnectorC0Path::Assert(witness_data) => witness_data,
        }
    }
}

/// Connector from the claim transaction used in optimistic payouts or assertions.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorC0 {
    n_of_n_agg_pubkey: XOnlyPublicKey,
    network: Network,
    pre_assert_timelock: u32,
}

impl ConnectorC0 {
    /// Constructs a new instance of this connector.
    pub fn new(
        n_of_n_agg_pubkey: XOnlyPublicKey,
        network: Network,
        pre_assert_timelock: u32,
    ) -> Self {
        Self {
            n_of_n_agg_pubkey,
            network,
            pre_assert_timelock,
        }
    }

    /// Returns the relative timelock on the pre-assert output (measured in number of blocks).
    pub fn pre_assert_timelock(&self) -> u32 {
        self.pre_assert_timelock
    }

    /// Generate the payout script.
    fn generate_payout_script(&self) -> ScriptBuf {
        n_of_n_with_timelock(&self.n_of_n_agg_pubkey, self.pre_assert_timelock).compile()
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
    pub fn generate_spend_info(&self) -> (ScriptBuf, ControlBlock) {
        let (_, taproot_spend_info) = self.generate_taproot_address();

        let script = self.generate_payout_script();
        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script is always present in the address");

        (script, control_block)
    }

    /// Constructs the taproot address for this connector along with the spending info.
    pub fn generate_taproot_address(&self) -> (Address, TaprootSpendInfo) {
        let scripts = &[self.generate_payout_script()];

        create_taproot_addr(
            &self.network,
            SpendPath::Both {
                internal_key: self.n_of_n_agg_pubkey,
                scripts,
            },
        )
        .expect("should be able to create taproot address")
    }

    /// Generates the merkle root for the connector for tweaking taproot keys.
    pub fn generate_merkle_root(&self) -> TapNodeHash {
        let payout_script = self.generate_payout_script();

        TapNodeHash::from_script(&payout_script, LeafVersion::TapScript)
    }

    /// Finalizes the psbt input that spends this connector.
    ///
    /// This requires that the connector leaf contain the schnorr signature as the witness.
    pub fn finalize_input(&self, input: &mut Input, tapleaf: ConnectorC0Path<schnorr::Signature>) {
        let witnesses = match tapleaf {
            ConnectorC0Path::PayoutOptimistic(n_of_n_sig) => vec![n_of_n_sig.serialize().to_vec()],
            ConnectorC0Path::Assert(n_of_n_sig) => {
                let (script, control_block) = self.generate_spend_info();

                vec![
                    n_of_n_sig.serialize().to_vec(),
                    script.to_bytes(),
                    control_block.serialize(),
                ]
            }
        };

        finalize_input(input, witnesses);
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{
        key::TapTweak,
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
        let pre_assert_timelock: u32 = 250;
        let connector = ConnectorC0::new(n_of_n_agg_pubkey, network, pre_assert_timelock);

        const INPUT_AMOUNT: Amount = Amount::from_sat(1_000_000);
        const NUM_OUTPUTS: usize = 2;
        const LEAVES: [ConnectorC0Path; NUM_OUTPUTS] = [
            ConnectorC0Path::PayoutOptimistic(()),
            ConnectorC0Path::Assert(()),
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
                let (witness, keypair) = match leaf {
                    ConnectorC0Path::PayoutOptimistic(_) => {
                        let tweak = connector.generate_merkle_root();
                        (
                            TaprootWitness::Tweaked { tweak },
                            keypair.tap_tweak(SECP256K1, Some(tweak)).to_inner(),
                        )
                    }
                    ConnectorC0Path::Assert(_) => {
                        spend_connector_tx.input[0].sequence =
                            Sequence::from_height(pre_assert_timelock as u16);
                        let (script, control_block) = connector.generate_spend_info();
                        (
                            TaprootWitness::Script {
                                script_buf: script,
                                control_block,
                            },
                            keypair,
                        )
                    }
                };
                if let ConnectorC0Path::PayoutOptimistic(_) = leaf {
                    spend_connector_tx.input[0].sequence =
                        Sequence::from_height(pre_assert_timelock as u16);
                }

                let mut psbt =
                    Psbt::from_unsigned_tx(spend_connector_tx.clone()).expect("must be unsigned");

                psbt.inputs[0].witness_utxo = Some(prevout.clone());

                let tx_hash = create_message_hash(
                    &mut SighashCache::new(&spend_connector_tx),
                    Prevouts::All(&[prevout.clone()]),
                    &witness,
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

                if let ConnectorC0Path::PayoutOptimistic(_) = leaf {
                    assert!(
                        btc_client.send_raw_transaction(&signed_tx).is_err(),
                        "must not be able to send tx before timelock"
                    );

                    let random_address = btc_client
                        .new_address()
                        .expect("must be able to generate new address");

                    vec![(); pre_assert_timelock as usize]
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
