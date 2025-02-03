use bitcoin::{
    hashes::{sha256, Hash},
    opcodes::all::{OP_EQUALVERIFY, OP_SHA256, OP_SIZE},
    psbt::Input,
    taproot::{ControlBlock, LeafVersion},
    Address, Network, ScriptBuf,
};
use secp256k1::XOnlyPublicKey;
use strata_bridge_primitives::scripts::prelude::*;

use crate::connectors::witness_data::WitnessData;

/// The connector to decide whether the operator's stake can be used for a withdrawal (Payout
/// Optimistic) or not (Burn Payouts).
///
/// It is used in the Payout Optimistic and Burn Payouts transactions.
///
/// To illustrate the concept, let's say that an operator wants to claim the `k`th bridged-in UTXO.
/// For this, they need the `k`th Claim Transaction and hence the `k`th stake transaction. An
/// operator is not required to periodically advance the stake chain, so it may be the case that
/// they have only posted the `k-n`th stake chain. In this case, they post the next `n` stake
/// transactions at an interval of `ΔS`. We can set the value of `ΔS` to a small enough value while
/// still preventing an operator from spamming the system with faulty claims. Once the chain has
/// been advanced, they can use the `k`th stake to make their claim.
///
/// If the operator tries to advance the chain to the `k+1`th stake, they are required to reveal a
/// pre-image (publicly) on bitcoin. Using this stake, anybody can post the Burn Payouts transaction
/// which renders it impossible for an operator to receive a payout (optimistically or otherwise).
///
/// If the operator has received a `k`th Payout Optimistic or Payout transaction, they can advance
/// the stake chain (revealing the pre-image) without fear. It is the responsibility of the
/// [`ConnectorP`] and [`ConnectorStake`](super::connector_s::ConnectorStake) to ensure that will
/// make it impossible
///
/// # Security
///
/// An operator can only advance the stake chain if they reveal the pre-image. Hence, the operator
/// must be able to provide the pre-image to the [`ConnectorP`]. It is required that the preimage be
/// securely derived and never reused under any circumstances.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorP {
    /// The N-of-N aggregated public key for the operator set.
    n_of_n_agg_pubkey: XOnlyPublicKey,

    /// The hash of the `k`th stake preimage.
    ///
    /// It is used to derive the locking script and must be shared with between operators so that
    /// each operator can compute the transactions deterministically. This is important for
    /// validating transactions before operators offer up their signatures.
    stake_hash: sha256::Hash,

    /// The bitcoin network on which the connector operates.
    network: Network,
}

impl ConnectorP {
    /// Creates a new [`ConnectorP`] with the given N-of-N aggregated public key, `k`th stake
    /// preimage, and the bitcoin network.
    pub fn new(
        n_of_n_agg_pubkey: XOnlyPublicKey,
        stake_hash: sha256::Hash,
        network: Network,
    ) -> Self {
        Self {
            n_of_n_agg_pubkey,
            stake_hash,
            network,
        }
    }

    /// Generates the locking script for this connector if using the script spend path.
    ///
    /// # Implementation Details
    ///
    /// The locking script can be represented as the following miniscript policy:
    ///
    /// ```text
    /// sha256(stake_preimage)
    /// ```
    ///
    /// which compiles to the following script:
    ///
    /// ```text
    /// OP_SIZE <20> OP_EQUALVERIFY OP_SHA256 <stake_preimage> OP_EQUALVERIFY
    /// ```
    pub fn generate_script(&self) -> ScriptBuf {
        ScriptBuf::builder()
            .push_opcode(OP_SIZE)
            .push_int(0x20)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_SHA256)
            .push_slice(self.stake_hash.to_byte_array())
            .push_opcode(OP_EQUALVERIFY)
            .push_int(1)
            .into_script()
    }

    /// Creates a P2TR address with key spend path for the given operator set and a single script
    /// path that can be unlocked by revealing the pre-image.
    ///
    /// This is used to invalidate that a certain stake can be used in payouts by an operator in a
    /// Burn Payouts transaction.
    ///
    /// See [`Self::generate_script`] for the script implementation details.
    pub fn generate_address(&self) -> Address {
        let script = self.generate_script();
        let (taproot_address, _) = create_taproot_addr(
            &self.network,
            SpendPath::Both {
                internal_key: self.n_of_n_agg_pubkey,
                scripts: &[script],
            },
        )
        .expect("should be able to create taproot address");

        taproot_address
    }

    /// Generates the spending info for the address.
    pub fn generate_spend_info(&self) -> (ScriptBuf, ControlBlock) {
        let script = self.generate_script();
        let (_, taproot_spending_info) = create_taproot_addr(
            &self.network,
            SpendPath::Both {
                internal_key: self.n_of_n_agg_pubkey,
                scripts: &[script],
            },
        )
        .expect("should be able to create taproot address");

        let script = self.generate_script();
        let control_block = taproot_spending_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script is always present in the address");

        (script, control_block)
    }

    /// Finalizes a psbt input where this connector is used with the provided `witness_data`.
    ///
    /// Depending on the `witness_data` it will be used either a key or scripth path spend.
    ///
    /// # Note
    ///
    /// This method does not check if the `witness_data` is valid for the input, deferring the
    /// validation to the caller.
    ///
    /// If the psbt input is already in the final state, then this method overrides the signature.
    pub fn create_tx_input(&self, witness_data: WitnessData, input: &mut Input) {
        match witness_data {
            WitnessData::Signature(signature) => {
                finalize_input(input, [&signature.serialize().to_vec()]);
            }
            WitnessData::Preimage(preimage) => {
                finalize_input(input, [&preimage]);
            }
            _ => (), // other variants are no-op.
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute, consensus, transaction, Amount, BlockHash, OutPoint, Transaction, TxIn, TxOut,
        Witness,
    };
    use corepc_node::{serde_json::json, Conf, Node};
    use strata_bridge_test_utils::prelude::generate_keypair;
    use strata_btcio::rpc::types::SignRawTransactionWithWallet;
    use strata_common::logging::{self, LoggerConfig};
    use tracing::info;

    use super::*;

    #[test]
    fn connector_p_script_path() {
        logging::init(LoggerConfig::new("connector-p-script-path".to_string()));

        // Setup Bitcoin node
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        let bitcoind = Node::from_downloaded_with_conf(&conf).unwrap();
        let btc_client = &bitcoind.client;

        // Get network
        let network = btc_client
            .get_blockchain_info()
            .expect("must get blockchain info")
            .chain;
        let network = network.parse::<Network>().expect("network must be valid");

        // Mine until maturity
        let funded_address = btc_client.new_address().unwrap();
        let change_address = btc_client.new_address().unwrap();
        let coinbase_block = btc_client
            .generate_to_address(101, &funded_address)
            .expect("must be able to generate blocks")
            .0
            .first()
            .expect("must be able to get the blocks")
            .parse::<BlockHash>()
            .expect("must parse");
        let coinbase_txid = btc_client
            .get_block(coinbase_block)
            .expect("must be able to get coinbase block")
            .coinbase()
            .expect("must be able to get the coinbase transaction")
            .compute_txid();

        // Generate keys and preimage
        let n_of_n_keypair = generate_keypair();
        let n_of_n_pubkey = n_of_n_keypair.x_only_public_key().0;
        let stake_preimage = [1u8; 32];
        let stake_hash = sha256::Hash::hash(&stake_preimage);

        // Create connector
        let connector_p = ConnectorP::new(n_of_n_pubkey, stake_hash, network);

        // Create funding transaction
        let funding_input = OutPoint {
            txid: coinbase_txid,
            vout: 0,
        };

        let coinbase_amount = Amount::from_btc(50.0).expect("must be valid amount");
        let funding_amount = Amount::from_sat(50_000);
        let fees = Amount::from_sat(1_000);

        let input = vec![TxIn {
            previous_output: funding_input,
            script_sig: funded_address.script_pubkey(),
            ..Default::default()
        }];

        let output = vec![
            TxOut {
                value: funding_amount,
                script_pubkey: connector_p.generate_address().script_pubkey(),
            },
            TxOut {
                value: coinbase_amount
                    .checked_sub(funding_amount)
                    .unwrap()
                    .checked_sub(fees)
                    .unwrap(),
                script_pubkey: change_address.script_pubkey(),
            },
        ];

        let funding_tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };

        // Sign and broadcast funding transaction
        let signed_funding_tx = btc_client
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[json!(consensus::encode::serialize_hex(&&funding_tx))],
            )
            .expect("must be able to sign transaction");

        assert!(signed_funding_tx.complete);
        let signed_funding_tx =
            consensus::encode::deserialize_hex(&signed_funding_tx.hex).expect("must deserialize");

        let funding_txid = btc_client
            .send_raw_transaction(&signed_funding_tx)
            .expect("must be able to broadcast transaction")
            .txid()
            .expect("must have txid");

        info!(%funding_txid, "Funding transaction broadcasted");

        // Mine the funding transaction
        let _ = btc_client
            .generate_to_address(1, &funded_address)
            .expect("must be able to generate blocks");

        // Create spending transaction that spends the connector p
        let spending_input = OutPoint {
            txid: funding_txid,
            vout: 0,
        };

        let spending_output = TxOut {
            value: funding_amount.checked_sub(fees).unwrap(),
            script_pubkey: change_address.script_pubkey(),
        };

        let mut spending_tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: spending_input,
                ..Default::default()
            }],
            output: vec![spending_output],
        };

        // Create the locking script
        let locking_script = connector_p.generate_script();

        // Get taproot spend info
        let (_, control_block) = connector_p.generate_spend_info();

        // Construct the witness stack
        let mut witness = Witness::new();
        witness.push(stake_preimage);
        witness.push(locking_script.to_bytes());
        witness.push(control_block.serialize());

        // Set the witness in the transaction
        spending_tx.input[0].witness = witness;

        // Broadcast spending transaction
        let spending_txid = btc_client
            .send_raw_transaction(&spending_tx)
            .expect("must be able to broadcast spending transaction")
            .txid()
            .expect("must have txid");

        info!(%spending_txid, "Spending transaction broadcasted");

        // Verify the transaction was mined
        btc_client
            .generate_to_address(1, &funded_address)
            .expect("must be able to generate block");

        let tx = btc_client
            .call::<String>("getrawtransaction", &[json!(&spending_txid)])
            .expect("must be able to get transaction");
        let tx = consensus::encode::deserialize_hex::<Transaction>(&tx).expect("must deserialize");

        assert_eq!(spending_txid, tx.compute_txid());
    }
}
