use bitcoin::{
    opcodes::all::{OP_EQUALVERIFY, OP_SHA256, OP_SIZE},
    psbt::Input,
    Address, Network, ScriptBuf,
};
use secp256k1::{schnorr::Signature, XOnlyPublicKey};
use strata_bridge_primitives::{params::tx::UNSPENDABLE_INTERNAL_KEY, scripts::prelude::*};

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
/// must be able to provide the pre-image to the [`ConnectorP`]. It is advised to use a secure
/// storage mechanism to store the pre-image, and optionally a deterministic key derivation function
/// to derive the pre-image from something such as an operator's master entropy.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorP {
    /// The N-of-N aggregated public key for the operator set.
    n_of_n_agg_pubkey: XOnlyPublicKey,

    /// The corresponding pre-image for the `k`th stake.
    ///
    /// This is a 32-byte array, that should be generated securely from the operator's master
    /// entropy along with the `k`th stake's index.
    ///
    /// A suggestion is to hash them together, i.e. SHA256(master entropy || stake_index), and take
    /// the 32 bytes of the resulting hash.
    stake_preimage: [u8; 32],

    /// The bitcoin network on which the connector operates.
    network: Network,
}

impl ConnectorP {
    /// Creates a new [`ConnectorP`] with the given N-of-N aggregated public key, `k`th stake
    /// preimage, and the bitcoin network.
    pub fn new(
        n_of_n_agg_pubkey: XOnlyPublicKey,
        stake_preimage: [u8; 32],
        network: Network,
    ) -> Self {
        Self {
            n_of_n_agg_pubkey,
            stake_preimage,
            network,
        }
    }

    /// Creates a P2TR address with key spend path for the given operator set and no script paths.
    ///
    /// This is used both in the Disprove and in the Slash Stake `k` transactions.
    pub fn create_n_of_n(&self) -> Address {
        let (addr, _spend_info) = create_taproot_addr(
            &self.network,
            SpendPath::KeySpend {
                internal_key: self.n_of_n_agg_pubkey,
            },
        )
        .expect("must be able to create taproot address");

        addr
    }

    /// Creates a P2TR address with an unspendable key spend path and a single script path that can
    /// be unlocked by revealing the pre-image.
    ///
    /// This is used to invalidate that a certain stake can be used in payouts by an operator in a
    /// Burn Payouts transaction.
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
    pub fn create_pre_image(&self) -> ScriptBuf {
        let script = ScriptBuf::builder()
            .push_opcode(OP_SIZE)
            .push_int(20)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_SHA256)
            .push_slice(self.stake_preimage)
            .push_opcode(OP_EQUALVERIFY)
            .into_script();
        let (taproot_address, _) = create_taproot_addr(
            &self.network,
            SpendPath::Both {
                internal_key: *UNSPENDABLE_INTERNAL_KEY,
                scripts: &[script],
            },
        )
        .expect("should be able to create taproot address");

        taproot_address.script_pubkey()
    }

    /// Finalizes a psbt input where this connector is used with the provided signature.
    ///
    /// # Note
    ///
    /// This method does not check if the signature is valid for the input. It is the caller's
    /// responsibility to ensure that the signature is valid.
    ///
    /// If the psbt input is already in the final state, then this method overrides the signature.
    pub fn create_tx_input(&self, signature: Signature, input: &mut Input) {
        finalize_input(input, [signature.as_ref()]);
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute, consensus, taproot::LeafVersion, transaction, Amount, BlockHash, OutPoint,
        Transaction, TxIn, TxOut, Witness,
    };
    use corepc_node::{serde_json::json, Conf, Node};
    use strata_bridge_test_utils::prelude::generate_keypair;
    use strata_btcio::rpc::types::SignRawTransactionWithWallet;
    use strata_common::logging::{self, LoggerConfig};
    use tracing::info;

    use super::*;

    #[test]
    fn test_create_pre_image() {
        logging::init(LoggerConfig::new("test-pre-image".to_string()));

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

        // Create connector
        let connector_p = ConnectorP::new(n_of_n_pubkey, stake_preimage, network);

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
                script_pubkey: connector_p.create_pre_image(),
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
        let locking_script = ScriptBuf::builder()
            .push_opcode(OP_SIZE)
            .push_int(20)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_SHA256)
            .push_slice(stake_preimage)
            .push_opcode(OP_EQUALVERIFY)
            .into_script();

        // Get taproot spend info
        let (_, taproot_spend_info) = create_taproot_addr(
            &network,
            SpendPath::Both {
                internal_key: *UNSPENDABLE_INTERNAL_KEY,
                scripts: &[locking_script.clone()],
            },
        )
        .expect("should be able to create taproot address");

        let control_block = taproot_spend_info
            .control_block(&(locking_script.clone(), LeafVersion::TapScript))
            .expect("must get control block");

        // Construct the witness stack
        let mut witness = Witness::new();
        witness.push(stake_preimage.to_vec());
        witness.push(locking_script.to_bytes());
        witness.push(&control_block.serialize());

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
