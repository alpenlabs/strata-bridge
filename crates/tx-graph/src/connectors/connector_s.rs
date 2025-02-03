use bitcoin::{
    hashes::{sha256, Hash},
    opcodes::all::{OP_CHECKSIGVERIFY, OP_CSV, OP_EQUALVERIFY, OP_SHA256, OP_SIZE},
    psbt::Input,
    relative,
    taproot::{ControlBlock, LeafVersion},
    Address, Network, ScriptBuf,
};
use secp256k1::{schnorr::Signature, XOnlyPublicKey};
use strata_bridge_primitives::scripts::prelude::*;

use crate::connectors::witness_data::WitnessData;

/// The connector to move the operator's stake across transactions.
// TODO: Replace this with `ConnectorStake`.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorS {
    /// The N-of-N aggregated public key for the operator set.
    n_of_n_agg_pubkey: XOnlyPublicKey,

    /// The bitcoin network on which the connector operates.
    network: Network,
}

impl ConnectorS {
    /// Creates a new `ConnectorS` with the given N-of-N aggregated public key and the
    /// bitcoin network.
    pub fn new(n_of_n_agg_pubkey: XOnlyPublicKey, network: Network) -> Self {
        Self {
            n_of_n_agg_pubkey,
            network,
        }
    }

    /// Creates a taproot address with key spend path for the given operator set.
    pub fn create_taproot_address(&self) -> Address {
        let (addr, _spend_info) = create_taproot_addr(
            &self.network,
            SpendPath::KeySpend {
                internal_key: self.n_of_n_agg_pubkey,
            },
        )
        .expect("must be able to create taproot address");

        addr
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

/// The connector to move the operator's stake across Stake transactions.
///
/// It is used in the Disprove and Slash Stake `k` transactions, where `k` is the index of the
/// stake transaction.
///
/// The operator can also advance the stake chain by revealing the preimage, along with a valid
/// signature from the operator's public key.
/// Note that the stake advancement is done by the `stake-chain` crate.
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
/// preimage (publicly) on bitcoin. Using this stake, anybody can post the Burn Payouts transaction
/// which renders it impossible for an operator to receive a payout (optimistically or otherwise).
///
/// If the operator has received a `k`th Payout Optimistic or Payout transaction, they can advance
/// the stake chain (revealing the preimage) without fear. It is the responsibility of the
/// [`ConnectorP`](super::connector_p::ConnectorP) and [`ConnectorStake`] to ensure that will make
/// it impossible make it impossible
///
/// # Security
///
/// An operator can only advance the stake chain if they reveal the preimage along with a valid
/// signature from the operator's public key. Hence, the operator must must be able to provide the
/// preimage to the [`ConnectorStake`]. It is required that the preimage be securely derived and
/// never reused under any circumstances
// TODO: This should replace the `ConnectorS` struct above.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorStake {
    /// The N-of-N aggregated public key for the operator set.
    n_of_n_agg_pubkey: XOnlyPublicKey,

    /// The operator's public key.
    operator_pubkey: XOnlyPublicKey,

    /// The hash of the `k`th stake preimage.
    ///
    /// It is used to derive the locking script and must be shared with between operators so that
    /// each operator can compute the transactions deterministically. This is important for
    /// validating transactions before operators offer up their signatures.
    stake_hash: sha256::Hash,

    /// The `ΔS` interval relative timelock to advance the stake chain.
    delta: relative::LockTime,

    /// The bitcoin network on which the connector operates.
    network: Network,
}

impl ConnectorStake {
    /// Creates a new [`ConnectorStake`] with the given N-of-N aggregated public key, `k`th stake
    /// preimage, and the bitcoin network.
    pub fn new(
        n_of_n_agg_pubkey: XOnlyPublicKey,
        operator_pubkey: XOnlyPublicKey,
        stake_hash: sha256::Hash,
        delta: relative::LockTime,
        network: Network,
    ) -> Self {
        Self {
            n_of_n_agg_pubkey,
            operator_pubkey,
            stake_hash,
            delta,
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
    /// thresh(3,pk(operator_pubkey), sha256(stake_preimage), older(ΔS))
    /// ```
    ///
    /// which compiles to the following script:
    ///
    /// ```text
    /// <operator_pubkey> OP_CHECKSIGVERIFY OP_SIZE <20> OP_EQUALVERIFY OP_SHA256
    /// <stake_preimage> OP_EQUALVERIFY <ΔS> OP_CHECKSEQUENCEVERIFY
    /// ```
    pub fn generate_script(&self) -> ScriptBuf {
        ScriptBuf::builder()
            .push_slice(self.operator_pubkey.serialize())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_opcode(OP_SIZE)
            .push_int(0x20)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_SHA256)
            .push_slice(self.stake_hash.to_byte_array())
            .push_opcode(OP_EQUALVERIFY)
            .push_sequence(self.delta.into())
            .push_opcode(OP_CSV)
            .into_script()
    }

    /// Creates a P2TR address with key spend path for the given operator set and a single script
    /// path that can be unlocked by revealing the preimage, along with an operator signature and
    /// is timelocked by `ΔS`.
    ///
    /// This is used to advance the stake chain, slash the stake, and disprove the stake.
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
            WitnessData::SignaturePreimage {
                signature,
                preimage,
            } => finalize_input(
                input,
                // NOTE: Order matters here.
                vec![&preimage.to_vec(), &signature.serialize().to_vec()],
            ),
            _ => (), // other variants are no-op.
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute, consensus,
        hashes::Hash,
        sighash::{self, Prevouts, SighashCache},
        taproot::LeafVersion,
        transaction, Amount, BlockHash, OutPoint, TapLeafHash, Transaction, TxIn, TxOut, Witness,
    };
    use corepc_node::{serde_json::json, Conf, Node};
    use secp256k1::{Message, SECP256K1};
    use strata_bridge_test_utils::prelude::generate_keypair;
    use strata_btcio::rpc::types::SignRawTransactionWithWallet;
    use strata_common::logging::{self, LoggerConfig};
    use tracing::{info, trace};

    use super::*;

    #[test]
    fn connector_s_script_path() {
        logging::init(LoggerConfig::new("connector-s-script-path".to_string()));

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

        // Generate keys
        let n_of_n_keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let n_of_n_pubkey = n_of_n_keypair.x_only_public_key().0;
        let operator_pubkey = operator_keypair.x_only_public_key().0;

        // Generate stake preimage
        let stake_preimage = [1; 32];
        let stake_hash = sha256::Hash::hash(&stake_preimage);

        // Create relative timelock (e.g., 10 blocks)
        let delta = relative::LockTime::from_height(10);

        // Create connector
        let connector_s =
            ConnectorStake::new(n_of_n_pubkey, operator_pubkey, stake_hash, delta, network);

        // Generate address and script
        let taproot_script = connector_s.generate_address().script_pubkey();

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
                script_pubkey: taproot_script.clone(),
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

        // Sign the transaction
        let signed_funding_tx = btc_client
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[json!(consensus::encode::serialize_hex(&&funding_tx))],
            )
            .expect("must be able to sign transaction");

        assert!(signed_funding_tx.complete);
        let signed_funding_tx =
            consensus::encode::deserialize_hex(&signed_funding_tx.hex).expect("must deserialize");

        // Broadcast the funding transaction
        let funding_txid = btc_client
            .send_raw_transaction(&signed_funding_tx)
            .expect("must be able to broadcast transaction")
            .txid()
            .expect("must have txid");

        info!(%funding_txid, "Funding transaction broadcasted");

        // Mine the funding transaction with sufficient blocks for the relative timelock
        let _ = btc_client
            .generate_to_address((delta.to_consensus_u32() as usize) + 1, &funded_address)
            .expect("must be able to generate blocks");

        // Create the transaction that spents the connector s
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
                sequence: delta.into(), // Important: Set the sequence number to match the timelock
                ..Default::default()
            }],
            output: vec![spending_output],
        };

        // Create sighash for the spending transaction
        let mut sighash_cache = SighashCache::new(&spending_tx);
        let sighash_type = sighash::TapSighashType::Default;
        // Create the prevouts
        let prevouts = [TxOut {
            value: funding_amount,
            script_pubkey: taproot_script,
        }];
        let prevouts = Prevouts::All(&prevouts);

        // Create the locking script
        let locking_script = connector_s.generate_script();

        // Get taproot spend info
        let (_, control_block) = connector_s.generate_spend_info();

        let leaf_hash =
            TapLeafHash::from_script(locking_script.as_script(), LeafVersion::TapScript);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, sighash_type)
            .expect("must create sighash");

        let message =
            Message::from_digest_slice(sighash.as_byte_array()).expect("must create a message");

        // Sign the transaction with operator key
        let signature = SECP256K1.sign_schnorr(&message, &operator_keypair);
        trace!(%signature, "Signature");

        // Construct the witness stack
        let mut witness = Witness::new();
        witness.push(stake_preimage);
        witness.push(signature.as_ref());
        witness.push(locking_script.to_bytes());
        witness.push(control_block.serialize());

        // Set the witness in the transaction
        spending_tx.input[0].witness = witness;

        // Try to broadcast the spending transaction
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
