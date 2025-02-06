//! The [`StakeTx`] transaction is used to move stake across transactions.

use bitcoin::{
    absolute,
    hashes::{sha256, Hash},
    key::Keypair,
    relative,
    secp256k1::SECP256K1,
    sighash::{self, Prevouts, SighashCache},
    taproot::LeafVersion,
    transaction, Address, Amount, FeeRate, Network, Psbt, TapLeafHash, Transaction, TxIn, TxOut,
    Txid, XOnlyPublicKey,
};
use secp256k1::Message;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::scripts::taproot::finalize_input;
use strata_bridge_tx_graph::connectors::prelude::{ConnectorK, ConnectorP, ConnectorStake};
use tracing::trace;

use crate::{
    prelude::{DUST_AMOUNT, OPERATOR_FUNDS},
    StakeChainError,
};

/// The [`StakeTx`] transaction is used to move stake across transactions.
///
/// It includes a PSBT that contains the inputs and outputs for the transaction.
///
/// # Input order
///
/// Inputs must be ordered in the following way:
///
/// 1. The [`OPERATOR_FUNDS`] input that will cover all the dust outputs for the current stake
///    transaction.
/// 2. The stake amount from the previous [`StakeTx`] transaction.
///
/// # Output order
///
/// The outputs must be ordered in the following way:
///
/// 1. A dust output, [`ConnectorK`] used as an input to the Claim transaction and it is used to
///    bind the stake to the transaction graph for a particular deposit.
/// 2. A dust output, [`ConnectorP`] used as an input to the Burn Payouts transaction that makes
///    sure that, if the stake is advanced before a withdrawal has been fully processed, then the
///    sake is burned via the Slash Stake transactions. The purpose of the burn payouts is to burn
///    the payout path if an operator starts publishing past claims (that weren't assigned) _after_
///    their stake has been slashed.
/// 3. The stake amount, [`ConnectorStake`].This is used to move the stake from the previous
///    [`StakeTx`] transaction to the current one.
/// 4. A dust output for the operator to use as CPFP in future transactions that spends this one.
///
/// # Implementation Details
///
/// Users can instantiate a [`StakeTx`] by calling the [`StakeTx::new`] function as in the example:
///
/// ```rust,ignore
/// let stake_1 = StakeTxnew(1, stake_tx_in, connector_k, connector_p, connector_s);
/// # drop(stake_1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StakeTx {
    /// The index of the stake transaction, denoted by `k` in the docs and specifications.
    pub index: u32,

    /// The PSBT that contains the inputs and outputs for the transaction.
    pub psbt: Psbt,

    /// The stake amount to be moved and locked up.
    pub amount: Amount,
}

impl StakeTx {
    /// Creates a new [`StakeTx`] transaction from the previous stake transaction as input and
    /// connector outputs.
    ///
    /// The inputs should be both the
    /// [`OPERATOR_FUNDS`] and the
    /// [`ConnectorStake`] from the previous stake transaction as a [`Transaction`]'s vector of
    /// [`TxIn`].
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        index: u32,
        stake_input: TxIn,
        stake_amount: Amount,
        operator_funds: TxIn,
        operator_pubkey: XOnlyPublicKey,
        connector_k: ConnectorK,
        connector_p: ConnectorP,
        connector_s: ConnectorStake,
        network: Network,
    ) -> Self {
        // The first input is the operator's funds.
        let inputs = vec![operator_funds, stake_input];
        // Create a P2TR from the `operator_pubkey`.
        let operator_address = Address::p2tr(SECP256K1, operator_pubkey, None, network);
        // The outputs are the `TxOut`s created from the connectors.
        let outputs = vec![
            TxOut {
                // The value is deducted 2 dust outputs, i.e. 2 * 330 sats.
                value: OPERATOR_FUNDS
                    .checked_sub(Amount::from_sat(2 * 330))
                    .expect("must be able to subtract 2*330 sats from OPERATOR_FUNDS"),
                script_pubkey: connector_k.create_taproot_address().script_pubkey(),
            },
            TxOut {
                value: connector_p
                    .generate_address()
                    .script_pubkey()
                    .minimal_non_dust(),
                script_pubkey: connector_p.generate_address().script_pubkey(),
            },
            TxOut {
                value: stake_amount,
                script_pubkey: connector_s.generate_address().script_pubkey(),
            },
            TxOut {
                value: DUST_AMOUNT,
                script_pubkey: operator_address.script_pubkey(),
            },
        ];
        let transaction = Transaction {
            version: transaction::Version(3), // needed for 1P1C TRUC relay
            lock_time: absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        Self {
            index,
            psbt: Psbt::from_unsigned_tx(transaction)
                .expect("cannot fail since transaction will be always unsigned"),
            amount: stake_amount,
        }
    }

    /// The transaction's inputs.
    pub fn inputs(&self) -> Vec<TxIn> {
        self.psbt.unsigned_tx.input.clone()
    }

    /// The transaction's outputs.
    pub fn outputs(&self) -> Vec<TxOut> {
        self.psbt.unsigned_tx.output.clone()
    }

    /// The transaction's [`Txid`].
    ///
    /// # Note
    ///
    /// Getting the txid from a [`Psbt`]'s `unsigned_tx` is fine IF it's SegWit since the signature
    /// does not change the [`Txid`].
    pub fn compute_txid(&self) -> Txid {
        self.psbt.unsigned_tx.compute_txid()
    }

    /// The transaction's fee.
    pub fn fee(&self) -> Result<Amount, StakeChainError> {
        Ok(self.psbt.fee()?)
    }

    /// The transaction's fee rate.
    ///
    /// # Note
    ///
    /// The fee rate calculation relies on an unchecked division using the total fees and the total
    /// transaction virtual size. Internally it calls [`FeeRate::from_sat_per_vb_unchecked`].
    pub fn fee_rate(&self) -> Result<FeeRate, StakeChainError> {
        let vsize = self.psbt.unsigned_tx.vsize();
        let fee = self.fee()?;
        Ok(FeeRate::from_sat_per_vb_unchecked(
            fee.to_sat() / vsize as u64,
        ))
    }

    /// Adds the preimage and signature for the previous [`StakeTx`] transaction is an input to the
    /// current [`StakeTx`] transaction.
    ///
    /// This is used to advance a [`StakeChain`](crate::StakeChain) by revealing the preimage.
    ///
    /// # Implementation Details
    ///
    /// Under the hood, it spents the underlying [`ConnectorStake`] from the previous [`StakeTx`].
    #[expect(clippy::too_many_arguments)]
    pub fn finalize_connector_s(
        &mut self,
        stake_amount: Amount,
        operator_funds: TxOut,
        preimage: &[u8; 32],
        keypair: &Keypair,
        n_of_n_agg_pubkey: XOnlyPublicKey,
        delta: relative::LockTime,
        network: Network,
    ) {
        // Regenerate the Connector s.
        let stake_hash = sha256::Hash::hash(preimage);
        let operator_pubkey = keypair.public_key().x_only_public_key().0;
        let connector_s = ConnectorStake::new(
            n_of_n_agg_pubkey,
            operator_pubkey,
            stake_hash,
            delta,
            network,
        );
        let unsigned_tx = self.psbt.unsigned_tx.clone();
        let taproot_script = connector_s.generate_address().script_pubkey();

        // Create sighash for the spending transaction
        let mut sighash_cache = SighashCache::new(&unsigned_tx);
        let sighash_type = sighash::TapSighashType::Default;
        // Create the prevouts
        let prevouts = [
            operator_funds,
            TxOut {
                value: stake_amount,
                script_pubkey: taproot_script,
            },
        ];
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
        let signature = SECP256K1.sign_schnorr(&message, keypair);
        trace!(%signature, "Signature");

        // Need to change the inputs
        finalize_input(
            self.psbt
                .inputs
                .first_mut()
                .expect("must have second input"),
            [signature.serialize().to_vec()],
        );
        finalize_input(
            self.psbt.inputs.get_mut(1).expect("must have second input"),
            [
                preimage.to_vec(),
                signature.serialize().to_vec(),
                locking_script.to_bytes(),
                control_block.serialize(),
            ],
        );
    }
}
