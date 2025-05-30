//! The [`StakeTx`] transaction is used to move stake across transactions.

use alpen_bridge_params::prelude::StakeChainParams;
use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{schnorr, Message},
    sighash::{Prevouts, SighashCache},
    taproot::LeafVersion,
    transaction, Amount, OutPoint, Psbt, ScriptBuf, Sequence, TapLeafHash, TapSighashType,
    Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};
use strata_bridge_connectors::prelude::{ConnectorCpfp, ConnectorK, ConnectorP, ConnectorStake};
use strata_bridge_primitives::{
    build_context::BuildContext,
    constants::{FUNDING_AMOUNT, SEGWIT_MIN_AMOUNT},
    scripts::{
        prelude::{create_tx, create_tx_ins, create_tx_outs},
        taproot::{finalize_input, TaprootWitness},
    },
    wots::Wots256PublicKey,
};

use crate::prelude::{OPERATOR_FUNDS, STAKE_VOUT};

/// The metadata required to create a [`StakeTx`] transaction in the stake chain (except the first
/// stake transaction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StakeTxData {
    /// The [`OutPoint`] used to fund the dust outputs for the tx-graph for the given stake
    /// transaction.
    pub operator_funds: OutPoint,

    /// The [`sha256::Hash`] used in the hashlock of the current stake transaction.
    pub hash: sha256::Hash,

    /// The [`Wots256PublicKey`] used in the output of the current stake transaction that is spent
    /// by the Claim transaction to bitcommit to the [`Txid`] of the Withdrawal Fulfilllment
    /// Transaction.
    pub withdrawal_fulfillment_pk: Wots256PublicKey,
}

impl std::hash::Hash for StakeTxData {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.operator_funds.hash(state);
    }
}

/// The number of inputs in a stake transaction.
pub const NUM_STAKE_TX_INPUTS: usize = 2;

/// A marker for the first stake transaction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Head;

/// A marker for the subsequent stake transactions i.e., all transactions in the stake chain other
/// than the first.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tail;

/// The type of stake transaction.
///
/// As the first stake transaction is distinct in how it is spent from the rest of the transactions
/// in the stake chain, this is a convenience enum used when a common semantics is desired when
/// dealing with both types.
#[derive(Debug, Clone)]
pub enum StakeTxKind {
    /// The head of the stake chain i.e., the first stake transaction.
    Head(StakeTx<Head>),

    /// Any transaction in the stake chain other than the first.
    Tail(StakeTx<Tail>),
}

impl StakeTxKind {
    /// Returns the stake transaction as a PSBT.
    pub const fn psbt(&self) -> &Psbt {
        match self {
            StakeTxKind::Head(stake_tx) => &stake_tx.psbt,
            StakeTxKind::Tail(stake_tx) => &stake_tx.psbt,
        }
    }

    /// Computes the txid of the underlying stake transaction.
    pub fn compute_txid(&self) -> Txid {
        match self {
            StakeTxKind::Head(stake_tx) => stake_tx.compute_txid(),
            StakeTxKind::Tail(stake_tx) => stake_tx.compute_txid(),
        }
    }
}

/// The [`StakeTx`] transaction is used to move stake across transactions.
///
/// It includes a PSBT that contains the inputs and outputs for the transaction.
/// Users can instantiate a [`StakeTx`] by calling the [`StakeTx<HEAD>::new`] for the first
/// stake transaction that spends the [`PreStakeTx`](crate::transactions::pre_stake::PreStakeTx) and
/// [`StakeTx<HEAD>.advance`] to advance the stake chain beyond that.
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
/// 4. A dust output, [`ConnectorCpfp`], for the operator to use as CPFP in future transactions that
///    spends this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeTx<StakeTxType = Head> {
    /// The PSBT that contains the inputs and outputs for the transaction.
    pub psbt: Psbt,

    /// The hash in the output of this transaction that locks the stake.
    ///
    /// This information is used to compute the locking script used to advance the stake.
    hash: sha256::Hash,

    /// The type of witness required to spend the inputs of this transaction.
    witnesses: [TaprootWitness; NUM_STAKE_TX_INPUTS],
}

impl<StakeTxType> StakeTx<StakeTxType> {
    /// The transaction's inputs.
    pub fn inputs(&self) -> Vec<TxIn> {
        self.psbt.unsigned_tx.input.clone()
    }

    /// The transaction's outputs.
    pub fn outputs(&self) -> Vec<TxOut> {
        self.psbt.unsigned_tx.output.clone()
    }

    /// The witness types required to spend the inputs to this transaction.
    pub const fn witnesses(&self) -> &[TaprootWitness; 2] {
        &self.witnesses
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

    /// Creates a new [`StakeTx`] transaction in the chain that spends the stake output from the
    /// current transaction.
    pub fn advance(
        &self,
        context: &impl BuildContext,
        params: &StakeChainParams,
        input: StakeTxData,
        operator_pubkey: XOnlyPublicKey,
        connector_cpfp: ConnectorCpfp,
    ) -> StakeTx<Tail> {
        let prev_stake = OutPoint::new(self.compute_txid(), STAKE_VOUT);

        // The first input is the operator's funds.
        let utxos = [input.operator_funds, prev_stake];
        let tx_ins = create_tx_ins(utxos);

        let connector_k = ConnectorK::new(context.network(), input.withdrawal_fulfillment_pk);
        let connector_p =
            ConnectorP::new(context.aggregated_pubkey(), input.hash, context.network());
        let connector_s = ConnectorStake::new(
            context.aggregated_pubkey(),
            operator_pubkey,
            input.hash,
            params.delta,
            context.network(),
        );

        // The outputs are the `TxOut`s created from the connectors.
        let scripts_and_amounts = [
            (
                connector_k.create_taproot_address().script_pubkey(),
                FUNDING_AMOUNT,
            ),
            (
                connector_p.generate_address().script_pubkey(),
                connector_p
                    .generate_address()
                    .script_pubkey()
                    .minimal_non_dust(),
            ),
            (
                connector_s.generate_address().script_pubkey(),
                params.stake_amount,
            ),
            (
                connector_cpfp.generate_taproot_address().script_pubkey(),
                SEGWIT_MIN_AMOUNT,
            ),
        ];

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let mut tx = create_tx(tx_ins, tx_outs);
        // needed for 1P1C TRUC relay
        tx.version = transaction::Version(3);
        // the previous stake input has a relative timelock.
        tx.input[1].sequence = Sequence::from_height(params.delta.to_consensus_u32() as u16);

        let mut psbt = Psbt::from_unsigned_tx(tx)
            .expect("cannot fail since transaction will be always unsigned");

        let prev_stake_connector = ConnectorStake::new(
            context.aggregated_pubkey(),
            operator_pubkey,
            self.hash,
            params.delta,
            context.network(),
        );
        let prev_stake_out = TxOut {
            script_pubkey: prev_stake_connector.generate_address().script_pubkey(),
            value: params.stake_amount,
        };

        psbt.inputs[1].witness_utxo = Some(prev_stake_out);

        let (script_buf, control_block) = prev_stake_connector.generate_spend_info();
        let witnesses = [
            TaprootWitness::Key,
            TaprootWitness::Script {
                script_buf,
                control_block,
            },
        ];

        StakeTx::<Tail> {
            psbt,
            hash: input.hash,
            witnesses,
        }
    }

    fn compute_sighash_with_prevouts<const NUM_INPUTS: usize>(
        &self,
        prevouts: Prevouts<'_, TxOut>,
    ) -> [Message; NUM_INPUTS] {
        let mut sighasher = SighashCache::new(&self.psbt.unsigned_tx);

        self.psbt
            .inputs
            .iter()
            .enumerate()
            .map(|(input_index, input)| {
                let sighash_type = input
                    .sighash_type
                    .map(|sighash_type| sighash_type.taproot_hash_ty())
                    .unwrap_or(Ok(TapSighashType::Default))
                    .expect("default value must be Ok");

                let tap_sighash = match &self.witnesses[input_index] {
                    TaprootWitness::Script { script_buf, .. } => sighasher
                        .taproot_script_spend_signature_hash(
                            input_index,
                            &prevouts,
                            TapLeafHash::from_script(script_buf, LeafVersion::TapScript),
                            sighash_type,
                        )
                        .expect("must be able to get taproot script spend signature hash"),

                    TaprootWitness::Key | TaprootWitness::Tweaked { .. } => sighasher
                        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
                        .expect("must be able to get taproot key spend signature hash"),
                };

                Message::from_digest(tap_sighash.to_byte_array())
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("stake tx must have two inputs")
    }
}

impl StakeTx<Head> {
    /// Creates the first [`StakeTx`] transaction.
    ///
    /// # Params
    ///
    /// - `context`: The context used to create the transaction.
    /// - `params`: The parameters used to create the transaction.
    /// - `hash`: The hash used in the hashlock output of the current stake transaction.
    /// - `withdrawal_fulfillment_pk`: The public key used in the output of the current stake
    ///   transaction.
    /// - `pre_stake`: The [`OutPoint`] from the pre-stake transaction that the initial stake
    ///   transaction spends.
    /// - `operator_funds`: The [`OutPoint`] with the amount necessary to fund the dust outputs for
    ///   tx-graph as well as those in the state transaction.
    /// - `operator_pubkey`: The operator's public key used to create the [`ConnectorStake`] output
    ///   that is spent by the next stake transaction in the chain.
    /// - `connector_cpfp`: The [`ConnectorCpfp`] used to create the dust output for the CPFP.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        context: &impl BuildContext,
        params: &StakeChainParams,
        hash: sha256::Hash,
        withdrawal_fulfillment_pk: Wots256PublicKey,
        pre_stake: OutPoint,
        operator_funds: OutPoint,
        operator_pubkey: XOnlyPublicKey,
        connector_cpfp: ConnectorCpfp,
    ) -> StakeTx<Head> {
        // The first input is the operator's funds.
        let utxos = [operator_funds, pre_stake];
        let tx_ins = create_tx_ins(utxos);

        let connector_k = ConnectorK::new(context.network(), withdrawal_fulfillment_pk);

        let connector_p = ConnectorP::new(context.aggregated_pubkey(), hash, context.network());

        let connector_s = ConnectorStake::new(
            context.aggregated_pubkey(),
            operator_pubkey,
            hash,
            params.delta,
            context.network(),
        );

        // The outputs are the `TxOut`s created from the connectors.
        let connector_p_addr = connector_p.generate_address();
        let cpfp_addr = connector_cpfp.generate_taproot_address();
        let scripts_and_amounts = [
            (
                connector_k.create_taproot_address().script_pubkey(),
                // The value is deducted 2 dust outputs, i.e. 2 * 330 sats.
                OPERATOR_FUNDS
                    .checked_sub(Amount::from_sat(2 * 330))
                    .expect("must be able to subtract 2*330 sats from OPERATOR_FUNDS"),
            ),
            (
                connector_p_addr.script_pubkey(),
                connector_p_addr.script_pubkey().minimal_non_dust(),
            ),
            (
                connector_s.generate_address().script_pubkey(),
                params.stake_amount,
            ),
            (
                cpfp_addr.script_pubkey(),
                cpfp_addr.script_pubkey().minimal_non_dust(),
            ),
        ];
        let tx_outs = create_tx_outs(scripts_and_amounts);

        let mut tx = create_tx(tx_ins, tx_outs);
        tx.version = transaction::Version(3); // needed for 1P1C TRUC relay

        let psbt = Psbt::from_unsigned_tx(tx)
            .expect("cannot fail since transaction will be always unsigned");

        let witnesses = [
            TaprootWitness::Key,
            TaprootWitness::Key, // the first stake transaction spends via key-spend from PreStake.
        ];

        StakeTx::<Head> {
            psbt,
            hash,
            witnesses,
        }
    }

    /// Generates the transaction message sighash for the first stake transaction.
    pub fn sighashes(
        &self,
        stake_amount: Amount,
        prevouts: [ScriptBuf; NUM_STAKE_TX_INPUTS],
    ) -> [Message; NUM_STAKE_TX_INPUTS] {
        let prevouts = prevouts
            .into_iter()
            .zip([OPERATOR_FUNDS, stake_amount])
            .map(|(script_pubkey, amount)| TxOut {
                script_pubkey,
                value: amount,
            })
            .collect::<Vec<_>>();

        let prevouts = Prevouts::All(&prevouts);

        self.compute_sighash_with_prevouts(prevouts)
    }

    /// Finalizes the first stake transaction.
    ///
    /// Unlike the rest of the stake transactions in the stake chain, the first stake transaction
    /// spends via key-spend path the PreStake transaction input and does not need a preimage.
    pub fn finalize_unchecked(
        mut self,
        funds_signature: schnorr::Signature,
        stake_signature: schnorr::Signature,
    ) -> Transaction {
        finalize_input(
            self.psbt.inputs.first_mut().expect("must have first input"),
            [funds_signature.as_ref()],
        );
        finalize_input(
            self.psbt.inputs.get_mut(1).expect("must have second input"),
            [stake_signature.as_ref()],
        );

        self.psbt.extract_tx_unchecked_fee_rate()
    }
}

impl StakeTx<Tail> {
    /// Creates a new [`StakeTx`] transaction in the chain that spends the stake output from the
    /// previous stake transaction in the chain.
    ///
    /// This can be used to create any transaction in the stake chain other than the first directly
    /// without needing to construct the chain incrementally.
    pub fn new(
        context: &impl BuildContext,
        params: &StakeChainParams,
        input: StakeTxData,
        prev_hash: sha256::Hash,
        prev_stake: OutPoint,
        operator_pubkey: XOnlyPublicKey,
        connector_cpfp: ConnectorCpfp,
    ) -> StakeTx<Tail> {
        // The first input is the operator's funds.
        let utxos = [input.operator_funds, prev_stake];
        let tx_ins = create_tx_ins(utxos);

        let connector_k = ConnectorK::new(context.network(), input.withdrawal_fulfillment_pk);
        let connector_p =
            ConnectorP::new(context.aggregated_pubkey(), input.hash, context.network());
        let connector_s = ConnectorStake::new(
            context.aggregated_pubkey(),
            operator_pubkey,
            input.hash,
            params.delta,
            context.network(),
        );

        // The outputs are the `TxOut`s created from the connectors.
        let scripts_and_amounts = [
            (
                connector_k.create_taproot_address().script_pubkey(),
                FUNDING_AMOUNT,
            ),
            (
                connector_p.generate_address().script_pubkey(),
                connector_p
                    .generate_address()
                    .script_pubkey()
                    .minimal_non_dust(),
            ),
            (
                connector_s.generate_address().script_pubkey(),
                params.stake_amount,
            ),
            (
                connector_cpfp.generate_taproot_address().script_pubkey(),
                SEGWIT_MIN_AMOUNT,
            ),
        ];

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let mut tx = create_tx(tx_ins, tx_outs);
        // needed for 1P1C TRUC relay
        tx.version = transaction::Version(3);
        // the previous stake input has a relative timelock.
        tx.input[1].sequence = Sequence::from_height(params.delta.to_consensus_u32() as u16);

        let mut psbt = Psbt::from_unsigned_tx(tx)
            .expect("cannot fail since transaction will be always unsigned");

        let prev_stake_connector = ConnectorStake::new(
            context.aggregated_pubkey(),
            operator_pubkey,
            prev_hash,
            params.delta,
            context.network(),
        );
        let prev_stake_out = TxOut {
            script_pubkey: prev_stake_connector.generate_address().script_pubkey(),
            value: params.stake_amount,
        };

        psbt.inputs[1].witness_utxo = Some(prev_stake_out);

        let (script_buf, control_block) = prev_stake_connector.generate_spend_info();
        let witnesses = [
            TaprootWitness::Key,
            TaprootWitness::Script {
                script_buf,
                control_block,
            },
        ];

        StakeTx::<Tail> {
            psbt,
            hash: input.hash,
            witnesses,
        }
    }

    /// Generates the transaction message sighash for the stake transaction.
    pub fn sighashes(&self, funding_script: ScriptBuf) -> [Message; NUM_STAKE_TX_INPUTS] {
        let TxOut {
            value: prev_value,
            script_pubkey: prev_script_pubkey,
        } = self
            .psbt
            .inputs
            .get(1)
            .expect("must have second input")
            .witness_utxo
            .as_ref()
            .expect("second input must have a witness utxo")
            .clone();

        let prevouts = [funding_script, prev_script_pubkey]
            .into_iter()
            .zip([OPERATOR_FUNDS, prev_value])
            .map(|(script_pubkey, value)| TxOut {
                script_pubkey,
                value,
            })
            .collect::<Vec<_>>();

        let prevouts = Prevouts::All(&prevouts);

        self.compute_sighash_with_prevouts(prevouts)
    }

    /// Adds the preimage and signature for the previous [`StakeTx`] transaction as an input to the
    /// current [`StakeTx`] transaction.
    ///
    /// This is used to advance a [`StakeChain`](crate::StakeChain) by revealing the preimage.
    ///
    /// # Implementation Details
    ///
    /// Under the hood, it spents the underlying [`ConnectorStake`] from the previous [`StakeTx`].
    ///
    /// # CAUTION
    ///
    /// This function does not check if the fee rate is valid.
    pub fn finalize_unchecked(
        mut self,
        prev_preimage: &[u8; 32],
        funds_signature: schnorr::Signature,
        stake_signature: schnorr::Signature,
        prev_connector_s: ConnectorStake,
    ) -> Transaction {
        // Get taproot spend info
        let (locking_script, control_block) = prev_connector_s.generate_spend_info();

        // Need to change the inputs
        finalize_input(
            self.psbt.inputs.first_mut().expect("must have first input"),
            [funds_signature.serialize().to_vec()],
        );
        finalize_input(
            self.psbt.inputs.get_mut(1).expect("must have second input"),
            [
                prev_preimage.to_vec(),
                stake_signature.serialize().to_vec(),
                locking_script.to_bytes(),
                control_block.serialize(),
            ],
        );

        // Extract the transaction
        self.psbt.extract_tx_unchecked_fee_rate()
    }
}
