//! The [`StakeTx`] transaction is used to move stake across transactions.

use alpen_bridge_params::prelude::StakeChainParams;
use bitcoin::{
    hashes::sha256, key::TapTweak, secp256k1::schnorr, transaction, Address, Amount, FeeRate,
    OutPoint, Psbt, Sequence, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};
use strata_bridge_connectors::prelude::{ConnectorCpfp, ConnectorK, ConnectorP, ConnectorStake};
use strata_bridge_primitives::{
    build_context::BuildContext,
    scripts::{
        prelude::{create_tx, create_tx_ins, create_tx_outs},
        taproot::{finalize_input, TaprootWitness},
    },
    wots::Wots256PublicKey,
};

use crate::{
    prelude::{DUST_AMOUNT, OPERATOR_FUNDS},
    StakeChainError,
};

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

/// The [`StakeTx`] transaction is used to move stake across transactions.
///
/// It includes a PSBT that contains the inputs and outputs for the transaction.
/// Users can instantiate a [`StakeTx`] by calling the [`StakeTx::create_initial`] for the first
/// stake transaction that spends the [`PreStakeTx`](crate::transactions::pre_stake::PreStakeTx) and
/// [`StakeTx::advance`] to advance the stake chain beyond that.
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
pub struct StakeTx {
    /// The PSBT that contains the inputs and outputs for the transaction.
    pub psbt: Psbt,

    /// The type of witness required to spend the inputs of this transaction.
    witnesses: [TaprootWitness; 2],
}

impl StakeTx {
    // Creates a new [`StakeTx`] transaction from the previous stake transaction as input and
    /// connector outputs.
    ///
    /// The inputs should be both the
    /// [`OPERATOR_FUNDS`] and the
    /// [`ConnectorStake`] from the previous stake transaction as a [`Transaction`]'s vector of
    /// [`TxIn`].
    ///
    /// `operator_funds_utxo` is the previous operator funds output that will fund the dust outputs
    /// for the current stake transaction.
    ///
    /// `stake_utxo` is the previous stake output that will be used as an input to the current stake
    /// transaction.
    #[expect(clippy::too_many_arguments)]
    pub fn create_initial(
        context: &impl BuildContext,
        params: &StakeChainParams,
        hash: sha256::Hash,
        withdrawal_fulfillment_pk: Wots256PublicKey,
        pre_stake: OutPoint,
        operator_funds: OutPoint,
        operator_pubkey: XOnlyPublicKey,
        connector_cpfp: ConnectorCpfp,
    ) -> Self {
        // The first input is the operator's funds.
        let utxos = [operator_funds, pre_stake];
        let tx_ins = create_tx_ins(utxos);

        let connector_k = ConnectorK::new(
            context.aggregated_pubkey(),
            context.network(),
            withdrawal_fulfillment_pk,
        );

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

        let mut psbt = Psbt::from_unsigned_tx(tx)
            .expect("cannot fail since transaction will be always unsigned");

        let operator_addr = Address::p2tr_tweaked(
            operator_pubkey.dangerous_assume_tweaked(),
            context.network(),
        );

        let funding_prevout = TxOut {
            script_pubkey: operator_addr.script_pubkey(),
            value: OPERATOR_FUNDS,
        };
        let stake_prevout = TxOut {
            script_pubkey: operator_addr.script_pubkey(),
            value: params.stake_amount,
        };

        psbt.inputs[0].witness_utxo = Some(funding_prevout);

        psbt.inputs[1].witness_utxo = Some(stake_prevout);

        let witnesses = [
            TaprootWitness::Key,
            TaprootWitness::Key, // the first stake transaction spends via key-spend from PreStake.
        ];

        Self { psbt, witnesses }
    }

    /// Creates a new [`StakeTx`] transaction in the chain provided that the data for the previous
    /// stake transaction exists.
    pub fn advance(
        context: &impl BuildContext,
        params: &StakeChainParams,
        input: StakeTxData,
        prev_hash: sha256::Hash,
        prev_stake: OutPoint,
        operator_pubkey: XOnlyPublicKey,
        connector_cpfp: ConnectorCpfp,
    ) -> Self {
        // The first input is the operator's funds.
        let utxos = [input.operator_funds, prev_stake];
        let tx_ins = create_tx_ins(utxos);

        let connector_k = ConnectorK::new(
            context.aggregated_pubkey(),
            context.network(),
            input.withdrawal_fulfillment_pk,
        );
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
                // The value is deducted 2 dust outputs, i.e. 2 * 330 sats.
                OPERATOR_FUNDS
                    .checked_sub(Amount::from_sat(2 * 330))
                    .expect("must be able to subtract 2*330 sats from OPERATOR_FUNDS"),
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
                DUST_AMOUNT,
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

        let operator_addr = Address::p2tr_tweaked(
            operator_pubkey.dangerous_assume_tweaked(),
            context.network(),
        );
        psbt.inputs[0].witness_utxo = Some(TxOut {
            script_pubkey: operator_addr.script_pubkey(),
            value: OPERATOR_FUNDS,
        });

        psbt.inputs[1].witness_utxo = Some(prev_stake_out);

        let (script_buf, control_block) = prev_stake_connector.generate_spend_info();
        let witnesses = [
            TaprootWitness::Key,
            TaprootWitness::Script {
                script_buf,
                control_block,
            },
        ];

        Self { psbt, witnesses }
    }

    /// The transaction's inputs.
    pub fn inputs(&self) -> Vec<TxIn> {
        self.psbt.unsigned_tx.input.clone()
    }

    /// The transaction's outputs.
    pub fn outputs(&self) -> Vec<TxOut> {
        self.psbt.unsigned_tx.output.clone()
    }

    /// The witness types required to spend the inputs to this transaction.
    pub fn witnesses(&self) -> &[TaprootWitness; 2] {
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

    /// Finalizes the first stake transaction.
    ///
    /// Unlike the rest of the stake transactions in the stake chain, the first stake transaction
    /// spends via key-spend path the PreStake transaction input and does not need a preimage.
    pub fn finalize_initial(
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

        self.psbt
            .extract_tx()
            .expect("must be able to extract signed tx")
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
    /// # Note: This function can only be used to finalize the first stake transaction if the
    /// `pre-stake` transaction output that it spends also uses the same script as the stake output
    /// script in each stake transaction.
    pub fn finalize(
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
        self.psbt
            .extract_tx()
            .expect("must be able to extract signed tx")
    }
}
