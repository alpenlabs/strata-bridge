//! This module contains the unstaking intent transaction.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, OutPoint, Psbt, ScriptBuf, Transaction, TxIn, TxOut, Txid,
};
use strata_asm_txs_bridge_v1::unstake::UnstakeTxHeaderAux;
use strata_bridge_connectors2::{
    prelude::{
        P2AConnector, UnstakingIntentOutput, UnstakingIntentSpend, UnstakingIntentWitness,
        UnstakingOutput,
    },
    Connector, ParentTx, SigningInfo,
};
use strata_l1_txfmt::{MagicBytes, ParseConfig};

use crate::transactions::{prelude::StakeTx, PresignedTx};

/// Data that is needed to construct an [`UnstakingIntentTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct UnstakingIntentData {
    /// Operator index.
    pub operator_idx: u32,
    /// ID of the stake transaction.
    pub stake_txid: Txid,
    /// Magic bytes that identify the bridge.
    pub magic_bytes: MagicBytes,
}

impl UnstakingIntentData {
    /// Computes the OP_RETURN leaf script that pushes
    /// the SPS-50 header of the unstaking intent transaction.
    pub fn header_leaf_script(&self) -> ScriptBuf {
        let tag_data = UnstakeTxHeaderAux::new(self.operator_idx).build_tag_data();
        ParseConfig::new(self.magic_bytes)
            .encode_script_buf(&tag_data.as_ref())
            .unwrap()
    }
}

// TODO: (@uncomputable) Check in unit test that unstaking intent tx can be parsed by ASM code
// https://github.com/alpenlabs/alpen/blob/b016495114050409e831898436d7d0ac04df8d82/crates/asm/txs/bridge-v1/src/unstake/parse.rs#L34
/// The unstaking  intent transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnstakingIntentTx {
    psbt: Psbt,
    prevouts: [TxOut; Self::N_INPUTS],
    unstaking_intent_output: UnstakingIntentOutput,
    unstaking_output: UnstakingOutput,
    cpfp_connector: P2AConnector,
}

impl UnstakingIntentTx {
    /// Index of the SPS-50 header output.
    pub const HEADER_VOUT: u32 = 0;
    /// Index of the unstaking output.
    pub const UNSTAKING_VOUT: u32 = 1;
    /// Index of the CPFP output.
    pub const CPFP_VOUT: u32 = 2;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 1;

    /// Creates an unstaking intent transaction.
    pub fn new(
        data: UnstakingIntentData,
        unstaking_intent_output: UnstakingIntentOutput,
        unstaking_output: UnstakingOutput,
    ) -> Self {
        debug_assert!(unstaking_intent_output.network() == unstaking_output.network());
        let cpfp_connector = P2AConnector::new(unstaking_intent_output.network(), Amount::ZERO);

        let prevouts = [unstaking_intent_output.tx_out()];
        let input = vec![TxIn {
            previous_output: OutPoint {
                txid: data.stake_txid,
                vout: StakeTx::UNSTAKING_INTENT_VOUT,
            },
            sequence: unstaking_intent_output.sequence(UnstakingIntentSpend),
            ..Default::default()
        }];
        let output = vec![
            TxOut {
                script_pubkey: data.header_leaf_script(),
                value: Amount::ZERO,
            },
            unstaking_output.tx_out(),
            cpfp_connector.tx_out(),
        ];

        let tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("witness should be empty");

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo);
        }

        Self {
            psbt,
            prevouts,
            unstaking_intent_output,
            unstaking_output,
            cpfp_connector,
        }
    }

    /// Finalizes the transaction with the given witness data.
    pub fn finalize(self, witness: &UnstakingIntentWitness) -> Transaction {
        let mut psbt = self.psbt;

        self.unstaking_intent_output
            .finalize_input(&mut psbt.inputs[0], witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl ParentTx for UnstakingIntentTx {
    fn cpfp_tx_out(&self) -> TxOut {
        self.cpfp_connector.tx_out()
    }

    fn cpfp_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.psbt.unsigned_tx.compute_txid(),
            vout: Self::CPFP_VOUT,
        }
    }
}

impl PresignedTx<{ Self::N_INPUTS }> for UnstakingIntentTx {
    fn signing_info(&self) -> [SigningInfo; Self::N_INPUTS] {
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);

        [self.unstaking_intent_output.get_signing_info(
            &mut cache,
            Prevouts::All(&self.prevouts),
            UnstakingIntentSpend,
            0,
        )]
    }
}

impl AsRef<Transaction> for UnstakingIntentTx {
    fn as_ref(&self) -> &Transaction {
        &self.psbt.unsigned_tx
    }
}
