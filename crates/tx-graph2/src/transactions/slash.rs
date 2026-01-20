//! This module contains the slash transaction.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, OutPoint, Psbt, ScriptBuf, Transaction, TxIn, TxOut, Txid,
};
use secp256k1::schnorr;
use strata_asm_txs_bridge_v1::slash::SlashTxHeaderAux;
use strata_bridge_connectors2::{
    prelude::{
        ContestSlashConnector, CpfpConnector, NOfNConnector, NOfNSpend, TimelockedSpendPath,
        TimelockedWitness,
    },
    Connector, ParentTx, SigningInfo,
};
use strata_l1_txfmt::{MagicBytes, ParseConfig};
use strata_primitives::bitcoin_bosd::Descriptor;

use crate::transactions::{prelude::ContestTx, PresignedTx};

/// Data that is needed to construct a [`SlashTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct SlashData {
    /// Operator index.
    pub operator_idx: u32,
    /// ID of the contest transaction.
    pub contest_txid: Txid,
    /// Outpoint where the stake is stored.
    pub stake_outpoint: OutPoint,
    /// Magic bytes that identify the bridge.
    pub magic_bytes: MagicBytes,
}

impl SlashData {
    /// Computes the OP_RETURN leaf script that pushes
    /// the SPS-50 header of the slash transaction.
    pub fn header_leaf_script(&self) -> ScriptBuf {
        let tag_data = SlashTxHeaderAux::new(self.operator_idx).build_tag_data();
        ParseConfig::new(self.magic_bytes)
            .encode_script_buf(&tag_data.as_ref())
            .unwrap()
    }
}

// TODO: (@uncomputable) Check in unit test that slash tx can be parsed by ASM code
// https://github.com/alpenlabs/alpen/blob/b016495114050409e831898436d7d0ac04df8d82/crates/asm/txs/bridge-v1/src/slash/parse.rs#L52
/// The slash transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SlashTx {
    psbt: Psbt,
    prevouts: [TxOut; Self::N_INPUTS],
    contest_slash_connector: ContestSlashConnector,
    stake_connector: NOfNConnector,
    cpfp_connector: CpfpConnector,
}

impl SlashTx {
    /// Index of the SPS-50 header output.
    pub const HEADER_VOUT: u32 = 0;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 2;

    /// Creates a slash transaction.
    pub fn new(
        data: SlashData,
        contest_slash_connector: ContestSlashConnector,
        stake_connector: NOfNConnector,
        watchtower_descriptors: &[Descriptor],
    ) -> Self {
        // cast safety: size(usize) <= size(u64)
        let watchtower_stake = match stake_connector.value().checked_div(watchtower_descriptors.len() as u64) {
            Some(x) => x,
            None => panic!("The total stake must be divisible by the number of watchtowers. Total stake = {}, number of watchtowers = {}", stake_connector.value(), watchtower_descriptors.len()),
        };
        debug_assert!(contest_slash_connector.network() == stake_connector.network());
        let cpfp_connector = CpfpConnector::new(
            contest_slash_connector.network(),
            contest_slash_connector.value(),
        );

        let prevouts = [contest_slash_connector.tx_out(), stake_connector.tx_out()];
        let input = vec![
            TxIn {
                previous_output: OutPoint {
                    txid: data.contest_txid,
                    vout: ContestTx::SLASH_VOUT,
                },
                sequence: contest_slash_connector.sequence(TimelockedSpendPath::Timeout),
                ..Default::default()
            },
            TxIn {
                previous_output: data.stake_outpoint,
                sequence: stake_connector.sequence(NOfNSpend),
                ..Default::default()
            },
        ];
        let mut output = vec![TxOut {
            script_pubkey: data.header_leaf_script(),
            value: Amount::ZERO,
        }];
        output.extend(watchtower_descriptors.iter().map(|x| TxOut {
            script_pubkey: x.to_script(),
            value: watchtower_stake,
        }));
        output.push(cpfp_connector.tx_out());

        let value_in: Amount = prevouts.iter().map(|x| x.value).sum();
        let value_out: Amount = output.iter().map(|x| x.value).sum();
        debug_assert!(
            value_in == value_out,
            "tx should pay zero fees (value in = {value_in}, value out = {value_out})"
        );

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
            contest_slash_connector,
            stake_connector,
            cpfp_connector,
        }
    }

    /// Returns the index of the output for the given watchtower.
    pub const fn watchtower_vout(watchtower_index: u32) -> u32 {
        1 + watchtower_index
    }

    /// Returns the index of the CPFP output.
    pub const fn cpfp_vout(n_watchtowers: u32) -> u32 {
        1 + n_watchtowers
    }

    /// Finalizes the transaction with the given witness data.
    pub fn finalize(self, n_of_n_signatures: [schnorr::Signature; Self::N_INPUTS]) -> Transaction {
        let mut psbt = self.psbt;

        let contest_slash_witness = TimelockedWitness::Timeout {
            timelocked_key_signature: n_of_n_signatures[0],
        };
        self.contest_slash_connector
            .finalize_input(&mut psbt.inputs[0], &contest_slash_witness);
        self.stake_connector
            .finalize_input(&mut psbt.inputs[1], &n_of_n_signatures[1]);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl ParentTx for SlashTx {
    fn cpfp_tx_out(&self) -> TxOut {
        self.cpfp_connector.tx_out()
    }

    fn cpfp_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.psbt.unsigned_tx.compute_txid(),
            vout: self.psbt.outputs.len() as u32 - 1,
        }
    }
}

impl PresignedTx<{ Self::N_INPUTS }> for SlashTx {
    fn signing_info(&self) -> [SigningInfo; Self::N_INPUTS] {
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);

        [
            self.contest_slash_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                TimelockedSpendPath::Timeout,
                0,
            ),
            self.stake_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                NOfNSpend,
                1,
            ),
        ]
    }
}

impl AsRef<Transaction> for SlashTx {
    fn as_ref(&self) -> &Transaction {
        &self.psbt.unsigned_tx
    }
}
