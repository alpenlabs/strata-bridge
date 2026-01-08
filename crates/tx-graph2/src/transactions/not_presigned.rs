//! This module contains transactions that are not presigned.
//!
//! These transactions spend a single connector in their first input.
//! The other inputs and outputs are malleable.
//!
//! This implementation lets you construct the base transaction,
//! add inputs and outputs, and finalize the first input.
//! The other inputs must be finalized by the respective wallet software.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    OutPoint, Psbt, Transaction, TxIn, TxOut, Txid,
};
use secp256k1::schnorr;

use crate::{
    connectors::{
        prelude::{
            ClaimPayoutConnector, ClaimPayoutSpendPath, ClaimPayoutWitness, CounterproofConnector,
            TimelockedSpendPath, TimelockedWitness,
        },
        Connector, SigningInfo,
    },
    transactions::prelude::{ClaimTx, CounterproofTx},
};

macro_rules! impl_not_presigned_tx {
    (
        $(#[$data_docs:meta])*
        pub struct $data:ident {
            $(#[$txid_docs:meta])*
                pub $txid:ident: Txid,
        }

        $(#[$tx_docs:meta])*
        pub struct $tx:ident;

        type Connector = $connector:ty;
        const VOUT = $vout:expr;
        const SPEND_PATH = $spend_path:expr;
    ) => {
        $(#[$data_docs])*
        #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
        pub struct $data {
            $(#[$txid_docs])*
            pub $txid: Txid,
        }

        $(#[$tx_docs])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $tx {
            tx: Transaction,
            // invariant: tx.input.len() == prevouts.len()
            prevouts: Vec<TxOut>,
            connector: $connector,
        }

        impl $tx {
            /// Creates a transaction.
            pub fn new(data: $data, connector: $connector) -> Self {
                let prevouts = vec![connector.tx_out()];
                let input = vec![TxIn {
                    previous_output: OutPoint {
                        txid: data.$txid,
                        vout: $vout,
                    },
                    sequence: connector.sequence($spend_path),
                    ..Default::default()
                }];
                let output = vec![];
                let tx = Transaction {
                    version: Version(3),
                    lock_time: absolute::LockTime::ZERO,
                    input,
                    output,
                };

                Self {
                    tx,
                    prevouts,
                    connector,
                }
            }

            /// Pushes an input to the transaction.
            pub fn push_input(&mut self, input: TxIn, prevout: TxOut) {
                self.tx.input.push(input);
                self.prevouts.push(prevout);
            }

            /// Pushes an output to the transaction.
            pub fn push_output(&mut self, output: TxOut) {
                self.tx.output.push(output);
            }

            /// Returns the signing info for the first transaction input.
            pub fn signing_info_partial(&self) -> SigningInfo {
                let mut cache = SighashCache::new(&self.tx);
                let prevouts = Prevouts::All(&self.prevouts);

                self.connector.get_signing_info(&mut cache, prevouts, $spend_path, 0)
            }
        }

        impl AsRef<Transaction> for $tx {
            fn as_ref(&self) -> &Transaction {
                &self.tx
            }
        }

    }
}

impl_not_presigned_tx! {
    /// Data that is needed to construct a [`CounterproofNackTx`].
    pub struct CounterproofNackData {
        /// ID of the counterproof transaction.
        pub counterproof_txid: Txid,
    }

    /// Counterproof NACK transaction of a watchtower.
    pub struct CounterproofNackTx;

    type Connector = CounterproofConnector;
    const VOUT = CounterproofTx::ACK_NACK_VOUT;
    const SPEND_PATH = TimelockedSpendPath::Normal;
}

impl CounterproofNackTx {
    /// Finalizes the first transaction input and returns the resulting bitcoin transaction.
    ///
    /// The remaining inputs must be manually signed.
    pub fn finalize_partial(self, wt_fault_signature: schnorr::Signature) -> Transaction {
        let mut psbt = Psbt::from_unsigned_tx(self.tx).expect("witness should be empty");
        for (input, utxo) in psbt.inputs.iter_mut().zip(self.prevouts) {
            input.witness_utxo = Some(utxo);
        }

        let witness = TimelockedWitness::Normal {
            output_key_signature: wt_fault_signature,
        };
        self.connector.finalize_input(&mut psbt.inputs[0], &witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl_not_presigned_tx! {
    /// Data that is needed to construct an [`AdminBurnTx`].
    pub struct AdminBurnData {
        /// ID of the claim transaction.
        pub claim_txid: Txid,
    }

    /// Admin burn transaction.
    pub struct AdminBurnTx;

    type Connector = ClaimPayoutConnector;
    const VOUT = ClaimTx::PAYOUT_VOUT;
    const SPEND_PATH = ClaimPayoutSpendPath::AdminBurn;
}

impl AdminBurnTx {
    /// Finalizes the first transaction input and returns the resulting bitcoin transaction.
    ///
    /// The remaining inputs must be manually signed.
    pub fn finalize_partial(self, admin_signature: schnorr::Signature) -> Transaction {
        let mut psbt = Psbt::from_unsigned_tx(self.tx).expect("witness should be empty");
        for (input, utxo) in psbt.inputs.iter_mut().zip(self.prevouts) {
            input.witness_utxo = Some(utxo);
        }

        let witness = ClaimPayoutWitness::AdminBurn { admin_signature };
        self.connector.finalize_input(&mut psbt.inputs[0], &witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl_not_presigned_tx! {
    /// Data that is needed to construct an [`UnstakingBurnTx`].
    pub struct UnstakingBurnData {
        /// ID of the claim transaction.
        pub claim_txid: Txid,
    }

    /// Unstaking burn transaction.
    pub struct UnstakingBurnTx;

    type Connector = ClaimPayoutConnector;
    const VOUT = ClaimTx::PAYOUT_VOUT;
    const SPEND_PATH = ClaimPayoutSpendPath::UnstakingBurn;
}

impl UnstakingBurnTx {
    /// Finalizes the first transaction input and returns the resulting bitcoin transaction.
    ///
    /// The remaining inputs must be manually signed.
    pub fn finalize_partial(self, unstaking_preimage: [u8; 32]) -> Transaction {
        let mut psbt = Psbt::from_unsigned_tx(self.tx).expect("witness should be empty");
        for (input, utxo) in psbt.inputs.iter_mut().zip(self.prevouts) {
            input.witness_utxo = Some(utxo);
        }

        let witness = ClaimPayoutWitness::UnstakingBurn { unstaking_preimage };
        self.connector.finalize_input(&mut psbt.inputs[0], &witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}
