//! This module contains the claim transaction.

use bitcoin::{absolute, transaction::Version, Amount, OutPoint, Transaction, TxOut};
use strata_bridge_primitives::scripts::prelude::create_tx_ins;

use crate::{
    connectors::{
        prelude::{ClaimContestConnector, ClaimPayoutConnector, CpfpConnector},
        Connector,
    },
    transactions::ParentTx,
};

/// Data that is needed to construct a [`ClaimTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ClaimData {
    /// UTXO that funds the claim transaction.
    pub claim_funds: OutPoint,
}

/// The claim transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClaimTx {
    tx: Transaction,
    cpfp_connector: CpfpConnector,
}

impl ClaimTx {
    /// Index of the contest output.
    pub const CONTEST_VOUT: u32 = 0;
    /// Index of the payout output.
    pub const PAYOUT_VOUT: u32 = 1;
    /// Index of the CPFP output.
    pub const CPFP_VOUT: u32 = 2;

    /// Creates a claim transaction.
    pub fn new(
        data: ClaimData,
        claim_contest_connector: ClaimContestConnector,
        claim_payout_connector: ClaimPayoutConnector,
    ) -> Self {
        debug_assert!(claim_contest_connector.network() == claim_payout_connector.network());
        let cpfp_connector = CpfpConnector::new(claim_contest_connector.network(), Amount::ZERO);

        let input = create_tx_ins([data.claim_funds]);
        let output = vec![
            claim_contest_connector.tx_out(),
            claim_payout_connector.tx_out(),
            cpfp_connector.tx_out(),
        ];
        let tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };

        Self { tx, cpfp_connector }
    }

    /// Accesses the claim transaction.
    pub const fn tx(&self) -> &Transaction {
        &self.tx
    }
}

impl ParentTx for ClaimTx {
    fn cpfp_tx_out(&self) -> TxOut {
        self.cpfp_connector.tx_out()
    }

    fn cpfp_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.tx.compute_txid(),
            vout: Self::CPFP_VOUT,
        }
    }
}
