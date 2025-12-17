//! This module contains the claim transaction.

use bitcoin::{transaction, OutPoint, Transaction, TxOut};
use strata_bridge_primitives::scripts::prelude::{create_tx, create_tx_ins, create_tx_outs};

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
    /// The outpoint of the UTXO that funds the claim transaction.
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
        cpfp_connector: CpfpConnector,
    ) -> Self {
        let claim_funds = data.claim_funds;
        let claim_contest_tx_out = claim_contest_connector.tx_out();
        let claim_payout_tx_out = claim_payout_connector.tx_out();
        let cpfp_tx_out = cpfp_connector.tx_out();

        let tx_ins = create_tx_ins([claim_funds]);
        let scripts_and_amounts = [
            (
                claim_contest_tx_out.script_pubkey,
                claim_contest_tx_out.value,
            ),
            (
                claim_payout_tx_out.script_pubkey,
                claim_contest_tx_out.value,
            ),
            (cpfp_tx_out.script_pubkey, cpfp_tx_out.value),
        ];
        let tx_outs = create_tx_outs(scripts_and_amounts);

        let mut tx = create_tx(tx_ins, tx_outs);
        tx.version = transaction::Version(3);

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
