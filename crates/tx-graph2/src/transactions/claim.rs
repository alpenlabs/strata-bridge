//! This module contains the claim transaction.

use bitcoin::{transaction, Amount, OutPoint, Transaction, TxOut};
use strata_bridge_connectors::connector_cpfp::ConnectorCpfp;
use strata_bridge_primitives::scripts::prelude::{create_tx, create_tx_ins, create_tx_outs};

use crate::connectors::claim_contest_connector::ClaimContestConnector;

/// Data that is needed to construct a [`ClaimTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ClaimData {
    /// The outpoint of the UTXO that funds the claim transaction.
    pub claim_funds: OutPoint,
}

/// The claim transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClaimTx(Transaction);

const CLAIM_CONTEST_VOUT: usize = 0;
const CLAIM_CPFP_VOUT: usize = 1;

impl ClaimTx {
    /// Creates a claim transaction.
    pub fn new(
        data: ClaimData,
        claim_contest_connector: ClaimContestConnector,
        cpfp_connector: ConnectorCpfp,
    ) -> Self {
        let claim_funds = data.claim_funds;
        let claim_contest_tx_out = claim_contest_connector.tx_out();

        let tx_ins = create_tx_ins([claim_funds]);
        let scripts_and_amounts = [
            (
                claim_contest_tx_out.script_pubkey,
                claim_contest_tx_out.value,
            ),
            (cpfp_connector.locking_script(), Amount::ZERO),
        ];
        let tx_outs = create_tx_outs(scripts_and_amounts);

        let mut tx = create_tx(tx_ins, tx_outs);
        tx.version = transaction::Version(3);

        Self(tx)
    }

    /// Accesses the claim transaction.
    pub const fn tx(&self) -> &Transaction {
        &self.0
    }

    /// Accesses the contest transaction output.
    pub fn contest_tx_out(&self) -> &TxOut {
        &self.0.output[CLAIM_CONTEST_VOUT]
    }

    /// Accesses the CPFP transaction output.
    pub fn cpfp_tx_out(&self) -> &TxOut {
        &self.0.output[CLAIM_CPFP_VOUT]
    }
}
