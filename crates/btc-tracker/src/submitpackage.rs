//! Typed wrapper around `bitcoind`'s `submitpackage` RPC.
//!
//! `bitcoind-async-client`'s `Reader::submit_package` returns a `corepc-types::SubmitPackage`
//! struct whose `package_msg: String` carries the package-level outcome ("success" iff every
//! tx in the package was accepted into or already present in the mempool). This wrapper turns
//! that into a typed result so call sites can pattern-match on outcomes rather than string-compare.
//!
//! Used by [`crate::tx_driver`] when broadcasting `[parent, child]` v3 1P1C CPFP packages.

use std::collections::BTreeMap;

use bitcoin::{Transaction, Txid, Wtxid};
use bitcoind_async_client::{
    corepc_types::model::{SubmitPackage, SubmitPackageTxResult},
    error::ClientError,
    traits::Broadcaster,
};
use thiserror::Error;
use tracing::{debug, warn};

/// `bitcoind` returns this string in `package_msg` iff every transaction in the package was
/// accepted into the mempool (or was already present).
const PACKAGE_MSG_SUCCESS: &str = "success";

/// Successful `submitpackage` outcome — every transaction in the package was either newly
/// accepted into the mempool or already present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitPackageSummary {
    /// Per-transaction result keyed by [`Txid`]. Tracks which submitted txs were accepted vs.
    /// already-in-mempool, plus per-tx fee/vsize where bitcoind reported them.
    pub tx_results: BTreeMap<Txid, TxOutcome>,
    /// `[Txid]`s of any in-mempool transactions that this package's submission replaced via
    /// RBF. Used by callers tracking RBF lineage (typically just the prior CPFP child).
    pub replaced: Vec<Txid>,
}

/// Per-transaction outcome inside a successful package submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutcome {
    /// Sigops-adjusted virtual size, when bitcoind reports one.
    pub vsize: Option<u32>,
    /// Base fee + effective fee rate when bitcoind reports them. `effective_fee_rate` is
    /// `None` for transactions that were already in the mempool.
    pub fees: Option<TxFees>,
    /// `Some(wtxid)` if bitcoind ignored this submission because a different witness for the
    /// same txid was already in the mempool. Callers may use this as a signal that a prior
    /// broadcast won the race.
    pub conflicting_wtxid: Option<Wtxid>,
}

/// Fee/fee-rate details bitcoind reports per accepted transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxFees {
    /// Base fee in sats.
    pub base_fee: bitcoin::Amount,
    /// Effective fee rate (`None` if the transaction was already in the mempool — no rate was
    /// computed because the tx wasn't newly accepted).
    pub effective_fee_rate: Option<bitcoin::FeeRate>,
}

/// Errors produced by [`submit_package`].
#[derive(Debug, Error)]
pub enum SubmitPackageError {
    /// The RPC call itself failed (network, auth, deserialization, etc).
    #[error("submitpackage rpc: {0}")]
    Rpc(#[from] ClientError),
    /// `bitcoind` returned a non-success `package_msg`. Carries the message and any per-tx
    /// rejection reasons it reported. Typical causes: package-level policy violations
    /// (`package-not-valid`, `package-fee-too-low`), or RBF rule failures
    /// (`replacement-adds-unconfirmed`, `insufficient-fee`).
    #[error("submitpackage rejected: {message}")]
    Rejected {
        /// The raw `package_msg` from bitcoind.
        message: String,
        /// Per-tx error strings when bitcoind reported any. Empty if the rejection was
        /// purely at the package level.
        tx_errors: Vec<(Txid, String)>,
    },
}

/// Submits a transaction package via the `submitpackage` RPC.
///
/// Returns [`Ok`] only when bitcoind reports `package_msg == "success"`, which means every
/// transaction in `txs` is now in the mempool (either newly accepted or already present
/// before submission).
///
/// On any other outcome — RPC failure, package rejection, per-tx rejection — returns
/// [`SubmitPackageError`]. Per-tx error strings are surfaced verbatim in `tx_errors`.
///
/// # Notes
///
/// * Bitcoin Core's `submitpackage` expects the transactions in topological order (parent before
///   child). Callers must ensure this; this wrapper does not reorder.
/// * The `replaced_transactions` field of bitcoind's response is surfaced in
///   [`SubmitPackageSummary::replaced`]. Callers using this wrapper for RBF will typically find
///   their prior CPFP child's txid here.
pub async fn submit_package<B: Broadcaster + ?Sized>(
    client: &B,
    txs: &[Transaction],
) -> Result<SubmitPackageSummary, SubmitPackageError> {
    debug!(
        count = txs.len(),
        first_txid = ?txs.first().map(Transaction::compute_txid),
        "submitting package via submitpackage rpc"
    );
    let response = client.submit_package(txs).await?;

    if response.package_msg != PACKAGE_MSG_SUCCESS {
        let tx_errors = collect_tx_errors(&response);
        warn!(
            package_msg = %response.package_msg,
            n_tx_errors = tx_errors.len(),
            "submitpackage was rejected by bitcoind"
        );
        return Err(SubmitPackageError::Rejected {
            message: response.package_msg,
            tx_errors,
        });
    }

    Ok(summarize_success(response))
}

/// Walks `tx_results` and pulls out any per-tx `error` strings, keyed by the public [`Txid`].
fn collect_tx_errors(response: &SubmitPackage) -> Vec<(Txid, String)> {
    response
        .tx_results
        .values()
        .filter_map(|res: &SubmitPackageTxResult| {
            res.error.as_ref().map(|err| (res.txid, err.clone()))
        })
        .collect()
}

/// Builds the typed summary from a successful response.
fn summarize_success(response: SubmitPackage) -> SubmitPackageSummary {
    let tx_results = response
        .tx_results
        .into_values()
        .map(|res| {
            let outcome = TxOutcome {
                vsize: res.vsize,
                fees: res.fees.map(|f| TxFees {
                    base_fee: f.base_fee,
                    effective_fee_rate: f.effective_fee_rate,
                }),
                conflicting_wtxid: res.other_wtxid,
            };
            (res.txid, outcome)
        })
        .collect();
    SubmitPackageSummary {
        tx_results,
        replaced: response.replaced_transactions,
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute, hashes::Hash, transaction::Version, Amount, Transaction, TxOut, Wtxid,
    };
    use bitcoind_async_client::{
        corepc_types::model::{SubmitPackage, SubmitPackageTxResult, SubmitPackageTxResultFees},
        error::ClientError,
        ClientResult,
    };

    use super::*;

    /// Stub [`Broadcaster`] that returns a configured `submit_package` response. Other methods
    /// panic — fee-source / tx-driver tests have their own seams.
    #[derive(Debug)]
    struct MockBroadcaster {
        response: ClientResult<SubmitPackage>,
    }

    impl Broadcaster for MockBroadcaster {
        async fn send_raw_transaction(&self, _tx: &Transaction) -> ClientResult<Txid> {
            unimplemented!("not used by submit_package tests")
        }

        async fn test_mempool_accept(
            &self,
            _tx: &Transaction,
        ) -> ClientResult<bitcoind_async_client::corepc_types::model::TestMempoolAccept> {
            unimplemented!("not used by submit_package tests")
        }

        async fn submit_package(&self, _txs: &[Transaction]) -> ClientResult<SubmitPackage> {
            self.response.clone()
        }
    }

    fn dummy_tx(lock_time_seed: u32) -> Transaction {
        Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::from_consensus(lock_time_seed),
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(330),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }

    fn success_response(parent: &Transaction, child: &Transaction) -> SubmitPackage {
        let parent_txid = parent.compute_txid();
        let child_txid = child.compute_txid();
        let parent_wtxid = parent.compute_wtxid();
        let child_wtxid = child.compute_wtxid();
        let mut tx_results = BTreeMap::new();
        tx_results.insert(
            parent_wtxid,
            SubmitPackageTxResult {
                txid: parent_txid,
                other_wtxid: None,
                vsize: Some(110),
                fees: Some(SubmitPackageTxResultFees {
                    base_fee: Amount::from_sat(220),
                    effective_fee_rate: bitcoin::FeeRate::from_sat_per_vb(2),
                    effective_includes: vec![parent_wtxid],
                }),
                error: None,
            },
        );
        tx_results.insert(
            child_wtxid,
            SubmitPackageTxResult {
                txid: child_txid,
                other_wtxid: None,
                vsize: Some(150),
                fees: Some(SubmitPackageTxResultFees {
                    base_fee: Amount::from_sat(2_000),
                    effective_fee_rate: bitcoin::FeeRate::from_sat_per_vb(15),
                    effective_includes: vec![child_wtxid],
                }),
                error: None,
            },
        );
        SubmitPackage {
            package_msg: "success".to_string(),
            tx_results,
            replaced_transactions: vec![],
        }
    }

    #[tokio::test]
    async fn success_returns_summary_with_per_tx_outcomes() {
        let parent = dummy_tx(0);
        let child = dummy_tx(1);
        let response = success_response(&parent, &child);
        let client = MockBroadcaster {
            response: Ok(response),
        };

        let summary = submit_package(&client, &[parent.clone(), child.clone()])
            .await
            .expect("success response must produce Ok");

        assert_eq!(summary.tx_results.len(), 2);
        assert!(summary.tx_results.contains_key(&parent.compute_txid()));
        assert!(summary.tx_results.contains_key(&child.compute_txid()));
        assert!(summary.replaced.is_empty());

        let parent_outcome = &summary.tx_results[&parent.compute_txid()];
        assert_eq!(parent_outcome.vsize, Some(110));
        assert_eq!(
            parent_outcome.fees.as_ref().map(|f| f.base_fee),
            Some(Amount::from_sat(220))
        );
        assert!(parent_outcome.conflicting_wtxid.is_none());
    }

    #[tokio::test]
    async fn success_reports_replaced_transactions() {
        let parent = dummy_tx(0);
        let child = dummy_tx(1);
        let replaced_child = Txid::from_slice(&[7u8; 32]).unwrap();
        let mut response = success_response(&parent, &child);
        response.replaced_transactions = vec![replaced_child];

        let client = MockBroadcaster {
            response: Ok(response),
        };
        let summary = submit_package(&client, &[parent, child]).await.unwrap();
        assert_eq!(summary.replaced, vec![replaced_child]);
    }

    #[tokio::test]
    async fn package_level_rejection_surfaces_as_rejected() {
        let parent = dummy_tx(0);
        let child = dummy_tx(1);
        let response = SubmitPackage {
            package_msg: "package-not-valid".to_string(),
            tx_results: BTreeMap::new(),
            replaced_transactions: vec![],
        };
        let client = MockBroadcaster {
            response: Ok(response),
        };

        let err = submit_package(&client, &[parent, child])
            .await
            .expect_err("non-success package_msg must be an error");
        match err {
            SubmitPackageError::Rejected { message, tx_errors } => {
                assert_eq!(message, "package-not-valid");
                assert!(tx_errors.is_empty());
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn per_tx_rejection_surfaces_in_tx_errors() {
        let parent = dummy_tx(0);
        let child = dummy_tx(1);
        let parent_txid = parent.compute_txid();
        let child_wtxid = child.compute_wtxid();
        let parent_wtxid = parent.compute_wtxid();
        let mut tx_results = BTreeMap::new();
        tx_results.insert(
            parent_wtxid,
            SubmitPackageTxResult {
                txid: parent_txid,
                other_wtxid: None,
                vsize: None,
                fees: None,
                error: Some("bad-txns-in-mempool".to_string()),
            },
        );
        tx_results.insert(
            child_wtxid,
            SubmitPackageTxResult {
                txid: child.compute_txid(),
                other_wtxid: None,
                vsize: None,
                fees: None,
                error: None,
            },
        );
        let response = SubmitPackage {
            package_msg: "package-mempool-error".to_string(),
            tx_results,
            replaced_transactions: vec![],
        };
        let client = MockBroadcaster {
            response: Ok(response),
        };

        let err = submit_package(&client, &[parent, child]).await.unwrap_err();
        match err {
            SubmitPackageError::Rejected { tx_errors, .. } => {
                assert_eq!(tx_errors.len(), 1);
                assert_eq!(tx_errors[0].0, parent_txid);
                assert_eq!(tx_errors[0].1, "bad-txns-in-mempool");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rpc_failure_surfaces_as_rpc() {
        let parent = dummy_tx(0);
        let client = MockBroadcaster {
            response: Err(ClientError::Request("boom".to_string())),
        };
        let err = submit_package(&client, &[parent]).await.unwrap_err();
        assert!(matches!(err, SubmitPackageError::Rpc(_)));
    }

    #[tokio::test]
    async fn conflicting_wtxid_propagated_into_outcome() {
        let parent = dummy_tx(0);
        let child = dummy_tx(1);
        let parent_txid = parent.compute_txid();
        let other_wtxid = Wtxid::from_slice(&[9u8; 32]).unwrap();
        let parent_wtxid = parent.compute_wtxid();
        let child_wtxid = child.compute_wtxid();
        let mut tx_results = BTreeMap::new();
        tx_results.insert(
            parent_wtxid,
            SubmitPackageTxResult {
                txid: parent_txid,
                other_wtxid: Some(other_wtxid),
                vsize: Some(110),
                fees: None,
                error: None,
            },
        );
        tx_results.insert(
            child_wtxid,
            SubmitPackageTxResult {
                txid: child.compute_txid(),
                other_wtxid: None,
                vsize: Some(150),
                fees: None,
                error: None,
            },
        );
        let response = SubmitPackage {
            package_msg: "success".to_string(),
            tx_results,
            replaced_transactions: vec![],
        };
        let client = MockBroadcaster {
            response: Ok(response),
        };
        let summary = submit_package(&client, &[parent.clone(), child])
            .await
            .unwrap();
        assert_eq!(
            summary.tx_results[&parent_txid].conflicting_wtxid,
            Some(other_wtxid)
        );
    }
}
