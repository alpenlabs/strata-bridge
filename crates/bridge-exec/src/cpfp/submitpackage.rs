//! Typed wrapper around `bitcoind`'s `submitpackage` RPC.
//!
//! `bitcoind-async-client`'s `Reader::submit_package` returns a `corepc-types::SubmitPackage`
//! struct whose `package_msg: String` carries the package-level outcome ("success" iff every
//! tx in the package was accepted into or already present in the mempool). This wrapper turns
//! that into a typed result so call sites can pattern-match on outcomes rather than string-compare.
//!
//! Used by a CPFP bump when broadcasting `[parent, child]` v3 1P1C CPFP packages.

use bitcoin::{Amount, FeeRate, Transaction, Txid};
use bitcoind_async_client::{
    corepc_types::model::{SubmitPackage, SubmitPackageTxResult},
    error::ClientError,
    traits::Broadcaster,
    types::BroadcastOptions,
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
    /// [`Txid`]s of any in-mempool transactions that this package's submission replaced via
    /// RBF.
    pub replaced: Vec<Txid>,
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

/// Which replacement rule the node applied to reject a package member.
///
/// The ladder reads only whether a replacement rejection happened. The two variants exist for the
/// log line: the design review of 2026-11-02 asks for the rule-6 rejection to be told apart from
/// the rules 3 and 4 one, because the first is our own oversized replacement and the second is
/// the shared-anchor race by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplacementRejection {
    /// The own fee rate of the new transaction does not beat the transaction it replaces (BIP-125
    /// rule 6, in Bitcoin Core before v31). The usual cause is our own replacement that took
    /// another funding input and grew.
    OwnRateBelowIncumbent,
    /// The absolute fee of the new transaction does not beat the transaction it replaces (BIP-125
    /// rules 3 and 4). A shared `MultiAnchor` produces this by design: every watchtower of the
    /// graph bumps the same anchor at the same market rate, and the first one gets in. A loser
    /// reads this once, and the probe stands it down on the next trigger.
    FeeBelowIncumbent,
}

impl ReplacementRejection {
    /// Reads the rule from a per-transaction error of bitcoind.
    ///
    /// bitcoind reports rule 6 in the form
    /// `insufficient fee, rejecting replacement <txid>; new feerate <a> <= old feerate <b>`, and
    /// rules 3 and 4 in the form
    /// `insufficient fee, rejecting replacement <txid>, not enough additional fees to relay`.
    fn of(error: &str) -> Option<Self> {
        if !error.contains(REPLACEMENT_CONTENTION_MARKER) {
            return None;
        }
        Some(if error.contains(OWN_RATE_REJECTION_MARKER) {
            Self::OwnRateBelowIncumbent
        } else {
            Self::FeeBelowIncumbent
        })
    }
}

impl SubmitPackageError {
    /// Which replacement rule rejected a member of the package, if one did.
    pub fn replacement_rejection(&self) -> Option<ReplacementRejection> {
        match self {
            Self::Rejected { tx_errors, .. } => tx_errors
                .iter()
                .find_map(|(_, err)| ReplacementRejection::of(err)),
            Self::Rpc(_) => None,
        }
    }

    /// Whether bitcoind refused the package because an input does not exist. A spend in the
    /// mempool does not read as this, because that is a conflict the package can replace. The
    /// caller's view of its inputs is behind the chain.
    pub fn is_missing_inputs(&self) -> bool {
        let names_missing_input = |text: &str| {
            MISSING_INPUT_MARKERS
                .iter()
                .any(|marker| text.contains(marker))
        };
        match self {
            Self::Rejected { message, tx_errors } => {
                names_missing_input(message)
                    || tx_errors.iter().any(|(_, err)| names_missing_input(err))
            }
            Self::Rpc(_) => false,
        }
    }

    /// Whether the package member `txid` itself lost a replacement race.
    ///
    /// The per-tx entries key on the members of the submitted package, so this reports which
    /// of the package's own transactions bitcoind declined. A rejection on the child means a
    /// transaction in the mempool spends one of the child's inputs. A rejection on the parent
    /// means a conflict with the parent itself is in the mempool, and the parent is not.
    pub fn is_replacement_contention_for(&self, txid: &Txid) -> bool {
        match self {
            Self::Rejected { tx_errors, .. } => tx_errors
                .iter()
                .any(|(t, err)| t == txid && ReplacementRejection::of(err).is_some()),
            Self::Rpc(_) => false,
        }
    }
}

/// What bitcoind reports when a package spends an output that the chain does not hold.
///
/// The first is the topology check of `submitpackage`, which sees a child input that is neither
/// a confirmed coin nor an output of the package. The rest come from the per-transaction check.
const MISSING_INPUT_MARKERS: [&str; 3] = [
    "package-not-child-with-unconfirmed-parents",
    "bad-txns-inputs-missingorspent",
    "missing-inputs",
];

/// Substring that bitcoind uses when it declines a replacement for paying too little.
///
/// Matching on a message is brittle in general. It is the only signal available here, because
/// `submitpackage` reports per-transaction outcomes as free text. The e2e test
/// `cpfp_e2e_multi_anchor_contention_is_quiet` pins the real string against a live bitcoind, so
/// a change upstream fails a test.
const REPLACEMENT_CONTENTION_MARKER: &str = "rejecting replacement";

/// Substring that sets a rule 6 rejection apart from the other replacement rejections.
const OWN_RATE_REJECTION_MARKER: &str = "new feerate";

/// Computes the `maxburnamount` guard for a whole package submission.
///
/// Mirrors the per-transaction logic the tx-driver applies to bare rebroadcasts, lifted to
/// package scope: bitcoind applies the guard to the submission as a whole, so we take the
/// largest valued `OP_RETURN` output across every transaction in the package. Bridge txs carry
/// SPS-50 header outputs, and any that hold value would otherwise trip bitcoind's burn guard
/// and get the entire package rejected.
///
/// Always returns options: the fee-rate cap is disabled unconditionally, and
/// `max_burn_amount` is set when some transaction in the package has a valued `OP_RETURN`.
///
/// The cap is disabled for a structural reason. bitcoind applies its default `maxfeerate`
/// (0.10 BTC/kvB) to each transaction individually. A CPFP child concentrates the whole
/// package's fee into its own few vbytes, so its individual rate is near `target ×
/// package_vbytes / child_vbytes` — a large multiple of each target a bump sets. A
/// per-transaction guard on the child alone rejects well-formed high-ratio packages. A
/// bump already caps the package price: `max_fee_rate` bounds the target and every
/// replacement before the build. Zero turns the bitcoind check off.
fn package_broadcast_options(txs: &[Transaction]) -> BroadcastOptions {
    let max_burn_amount = txs
        .iter()
        .flat_map(|tx| tx.output.iter())
        .filter(|output| output.value > Amount::ZERO && output.script_pubkey.is_op_return())
        .map(|output| output.value)
        .max();

    BroadcastOptions {
        max_burn_amount,
        max_fee_rate: Some(FeeRate::ZERO),
    }
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
///   [`SubmitPackageSummary::replaced`].
pub async fn submit_package<B: Broadcaster + ?Sized>(
    client: &B,
    txs: &[Transaction],
) -> Result<SubmitPackageSummary, SubmitPackageError> {
    debug!(
        count = txs.len(),
        first_txid = ?txs.first().map(Transaction::compute_txid),
        "submitting package via submitpackage rpc"
    );
    let response = client
        .submit_package(txs, Some(package_broadcast_options(txs)))
        .await?;

    if response.package_msg != PACKAGE_MSG_SUCCESS {
        let tx_errors = collect_tx_errors(&response);
        let rejection = SubmitPackageError::Rejected {
            message: response.package_msg,
            tx_errors,
        };
        // A replacement rejection is not a fault of this call. The ladder reads it against the
        // live child and warns when the parent stays below its target.
        match rejection.replacement_rejection() {
            Some(ReplacementRejection::OwnRateBelowIncumbent) => {
                debug!(error = %rejection, "submitpackage refused a child with a low own rate");
            }
            Some(ReplacementRejection::FeeBelowIncumbent) => {
                debug!(error = %rejection, "submitpackage lost a race for the child slot");
            }
            None => warn!(error = %rejection, "submitpackage was rejected by bitcoind"),
        }
        return Err(rejection);
    }

    Ok(SubmitPackageSummary {
        replaced: response.replaced_transactions,
    })
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Mutex};

    use bitcoin::{Amount, Transaction, TxOut, absolute, hashes::Hash, transaction::Version};
    use bitcoind_async_client::{
        ClientResult,
        corepc_types::model::{SubmitPackage, SubmitPackageTxResult, SubmitPackageTxResultFees},
    };

    use super::*;

    fn rejected_with(error: &str) -> SubmitPackageError {
        SubmitPackageError::Rejected {
            message: "transaction failed".to_string(),
            tx_errors: vec![(Txid::from_byte_array([1; 32]), error.to_string())],
        }
    }

    #[test]
    fn a_rule_6_rejection_reads_apart_from_shared_anchor_contention() {
        let rule_6 = rejected_with(
            "insufficient fee, rejecting replacement aa; new feerate 0.00039 BTC/kvB <= old \
             feerate 0.00040 BTC/kvB",
        );
        let rule_3 = rejected_with(
            "insufficient fee, rejecting replacement aa, less fees than conflicting txs; 1 < 2",
        );
        let rule_4 = rejected_with(
            "insufficient fee, rejecting replacement aa, not enough additional fees to relay; 1 < 2",
        );

        assert_eq!(
            rule_6.replacement_rejection(),
            Some(ReplacementRejection::OwnRateBelowIncumbent)
        );
        for rejection in [rule_3, rule_4] {
            assert_eq!(
                rejection.replacement_rejection(),
                Some(ReplacementRejection::FeeBelowIncumbent)
            );
        }
    }

    #[test]
    fn another_rejection_is_not_a_replacement_rejection() {
        let error = rejected_with("mempool min fee not met");
        assert_eq!(error.replacement_rejection(), None);
    }

    /// Stub [`Broadcaster`] that returns a configured `submit_package` response. Other methods
    /// panic — fee-source / tx-driver tests have their own seams.
    #[derive(Debug)]
    struct MockBroadcaster {
        response: ClientResult<SubmitPackage>,
        captured_options: Mutex<Vec<Option<BroadcastOptions>>>,
    }

    impl Broadcaster for MockBroadcaster {
        async fn send_raw_transaction(
            &self,
            _tx: &Transaction,
            _options: Option<BroadcastOptions>,
        ) -> ClientResult<Txid> {
            unimplemented!("not used by submit_package tests")
        }

        async fn test_mempool_accept(
            &self,
            _tx: &Transaction,
        ) -> ClientResult<bitcoind_async_client::corepc_types::model::TestMempoolAccept> {
            unimplemented!("not used by submit_package tests")
        }

        async fn submit_package(
            &self,
            _txs: &[Transaction],
            options: Option<BroadcastOptions>,
        ) -> ClientResult<SubmitPackage> {
            self.captured_options.lock().unwrap().push(options);
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
    async fn success_reports_replaced_transactions() {
        let parent = dummy_tx(0);
        let child = dummy_tx(1);
        let replaced_child = Txid::from_slice(&[7u8; 32]).unwrap();
        let mut response = success_response(&parent, &child);
        response.replaced_transactions = vec![replaced_child];

        let client = MockBroadcaster {
            response: Ok(response),
            captured_options: Mutex::new(Vec::new()),
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
            captured_options: Mutex::new(Vec::new()),
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

    #[test]
    fn a_spent_input_reads_as_a_missing_input() {
        let rejected = |message: &str, tx_error: &str| SubmitPackageError::Rejected {
            message: message.to_string(),
            tx_errors: vec![(dummy_tx(0).compute_txid(), tx_error.to_string())],
        };
        assert!(rejected("package-not-child-with-unconfirmed-parents", "").is_missing_inputs());
        assert!(
            rejected("transaction failed", "bad-txns-inputs-missingorspent").is_missing_inputs()
        );
        assert!(rejected("transaction failed", "missing-inputs").is_missing_inputs());
        assert!(
            !rejected(
                "transaction failed",
                "insufficient fee, rejecting replacement"
            )
            .is_missing_inputs()
        );
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
            captured_options: Mutex::new(Vec::new()),
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

    /// The package-level `maxburnamount` guard is what lets packages containing valued
    /// SPS-50 `OP_RETURN` outputs (e.g. a slash parent) through bitcoind's burn protection.
    /// Deleting `package_broadcast_options` compiles fine and every response-mapping test
    /// still passes — this pins the actual option bitcoind receives.
    #[tokio::test]
    async fn valued_op_return_sets_max_burn_amount() {
        use bitcoin::{Amount, opcodes, script};

        let mut burn_tx = dummy_tx(7);
        burn_tx.output.push(bitcoin::TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: script::Builder::new()
                .push_opcode(opcodes::all::OP_RETURN)
                .push_slice([0xAB; 8])
                .into_script(),
        });
        let plain_tx = dummy_tx(8);

        let client = MockBroadcaster {
            response: Ok(success_response(&burn_tx, &plain_tx)),
            captured_options: Mutex::new(Vec::new()),
        };

        submit_package(&client, &[burn_tx.clone(), plain_tx.clone()])
            .await
            .expect("mocked success");
        let first_options = client.captured_options.lock().unwrap()[0]
            .clone()
            .expect("options are always set");
        assert_eq!(
            first_options.max_burn_amount,
            Some(Amount::from_sat(1_000)),
            "guard must cover the largest valued OP_RETURN in the package"
        );
        assert_eq!(
            first_options.max_fee_rate,
            Some(bitcoin::FeeRate::ZERO),
            "the per-transaction fee cap must be disabled"
        );

        // A package with no valued OP_RETURN still disables the fee cap. A CPFP child
        // concentrates the whole package's fee into its own few vbytes, and the default
        // per-transaction `maxfeerate` rejects such well-formed high-ratio packages. Burn
        // stays on its default.
        let other_plain = dummy_tx(9);
        let client = MockBroadcaster {
            response: Ok(success_response(&plain_tx, &other_plain)),
            captured_options: Mutex::new(Vec::new()),
        };
        submit_package(&client, &[plain_tx, other_plain])
            .await
            .expect("mocked success");
        let plain_options = client.captured_options.lock().unwrap()[0]
            .clone()
            .expect("options are always set");
        assert_eq!(plain_options.max_burn_amount, None);
        assert_eq!(plain_options.max_fee_rate, Some(bitcoin::FeeRate::ZERO));
    }
}
