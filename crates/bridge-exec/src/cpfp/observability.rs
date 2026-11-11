//! Metric names and bounded labels of the CPFP ladder.
//!
//! Parent and child txids deliberately do not appear in metric labels. They belong in the logs,
//! where they do not create unbounded Prometheus series.

use bitcoin::Amount;
use btc_tracker::cpfp::DeadlineClass;
use metrics::{counter, describe_counter};

const CHILD_FEE_SATS_TOTAL: &str = "strata_bridge_cpfp_child_fee_sats_total";
const CHILDREN_ACCEPTED_TOTAL: &str = "strata_bridge_cpfp_children_accepted_total";
const CAPPED_ATTEMPTS_TOTAL: &str = "strata_bridge_cpfp_capped_attempts_total";

/// Why [`max_fee_rate`](crate::fees::FeeTargetPolicy::max_fee_rate) held a parent back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapReason {
    /// The target asked for more than the cap.
    Target,
}

impl CapReason {
    const fn label(self) -> &'static str {
        match self {
            Self::Target => "target",
        }
    }
}

/// Bounded label of the parent of a child.
pub(crate) const fn parent_label(deadline: DeadlineClass) -> &'static str {
    match deadline {
        DeadlineClass::Deadline => "deadline",
        DeadlineClass::NoDeadline => "no_deadline",
    }
}

/// Registers the descriptions of the metrics of this module. Run once at startup.
pub fn describe_metrics() {
    describe_counter!(
        CHILD_FEE_SATS_TOTAL,
        "Fee of every CPFP child that a mempool accepted, in sats. Only the child that confirms \
         pays, so this is an upper bound on the wallet spend."
    );
    describe_counter!(
        CHILDREN_ACCEPTED_TOTAL,
        "CPFP children that a mempool accepted"
    );
    describe_counter!(
        CAPPED_ATTEMPTS_TOTAL,
        "Bump attempts that max_fee_rate held back, once per attempt, by reason"
    );
}

/// Counts one child that a mempool accepted.
pub(crate) fn record_accepted_child(deadline: DeadlineClass, fee: Amount) {
    let parent = parent_label(deadline);
    counter!(CHILD_FEE_SATS_TOTAL, "parent" => parent).increment(fee.to_sat());
    counter!(CHILDREN_ACCEPTED_TOTAL, "parent" => parent).increment(1);
}

/// Counts one bump attempt that the cap held back.
pub(crate) fn record_capped_attempt(deadline: DeadlineClass, reason: CapReason) {
    counter!(
        CAPPED_ATTEMPTS_TOTAL,
        "parent" => parent_label(deadline),
        "reason" => reason.label()
    )
    .increment(1);
}
