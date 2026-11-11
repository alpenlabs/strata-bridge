//! The CPFP bump policy: a pure function from what an attempt read to what it does.

use bitcoin::{Amount, FeeRate};

use super::interfaces::ParentProbe;
use crate::fees::FeeTargetPolicy;

/// Everything [`decide`] reads.
#[derive(Debug, Clone, Copy)]
pub(super) struct BumpInputs {
    /// Next-block rate of the fee source.
    pub(super) estimate: FeeRate,
    /// Fee settings of the operator.
    pub(super) policy: FeeTargetPolicy,
    /// [`CpfpMempool::min_fee_rate`] when the attempt read it. An attempt reads it only for an
    /// absent parent, to spare the RPC. The rule itself is in `decide`.
    pub(super) node_min: Option<FeeRate>,
    /// Size of the parent.
    pub(super) parent_vbytes: u64,
    /// Fee that the parent pays.
    pub(super) parent_fee: Amount,
    /// The probe of this attempt. `None` when it failed.
    pub(super) probe: Option<ParentProbe>,
    /// Whether the handle records a child that can be in a mempool.
    pub(super) child_may_be_live: bool,
}

/// What one attempt does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BumpAction {
    /// The parent meets the target alone. A child would only pay for its own vbytes, and a child
    /// asked to cover nothing can select no funding input and fail on a below-dust drain.
    ParentSuffices,
    /// A live child is in the mempool.
    StandDown,
    /// The probe failed and the handle records a child that can be live. The fee of that child is
    /// unknown, so a build cannot be priced to replace it, and each refused build costs a signing
    /// round and, through the rejection, the lease of a candidate.
    AwaitProbe,
    /// The node holds no parent and asks more than the cap for a package. A package cannot enter,
    /// so an attempt spends no lease and no signing round on one.
    NodeMinAboveCap,
    /// Build a child.
    Build,
}

/// What [`decide`] returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Decision {
    /// Package rate of this attempt. Never above the cap.
    pub(super) target: FeeRate,
    /// What the target would be with no cap.
    pub(super) wanted: FeeRate,
    /// What the attempt does.
    pub(super) action: BumpAction,
}

/// Decides one bump attempt.
///
/// ## Target
///
/// The target starts at the next-block estimate: a CPFP child must confirm in the next block.
///
/// The premium raises the estimate (a percentage, rounded up in sat/kwu) and
/// `min_package_fee_rate` floors the result. The floor bounds the package rate, and the child pays
/// the whole shortfall, so the package always lands at or above the floor. Sources report raw
/// market estimates; both settings are policy of this consumer.
///
/// `node_min` raises the target only while the node does not hold the parent. A package with
/// the parent in it must clear that rate as a package, or the node refuses it. With the parent in
/// the mempool, the node judges the child alone, and the child's own rate clears it. The target
/// therefore stays independent of the local mempool wherever that is possible.
///
/// The cap applies last, to all of the above.
///
/// ## Action
///
/// A parent that meets the target alone needs nothing, whatever the mempool holds. Otherwise, a
/// live child ends the attempt, and an empty slot gets a new child. A failed probe with a child on
/// the handle waits for the next trigger.
pub(super) fn decide(inputs: BumpInputs) -> Decision {
    let BumpInputs {
        estimate,
        policy,
        node_min,
        parent_vbytes,
        parent_fee,
        probe,
        child_may_be_live,
    } = inputs;

    let node_min = node_min.filter(|_| probe == Some(ParentProbe::Absent));
    let wanted = policy
        .wanted(estimate)
        .max(node_min.unwrap_or(FeeRate::ZERO));
    let target = wanted.min(policy.max_fee_rate);

    let parent_suffices = target
        .fee_vb(parent_vbytes)
        .is_some_and(|needed| parent_fee >= needed);
    let action = match probe {
        _ if parent_suffices => BumpAction::ParentSuffices,
        Some(ParentProbe::Absent) if node_min > Some(policy.max_fee_rate) => {
            BumpAction::NodeMinAboveCap
        }
        Some(ParentProbe::Child(_)) => BumpAction::StandDown,
        None if child_may_be_live => BumpAction::AwaitProbe,
        None | Some(ParentProbe::Absent | ParentProbe::NoChild) => BumpAction::Build,
    };

    Decision {
        target,
        wanted,
        action,
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use bitcoin::{Txid, hashes::Hash};
    use proptest::prelude::*;

    use super::*;
    use crate::cpfp::interfaces::MempoolChild;

    fn rate() -> impl Strategy<Value = FeeRate> {
        (0u64..4_000_000).prop_map(FeeRate::from_sat_per_kwu)
    }

    fn probe() -> impl Strategy<Value = Option<ParentProbe>> {
        let child = (0u64..10_000_000, 1u64..1000, rate()).prop_map(|(fee, vbytes, rate)| {
            ParentProbe::Child(MempoolChild {
                txid: Txid::from_byte_array([0xAA; 32]),
                fee: Amount::from_sat(fee),
                vbytes: NonZeroU64::new(vbytes).unwrap(),
                pkg_fee_rate: rate,
            })
        });
        prop_oneof![
            Just(None),
            Just(Some(ParentProbe::Absent)),
            Just(Some(ParentProbe::NoChild)),
            child.prop_map(Some),
        ]
    }

    fn bump_inputs() -> impl Strategy<Value = BumpInputs> {
        (
            (rate(), 0u32..1000, rate(), rate()),
            proptest::option::of(rate()),
            (1u64..100_000, 0u64..10_000_000),
            probe(),
            any::<bool>(),
        )
            .prop_map(
                |(
                    (estimate, premium_percent, min_package_fee_rate, max_fee_rate),
                    node_min,
                    (parent_vbytes, parent_fee),
                    probe,
                    child_may_be_live,
                )| BumpInputs {
                    estimate,
                    policy: FeeTargetPolicy {
                        premium_percent,
                        min_package_fee_rate,
                        max_fee_rate,
                    },
                    node_min,
                    parent_vbytes,
                    parent_fee: Amount::from_sat(parent_fee),
                    probe,
                    child_may_be_live,
                },
            )
    }

    proptest! {
        #[test]
        fn a_capped_target_sits_at_the_cap(inputs in bump_inputs()) {
            let decision = decide(inputs);
            if decision.wanted > inputs.policy.max_fee_rate {
                prop_assert_eq!(decision.target, inputs.policy.max_fee_rate);
            } else {
                prop_assert_eq!(decision.target, decision.wanted);
            }
        }

        #[test]
        fn the_target_reaches_the_floor_or_the_cap(inputs in bump_inputs()) {
            let policy = inputs.policy;
            prop_assert!(
                decide(inputs).target >= policy.min_package_fee_rate.min(policy.max_fee_rate)
            );
        }

        #[test]
        fn the_node_minimum_counts_only_for_an_absent_parent(inputs in bump_inputs()) {
            let without = BumpInputs { node_min: None, ..inputs };
            if inputs.probe != Some(ParentProbe::Absent) {
                prop_assert_eq!(decide(inputs), decide(without));
            } else {
                prop_assert!(decide(inputs).target >= decide(without).target);
            }
        }

        #[test]
        fn no_build_runs_at_or_above_the_target(inputs in bump_inputs()) {
            let decision = decide(inputs);
            if let (BumpAction::Build, Some(ParentProbe::Child(child))) =
                (decision.action, inputs.probe)
            {
                prop_assert!(child.pkg_fee_rate < decision.target);
            }
        }

        #[test]
        fn a_node_minimum_above_the_cap_never_builds(inputs in bump_inputs()) {
            let inputs = BumpInputs {
                node_min: Some(FeeRate::from_sat_per_kwu(
                    inputs.policy.max_fee_rate.to_sat_per_kwu() + 1,
                )),
                probe: Some(ParentProbe::Absent),
                ..inputs
            };
            let is_build = matches!(decide(inputs).action, BumpAction::Build);
            prop_assert!(!is_build);
        }

        #[test]
        fn a_failed_probe_with_a_recorded_child_never_builds(inputs in bump_inputs()) {
            let inputs = BumpInputs { probe: None, child_may_be_live: true, ..inputs };
            let is_build = matches!(decide(inputs).action, BumpAction::Build);
            prop_assert!(!is_build);
        }

    }
}
