//! Deposit admission status of the covenant that is current after the last processed block.
//!
//! A ready covenant is reported only when every member's usable stake was processed through the
//! same block as the membership. A view assembled from rows written at different blocks therefore
//! never presents an earlier or later stake as positive readiness.

use std::collections::{BTreeMap, BTreeSet};

use strata_bridge_primitives::{
    covenant::StakeKey,
    types::{BitcoinBlockHeight, OperatorIdx},
};
use strata_bridge_sm::{
    operator_set::{BlockCovenant, OperatorSetError, OperatorSetSM},
    stake::machine::StakeSM,
};
use thiserror::Error;

use crate::stake_readiness::{self, CovenantStakes, ReadinessError, StakeShortfall};

/// The covenant that is current after the last processed block and whether it admits deposits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentCovenant {
    /// The last block reflected by the membership.
    pub processed_height: BitcoinBlockHeight,
    /// The covenant and its membership after that block.
    pub block_covenant: BlockCovenant,
    /// Whether a deposit request addressed to the covenant would be admitted.
    pub admission: Admission,
}

/// Whether the current covenant admits new deposits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Every member holds a usable stake for the covenant.
    Ready,
    /// Safe harbour is active, so no new deposits are admitted.
    SafeHarbour,
    /// This node's deposit cap is full, so it would register a new request without taking part
    /// in its deposit.
    DepositCapReached,
    /// These members lack a usable stake for the covenant.
    Unready(BTreeMap<OperatorIdx, StakeShortfall>),
    /// These members' usable stakes were processed through a different block than the
    /// membership, so readiness cannot be established yet.
    Unsettled(BTreeSet<OperatorIdx>),
}

/// Why the current covenant's status could not be derived.
#[derive(Debug, Error)]
pub enum CurrentCovenantError {
    /// The membership could not produce its block-final covenant.
    #[error("cannot derive the current covenant: {0}")]
    Membership(#[from] OperatorSetError),
    /// The membership's covenant does not match its own operator table.
    #[error("cannot assess the current covenant: {0}")]
    Readiness(ReadinessError),
}

/// Reports the covenant that `membership` holds after its last processed block and whether it
/// admits deposits.
pub fn assess(
    membership: &OperatorSetSM,
    stakes: &BTreeMap<StakeKey, StakeSM>,
    safe_harbour_active: bool,
    deposit_cap_reached: bool,
) -> Result<CurrentCovenant, CurrentCovenantError> {
    let processed_height = membership.last_block_height();
    let block_covenant = membership.covenant_at(processed_height)?;
    let admission = if safe_harbour_active {
        Admission::SafeHarbour
    } else if deposit_cap_reached {
        Admission::DepositCapReached
    } else {
        match stake_readiness::assess(&block_covenant, stakes) {
            Ok(CovenantStakes {
                covenant,
                stakes: bindings,
            }) => {
                let unsettled: BTreeSet<_> = bindings
                    .into_keys()
                    .filter(|&operator| {
                        stakes
                            .get(&StakeKey { covenant, operator })
                            .and_then(|stake| stake.state().last_processed_block_height())
                            != Some(processed_height)
                    })
                    .collect();
                if unsettled.is_empty() {
                    Admission::Ready
                } else {
                    Admission::Unsettled(unsettled)
                }
            }
            Err(ReadinessError::Unready { shortfalls, .. }) => Admission::Unready(shortfalls),
            Err(err @ ReadinessError::CovenantMismatch(_)) => {
                return Err(CurrentCovenantError::Readiness(err));
            }
        }
    };
    Ok(CurrentCovenant {
        processed_height,
        block_covenant,
        admission,
    })
}

#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::prelude::generate_txid;

    use super::*;
    use crate::{
        sm_registry::SMRegistry,
        testing::{
            INITIAL_BLOCK_HEIGHT, insert_confirmed_stake, insert_test_membership,
            test_empty_registry, test_membership_table, test_registry_with_cap,
            test_safe_harbour_address,
        },
    };

    /// Returns a registry whose membership was processed through `height` and whose members hold
    /// stakes confirmed at the initial height.
    fn staked_registry(height: BitcoinBlockHeight) -> SMRegistry {
        let mut registry = test_empty_registry();
        insert_test_membership(&mut registry, height);
        let table = test_membership_table();
        for operator in table.operator_idxs() {
            insert_confirmed_stake(&mut registry, operator, table.clone(), generate_txid());
        }
        registry
    }

    fn admission(registry: &SMRegistry) -> Admission {
        registry
            .current_covenant()
            .unwrap()
            .expect("membership is initialized")
            .admission
    }

    #[test]
    fn no_covenant_is_current_before_membership_is_initialized() {
        assert_eq!(
            test_empty_registry().current_covenant().unwrap(),
            None,
            "A registry without membership must not report a covenant"
        );
    }

    #[test]
    fn a_covenant_whose_members_hold_usable_stakes_admits_deposits() {
        let registry = staked_registry(INITIAL_BLOCK_HEIGHT);
        let membership = registry.get_operator_set().unwrap();
        assert_eq!(
            registry.current_covenant().unwrap(),
            Some(CurrentCovenant {
                processed_height: INITIAL_BLOCK_HEIGHT,
                block_covenant: membership.covenant_at(INITIAL_BLOCK_HEIGHT).unwrap(),
                admission: Admission::Ready,
            }),
            "The block-final covenant must be ready when every member's stake is usable"
        );
    }

    #[test]
    fn missing_stakes_and_safe_harbour_refuse_admission() {
        let mut registry = test_empty_registry();
        insert_test_membership(&mut registry, INITIAL_BLOCK_HEIGHT);
        let missing = test_membership_table()
            .operator_idxs()
            .into_iter()
            .map(|operator| (operator, StakeShortfall::Missing))
            .collect();
        assert_eq!(
            admission(&registry),
            Admission::Unready(missing),
            "Public membership alone must not be reported as ready"
        );

        let mut registry = staked_registry(INITIAL_BLOCK_HEIGHT);
        registry.activate_safe_harbour(test_safe_harbour_address());
        assert_eq!(
            admission(&registry),
            Admission::SafeHarbour,
            "Safe harbour must refuse admission even when every stake is usable"
        );
    }

    #[test]
    fn a_full_deposit_cap_refuses_admission_after_safe_harbour() {
        let mut registry = test_registry_with_cap(Some(0));
        insert_test_membership(&mut registry, INITIAL_BLOCK_HEIGHT);
        assert_eq!(
            admission(&registry),
            Admission::DepositCapReached,
            "A full deposit cap must refuse admission before stakes are assessed"
        );

        let table = test_membership_table();
        for operator in table.operator_idxs() {
            insert_confirmed_stake(&mut registry, operator, table.clone(), generate_txid());
        }
        assert_eq!(
            admission(&registry),
            Admission::DepositCapReached,
            "A full deposit cap must refuse admission even when every stake is usable"
        );

        registry.activate_safe_harbour(test_safe_harbour_address());
        assert_eq!(
            admission(&registry),
            Admission::SafeHarbour,
            "Safe harbour must take precedence over a full deposit cap"
        );
    }

    #[test]
    fn stakes_processed_through_another_block_are_not_reported_ready() {
        let registry = staked_registry(INITIAL_BLOCK_HEIGHT + 1);
        assert_eq!(
            admission(&registry),
            Admission::Unsettled(test_membership_table().operator_idxs()),
            "Stakes from an earlier block than the membership must not establish readiness"
        );
    }
}
