//! Stake readiness of a covenant for admitting new deposits.
//!
//! A covenant is ready when every member has a confirmed stake keyed to that covenant and set up
//! for the same membership. If any member's stake is missing, unconfirmed, exited, or set up for
//! a different membership, the whole covenant is not ready.

use std::{collections::BTreeMap, fmt};

use bitcoin::{OutPoint, hashes::sha256};
use strata_bridge_primitives::{
    covenant::{CovenantId, StakeKey},
    operator_table::PublicOperatorTable,
    types::OperatorIdx,
};
use strata_bridge_sm::{
    operator_set::BlockCovenant,
    stake::{machine::StakeSM, state::StakeState},
};
use strata_bridge_tx_graph::transactions::stake::StakeTx;
use thiserror::Error;

/// The stake output and unstaking image that a member's graphs are bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StakeBinding {
    /// The stake output that watchtowers spend if the member is faulty.
    pub outpoint: OutPoint,
    /// The image whose preimage the member reveals when it starts unstaking.
    pub unstaking_image: sha256::Hash,
}

/// Usable stakes for every member of a ready covenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CovenantStakes {
    /// The covenant whose members all hold usable stakes.
    pub covenant: CovenantId,
    /// The stake binding of each member.
    pub stakes: BTreeMap<OperatorIdx, StakeBinding>,
}

/// Why a member's stake cannot back new deposits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakeShortfall {
    /// No stake state machine exists for the member in this covenant.
    Missing,
    /// The stake transaction has not confirmed yet.
    Unconfirmed,
    /// The member has started unstaking, has unstaked, or has been slashed.
    Exited,
    /// The stake was set up for a different membership than the covenant's.
    MembershipMismatch,
}

impl fmt::Display for StakeShortfall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::Missing => "missing",
            Self::Unconfirmed => "unconfirmed",
            Self::Exited => "exited",
            Self::MembershipMismatch => "membership mismatch",
        };
        f.write_str(description)
    }
}

/// Reasons a covenant cannot admit new deposits.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReadinessError {
    /// The covenant identifier was not derived from the supplied membership.
    #[error("covenant {0} does not match its operator table")]
    CovenantMismatch(CovenantId),
    /// At least one member lacks a usable stake.
    #[error("covenant {covenant} is not ready: {}", describe_shortfalls(.shortfalls))]
    Unready {
        /// The covenant that was assessed.
        covenant: CovenantId,
        /// Every member without a usable stake, and why.
        shortfalls: BTreeMap<OperatorIdx, StakeShortfall>,
    },
}

/// Assesses whether every member of `block_covenant` holds a usable stake for exactly that
/// covenant.
///
/// Every member is checked, so a [`ReadinessError::Unready`] error lists all shortfalls rather
/// than the first one found. Membership is never empty: [`BlockCovenant`] tables cannot be
/// constructed without members.
pub fn assess(
    block_covenant: &BlockCovenant,
    stakes: &BTreeMap<StakeKey, StakeSM>,
) -> Result<CovenantStakes, ReadinessError> {
    let BlockCovenant {
        covenant,
        operator_table,
    } = block_covenant;
    if CovenantId::from_operator_table(operator_table, covenant.activation_height) != Ok(*covenant)
    {
        return Err(ReadinessError::CovenantMismatch(*covenant));
    }

    let mut ready = BTreeMap::new();
    let mut shortfalls = BTreeMap::new();
    for operator in operator_table.operator_idxs() {
        let key = StakeKey {
            covenant: *covenant,
            operator,
        };
        match member_binding(stakes.get(&key), operator_table) {
            Ok(binding) => {
                ready.insert(operator, binding);
            }
            Err(shortfall) => {
                shortfalls.insert(operator, shortfall);
            }
        }
    }

    if shortfalls.is_empty() {
        Ok(CovenantStakes {
            covenant: *covenant,
            stakes: ready,
        })
    } else {
        Err(ReadinessError::Unready {
            covenant: *covenant,
            shortfalls,
        })
    }
}

fn member_binding(
    stake: Option<&StakeSM>,
    operator_table: &PublicOperatorTable,
) -> Result<StakeBinding, StakeShortfall> {
    let stake = stake.ok_or(StakeShortfall::Missing)?;
    if !stake
        .context()
        .operator_table()
        .has_same_membership(operator_table)
    {
        return Err(StakeShortfall::MembershipMismatch);
    }

    match stake.state() {
        StakeState::Confirmed {
            stake_data,
            summary,
            ..
        } => Ok(StakeBinding {
            outpoint: OutPoint::new(summary.stake, StakeTx::STAKE_VOUT),
            unstaking_image: stake_data.unstaking_image,
        }),
        StakeState::Created { .. }
        | StakeState::StakeGraphGenerated { .. }
        | StakeState::UnstakingNoncesCollected { .. }
        | StakeState::UnstakingSigned { .. } => Err(StakeShortfall::Unconfirmed),
        StakeState::PreimageRevealed { .. }
        | StakeState::Unstaked { .. }
        | StakeState::Slashed { .. } => Err(StakeShortfall::Exited),
    }
}

fn describe_shortfalls(shortfalls: &BTreeMap<OperatorIdx, StakeShortfall>) -> String {
    shortfalls
        .iter()
        .map(|(operator, shortfall)| format!("operator {operator} {shortfall}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use strata_bridge_primitives::operator_table::OperatorTable;
    use strata_bridge_sm::stake::context::StakeSMCtx;
    use strata_bridge_test_utils::prelude::generate_txid;

    use super::*;
    use crate::testing::{
        INITIAL_BLOCK_HEIGHT, N_TEST_OPERATORS, TEST_POV_IDX, make_confirmed_stake_sm,
        test_operator_table,
    };

    fn block_covenant(table: &OperatorTable, activation_height: u64) -> BlockCovenant {
        BlockCovenant {
            covenant: CovenantId::from_operator_table(table, activation_height)
                .expect("test keys aggregate"),
            operator_table: table.clone().into_public(),
        }
    }

    fn insert(stakes: &mut BTreeMap<StakeKey, StakeSM>, sm: StakeSM) {
        stakes.insert(sm.context().stake_key(), sm);
    }

    fn confirmed(operator: OperatorIdx, table: &OperatorTable) -> StakeSM {
        make_confirmed_stake_sm(operator, table.clone(), generate_txid())
    }

    fn with_state(mut sm: StakeSM, state: StakeState) -> StakeSM {
        sm.state = state;
        sm
    }

    fn all_confirmed(table: &OperatorTable) -> BTreeMap<StakeKey, StakeSM> {
        let mut stakes = BTreeMap::new();
        for operator in table.operator_idxs() {
            insert(&mut stakes, confirmed(operator, table));
        }
        stakes
    }

    fn shortfalls(
        result: Result<CovenantStakes, ReadinessError>,
    ) -> BTreeMap<OperatorIdx, StakeShortfall> {
        match result {
            Err(ReadinessError::Unready { shortfalls, .. }) => shortfalls,
            other => panic!("expected an unready covenant, got {other:?}"),
        }
    }

    #[test]
    fn ready_when_every_member_has_a_confirmed_stake() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let block_covenant = block_covenant(&table, INITIAL_BLOCK_HEIGHT);
        let stakes = all_confirmed(&table);

        let ready = assess(&block_covenant, &stakes).expect("every member has a confirmed stake");

        assert_eq!(
            ready.covenant, block_covenant.covenant,
            "readiness must report the assessed covenant"
        );
        assert_eq!(
            ready.stakes.keys().copied().collect::<Vec<_>>(),
            table.operator_idxs().into_iter().collect::<Vec<_>>(),
            "every member must have a binding"
        );
        for (key, sm) in &stakes {
            let StakeState::Confirmed {
                stake_data,
                summary,
                ..
            } = sm.state()
            else {
                unreachable!("fixture stakes are confirmed");
            };
            assert_eq!(
                ready.stakes[&key.operator],
                StakeBinding {
                    outpoint: OutPoint::new(summary.stake, StakeTx::STAKE_VOUT),
                    unstaking_image: stake_data.unstaking_image,
                },
                "binding must come from the member's own confirmed stake"
            );
        }
    }

    #[test]
    fn reports_every_member_without_a_usable_stake() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let block_covenant = block_covenant(&table, INITIAL_BLOCK_HEIGHT);
        let [missing, unconfirmed, exited]: [OperatorIdx; 3] = table
            .operator_idxs()
            .into_iter()
            .collect::<Vec<_>>()
            .try_into()
            .expect("fixture has three operators");

        let mut stakes = BTreeMap::new();
        insert(
            &mut stakes,
            with_state(
                confirmed(unconfirmed, &table),
                StakeState::new(INITIAL_BLOCK_HEIGHT),
            ),
        );
        insert(
            &mut stakes,
            with_state(
                confirmed(exited, &table),
                StakeState::Unstaked {
                    preimage: [7; 32],
                    unstaking_txid: generate_txid(),
                },
            ),
        );

        let result = assess(&block_covenant, &stakes);
        let message = result
            .as_ref()
            .expect_err("covenant is not ready")
            .to_string();

        assert_eq!(
            shortfalls(result),
            BTreeMap::from([
                (missing, StakeShortfall::Missing),
                (unconfirmed, StakeShortfall::Unconfirmed),
                (exited, StakeShortfall::Exited),
            ]),
            "every unready member must be reported, not only the first"
        );
        for operator in [missing, unconfirmed, exited] {
            assert!(
                message.contains(&format!("operator {operator}")),
                "error message must name operator {operator}: {message}"
            );
        }
    }

    #[test]
    fn exited_stakes_are_not_ready() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let block_covenant = block_covenant(&table, INITIAL_BLOCK_HEIGHT);
        let operator = TEST_POV_IDX;
        let template = confirmed(operator, &table);
        let StakeState::Confirmed {
            stake_data,
            summary,
            signatures,
            ..
        } = template.state().clone()
        else {
            unreachable!("fixture stake is confirmed");
        };

        let exited_states = [
            StakeState::PreimageRevealed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                stake_data,
                summary,
                preimage: [1; 32],
                unstaking_intent_block_height: INITIAL_BLOCK_HEIGHT,
                signatures,
            },
            StakeState::Unstaked {
                preimage: [1; 32],
                unstaking_txid: summary.unstaking,
            },
            StakeState::Slashed {
                summary,
                slash_txid: generate_txid(),
                preimage: None,
            },
        ];

        for state in exited_states {
            let mut stakes = all_confirmed(&table);
            insert(&mut stakes, with_state(template.clone(), state.clone()));

            assert_eq!(
                shortfalls(assess(&block_covenant, &stakes)),
                BTreeMap::from([(operator, StakeShortfall::Exited)]),
                "a stake in {state:?} must not back new deposits"
            );
        }
    }

    #[test]
    fn stakes_of_an_earlier_activation_do_not_count() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let stakes = all_confirmed(&table);
        let successor = block_covenant(&table, INITIAL_BLOCK_HEIGHT + 100);

        assert_eq!(
            shortfalls(assess(&successor, &stakes)),
            table
                .operator_idxs()
                .into_iter()
                .map(|operator| (operator, StakeShortfall::Missing))
                .collect(),
            "the same signing set at a later activation needs fresh stakes from every member"
        );
    }

    #[test]
    fn successor_stakes_make_the_successor_ready() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let successor_height = INITIAL_BLOCK_HEIGHT + 100;
        let successor = block_covenant(&table, successor_height);
        let mut stakes = all_confirmed(&table);
        for operator in table.operator_idxs() {
            let mut sm = confirmed(operator, &table);
            sm.context = StakeSMCtx::new(operator, table.clone(), successor_height);
            insert(&mut stakes, sm);
        }

        let ready = assess(&successor, &stakes).expect("successor stakes are confirmed");

        for (operator, binding) in &ready.stakes {
            let successor_key = StakeKey {
                covenant: successor.covenant,
                operator: *operator,
            };
            assert_eq!(
                Some(binding.outpoint.txid),
                stakes[&successor_key].state().stake_txid(),
                "operator {operator} must be bound to its successor stake"
            );
        }
    }

    #[test]
    fn stake_for_a_different_membership_is_a_mismatch() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let entries = table
            .operator_idxs()
            .into_iter()
            .map(|idx| {
                (
                    idx,
                    table
                        .idx_to_p2p_key(&((idx + 1) % N_TEST_OPERATORS as u32))
                        .expect("fixture member")
                        .clone(),
                    table.idx_to_btc_key(&idx).expect("fixture member"),
                )
            })
            .collect();
        let rotated_p2p =
            OperatorTable::new(entries, |(idx, _, _)| *idx == TEST_POV_IDX).expect("valid table");
        let block_covenant = block_covenant(&table, INITIAL_BLOCK_HEIGHT);
        assert_eq!(
            block_covenant.covenant,
            CovenantId::from_operator_table(&rotated_p2p, INITIAL_BLOCK_HEIGHT).unwrap(),
            "rotating P2P keys keeps the signing aggregate"
        );
        let mut stakes = all_confirmed(&table);
        insert(&mut stakes, confirmed(TEST_POV_IDX, &rotated_p2p));

        assert_eq!(
            shortfalls(assess(&block_covenant, &stakes)),
            BTreeMap::from([(TEST_POV_IDX, StakeShortfall::MembershipMismatch)]),
            "a stake set up for different membership must not satisfy the covenant"
        );
    }

    #[test]
    fn rejects_a_covenant_not_derived_from_its_table() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let other = test_operator_table(N_TEST_OPERATORS + 1, TEST_POV_IDX);
        let mismatched = BlockCovenant {
            covenant: CovenantId::from_operator_table(&other, INITIAL_BLOCK_HEIGHT).unwrap(),
            operator_table: table.clone().into_public(),
        };

        assert_eq!(
            assess(&mismatched, &all_confirmed(&table)),
            Err(ReadinessError::CovenantMismatch(mismatched.covenant)),
            "a covenant must be derived from the table it is assessed against"
        );
    }

    #[test]
    fn each_binding_carries_its_own_stakes_image() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let block_covenant = block_covenant(&table, INITIAL_BLOCK_HEIGHT);
        let mut stakes = all_confirmed(&table);
        let key = StakeKey {
            covenant: block_covenant.covenant,
            operator: TEST_POV_IDX,
        };
        let sm = stakes.get_mut(&key).expect("fixture stake");
        if let StakeState::Confirmed { stake_data, .. } = &mut sm.state {
            stake_data.unstaking_image = sha256::Hash::hash(&[9; 32]);
        }

        let ready = assess(&block_covenant, &stakes).expect("every member has a confirmed stake");

        assert_eq!(
            ready.stakes[&TEST_POV_IDX].unstaking_image,
            sha256::Hash::hash(&[9; 32]),
            "each binding must carry its own stake's image"
        );
    }
}
