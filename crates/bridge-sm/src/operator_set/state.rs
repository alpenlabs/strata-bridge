//! Membership state, history, and schedule validation.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{
    covenant::CovenantId,
    operator_set_schedule::OperatorSetSchedule,
    operator_table::PublicOperatorTable,
    types::{BitcoinBlockHeight, OperatorIdx},
};
use thiserror::Error;

use super::schedule::{MembershipUpdate, SortedUpdates};

/// The operation responsible for a recorded membership view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipCause {
    /// Membership trusted from registration intervals on first initialization.
    Initialization,
}

/// Indexed membership after one operation, retained in execution order.
///
/// Keys and descriptors are resolved through the historical registration schedule instead
/// of copying complete operator tables into every history entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipSnapshot {
    /// The Bitcoin height at which this view was established.
    pub block_height: BitcoinBlockHeight,
    /// The last operation that produced the view.
    pub cause: MembershipCause,
    /// The permanent indices present after that operation.
    pub members: BTreeSet<OperatorIdx>,
}

/// Public operator membership, covenant identity, and ordered transition history.
///
/// Historical registrations and exits survive serialization. Membership is independent of
/// local signing identity and stake availability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSetSM {
    /// Complete historical and future registrations, preserving permanent identities and
    /// resolving keys for current and historical membership without copying registration data.
    pub(super) registrations: OperatorSetSchedule,
    /// Remaining authorized admin operations, ordered by activation height with stable ties.
    /// Supplies due block transitions and projections used to prepare future covenants.
    pub(super) pending_updates: SortedUpdates,
    /// Permanently removed registration indices. Makes duplicate exits harmless and prevents
    /// later scheduled additions from reactivating an exited registration.
    pub(super) exited_operators: BTreeSet<OperatorIdx>,
    /// Finalized signing authority and its last effective admin activation height, used to
    /// identify covenant-scoped stakes. Automatic exits preserve the admin activation height.
    pub(super) current_covenant: CovenantId,
    /// Indexed membership and transition provenance in execution order, starting at
    /// initialization. The latest snapshot supplies current membership; earlier snapshots
    /// retain intermediate views.
    pub(super) membership_history: Vec<MembershipSnapshot>,
    /// Processed Bitcoin height, enforcing consecutive blocks and requiring pending updates
    /// and covenant preparation to target future heights.
    pub(super) last_block_height: BitcoinBlockHeight,
}

/// Invalid membership input or an unsupported membership transition.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OperatorSetError {
    /// Every actual membership step must retain at least one member.
    #[error("operator membership cannot be empty")]
    EmptyMembership,
    /// A schedule or event referenced an unregistered index.
    #[error("unknown operator index {0}")]
    UnknownOperator(OperatorIdx),
    /// Updates must activate after the processed height.
    #[error("admin updates must be later than processed height {0}")]
    InvalidSchedule(BitcoinBlockHeight),
    /// Public membership could not be constructed from the supplied registrations.
    #[error("invalid public operator membership")]
    InvalidMembership,
}

impl OperatorSetSM {
    /// Initializes from trusted registration intervals at the current processing height.
    ///
    /// `pending_updates` is sorted by activation height, preserving supplied order at equal
    /// heights. Every update must be later than `block_height` and reference known registrations.
    pub fn new(
        block_height: BitcoinBlockHeight,
        registrations: OperatorSetSchedule,
        pending_updates: Vec<MembershipUpdate>,
    ) -> Result<Self, OperatorSetError> {
        Self::validate_pending_updates(block_height, &registrations, &pending_updates)?;
        let pending_updates = SortedUpdates::from(pending_updates);
        let members = registrations
            .active_at(block_height)
            .map(|op| op.index())
            .collect();
        let active_table = Self::table_for(&registrations, &members)?;
        let boundary = registrations
            .iter()
            .flat_map(|op| {
                [Some(op.activation_height()), op.deactivation_height()]
                    .into_iter()
                    .flatten()
            })
            .filter(|height| *height <= block_height)
            .max()
            .ok_or(OperatorSetError::EmptyMembership)?;
        let current_covenant = CovenantId::from_operator_table(&active_table, boundary)
            .map_err(|_| OperatorSetError::InvalidMembership)?;
        let exited_operators = registrations
            .iter()
            .filter(|op| {
                op.deactivation_height()
                    .is_some_and(|height| height <= block_height)
            })
            .map(|op| op.index())
            .collect();
        Ok(Self {
            registrations,
            pending_updates,
            exited_operators,
            current_covenant,
            membership_history: vec![MembershipSnapshot {
                block_height,
                cause: MembershipCause::Initialization,
                members,
            }],
            last_block_height: block_height,
        })
    }

    /// All immutable registrations, including past and future members.
    pub const fn registrations(&self) -> &OperatorSetSchedule {
        &self.registrations
    }

    /// Remaining authorized updates in nondecreasing activation-height order.
    pub fn pending_updates(&self) -> &[MembershipUpdate] {
        self.pending_updates.as_slice()
    }

    /// Registrations barred from reactivation, including configured past removals.
    pub const fn exited_operators(&self) -> &BTreeSet<OperatorIdx> {
        &self.exited_operators
    }

    /// The finalized covenant, whose height is the most recent effective admin boundary.
    pub const fn current_covenant(&self) -> CovenantId {
        self.current_covenant
    }

    /// Membership snapshots in execution order, beginning with initialization.
    pub fn membership_history(&self) -> &[MembershipSnapshot] {
        &self.membership_history
    }

    /// The last fully processed block height.
    pub const fn last_block_height(&self) -> BitcoinBlockHeight {
        self.last_block_height
    }

    /// Builds the finalized public table without selecting a local participant.
    pub fn current_operator_table(&self) -> Result<PublicOperatorTable, OperatorSetError> {
        Self::table_for(&self.registrations, self.current_members())
    }

    /// Resolves an indexed historical view using the retained registration keys.
    pub fn historical_operator_table(
        &self,
        snapshot: &MembershipSnapshot,
    ) -> Result<PublicOperatorTable, OperatorSetError> {
        Self::table_for(&self.registrations, &snapshot.members)
    }

    /// Checks that pending operations are future-dated and reference known registrations.
    pub(super) fn validate_pending_updates(
        block_height: BitcoinBlockHeight,
        registrations: &OperatorSetSchedule,
        updates: &[MembershipUpdate],
    ) -> Result<(), OperatorSetError> {
        for update in updates {
            if update.activation_height <= block_height {
                return Err(OperatorSetError::InvalidSchedule(block_height));
            }
            for idx in update.additions.iter().chain(&update.removals) {
                if registrations.get(*idx).is_none() {
                    return Err(OperatorSetError::UnknownOperator(*idx));
                }
            }
        }
        Ok(())
    }

    pub(super) fn current_members(&self) -> &BTreeSet<OperatorIdx> {
        &self
            .membership_history
            .last()
            .expect("initialized membership history")
            .members
    }

    fn table_for(
        registrations: &OperatorSetSchedule,
        members: &BTreeSet<OperatorIdx>,
    ) -> Result<PublicOperatorTable, OperatorSetError> {
        if members.is_empty() {
            return Err(OperatorSetError::EmptyMembership);
        }
        let entries = members
            .iter()
            .map(|idx| {
                let op = registrations
                    .get(*idx)
                    .ok_or(OperatorSetError::UnknownOperator(*idx))?;
                Ok((op.index(), op.p2p_key().clone(), op.covenant_public_key()))
            })
            .collect::<Result<Vec<_>, OperatorSetError>>()?;
        PublicOperatorTable::from_entries(entries).ok_or(OperatorSetError::InvalidMembership)
    }
}
