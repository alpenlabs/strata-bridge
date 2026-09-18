//! Ordered membership operations and atomic block finalization.

use strata_bridge_primitives::{
    covenant::CovenantId, operator_set_schedule::OperatorSetSchedule, types::BitcoinBlockHeight,
};

use super::{
    ConfirmedExit, MembershipCause, MembershipSnapshot, MembershipUpdate, OperatorSetError,
    OperatorSetSM, schedule::SortedUpdates,
};

impl OperatorSetSM {
    /// Applies validated exits in Bitcoin order, then due admin updates in activation order.
    ///
    /// Equal-height admin operations retain their supplied order. Each exit must already be
    /// validated against membership at its transaction position. Finalizes at most one successor
    /// covenant, preserving the admin activation height across automatic exits.
    ///
    /// Returns whether any operation changed membership, even if later operations restore the
    /// original signing set. Successful processing advances the block height even when this
    /// returns `false`. Any error leaves the entire state unchanged.
    ///
    /// # Errors
    ///
    /// Rejects nonconsecutive blocks, exits out of transaction order, unknown exit indices,
    /// any intermediate empty membership, or membership that cannot form a covenant.
    /// A later addition cannot rescue an earlier operation that empties membership.
    pub fn apply_block(
        &mut self,
        block_height: BitcoinBlockHeight,
        exits: &[ConfirmedExit],
    ) -> Result<bool, OperatorSetError> {
        if self.last_block_height.checked_add(1) != Some(block_height) {
            return Err(OperatorSetError::NonconsecutiveBlock {
                processed: self.last_block_height,
                received: block_height,
            });
        }

        if exits
            .windows(2)
            .any(|pair| pair[0].tx_index > pair[1].tx_index)
        {
            return Err(OperatorSetError::UnorderedExits);
        }

        if exits.is_empty() && self.pending_updates.due(block_height).is_empty() {
            self.last_block_height = block_height;
            return Ok(false);
        }

        let mut next = self.clone();
        let mut changed = false;
        for exit in exits {
            changed |= next.apply_exit(block_height, exit)?;
        }

        let mut admin_height = self.current_covenant.activation_height;
        for update in next.pending_updates.take_due(block_height) {
            let height = update.activation_height;
            if next.apply_update(update)? {
                changed = true;
                admin_height = height;
            }
        }

        if changed {
            next.current_covenant =
                CovenantId::from_operator_table(&next.current_operator_table()?, admin_height)
                    .map_err(|_| OperatorSetError::InvalidMembership)?;
        }

        next.last_block_height = block_height;

        *self = next;

        Ok(changed)
    }

    /// Replaces registrations and pending operations with an authorized proposed schedule.
    ///
    /// The supplied table must retain every stored registration's identity and original
    /// activation height. Future deactivation edits are allowed; past intervals cannot change.
    /// Additional registrations must activate after the processed height. Pending operations
    /// are sorted by activation height, preserving supplied order at equal heights.
    ///
    /// Returns whether the registrations or normalized pending operations changed. Current
    /// membership, covenant, recorded exits, history, and processing height remain unchanged.
    /// Any error leaves the entire state unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`OperatorSetError::InvalidSchedule`] for nonfuture pending operations,
    /// [`OperatorSetError::UnknownOperator`] for unregistered indices in those operations, or
    /// [`OperatorSetError::RegistrationMismatch`] for missing or rewritten registrations,
    /// changed past deactivations, or additional registrations activating at or before the
    /// processed height.
    pub fn update_operator_table(
        &mut self,
        registrations: OperatorSetSchedule,
        pending_updates: Vec<MembershipUpdate>,
    ) -> Result<bool, OperatorSetError> {
        Self::validate_pending_updates(self.last_block_height, &registrations, &pending_updates)?;
        let pending_updates = SortedUpdates::from(pending_updates);
        if self.registrations == registrations && self.pending_updates == pending_updates {
            return Ok(false);
        }

        for old in &self.registrations {
            let supplied = registrations
                .get(old.index())
                .ok_or(OperatorSetError::RegistrationMismatch(old.index()))?;

            let identity_changed = old.covenant_key() != supplied.covenant_key()
                || old.p2p_key() != supplied.p2p_key()
                || old.payout_descriptor() != supplied.payout_descriptor()
                || old.activation_height() != supplied.activation_height();

            let past_deactivation_changed = old.deactivation_height()
                != supplied.deactivation_height()
                && [old.deactivation_height(), supplied.deactivation_height()]
                    .into_iter()
                    .flatten()
                    .any(|height| height <= self.last_block_height);

            if identity_changed || past_deactivation_changed {
                return Err(OperatorSetError::RegistrationMismatch(old.index()));
            }
        }

        for supplied in &registrations {
            if self.registrations.get(supplied.index()).is_none()
                && supplied.activation_height() <= self.last_block_height
            {
                return Err(OperatorSetError::RegistrationMismatch(supplied.index()));
            }
        }

        self.registrations = registrations;
        self.pending_updates = pending_updates;

        Ok(true)
    }

    /// Records one validated exit and bars its registration from reactivation.
    ///
    /// Returns whether the index was removed from current membership. An already-exited index
    /// is a no-op; otherwise records an exit snapshot at `height`, even if the index was absent.
    /// Does not finalize the covenant or advance the processing height.
    ///
    /// # Errors
    ///
    /// Returns [`OperatorSetError::UnknownOperator`] for an unregistered index or
    /// [`OperatorSetError::EmptyMembership`] if removal leaves no members. State is unchanged
    /// on error.
    fn apply_exit(
        &mut self,
        height: BitcoinBlockHeight,
        exit: &ConfirmedExit,
    ) -> Result<bool, OperatorSetError> {
        if self.registrations.get(exit.operator_idx).is_none() {
            return Err(OperatorSetError::UnknownOperator(exit.operator_idx));
        }

        if self.exited_operators.contains(&exit.operator_idx) {
            return Ok(false);
        }

        let mut members = self.current_members().clone();
        let changed = members.remove(&exit.operator_idx);
        if members.is_empty() {
            return Err(OperatorSetError::EmptyMembership);
        }

        self.exited_operators.insert(exit.operator_idx);
        self.membership_history.push(MembershipSnapshot {
            block_height: height,
            cause: MembershipCause::Exit(exit.clone()),
            members,
        });

        Ok(changed)
    }

    /// Applies one authorized admin operation, adding members before removing members.
    ///
    /// Skips additions of exited registrations and bars removed indices from reactivation.
    /// Returns whether any addition or removal changed membership, recording the operation
    /// and resulting view even for a no-op. Does not finalize the covenant or advance the
    /// processing height. The operation's height and registration indices must be validated
    /// before it is installed in the pending schedule.
    ///
    /// # Errors
    ///
    /// Returns [`OperatorSetError::EmptyMembership`] if any removal leaves no members.
    /// State is unchanged on error.
    pub(super) fn apply_update(
        &mut self,
        update: MembershipUpdate,
    ) -> Result<bool, OperatorSetError> {
        let mut members = self.current_members().clone();
        let mut effective = false;
        for idx in update.additions.difference(&self.exited_operators) {
            effective |= members.insert(*idx);
        }

        for idx in &update.removals {
            effective |= members.remove(idx);
            if members.is_empty() {
                return Err(OperatorSetError::EmptyMembership);
            }
        }

        self.exited_operators.extend(&update.removals);
        self.membership_history.push(MembershipSnapshot {
            block_height: update.activation_height,
            cause: MembershipCause::Admin { update, effective },
            members,
        });

        Ok(effective)
    }
}
