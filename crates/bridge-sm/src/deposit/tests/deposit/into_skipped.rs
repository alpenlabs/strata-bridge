//! Unit Tests for into_skipped
#[cfg(test)]
mod tests {
    use crate::deposit::{state::DepositState, tests::*};

    /// Skipping keeps the context, so the deposit index and outpoints stay aligned with the
    /// operators that admitted the request.
    #[test]
    fn test_into_skipped_keeps_context() {
        let sm = create_sm(DepositState::Created {
            deposit_transaction: test_deposit_txn(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
            claim_txids: BTreeMap::new(),
        });
        let context = sm.context().clone();

        let skipped = sm.into_skipped();

        assert_eq!(skipped.state(), &DepositState::Skipped);
        assert_eq!(skipped.context(), &context);
    }
}
