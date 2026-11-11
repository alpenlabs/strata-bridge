//! What one CPFP attempt keeps for the next one.

use std::sync::Arc;

use bitcoin::Txid;
use operator_wallet::PriorChild;

use super::{
    interfaces::{FundingLease, ParentProbe},
    submitpackage::SubmitPackageError,
};

/// A child that this operator built or adopted, and the lease on its wallet inputs.
#[derive(Debug, Clone)]
pub(super) struct HeldChild {
    /// Txid of the child.
    pub(super) txid: Txid,
    /// The wallet frees the inputs when the last clone of this value drops.
    pub(super) lease: Arc<dyn FundingLease>,
}

/// Per-parent state the driver carries between bump attempts.
///
/// The handle holds leases and identities only. The fee that a replacement must beat comes from
/// the mempool on every attempt.
///
/// Every path that stops the bumps for a parent frees the inputs by dropping the handle, and no
/// path needs an explicit release call. The driver clones the handle to run a bump without the
/// entries lock held. The clone keeps the leases alive for the length of the bump.
#[derive(Debug, Default, Clone)]
pub struct CpfpHandle {
    /// The child that the mempool holds, by a success result or by a probe. Its lease stays until
    /// a mempool accepts its replacement or a probe shows that the child is gone.
    pub(super) accepted: Option<HeldChild>,
    /// The most recent child with no known place in a mempool: one with an unknown submission
    /// result, or one that left this mempool. It can be in another mempool, so its inputs stay
    /// held, and the next build can spend them again. One slot: a newer such child takes it over,
    /// and the older lease drops. A rejection of a later child, a demotion of the accepted child
    /// and a promotion of the candidate also free the inputs, so a child in another mempool can
    /// lose them to another duty. The design accepts that: such a child is in no mempool this node
    /// sees, and the inputs cannot stay held on a guess.
    pub(super) candidate: Option<HeldChild>,
}

impl CpfpHandle {
    /// Txid of the child that the mempool holds, as far as this handle knows.
    pub fn accepted_txid(&self) -> Option<Txid> {
        self.accepted.as_ref().map(|child| child.txid)
    }

    /// The children whose inputs the next child may spend again. Those of [`Self::accepted`]
    /// conflict with it, which a replacement must do. Those of [`Self::candidate`] are spent by no
    /// child in this mempool.
    pub(super) fn prior_children(&self) -> Vec<PriorChild<'_>> {
        [&self.accepted, &self.candidate]
            .into_iter()
            .flatten()
            .map(|child| PriorChild {
                txid: child.txid,
                lease: child.lease.lease(),
                inputs: child.lease.inputs(),
            })
            .collect()
    }

    /// Moves [`Self::accepted`] to [`Self::candidate`]: the mempool does not hold that child.
    pub(super) fn demote_accepted(&mut self) {
        if let Some(gone) = self.accepted.take() {
            self.candidate = Some(gone);
        }
    }

    /// Applies a probe. Returns the live child when the handle does not know it.
    ///
    /// A `None` probe teaches nothing, so it changes nothing.
    pub(super) fn observe(&mut self, probe: Option<&ParentProbe>) -> Option<Txid> {
        let is = |held: &Option<HeldChild>, txid| held.as_ref().is_some_and(|c| c.txid == txid);
        match probe? {
            ParentProbe::Absent | ParentProbe::NoChild => {
                self.demote_accepted();
                None
            }
            ParentProbe::Child(child) if is(&self.accepted, child.txid) => None,
            ParentProbe::Child(child) if is(&self.candidate, child.txid) => {
                self.accepted = self.candidate.take();
                None
            }
            ParentProbe::Child(child) => Some(child.txid),
        }
    }

    /// Records what became of `child` after its submission.
    ///
    /// - A success makes `child` the accepted child, and every older lease drops.
    /// - An unknown result keeps `child` as the candidate.
    /// - A rejection drops `child`: the node did not take it, so it did not relay it. The candidate
    ///   drops too, because the rejection can come from an input of the candidate, and that input
    ///   would repeat the rejection on every trigger. The next build reselects from what the wallet
    ///   lists. The accepted child stays.
    pub(super) fn record_submission(
        &mut self,
        child: HeldChild,
        result: Result<(), &SubmitPackageError>,
    ) {
        match result {
            Ok(()) => {
                self.accepted = Some(child);
                self.candidate = None;
            }
            Err(SubmitPackageError::Rpc(_)) => self.candidate = Some(child),
            Err(SubmitPackageError::Rejected { .. }) => self.candidate = None,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{FeeRate, OutPoint, hashes::Hash};
    use bitcoind_async_client::error::ClientError;

    use super::*;
    use crate::cpfp::test_utils::{FakeWallet, child_at, seeded_handle};

    fn held(wallet: &FakeWallet, seed: u8) -> HeldChild {
        HeldChild {
            txid: Txid::from_byte_array([seed; 32]),
            lease: wallet.lease(vec![OutPoint::new(Txid::from_byte_array([seed; 32]), 0)]),
        }
    }

    /// Every submission result over a handle with both slots set. `A` is accepted, `B` is the
    /// candidate, and `C` is the new child.
    #[test]
    fn a_submission_result_moves_the_leases_of_the_handle() {
        let rejection = SubmitPackageError::Rejected {
            message: "package-not-valid".to_string(),
            tx_errors: Vec::new(),
        };
        let contention = SubmitPackageError::Rejected {
            message: "transaction failed".to_string(),
            tx_errors: vec![(Txid::all_zeros(), "rejecting replacement".to_string())],
        };
        let unknown = SubmitPackageError::Rpc(ClientError::Timeout);
        let (a, b, c) = (0xA, 0xB, 0xC);

        for (result, accepted, candidate) in [
            (Ok(()), c, None),
            (Err(&unknown), a, Some(c)),
            (Err(&rejection), a, None),
            (Err(&contention), a, None),
        ] {
            let wallet = FakeWallet::failing("no build");
            let mut handle = CpfpHandle {
                accepted: Some(held(&wallet, a)),
                candidate: Some(held(&wallet, b)),
            };
            handle.record_submission(held(&wallet, c), result);

            assert_eq!(
                handle.accepted_txid(),
                Some(Txid::from_byte_array([accepted; 32]))
            );
            assert_eq!(
                handle.candidate.as_ref().map(|child| child.txid),
                candidate.map(|seed| Txid::from_byte_array([seed; 32]))
            );
        }
    }

    /// A probe that reads the candidate makes it the accepted child, and the lease of the older
    /// accepted child drops.
    #[test]
    fn a_probe_that_reads_the_candidate_promotes_it() {
        let wallet = FakeWallet::failing("no build");
        let (a, b) = (held(&wallet, 0xA), held(&wallet, 0xB));
        let (first, second) = (a.txid, b.txid);
        let mut handle = CpfpHandle {
            accepted: Some(a),
            candidate: Some(b),
        };

        assert_eq!(handle.observe(Some(&child_at(second, FeeRate::ZERO))), None);

        assert_eq!(handle.accepted_txid(), Some(second));
        assert!(handle.candidate.is_none());
        assert_eq!(
            *wallet.released.lock().unwrap(),
            vec![OutPoint::new(first, 0)]
        );
    }

    /// A probe that finds nothing moves the live child to the candidate slot.
    #[test]
    fn a_probe_that_finds_no_child_demotes_the_accepted_child() {
        let wallet = FakeWallet::failing("no build");
        for probe in [ParentProbe::Absent, ParentProbe::NoChild] {
            let ours = Txid::from_byte_array([0xAA; 32]);
            let mut handle = seeded_handle(&wallet, &[], ours);
            assert_eq!(handle.observe(Some(&probe)), None);
            assert!(handle.accepted.is_none());
            assert_eq!(handle.candidate.as_ref().map(|c| c.txid), Some(ours));
        }
    }

    /// A failed probe teaches nothing, so the handle stays as it was.
    #[test]
    fn a_failed_probe_leaves_the_handle_as_it_is() {
        let wallet = FakeWallet::failing("no build");
        let ours = Txid::from_byte_array([0xAA; 32]);
        let mut handle = seeded_handle(&wallet, &[], ours);
        assert_eq!(handle.observe(None), None);
        assert_eq!(handle.accepted_txid(), Some(ours));
    }

    /// A spender that neither slot knows comes back for the ownership lookup.
    #[test]
    fn an_unknown_child_returns_for_the_ownership_lookup() {
        let wallet = FakeWallet::failing("no build");
        let theirs = Txid::from_byte_array([0xBB; 32]);
        let mut handle = seeded_handle(&wallet, &[], Txid::from_byte_array([0xAA; 32]));
        let probe = child_at(theirs, FeeRate::ZERO);
        assert_eq!(handle.observe(Some(&probe)), Some(theirs));
    }
}
