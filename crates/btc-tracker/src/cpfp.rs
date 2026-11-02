//! The seam between [`TxDriver`](crate::tx_driver::TxDriver) and the CPFP implementation.
//!
//! The driver owns the lifecycle of a parent: which parent gets a bump, when, and what happens
//! to the record afterwards. Everything that builds, signs, prices, and submits a child sits
//! behind [`CpfpBumper`], so this crate stays free of any dependency on the wallet.

use std::{any::Any, fmt, sync::Arc};

use async_trait::async_trait;
use bitcoin::{Amount, Transaction};
use strata_bridge_primitives::cpfp::ChildSpend;

/// Whether a protocol timelock races the confirmation of a parent.
///
/// The caller of the publish path states the class, because the caller knows which transaction
/// it publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineClass {
    /// A protocol timelock races this parent: contest, bridge proof timeout, counterproof,
    /// counterproof ack, counterproof NACK, slash, bridge proof, contested payout, and withdrawal
    /// fulfillment.
    Deadline,
    /// No protocol timelock races this parent.
    NoDeadline,
}

/// When the first bump of a parent runs.
///
/// Every later bump runs on a block, a tick, or an eviction, whatever this says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstBump {
    /// Right after the publish. A presigned parent pays a fee that was fixed before the market
    /// was known, so the first bump brings it to the target at once.
    AtPublish,
    /// On the first trigger. The caller priced the parent at the market rate at the publish, so a
    /// child at that moment would pay the premium of the ladder for nothing.
    AtTrigger,
}

/// How to bump one parent.
#[derive(Debug, Clone)]
pub struct CpfpStrategy {
    /// The output of the parent that the child spends.
    pub spend: ChildSpend,
    /// The exact fee that the parent already pays. The child pays the difference between this
    /// and what the package target asks for, so a wrong value makes it overpay or underpay.
    pub parent_fee: Amount,
    /// Whether a protocol timelock races this parent.
    pub deadline: DeadlineClass,
    /// When the first bump runs.
    pub first_bump: FirstBump,
}

/// What one [`CpfpBumper::bump`] attempt achieved.
///
/// A caller that must decide the fate of a transaction needs more than "no package went
/// out". A bump that read the parent in the mempool proves that it reached the network, unless
/// a conflict then replaced it, and any other skip proves no publication failure: the next trigger
/// retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BumpOutcome {
    /// A `[parent, child]` package reached the mempool.
    Submitted,
    /// No package went out, and the bump read the parent in the mempool.
    ParentIsLive,
    /// The bump did not see a package go out, and it did not read the parent in the mempool: the
    /// parent's own fee meets the target, or the attempt failed. A submission with an unknown
    /// result reads as this, so a package can be live. The next trigger retries.
    NoPackage,
    /// The parent cannot carry a child at all. Every later bump for it fails the same way, so
    /// the driver stops bumping it and lets the bare paths carry it.
    Unbumpable,
}

impl BumpOutcome {
    /// Whether the attempt proves that the parent is in a mempool or in a block.
    pub const fn reached_network(self) -> bool {
        matches!(self, Self::Submitted | Self::ParentIsLive)
    }
}

/// What a [`CpfpBumper`] remembers about one parent between attempts.
///
/// The driver keeps one value per parent, clones it for each attempt, writes the result back,
/// and drops it when the parent needs no more bumps. The driver never reads the value. Its
/// contents belong to the bumper, and dropping the last clone frees what they hold, such as
/// the funding lease of the last child. That drop is what releases the lease on every path
/// that stops the bumps for a parent.
#[derive(Clone, Default)]
pub struct BumpState(Option<Arc<dyn Any + Send + Sync>>);

impl BumpState {
    /// Wraps the bumper's value for the driver to carry.
    pub fn new<T: Any + Send + Sync>(value: T) -> Self {
        Self(Some(Arc::new(value)))
    }

    /// The value inside, when one of type `T` is there. A parent with no attempt yet holds
    /// none.
    pub fn get<T: Any>(&self) -> Option<&T> {
        self.0.as_deref().and_then(|value| value.downcast_ref())
    }
}

impl fmt::Debug for BumpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BumpState")
    }
}

/// Runs one CPFP bump attempt for a parent.
///
/// The driver spawns each attempt, so an implementation may take as long as its wallet and its
/// signers need. An attempt never fails from the point of view of the driver: the implementation
/// classifies every failure into a [`BumpOutcome`], and the next trigger retries.
#[async_trait]
pub trait CpfpBumper: Send + Sync {
    /// Attempts one bump of `parent` under `strategy`.
    ///
    /// `state` is what this bumper stored for the parent on the last attempt. The driver writes
    /// it back whatever the outcome, so a value set before a step that can fail survives that
    /// failure.
    async fn bump(
        &self,
        parent: &Transaction,
        strategy: &CpfpStrategy,
        state: &mut BumpState,
    ) -> BumpOutcome;
}
