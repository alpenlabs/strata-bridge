//! Drops repeat nag requests whose reply this node has just sent, or is still sending.
//!
//! A nag reply is broadcast, so one reply serves every peer that nagged for the same data. Entries
//! are therefore keyed by the nag payload alone, not by the sender.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use strata_bridge_p2p_types::NagRequestPayload;
use tracing::debug;

/// Remembers recent nag replies so that repeats can be dropped.
///
/// Cloning shares the same state, so detached duty tasks can report their outcome.
#[derive(Debug, Clone)]
pub(crate) struct NagDedup {
    window: Duration,
    in_flight_timeout: Duration,
    replies: Arc<Mutex<Replies>>,
}

#[derive(Debug, Default)]
struct Replies {
    entries: HashMap<NagRequestPayload, Reply>,
    last_prune: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reply {
    /// Dispatched at this instant and not yet settled. Expires after the in-flight timeout, so a
    /// duty that never settles cannot block its payload for good.
    InFlight(Instant),
    /// Succeeded at this instant; expires after the window.
    Sent(Instant),
}

impl NagDedup {
    /// Creates a deduplicator; a zero `window` disables it.
    pub(crate) fn new(window: Duration, in_flight_timeout: Duration) -> Self {
        Self {
            window,
            in_flight_timeout,
            replies: Arc::default(),
        }
    }

    /// Returns whether a reply to `payload` is in flight or was sent within the window.
    pub(crate) fn should_drop(&self, payload: &NagRequestPayload, now: Instant) -> bool {
        if self.window.is_zero() {
            return false;
        }
        let mut replies = self.lock();
        self.prune(&mut replies, now);
        replies
            .entries
            .get(payload)
            .is_some_and(|reply| self.is_live(*reply, now))
    }

    /// Records that a reply to `payload` was dispatched at `now`.
    pub(crate) fn reply_dispatched(&self, payload: NagRequestPayload, now: Instant) {
        if self.window.is_zero() {
            return;
        }
        self.lock().entries.insert(payload, Reply::InFlight(now));
    }

    /// Records how the reply to `payload` dispatched at `dispatched_at` ended. A failure only
    /// clears that dispatch's own entry, so the next nag is served, while a sent reply or a newer
    /// dispatch keeps suppressing repeats.
    pub(crate) fn reply_settled(
        &self,
        payload: NagRequestPayload,
        dispatched_at: Instant,
        succeeded: bool,
        now: Instant,
    ) {
        if self.window.is_zero() {
            return;
        }
        let mut replies = self.lock();
        if succeeded {
            replies.entries.insert(payload, Reply::Sent(now));
            return;
        }
        match replies.entries.get(&payload).copied() {
            Some(Reply::InFlight(at)) if at == dispatched_at => {
                replies.entries.remove(&payload);
            }
            Some(Reply::InFlight(_)) => debug!(
                ?payload,
                "nag reply failed after its in-flight entry expired; keeping the newer dispatch"
            ),
            _ => {}
        }
    }

    fn is_live(&self, reply: Reply, now: Instant) -> bool {
        let (at, ttl) = match reply {
            Reply::InFlight(at) => (at, self.in_flight_timeout),
            Reply::Sent(at) => (at, self.window),
        };
        now.saturating_duration_since(at) < ttl
    }

    /// Drops expired entries, at most once per window.
    fn prune(&self, replies: &mut Replies, now: Instant) {
        if replies
            .last_prune
            .is_some_and(|at| now.saturating_duration_since(at) < self.window)
        {
            return;
        }
        replies.entries.retain(|_, reply| self.is_live(*reply, now));
        replies.last_prune = Some(now);
    }

    fn lock(&self) -> MutexGuard<'_, Replies> {
        // Nothing panics while holding the lock, and the map stays consistent if something did.
        self.replies.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(30);
    const IN_FLIGHT_TIMEOUT: Duration = Duration::from_secs(120);

    fn payload(deposit_idx: u32) -> NagRequestPayload {
        NagRequestPayload::DepositNonce { deposit_idx }
    }

    fn dedup() -> NagDedup {
        NagDedup::new(WINDOW, IN_FLIGHT_TIMEOUT)
    }

    #[test]
    fn sent_reply_suppresses_repeats_until_the_window_passes() {
        let dedup = dedup();
        let t0 = Instant::now();

        assert!(!dedup.should_drop(&payload(0), t0));
        dedup.reply_dispatched(payload(0), t0);
        dedup.reply_settled(payload(0), t0, true, t0);

        assert!(dedup.should_drop(&payload(0), t0 + WINDOW - Duration::from_secs(1)));
        assert!(
            !dedup.should_drop(&payload(1), t0),
            "other payloads are unaffected"
        );
        assert!(!dedup.should_drop(&payload(0), t0 + WINDOW));
    }

    #[test]
    fn in_flight_reply_suppresses_repeats_past_the_window() {
        let dedup = dedup();
        let t0 = Instant::now();

        dedup.reply_dispatched(payload(0), t0);

        assert!(dedup.should_drop(&payload(0), t0 + WINDOW));
        assert!(!dedup.should_drop(&payload(0), t0 + IN_FLIGHT_TIMEOUT));
    }

    #[test]
    fn failed_reply_lets_the_next_nag_through() {
        let dedup = dedup();
        let t0 = Instant::now();

        dedup.reply_dispatched(payload(0), t0);
        dedup.reply_settled(payload(0), t0, false, t0 + Duration::from_secs(1));

        assert!(!dedup.should_drop(&payload(0), t0 + Duration::from_secs(2)));
    }

    #[test]
    fn failed_reply_does_not_clear_a_sent_one() {
        let dedup = dedup();
        let t0 = Instant::now();

        dedup.reply_settled(payload(0), t0, true, t0);
        dedup.reply_settled(payload(0), t0, false, t0 + Duration::from_secs(1));

        assert!(dedup.should_drop(&payload(0), t0 + Duration::from_secs(2)));
    }

    #[test]
    fn stale_failure_does_not_clear_a_newer_dispatch() {
        let dedup = dedup();
        let t0 = Instant::now();
        let t1 = t0 + IN_FLIGHT_TIMEOUT;

        dedup.reply_dispatched(payload(0), t0);
        dedup.reply_dispatched(payload(0), t1);
        dedup.reply_settled(payload(0), t0, false, t1 + Duration::from_secs(1));

        assert!(dedup.should_drop(&payload(0), t1 + Duration::from_secs(2)));
    }

    #[test]
    fn zero_window_disables_dedup() {
        let dedup = NagDedup::new(Duration::ZERO, IN_FLIGHT_TIMEOUT);
        let t0 = Instant::now();

        dedup.reply_dispatched(payload(0), t0);
        dedup.reply_settled(payload(0), t0, true, t0);

        assert!(!dedup.should_drop(&payload(0), t0));
        assert!(dedup.lock().entries.is_empty());
    }

    #[test]
    fn expired_entries_are_pruned() {
        let dedup = dedup();
        let t0 = Instant::now();

        dedup.reply_settled(payload(0), t0, true, t0);
        dedup.reply_dispatched(payload(1), t0);
        dedup.should_drop(&payload(2), t0 + IN_FLIGHT_TIMEOUT);

        assert!(dedup.lock().entries.is_empty());
    }
}
