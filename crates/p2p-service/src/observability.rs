//! Stable metric names and recorders for the p2p service, and a validator wrapper that records
//! rate-limiter activity.
//!
//! Labels are bounded: message kinds and protocol names only, never peer or object identifiers.

use std::time::Duration;

use metrics::{counter, describe_counter, describe_histogram, histogram};
use strata_p2p::{
    score_manager::PeerScore,
    validator::{Message, PenaltyType, Validator},
};
use tracing::warn;

const GOSSIP_PUBLISHED_TOTAL: &str = "strata_bridge_gossip_published_total";
const RATE_LIMIT_SCORE: &str = "strata_bridge_p2p_rate_limit_score";
const RATE_LIMIT_WATERMARKS_TOTAL: &str = "strata_bridge_p2p_rate_limit_watermarks_total";
const RATE_LIMIT_PENALTIES_TOTAL: &str = "strata_bridge_p2p_rate_limit_penalties_total";

/// Fractions of the mute threshold whose downward crossing is logged and counted.
const WATERMARKS: [(f64, &str); 3] = [(0.25, "25"), (0.5, "50"), (0.75, "75")];

pub(crate) fn describe_metrics() {
    describe_counter!(
        GOSSIP_PUBLISHED_TOTAL,
        "Broadcasts handed to the p2p swarm by message kind; `dropped` means the command queue was \
         full"
    );
    describe_histogram!(
        RATE_LIMIT_SCORE,
        "Rate-limit score of the delivering peer after charging each accepted message"
    );
    describe_counter!(
        RATE_LIMIT_WATERMARKS_TOTAL,
        "Times a peer's rate-limit score fell through a fraction of the mute threshold"
    );
    describe_counter!(
        RATE_LIMIT_PENALTIES_TOTAL,
        "Penalties (mutes) the rate limiter issued"
    );
}

pub(crate) fn record_gossip_published(kind: &'static str, queued: bool) {
    let result = if queued { "queued" } else { "dropped" };
    counter!(GOSSIP_PUBLISHED_TOTAL, "kind" => kind, "result" => result).increment(1);
}

fn record_rate_limit_score(protocol: &'static str, score: f64) {
    histogram!(RATE_LIMIT_SCORE, "protocol" => protocol).record(score);
}

fn record_rate_limit_watermark(protocol: &'static str, level: &'static str) {
    counter!(RATE_LIMIT_WATERMARKS_TOTAL, "protocol" => protocol, "level" => level).increment(1);
}

fn record_rate_limit_penalty(protocol: &'static str) {
    counter!(RATE_LIMIT_PENALTIES_TOTAL, "protocol" => protocol).increment(1);
}

/// Records rate-limiter activity without changing the wrapped validator's decisions.
///
/// strata-p2p passes no peer id to the validator. Watermark logs inherit the message author from
/// the enclosing `handle_gossip_msg` span, which differs from the charged peer when a forwarded
/// copy arrives first.
#[derive(Debug, Clone)]
pub(crate) struct InstrumentedValidator<V> {
    inner: V,
    mute_threshold: f64,
}

impl<V> InstrumentedValidator<V> {
    /// Wraps `inner`, whose mute threshold is `mute_threshold`.
    pub(crate) const fn new(inner: V, mute_threshold: f64) -> Self {
        Self {
            inner,
            mute_threshold,
        }
    }
}

const fn protocol(msg: &Message) -> &'static str {
    match msg {
        Message::Gossipsub(_) => "gossipsub",
        Message::Request(_) | Message::Response(_) => "req_resp",
    }
}

impl<V: Validator> Validator for InstrumentedValidator<V> {
    fn validate_msg(&self, msg: &Message, old_app_score: f64) -> f64 {
        let score = self.inner.validate_msg(msg, old_app_score);
        let protocol = protocol(msg);
        record_rate_limit_score(protocol, score);

        for (fraction, level) in WATERMARKS {
            let watermark = self.mute_threshold * fraction;
            if old_app_score > watermark && score <= watermark {
                record_rate_limit_watermark(protocol, level);
                warn!(
                    protocol,
                    level_pct = level,
                    score,
                    mute_threshold = self.mute_threshold,
                    "peer rate-limit score crossed watermark"
                );
            }
        }

        score
    }

    fn get_penalty(&self, msg: &Message, peer_score: &PeerScore) -> Option<PenaltyType> {
        let penalty = self.inner.get_penalty(msg, peer_score);
        if penalty.is_some() {
            record_rate_limit_penalty(protocol(msg));
        }
        penalty
    }

    fn apply_decay(&self, score: &f64, time_since_last_decay: &Duration) -> f64 {
        self.inner.apply_decay(score, time_since_last_decay)
    }
}

#[cfg(test)]
mod tests {
    use strata_p2p::{
        score_manager::AppPeerScore,
        validator::{DefaultP2PValidator, DEFAULT_MUTE_THRESHOLD},
    };

    use super::*;

    fn gossip_score(gossipsub_app_score: f64) -> PeerScore {
        PeerScore {
            app_score: AppPeerScore {
                gossipsub_app_score,
                req_resp_app_score: 0.0,
            },
            gossipsub_internal_score: 0.0,
        }
    }

    #[test]
    fn instrumented_validator_keeps_inner_decisions() {
        let plain = DefaultP2PValidator;
        let instrumented = InstrumentedValidator::new(DefaultP2PValidator, DEFAULT_MUTE_THRESHOLD);
        let msg = Message::Gossipsub(vec![]);

        let (mut plain_score, mut instrumented_score) = (0.0, 0.0);
        for _ in 0..=(-DEFAULT_MUTE_THRESHOLD as usize) {
            plain_score = plain.validate_msg(&msg, plain_score);
            instrumented_score = instrumented.validate_msg(&msg, instrumented_score);
            assert_eq!(plain_score, instrumented_score);
            assert_eq!(
                plain
                    .get_penalty(&msg, &gossip_score(plain_score))
                    .is_some(),
                instrumented
                    .get_penalty(&msg, &gossip_score(instrumented_score))
                    .is_some()
            );
        }
        assert!(instrumented
            .get_penalty(&msg, &gossip_score(instrumented_score))
            .is_some());

        let elapsed = Duration::from_secs(7);
        assert_eq!(
            plain.apply_decay(&plain_score, &elapsed),
            instrumented.apply_decay(&instrumented_score, &elapsed)
        );
    }
}
