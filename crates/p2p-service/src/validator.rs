//! Message rate limiting for the operator set.

use std::time::Duration;

use strata_p2p::{
    score_manager::PeerScore,
    validator::{Message, PenaltyType, Validator},
};

/// Default score charged per accepted message.
pub const DEFAULT_MESSAGE_COST: f64 = 1.0;

/// Default score below which a peer is muted.
pub const DEFAULT_MUTE_THRESHOLD: f64 = -10_000.0;

/// Default score recovered per second.
pub const DEFAULT_RECOVERY_PER_SEC: f64 = 250.0;

/// Default time a peer that crosses the threshold stays muted.
pub const DEFAULT_MUTE_DURATION: Duration = Duration::from_secs(10);

/// Rate limiter sized for allowlisted operators.
///
/// strata-p2p's default validator (100-message burst, 0.9/s recovery, 60 s mute) is tuned for
/// open networks and mutes operators in the middle of a signing round, which stalls it. This keeps
/// the same shape with limits sized for the protocol's bursts.
#[derive(Debug, Clone, Copy)]
pub struct OperatorValidator {
    /// Score charged per accepted message.
    pub message_cost: f64,

    /// Score below which a peer is muted, i.e. the burst a rested peer may send. Must be negative.
    pub mute_threshold: f64,

    /// Score recovered per second, capped at zero, i.e. the sustained per-peer rate that never
    /// mutes.
    pub recovery_per_sec: f64,

    /// How long a peer that crosses the threshold stays muted.
    ///
    /// A muted peer's messages are dropped, not queued, so a short mute limits what must be nagged
    /// for again.
    pub mute_duration: Duration,
}

impl Default for OperatorValidator {
    fn default() -> Self {
        Self {
            message_cost: DEFAULT_MESSAGE_COST,
            mute_threshold: DEFAULT_MUTE_THRESHOLD,
            recovery_per_sec: DEFAULT_RECOVERY_PER_SEC,
            mute_duration: DEFAULT_MUTE_DURATION,
        }
    }
}

impl Validator for OperatorValidator {
    fn validate_msg(&self, _msg: &Message, old_app_score: f64) -> f64 {
        old_app_score - self.message_cost
    }

    fn get_penalty(&self, msg: &Message, peer_score: &PeerScore) -> Option<PenaltyType> {
        let (score, penalty) = match msg {
            Message::Gossipsub(_) => (
                peer_score.app_score.gossipsub_app_score,
                PenaltyType::MuteGossip(self.mute_duration),
            ),
            Message::Request(_) | Message::Response(_) => (
                peer_score.app_score.req_resp_app_score,
                PenaltyType::MuteReqresp(self.mute_duration),
            ),
        };
        (score < self.mute_threshold).then_some(penalty)
    }

    fn apply_decay(&self, score: &f64, time_since_last_decay: &Duration) -> f64 {
        (score + self.recovery_per_sec * time_since_last_decay.as_secs_f64()).min(0.0)
    }
}

#[cfg(test)]
mod tests {
    use strata_p2p::score_manager::AppPeerScore;

    use super::*;

    fn peer_score(gossipsub_app_score: f64, req_resp_app_score: f64) -> PeerScore {
        PeerScore {
            app_score: AppPeerScore {
                gossipsub_app_score,
                req_resp_app_score,
            },
            gossipsub_internal_score: 0.0,
        }
    }

    #[test]
    fn burst_up_to_threshold_is_free_and_one_more_mutes() {
        let validator = OperatorValidator::default();
        let msg = Message::Gossipsub(vec![]);

        let mut score = 0.0;
        for _ in 0..(-DEFAULT_MUTE_THRESHOLD as usize) {
            score = validator.validate_msg(&msg, score);
        }
        assert_eq!(score, DEFAULT_MUTE_THRESHOLD);
        assert!(validator
            .get_penalty(&msg, &peer_score(score, 0.0))
            .is_none());

        score = validator.validate_msg(&msg, score);
        assert!(matches!(
            validator.get_penalty(&msg, &peer_score(score, 0.0)),
            Some(PenaltyType::MuteGossip(DEFAULT_MUTE_DURATION))
        ));
    }

    #[test]
    fn request_response_uses_its_own_score() {
        let validator = OperatorValidator::default();
        let msg = Message::Request(vec![]);

        assert!(validator
            .get_penalty(&msg, &peer_score(DEFAULT_MUTE_THRESHOLD - 1.0, 0.0))
            .is_none());
        assert!(matches!(
            validator.get_penalty(&msg, &peer_score(0.0, DEFAULT_MUTE_THRESHOLD - 1.0)),
            Some(PenaltyType::MuteReqresp(DEFAULT_MUTE_DURATION))
        ));
    }

    #[test]
    fn decay_recovers_at_rate_and_caps_at_zero() {
        let validator = OperatorValidator::default();

        let recovered = validator.apply_decay(&-1_000.0, &Duration::from_secs(2));
        assert_eq!(recovered, -1_000.0 + 2.0 * DEFAULT_RECOVERY_PER_SEC);
        assert_eq!(validator.apply_decay(&-10.0, &Duration::from_secs(60)), 0.0);
    }

    #[test]
    fn configured_limits_replace_defaults() {
        let validator = OperatorValidator {
            message_cost: 2.0,
            mute_threshold: -3.0,
            mute_duration: Duration::from_secs(1),
            ..OperatorValidator::default()
        };
        let msg = Message::Gossipsub(vec![]);

        let score = validator.validate_msg(&msg, validator.validate_msg(&msg, 0.0));
        assert_eq!(score, -4.0);
        assert!(matches!(
            validator.get_penalty(&msg, &peer_score(score, 0.0)),
            Some(PenaltyType::MuteGossip(d)) if d == Duration::from_secs(1)
        ));
    }
}
