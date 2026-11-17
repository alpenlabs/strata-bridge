//! The sidecar's answer: a [`Decision`], wrapped in an [`Assessment`] bound to one request.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::AssessmentRequest;

/// What the sidecar decided about the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// The node may take the action.
    Proceed,
    /// The node must not take the action.
    Decline,
    /// No decision yet. The node treats it like no answer: the action waits and it asks again.
    Defer,
}

/// The sidecar's answer to one [`AssessmentRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    /// The [`id`](AssessmentRequest::id) of the request this answers.
    pub request_id: String,
    /// The decision.
    pub decision: Decision,
    /// A stable, machine-readable reason, for logs and reports.
    pub reason: String,
    /// When the sidecar decided, in Unix milliseconds.
    pub assessed_at_ms: u64,
    /// When the answer stops counting, in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl Assessment {
    /// Whether this answer counts for `request` at time `now` (Unix milliseconds).
    ///
    /// It counts only if it answers this exact request, was not given in the future, has not
    /// expired, and lives no longer than `max_ttl_ms`. The decision itself is not
    /// checked here: a valid `Defer` still decides nothing.
    pub fn valid_for(&self, request: &AssessmentRequest, now: u64, max_ttl_ms: u64) -> bool {
        let answers_this_request = self.request_id == request.id();
        let is_fresh = self.assessed_at_ms <= now && now < self.expires_at_ms;
        let lifetime_ok = self.assessed_at_ms < self.expires_at_ms
            && self.expires_at_ms - self.assessed_at_ms <= max_ttl_ms;
        answers_this_request && is_fresh && lifetime_ok
    }
}

/// The current time in Unix milliseconds. A clock before 1970 reads as zero; then only an answer
/// stamped at exactly zero could still count.
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::tests::{deposit, withdrawal};

    const NOW: u64 = 1_000_000;
    const MAX_TTL: u64 = 300_000;

    /// A `Proceed` for `request`, given at [`NOW`] and valid for `lifetime_ms`.
    fn answer(request: &AssessmentRequest, lifetime_ms: u64) -> Assessment {
        Assessment {
            request_id: request.id(),
            decision: Decision::Proceed,
            reason: "clean".into(),
            assessed_at_ms: NOW,
            expires_at_ms: NOW + lifetime_ms,
        }
    }

    #[test]
    fn an_answer_counts_only_for_its_own_request() {
        let request = deposit();
        let valid = answer(&request, 1_000);
        assert!(valid.valid_for(&request, NOW, MAX_TTL));

        assert!(
            !valid.valid_for(&withdrawal(), NOW, MAX_TTL),
            "another request"
        );
    }

    #[test]
    fn an_answer_counts_only_while_fresh() {
        let request = deposit();
        let valid = answer(&request, 1_000);
        assert!(
            !valid.valid_for(&request, NOW - 1, MAX_TTL),
            "given in the future"
        );
        assert!(!valid.valid_for(&request, NOW + 1_000, MAX_TTL), "expired");

        let no_lifetime = answer(&request, 0);
        assert!(
            !no_lifetime.valid_for(&request, NOW, MAX_TTL),
            "expires when given"
        );

        assert!(
            answer(&request, MAX_TTL).valid_for(&request, NOW, MAX_TTL),
            "lifetime at the cap"
        );
        assert!(
            !answer(&request, MAX_TTL + 1).valid_for(&request, NOW, MAX_TTL),
            "lifetime over the cap"
        );
    }

    /// The exact JSON of an answer. A change here is a protocol change.
    #[test]
    fn the_answer_wire_format_is_stable() {
        let mut assessment = answer(&deposit(), 1_000);
        assessment.request_id = "id".into();
        assert_eq!(
            serde_json::to_string(&assessment).unwrap(),
            r#"{"request_id":"id","decision":"proceed","reason":"clean","assessed_at_ms":1000000,"expires_at_ms":1001000}"#
        );
        assert_eq!(
            serde_json::to_string(&Decision::Defer).unwrap(),
            r#""defer""#
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut assessment = serde_json::to_value(answer(&deposit(), 1_000)).unwrap();
        assessment["extra"] = 1.into();
        assert!(serde_json::from_value::<Assessment>(assessment).is_err());
    }
}
