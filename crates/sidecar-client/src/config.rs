//! The node's `[sidecar]` section, and the client's fixed limits.

use std::{fmt, time::Duration};

use serde::{Deserialize, Serialize};

/// Whether this node asks a sidecar before taking part in a deposit request or paying a
/// withdrawal assigned to it.
///
/// A tagged section with a default, like `fee_source`: a node that never sets it behaves as
/// before.
///
/// ```toml
/// [sidecar]
/// kind = "enabled"
/// endpoint = "http://127.0.0.1:8099"
/// token_env = "BRIDGE_SIDECAR_TOKEN"
/// ```
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SidecarConfig {
    /// No sidecar: the node takes part in every deposit and pays every withdrawal assigned to it.
    #[default]
    Disabled,
    /// Ask the sidecar at `endpoint` before both actions.
    Enabled {
        /// The sidecar's HTTP(S) URL, for example `http://127.0.0.1:8099`. A non-loopback
        /// endpoint must use HTTPS.
        endpoint: String,
        /// Environment variable holding the bearer token sent to the sidecar. Required unless
        /// the node runs with `dev = true` off mainnet.
        #[serde(default)]
        token_env: Option<String>,
        /// Whole-request timeout. Defaults to 5 s; must be between 1 ms and 300 s.
        #[serde(default = "default_request_timeout")]
        request_timeout: Duration,
    },
}

/// Logged with the node's configuration, so the endpoint is shown without credentials, query or
/// fragment, even when it is invalid and about to be rejected.
impl fmt::Debug for SidecarConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => f.write_str("Disabled"),
            Self::Enabled {
                endpoint,
                token_env,
                request_timeout,
            } => f
                .debug_struct("Enabled")
                .field("endpoint", &redacted(endpoint))
                .field("token_env", token_env)
                .field("request_timeout", request_timeout)
                .finish(),
        }
    }
}

/// `endpoint` without user, password, query or fragment.
fn redacted(endpoint: &str) -> String {
    let Ok(mut url) = url::Url::parse(endpoint) else {
        return "<invalid URL>".to_owned();
    };
    // Only HTTP(S) URLs can be stripped reliably; anything else is rejected at startup anyway.
    if url.cannot_be_a_base() || !matches!(url.scheme(), "http" | "https") {
        return "<unsupported URL>".to_owned();
    }
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

const fn default_request_timeout() -> Duration {
    Duration::from_secs(5)
}

/// How soon an action still waiting for a decision is asked again. Short enough that the node
/// recovers within seconds after an outage, long enough not to hammer a service that keeps
/// deferring.
const RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Longest an answer may authorize an action after it was given. Every answer carries its own
/// expiry; this cap stops a faulty service from issuing a long-lived grant.
const MAX_ASSESSMENT_TTL: Duration = Duration::from_secs(300);

/// Most assessments in flight at once. The load comes from this node only: deposits it holds
/// plus withdrawals assigned to it, each asked at most once per [`RETRY_INTERVAL`]. Eight covers
/// a block full of deposit requests without letting a slow service pile up calls; the rest wait
/// for the next wake-up.
const MAX_CONCURRENT_REQUESTS: usize = 8;

/// The client's timing and concurrency limits.
///
/// Not operator configuration: the values follow from the node's own load. Tests in this crate
/// shorten them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) retry: Duration,
    pub(crate) max_assessment_ttl: Duration,
    pub(crate) max_concurrent_requests: usize,
}

impl Limits {
    /// The production limits.
    pub(crate) const DEFAULT: Self = Self {
        retry: RETRY_INTERVAL,
        max_assessment_ttl: MAX_ASSESSMENT_TTL,
        max_concurrent_requests: MAX_CONCURRENT_REQUESTS,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct Node {
        #[serde(default)]
        sidecar: SidecarConfig,
    }

    #[test]
    fn a_missing_section_means_disabled() {
        let node: Node = toml::from_str("").unwrap();
        assert_eq!(node.sidecar, SidecarConfig::Disabled);
    }

    #[test]
    fn an_enabled_section_parses_with_defaults_and_rejects_unknown_keys() {
        let node: Node = toml::from_str(
            r#"
            [sidecar]
            kind = "enabled"
            endpoint = "http://127.0.0.1:8099"
            token_env = "BRIDGE_SIDECAR_TOKEN"
            "#,
        )
        .unwrap();
        assert_eq!(
            node.sidecar,
            SidecarConfig::Enabled {
                endpoint: "http://127.0.0.1:8099".into(),
                token_env: Some("BRIDGE_SIDECAR_TOKEN".into()),
                request_timeout: Duration::from_secs(5),
            }
        );
        let unknown = toml::from_str::<Node>(
            r#"
            [sidecar]
            kind = "enabled"
            endpoint = "http://127.0.0.1:8099"
            max_concurrent_requests = 8
            "#,
        );
        assert!(
            unknown.is_err(),
            "removed knobs must not be silently accepted"
        );
    }

    #[test]
    fn the_endpoint_is_logged_without_credentials() {
        let config = SidecarConfig::Enabled {
            endpoint: "https://operator:hunter2@sidecar.example:8099/?key=abc#frag".into(),
            token_env: Some("BRIDGE_SIDECAR_TOKEN".into()),
            request_timeout: Duration::from_secs(5),
        };
        let logged = format!("{config:?}");
        for secret in ["operator", "hunter2", "key=abc", "frag"] {
            assert!(!logged.contains(secret), "{secret} leaked: {logged}");
        }
        assert!(logged.contains("https://sidecar.example:8099/"));

        for rejected in [
            "not a url with hunter2",
            "mailto:operator:hunter2@sidecar.example",
            "ftp://operator:hunter2@sidecar.example/",
        ] {
            let config = SidecarConfig::Enabled {
                endpoint: rejected.into(),
                token_env: None,
                request_timeout: Duration::from_secs(5),
            };
            assert!(!format!("{config:?}").contains("hunter2"), "{rejected}");
        }
    }
}
