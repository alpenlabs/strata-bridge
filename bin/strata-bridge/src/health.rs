//! Bridge process health registry and `/healthz` response types.

use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use chrono::{SecondsFormat, Utc};
use jsonrpsee::server::{HttpBody, HttpRequest, HttpResponse};
use metrics::{describe_gauge, gauge};
use serde::Serialize;
use tracing::error;

/// HTTP path exposed for bridge health checks.
pub(crate) const HEALTH_HTTP_PATH: &str = "/healthz";
/// Process-level component name.
pub(crate) const COMPONENT_PROCESS: &str = "process";
/// Bitcoin RPC component name.
pub(crate) const COMPONENT_BITCOIN_RPC: &str = "bitcoin_rpc";
/// Bitcoin ZMQ component name.
pub(crate) const COMPONENT_BITCOIN_ZMQ: &str = "bitcoin_zmq";
/// ASM RPC component name.
pub(crate) const COMPONENT_ASM_RPC: &str = "asm_rpc";
/// ASM assignment feed component name.
pub(crate) const COMPONENT_ASM_ASSIGNMENT_FEED: &str = "asm_assignment_feed";
/// FoundationDB component name.
pub(crate) const COMPONENT_FDB: &str = "fdb";
/// P2P component name.
pub(crate) const COMPONENT_P2P: &str = "p2p";
/// Mosaic component name.
pub(crate) const COMPONENT_MOSAIC: &str = "mosaic";
/// Secret service component name.
pub(crate) const COMPONENT_S2: &str = "s2";
/// Operator wallet component name.
pub(crate) const COMPONENT_WALLET: &str = "wallet";
/// Bitcoin transaction driver component name.
pub(crate) const COMPONENT_TX_DRIVER: &str = "tx_driver";
/// Orchestrator component name.
pub(crate) const COMPONENT_ORCHESTRATOR: &str = "orchestrator";
/// RPC state cache component name.
pub(crate) const COMPONENT_RPC_CACHE: &str = "rpc_cache";

const ALL_COMPONENTS: &[&str] = &[
    COMPONENT_PROCESS,
    COMPONENT_BITCOIN_RPC,
    COMPONENT_BITCOIN_ZMQ,
    COMPONENT_ASM_RPC,
    COMPONENT_ASM_ASSIGNMENT_FEED,
    COMPONENT_FDB,
    COMPONENT_P2P,
    COMPONENT_MOSAIC,
    COMPONENT_S2,
    COMPONENT_WALLET,
    COMPONENT_TX_DRIVER,
    COMPONENT_ORCHESTRATOR,
    COMPONENT_RPC_CACHE,
];

/// Low-cardinality health status for the bridge and its components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HealthStatus {
    /// Component is healthy.
    Ok,

    /// Component can not yet prove full readiness, but the process can still report health.
    Degraded,

    /// Component has observed a hard failure.
    Unhealthy,
}

impl HealthStatus {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
        }
    }
}

/// Shared health state updated by bootstrap code and read by the RPC server.
#[derive(Debug, Clone)]
pub(crate) struct HealthRegistry {
    components: Arc<RwLock<BTreeMap<&'static str, ComponentHealth>>>,
}

impl HealthRegistry {
    /// Creates a registry with every known component explicitly marked as not initialized.
    pub(crate) fn new() -> Self {
        describe_gauge!(
            "strata_bridge_health_component_status",
            "Bridge component health status. Labels are intentionally limited to component and status."
        );

        let components = ALL_COMPONENTS
            .iter()
            .copied()
            .map(|component| {
                let health =
                    ComponentHealth::new(component, HealthStatus::Unhealthy, "not_initialized");
                emit_component_metric(component, health.status);
                (component, health)
            })
            .collect();

        Self {
            components: Arc::new(RwLock::new(components)),
        }
    }

    /// Marks a component as healthy and records a new last-success timestamp.
    pub(crate) fn mark_ok(&self, component: &'static str, reason: impl Into<String>) {
        self.set(component, HealthStatus::Ok, reason.into(), true);
    }

    /// Marks a component as degraded while preserving its previous last-success timestamp.
    pub(crate) fn mark_degraded(&self, component: &'static str, reason: impl Into<String>) {
        self.set(component, HealthStatus::Degraded, reason.into(), false);
    }

    /// Marks a component as unhealthy while preserving its previous last-success timestamp.
    pub(crate) fn mark_unhealthy(&self, component: &'static str, reason: impl Into<String>) {
        self.set(component, HealthStatus::Unhealthy, reason.into(), false);
    }

    /// Returns the current machine-readable health payload.
    pub(crate) fn snapshot(&self) -> HealthSnapshot {
        let components = match self.components.read() {
            Ok(components) => components,
            Err(poisoned) => {
                error!("health registry read lock poisoned");
                poisoned.into_inner()
            }
        };

        let component_snapshots: Vec<_> = components
            .values()
            .cloned()
            .map(ComponentHealthSnapshot::from)
            .collect();
        let status = aggregate_status(component_snapshots.iter().map(|component| component.status));

        HealthSnapshot {
            status,
            checked_at: now_rfc3339(),
            components: component_snapshots,
        }
    }

    fn set(
        &self,
        component: &'static str,
        status: HealthStatus,
        reason: String,
        update_last_success: bool,
    ) {
        let mut components = match self.components.write() {
            Ok(components) => components,
            Err(poisoned) => {
                error!("health registry write lock poisoned");
                poisoned.into_inner()
            }
        };

        let (last_success_time, last_success_instant) = if update_last_success {
            (Some(now_rfc3339()), Some(Instant::now()))
        } else {
            let previous = components
                .get(component)
                .map(|health| {
                    (
                        health.last_success_time.clone(),
                        health.last_success_instant,
                    )
                })
                .unwrap_or((None, None));
            previous
        };

        components.insert(
            component,
            ComponentHealth {
                component,
                status,
                reason,
                last_success_time,
                last_success_instant,
            },
        );
        emit_component_metric(component, status);
    }

    /// Marks a component unhealthy if its last successful update is older than `max_age`.
    pub(crate) fn mark_unhealthy_if_stale(
        &self,
        component: &'static str,
        max_age: Duration,
        reason: impl Into<String>,
    ) {
        let mut components = match self.components.write() {
            Ok(components) => components,
            Err(poisoned) => {
                error!("health registry write lock poisoned");
                poisoned.into_inner()
            }
        };

        let health = components.entry(component).or_insert_with(|| {
            ComponentHealth::new(component, HealthStatus::Degraded, "not_initialized")
        });

        if health
            .last_success_instant
            .is_some_and(|instant| instant.elapsed() <= max_age)
        {
            return;
        }

        health.status = HealthStatus::Unhealthy;
        health.reason = reason.into();
        emit_component_metric(component, HealthStatus::Unhealthy);
    }
}

/// Tower layer that serves `GET /healthz` before JSON-RPC dispatch.
#[derive(Debug, Clone)]
pub(crate) struct HealthHttpLayer {
    registry: HealthRegistry,
}

impl HealthHttpLayer {
    /// Creates a health HTTP layer backed by the shared registry.
    pub(crate) fn new(registry: HealthRegistry) -> Self {
        Self { registry }
    }
}

impl<S> tower::Layer<S> for HealthHttpLayer {
    type Service = HealthHttpService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HealthHttpService {
            inner,
            registry: self.registry.clone(),
        }
    }
}

/// Service produced by [`HealthHttpLayer`].
#[derive(Debug, Clone)]
pub(crate) struct HealthHttpService<S> {
    inner: S,
    registry: HealthRegistry,
}

impl<S, B> tower::Service<HttpRequest<B>> for HealthHttpService<S>
where
    S: tower::Service<HttpRequest<B>, Response = HttpResponse> + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = HttpResponse;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: HttpRequest<B>) -> Self::Future {
        if request.uri().path() == HEALTH_HTTP_PATH {
            let response = if request.method().as_str() == "GET" {
                health_response(self.registry.snapshot())
            } else {
                method_not_allowed_response()
            };
            return Box::pin(async move { Ok(response) });
        }

        Box::pin(self.inner.call(request))
    }
}

fn health_response(snapshot: HealthSnapshot) -> HttpResponse {
    let status = http_status_for_health(snapshot.status);
    match serde_json::to_vec(&snapshot) {
        Ok(body) => response(status, "application/json; charset=utf-8", body),
        Err(err) => {
            error!(%err, "failed to serialize health snapshot");
            response(
                500,
                "application/json; charset=utf-8",
                br#"{"status":"unhealthy","reason":"health_snapshot_serialization_failed"}"#
                    .to_vec(),
            )
        }
    }
}

fn method_not_allowed_response() -> HttpResponse {
    response(
        405,
        "application/json; charset=utf-8",
        br#"{"error":"method_not_allowed"}"#.to_vec(),
    )
}

fn response(status: u16, content_type: &'static str, body: Vec<u8>) -> HttpResponse {
    HttpResponse::builder()
        .status(status)
        .header("content-type", content_type)
        .header("cache-control", "no-store")
        .body(HttpBody::from(body))
        .expect("static health HTTP response should be valid")
}

fn http_status_for_health(status: HealthStatus) -> u16 {
    match status {
        HealthStatus::Ok | HealthStatus::Degraded => 200,
        HealthStatus::Unhealthy => 503,
    }
}

impl Default for HealthRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct ComponentHealth {
    component: &'static str,
    status: HealthStatus,
    reason: String,
    last_success_time: Option<String>,
    last_success_instant: Option<Instant>,
}

impl ComponentHealth {
    fn new(component: &'static str, status: HealthStatus, reason: impl Into<String>) -> Self {
        Self {
            component,
            status,
            reason: reason.into(),
            last_success_time: None,
            last_success_instant: None,
        }
    }
}

/// Top-level `/healthz` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct HealthSnapshot {
    /// Aggregate bridge health status.
    pub(crate) status: HealthStatus,

    /// RFC 3339 timestamp when this snapshot was built.
    pub(crate) checked_at: String,

    /// Per-component health records.
    pub(crate) components: Vec<ComponentHealthSnapshot>,
}

/// Per-component `/healthz` response entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ComponentHealthSnapshot {
    /// Stable low-cardinality component name.
    pub(crate) component: &'static str,

    /// Current component health status.
    pub(crate) status: HealthStatus,

    /// Stable, operator-readable reason.
    pub(crate) reason: String,

    /// RFC 3339 timestamp of the last successful component update, if known.
    pub(crate) last_success_time: Option<String>,
}

impl From<ComponentHealth> for ComponentHealthSnapshot {
    fn from(health: ComponentHealth) -> Self {
        Self {
            component: health.component,
            status: health.status,
            reason: health.reason,
            last_success_time: health.last_success_time,
        }
    }
}

fn aggregate_status(statuses: impl IntoIterator<Item = HealthStatus>) -> HealthStatus {
    let mut aggregate = HealthStatus::Ok;

    for status in statuses {
        match status {
            HealthStatus::Unhealthy => return HealthStatus::Unhealthy,
            HealthStatus::Degraded => aggregate = HealthStatus::Degraded,
            HealthStatus::Ok => {}
        }
    }

    aggregate
}

fn emit_component_metric(component: &'static str, active_status: HealthStatus) {
    for status in [
        HealthStatus::Ok,
        HealthStatus::Degraded,
        HealthStatus::Unhealthy,
    ] {
        let value = if status == active_status { 1.0 } else { 0.0 };
        gauge!(
            "strata_bridge_health_component_status",
            "component" => component,
            "status" => status.as_label(),
        )
        .set(value);
    }
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };

    use tower::{Layer, Service};

    use super::*;

    #[test]
    fn new_registry_starts_unhealthy_for_all_components() {
        let snapshot = HealthRegistry::new().snapshot();

        assert_eq!(snapshot.status, HealthStatus::Unhealthy);
        assert_eq!(snapshot.components.len(), ALL_COMPONENTS.len());
        assert!(
            snapshot
                .components
                .iter()
                .all(|component| component.status == HealthStatus::Unhealthy)
        );
    }

    #[test]
    fn aggregate_status_prioritizes_unhealthy_then_degraded() {
        assert_eq!(
            aggregate_status([HealthStatus::Ok, HealthStatus::Degraded]),
            HealthStatus::Degraded
        );
        assert_eq!(
            aggregate_status([HealthStatus::Degraded, HealthStatus::Unhealthy]),
            HealthStatus::Unhealthy
        );
    }

    #[test]
    fn ok_update_records_last_success_and_degraded_preserves_it() {
        let registry = HealthRegistry::new();

        registry.mark_ok(COMPONENT_PROCESS, "initialized");
        let ok_snapshot = registry.snapshot();
        let process = ok_snapshot
            .components
            .iter()
            .find(|component| component.component == COMPONENT_PROCESS)
            .expect("process component must exist");
        let last_success = process.last_success_time.clone();
        assert!(last_success.is_some());

        registry.mark_degraded(COMPONENT_PROCESS, "test_degraded");
        let degraded_snapshot = registry.snapshot();
        let process = degraded_snapshot
            .components
            .iter()
            .find(|component| component.component == COMPONENT_PROCESS)
            .expect("process component must exist");

        assert_eq!(process.status, HealthStatus::Degraded);
        assert_eq!(process.last_success_time, last_success);
    }

    #[test]
    fn snapshot_serializes_last_success_time_field() {
        let registry = HealthRegistry::new();
        registry.mark_ok(COMPONENT_PROCESS, "initialized");

        let value = serde_json::to_value(registry.snapshot()).expect("snapshot must serialize");
        let process = value["components"]
            .as_array()
            .expect("components must serialize as array")
            .iter()
            .find(|component| component["component"] == COMPONENT_PROCESS)
            .expect("process component must exist");

        assert!(process.get("last_success_time").is_some());
        assert!(process.get("last_success_at").is_none());
    }

    #[test]
    fn stale_check_preserves_fresh_component_and_marks_missing_success_unhealthy() {
        let registry = HealthRegistry::new();

        registry.mark_ok(COMPONENT_PROCESS, "initialized");
        registry.mark_unhealthy_if_stale(
            COMPONENT_PROCESS,
            Duration::from_secs(60),
            "process_stale",
        );
        let process = registry
            .snapshot()
            .components
            .into_iter()
            .find(|component| component.component == COMPONENT_PROCESS)
            .expect("process component must exist");
        assert_eq!(process.status, HealthStatus::Ok);

        registry.mark_unhealthy_if_stale(
            COMPONENT_ORCHESTRATOR,
            Duration::from_secs(60),
            "pipeline_stale",
        );
        let orchestrator = registry
            .snapshot()
            .components
            .into_iter()
            .find(|component| component.component == COMPONENT_ORCHESTRATOR)
            .expect("orchestrator component must exist");
        assert_eq!(orchestrator.status, HealthStatus::Unhealthy);
        assert_eq!(orchestrator.reason, "pipeline_stale");
    }

    #[test]
    fn asm_rpc_and_assignment_feed_health_are_independent() {
        let registry = HealthRegistry::new();

        registry.mark_unhealthy(COMPONENT_ASM_ASSIGNMENT_FEED, "assignments_fetch_failed");
        registry.mark_ok(COMPONENT_ASM_RPC, "asm_rpc_reachable");

        let snapshot = registry.snapshot();
        let asm_rpc = snapshot
            .components
            .iter()
            .find(|component| component.component == COMPONENT_ASM_RPC)
            .expect("asm rpc component must exist");
        let assignment_feed = snapshot
            .components
            .iter()
            .find(|component| component.component == COMPONENT_ASM_ASSIGNMENT_FEED)
            .expect("asm assignment feed component must exist");

        assert_eq!(asm_rpc.status, HealthStatus::Ok);
        assert_eq!(assignment_feed.status, HealthStatus::Unhealthy);
        assert_eq!(assignment_feed.reason, "assignments_fetch_failed");
    }

    #[test]
    fn health_status_maps_to_infra_http_status() {
        assert_eq!(http_status_for_health(HealthStatus::Ok), 200);
        assert_eq!(http_status_for_health(HealthStatus::Degraded), 200);
        assert_eq!(http_status_for_health(HealthStatus::Unhealthy), 503);
    }

    #[tokio::test]
    async fn health_http_layer_returns_503_for_unhealthy_snapshot() {
        let registry = HealthRegistry::new();
        let mut service = HealthHttpLayer::new(registry).layer(TestService);
        let request = health_request("GET", HEALTH_HTTP_PATH);

        let response = service.call(request).await.expect("health response");

        assert_eq!(response.status().as_u16(), 503);
        assert_json_health_headers(&response);
    }

    #[tokio::test]
    async fn health_http_layer_returns_200_for_degraded_snapshot() {
        let registry = HealthRegistry::new();
        for component in ALL_COMPONENTS {
            registry.mark_ok(component, "test_ok");
        }
        registry.mark_degraded(COMPONENT_P2P, "partial_peer_connectivity");
        let mut service = HealthHttpLayer::new(registry).layer(TestService);
        let request = health_request("GET", HEALTH_HTTP_PATH);

        let response = service.call(request).await.expect("health response");

        assert_eq!(response.status().as_u16(), 200);
        assert_json_health_headers(&response);
    }

    #[tokio::test]
    async fn health_http_layer_rejects_non_get_health_requests() {
        let registry = HealthRegistry::new();
        let mut service = HealthHttpLayer::new(registry).layer(TestService);
        let request = health_request("POST", HEALTH_HTTP_PATH);

        let response = service.call(request).await.expect("health response");

        assert_eq!(response.status().as_u16(), 405);
        assert_json_health_headers(&response);
    }

    #[tokio::test]
    async fn health_http_layer_passes_through_non_health_requests() {
        let registry = HealthRegistry::new();
        let mut service = HealthHttpLayer::new(registry).layer(TestService);
        let request = health_request("GET", "/");

        let response = service.call(request).await.expect("inner response");

        assert_eq!(response.status().as_u16(), 418);
    }

    #[derive(Clone)]
    struct TestService;

    impl tower::Service<HttpRequest<HttpBody>> for TestService {
        type Response = HttpResponse;
        type Error = Infallible;
        type Future =
            Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: HttpRequest<HttpBody>) -> Self::Future {
            Box::pin(async {
                Ok(HttpResponse::builder()
                    .status(418)
                    .body(HttpBody::from("inner"))
                    .expect("test response should be valid"))
            })
        }
    }

    fn health_request(method: &str, uri: &str) -> HttpRequest<HttpBody> {
        HttpRequest::builder()
            .method(method)
            .uri(uri)
            .body(HttpBody::from(Vec::new()))
            .expect("test request should be valid")
    }

    fn assert_json_health_headers(response: &HttpResponse) {
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .expect("cache-control header")
                .to_str()
                .expect("cache-control header value"),
            "no-store"
        );
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .expect("content-type header")
                .to_str()
                .expect("content-type header value"),
            "application/json; charset=utf-8"
        );
    }
}
