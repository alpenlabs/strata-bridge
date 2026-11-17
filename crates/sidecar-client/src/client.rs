//! [`SidecarClient`]: building it from the node's configuration, the answers it holds, and
//! `poll`, which answers from memory and hands missing answers to the worker.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError},
    time::{Duration, Instant},
};

use anyhow::{Context, anyhow, bail};
use bitcoin::Network;
use jsonrpsee::http_client::{HeaderMap, HeaderValue, HttpClient, HttpClientBuilder};
use strata_bridge_sidecar_api::{Assessment, AssessmentRequest, Decision, unix_ms};
use tokio::sync::{Semaphore, mpsc, watch};
use tracing::{debug, error, warn};

use crate::{
    config::{Limits, SidecarConfig},
    worker::{FetchFailure, Job, run_worker},
};

/// How long an answer nobody asks about stays in memory. The pipeline asks about every live
/// action after every committed batch, so an entry this old belongs to an action that is gone
/// (decided, reassigned, or taken back); this only bounds the memory such entries hold.
const CACHE_RETENTION: Duration = Duration::from_secs(3600);

/// A final decision just recorded, identified by its timestamps so a later timer can tell
/// whether it is still the answer held.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HeldDecision {
    /// How long it stays valid, capped at the longest lifetime the client accepts.
    pub(crate) lifetime: Duration,
    pub(crate) assessed_at_ms: u64,
    pub(crate) expires_at_ms: u64,
}

/// What the client holds for one request.
#[derive(Debug)]
pub(crate) struct Cached {
    pub(crate) assessment: Option<Assessment>,
    /// Waiting in the worker's queue or running.
    pub(crate) in_flight: bool,
    pub(crate) retry_at: Instant,
    pub(crate) last_polled: Instant,
}

/// [`Limits::max_assessment_ttl`] in the milliseconds [`Assessment::valid_for`] takes.
fn max_ttl_ms(limits: Limits) -> u64 {
    u64::try_from(limits.max_assessment_ttl.as_millis()).unwrap_or(u64::MAX)
}

/// Locks `mutex`, recovering from poisoning.
///
/// Every critical section here leaves the data valid even if it unwinds part-way: at worst an
/// entry is still marked in flight or a stale answer stays cached, and both expire or are
/// replaced on the next attempt. Recovering keeps one panic from taking the pipeline down.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// State shared by the pipeline-facing client and its assessment worker.
#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) limits: Limits,
    pub(crate) cache: Mutex<BTreeMap<String, Cached>>,
    wake_tx: mpsc::Sender<()>,
}

impl Shared {
    pub(crate) fn wake(&self) {
        // A full channel already holds a pending wake-up; a closed one has no consumer.
        let _ = self.wake_tx.try_send(());
    }

    pub(crate) fn usable(&self, assessment: &Assessment, request: &AssessmentRequest) -> bool {
        assessment.valid_for(request, unix_ms(), max_ttl_ms(self.limits))
    }

    /// How much longer `decision` stays valid by the wall clock, if it is still the answer held
    /// for `id`; `None` once it has expired or been replaced by a newer answer.
    pub(crate) fn remaining_validity(&self, id: &str, decision: HeldDecision) -> Option<Duration> {
        let cache = lock(&self.cache);
        let answer = cache.get(id)?.assessment.as_ref()?;
        let now = unix_ms();
        (answer.decision != Decision::Defer
            && answer.assessed_at_ms == decision.assessed_at_ms
            && answer.expires_at_ms == decision.expires_at_ms
            && answer.assessed_at_ms <= now
            && now < answer.expires_at_ms)
            .then(|| Duration::from_millis(answer.expires_at_ms - now))
    }

    /// Records the result of an attempt and clears its in-flight mark. Returns the decision if
    /// the result is a final one, `None` otherwise.
    pub(crate) fn settle(
        &self,
        id: &str,
        response: Result<Assessment, FetchFailure>,
    ) -> Option<HeldDecision> {
        let mut cache = lock(&self.cache);
        let record = cache.get_mut(id)?;
        record.in_flight = false;
        // Nothing is asked again within the retry interval, however short an answer's lifetime:
        // that bounds the call rate. The worker always wakes the pipeline once a new ask is due.
        record.retry_at = Instant::now() + self.limits.retry;
        match response {
            Ok(result) if result.decision != Decision::Defer => {
                let remaining_ms = result.expires_at_ms.saturating_sub(unix_ms());
                let held = HeldDecision {
                    lifetime: Duration::from_millis(remaining_ms)
                        .min(self.limits.max_assessment_ttl),
                    assessed_at_ms: result.assessed_at_ms,
                    expires_at_ms: result.expires_at_ms,
                };
                record.assessment = Some(result);
                Some(held)
            }
            Ok(result) => {
                debug!(request_id = %id, reason = ?result.reason, "sidecar deferred its decision");
                record.assessment = Some(result);
                None
            }
            Err(failure) => {
                warn!(request_id = %id, %failure, "sidecar assessment unavailable; action waits");
                record.assessment = None;
                None
            }
        }
    }
}

/// Nonblocking assessment scheduler with an in-memory decision cache.
///
/// `poll` never awaits HTTP. It hands a missing assessment to one long-lived worker task, which
/// runs the calls and wakes the bridge pipeline through the receiver returned by
/// [`SidecarClient::take_wakeups`], so a decision is acted on as soon as it arrives rather than
/// on the next periodic tick. The worker starts on the first `poll` and stops when the client is
/// dropped. Grants are not persisted: they live for at most a few minutes, and the
/// durable outcome of a deposit decision is the bridge's own lifecycle state. After a restart
/// every pending action is assessed again.
pub struct SidecarClient {
    pub(crate) shared: Arc<Shared>,
    pub(crate) http: HttpClient,
    last_cache_prune: Mutex<Instant>,
    pub(crate) slots: Arc<Semaphore>,
    jobs: OnceLock<mpsc::UnboundedSender<Job>>,
    wake_rx: Mutex<Option<mpsc::Receiver<()>>>,
    /// Dropped with the client, which stops the worker at once, even while it waits for a slot
    /// or still has queued jobs.
    shutdown: watch::Sender<()>,
}

impl std::fmt::Debug for SidecarClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidecarClient")
            .field("limits", &self.shared.limits)
            .finish_non_exhaustive()
    }
}

impl SidecarClient {
    /// Builds the client for `config`, or returns `None` when the sidecar is disabled. Validates
    /// the configuration and reads the token; does not contact the service.
    ///
    /// A missing token is accepted only when the node runs in `dev` mode off mainnet.
    pub fn connect(
        config: &SidecarConfig,
        network: Network,
        dev: bool,
    ) -> anyhow::Result<Option<Arc<Self>>> {
        Self::connect_with(
            config,
            network,
            dev,
            |name| std::env::var(name),
            Limits::DEFAULT,
        )
    }

    /// [`Self::connect`], reading environment variables through `read_env` and using `limits`.
    fn connect_with(
        config: &SidecarConfig,
        network: Network,
        dev: bool,
        read_env: impl Fn(&str) -> Result<String, std::env::VarError>,
        limits: Limits,
    ) -> anyhow::Result<Option<Arc<Self>>> {
        let SidecarConfig::Enabled {
            endpoint,
            token_env,
            request_timeout,
        } = config
        else {
            return Ok(None);
        };
        if *request_timeout < Duration::from_millis(1)
            || *request_timeout > Duration::from_secs(300)
        {
            bail!("sidecar request_timeout must be between 1 ms and 300 s");
        }
        let endpoint = url::Url::parse(endpoint).context("invalid sidecar URL")?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            bail!("sidecar URL must be HTTP(S), without embedded credentials, query or fragment");
        }
        if endpoint.scheme() == "http"
            && !matches!(endpoint.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
            && !matches!(endpoint.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback())
            && endpoint.host_str() != Some("localhost")
        {
            bail!("remote sidecar URL requires HTTPS");
        }
        let bearer = match token_env {
            // The error never carries the variable's value.
            Some(name) => Some(read_env(name).map_err(|error| match error {
                std::env::VarError::NotPresent => {
                    anyhow!("missing sidecar credential environment variable {name}")
                }
                std::env::VarError::NotUnicode(_) => {
                    anyhow!("sidecar credential environment variable {name} is not valid Unicode")
                }
            })?),
            None if network == Network::Bitcoin => bail!("sidecar requires token_env on mainnet"),
            None if !dev => {
                bail!("sidecar requires token_env unless the node runs with dev = true")
            }
            None => {
                warn!("sidecar authentication is off (dev mode, no token_env)");
                None
            }
        };
        let mut headers = HeaderMap::new();
        if let Some(token) = bearer {
            if token.is_empty() {
                bail!("empty sidecar bearer credential");
            }
            let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
                .context("invalid sidecar bearer credential")?;
            value.set_sensitive(true);
            headers.insert("authorization", value);
        }
        let http = HttpClientBuilder::default()
            .request_timeout(*request_timeout)
            .max_request_size(64 * 1024)
            .max_response_size(64 * 1024)
            .set_headers(headers)
            .build(endpoint.as_str())?;
        // Capacity one: wake-ups coalesce, and the pipeline re-reads every pending action
        // on each wake-up anyway.
        let (wake_tx, wake_rx) = mpsc::channel(1);
        Ok(Some(Arc::new(Self {
            slots: Arc::new(Semaphore::new(limits.max_concurrent_requests)),
            shared: Arc::new(Shared {
                limits,
                cache: Mutex::new(BTreeMap::new()),
                wake_tx,
            }),
            http,
            last_cache_prune: Mutex::new(Instant::now()),
            jobs: OnceLock::new(),
            wake_rx: Mutex::new(Some(wake_rx)),
            shutdown: watch::Sender::new(()),
        })))
    }

    /// Takes the receiver that fires when an assessment finishes or a retry becomes due.
    ///
    /// Returns `None` after the first call; the pipeline is the only consumer.
    pub fn take_wakeups(&self) -> Option<mpsc::Receiver<()>> {
        lock(&self.wake_rx).take()
    }

    /// The worker's job queue, starting the worker on first use. Must run inside a Tokio
    /// runtime.
    ///
    /// The queue holds each request at most once (it stays `in_flight` until settled). The
    /// worker serves it in order, so a request that arrives while every slot is busy waits its
    /// turn instead of losing out to requests that are asked again first. A request whose action
    /// went away while it waited (taken back, reassigned) still runs once, and is not asked
    /// again.
    fn jobs(&self) -> &mpsc::UnboundedSender<Job> {
        self.jobs.get_or_init(|| {
            let (jobs_tx, jobs_rx) = mpsc::unbounded_channel();
            tokio::spawn(run_worker(
                self.shared.clone(),
                self.http.clone(),
                self.slots.clone(),
                jobs_rx,
                self.shutdown.subscribe(),
            ));
            jobs_tx
        })
    }

    /// Returns a cached decision or schedules a bounded background assessment and returns
    /// [`Decision::Defer`].
    pub fn poll(&self, request: AssessmentRequest) -> Decision {
        let id = request.id();
        let mut cache = lock(&self.shared.cache);
        {
            let mut last_prune = lock(&self.last_cache_prune);
            if last_prune.elapsed() >= Duration::from_secs(60) {
                cache.retain(|_, entry| {
                    entry.in_flight || entry.last_polled.elapsed() < CACHE_RETENTION
                });
                *last_prune = Instant::now();
            }
        }
        let record = cache.entry(id.clone()).or_insert_with(|| Cached {
            assessment: None,
            in_flight: false,
            retry_at: Instant::now(),
            last_polled: Instant::now(),
        });
        record.last_polled = Instant::now();
        if let Some(result) = &record.assessment
            && self.shared.usable(result, &request)
            && result.decision != Decision::Defer
        {
            return result.decision;
        }
        if record.in_flight || Instant::now() < record.retry_at {
            return Decision::Defer;
        }
        record.in_flight = true;
        drop(cache);
        let job = Job {
            id: id.clone(),
            request,
        };
        if self.jobs().send(job).is_err() {
            // Only a stopped worker refuses a job.
            error!(request_id = %id, "sidecar worker stopped; action remains deferred");
            if let Some(record) = lock(&self.shared.cache).get_mut(&id) {
                record.in_flight = false;
            }
        }
        Decision::Defer
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use strata_bridge_sidecar_api::Action;

    use super::*;

    /// Fast limits so retries and expiry happen within a test.
    const TEST_LIMITS: Limits = Limits {
        retry: Duration::from_millis(100),
        max_assessment_ttl: Duration::from_secs(1),
        max_concurrent_requests: 1,
    };

    pub(crate) fn test_config(endpoint: &str) -> SidecarConfig {
        test_config_with(endpoint, None, Duration::from_secs(1))
    }

    pub(crate) fn test_config_with(
        endpoint: &str,
        token_env: Option<&str>,
        request_timeout: Duration,
    ) -> SidecarConfig {
        SidecarConfig::Enabled {
            endpoint: endpoint.into(),
            token_env: token_env.map(str::to_owned),
            request_timeout,
        }
    }

    /// Opens an enabled client on regtest in dev mode, with the fast test limits.
    pub(crate) fn open(config: SidecarConfig) -> anyhow::Result<Arc<SidecarClient>> {
        open_with_limits(config, TEST_LIMITS)
    }

    fn open_with_limits(
        config: SidecarConfig,
        limits: Limits,
    ) -> anyhow::Result<Arc<SidecarClient>> {
        SidecarClient::connect_with(
            &config,
            Network::Regtest,
            true,
            |name| std::env::var(name),
            limits,
        )
        .map(|client| client.expect("test configs are enabled"))
    }

    pub(crate) fn deposit_request(deposit_idx: u32) -> AssessmentRequest {
        AssessmentRequest::new(Action::DepositRequest {
            drt_txid: format!("test-drt-{deposit_idx}"),
            drt_vout: 1,
            amount_sats: 1,
        })
    }

    /// A JSON-RPC server that answers every `assess` call with `decision`, valid for 1 s.
    pub(crate) async fn answering_server(
        decision: Decision,
    ) -> (String, tokio::task::JoinHandle<()>) {
        server_with(move |_| (decision, 1000)).await
    }

    /// A JSON-RPC server that answers each request with the decision and lifetime (in ms) that
    /// `answer` picks for it.
    async fn server_with(
        answer: impl Fn(&AssessmentRequest) -> (Decision, u64) + Send + Sync + 'static,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use jsonrpsee::server::{RpcModule, Server};
        let server = Server::builder().build("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", server.local_addr().unwrap());
        let mut module = RpcModule::new(());
        module
            .register_method("sidecar_assess", move |params, _, _| {
                let request: AssessmentRequest = params.one().unwrap();
                let (decision, lifetime_ms) = answer(&request);
                let now = unix_ms();
                Ok::<_, jsonrpsee::types::ErrorObjectOwned>(Assessment {
                    request_id: request.id(),
                    decision,
                    reason: "test".into(),
                    assessed_at_ms: now,
                    expires_at_ms: now + lifetime_ms,
                })
            })
            .unwrap();
        let handle = server.start(module);
        let task = tokio::spawn(async move { handle.stopped().await });
        (endpoint, task)
    }

    #[test]
    fn remote_sidecar_requires_https_and_loopback_http_remains_available() {
        assert!(open(test_config("http://127.0.0.1:8099")).is_ok());
        assert!(open(test_config("http://[::1]:8099")).is_ok());
        assert!(
            open(test_config("http://192.0.2.10:8099"))
                .unwrap_err()
                .to_string()
                .contains("requires HTTPS")
        );
        assert!(open(test_config("https://192.0.2.10:8099")).is_ok());
    }

    #[test]
    fn a_disabled_config_builds_no_client() {
        let client = SidecarClient::connect(&SidecarConfig::Disabled, Network::Bitcoin, false);
        assert!(client.unwrap().is_none());
    }

    #[test]
    fn a_token_is_required_except_in_dev_mode_off_mainnet() {
        let error = |network, dev| {
            let config = test_config("http://127.0.0.1:8099");
            SidecarClient::connect(&config, network, dev)
                .unwrap_err()
                .to_string()
        };
        assert!(error(Network::Regtest, false).contains("unless the node runs with dev = true"));
        assert!(error(Network::Bitcoin, true).contains("on mainnet"));
        let config = test_config("http://127.0.0.1:8099");
        for network in [Network::Regtest, Network::Signet, Network::Testnet4] {
            assert!(
                SidecarClient::connect(&config, network, true)
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[test]
    fn the_token_comes_from_the_named_environment_variable() {
        let config = test_config_with(
            "http://127.0.0.1:8099",
            Some("BRIDGE_SIDECAR_TOKEN"),
            Duration::from_secs(1),
        );
        let open_with = |value: Result<&str, std::env::VarError>| {
            SidecarClient::connect_with(
                &config,
                Network::Bitcoin,
                false,
                |name| {
                    assert_eq!(name, "BRIDGE_SIDECAR_TOKEN");
                    value.clone().map(str::to_owned)
                },
                TEST_LIMITS,
            )
        };

        assert!(open_with(Ok("secret")).is_ok(), "a token works on mainnet");
        assert!(
            open_with(Err(std::env::VarError::NotPresent))
                .unwrap_err()
                .to_string()
                .contains("missing sidecar credential")
        );
        assert!(
            open_with(Ok(""))
                .unwrap_err()
                .to_string()
                .contains("empty sidecar bearer credential")
        );
    }

    /// The startup error never carries the variable's value, even one that is not Unicode.
    #[cfg(unix)]
    #[test]
    fn a_non_unicode_token_is_reported_without_its_value() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let config = test_config_with(
            "http://127.0.0.1:8099",
            Some("BRIDGE_SIDECAR_TOKEN"),
            Duration::from_secs(1),
        );
        let error = SidecarClient::connect_with(
            &config,
            Network::Bitcoin,
            false,
            |_| {
                Err(std::env::VarError::NotUnicode(OsString::from_vec(
                    b"hunter2\xff".to_vec(),
                )))
            },
            TEST_LIMITS,
        )
        .unwrap_err();
        let reported = format!("{error:?}");
        assert!(reported.contains("not valid Unicode"), "{reported}");
        assert!(!reported.contains("hunter2"), "{reported}");
    }

    #[test]
    fn no_response_deadline_cannot_be_disabled_by_configuration() {
        for timeout in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_secs(301),
        ] {
            let config = test_config_with("http://127.0.0.1:8099", None, timeout);
            assert!(open(config).is_err(), "{timeout:?}");
        }
        for timeout in [Duration::from_millis(1), Duration::from_secs(300)] {
            let config = test_config_with("http://127.0.0.1:8099", None, timeout);
            assert!(open(config).is_ok(), "{timeout:?}");
        }
    }

    #[tokio::test]
    async fn finished_assessment_wakes_the_pipeline_without_a_periodic_tick() {
        let (endpoint, server) = answering_server(Decision::Proceed).await;
        let client = open(test_config(&endpoint)).unwrap();
        let mut wakeups = client.take_wakeups().unwrap();
        assert!(client.take_wakeups().is_none(), "one consumer only");
        let request = deposit_request(1);
        assert_eq!(client.poll(request.clone()), Decision::Defer);
        tokio::time::timeout(Duration::from_secs(2), wakeups.recv())
            .await
            .expect("a decision must wake the pipeline")
            .unwrap();
        assert_eq!(client.poll(request), Decision::Proceed);
        server.abort();
    }

    #[tokio::test]
    async fn unavailable_service_schedules_its_own_retry_wakeup() {
        // Nothing listens on port 1: every attempt fails at once.
        let client = open(test_config("http://127.0.0.1:1")).unwrap();
        let mut wakeups = client.take_wakeups().unwrap();
        let request = deposit_request(1);
        assert_eq!(client.poll(request.clone()), Decision::Defer);
        tokio::time::timeout(Duration::from_secs(2), wakeups.recv())
            .await
            .expect("a failed attempt must schedule a retry wake-up")
            .unwrap();
        assert_eq!(client.poll(request), Decision::Defer);
    }

    #[tokio::test]
    async fn stale_unanswered_requests_are_pruned_during_a_continued_outage() {
        let client = open(test_config("http://127.0.0.1:1")).unwrap();
        client.shared.cache.lock().unwrap().insert(
            "orphaned-anchor".into(),
            Cached {
                assessment: None,
                in_flight: false,
                retry_at: Instant::now(),
                last_polled: Instant::now() - CACHE_RETENTION - Duration::from_secs(1),
            },
        );
        *client.last_cache_prune.lock().unwrap() = Instant::now() - Duration::from_secs(61);
        let request = deposit_request(1);
        assert_eq!(client.poll(request.clone()), Decision::Defer);
        let cache = client.shared.cache.lock().unwrap();
        assert!(!cache.contains_key("orphaned-anchor"));
        assert!(cache.contains_key(&request.id()));
    }

    #[tokio::test]
    async fn never_responding_rpc_times_out_and_releases_the_request_slot() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                accepted_tx.send(()).unwrap();
                // Accept the RPC but keep the connection open without sending a response.
                tokio::spawn(async move {
                    let _socket = socket;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                });
            }
        });
        let config = test_config_with(&endpoint, None, Duration::from_millis(100));
        let client = open(config).unwrap();
        for deposit_idx in [1, 2] {
            let request = deposit_request(deposit_idx);
            assert_eq!(client.poll(request.clone()), Decision::Defer);
            tokio::time::timeout(Duration::from_secs(1), accepted_rx.recv())
                .await
                .expect("RPC must reach the nonresponding server");
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if !client.shared.cache.lock().unwrap()[&request.id()].in_flight {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("unanswered RPC must release its slot within the configured timeout");
            assert_eq!(client.slots.available_permits(), 1);
        }
        server.abort();
    }

    /// Dropping the client closes the job queue: the worker stops and aborts the attempts it
    /// still runs, so nothing keeps the shared state alive.
    #[tokio::test]
    async fn dropping_the_client_stops_its_worker() {
        let client = open(test_config("http://127.0.0.1:1")).unwrap();
        assert_eq!(client.poll(deposit_request(1)), Decision::Defer);
        let shared = client.shared.clone();
        drop(client);
        tokio::time::timeout(Duration::from_secs(2), async {
            while Arc::strong_count(&shared) > 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the worker must release the shared state once the client is dropped");
    }

    /// A panic while a lock is held poisons it; the client keeps working instead of panicking
    /// the pipeline on the next poll.
    #[tokio::test]
    async fn a_poisoned_cache_lock_does_not_stop_polling() {
        let client = open(test_config("http://127.0.0.1:1")).unwrap();
        let shared = client.shared.clone();
        let _ = std::thread::spawn(move || {
            let _guard = shared.cache.lock().unwrap();
            panic!("poison the cache lock");
        })
        .join();
        assert!(client.shared.cache.is_poisoned());
        assert_eq!(client.poll(deposit_request(1)), Decision::Defer);
    }

    /// With one slot, a request that keeps deferring is asked again on every wake-up. A second
    /// request that arrived while the slot was busy still gets its turn.
    #[tokio::test]
    async fn a_waiting_request_is_not_starved_by_one_that_keeps_deferring() {
        let (endpoint, server) = server_with(|request| {
            let defers = request == &deposit_request(1);
            (
                if defers {
                    Decision::Defer
                } else {
                    Decision::Proceed
                },
                1000,
            )
        })
        .await;
        let client = open(test_config(&endpoint)).unwrap();
        let mut wakeups = client.take_wakeups().unwrap();
        let (deferring, waiting) = (deposit_request(1), deposit_request(2));
        assert_eq!(client.poll(deferring.clone()), Decision::Defer);
        assert_eq!(client.poll(waiting.clone()), Decision::Defer);

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                wakeups.recv().await.unwrap();
                // Asked in the same order every time, as the pipeline does.
                client.poll(deferring.clone());
                if client.poll(waiting.clone()) == Decision::Proceed {
                    break;
                }
            }
        })
        .await
        .expect("the waiting request must be served");
        server.abort();
    }

    /// An approval that expires before it is used is asked for again by the next retry, and the
    /// worker wakes the pipeline for it: nothing else is left to.
    #[tokio::test]
    async fn an_answer_used_after_it_expires_is_asked_again_by_the_next_retry() {
        let (endpoint, server) = server_with(|_| (Decision::Proceed, 200)).await;
        let limits = Limits {
            retry: Duration::from_millis(500),
            ..TEST_LIMITS
        };
        let client = open_with_limits(test_config(&endpoint), limits).unwrap();
        let mut wakeups = client.take_wakeups().unwrap();
        let request = deposit_request(1);
        assert_eq!(client.poll(request.clone()), Decision::Defer);
        wakeups.recv().await.unwrap();

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(client.poll(request.clone()), Decision::Defer, "expired");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                wakeups.recv().await.unwrap();
                if client.poll(request.clone()) == Decision::Proceed {
                    break;
                }
            }
        })
        .await
        .expect("a fresh approval arrives without any other event");
        server.abort();
    }

    /// A decision that keeps an action held (here a decline) wakes the pipeline again once it
    /// can be asked again, so the action is asked about again without any other event.
    #[tokio::test]
    async fn a_used_decision_wakes_the_pipeline_again_once_it_can_be_asked_again() {
        let (endpoint, server) = server_with(|_| (Decision::Decline, 300)).await;
        let limits = Limits {
            retry: Duration::from_millis(500),
            ..TEST_LIMITS
        };
        let client = open_with_limits(test_config(&endpoint), limits).unwrap();
        let mut wakeups = client.take_wakeups().unwrap();
        let request = deposit_request(1);
        assert_eq!(client.poll(request.clone()), Decision::Defer);
        wakeups.recv().await.unwrap();
        assert_eq!(client.poll(request), Decision::Decline, "used at once");

        tokio::time::timeout(Duration::from_secs(2), wakeups.recv())
            .await
            .expect("the pipeline is woken to ask again")
            .unwrap();
        server.abort();
    }

    /// Dropping the client stops the worker even with calls queued behind a busy slot: no
    /// queued call reaches the sidecar afterwards.
    #[tokio::test]
    async fn dropping_the_client_abandons_queued_calls() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                accepted_tx.send(()).unwrap();
                // Never answers, so the one slot stays busy.
                tokio::spawn(async move {
                    let _socket = socket;
                    tokio::time::sleep(Duration::from_secs(10)).await;
                });
            }
        });
        let client = open(test_config_with(&endpoint, None, Duration::from_secs(10))).unwrap();
        for deposit_idx in 1..=3 {
            assert_eq!(client.poll(deposit_request(deposit_idx)), Decision::Defer);
        }
        tokio::time::timeout(Duration::from_secs(1), accepted_rx.recv())
            .await
            .expect("the first call reaches the sidecar")
            .unwrap();
        drop(client);

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            accepted_rx.try_recv().is_err(),
            "a queued call ran after the drop"
        );
        server.abort();
    }

    /// However short an answer's lifetime, the same request is asked at most once per retry
    /// interval.
    #[tokio::test]
    async fn short_lived_decisions_do_not_raise_the_call_rate() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = calls.clone();
        let (endpoint, server) = server_with(move |_| {
            counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            (Decision::Decline, 10)
        })
        .await;
        let limits = Limits {
            retry: Duration::from_millis(200),
            ..TEST_LIMITS
        };
        let client = open_with_limits(test_config(&endpoint), limits).unwrap();
        let mut wakeups = client.take_wakeups().unwrap();
        let request = deposit_request(1);
        client.poll(request.clone());
        // Ask on every wake-up for one second, as an eager pipeline would.
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                wakeups.recv().await.unwrap();
                client.poll(request.clone());
            }
        })
        .await;
        let calls = calls.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            calls <= 7,
            "{calls} calls in 1 s with a 200 ms retry interval"
        );
        server.abort();
    }

    /// An expiry timer follows only the decision that started it: once a newer answer replaces
    /// it, the timer ends instead of following the new one.
    #[tokio::test]
    async fn an_expiry_timer_stops_following_a_replaced_decision() {
        let client = open(test_config("http://127.0.0.1:1")).unwrap();
        let request = deposit_request(1);
        let id = request.id();
        let answer = |assessed_at_ms| Assessment {
            request_id: id.clone(),
            decision: Decision::Decline,
            reason: "test".into(),
            assessed_at_ms,
            expires_at_ms: assessed_at_ms + 60_000,
        };
        client.shared.cache.lock().unwrap().insert(
            id.clone(),
            Cached {
                assessment: None,
                in_flight: true,
                retry_at: Instant::now(),
                last_polled: Instant::now(),
            },
        );
        // Both answers are already valid, so only their identity tells them apart.
        let now = unix_ms();
        let first = client.shared.settle(&id, Ok(answer(now - 2))).unwrap();
        assert!(client.shared.remaining_validity(&id, first).is_some());

        client.shared.settle(&id, Ok(answer(now - 1))).unwrap();
        assert!(
            client.shared.remaining_validity(&id, first).is_none(),
            "the first timer must not follow the replacement"
        );
    }
}
