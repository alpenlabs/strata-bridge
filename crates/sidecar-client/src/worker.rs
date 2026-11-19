//! The one background task that runs the sidecar calls.

use std::{collections::HashMap, panic::AssertUnwindSafe, sync::Arc};

use futures::FutureExt;
use jsonrpsee::http_client::HttpClient;
use strata_bridge_sidecar_api::{Assessment, AssessmentRequest, rpc::SidecarRpcClient};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::{Id, JoinSet},
};
use tracing::{Instrument, error, info_span};

use crate::client::{Shared, lock};

/// Longest part of a sidecar's RPC error message that is logged.
const MAX_LOGGED_RPC_MESSAGE: usize = 120;

/// One call for the worker to run.
pub(crate) struct Job {
    pub(crate) id: String,
    pub(crate) request: AssessmentRequest,
}

/// Why a call produced no usable answer.
///
/// Logged in place of the raw error: transport errors can embed the endpoint URL, so only the
/// failure class, an HTTP status, or the sidecar's own RPC code and short message are kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FetchFailure {
    /// No answer within the request timeout.
    Timeout,
    /// The connection could not be made, or broke before an answer arrived.
    Connect,
    /// The sidecar answered with a non-success HTTP status, for example 401 or 503.
    HttpStatus(u16),
    /// The sidecar answered with a JSON-RPC error.
    Rpc { code: i32, message: String },
    /// The answer was not a valid assessment.
    Decode,
    /// The answer is for another request, or is not fresh.
    Unusable,
    /// The call panicked.
    Panicked,
    /// Any other client-side failure.
    Other,
}

impl FetchFailure {
    fn classify(error: &jsonrpsee::core::client::Error) -> Self {
        use jsonrpsee::{core::client::Error, http_client::transport::Error as Transport};
        match error {
            Error::RequestTimeout => Self::Timeout,
            Error::Call(object) => Self::Rpc {
                code: object.code(),
                message: object
                    .message()
                    .chars()
                    .take(MAX_LOGGED_RPC_MESSAGE)
                    .collect(),
            },
            Error::ParseError(_) => Self::Decode,
            Error::Transport(inner) => match inner.downcast_ref::<Transport>() {
                Some(Transport::Rejected { status_code }) => Self::HttpStatus(*status_code),
                Some(Transport::Http(_)) => Self::Connect,
                _ => Self::Other,
            },
            _ => Self::Other,
        }
    }
}

impl std::fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => f.write_str("timeout"),
            Self::Connect => f.write_str("connect"),
            Self::HttpStatus(status) => write!(f, "http_status={status}"),
            // Debug-quote the sidecar's text so it cannot inject log lines.
            Self::Rpc { code, message } => write!(f, "rpc_error={code} {message:?}"),
            Self::Decode => f.write_str("decode"),
            Self::Unusable => f.write_str("stale_or_unbound"),
            Self::Panicked => f.write_str("panicked"),
            Self::Other => f.write_str("other"),
        }
    }
}

/// Runs calls until the client is dropped.
///
/// Takes jobs in order and starts each once one of the `slots` is free, so at most that many
/// calls run at once and none is skipped. Owns every running call. A call that panics settles like
/// a failed call, so its action is retried after the retry interval; a task that ends any other way
/// clears its in-flight mark here. When the client is dropped, `shutdown` closes: the loop ends at
/// once, even with jobs still queued or while waiting for a slot, and dropping the task set aborts
/// the calls still running.
pub(crate) async fn run_worker(
    shared: Arc<Shared>,
    http: HttpClient,
    slots: Arc<Semaphore>,
    mut jobs: mpsc::UnboundedReceiver<Job>,
    mut shutdown: watch::Receiver<()>,
) {
    let mut tasks = JoinSet::new();
    let mut running: HashMap<Id, String> = HashMap::new();
    loop {
        tokio::select! {
            // Shutdown first, then finished calls, then new ones: a steady backlog must not keep
            // finished tasks from being reaped.
            biased;
            _ = shutdown.changed() => return,
            Some(joined) = tasks.join_next_with_id() => {
                let task = match joined {
                    Ok((task, ())) => task,
                    Err(err) => {
                        let task = err.id();
                        if let Some(id) = running.get(&task) {
                            error!(%err, request_id = %id, "sidecar assessment task failed");
                            if let Some(record) = lock(&shared.cache).get_mut(id) {
                                record.in_flight = false;
                            }
                        }
                        task
                    }
                };
                running.remove(&task);
            }
            job = jobs.recv() => {
                let Some(Job { id, request }) = job else {
                    return;
                };
                // Waits for a running call to finish when every slot is busy.
                let slot = tokio::select! {
                    biased;
                    _ = shutdown.changed() => return,
                    slot = slots.clone().acquire_owned() => match slot {
                        Ok(slot) => slot,
                        Err(_) => return,
                    },
                };
                let span = info_span!("sidecar_assessment", request_id = %id);
                let call = fetch(shared.clone(), http.clone(), request);
                let task = tasks.spawn(run_call(shared.clone(), id.clone(), slot, call).instrument(span));
                running.insert(task.id(), id);
            }
        }
    }
}

/// Runs one call, records its result and wakes the pipeline: for a final decision at once and
/// again when it can be asked again (once it expires and the retry interval has passed), so an
/// action it leaves held, like a declined withdrawal, is asked about again; otherwise after the
/// retry interval.
pub(crate) async fn run_call(
    shared: Arc<Shared>,
    id: String,
    slot: OwnedSemaphorePermit,
    call: impl Future<Output = Result<Assessment, FetchFailure>>,
) {
    let response = AssertUnwindSafe(call)
        .catch_unwind()
        .await
        .unwrap_or_else(|_| {
            error!(request_id = %id, "sidecar assessment panicked");
            Err(FetchFailure::Panicked)
        });
    // Release the concurrency slot before any retry backoff below.
    drop(slot);
    // Nothing else is guaranteed to ask again soon (the periodic retry tick can be an hour
    // apart), so the next wake-up is scheduled here.
    match shared.settle(&id, response) {
        Some(decision) => {
            shared.wake();
            tokio::time::sleep(decision.lifetime.max(shared.limits.retry)).await;
            // The sleep is monotonic but validity follows the wall clock. If the clock stepped
            // back, this decision is still valid now; wait for its real expiry so the wake-up
            // below is not spent too early. A newer answer ends the wait: it has its own timer.
            while let Some(remaining) = shared.remaining_validity(&id, decision) {
                tokio::time::sleep(remaining.min(shared.limits.max_assessment_ttl)).await;
            }
        }
        None => tokio::time::sleep(shared.limits.retry).await,
    }
    shared.wake();
}

/// Calls the sidecar once and keeps the answer only if it counts for `request`.
pub(crate) async fn fetch(
    shared: Arc<Shared>,
    http: HttpClient,
    request: AssessmentRequest,
) -> Result<Assessment, FetchFailure> {
    let assessment = http
        .assess(request.clone())
        .await
        .map_err(|error| FetchFailure::classify(&error))?;
    if !shared.usable(&assessment, &request) {
        return Err(FetchFailure::Unusable);
    }
    Ok(assessment)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use strata_bridge_sidecar_api::Assessment;

    use super::*;
    use crate::client::{
        Cached,
        tests::{deposit_request, open, test_config, test_config_with},
    };

    /// A panic inside a call settles like a failed call: the action is no longer in flight, its
    /// slot is free, and a retry wake-up follows.
    #[tokio::test]
    async fn a_panicking_call_settles_as_a_failure_and_wakes_for_a_retry() {
        let client = open(test_config("http://127.0.0.1:1")).unwrap();
        let mut wakeups = client.take_wakeups().unwrap();
        let request = deposit_request(1);
        let id = request.id();
        client.shared.cache.lock().unwrap().insert(
            id.clone(),
            Cached {
                assessment: None,
                in_flight: true,
                retry_at: Instant::now(),
                last_polled: Instant::now(),
            },
        );
        let slot = client.slots.clone().try_acquire_owned().unwrap();
        run_call(client.shared.clone(), id.clone(), slot, async {
            panic!("assessment bug")
        })
        .await;
        assert!(!client.shared.cache.lock().unwrap()[&id].in_flight);
        assert_eq!(client.slots.available_permits(), 1);
        tokio::time::timeout(Duration::from_secs(2), wakeups.recv())
            .await
            .expect("a panicked call must schedule a retry wake-up")
            .unwrap();
    }

    /// Failed calls are logged by class, never with the raw error, which can embed the endpoint.
    #[tokio::test]
    async fn failed_calls_are_classified_without_the_raw_error() {
        let request = deposit_request(1);
        let fetch_with = |client: &Arc<crate::SidecarClient>| {
            fetch(client.shared.clone(), client.http.clone(), request.clone())
        };

        // Nothing listens on port 1.
        let client = open(test_config("http://127.0.0.1:1")).unwrap();
        assert_eq!(fetch_with(&client).await, Err(FetchFailure::Connect));

        // Accepts the connection but never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let silent = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let client = open(test_config_with(
            &endpoint,
            None,
            Duration::from_millis(100),
        ))
        .unwrap();
        assert_eq!(fetch_with(&client).await, Err(FetchFailure::Timeout));
        silent.abort();

        // An HTTP-level rejection, as a sidecar sends for a wrong bearer token.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let rejecting = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = [0u8; 4096];
                let _ = socket.read(&mut buffer).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n")
                    .await;
            }
        });
        let client = open(test_config(&endpoint)).unwrap();
        let failure = fetch_with(&client).await.unwrap_err();
        assert_eq!(failure, FetchFailure::HttpStatus(401));
        assert_eq!(failure.to_string(), "http_status=401");
        rejecting.abort();

        // A JSON-RPC error carries the sidecar's code and quoted message.
        use jsonrpsee::server::{RpcModule, Server};
        let server = Server::builder().build("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", server.local_addr().unwrap());
        let mut module = RpcModule::new(());
        module
            .register_method("sidecar_assess", |_, _, _| {
                Err::<Assessment, _>(jsonrpsee::types::ErrorObjectOwned::owned(
                    -32001,
                    "assessment capacity busy",
                    None::<()>,
                ))
            })
            .unwrap();
        let handle = server.start(module);
        let client = open(test_config(&endpoint)).unwrap();
        let failure = fetch_with(&client).await.unwrap_err();
        assert_eq!(
            failure.to_string(),
            "rpc_error=-32001 \"assessment capacity busy\""
        );
        handle.stop().unwrap();
    }
}
