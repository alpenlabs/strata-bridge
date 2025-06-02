//! The Alpen Bridge is a bridge node for the Alpen BitVM rollup.

use std::{fs, path::Path, thread::sleep};

use args::OperationMode;
use clap::Parser;
use config::Config;
use constants::{DEFAULT_THREAD_COUNT, DEFAULT_THREAD_STACK_SIZE, STARTUP_DELAY};
use mode::{operator, verifier};
use params::Params;
use serde::de::DeserializeOwned;
use strata_bridge_common::{logging, logging::LoggerConfig};
use tracing::{debug, info};

mod args;
mod config;
mod mode;
mod params;
mod rpc_server;

mod constants;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[allow(non_upper_case_globals)]
#[export_name = "malloc_conf"]
pub static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

fn main() {
    logging::init(LoggerConfig::with_base_name("bridge-node"));

    info!(?STARTUP_DELAY, "waiting for bitcoind setup phase");
    sleep(constants::STARTUP_DELAY);

    let cli = args::Cli::parse();
    info!(mode = %cli.mode, "starting bridge node");

    let params = parse_toml::<Params>(cli.params);
    let config = parse_toml::<Config>(cli.config);

    match cli.mode {
        OperationMode::Operator => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(config.num_threads.unwrap_or(DEFAULT_THREAD_COUNT).into())
                .thread_stack_size(
                    config
                        .thread_stack_size
                        .unwrap_or(DEFAULT_THREAD_STACK_SIZE),
                )
                .enable_all()
                .build()
                .expect("must be able to create runtime");

            runtime.block_on(async move {
                tokio::spawn(async move {
                    use axum::{http::StatusCode, response::IntoResponse};

                    async fn handle_get_heap() -> Result<impl IntoResponse, (StatusCode, String)> {
                        let mut prof_ctl = jemalloc_pprof::PROF_CTL.as_ref().unwrap().lock().await;
                        require_profiling_activated(&prof_ctl)?;
                        let pprof = prof_ctl
                            .dump_pprof()
                            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
                        Ok(pprof)
                    }

                    async fn handle_get_heap_flamegraph(
                    ) -> Result<impl IntoResponse, (StatusCode, String)> {
                        use axum::{body::Body, http::header::CONTENT_TYPE, response::Response};

                        let mut prof_ctl = jemalloc_pprof::PROF_CTL.as_ref().unwrap().lock().await;
                        require_profiling_activated(&prof_ctl)?;
                        let svg = prof_ctl
                            .dump_flamegraph()
                            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
                        Response::builder()
                            .header(CONTENT_TYPE, "image/svg+xml")
                            .body(Body::from(svg))
                            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))
                    }

                    /// Checks whether jemalloc profiling is activated an returns an error response
                    /// if not.
                    fn require_profiling_activated(
                        prof_ctl: &jemalloc_pprof::JemallocProfCtl,
                    ) -> Result<(), (StatusCode, String)> {
                        if prof_ctl.activated() {
                            Ok(())
                        } else {
                            Err((
                                axum::http::StatusCode::FORBIDDEN,
                                "heap profiling not activated".into(),
                            ))
                        }
                    }

                    let app = axum::Router::new()
                        .route("/debug/pprof/heap", axum::routing::get(handle_get_heap))
                        .route(
                            "/debug/pprof/heap/flamegraph",
                            axum::routing::get(handle_get_heap_flamegraph),
                        );

                    // run our app with hyper, listening globally on port 3000
                    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
                    axum::serve(listener, app).await.unwrap();
                });
                operator::bootstrap(params, config)
                    .await
                    .unwrap_or_else(|e| {
                        panic!("operator loop crashed: {:?}", e);
                    });
            });
        }
        OperationMode::Verifier => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(config.num_threads.unwrap_or(DEFAULT_THREAD_COUNT).into())
                .thread_stack_size(
                    config
                        .thread_stack_size
                        .unwrap_or(DEFAULT_THREAD_STACK_SIZE),
                )
                .enable_all()
                .build()
                .expect("must be able to create runtime");
            runtime.block_on(async move {
                verifier::bootstrap(params, config)
                    .await
                    .unwrap_or_else(|e| {
                        panic!("verifier loop crashed: {:?}", e);
                    });
            });
        }
    }
}

/// Reads and parses a TOML file from the given path into the given type `T`.
///
/// # Panics
///
/// 1. If the file is not readable.
/// 2. If the contents of the file cannot be deserialized into the given type `T`.
fn parse_toml<T>(path: impl AsRef<Path>) -> T
where
    T: std::fmt::Debug + DeserializeOwned,
{
    fs::read_to_string(path)
        .map(|p| {
            debug!(?p, "read file");

            let parsed = toml::from_str::<T>(&p).unwrap_or_else(|e| {
                panic!("failed to parse TOML file: {:?}", e);
            });
            debug!(?parsed, "parsed TOML file");

            parsed
        })
        .unwrap_or_else(|_| {
            panic!("failed to read TOML file");
        })
}
