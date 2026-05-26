//! Strata Bridge is a bridge node for the Strata protocol.
use std::{any::type_name, fs, net::SocketAddr, path::Path, sync::Arc};

use args::OperationMode;
use clap::Parser;
use config::Config;
use constants::{DEFAULT_THREAD_COUNT, DEFAULT_THREAD_STACK_SIZE};
use metrics::{describe_gauge, gauge};
use mode::{operator, watchtower};
use serde::de::DeserializeOwned;
use strata_bridge_common::{
    logging::{self, LoggingInitConfig, init_logging_from_config},
    params::Params,
};
use strata_bridge_db::fdb::client::{FdbClient, MustDrop};
use strata_bridge_p2p_service::GossipsubScoringPreset;
use strata_metrics::{MetricsConfig as ProcessMetricsConfig, MetricsInitConfig};
use strata_tasks::TaskManager;
use tokio::runtime;
use tracing::{debug, error, info, trace};

mod args;
mod config;
mod constants;
mod mode;

/// The default glibc malloc was observed to be responsible for bad memory fragmentation during
/// deposits which led to out-of-memory issues. [`Jemalloc`] is a general purpose malloc(3)
/// implementation that emphasizes fragmentation avoidance and scalable concurrency support.
/// It reduces the fragmentation so avoids overutilizing system memory
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

/// Configures Jemalloc to support memory profiling when the feature is enabled.
/// This allows us to build flamegraphs for memory usage.
/// - `prof:true`: enables profiling for memory allocations
/// - `prof_active:true`: activates the profiling that was enabled by prev option
/// - `lg_prof_sample:19`: sampling interval of every 1 in 2^19 (~512kib) allocations
#[cfg(feature = "memory_profiling")]
#[expect(non_upper_case_globals)]
#[unsafe(export_name = "malloc_conf")]
pub static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

fn main() {
    let cli = args::Cli::parse();
    let mode_label = cli.mode.to_string();

    let config = parse_toml::<Config>(&cli.config);
    let params = parse_toml::<Params>(&cli.params);
    let network_label = params.network.to_string();
    let shutdown_timeout = config.shutdown_timeout;

    let runtime = runtime::Builder::new_multi_thread()
        .worker_threads(config.num_threads.unwrap_or(DEFAULT_THREAD_COUNT).into())
        .thread_stack_size(
            config
                .thread_stack_size
                .unwrap_or(DEFAULT_THREAD_STACK_SIZE),
        )
        .enable_all()
        .build()
        .expect("must be able to create runtime");

    let service_label = logging::get_service_label_from_env();
    let otlp_url = logging::get_otlp_url_from_env();
    let service_name = logging::format_service_name("strata-bridge", service_label.as_deref());
    let metrics_otlp_url = config.metrics.otlp_url.clone().or_else(|| otlp_url.clone());
    let metrics_exporter = metrics_exporter_label(
        metrics_otlp_url.as_deref(),
        config.metrics.prometheus_listener_addr,
    );
    let p2p_scoring_preset = p2p_scoring_preset_label(&config);
    let btc_zmq = btc_zmq_label(&config);
    let fdb_tls = enabled_label(config.db.tls.is_some());
    let metrics_config = ProcessMetricsConfig::from_exporters(
        metrics_otlp_url,
        config.metrics.prometheus_listener_addr,
    );

    init_logging_from_config(LoggingInitConfig {
        service_base_name: "strata-bridge",
        service_label: service_label.as_deref(),
        otlp_url: otlp_url.as_deref(),
        log_dir: None,
        log_file_prefix: None,
        json_format: None,
        default_log_prefix: "strata-bridge",
        extra_filter_directives: logging::DEFAULT_EXTRA_FILTER_DIRECTIVES,
    });

    let metrics_init =
        MetricsInitConfig::new(service_name.clone()).with_metrics_config(metrics_config);
    strata_metrics::init(metrics_init, runtime.handle())
        .unwrap_or_else(|err| panic!("failed to initialize process metrics: {err}"));
    emit_node_info_metric(&NodeInfoLabels {
        service: &service_name,
        mode: &mode_label,
        network: &network_label,
        version: env!("CARGO_PKG_VERSION"),
        metrics_exporter,
        p2p_scoring_preset,
        btc_zmq,
        fdb_tls,
    });

    info!(mode = %mode_label, network = %network_label, "starting bridge node");

    // Initialize FDB client
    // Must happen once per process, before spawning tasks.
    // The MustDrop guard stops the FDB network thread when dropped, so it must
    // stay in main() scope until after all tasks complete.
    // The root directory name is configured via config.fdb.root_directory (defaults to
    // "strata-bridge-v1").
    info!(root_directory = %config.db.root_directory, "initializing FoundationDB client");
    let (fdb_client, _fdb_guard): (FdbClient, MustDrop) = runtime
        .block_on(FdbClient::setup(config.db.clone()))
        .expect("should initialize FDB client");
    let fdb_client = Arc::new(fdb_client);
    debug!("FoundationDB client initialized");

    let task_manager = TaskManager::new(runtime.handle().clone());
    task_manager.start_signal_listeners();

    let executor = task_manager.create_executor();

    match cli.mode {
        OperationMode::Operator => {
            let fdb = fdb_client.clone();
            executor
                .clone()
                .spawn_critical_async("operator", async move {
                    #[cfg(feature = "memory_profiling")]
                    memory_pprof::setup_memory_profiling(3_000);
                    operator::bootstrap(params, config, fdb, executor.clone()).await
                });
        }
        OperationMode::Watchtower => {
            executor
                .clone()
                .spawn_critical_async("watchtower", async move {
                    #[cfg(feature = "memory_profiling")]
                    memory_pprof::setup_memory_profiling(3_000);
                    watchtower::bootstrap(params, config, executor.clone()).await
                });
        }
    }

    if let Err(e) = task_manager.monitor(Some(shutdown_timeout)) {
        error!(err = ?e, "bridge node crashed");
        strata_metrics::finalize();
        logging::finalize();
        panic!("bridge node crashed: {e:?}");
    }

    info!("bridge node shutdown complete");
    strata_metrics::finalize();
    logging::finalize();
}

struct NodeInfoLabels<'a> {
    service: &'a str,
    mode: &'a str,
    network: &'a str,
    version: &'a str,
    metrics_exporter: &'a str,
    p2p_scoring_preset: &'a str,
    btc_zmq: &'a str,
    fdb_tls: &'a str,
}

fn emit_node_info_metric(labels: &NodeInfoLabels<'_>) {
    describe_gauge!(
        "strata_bridge_node_info",
        "Static bridge node metadata. Labels are intentionally low-cardinality."
    );
    gauge!(
        "strata_bridge_node_info",
        "service" => labels.service.to_owned(),
        "mode" => labels.mode.to_owned(),
        "network" => labels.network.to_owned(),
        "version" => labels.version.to_owned(),
        "metrics_exporter" => labels.metrics_exporter.to_owned(),
        "p2p_scoring_preset" => labels.p2p_scoring_preset.to_owned(),
        "btc_zmq" => labels.btc_zmq.to_owned(),
        "fdb_tls" => labels.fdb_tls.to_owned(),
    )
    .set(1.0);
}

fn metrics_exporter_label(
    otlp_url: Option<&str>,
    prometheus_listener_addr: Option<SocketAddr>,
) -> &'static str {
    match (otlp_url.is_some(), prometheus_listener_addr.is_some()) {
        (false, false) => "none",
        (true, false) => "otlp",
        (false, true) => "prometheus",
        (true, true) => "otlp_prometheus",
    }
}

fn p2p_scoring_preset_label(config: &Config) -> &'static str {
    match config.p2p.gossipsub_scoring_preset.unwrap_or_default() {
        GossipsubScoringPreset::Default => "default",
        GossipsubScoringPreset::Permissive => "permissive",
    }
}

fn btc_zmq_label(config: &Config) -> &'static str {
    enabled_label(
        config.btc_zmq.hashblock_connection_string.is_some()
            || config.btc_zmq.hashtx_connection_string.is_some()
            || config.btc_zmq.rawblock_connection_string.is_some()
            || config.btc_zmq.rawtx_connection_string.is_some()
            || config.btc_zmq.sequence_connection_string.is_some(),
    )
}

fn enabled_label(enabled: bool) -> &'static str {
    if enabled { "enabled" } else { "disabled" }
}

/// Reads and parses a TOML file from the given path into the given type `T`.
///
/// # Panics
///
/// 1. If the file is not readable.
/// 2. If the contents of the file cannot be deserialized into the given type `T`.
fn parse_toml<T>(path: impl AsRef<Path>) -> T
where
    T: DeserializeOwned,
{
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read TOML file {}: {e}", path.display()));
    trace!(path = %path.display(), "read TOML file");

    let parsed = toml::from_str::<T>(&contents)
        .unwrap_or_else(|e| panic!("failed to parse TOML file {}: {e}", path.display()));
    debug!(path = %path.display(), target_type = type_name::<T>(), "parsed TOML file");

    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_exporter_label_reports_effective_exporters() {
        let prometheus_addr = "127.0.0.1:9615".parse().unwrap();

        assert_eq!(metrics_exporter_label(None, None), "none");
        assert_eq!(
            metrics_exporter_label(Some("http://otel:4317"), None),
            "otlp"
        );
        assert_eq!(
            metrics_exporter_label(None, Some(prometheus_addr)),
            "prometheus"
        );
        assert_eq!(
            metrics_exporter_label(Some("http://otel:4317"), Some(prometheus_addr)),
            "otlp_prometheus"
        );
    }

    #[test]
    fn enabled_label_uses_bounded_values() {
        assert_eq!(enabled_label(true), "enabled");
        assert_eq!(enabled_label(false), "disabled");
    }
}
