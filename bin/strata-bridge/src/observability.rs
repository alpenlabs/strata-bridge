//! Observability initialization for the bridge binary.

use std::net::SocketAddr;

use metrics::{describe_gauge, gauge};
use strata_bridge_common::logging::{self, LoggingInitConfig, init_logging_from_config};
use strata_bridge_p2p_service::GossipsubScoringPreset;
use strata_metrics::{MetricsConfig as ProcessMetricsConfig, MetricsInitConfig};
use tokio::runtime::Handle;

use crate::config::Config;

const SERVICE_BASE_NAME: &str = "strata-bridge";

pub(crate) fn init(config: &Config, mode: &str, network: &str, runtime_handle: &Handle) {
    let service_label = logging::get_service_label_from_env();
    let otlp_url = logging::get_otlp_url_from_env();
    let service_name = logging::format_service_name(SERVICE_BASE_NAME, service_label.as_deref());
    let metrics_otlp_url = config.metrics.otlp_url.clone().or_else(|| otlp_url.clone());
    let metrics_exporter = metrics_exporter_label(
        metrics_otlp_url.as_deref(),
        config.metrics.prometheus_listener_addr,
    );
    let p2p_scoring_preset = p2p_scoring_preset_label(config);
    let btc_zmq = btc_zmq_label(config);
    let fdb_tls = enabled_label(config.db.tls.is_some());
    let metrics_config = ProcessMetricsConfig::from_exporters(
        metrics_otlp_url,
        config.metrics.prometheus_listener_addr,
    );

    init_logging_from_config(LoggingInitConfig {
        service_base_name: SERVICE_BASE_NAME,
        service_label: service_label.as_deref(),
        otlp_url: otlp_url.as_deref(),
        log_dir: None,
        log_file_prefix: None,
        json_format: None,
        default_log_prefix: SERVICE_BASE_NAME,
        extra_filter_directives: logging::DEFAULT_EXTRA_FILTER_DIRECTIVES,
    });

    let metrics_init =
        MetricsInitConfig::new(service_name.clone()).with_metrics_config(metrics_config);
    strata_metrics::init(metrics_init, runtime_handle)
        .unwrap_or_else(|err| panic!("failed to initialize process metrics: {err}"));
    emit_node_info_metric(&NodeInfoLabels {
        service: &service_name,
        mode,
        network,
        version: env!("CARGO_PKG_VERSION"),
        metrics_exporter,
        p2p_scoring_preset,
        btc_zmq,
        fdb_tls,
    });
}

pub(crate) fn finalize() {
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

const fn metrics_exporter_label(
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

const fn btc_zmq_label(config: &Config) -> &'static str {
    enabled_label(
        config.btc_zmq.hashblock_connection_string.is_some()
            || config.btc_zmq.hashtx_connection_string.is_some()
            || config.btc_zmq.rawblock_connection_string.is_some()
            || config.btc_zmq.rawtx_connection_string.is_some()
            || config.btc_zmq.sequence_connection_string.is_some(),
    )
}

const fn enabled_label(enabled: bool) -> &'static str {
    if enabled { "enabled" } else { "disabled" }
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
