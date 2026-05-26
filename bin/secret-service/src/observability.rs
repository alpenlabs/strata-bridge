//! Observability initialization for the secret-service binary.

use std::net::SocketAddr;

use bitcoin::Network;
use metrics::{describe_gauge, gauge};
use strata_bridge_common::logging::{self, init_logging_from_config, LoggingInitConfig};
use strata_metrics::{MetricsConfig as ProcessMetricsConfig, MetricsInitConfig};
use tokio::runtime::Handle;

use crate::config::{MetricsConfig, TlsConfig};

const SERVICE_BASE_NAME: &str = "secret-service";

pub(crate) fn init(
    config: &MetricsConfig,
    tls: &TlsConfig,
    network: Network,
    dev_mode: bool,
    runtime_handle: &Handle,
) {
    let service_label = logging::get_service_label_from_env();
    let otlp_url = logging::get_otlp_url_from_env();
    let service_name = logging::format_service_name(SERVICE_BASE_NAME, service_label.as_deref());
    let network = network.to_string();
    let metrics_otlp_url = config.otlp_url.clone().or_else(|| otlp_url.clone());
    let metrics_exporter =
        metrics_exporter_label(metrics_otlp_url.as_deref(), config.prometheus_listener_addr);
    let metrics_config =
        ProcessMetricsConfig::from_exporters(metrics_otlp_url, config.prometheus_listener_addr);

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
        network: &network,
        version: env!("CARGO_PKG_VERSION"),
        metrics_exporter,
        tls_client_auth: enabled_label(tls.ca.is_some()),
        dev_mode: enabled_label(dev_mode),
    });
}

pub(crate) fn finalize() {
    strata_metrics::finalize();
    logging::finalize();
}

struct NodeInfoLabels<'a> {
    service: &'a str,
    network: &'a str,
    version: &'a str,
    metrics_exporter: &'a str,
    tls_client_auth: &'a str,
    dev_mode: &'a str,
}

fn emit_node_info_metric(labels: &NodeInfoLabels<'_>) {
    describe_gauge!(
        "strata_secret_service_node_info",
        "Static secret-service metadata. Labels are intentionally low-cardinality."
    );
    gauge!(
        "strata_secret_service_node_info",
        "service" => labels.service.to_owned(),
        "network" => labels.network.to_owned(),
        "version" => labels.version.to_owned(),
        "metrics_exporter" => labels.metrics_exporter.to_owned(),
        "tls_client_auth" => labels.tls_client_auth.to_owned(),
        "dev_mode" => labels.dev_mode.to_owned(),
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

const fn enabled_label(enabled: bool) -> &'static str {
    if enabled {
        "enabled"
    } else {
        "disabled"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_exporter_label_reports_effective_exporters() {
        let prometheus_addr = "127.0.0.1:9616".parse().unwrap();

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
