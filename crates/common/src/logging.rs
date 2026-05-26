//! Provides utilities to initialize logging and OpenTelemetry tracing.

use std::env;

pub use strata_logging::{
    finalize, format_service_name, init_logging_from_config, FileLoggingConfig, LoggingInitConfig,
    MetricsLayer, OtlpExportConfig, ResourceConfig, Rotation, StdoutConfig,
};

/// Environment variable names for configuring the logger.
pub const OTLP_URL_ENVVAR: &str = "STRATA_BRIDGE_OTLP_URL";
/// Environment variable name for the service label, which is appended to the
/// service name.
pub const SVC_LABEL_ENVVAR: &str = "STRATA_BRIDGE_SVC_LABEL";
/// Extra filter directives shared by bridge binaries and tests.
pub const DEFAULT_EXTRA_FILTER_DIRECTIVES: &[&str] =
    &["sp1_core_executor=warn", "jsonrpsee_server::server=warn"];

/// Initializes logging with bridge-standard environment variables.
pub fn init_from_env(service_base_name: &str, default_log_prefix: &str) {
    let service_label = get_service_label_from_env();
    let otlp_url = get_otlp_url_from_env();

    init_logging_from_config(LoggingInitConfig {
        service_base_name,
        service_label: service_label.as_deref(),
        otlp_url: otlp_url.as_deref(),
        log_dir: None,
        log_file_prefix: None,
        json_format: None,
        default_log_prefix,
        enable_metrics_layer: false,
        extra_filter_directives: DEFAULT_EXTRA_FILTER_DIRECTIVES,
    });
}

/// Gets the OTLP URL from the standard envvar.
pub fn get_otlp_url_from_env() -> Option<String> {
    env::var(OTLP_URL_ENVVAR).ok()
}

/// Gets the service label from the standard envvar, which should be included
/// in the service name.
pub fn get_service_label_from_env() -> Option<String> {
    env::var(SVC_LABEL_ENVVAR).ok()
}

/// Computes a standard service name.
pub fn get_whoami_string(base: &str) -> String {
    format_service_name(base, get_service_label_from_env().as_deref())
}
