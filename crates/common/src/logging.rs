//! Provides utilities to initialize logging and OpenTelemetry tracing.
use std::env;

use opentelemetry::{trace::TracerProvider, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use tracing::*;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

/// Environment variable names for configuring the logger.
pub const OTLP_URL_ENVVAR: &str = "STRATA_BRIDGE_OTLP_URL";
/// Environment variable name for the service label, which is appended to the
/// whoami string.
pub const SVC_LABEL_ENVVAR: &str = "STRATA_BRIDGE_SVC_LABEL";

/// Configuration for the logger.
#[derive(Debug, Clone)]
pub struct LoggerConfig {
    /// The whoami string, which is used to identify the service in logs.
    whoami: String,

    /// The OpenTelemetry URL for exporting traces.
    otel_url: Option<String>,
}

impl LoggerConfig {
    /// Creates a new empty instance with whoami set.
    pub const fn new(whoami: String) -> Self {
        Self {
            whoami,
            otel_url: None,
        }
    }

    /// Creates a new instance with the whoami string set to the provided
    /// string.
    pub fn with_base_name(s: &str) -> Self {
        Self::new(get_whoami_string(s))
    }

    /// Sets the opentelemetry URL to the provided string.
    pub fn set_otlp_url(&mut self, url: String) {
        self.otel_url = Some(url);
    }
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self::with_base_name("(strata-bridge)")
    }
}

/// Initializes the logging subsystem with the provided config.
pub fn init(config: LoggerConfig) {
    let filt = tracing_subscriber::EnvFilter::from_default_env();

    // TODO switch to using subscribers everywhere instead of layers
    //let mut loggers: Vec<Box<dyn tracing::Subscriber + 'static>> = Vec::new();

    let log_file = std::env::var("LOG_FILE").is_ok_and(|v| v == "1");
    let log_line_num = std::env::var("LOG_LINE_NUM").is_ok_and(|v| v == "1");

    // Stdout logging.
    let stdout_sub = tracing_subscriber::fmt::layer()
        .compact()
        .event_format(
            tracing_subscriber::fmt::format()
                .with_file(log_file)
                .with_line_number(log_line_num),
        )
        .with_filter(filt);

    // OpenTelemetry output.
    if let Some(otel_url) = &config.otel_url {
        let resource = Resource::builder()
            .with_attribute(KeyValue::new("service.name", config.whoami.clone()))
            .build();

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(otel_url)
            .build()
            .expect("must be able to initialize exporter");

        let tp = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_resource(resource)
            .with_batch_exporter(exporter)
            .build();

        let tracer = tp.tracer("strata-bridge");

        let otel_sub = tracing_opentelemetry::layer().with_tracer(tracer);

        tracing_subscriber::registry()
            .with(stdout_sub)
            .with(otel_sub)
            .init();
    } else {
        tracing_subscriber::registry().with(stdout_sub).init();
    }

    info!(whoami = %config.whoami, "logging started");
}

/// Gets the OTLP URL from the standard envvar.
pub fn get_otlp_url_from_env() -> Option<String> {
    env::var(OTLP_URL_ENVVAR).ok()
}

/// Gets the service label from the standard envvar, which should be included
/// in the whoami string.
pub fn get_service_label_from_env() -> Option<String> {
    env::var(SVC_LABEL_ENVVAR).ok()
}

/// Computes a standard whoami string.
pub fn get_whoami_string(base: &str) -> String {
    match get_service_label_from_env() {
        Some(label) => format!("{base}%{label}"),
        // Clippy is mad at me about this being `format!`.
        None => base.to_owned(),
    }
}
