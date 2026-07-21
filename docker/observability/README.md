# Local bridge observability

This overlay adds a local bridge control room without changing the normal Compose stack:

- Prometheus scrapes all three bridge and secret-service nodes every five seconds and evaluates
  bridge-specific alert rules.
- Grafana provisions the Prometheus and Loki data sources plus the `Bridge control room`
  dashboard.
- Grafana Alloy discovers the bridge-related Docker containers and forwards their logs to Loki.
- Loki retains local logs for seven days. Prometheus retains local metrics for 30 days.

All HTTP ports bind to `127.0.0.1`. Grafana uses anonymous Viewer access for local development;
do not expose this overlay on a shared or public host.

## Start

From the repository root, start only the monitoring services:

```sh
docker compose -f compose.yml -f docker/observability/compose.yml \
  up -d prometheus loki alloy grafana
```

The bridge targets will show as down until the corresponding bridge services are running. Start
the complete bridge and monitoring stack with:

```sh
docker compose -f compose.yml -f docker/observability/compose.yml up -d
```

The full stack still requires the TLS material, seeds, bridge parameters, and `.env` values
documented in [`docker/README.md`](../README.md).

## Open

- Bridge control room: <http://localhost:3001/d/strata-bridge-control-room/bridge-control-room>
- Prometheus targets: <http://localhost:9090/targets>
- Prometheus alerts: <http://localhost:9090/alerts>
- Alloy component graph: <http://localhost:12345/graph>
- Loki readiness: <http://localhost:3100/ready>

The dashboard answers fleet-health and pipeline-stage questions. It intentionally keeps object
identifiers out of Prometheus labels; use the log filters for short-term deposit/transaction
drill-down. A durable months-long per-deposit timeline still requires the FoundationDB lifecycle
index tracked by STR-3598.

## Validate and troubleshoot

Validate the merged Compose model before startup:

```sh
docker compose -f compose.yml -f docker/observability/compose.yml config --quiet
```

Inspect service health and startup errors:

```sh
docker compose -f compose.yml -f docker/observability/compose.yml \
  ps prometheus loki alloy grafana
docker compose -f compose.yml -f docker/observability/compose.yml \
  logs --tail=200 prometheus loki alloy grafana
```

Prometheus deliberately uses Docker service names (`bridge-1:9615` through `bridge-3:9615` and
the corresponding secret-service endpoints). Running only the monitoring services therefore
produces expected DNS/scrape errors for those six targets, while the four observability targets
must remain up.

Stop the monitoring services without deleting their retained data:

```sh
docker compose -f compose.yml -f docker/observability/compose.yml \
  stop prometheus loki alloy grafana
```

## Metric contract

The dashboard consumes the stable `strata_bridge_*` metrics described and emitted by
`crates/orchestrator/src/observability.rs`. Labels are bounded enums such as event kind,
state-machine kind/state, duty kind, result, error class, and operator scrape identity. Deposit
indices, graph indices, txids, pubkeys, peer IDs, outpoints, message IDs, and raw errors belong in
structured logs or spans, never metric labels.

### Histograms are exported as summaries

The process's Prometheus exporter (`strata-metrics` → `metrics-exporter-prometheus`) is built
without bucket configuration, so every `histogram!` renders as a Prometheus **summary**: rolling
exporter-side quantile gauges (`quantile="0.5|0.9|0.95|0.99|..."`) plus `_sum`/`_count`. No
`_bucket` series exist, `histogram_quantile()` matches nothing, and quantiles cannot be
aggregated across operators or label combinations. The latency panels and the latency alert
therefore consume the per-operator `quantile="0.95"` series directly. Cross-operator
percentiles require bucket support in `strata-common`'s Prometheus recorder; until that lands,
treat every p95 panel as per-operator evidence only. `_sum`/`_count` (rates and averages) are
unaffected.
