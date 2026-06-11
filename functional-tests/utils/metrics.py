from urllib.request import urlopen

DEFAULT_METRICS_SCRAPE_TIMEOUT_SECS = 2


def scrape_prometheus_metrics(
    metrics_url: str,
    timeout: int = DEFAULT_METRICS_SCRAPE_TIMEOUT_SECS,
) -> str:
    """
    Read Prometheus text exposition from ``{metrics_url}/metrics``.

    Input:
        ``metrics_url`` is the service metrics base URL, for example
        ``http://127.0.0.1:12501``.

    Output:
        Raw Prometheus text exposition, with lines such as
        ``metric_name{label="value"} 3``.
    """
    with urlopen(f"{metrics_url}/metrics", timeout=timeout) as response:
        return response.read().decode()


def sum_prometheus_metric_samples(
    metrics_text: str,
    metric_name: str,
    *,
    include_counter_total: bool = True,
) -> float:
    """
    Sum all samples matching a metric name in Prometheus text exposition.

    Input:
        ``metrics_text`` is Prometheus text exposition. Matching sample lines may
        be unlabeled, like ``metric_name 1``, or labeled, like
        ``metric_name{operator="0"} 2``. Comment and metadata lines beginning
        with ``#`` are ignored.

    Output:
        Floating-point sum of every matching sample value, ignoring labels. When
        ``include_counter_total`` is true, ``metric_name_total`` is also matched.
    """
    metric_names = {metric_name}
    if include_counter_total:
        metric_names.add(f"{metric_name}_total")

    total = 0.0
    for line in metrics_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        sample_name = parts[0].split("{", 1)[0]
        if sample_name in metric_names:
            total += float(parts[1])

    return total


def read_prometheus_metric_sum(
    metrics_url: str,
    metric_name: str,
    *,
    timeout: int = DEFAULT_METRICS_SCRAPE_TIMEOUT_SECS,
    include_counter_total: bool = True,
) -> float:
    """
    Scrape a service metrics endpoint and sum samples for one metric.

    Input:
        ``metrics_url`` is the service metrics base URL, and ``metric_name`` is
        the Prometheus metric name without labels, for example
        ``strata_bridge_counterproof_generation_attempts``.

    Output:
        Floating-point sum of all matching samples from ``{metrics_url}/metrics``.
    """
    return sum_prometheus_metric_samples(
        scrape_prometheus_metrics(metrics_url, timeout=timeout),
        metric_name,
        include_counter_total=include_counter_total,
    )
