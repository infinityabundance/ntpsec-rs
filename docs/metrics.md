# Prometheus Metrics

The `ntpsec-rs` daemon can expose runtime metrics in Prometheus text format
via an optional HTTP endpoint.  Enable it with `--metrics-port <PORT>`.

## Usage

```sh
ntpd-rs --metrics-port 9090
```

Then scrape from Prometheus or manually:

```sh
curl http://localhost:9090/metrics
```

## Exposed Metrics

| Metric name                     | Type    | Description                                      |
|---------------------------------|---------|--------------------------------------------------|
| `ntp_stratum`                   | gauge   | Current stratum of the system peer               |
| `ntp_offset_seconds`            | gauge   | Clock offset from system peer (seconds)          |
| `ntp_frequency_ppm`             | gauge   | Local clock frequency error (PPM)               |
| `ntp_jitter_seconds`            | gauge   | System jitter (seconds)                          |
| `ntp_root_delay_seconds`        | gauge   | Root delay (seconds)                             |
| `ntp_root_dispersion_seconds`   | gauge   | Root dispersion (seconds)                        |
| `ntp_leap_indicator`            | gauge   | Leap indicator: 0=OK, 1=add, 2=del, 3=alarm     |
| `ntp_peer_count`                | gauge   | Number of configured peers                       |
| `ntp_peers_reachable`           | gauge   | Number of reachable peers                        |
| `ntp_poll_interval_seconds`     | gauge   | Current poll interval (seconds, 2^poll_exponent) |
| `ntp_adjustments_total`         | counter | Total clock adjustments performed                |
| `ntp_uptime_seconds`            | gauge   | Daemon uptime (seconds)                          |

All metrics carry the label `source="ntpsec-rs"`.

## Implementation

The metrics endpoint is served by the `ntpsec-rs-metrics` crate, which uses
`std::net::TcpListener` directly — no external HTTP dependencies.  The daemon
shares its engine state via `Arc<Mutex<DaemonEngine>>`, and the metrics handler
briefly locks the engine to snapshot the current values.

The HTTP server runs in a dedicated background thread named `ntp-metrics` and
handles one connection at a time.  Only the `/` and `/metrics` paths are
served; everything else returns 404.

## Prometheus Configuration

Add a scrape target to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'ntpsec-rs'
    static_configs:
      - targets: ['localhost:9090']
```
