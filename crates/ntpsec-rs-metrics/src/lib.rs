// =============================================================================
// ntpsec-rs-metrics — Prometheus metrics endpoint for the NTPsec daemon
//
// Exposes a /metrics HTTP endpoint (Prometheus text format) over a raw
// std::net::TcpListener — zero external HTTP dependencies.
// =============================================================================

use ntpsec_rs_core::DaemonEngine;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// Start a minimal HTTP server on the given port that serves Prometheus metrics
/// from the shared daemon engine state.
///
/// Returns a `JoinHandle` so the caller can join the thread if desired (e.g.
/// during shutdown).
pub fn start_metrics_server(
    engine: Arc<Mutex<DaemonEngine>>,
    port: u16,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("ntp-metrics".into())
        .spawn(move || {
            let addr = format!("[::]:{port}");
            let listener = match TcpListener::bind(&addr) {
                Ok(l) => {
                    tracing::info!("Metrics server listening on {addr}");
                    l
                }
                Err(e) => {
                    tracing::error!("Cannot bind metrics server to {addr}: {e}");
                    return;
                }
            };

            // Accept connections in a loop — one at a time, no thread pool needed
            // for a lightweight metrics endpoint.
            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        handle_connection(&mut stream, &engine);
                    }
                    Err(e) => {
                        tracing::debug!("Metrics server accept error: {e}");
                    }
                }
            }
        })
        .expect("metrics server thread should spawn")
}

/// Handle a single HTTP connection: parse the request line, produce a response.
fn handle_connection(stream: &mut std::net::TcpStream, engine: &Arc<Mutex<DaemonEngine>>) {
    use std::io::BufRead;

    // Read the request line (e.g. "GET /metrics HTTP/1.1") using a buffered
    // wrapper around a clone of the stream (we still need the original for
    // the response write).
    let mut reader = match stream.try_clone() {
        Ok(clone) => std::io::BufReader::new(clone),
        Err(e) => {
            tracing::warn!("Metrics connection try_clone failed: {e}");
            return;
        }
    };
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        let _ = write_response(stream, 400, "Bad Request\n");
        return;
    }

    // Parse the request path from "GET /path HTTP/1.1"
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    match path {
        "/" | "/metrics" => {
            let body = format_metrics(engine);
            write_response(stream, 200, &body);
        }
        _ => {
            write_response(stream, 404, "Not Found\n");
        }
    }
}

/// Write an HTTP response with the given status code and body.
fn write_response(stream: &mut std::net::TcpStream, status: u16, body: &str) {
    use std::io::Write;

    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    };

    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );

    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

/// Build the Prometheus-format metrics text from the daemon engine state.
fn format_metrics(engine: &Arc<Mutex<DaemonEngine>>) -> String {
    // Extract all field values while holding the lock, then release it
    // before performing the (potentially expensive) string formatting.
    let (
        stratum,
        sys_offset,
        frequency,
        jitter,
        root_delay,
        root_dispersion,
        leap_val,
        peer_count,
        reachable,
        poll_seconds,
        adjustments,
        uptime,
    ) = {
        let guard = match engine.lock() {
            Ok(g) => g,
            Err(_) => return "# ERROR: engine lock poisoned\n".to_string(),
        };

        let sys = &guard.system;
        let lf = &guard.loop_filter;

        // ── Peer reachability count ──────────────────────────────────────
        let reachable = guard.peers.iter().filter(|p| p.is_reachable()).count() as u32;

        // ── Poll interval in seconds (2^poll_exponent) ───────────────────
        let poll_seconds = if sys.poll > 0 { 1u64 << sys.poll } else { 0 };

        // ── Leap indicator as numeric value ──────────────────────────────
        let leap_val = match sys.leap {
            ntpsec_rs_core::ntp_types::LeapIndicator::NoWarning => 0,
            ntpsec_rs_core::ntp_types::LeapIndicator::AddLeapSecond => 1,
            ntpsec_rs_core::ntp_types::LeapIndicator::RemoveLeapSecond => 2,
            ntpsec_rs_core::ntp_types::LeapIndicator::Alarm => 3,
        };

        (
            sys.stratum,
            sys.sys_offset,
            lf.frequency_ppm(),
            lf.jitter,
            sys.root_delay,
            sys.root_dispersion,
            leap_val,
            sys.peer_count,
            reachable,
            poll_seconds,
            lf.update_count, // adjustments_total
            sys.uptime_secs, // uptime_seconds
        )
    };
    // ── Lock released ──────────────────────────────────────────────────

    // Build the output — keep the format stable for automated scraping.
    format!(
        concat!(
            "# HELP ntp_stratum Current stratum of the system peer\n",
            "# TYPE ntp_stratum gauge\n",
            "ntp_stratum{{source=\"ntpsec-rs\"}} {}\n",
            "\n",
            "# HELP ntp_offset_seconds Clock offset from system peer\n",
            "# TYPE ntp_offset_seconds gauge\n",
            "ntp_offset_seconds{{source=\"ntpsec-rs\"}} {}\n",
            "\n",
            "# HELP ntp_frequency_ppm Local clock frequency error\n",
            "# TYPE ntp_frequency_ppm gauge\n",
            "ntp_frequency_ppm{{source=\"ntpsec-rs\"}} {}\n",
            "\n",
            "# HELP ntp_jitter_seconds System jitter\n",
            "# TYPE ntp_jitter_seconds gauge\n",
            "ntp_jitter_seconds{{source=\"ntpsec-rs\"}} {}\n",
            "\n",
            "# HELP ntp_root_delay_seconds Root delay\n",
            "# TYPE ntp_root_delay_seconds gauge\n",
            "ntp_root_delay_seconds{{source=\"ntpsec-rs\"}} {}\n",
            "\n",
            "# HELP ntp_root_dispersion_seconds Root dispersion\n",
            "# TYPE ntp_root_dispersion_seconds gauge\n",
            "ntp_root_dispersion_seconds{{source=\"ntpsec-rs\"}} {}\n",
            "\n",
            "# HELP ntp_leap_indicator Leap indicator (0=OK, 1=add, 2=del, 3=alarm)\n",
            "# TYPE ntp_leap_indicator gauge\n",
            "ntp_leap_indicator{{source=\"ntpsec-rs\"}} {}\n",
            "\n",
            "# HELP ntp_peer_count Number of configured peers\n",
            "# TYPE ntp_peer_count gauge\n",
            "ntp_peer_count{{source=\"ntpsec-rs\"}} {}\n",
            "\n",
            "# HELP ntp_peers_reachable Number of reachable peers\n",
            "# TYPE ntp_peers_reachable gauge\n",
            "ntp_peers_reachable{{source=\"ntpsec-rs\"}} {}\n",
            "\n",
            "# HELP ntp_poll_interval_seconds Current poll interval\n",
            "# TYPE ntp_poll_interval_seconds gauge\n",
            "ntp_poll_interval_seconds{{source=\"ntpsec-rs\"}} {}\n",
            "\n",
            "# HELP ntp_adjustments_total Total clock adjustments\n",
            "# TYPE ntp_adjustments_total counter\n",
            "ntp_adjustments_total{{source=\"ntpsec-rs\"}} {}\n",
            "\n",
            "# HELP ntp_uptime_seconds Daemon uptime\n",
            "# TYPE ntp_uptime_seconds gauge\n",
            "ntp_uptime_seconds{{source=\"ntpsec-rs\"}} {}\n",
        ),
        stratum,
        sys_offset,
        frequency,
        jitter,
        root_delay,
        root_dispersion,
        leap_val,
        peer_count,
        reachable,
        poll_seconds,
        adjustments,
        uptime,
    )
}
