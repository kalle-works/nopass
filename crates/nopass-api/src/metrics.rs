//! Prometheus metrics, served on a separate internal port.
//!
//! The listener is not part of the public router, so the ingress can never
//! route to it; in the cluster a NetworkPolicy lets only Prometheus reach it.
//!
//! `NOPASS_METRICS_PORT` picks the port (default 9100); `0` turns the
//! listener off. The registry itself is always live, so counters can be
//! incremented from anywhere without checking whether the listener runs.

use std::{net::SocketAddr, sync::LazyLock, time::Instant};

use axum::{
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
    routing::get,
    Router,
};
use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts, Registry,
    TextEncoder,
};

const DEFAULT_PORT: u16 = 9100;

struct Metrics {
    registry: Registry,
    http_requests: IntCounterVec,
    http_duration: HistogramVec,
    login_failures: IntCounter,
}

static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let registry = Registry::new();
    let http_requests = IntCounterVec::new(
        Opts::new("nopass_http_requests_total", "HTTP requests served"),
        &["method", "route", "status"],
    )
    .expect("valid metric");
    let http_duration = HistogramVec::new(
        HistogramOpts::new(
            "nopass_http_request_duration_seconds",
            "HTTP request latency",
        )
        .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        &["method", "route"],
    )
    .expect("valid metric");
    let login_failures = IntCounter::new(
        "nopass_login_failures_total",
        "Login attempts that failed authentication",
    )
    .expect("valid metric");

    registry.register(Box::new(http_requests.clone())).expect("register");
    registry.register(Box::new(http_duration.clone())).expect("register");
    registry.register(Box::new(login_failures.clone())).expect("register");

    Metrics { registry, http_requests, http_duration, login_failures }
});

/// Counts one failed login. Call it wherever a login attempt is rejected for
/// bad credentials (not for malformed requests or rate limiting).
pub fn record_login_failure() {
    METRICS.login_failures.inc();
}

/// Middleware recording request count and latency per matched route. The
/// route template (`/v1/vaults/{vault_id}/items`), not the raw path, is the
/// label, so ids cannot blow up the series count.
pub async fn track_http(req: Request, next: Next) -> Response {
    let method = req.method().to_string();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());
    let start = Instant::now();

    let response = next.run(req).await;

    let status = response.status().as_u16().to_string();
    METRICS
        .http_requests
        .with_label_values(&[&method, &route, &status])
        .inc();
    let duration: Histogram = METRICS.http_duration.with_label_values(&[&method, &route]);
    duration.observe(start.elapsed().as_secs_f64());
    response
}

/// The metrics in Prometheus text exposition format.
pub fn render() -> String {
    let mut buf = Vec::new();
    TextEncoder::new()
        .encode(&METRICS.registry.gather(), &mut buf)
        .expect("text encoding cannot fail");
    String::from_utf8(buf).expect("text exposition is UTF-8")
}

/// Starts the metrics listener in the background. A failure to bind is logged
/// and does not stop the API: losing metrics must not take logins down.
pub fn spawn_server() {
    let port = match std::env::var("NOPASS_METRICS_PORT") {
        Ok(v) => match v.parse::<u16>() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("NOPASS_METRICS_PORT '{v}' is not a port, metrics listener disabled");
                return;
            }
        },
        Err(_) => DEFAULT_PORT,
    };
    if port == 0 {
        return;
    }
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tokio::spawn(async move {
        let app = Router::new().route("/metrics", get(|| async { render() }));
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                tracing::info!("metrics listening on {addr}");
                if let Err(e) = axum::serve(listener, app).await {
                    tracing::error!("metrics listener stopped: {e}");
                }
            }
            Err(e) => tracing::error!("cannot bind metrics listener on {addr}: {e}"),
        }
    });
}
