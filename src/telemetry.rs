//! Instruments for the proxy.
//!
//! The proxy is a *security control* as much as a data path, so the signals are
//! chosen to answer security questions first: how often is a placeholder
//! denied, and toward which upstream? A rising `outcome="denied"` rate is a
//! workload trying to reach a secret it has no claim to.
//!
//! Attribute cardinality is deliberately bounded — upstream hosts and route
//! prefixes come from the config file, and request paths (which are unbounded
//! and can carry user data) are never recorded as metric attributes.
//!
//! Secret **names** appear; secret **values** never do. `tests/telemetry.rs`
//! enforces that against a real substituted request.

use seekrit_telemetry::opentelemetry::metrics::{Counter, Histogram};
use seekrit_telemetry::opentelemetry::KeyValue;

/// Which listener handled a request — the two planes share these instruments.
pub const PLANE_REVERSE: &str = "reverse";
pub const PLANE_FORWARD: &str = "forward";

pub struct Metrics {
    requests: Counter<u64>,
    injections: Counter<u64>,
    upstream_duration: Histogram<f64>,
}

impl Metrics {
    pub fn new() -> Self {
        let meter = seekrit_telemetry::meter("seekrit-proxy");
        Metrics {
            requests: meter
                .u64_counter("seekrit.proxy.requests")
                .with_description("Requests handled, by plane and outcome.")
                .build(),
            injections: meter
                .u64_counter("seekrit.proxy.injections")
                .with_description("Secret substitutions performed, by upstream.")
                .build(),
            upstream_duration: meter
                .f64_histogram("seekrit.proxy.upstream_duration")
                .with_unit("ms")
                .with_description("Time spent awaiting the upstream response.")
                .build(),
        }
    }

    /// One handled request. `outcome` is a fixed set: `forwarded`, `denied`,
    /// `no_route`, `bad_request`, `upstream_error`.
    pub fn record_request(&self, plane: &'static str, outcome: &'static str) {
        self.requests.add(
            1,
            &[
                KeyValue::new("plane", plane),
                KeyValue::new("outcome", outcome),
            ],
        );
    }

    /// `count` secrets were substituted into a request bound for `upstream`.
    pub fn record_injections(&self, upstream: &str, count: usize) {
        if count == 0 {
            return;
        }
        self.injections.add(
            count as u64,
            &[KeyValue::new("upstream", upstream.to_string())],
        );
    }

    pub fn record_upstream_duration(&self, upstream: &str, millis: f64) {
        self.upstream_duration
            .record(millis, &[KeyValue::new("upstream", upstream.to_string())]);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
