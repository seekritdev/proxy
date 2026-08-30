//! Context propagation and instrument access.
//!
//! Everything here is built on the OpenTelemetry **API** only, so it compiles
//! and runs with or without the `otel` feature. With no provider installed the
//! API's no-op implementations take over: `meter` hands back instruments whose
//! `add`/`record` do nothing, and the propagator extracts and injects nothing.

use opentelemetry::propagation::{Extractor, Injector};
use opentelemetry::{global, Context};

/// A meter for recording instruments. Free when metrics are not configured.
pub fn meter(name: &'static str) -> opentelemetry::metrics::Meter {
    global::meter(name)
}

/// Read-only view of inbound headers for the W3C propagator.
struct HeaderExtractor<'a>(&'a http::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Writable view of outbound headers for the W3C propagator.
struct HeaderInjector<'a>(&'a mut http::HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(key.as_bytes()),
            http::HeaderValue::from_str(&value),
        ) {
            self.0.insert(name, value);
        }
    }
}

/// Extract a caller's W3C trace context (`traceparent`/`tracestate`) from
/// inbound HTTP headers, so a span started here continues their trace instead
/// of orphaning a new one.
pub fn extract_context(headers: &http::HeaderMap) -> Context {
    global::get_text_map_propagator(|p| p.extract(&HeaderExtractor(headers)))
}

/// Inject the given trace context into outbound HTTP headers.
///
/// Matters most in `apps/proxy`, which sits in the request path: without this
/// the customer's trace stops at the proxy and restarts, detached, at the
/// upstream.
pub fn inject_context(cx: &Context, headers: &mut http::HeaderMap) {
    global::get_text_map_propagator(|p| p.inject_context(cx, &mut HeaderInjector(headers)));
}

// Exercising a round trip needs a real propagator, which lives in the SDK.
#[cfg(all(test, feature = "otel"))]
mod tests {
    use super::*;

    /// Round-trip through the real W3C propagator: whatever we inject must come
    /// back out. Guards the header plumbing (name casing, value validity)
    /// independently of whether an SDK is installed.
    #[test]
    fn injects_and_extracts_traceparent() {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );

        let mut headers = http::HeaderMap::new();
        headers.insert(
            "traceparent",
            http::HeaderValue::from_static(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            ),
        );

        let cx = extract_context(&headers);

        let mut out = http::HeaderMap::new();
        inject_context(&cx, &mut out);

        let propagated = out
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .expect("traceparent should be injected");
        assert!(
            propagated.contains("4bf92f3577b34da6a3ce929d0e0e4736"),
            "trace id must survive the round trip, got {propagated:?}"
        );
    }
}
