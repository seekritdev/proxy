//! Test harness for asserting what telemetry a service actually emits.
//!
//! Behind the `testing` feature so it never ships in a release binary. Each
//! self-hosted service uses it for the same check: run a real request through
//! the real handler with a sentinel secret value, then assert that value
//! appears nowhere in the exported spans.
//!
//! That test is the enforcement mechanism behind the zero-knowledge note in the
//! crate docs. Reviewing instrumentation by eye does not scale — a `%value` or a
//! `?request` slipped into a span is easy to miss in a diff and impossible to
//! retract once it is in someone's observability vendor.

use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use tracing_subscriber::layer::SubscriberExt;

/// A scoped span collector. Spans recorded on **this thread** while the guard
/// is alive are captured in memory instead of being exported.
pub struct Capture {
    exporter: InMemorySpanExporter,
    provider: SdkTracerProvider,
    _guard: tracing::subscriber::DefaultGuard,
}

impl Capture {
    /// Install a thread-local subscriber that captures spans.
    ///
    /// Thread-local (`set_default`) rather than global, so tests running in
    /// parallel don't fight over the one global subscriber.
    ///
    /// **Consequence for async tests:** only spans opened on *this* thread are
    /// captured. `#[tokio::test]` defaults to a current-thread runtime, so
    /// tasks spawned by `axum::serve` land on the test thread and are captured;
    /// switching a test to `flavor = "multi_thread"` would silently capture
    /// nothing. Always pair `assert_absent` with a positive assertion that some
    /// expected field *was* recorded, so an empty capture fails loudly instead
    /// of passing vacuously.
    pub fn install() -> Self {
        use opentelemetry::trace::TracerProvider as _;

        let exporter = InMemorySpanExporter::default();
        // Simple, not batch: the test needs spans to be exported the moment they
        // close, without waiting on a background thread's schedule.
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();

        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));
        let guard = tracing::subscriber::set_default(subscriber);

        Capture {
            exporter,
            provider,
            _guard: guard,
        }
    }

    /// All spans closed so far.
    pub fn spans(&self) -> Vec<SpanData> {
        let _ = self.provider.force_flush();
        self.exporter.get_finished_spans().unwrap_or_default()
    }

    /// Every string that made it into a span: names plus attribute keys and
    /// values, flattened. This is the haystack a leak test searches.
    pub fn emitted_strings(&self) -> Vec<String> {
        let mut out = Vec::new();
        for span in self.spans() {
            out.push(span.name.to_string());
            for kv in span.attributes.iter() {
                out.push(kv.key.to_string());
                out.push(kv.value.to_string());
            }
            for event in span.events.iter() {
                out.push(event.name.to_string());
                for kv in event.attributes.iter() {
                    out.push(kv.key.to_string());
                    out.push(kv.value.to_string());
                }
            }
        }
        out
    }

    /// Assert none of `needles` appears anywhere in the exported telemetry.
    ///
    /// Panics with the offending value and the span text that carried it, since
    /// "a secret leaked" is worth an obvious failure message.
    pub fn assert_absent(&self, needles: &[&str]) {
        let emitted = self.emitted_strings();
        for needle in needles {
            for text in &emitted {
                assert!(
                    !text.contains(needle),
                    "secret material leaked into telemetry: {needle:?} found in {text:?}"
                );
            }
        }
    }
}
