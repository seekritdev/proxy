//! The `otel`-enabled implementation. See the crate docs for the contract; the
//! surface here is mirrored by the no-op module in `lib.rs`.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, Context, KeyValue};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::WithHttpConfig;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

use crate::client::BlockingClient;

/// Live providers. Hold this for the process lifetime and [`Telemetry::shutdown`]
/// before exit — dropping it is not enough to guarantee a final flush, and in
/// `seekrit-run` nothing is dropped at all (see below).
pub struct Telemetry {
    tracer: Option<SdkTracerProvider>,
    meter: Option<SdkMeterProvider>,
    logger: Option<SdkLoggerProvider>,
}

impl Telemetry {
    /// Whether anything is actually being exported.
    pub fn active(&self) -> bool {
        self.tracer.is_some() || self.meter.is_some() || self.logger.is_some()
    }

    /// Flush pending telemetry and stop the exporter threads.
    ///
    /// **`seekrit-run` must call this before `execvp`.** `exec` replaces the
    /// process image in place: no destructors run, no atexit handlers fire, and
    /// any batched span still sitting in the processor is lost. Every other
    /// service calls it on the normal shutdown path.
    pub fn shutdown(self) {
        // Order matters only in that all three should get a chance to flush even
        // if an earlier one errors — hence no `?`.
        if let Some(t) = &self.tracer {
            if let Err(e) = t.shutdown() {
                tracing::debug!("tracer shutdown: {e}");
            }
        }
        if let Some(m) = &self.meter {
            if let Err(e) = m.shutdown() {
                tracing::debug!("meter shutdown: {e}");
            }
        }
        if let Some(l) = &self.logger {
            if let Err(e) = l.shutdown() {
                tracing::debug!("logger shutdown: {e}");
            }
        }
    }
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.trim().is_empty())
}

/// `OTEL_SDK_DISABLED=true` is the spec's global kill switch.
fn sdk_disabled() -> bool {
    env_nonempty("OTEL_SDK_DISABLED")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Is any OTLP endpoint configured? The generic variable enables all three
/// signals; a per-signal variable enables just that one.
///
/// We check rather than letting the SDK fall back to its `localhost:4318`
/// default, so an unconfigured service exports nothing instead of retrying a
/// port that will never answer. See the crate docs.
fn endpoint_configured(signal: &str) -> bool {
    env_nonempty("OTEL_EXPORTER_OTLP_ENDPOINT").is_some()
        || env_nonempty(&format!("OTEL_EXPORTER_OTLP_{signal}_ENDPOINT")).is_some()
}

/// Honour `OTEL_{TRACES,METRICS,LOGS}_EXPORTER=none` to turn one signal off
/// while leaving the others on. Anything else (including unset) means "export",
/// since we only get here with an endpoint configured.
fn signal_enabled(signal: &str) -> bool {
    match env_nonempty(&format!("OTEL_{signal}_EXPORTER")) {
        Some(v) => !v.eq_ignore_ascii_case("none"),
        None => true,
    }
}

/// Resource identifying this service.
///
/// `Resource::builder()` already folds in `OTEL_SERVICE_NAME` and
/// `OTEL_RESOURCE_ATTRIBUTES`, so an operator can override or extend any of
/// this (`deployment.environment.name`, `service.instance.id`, …) without a
/// code change. The name passed in is only the default.
fn resource(service_name: &'static str, version: &'static str) -> Resource {
    Resource::builder()
        .with_service_name(service_name)
        .with_attributes([KeyValue::new("service.version", version)])
        .build()
}

/// Build the providers for whichever signals are configured.
///
/// Endpoint, headers, timeout, compression, and protocol are all left to the
/// SDK's own `OTEL_EXPORTER_OTLP_*` handling — including appending `/v1/traces`
/// and friends to a base endpoint — so behaviour matches every other OTLP
/// client the operator already runs. We supply only the HTTP client.
pub fn init(service_name: &'static str, version: &'static str) -> Telemetry {
    if sdk_disabled() {
        return Telemetry {
            tracer: None,
            meter: None,
            logger: None,
        };
    }

    let res = resource(service_name, version);

    let tracer = (endpoint_configured("TRACES") && signal_enabled("TRACES"))
        .then(|| {
            opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_http_client(BlockingClient::new())
                .build()
                .inspect_err(|e| tracing::warn!("OTLP trace exporter disabled: {e}"))
                .ok()
                .map(|exporter| {
                    SdkTracerProvider::builder()
                        .with_batch_exporter(exporter)
                        .with_resource(res.clone())
                        .build()
                })
        })
        .flatten();

    let meter = (endpoint_configured("METRICS") && signal_enabled("METRICS"))
        .then(|| {
            opentelemetry_otlp::MetricExporter::builder()
                .with_http()
                .with_http_client(BlockingClient::new())
                .build()
                .inspect_err(|e| tracing::warn!("OTLP metric exporter disabled: {e}"))
                .ok()
                .map(|exporter| {
                    SdkMeterProvider::builder()
                        .with_periodic_exporter(exporter)
                        .with_resource(res.clone())
                        .build()
                })
        })
        .flatten();

    let logger = (endpoint_configured("LOGS") && signal_enabled("LOGS"))
        .then(|| {
            opentelemetry_otlp::LogExporter::builder()
                .with_http()
                .with_http_client(BlockingClient::new())
                .build()
                .inspect_err(|e| tracing::warn!("OTLP log exporter disabled: {e}"))
                .ok()
                .map(|exporter| {
                    SdkLoggerProvider::builder()
                        .with_batch_exporter(exporter)
                        .with_resource(res)
                        .build()
                })
        })
        .flatten();

    if let Some(tp) = tracer.as_ref() {
        global::set_tracer_provider(tp.clone());
        // W3C `traceparent`/`tracestate`: lets a proxied request join the
        // caller's trace and continue into the upstream.
        global::set_text_map_propagator(TraceContextPropagator::new());
    }
    if let Some(mp) = meter.as_ref() {
        global::set_meter_provider(mp.clone());
    }

    Telemetry {
        tracer,
        meter,
        logger,
    }
}

/// Install the process-wide `tracing` subscriber: the existing human-readable
/// stderr output, plus — when configured — a span layer and an OTLP log bridge.
///
/// Kept here rather than in each `main.rs` so all five services filter and
/// format identically. `seekrit-run` is the exception and does not call this:
/// its stderr is user-facing CLI output, not a service log.
pub fn install_subscriber(telemetry: &Telemetry, default_filter: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter));

    let otel_layer = telemetry
        .tracer
        .as_ref()
        .map(|tp| tracing_opentelemetry::layer().with_tracer(tp.tracer(env!("CARGO_PKG_NAME"))));

    // The log bridge must not re-ingest the SDK's own diagnostics: exporting a
    // log emits a log, which would be exported… Filtering the `opentelemetry*`
    // targets breaks that cycle.
    let log_layer = telemetry.logger.as_ref().map(|lp| {
        OpenTelemetryTracingBridge::new(lp).with_filter(tracing_subscriber::filter::filter_fn(
            |meta| !meta.target().starts_with("opentelemetry"),
        ))
    });

    // `try_init` so a subscriber already installed (tests) is not a panic.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(otel_layer)
        .with(log_layer)
        .try_init();
}

/// Install *only* the OpenTelemetry span layer, leaving stderr alone.
///
/// For one-shot CLIs (`seekrit-run`) whose stderr is user-facing output rather
/// than a service log: piping `tracing`'s formatter into it would turn tidy
/// command output into log lines. Spans still export; nothing is printed.
pub fn install_span_layer_only(telemetry: &Telemetry) {
    let Some(tp) = telemetry.tracer.as_ref() else {
        return;
    };
    let _ = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(tp.tracer(env!("CARGO_PKG_NAME"))))
        .try_init();
}

/// Extract a trace context from the **environment** rather than HTTP headers.
///
/// CI systems that are themselves instrumented (the Jenkins OTel plugin,
/// GitLab, Buildkite, `otel-cli`) publish the job's context as `TRACEPARENT` /
/// `TRACESTATE`. Reading them makes a `seekrit run` invocation a child of the
/// pipeline step that launched it instead of an unattached root trace.
pub fn extract_context_from_env() -> Context {
    let mut headers = http::HeaderMap::new();
    for (var, header) in [("TRACEPARENT", "traceparent"), ("TRACESTATE", "tracestate")] {
        if let Some(value) = env_nonempty(var).and_then(|v| http::HeaderValue::from_str(&v).ok()) {
            if let Ok(name) = http::header::HeaderName::from_bytes(header.as_bytes()) {
                headers.insert(name, value);
            }
        }
    }
    crate::extract_context(&headers)
}

/// Attach an extracted context as the parent of the given `tracing` span.
pub fn set_parent_context(span: &tracing::Span, cx: Context) {
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    // Errors only when no OpenTelemetry layer is installed (telemetry off), in
    // which case there is no parent to set and nothing to report.
    let _ = span.set_parent(cx);
}

/// The OpenTelemetry context of the currently-entered `tracing` span, for
/// handing to [`crate::inject_context`].
pub fn current_context() -> Context {
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    tracing::Span::current().context()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the opt-in contract: an unconfigured signal must report no
    /// endpoint. A regression here means every CI job and container running a
    /// seekrit binary starts dialling localhost:4318.
    ///
    /// Uses a signal name no real deployment sets, so the assertion holds
    /// regardless of the developer's own `OTEL_*` environment — except for the
    /// generic variable, which is checked explicitly.
    #[test]
    fn endpoint_detection_is_opt_in() {
        let generic_set = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok();
        assert_eq!(endpoint_configured("TESTSIG"), generic_set);

        std::env::set_var(
            "OTEL_EXPORTER_OTLP_TESTSIG_ENDPOINT",
            "http://127.0.0.1:4318",
        );
        assert!(endpoint_configured("TESTSIG"));
        std::env::remove_var("OTEL_EXPORTER_OTLP_TESTSIG_ENDPOINT");
        assert_eq!(endpoint_configured("TESTSIG"), generic_set);
    }

    /// `OTEL_SDK_DISABLED` parsing and its effect on [`init`], in one test:
    /// cargo runs tests in parallel threads of a single process, so two tests
    /// mutating the same environment variable would race.
    #[test]
    fn sdk_disabled_kill_switch() {
        std::env::set_var("OTEL_SDK_DISABLED", "TRUE");
        assert!(sdk_disabled(), "the flag is case-insensitive per the spec");

        let t = init("test-service", "0.0.0");
        assert!(!t.active(), "OTEL_SDK_DISABLED must suppress all exporters");
        t.shutdown();

        std::env::set_var("OTEL_SDK_DISABLED", "false");
        assert!(!sdk_disabled());
        std::env::remove_var("OTEL_SDK_DISABLED");
        assert!(!sdk_disabled(), "unset means enabled");
    }

    #[test]
    fn signal_toggle_recognises_none() {
        std::env::set_var("OTEL_TESTSIGNAL_EXPORTER", "none");
        assert!(!signal_enabled("TESTSIGNAL"));
        std::env::set_var("OTEL_TESTSIGNAL_EXPORTER", "otlp");
        assert!(signal_enabled("TESTSIGNAL"));
        std::env::remove_var("OTEL_TESTSIGNAL_EXPORTER");
        // Unset means enabled — we only reach this code with an endpoint set.
        assert!(signal_enabled("TESTSIGNAL"));
    }

    #[test]
    fn blank_env_values_are_treated_as_unset() {
        std::env::set_var("SEEKRIT_TELEMETRY_BLANK", "   ");
        assert!(env_nonempty("SEEKRIT_TELEMETRY_BLANK").is_none());
        std::env::remove_var("SEEKRIT_TELEMETRY_BLANK");
    }
}
