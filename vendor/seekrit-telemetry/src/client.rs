//! The OTLP exporter's HTTP client.
//!
//! Deliberately **blocking `ureq`**, not the async `reqwest` client the server
//! apps already hold — this is the single least obvious decision in the crate,
//! so it is worth stating plainly.
//!
//! The SDK drives every export with `futures_executor::block_on` on its own
//! dedicated thread (`OpenTelemetry.Traces.BatchProcessor`,
//! `OpenTelemetry.Metrics.PeriodicReader`). That thread is not a tokio worker
//! and has no reactor, so polling a `reqwest` future there panics with
//! *"there is no reactor running, must be called from the context of a Tokio
//! 1.x runtime"*. The panic happens on the exporter thread, which means the
//! service keeps serving traffic and looks perfectly healthy while delivering
//! **nothing** — the worst possible failure mode for observability.
//!
//! A blocking client on that thread is the shape the SDK actually wants, and it
//! is what lets one code path serve both the tokio services (proxy, sdk-server,
//! kms) and the runtime-free ones (run, provisioner) with no `rt-tokio`
//! feature and no second async runtime.
//!
//! `ureq` is already a dependency of `apps/run`, is rustls + bundled webpki
//! roots (so no system CA store is required and the `scratch` images keep
//! working), and adds no runtime of its own.

use std::io::Read as _;
use std::time::Duration;

use opentelemetry_http::{HttpClient, HttpError};

/// Cap on a single export request. The SDK's own `OTEL_EXPORTER_OTLP_TIMEOUT`
/// governs the export as a whole; this is the transport-level backstop that
/// stops a black-holed collector pinning the exporter thread forever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Blocking OTLP transport. Cloned per signal (traces/metrics/logs); the inner
/// `ureq::Agent` is itself an `Arc`, so clones share one connection pool.
#[derive(Debug, Clone)]
pub struct BlockingClient {
    agent: ureq::Agent,
}

impl BlockingClient {
    pub fn new() -> Self {
        BlockingClient {
            agent: ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build(),
        }
    }
}

impl Default for BlockingClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HttpClient for BlockingClient {
    async fn send_bytes(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> Result<http::Response<bytes::Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        let mut req = self.agent.post(&parts.uri.to_string());
        // Carries content-type plus whatever OTEL_EXPORTER_OTLP_HEADERS holds —
        // typically the collector's credential. Never logged: see `redact` in
        // lib.rs for why the header map stays out of every diagnostic path.
        for (name, value) in parts.headers.iter() {
            if let Ok(v) = value.to_str() {
                req = req.set(name.as_str(), v);
            }
        }

        // ureq treats 4xx/5xx as `Err(Status)`. The SDK wants the status back so
        // it can log a useful retry/backoff message, so unwrap it into a normal
        // response rather than an error.
        let (status, reader) = match req.send_bytes(&body) {
            Ok(resp) => (resp.status(), resp.into_reader()),
            Err(ureq::Error::Status(code, resp)) => (code, resp.into_reader()),
            Err(e) => return Err(Box::new(e)),
        };

        let mut buf = Vec::new();
        let mut reader = reader;
        reader.read_to_end(&mut buf)?;

        Ok(http::Response::builder()
            .status(status)
            .body(bytes::Bytes::from(buf))?)
    }
}
