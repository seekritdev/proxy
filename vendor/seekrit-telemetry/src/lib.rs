//! Shared OpenTelemetry wiring for the seekrit services that run on **your**
//! infrastructure: `seekrit-run`, `seekrit-proxy`, `seekrit-provisioner`,
//! `seekrit-sdk-server`, and `seekrit-kms`.
//!
//! These are the components a customer operates themselves, so their telemetry
//! belongs in the customer's own stack — not seekrit's. Everything here speaks
//! plain **OTLP/HTTP** and is configured through the **standard `OTEL_*`
//! environment variables**, so an existing collector, agent, or vendor endpoint
//! picks these services up with no seekrit-specific configuration.
//!
//! # Opt-in
//!
//! Telemetry is **inert until an OTLP endpoint is configured**. With no
//! `OTEL_EXPORTER_OTLP_ENDPOINT` (or per-signal equivalent) set, [`init`]
//! installs no exporters, starts no threads, and opens no sockets.
//!
//! This deliberately departs from the OTel spec's `http://localhost:4318`
//! default: these binaries routinely run in containers and CI with no collector
//! anywhere, and a default-on exporter would mean every one of them retrying
//! connections to a port that will never answer.
//!
//! # What is safe to record — the zero-knowledge line
//!
//! These services hold decrypted secrets in memory. Telemetry leaves the
//! process and lands in a system with different access controls, so it is held
//! to the same rule as the audit log:
//!
//! - **Allowed**: secret *names*, counts, environment/app/route identifiers,
//!   upstream hosts, durations, status codes, error *kinds*.
//! - **Never**: secret values, ciphertext, DEKs, private keys, passphrases,
//!   service tokens, `Authorization` headers, request/response bodies, or the
//!   contents of `OTEL_EXPORTER_OTLP_HEADERS` (which is itself a credential for
//!   the customer's collector).
//!
//! `attr` below exists so instrumentation reaches for a named, reviewed
//! attribute instead of formatting whatever is in scope, and each service has a
//! test asserting no exported attribute ever carries a secret value.
//!
//! # Size
//!
//! The `otel` feature is on by default and costs, measured on the release
//! profiles these binaries actually ship with (`opt-level = "z"`, LTO, strip):
//!
//! | binary                | without  | with     | delta           |
//! |-----------------------|----------|----------|-----------------|
//! | `seekrit-run`         | 1.30 MiB | 1.70 MiB | +408 KiB (+31%) |
//! | `seekrit-proxy`       | 3.16 MiB | 3.69 MiB | +538 KiB (+17%) |
//! | `seekrit-provisioner` | 2.68 MiB | 3.04 MiB | +359 KiB (+13%) |
//! | `seekrit-sdk-server`  | 2.82 MiB | 3.31 MiB | +505 KiB (+18%) |
//! | `seekrit-kms`         | 2.85 MiB | 3.34 MiB | +505 KiB (+17%) |
//!
//! Every binary exposes a matching `otel` feature, so
//! `cargo build --no-default-features` compiles the stack out entirely: the API
//! below keeps its shape, every call becomes a no-op, and no OpenTelemetry SDK
//! or exporter crate is linked. `seekrit-run` is the one where this is worth
//! considering — it is the smallest binary and the one distributed standalone.

#![forbid(unsafe_code)]

#[cfg(feature = "otel")]
mod client;

#[cfg(feature = "otel")]
mod imp;

mod propagate;

#[cfg(feature = "testing")]
pub mod testing;

/// Re-exported so services record instruments against exactly the API version
/// this crate was built with, rather than pinning `opentelemetry` themselves
/// and risking two incompatible copies in the graph.
pub use opentelemetry;

pub use propagate::{extract_context, inject_context, meter};

#[cfg(not(feature = "otel"))]
mod imp {
    //! No-op implementation used when the `otel` feature is off. Same surface,
    //! so consumers need no `cfg` of their own.

    pub struct Telemetry;

    impl Telemetry {
        pub fn active(&self) -> bool {
            false
        }
        pub fn shutdown(self) {}
    }

    pub fn init(_service_name: &'static str, _version: &'static str) -> Telemetry {
        Telemetry
    }

    pub fn install_subscriber(_telemetry: &Telemetry, default_filter: &str) {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter));
        let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    }

    /// Without the SDK there is no span to reparent, so this is a no-op — the
    /// call site stays identical in both builds.
    pub fn set_parent_context(_span: &tracing::Span, _cx: opentelemetry::Context) {}

    /// No spans exist to read a context from; injecting this produces no
    /// headers, which is the correct behaviour with telemetry compiled out.
    pub fn current_context() -> opentelemetry::Context {
        opentelemetry::Context::new()
    }

    /// Nothing to install without the SDK.
    pub fn install_span_layer_only(_telemetry: &Telemetry) {}

    /// No propagator is registered, so this is an empty context.
    pub fn extract_context_from_env() -> opentelemetry::Context {
        opentelemetry::Context::new()
    }
}

pub use imp::{
    current_context, extract_context_from_env, init, install_span_layer_only, install_subscriber,
    set_parent_context, Telemetry,
};

/// Attribute keys used across the services.
///
/// Centralised for two reasons: consistency (a dashboard written against one
/// service works against the others), and review — everything telemetry is
/// allowed to record has a name here, so widening the surface is a visible diff
/// rather than an inline `format!` someone slips into a handler.
///
/// Names follow OpenTelemetry semantic conventions where one exists
/// (`http.*`, `server.*`, `error.*`) and are namespaced under `seekrit.*`
/// where none does.
pub mod attr {
    /// Number of secrets in scope for an operation. A count, never the names'
    /// values.
    pub const SECRET_COUNT: &str = "seekrit.secret.count";
    /// Names of the secrets substituted into one request (proxy). Names are
    /// already in the audit log; values never appear.
    pub const SECRET_NAMES: &str = "seekrit.secret.names";
    /// The secret name an operation refers to.
    pub const SECRET_NAME: &str = "seekrit.secret.name";
    /// Why a request was refused, e.g. `not_allowed`, `unknown_secret`.
    pub const DENY_REASON: &str = "seekrit.deny.reason";
    /// Configured upstream a proxied request was forwarded to.
    pub const UPSTREAM_HOST: &str = "seekrit.upstream.host";
    /// The matched route prefix (reverse proxy).
    pub const ROUTE_PREFIX: &str = "seekrit.route.prefix";
    /// Agent identity a proxied request was authorized as (an id or slug — a
    /// policy subject, never a credential).
    pub const AGENT_IDENTITY: &str = "seekrit.agent.identity";
    /// Version of the signed policy bundle in force for that request.
    pub const POLICY_VERSION: &str = "seekrit.policy.version";
    /// Index of the policy rule that decided, so a refusal can be traced to the
    /// line an admin published.
    pub const POLICY_RULE: &str = "seekrit.policy.rule";
    /// Trust-ratchet state a request was evaluated in (`baseline` until a
    /// protected event narrows the run). A state *name* from the operator's own
    /// config — it says how much capability is left, never what was read.
    pub const RATCHET_STATE: &str = "seekrit.ratchet.state";
    /// AWS KMS operation name, e.g. `Encrypt`, `GenerateDataKey`.
    pub const KMS_OPERATION: &str = "seekrit.kms.operation";
    /// Managed key id an operation ran against.
    pub const KMS_KEY_ID: &str = "seekrit.kms.key_id";
    /// Database engine a lease was provisioned against.
    pub const PROVISION_PROVIDER: &str = "seekrit.provision.provider";
    /// Provisioning command kind, e.g. `create`, `revoke`.
    pub const PROVISION_COMMAND: &str = "seekrit.provision.command";
    /// Whether `seekrit-run` fell back to `.env` + live environment only.
    pub const RUN_DEGRADED: &str = "seekrit.run.degraded";
    /// Machine-readable failure kind. Never a message containing user data.
    pub const ERROR_KIND: &str = "error.type";
}
