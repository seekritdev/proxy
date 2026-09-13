//! `seekrit-proxy`: an egress proxy that substitutes `{{seekrit:NAME}}`
//! placeholders in outbound requests for decrypted secrets, so an (untrusted)
//! agent process never holds the plaintext.
//!
//! The library half is split from `main.rs` so the config, substitution, and
//! data-plane paths can be exercised in tests (see `tests/proxy.rs`).

pub mod activity;
pub mod approval;
pub mod ca;
pub mod config;
pub mod egress;
pub mod forward;
pub mod policy;
pub mod proxy;
pub mod ratchet;
pub mod redact;
pub mod resolve;
pub mod secrets;
pub mod substitute;
pub mod tasks;
pub mod telemetry;
pub mod tickets;

/// The HTTP client the data planes use to reach an upstream.
///
/// One constructor so production and the test harnesses cannot drift on the two
/// settings that matter here.
///
/// **Redirects are never followed.** A `3xx` is an upstream choosing the next
/// request. Following it would re-send the substituted credential to a method and
/// path this deployment's policy never authorized — operation constraints are
/// evaluated once, against the request the workload actually made — and it is
/// also how a credential escapes [`redact`]: the token comes back in a
/// `Location:` query parameter, and a proxy that chases it turns an echo into a
/// live request instead of scrubbing it. The `3xx` is passed through to the
/// caller instead, which is what a reverse proxy conventionally does (nginx
/// `proxy_pass` behaves the same way) and what the forward plane wants anyway,
/// since the workload's own client comes back through this proxy and is
/// authorized again.
///
/// **DNS goes through [`egress`].** Installing the gate as the client's own
/// resolver is what closes the rebinding window: the addresses it approves are
/// the addresses reqwest dials, with no second lookup in between.
pub fn upstream_client(egress: std::sync::Arc<egress::Egress>) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("seekrit-proxy/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(std::sync::Arc::new(egress::EgressResolver::new(egress)))
        .build()
}

/// The HTTP client for seekrit's own API — resolve, policy, tasks, activity.
///
/// Separate from [`upstream_client`] on purpose. The egress gate exists to stop
/// an *agent* steering this proxy at an internal address; the API base URL is
/// operator configuration, and a self-hosted control plane on a private network
/// is a legitimate deployment rather than an attack. Running it through the gate
/// would refuse that for no security gain.
pub fn api_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("seekrit-proxy/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// Render an error together with everything that caused it.
///
/// `reqwest::Error`'s own `Display` stops at "error sending request for url
/// (…)", which is exactly the wrong amount of information when the cause is a
/// refusal this proxy issued: the operator needs to read "…is link-local (cloud
/// instance metadata) — refusing to connect", not be told the request failed.
pub fn describe_error(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        // Skip a cause that only repeats what has already been said — hyper and
        // reqwest often wrap the same string twice.
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = cause.source();
    }
    out
}
