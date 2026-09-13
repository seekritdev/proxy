//! `seekrit-proxy`: an egress proxy that substitutes `{{seekrit:NAME}}`
//! placeholders in outbound requests for decrypted secrets, so an (untrusted)
//! agent process never holds the plaintext.
//!
//! The library half is split from `main.rs` so the config, substitution, and
//! data-plane paths can be exercised in tests (see `tests/proxy.rs`).

pub mod activity;
pub mod ca;
pub mod config;
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

/// The HTTP client both data planes use to reach an upstream.
///
/// One constructor so production and the test harnesses cannot drift on the
/// setting that matters here: **redirects are never followed.**
///
/// A `3xx` is an upstream choosing the next request. Following it would re-send
/// the substituted credential to a method and path this deployment's policy
/// never authorized — operation constraints are evaluated once, against the
/// request the workload actually made — and it is also how a credential escapes
/// [`redact`]: the token comes back in a `Location:` query parameter, and a proxy
/// that chases it turns an echo into a live request instead of scrubbing it.
///
/// The `3xx` is passed through to the caller instead, which is what a reverse
/// proxy conventionally does (nginx `proxy_pass` behaves the same way) and what
/// the forward plane wants regardless, since the workload's own client comes back
/// through this proxy and is authorized again.
pub fn upstream_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("seekrit-proxy/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .build()
}
