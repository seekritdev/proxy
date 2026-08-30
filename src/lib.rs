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
pub mod resolve;
pub mod secrets;
pub mod substitute;
pub mod tasks;
pub mod telemetry;
pub mod tickets;
