//! Types for the `GET /v1/resolve` response. **Transport-free**: this crate
//! never makes the request — the consuming app fetches the body (blocking
//! `ureq` in `apps/run`, async `reqwest` in `apps/proxy`) and deserializes it
//! into [`ResolveResponse`]. The server returns ciphertext + per-principal
//! wrapped DEKs only, never plaintext (the zero-knowledge invariant).

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ResolveResponse {
    pub scope: Scope,
    /// Lowest precedence first (composed groups → the app environment).
    pub layers: Vec<Layer>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Scope {
    /// Present on richer responses; harmless when absent (e.g. older fixtures).
    #[serde(default)]
    pub org_slug: Option<String>,
    pub app_slug: String,
    pub env_slug: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Layer {
    /// "group" or "app".
    pub source: String,
    pub environment_id: String,
    pub slug: String,
    #[serde(default)]
    pub group_slug: Option<String>,
    pub wrapped_dek: String,
    pub secrets: Vec<SecretBlob>,
}

#[derive(Debug, Deserialize)]
pub struct SecretBlob {
    pub name: String,
    pub ciphertext: String,
}
