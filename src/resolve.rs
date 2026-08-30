//! The one startup network call: `GET /v1/resolve` with the service token as a
//! bearer credential. Async (reqwest) rather than `apps/run`'s blocking `ureq`,
//! but it deserializes into the same shared [`ResolveResponse`] type. The server
//! returns ciphertext + wrapped DEKs only — never plaintext.

use seekrit_core::resolve::ResolveResponse;

use crate::secrets::StartupError;

/// The default public API, overridable via `--api-url` / `SEEKRIT_API_URL`.
pub const DEFAULT_API_URL: &str = "https://api.seekrit.dev";

/// Why a resolve failed, split by the only distinction the last-known-good
/// cache cares about: could we not *reach* the API, or did it *refuse* us?
#[derive(Debug)]
pub enum ResolveFailure {
    /// Network, TLS, timeout, 5xx, or a rate limit. The cached response (if
    /// any) may stand in.
    Unavailable(String),
    /// The API answered, and the answer was no (401/403/404/…). A cached
    /// response must **not** stand in: revocation is meant to bite here.
    Refused(String),
}

impl ResolveFailure {
    /// Whether a cached response may be served in place of this failure.
    pub fn may_fall_back(&self) -> bool {
        matches!(self, ResolveFailure::Unavailable(_))
    }
}

impl std::fmt::Display for ResolveFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveFailure::Unavailable(m) | ResolveFailure::Refused(m) => write!(f, "{m}"),
        }
    }
}

impl From<ResolveFailure> for StartupError {
    fn from(e: ResolveFailure) -> StartupError {
        StartupError::Resolve(e.to_string())
    }
}

pub async fn fetch(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
) -> Result<ResolveResponse, StartupError> {
    let body = fetch_body(client, api_url, token).await?;
    parse(&body)
}

/// Parse a resolve response body — freshly fetched, or read back from the cache.
pub fn parse(body: &str) -> Result<ResolveResponse, StartupError> {
    serde_json::from_str(body)
        .map_err(|e| StartupError::Resolve(format!("could not parse resolve response: {e}")))
}

/// Fetch the resolve response and return its **raw body**, so the cache can
/// store exactly what the API sent.
pub async fn fetch_body(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
) -> Result<String, ResolveFailure> {
    let base = api_url.trim_end_matches('/');
    let url = format!("{base}/v1/resolve");

    let resp = client
        .get(&url)
        .bearer_auth(token)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|e| ResolveFailure::Unavailable(e.to_string()))?;

    let status = resp.status();
    // A body we cannot even read is a transport problem, not an answer.
    let body = resp
        .text()
        .await
        .map_err(|e| ResolveFailure::Unavailable(e.to_string()))?;

    if !status.is_success() {
        let message = format!("HTTP {} from {url}: {}", status.as_u16(), snippet(&body));
        return Err(if status.is_server_error() || status.as_u16() == 429 {
            ResolveFailure::Unavailable(message)
        } else {
            ResolveFailure::Refused(message)
        });
    }
    Ok(body)
}

/// A short, single-line snippet of an error body for logs (never a secret;
/// resolve error bodies are the API's JSON error envelope).
fn snippet(body: &str) -> String {
    let one_line: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.len() > 200 {
        format!("{}…", &one_line[..200])
    } else {
        one_line
    }
}
