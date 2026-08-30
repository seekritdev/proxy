//! Session tickets: which agent a request *is*, and at most what it may use.
//!
//! One proxy often fronts several agents with different permissions — the case a
//! local file cannot express, since a file has no way to tell two callers apart.
//! A ticket closes that gap without handing an agent any authority:
//!
//! - The **orchestrator** (trusted, and the thing that knows which agent it is
//!   starting) calls the control listener for a ticket naming an agent identity
//!   and, optionally, a narrower set of secrets than that identity's policy
//!   allows.
//! - The **agent** receives only the opaque ticket. It cannot mint one, read one
//!   it was not given, or widen the one it has: minting requires the control
//!   token, and scopes only ever intersect with published policy
//!   ([`crate::policy::permits_secret`]).
//!
//! Backwards compatibility is deliberate: a single-agent sidecar never has to
//! adopt tickets. With no `[control]` block there is no listener, and a request
//! with no ticket is evaluated against `[policy] agent` — the default identity.
//!
//! The control listener binds loopback by default and **requires**
//! `SEEKRIT_PROXY_CONTROL_TOKEN`. Without that, any local process — including the
//! agent the proxy is supposed to constrain — could mint itself a ticket for any
//! identity, and the whole mechanism would be decoration.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::info;

/// Header an agent presents its ticket in.
pub const TICKET_HEADER: &str = "x-seekrit-ticket";
/// Header the orchestrator authenticates to the control listener with.
pub const CONTROL_TOKEN_HEADER: &str = "x-seekrit-control-token";
/// Environment variable carrying the control token. Never the config file —
/// credentials do not belong in a committable file (same rule as `SEEKRIT_TOKEN`).
pub const CONTROL_TOKEN_ENV: &str = "SEEKRIT_PROXY_CONTROL_TOKEN";

/// What a presented ticket authorizes.
#[derive(Debug, Clone)]
pub struct Session {
    /// The agent identity this run is, as named in `[policy] agents`.
    pub agent: String,
    /// Secrets this run may use, when the orchestrator narrowed them. `None`
    /// means "whatever the agent's policy allows".
    pub scopes: Option<BTreeSet<String>>,
}

struct Entry {
    session: Session,
    expires_at: Instant,
}

/// Live tickets. Small, short-lived, and never persisted: a restarted proxy has
/// no tickets, which fails closed for anything that was relying on one.
pub struct TicketStore {
    entries: Mutex<HashMap<String, Entry>>,
    /// Identities this proxy serves — a ticket cannot name anything else.
    known_agents: Vec<String>,
    default_ttl: Duration,
    max_ttl: Duration,
}

impl TicketStore {
    pub fn new(known_agents: Vec<String>, default_ttl: Duration, max_ttl: Duration) -> TicketStore {
        TicketStore {
            entries: Mutex::new(HashMap::new()),
            known_agents,
            default_ttl,
            max_ttl,
        }
    }

    /// Mint a ticket. `agent` must be one this proxy was configured for.
    pub async fn mint(
        &self,
        agent: Option<String>,
        scopes: Option<Vec<String>>,
        ttl: Option<Duration>,
    ) -> Result<(String, Duration), String> {
        let agent = match agent {
            Some(agent) => agent,
            None => self
                .known_agents
                .first()
                .cloned()
                .ok_or_else(|| "this proxy has no agent identities configured".to_string())?,
        };
        if !self.known_agents.contains(&agent) {
            return Err(format!(
                "unknown agent {agent:?}; this proxy serves {:?}",
                self.known_agents
            ));
        }
        let ttl = ttl.unwrap_or(self.default_ttl).min(self.max_ttl);
        let ticket = random_ticket();
        let session = Session {
            agent,
            scopes: scopes.map(|s| s.into_iter().collect()),
        };
        let mut entries = self.entries.lock().await;
        // Opportunistic sweep: tickets are cheap, but a long-lived proxy minting
        // one per agent run should not grow a map forever.
        let now = Instant::now();
        entries.retain(|_, e| e.expires_at > now);
        entries.insert(
            ticket.clone(),
            Entry {
                session,
                expires_at: now + ttl,
            },
        );
        Ok((ticket, ttl))
    }

    /// Look up a presented ticket, if it exists and has not expired.
    ///
    /// Synchronous because it is on the request path: a `blocking_lock` would be
    /// wrong inside async, so this uses `try_lock` and treats contention as a
    /// miss — mint/sweep hold the lock for microseconds, and failing closed on a
    /// lock we could not take is the safe direction.
    pub fn resolve(&self, ticket: &str) -> Option<Session> {
        let entries = self.entries.try_lock().ok()?;
        let entry = entries.get(ticket)?;
        if entry.expires_at <= Instant::now() {
            return None;
        }
        Some(entry.session.clone())
    }

    pub async fn revoke(&self, ticket: &str) -> bool {
        self.entries.lock().await.remove(ticket).is_some()
    }

    /// How many tickets are currently live — for the control listener's health
    /// endpoint, which is the only introspection this listener offers.
    pub async fn live_tickets(&self) -> usize {
        let now = Instant::now();
        self.entries
            .lock()
            .await
            .values()
            .filter(|e| e.expires_at > now)
            .count()
    }
}

/// The ticket a request presents, if any.
pub fn ticket_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(TICKET_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// 256 bits of randomness, base64url. Long enough that guessing is not a
/// consideration and the value never needs to be stored hashed.
fn random_ticket() -> String {
    let mut bytes = [0u8; 32];
    // The proxy already depends on a CSPRNG through rustls/rcgen; this uses the
    // same OS source.
    getrandom::getrandom(&mut bytes).expect("OS randomness");
    format!("skp_{}", seekrit_core::b64::encode(&bytes))
}

#[derive(Clone)]
pub struct ControlState {
    pub tickets: Arc<TicketStore>,
    /// The shared secret an orchestrator must present.
    pub token: Arc<String>,
}

#[derive(Debug, Deserialize)]
pub struct MintRequest {
    #[serde(default)]
    pub agent: Option<String>,
    /// Secret names this run may use. Absent = the agent's full policy.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Lifetime, e.g. `"15m"`. Capped by `[control] max_ttl`.
    #[serde(default)]
    pub ttl: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MintResponse {
    pub ticket: String,
    pub agent: String,
    pub expires_in_seconds: u64,
    /// The header the agent must present it in — so an orchestrator author does
    /// not have to go and find it in the docs.
    pub header: &'static str,
}

/// The control router: mint and revoke, nothing else. Deliberately tiny — this
/// listener exists to hand out tickets, not to expose the proxy's innards.
pub fn control_router(state: ControlState) -> Router {
    Router::new()
        .route("/session", axum::routing::post(mint))
        .route("/session/revoke", axum::routing::post(revoke))
        .route("/health", axum::routing::get(health))
        .with_state(state)
}

fn authenticate(state: &ControlState, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let presented = headers
        .get(CONTROL_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if constant_time_eq(presented.as_bytes(), state.token.as_bytes()) {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            format!("seekrit-proxy: present the control token in {CONTROL_TOKEN_HEADER}\n"),
        ))
    }
}

async fn mint(
    State(state): State<ControlState>,
    headers: HeaderMap,
    body: Option<Json<MintRequest>>,
) -> axum::response::Response {
    if let Err((status, msg)) = authenticate(&state, &headers) {
        return (status, msg).into_response();
    }
    let req = body.map(|Json(b)| b).unwrap_or(MintRequest {
        agent: None,
        scopes: None,
        ttl: None,
    });
    let ttl = match req.ttl.as_deref().map(seekrit_cache::parse_duration) {
        Some(Ok(d)) => Some(d),
        Some(Err(e)) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("seekrit-proxy: invalid ttl: {e}\n"),
            )
                .into_response()
        }
        None => None,
    };
    match state.tickets.mint(req.agent, req.scopes, ttl).await {
        Ok((ticket, ttl)) => {
            let agent = state
                .tickets
                .resolve(&ticket)
                .map(|s| s.agent)
                .unwrap_or_default();
            // Names and lifetimes only. The ticket itself is a credential and is
            // never logged, exactly like a secret value.
            info!(
                agent = %agent,
                ttl_seconds = ttl.as_secs(),
                "minted a session ticket"
            );
            Json(MintResponse {
                ticket,
                agent,
                expires_in_seconds: ttl.as_secs(),
                header: TICKET_HEADER,
            })
            .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("seekrit-proxy: {e}\n")).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct RevokeRequest {
    ticket: String,
}

async fn revoke(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(body): Json<RevokeRequest>,
) -> axum::response::Response {
    if let Err((status, msg)) = authenticate(&state, &headers) {
        return (status, msg).into_response();
    }
    let existed = state.tickets.revoke(&body.ticket).await;
    Json(serde_json::json!({ "revoked": existed })).into_response()
}

async fn health(State(state): State<ControlState>) -> axum::response::Response {
    Json(serde_json::json!({ "ok": true, "tickets": state.tickets.live_tickets().await }))
        .into_response()
}

/// Compare two byte strings without leaking their common prefix through timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> TicketStore {
        TicketStore::new(
            vec!["nova".into(), "scribe".into()],
            Duration::from_secs(60),
            Duration::from_secs(300),
        )
    }

    #[tokio::test]
    async fn mints_and_resolves_a_ticket() {
        let store = store();
        let (ticket, ttl) = store.mint(Some("nova".into()), None, None).await.unwrap();
        assert_eq!(ttl, Duration::from_secs(60));
        assert!(ticket.starts_with("skp_"));
        let session = store.resolve(&ticket).expect("resolves");
        assert_eq!(session.agent, "nova");
        assert!(session.scopes.is_none());
    }

    #[tokio::test]
    async fn defaults_to_the_first_configured_agent() {
        let store = store();
        let (ticket, _) = store.mint(None, None, None).await.unwrap();
        assert_eq!(store.resolve(&ticket).unwrap().agent, "nova");
    }

    #[tokio::test]
    async fn refuses_an_agent_this_proxy_does_not_serve() {
        let store = store();
        let err = store
            .mint(Some("stranger".into()), None, None)
            .await
            .expect_err("must refuse");
        assert!(err.contains("unknown agent"));
    }

    #[tokio::test]
    async fn caps_ttl_at_max() {
        let store = store();
        let (_, ttl) = store
            .mint(None, None, Some(Duration::from_secs(9_999)))
            .await
            .unwrap();
        assert_eq!(ttl, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn scopes_are_carried_through() {
        let store = store();
        let (ticket, _) = store
            .mint(None, Some(vec!["A_KEY".into(), "B_KEY".into()]), None)
            .await
            .unwrap();
        let scopes = store.resolve(&ticket).unwrap().scopes.expect("scopes");
        assert!(scopes.contains("A_KEY") && scopes.contains("B_KEY"));
    }

    #[tokio::test]
    async fn an_expired_ticket_stops_resolving() {
        let store = TicketStore::new(
            vec!["nova".into()],
            Duration::from_millis(1),
            Duration::from_secs(1),
        );
        let (ticket, _) = store.mint(None, None, None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(store.resolve(&ticket).is_none());
        assert_eq!(store.live_tickets().await, 0);
    }

    #[tokio::test]
    async fn revoke_removes_a_ticket() {
        let store = store();
        let (ticket, _) = store.mint(None, None, None).await.unwrap();
        assert!(store.revoke(&ticket).await);
        assert!(store.resolve(&ticket).is_none());
        assert!(!store.revoke(&ticket).await);
    }

    #[test]
    fn tickets_are_unique_and_opaque() {
        let a = random_ticket();
        let b = random_ticket();
        assert_ne!(a, b);
        assert!(a.len() > 40);
    }

    #[test]
    fn header_lookup_ignores_blank_values() {
        let mut headers = HeaderMap::new();
        assert!(ticket_from_headers(&headers).is_none());
        headers.insert(TICKET_HEADER, "   ".parse().unwrap());
        assert!(ticket_from_headers(&headers).is_none());
        headers.insert(TICKET_HEADER, " skp_abc ".parse().unwrap());
        assert_eq!(ticket_from_headers(&headers), Some("skp_abc"));
    }

    #[test]
    fn constant_time_eq_rejects_empty_and_mismatched() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreu"));
        assert!(!constant_time_eq(b"secret", b"sec"));
        // An empty configured token must never match an empty presented one.
        assert!(!constant_time_eq(b"", b""));
    }
}
