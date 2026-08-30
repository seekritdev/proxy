//! Server-dispatched task tokens: turning an `skd_…` credential into the session
//! it authorizes.
//!
//! A [`crate::tickets::TicketStore`] answers the same question for tickets this
//! proxy minted itself. The difference is where the run boundary was drawn: a
//! ticket is minted by the control listener on this machine, a **task** is
//! dispatched through the seekrit API, so one dispatch is honoured by every
//! enforcement point an agent talks to rather than by one proxy. Both resolve to
//! the same [`Session`], so everything downstream is identical.
//!
//! Three properties, in the order they matter:
//!
//! - **A task can only narrow.** The API refuses at dispatch any scope the
//!   agent's published policy does not already permit, and this proxy intersects
//!   again in [`crate::policy::Gate`]. Neither side trusts the other to have done
//!   it.
//! - **The local file still decides which identities exist here.** A task naming
//!   an agent this deployment was not configured for is refused, exactly as a
//!   ticket is. Otherwise a dispatched task could make a proxy serve policy its
//!   operator never named, which is the property `[policy] agents` exists to
//!   hold.
//! - **Fail closed, including on our own failure.** A task we cannot verify is
//!   not a task. If the API is unreachable the request is refused rather than
//!   admitted on the assumption it was probably fine.
//!
//! Introspection is cached, because it is on the request path and a run makes
//! many requests. The cache is what bounds how quickly a revoke takes effect, so
//! it is deliberately short and configurable — see `[tasks] cache_ttl`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tracing::warn;

use crate::tickets::{Session, TICKET_HEADER};

/// Prefix of a token dispatched by the API, as opposed to `skp_` minted here.
pub const TASK_PREFIX: &str = "skd_";

/// Why a presented task token yields no session. Every variant fails closed; the
/// distinction is what the operator gets told.
#[derive(Debug, Clone)]
pub enum TaskError {
    /// The API could not be reached. Unlike policy, there is no last-known-good
    /// fallback: a cached *bundle* is still signed and self-describing, whereas a
    /// task's whole meaning is "is this still live", which only the API knows.
    Unavailable(String),
    /// The API answered no: revoked, expired, unknown, or a disabled identity.
    Refused(String),
    /// This deployment does not serve the identity the task names.
    UnknownAgent(String),
}

impl std::fmt::Display for TaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskError::Unavailable(m) => {
                write!(f, "could not verify the dispatched task: {m}")
            }
            TaskError::Refused(m) => write!(f, "the dispatched task is not usable: {m}"),
            TaskError::UnknownAgent(m) => write!(f, "{m}"),
        }
    }
}

/// The `{ session: … }` body of `POST /v1/tasks/introspect`.
#[derive(Debug, Deserialize)]
struct IntrospectResponse {
    session: IntrospectSession,
}

#[derive(Debug, Deserialize)]
struct IntrospectSession {
    #[serde(rename = "taskId")]
    task_id: String,
    agent: IntrospectAgent,
    /// Absent or null ⇒ no narrowing beyond the agent's published policy.
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(rename = "policyVersion")]
    policy_version: u32,
}

#[derive(Debug, Deserialize)]
struct IntrospectAgent {
    slug: String,
}

/// A resolved (or refused) introspection, held for a bounded window.
struct Cached {
    /// `Err` is cached too, briefly: an agent looping on a revoked token should
    /// not turn into a request per attempt against the API.
    result: Result<Session, TaskError>,
    until: Instant,
}

/// Resolves `skd_…` tokens against the API, with a short cache.
pub struct TaskClient {
    client: reqwest::Client,
    api_url: String,
    token: String,
    /// Identities this proxy serves. **Empty means file mode**: there is one
    /// local rule set, no per-agent policy to select, so the name a task carries
    /// is informational and cannot widen anything. In server mode a task naming
    /// anything outside this list is refused.
    known_agents: Vec<String>,
    cache: Mutex<HashMap<String, Cached>>,
    positive_ttl: Duration,
    negative_ttl: Duration,
}

impl TaskClient {
    pub fn new(
        client: reqwest::Client,
        api_url: String,
        token: String,
        known_agents: Vec<String>,
        positive_ttl: Duration,
    ) -> TaskClient {
        TaskClient {
            client,
            api_url,
            token,
            known_agents,
            cache: Mutex::new(HashMap::new()),
            positive_ttl,
            // Long enough to blunt a hot retry loop, short enough that a task
            // dispatched a moment after it was first presented still works.
            negative_ttl: Duration::from_secs(5),
        }
    }

    /// Resolve a presented token, from cache when possible.
    pub async fn resolve(&self, presented: &str) -> Result<Session, TaskError> {
        if let Some(hit) = self.cached(presented) {
            return hit;
        }
        let fresh = self.introspect(presented).await;
        let ttl = if fresh.is_ok() {
            self.positive_ttl
        } else {
            self.negative_ttl
        };
        if let Ok(mut cache) = self.cache.lock() {
            let now = Instant::now();
            // Opportunistic sweep, same reasoning as the ticket store: a
            // long-lived proxy seeing many runs should not grow a map forever.
            cache.retain(|_, c| c.until > now);
            cache.insert(
                presented.to_string(),
                Cached {
                    result: fresh.clone(),
                    until: now + ttl,
                },
            );
        }
        fresh
    }

    fn cached(&self, presented: &str) -> Option<Result<Session, TaskError>> {
        let cache = self.cache.lock().ok()?;
        let hit = cache.get(presented)?;
        if hit.until <= Instant::now() {
            return None;
        }
        Some(hit.result.clone())
    }

    async fn introspect(&self, presented: &str) -> Result<Session, TaskError> {
        let url = format!("{}/v1/tasks/introspect", self.api_url.trim_end_matches('/'));
        // The token goes in the body, never the URL — it is a credential, and a
        // URL ends up in logs and traces. Serialized by hand rather than with
        // reqwest's `json` feature, which this crate deliberately does not build
        // (the release profile optimizes for size).
        let body = serde_json::json!({ "token": presented }).to_string();
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| TaskError::Unavailable(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let detail = summarize(&body);
            return Err(if status.is_server_error() {
                TaskError::Unavailable(format!("HTTP {status}{detail}"))
            } else {
                TaskError::Refused(detail.trim_start_matches(" — ").to_string())
            });
        }

        let body = resp
            .text()
            .await
            .map_err(|e| TaskError::Unavailable(e.to_string()))?;
        let parsed: IntrospectResponse = serde_json::from_str(&body).map_err(|e| {
            TaskError::Refused(format!("introspection response is not usable: {e}"))
        })?;
        let session = parsed.session;

        // The local control: this proxy serves the identities its own file names.
        if !self.known_agents.is_empty() && !self.known_agents.contains(&session.agent.slug) {
            return Err(TaskError::UnknownAgent(format!(
                "the dispatched task is for agent {:?}, which this proxy does not serve (it serves {:?})",
                session.agent.slug, self.known_agents
            )));
        }

        tracing::debug!(
            task = %session.task_id,
            agent = %session.agent.slug,
            policy_version = session.policy_version,
            scoped = session.scopes.is_some(),
            "resolved a dispatched task"
        );
        Ok(Session {
            agent: session.agent.slug,
            scopes: session.scopes.map(|s| s.into_iter().collect()),
        })
    }
}

/// Resolves whatever a request presented in `x-seekrit-ticket` — a locally
/// minted ticket, a dispatched task, or nothing at all.
///
/// One place, so the two data planes cannot disagree about what a header means.
/// The prefix decides which mechanism answers, which is what lets a deployment
/// adopt dispatched tasks without changing anything about its existing tickets.
pub struct SessionResolver {
    tickets: Option<std::sync::Arc<crate::tickets::TicketStore>>,
    tasks: Option<TaskClient>,
}

impl SessionResolver {
    pub fn new(
        tickets: Option<std::sync::Arc<crate::tickets::TicketStore>>,
        tasks: Option<TaskClient>,
    ) -> SessionResolver {
        SessionResolver { tickets, tasks }
    }

    /// No ticket store and no task client: every request is the default identity.
    pub fn is_inert(&self) -> bool {
        self.tickets.is_none() && self.tasks.is_none()
    }

    /// Resolve a presented credential. `None` means the request carried none,
    /// which is the single-agent sidecar case and resolves to the default
    /// identity.
    pub async fn resolve(&self, presented: Option<&str>) -> Result<Option<Session>, String> {
        let Some(presented) = presented else {
            return Ok(None);
        };
        if presented.starts_with(TASK_PREFIX) {
            let Some(tasks) = self.tasks.as_ref() else {
                return Err(format!(
                    "a dispatched task was presented in {TICKET_HEADER}, but this proxy has no [tasks] block — add one, or mint tickets from the control listener instead"
                ));
            };
            return match tasks.resolve(presented).await {
                Ok(session) => Ok(Some(session)),
                Err(e) => {
                    // Logged at warn because a refused run is the operator's
                    // problem to see; the token itself is never logged.
                    warn!(error = %e, "refused a dispatched task");
                    Err(e.to_string())
                }
            };
        }
        let Some(tickets) = self.tickets.as_ref() else {
            return Err(format!(
                "a session ticket was presented in {TICKET_HEADER}, but this proxy has no [control] listener"
            ));
        };
        match tickets.resolve(presented) {
            Some(session) => Ok(Some(session)),
            None => Err(format!(
                "the {TICKET_HEADER} session ticket is unknown or expired"
            )),
        }
    }
}

/// First line of an error body, trimmed — the API's messages are written to be
/// read, and truncating one is better than logging a page of HTML.
fn summarize(body: &str) -> String {
    let text = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => v
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| body.to_string()),
        Err(_) => body.to_string(),
    };
    let line = text.lines().next().unwrap_or("").trim();
    if line.is_empty() {
        String::new()
    } else if line.len() > 200 {
        format!(" — {}…", &line[..200])
    } else {
        format!(" — {line}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_a_dispatched_token_by_prefix() {
        assert!("skd_abc".starts_with(TASK_PREFIX));
        assert!(!"skp_abc".starts_with(TASK_PREFIX));
    }

    #[test]
    fn summarize_prefers_the_api_message() {
        let body = r#"{"error":{"code":"forbidden","message":"this task has been revoked"}}"#;
        assert_eq!(summarize(body), " — this task has been revoked");
    }

    #[test]
    fn summarize_survives_a_non_json_body() {
        assert_eq!(summarize("<html>502</html>"), " — <html>502</html>");
        assert_eq!(summarize(""), "");
    }

    #[tokio::test]
    async fn a_task_token_with_no_tasks_block_is_refused_by_name() {
        let resolver = SessionResolver::new(None, None);
        let err = resolver.resolve(Some("skd_whatever")).await.unwrap_err();
        assert!(err.contains("[tasks]"), "{err}");
    }

    #[tokio::test]
    async fn a_ticket_with_no_control_listener_is_refused_by_name() {
        let resolver = SessionResolver::new(None, None);
        let err = resolver.resolve(Some("skp_whatever")).await.unwrap_err();
        assert!(err.contains("[control]"), "{err}");
    }

    #[tokio::test]
    async fn no_header_resolves_to_the_default_identity() {
        let resolver = SessionResolver::new(None, None);
        assert!(resolver.resolve(None).await.unwrap().is_none());
    }
}
