//! Holding a request open until a human says yes.
//!
//! Policy and the ratchet both answer in microseconds, from rules written
//! earlier. Some operations do not want an answer written earlier. Moving money,
//! deleting a production dataset, sending mail as the company — for those, the
//! useful control is not "was this permitted in general" but **"is this the one
//! you meant, right now"**, asked while the request is still in the proxy's hands
//! and nothing has left the process.
//!
//! So a rule may mark an operation as requiring approval. A matching request
//! stops at the last moment before dispatch, a prompt appears, and the request
//! resumes or is refused on the answer.
//!
//! Five decisions shape this, and each one is somewhere a more obvious design is
//! worse.
//!
//! **1. It gates the dispatch, not the authorization.** The hold is placed after
//! policy, after the ratchet, and after substitution — the last moment before
//! `send()`. That is what lets the prompt say *which credential* is about to
//! travel, which is the only detail that makes a yes/no meaningful. Nothing has
//! left the process at that point; a denial drops the substituted bytes.
//!
//! **2. Timing out is a denial.** A prompt nobody answers must not become a
//! permit because a socket was patient. The same fail-closed direction as every
//! other control here, and the reason the timeout is short by default: it is a
//! held connection, not a ticket queue.
//!
//! **3. Approval is not a credential.** A decision is delivered over the existing
//! control listener, which is loopback-bound and requires
//! `SEEKRIT_PROXY_CONTROL_TOKEN`. The agent cannot approve its own request: it
//! has no control token, and the pending id it would need is never sent to it.
//!
//! **4. `always` is scoped to the run, and narrowly.** It remembers one
//! (rule, host, method) triple in memory, for this process only. Not the path —
//! "always allow POSTs to this host under this rule" is a sentence an operator
//! can hold in their head, while "always allow anything that matched this
//! prompt" is not. A restart forgets it, which is the right default for a
//! control whose whole purpose is a human in the loop.
//!
//! **5. A proxy that cannot ask is refused at startup.** With no control listener
//! and no terminal, every matching request would hang until it timed out, with
//! nobody able to answer — a control that silently becomes a denial generator.
//! `main.rs` checks for that before serving.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use seekrit_core::policy::{MethodSet, PathSet};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

/// Default hold. Short because this is a live connection: an upstream client is
/// waiting on it, and most have their own timeouts well under a minute.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
/// Below this a human cannot realistically answer, so the prompt would be
/// theatre.
pub const MIN_TIMEOUT: Duration = Duration::from_secs(5);
/// Above this the held connection is the problem rather than the approval.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(900);

/// One declared operation that needs a human.
#[derive(Debug, Clone)]
pub struct Trigger {
    pub host: String,
    pub methods: MethodSet,
    pub paths: PathSet,
    /// What the prompt calls this, so the question reads like the operation
    /// rather than like a URL.
    pub label: Option<String>,
}

impl Trigger {
    fn matches(&self, host: &str, method: &str, path: &str) -> bool {
        self.host.eq_ignore_ascii_case(host)
            && self.methods.matches(method)
            && self.paths.matches(path)
    }

    fn describe(&self) -> String {
        match &self.label {
            Some(label) => label.clone(),
            None => self.host.clone(),
        }
    }
}

/// The validated `[approval]` block.
#[derive(Debug, Clone)]
pub struct ApprovalConfig {
    pub timeout: Duration,
    pub require: Vec<Trigger>,
}

/// What a human said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Let this one through.
    Approve,
    /// Refuse this one.
    Deny,
    /// Let this one through, and stop asking about this (rule, host, method)
    /// for the rest of this process's life.
    Always,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Approve => "approve",
            Decision::Deny => "deny",
            Decision::Always => "always",
        }
    }
}

/// The outcome of asking. `Held` carries how long the wait was, for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No trigger matched, or a standing `always` covered it. Nothing was held.
    NotRequired,
    /// A human approved it.
    Approved { waited: Duration, standing: bool },
    /// A human refused it.
    Refused,
    /// Nobody answered in time. A denial, deliberately.
    TimedOut(Duration),
}

/// What a reviewer is shown about a held request.
///
/// Names, never values — the same line the audit log draws. The point of naming
/// the secrets is that "this request will carry STRIPE_SECRET_KEY" is what makes
/// a yes/no meaningful.
#[derive(Debug, Clone, Serialize)]
pub struct Pending {
    pub id: String,
    pub operation: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub secrets: Vec<String>,
    /// Seconds remaining before this is denied by timeout.
    pub expires_in_seconds: u64,
}

struct Waiter {
    pending: Pending,
    decided: oneshot::Sender<Decision>,
    /// The standing-approval key, so `always` can be recorded on the way out.
    key: StandingKey,
    deadline: std::time::Instant,
}

/// What an `always` remembers. Not the path: see decision 4 in the module doc.
type StandingKey = (usize, String, String);

/// Live approval state: what is waiting, and what has been waved through for the
/// rest of this run.
pub struct ApprovalStore {
    config: ApprovalConfig,
    waiting: Mutex<HashMap<String, Waiter>>,
    standing: Mutex<BTreeSet<StandingKey>>,
    seq: AtomicU64,
    /// Signalled whenever a request starts waiting, so a prompt can render
    /// without polling.
    nudge: tokio::sync::Notify,
}

impl ApprovalStore {
    pub fn new(config: ApprovalConfig) -> ApprovalStore {
        ApprovalStore {
            config,
            waiting: Mutex::new(HashMap::new()),
            standing: Mutex::new(BTreeSet::new()),
            seq: AtomicU64::new(0),
            nudge: tokio::sync::Notify::new(),
        }
    }

    pub fn timeout(&self) -> Duration {
        self.config.timeout
    }

    /// The trigger matching this operation, with its index, if any.
    fn trigger_for(&self, host: &str, method: &str, path: &str) -> Option<(usize, &Trigger)> {
        self.config
            .require
            .iter()
            .enumerate()
            .find(|(_, t)| t.matches(host, method, path))
    }

    /// Does this operation need a human at all? Cheap, synchronous, and the
    /// answer for almost every request.
    pub fn requires(&self, host: &str, method: &str, path: &str) -> bool {
        self.trigger_for(host, method, path).is_some()
    }

    /// What a refusal should call this operation — the trigger's label, or its
    /// host when it has none. Only needed on the refusal path, which is why it is
    /// a second lookup rather than something [`Self::gate`] carries back.
    pub fn describe(&self, host: &str, method: &str, path: &str) -> String {
        self.trigger_for(host, method, path)
            .map(|(_, t)| t.describe())
            .unwrap_or_else(|| host.to_string())
    }

    /// Hold this request until somebody decides, or the timeout denies it.
    ///
    /// Returns immediately with [`Outcome::NotRequired`] when no trigger matches
    /// — the path every ordinary request takes.
    pub async fn gate(
        &self,
        host: &str,
        method: &str,
        path: &str,
        secrets: &BTreeSet<String>,
    ) -> Outcome {
        let Some((index, trigger)) = self.trigger_for(host, method, path) else {
            return Outcome::NotRequired;
        };
        let key: StandingKey = (index, host.to_ascii_lowercase(), method.to_string());
        if self.standing.lock().expect("approval lock").contains(&key) {
            return Outcome::NotRequired;
        }

        let id = format!("apr_{:08x}", self.seq.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = oneshot::channel();
        let started = std::time::Instant::now();
        let pending = Pending {
            id: id.clone(),
            operation: trigger.describe(),
            host: host.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            secrets: secrets.iter().cloned().collect(),
            expires_in_seconds: self.config.timeout.as_secs(),
        };
        self.waiting.lock().expect("approval lock").insert(
            id.clone(),
            Waiter {
                pending,
                decided: tx,
                key,
                deadline: started + self.config.timeout,
            },
        );
        self.nudge.notify_waiters();

        let decision = match tokio::time::timeout(self.config.timeout, rx).await {
            Ok(Ok(decision)) => decision,
            // The sender was dropped without deciding — treat it as the same
            // non-answer a timeout is.
            Ok(Err(_)) => Decision::Deny,
            Err(_) => {
                self.waiting.lock().expect("approval lock").remove(&id);
                return Outcome::TimedOut(started.elapsed());
            }
        };

        match decision {
            Decision::Approve => Outcome::Approved {
                waited: started.elapsed(),
                standing: false,
            },
            Decision::Always => Outcome::Approved {
                waited: started.elapsed(),
                standing: true,
            },
            Decision::Deny => Outcome::Refused,
        }
    }

    /// Answer a held request. `false` when the id is unknown — already decided,
    /// or already timed out.
    pub fn decide(&self, id: &str, decision: Decision) -> bool {
        let Some(waiter) = self.waiting.lock().expect("approval lock").remove(id) else {
            return false;
        };
        if decision == Decision::Always {
            self.standing
                .lock()
                .expect("approval lock")
                .insert(waiter.key.clone());
        }
        // The receiver is gone if the request timed out between the lookup and
        // here; that is already a denial, so there is nothing to repair.
        waiter.decided.send(decision).is_ok()
    }

    /// Everything currently waiting, oldest deadline first — the order a prompt
    /// should work through, since that is the order they expire in.
    pub fn pending(&self) -> Vec<Pending> {
        let now = std::time::Instant::now();
        let waiting = self.waiting.lock().expect("approval lock");
        let mut out: Vec<(std::time::Instant, Pending)> = waiting
            .values()
            .map(|w| {
                let mut p = w.pending.clone();
                p.expires_in_seconds = w.deadline.saturating_duration_since(now).as_secs();
                (w.deadline, p)
            })
            .collect();
        out.sort_by_key(|(deadline, _)| *deadline);
        out.into_iter().map(|(_, p)| p).collect()
    }

    /// Wait until something is pending. Used by the terminal prompt so it does
    /// not poll.
    pub async fn wait_for_pending(&self) {
        loop {
            if !self.waiting.lock().expect("approval lock").is_empty() {
                return;
            }
            self.nudge.notified().await;
        }
    }

    /// How many (rule, host, method) triples have a standing `always`.
    pub fn standing_count(&self) -> usize {
        self.standing.lock().expect("approval lock").len()
    }
}

/// The terminal prompt: the thing that makes this usable on a laptop.
///
/// Reads from stdin and answers the oldest held request, which is also the one
/// that expires first. A decision can name an id explicitly (`y apr_00000003`)
/// when several are waiting.
///
/// Only started when stdin is a terminal. In a container the control listener is
/// the whole interface, and `main.rs` refuses to start a proxy that has neither.
pub async fn prompt_loop(
    store: std::sync::Arc<ApprovalStore>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use tokio::io::AsyncBufReadExt;

    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = store.wait_for_pending() => {}
        }
        let Some(pending) = store.pending().into_iter().next() else {
            continue;
        };
        eprint!("{}", render_prompt(&pending));

        let line = tokio::select! {
            _ = shutdown.changed() => return,
            line = lines.next_line() => line,
        };
        let answer = match line {
            Ok(Some(line)) => line,
            // stdin closed: there is nobody to ask any more. Stop prompting and
            // let every held request take the timeout, which is a denial.
            Ok(None) | Err(_) => {
                tracing::warn!(
                    "stdin closed — held requests will now be refused by timeout; use the \
                     control listener to approve them"
                );
                return;
            }
        };

        let (decision, id) = match parse_answer(&answer, &pending.id) {
            Some(parsed) => parsed,
            None => {
                eprintln!("  (answer y, n, or a — optionally followed by an id)");
                continue;
            }
        };
        if !store.decide(&id, decision) {
            eprintln!("  ({id} is no longer waiting — answered already, or timed out)");
        }
    }
}

/// The question, as it appears in a terminal.
fn render_prompt(p: &Pending) -> String {
    let carries = if p.secrets.is_empty() {
        // Worth saying explicitly: "no credential" is a materially different
        // question from "carries your live Stripe key".
        "no credential".to_string()
    } else {
        p.secrets.join(", ")
    };
    format!(
        "\nseekrit-proxy: approval needed — {operation}\n  \
         {id}  {method} https://{host}{path}\n  \
         carries: {carries}\n  \
         refused automatically in {expires}s\n  \
         [y]es / [n]o / [a]lways › ",
        operation = p.operation,
        id = p.id,
        method = p.method,
        host = p.host,
        path = p.path,
        carries = carries,
        expires = p.expires_in_seconds,
    )
}

/// Parse one typed answer. `default_id` is the oldest pending request, which is
/// what a bare `y` refers to.
fn parse_answer(line: &str, default_id: &str) -> Option<(Decision, String)> {
    let mut parts = line.split_whitespace();
    let verb = parts.next()?;
    let decision = match verb.to_ascii_lowercase().as_str() {
        "y" | "yes" | "approve" => Decision::Approve,
        "n" | "no" | "deny" => Decision::Deny,
        "a" | "always" => Decision::Always,
        _ => return None,
    };
    let id = parts.next().unwrap_or(default_id).to_string();
    Some((decision, id))
}

/// `GET /approvals` — what is waiting, oldest deadline first.
///
/// On the control listener rather than anywhere the agent can reach: the pending
/// id is the only thing needed to approve a request, so handing it to the
/// workload would let it wave itself through.
pub async fn list_pending(
    axum::extract::State(state): axum::extract::State<crate::tickets::ControlState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    if let Err((status, msg)) = crate::tickets::authenticate(&state, &headers) {
        return (status, msg).into_response();
    }
    let Some(approvals) = state.approvals.as_ref() else {
        return not_configured();
    };
    axum::Json(serde_json::json!({ "pending": approvals.pending() })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct DecideRequest {
    pub decision: Decision,
}

/// `POST /approvals/{id}` — answer one held request.
pub async fn decide_pending(
    axum::extract::State(state): axum::extract::State<crate::tickets::ControlState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::Json<DecideRequest>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    if let Err((status, msg)) = crate::tickets::authenticate(&state, &headers) {
        return (status, msg).into_response();
    }
    let Some(approvals) = state.approvals.as_ref() else {
        return not_configured();
    };
    if approvals.decide(&id, body.decision) {
        tracing::info!(
            target: "seekrit_audit",
            approval = %id,
            decision = body.decision.as_str(),
            "an operator decided a held request",
        );
        axum::Json(serde_json::json!({ "decided": true, "decision": body.decision }))
            .into_response()
    } else {
        // Already answered, or already timed out — both of which are decisions
        // that have happened, so this is a 404 rather than an error.
        (
            axum::http::StatusCode::NOT_FOUND,
            format!("seekrit-proxy: no request is waiting under {id:?} — it may have been answered already, or timed out\n"),
        )
            .into_response()
    }
}

fn not_configured() -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::NOT_FOUND,
        "seekrit-proxy: this proxy has no [approval] block, so nothing ever waits\n".to_string(),
    )
        .into_response()
}

/// The refusal body for a request a human declined or ignored.
pub fn describe_refusal(outcome: &Outcome, operation: &str) -> String {
    match outcome {
        Outcome::Refused => format!("{operation} was declined by an operator"),
        Outcome::TimedOut(waited) => format!(
            "{operation} needs approval and nobody answered within {}s — refused, \
             because a request that waits long enough must not become a permitted one",
            waited.as_secs()
        ),
        // Not reachable from a refusal path; stated rather than unwrapped.
        _ => format!("{operation} was permitted"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trigger(host: &str, methods: &[&str], paths: &[&str]) -> Trigger {
        Trigger {
            host: host.to_string(),
            methods: MethodSet::new(methods.iter().map(|m| m.to_string())),
            paths: PathSet::new(paths.iter().map(|p| p.to_string())),
            label: None,
        }
    }

    fn store(require: Vec<Trigger>) -> ApprovalStore {
        ApprovalStore::new(ApprovalConfig {
            timeout: Duration::from_millis(200),
            require,
        })
    }

    fn secrets(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[tokio::test]
    async fn an_unmatched_operation_is_never_held() {
        let s = store(vec![trigger("api.stripe.com", &["POST"], &[])]);
        assert_eq!(
            s.gate("api.openai.com", "POST", "/v1/chat", &secrets(&[]))
                .await,
            Outcome::NotRequired
        );
        // Same host, method the trigger does not name.
        assert_eq!(
            s.gate("api.stripe.com", "GET", "/v1/charges", &secrets(&[]))
                .await,
            Outcome::NotRequired
        );
    }

    #[tokio::test]
    async fn approving_releases_the_request() {
        let s = std::sync::Arc::new(store(vec![trigger("api.stripe.com", &["POST"], &[])]));
        let gate = {
            let s = s.clone();
            tokio::spawn(async move {
                s.gate(
                    "api.stripe.com",
                    "POST",
                    "/v1/charges",
                    &secrets(&["STRIPE"]),
                )
                .await
            })
        };
        s.wait_for_pending().await;

        let pending = s.pending();
        assert_eq!(pending.len(), 1);
        // The prompt names the credential about to travel — the detail that makes
        // a yes/no mean something.
        assert_eq!(pending[0].secrets, vec!["STRIPE"]);
        assert!(s.decide(&pending[0].id, Decision::Approve));

        assert!(matches!(
            gate.await.unwrap(),
            Outcome::Approved {
                standing: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn denying_refuses_the_request() {
        let s = std::sync::Arc::new(store(vec![trigger("api.stripe.com", &["POST"], &[])]));
        let gate = {
            let s = s.clone();
            tokio::spawn(async move {
                s.gate("api.stripe.com", "POST", "/v1/charges", &secrets(&[]))
                    .await
            })
        };
        s.wait_for_pending().await;
        let id = s.pending()[0].id.clone();
        s.decide(&id, Decision::Deny);
        assert_eq!(gate.await.unwrap(), Outcome::Refused);
    }

    #[tokio::test]
    async fn no_answer_is_a_denial() {
        // The property that makes this a control rather than a speed bump: a
        // request that waits long enough must not become a permitted one.
        let s = store(vec![trigger("api.stripe.com", &["POST"], &[])]);
        let outcome = s
            .gate("api.stripe.com", "POST", "/v1/charges", &secrets(&[]))
            .await;
        assert!(matches!(outcome, Outcome::TimedOut(_)), "{outcome:?}");
        // And the waiter is cleaned up rather than left in the list.
        assert!(s.pending().is_empty());
    }

    #[tokio::test]
    async fn always_stops_asking_for_that_rule_host_and_method() {
        let s = std::sync::Arc::new(store(vec![trigger("api.stripe.com", &["POST"], &[])]));
        let gate = {
            let s = s.clone();
            tokio::spawn(async move {
                s.gate("api.stripe.com", "POST", "/v1/charges", &secrets(&[]))
                    .await
            })
        };
        s.wait_for_pending().await;
        let id = s.pending()[0].id.clone();
        s.decide(&id, Decision::Always);
        assert!(matches!(
            gate.await.unwrap(),
            Outcome::Approved { standing: true, .. }
        ));
        assert_eq!(s.standing_count(), 1);

        // A different path under the same rule, host and method: no longer asked.
        assert_eq!(
            s.gate("api.stripe.com", "POST", "/v1/refunds", &secrets(&[]))
                .await,
            Outcome::NotRequired
        );
    }

    #[tokio::test]
    async fn always_does_not_cover_a_different_method() {
        let s = std::sync::Arc::new(store(vec![
            trigger("api.stripe.com", &["POST"], &[]),
            trigger("api.stripe.com", &["DELETE"], &[]),
        ]));
        let gate = {
            let s = s.clone();
            tokio::spawn(async move {
                s.gate("api.stripe.com", "POST", "/v1/charges", &secrets(&[]))
                    .await
            })
        };
        s.wait_for_pending().await;
        let id = s.pending()[0].id.clone();
        s.decide(&id, Decision::Always);
        gate.await.unwrap();

        // DELETE matched a different trigger, so it is still asked about.
        let outcome = s
            .gate("api.stripe.com", "DELETE", "/v1/charges/x", &secrets(&[]))
            .await;
        assert!(matches!(outcome, Outcome::TimedOut(_)), "{outcome:?}");
    }

    #[tokio::test]
    async fn paths_narrow_which_operations_are_held() {
        let s = store(vec![trigger(
            "api.stripe.com",
            &["POST"],
            &["/v1/charges/**"],
        )]);
        assert_eq!(
            s.gate("api.stripe.com", "POST", "/v1/customers", &secrets(&[]))
                .await,
            Outcome::NotRequired
        );
    }

    #[tokio::test]
    async fn deciding_an_unknown_id_reports_it_rather_than_panicking() {
        let s = store(vec![]);
        assert!(!s.decide("apr_deadbeef", Decision::Approve));
    }

    #[tokio::test]
    async fn several_requests_queue_in_deadline_order() {
        let s = std::sync::Arc::new(ApprovalStore::new(ApprovalConfig {
            timeout: Duration::from_secs(5),
            require: vec![trigger("api.stripe.com", &[], &[])],
        }));
        for path in ["/first", "/second"] {
            let s = s.clone();
            tokio::spawn(
                async move { s.gate("api.stripe.com", "POST", path, &secrets(&[])).await },
            );
            // Distinct deadlines, so the ordering assertion is about the sort and
            // not about which task happened to be scheduled first.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        s.wait_for_pending().await;
        let pending = s.pending();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].path, "/first");
        assert_eq!(pending[1].path, "/second");
    }

    #[test]
    fn answers_are_parsed_with_the_oldest_as_the_default() {
        assert_eq!(
            parse_answer("y", "apr_1"),
            Some((Decision::Approve, "apr_1".to_string()))
        );
        assert_eq!(
            parse_answer("ALWAYS", "apr_1"),
            Some((Decision::Always, "apr_1".to_string()))
        );
        // Naming an id answers that one instead of the oldest.
        assert_eq!(
            parse_answer("n apr_7", "apr_1"),
            Some((Decision::Deny, "apr_7".to_string()))
        );
        assert_eq!(parse_answer("", "apr_1"), None);
        assert_eq!(parse_answer("maybe", "apr_1"), None);
    }

    #[test]
    fn the_prompt_names_the_credential_or_says_there_is_none() {
        let mut p = Pending {
            id: "apr_1".into(),
            operation: "money movement".into(),
            host: "api.stripe.com".into(),
            method: "POST".into(),
            path: "/v1/charges".into(),
            secrets: vec!["STRIPE_SECRET_KEY".into()],
            expires_in_seconds: 120,
        };
        let with = render_prompt(&p);
        assert!(with.contains("money movement"), "{with}");
        assert!(with.contains("STRIPE_SECRET_KEY"), "{with}");
        assert!(with.contains("120s"), "{with}");

        // "no credential" is a materially different question from a live key.
        p.secrets.clear();
        assert!(render_prompt(&p).contains("no credential"));
    }

    #[test]
    fn a_refusal_says_which_operation_and_why() {
        let timed_out = describe_refusal(&Outcome::TimedOut(Duration::from_secs(120)), "a refund");
        assert!(timed_out.contains("a refund"), "{timed_out}");
        assert!(timed_out.contains("120s"), "{timed_out}");
        let declined = describe_refusal(&Outcome::Refused, "a refund");
        assert!(declined.contains("declined"), "{declined}");
    }
}
