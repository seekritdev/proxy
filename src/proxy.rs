//! The data plane: a reverse proxy that rewrites `{{seekrit:NAME}}`
//! placeholders in each request (path, headers, body) into decrypted values,
//! then forwards to the route's upstream and streams the response straight back.
//!
//! Only the **request** is rewritten; the response is streamed untouched, so
//! SSE / streaming APIs work without buffering. Substitution is gated by the
//! route's allowlist (default-deny) — the property that stops the proxy being
//! an exfiltration oracle: a secret can only reach the upstream(s) declared for
//! it.
//!
//! The gate is wider than the allowlist now: a rule may also bound the
//! **methods** and **paths** an agent may reach on that upstream, which turns
//! the check from anti-theft into anti-misuse (an agent with a legitimate
//! credential still cannot `DELETE /v1/files/…`). Rules come either from this
//! deployment's config or from a signed bundle published in the dashboard, and
//! both are evaluated by the same code in `seekrit_core::policy`.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use tracing::{info, warn};

use arc_swap::ArcSwap;

use seekrit_core::policy::{Decision, Rule};

use crate::activity::{ActivityLog, Cell};
use crate::config::Config;
use crate::policy::{now_secs, Gate, PolicyStore};
use crate::ratchet::{RatchetStore, DEFAULT_SESSION};
use crate::secrets::SecretStore;
use crate::substitute::{substitute, Lookup, SubError};
use crate::tasks::SessionResolver;
use crate::telemetry::{Metrics, PLANE_REVERSE};
use crate::tickets::{ticket_from_headers, TICKET_HEADER};

/// Shared state handed to every request. Cheap to clone (all `Arc`/handles).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    /// Swappable so a proxy that started from the last-known-good cache can be
    /// upgraded to live secrets without a restart (see `main.rs`'s reconnect
    /// task). Readers take a snapshot per request and never block.
    pub store: Arc<ArcSwap<SecretStore>>,
    pub client: reqwest::Client,
    pub metrics: Arc<Metrics>,
    /// Server-delivered policy, in `[policy] source = "server"` mode. `None`
    /// means the rules come from the config and never change.
    pub policy: Option<Arc<PolicyStore>>,
    /// Resolves whatever a request presented in `x-seekrit-ticket`: a locally
    /// minted ticket, a task dispatched through the API, or nothing.
    pub sessions: Arc<SessionResolver>,
    /// Trust ratchet, when `[ratchet]` is configured. Holds per-run state, so it
    /// is shared with the forward plane rather than cloned.
    pub ratchet: Option<Arc<RatchetStore>>,
    /// Aggregate decision counts awaiting their next flush, when `[activity]` is
    /// configured. Shared with the forward plane: one ledger per proxy.
    pub activity: Option<Arc<ActivityLog>>,
}

/// Build the proxy router: a single fallback that handles every method/path.
pub fn router(state: AppState) -> axum::Router {
    axum::Router::new().fallback(handle).with_state(state)
}

async fn handle(State(state): State<AppState>, req: Request) -> Response {
    // Continue the caller's trace when they sent one, so a proxied call shows up
    // as a child of the workload's own span rather than a detached root.
    let span = tracing::info_span!(
        "seekrit-proxy request",
        "http.request.method" = %req.method(),
        { seekrit_telemetry::attr::UPSTREAM_HOST } = tracing::field::Empty,
        { seekrit_telemetry::attr::ROUTE_PREFIX } = tracing::field::Empty,
        { seekrit_telemetry::attr::SECRET_NAMES } = tracing::field::Empty,
        { seekrit_telemetry::attr::DENY_REASON } = tracing::field::Empty,
        "http.response.status_code" = tracing::field::Empty,
    );
    seekrit_telemetry::set_parent_context(&span, seekrit_telemetry::extract_context(req.headers()));

    let metrics = state.metrics.clone();
    let result = {
        let _enter = span.enter();
        forward(state, req, &span).await
    };

    match result {
        Ok(resp) => {
            span.record("http.response.status_code", resp.status().as_u16());
            resp
        }
        Err(rej) => {
            metrics.record_request(PLANE_REVERSE, rej.outcome());
            if let Some(reason) = rej.deny_reason() {
                span.record(seekrit_telemetry::attr::DENY_REASON, reason);
            }
            let resp = rej.into_response();
            span.record("http.response.status_code", resp.status().as_u16());
            resp
        }
    }
}

/// Reasons a request is refused before (or instead of) reaching the upstream.
enum Reject {
    NoRoute,
    Denied(String),
    Unknown(String),
    BadRequest(String),
    Upstream(String),
    /// The operation itself is not permitted (method, path, or no rule at all) —
    /// refused before any placeholder is considered.
    Operation(Decision),
    /// Server policy is configured but not usable right now: expired, or the
    /// request named an agent identity this deployment does not serve.
    NoPolicy(String),
    /// The trust ratchet withdrew this capability earlier in the run. A separate
    /// variant from `Operation` on purpose: policy still permits it, so a refusal
    /// that read like a policy denial would send someone to edit the wrong file.
    Ratchet(String),
}

impl From<SubError> for Reject {
    fn from(e: SubError) -> Self {
        match e {
            SubError::Denied(n) => Reject::Denied(n),
            SubError::Unknown(n) => Reject::Unknown(n),
        }
    }
}

impl Reject {
    /// Fixed-cardinality label for the request metric.
    fn outcome(&self) -> &'static str {
        match self {
            Reject::NoRoute => "no_route",
            Reject::Denied(_) | Reject::Unknown(_) => "denied",
            Reject::BadRequest(_) => "bad_request",
            Reject::Upstream(_) => "upstream_error",
            Reject::Operation(_) => "denied",
            Reject::NoPolicy(_) => "no_policy",
            Reject::Ratchet(_) => "ratchet",
        }
    }

    /// Why a placeholder was refused, for the span. The secret *name* is
    /// already logged by `into_response`; this is the category.
    fn deny_reason(&self) -> Option<&'static str> {
        match self {
            Reject::Denied(_) => Some("not_allowed"),
            Reject::Unknown(_) => Some("unknown_secret"),
            // The policy engine's own vocabulary, so a dashboard simulation and
            // a real refusal read the same.
            Reject::Operation(d) => Some(d.reason()),
            Reject::NoPolicy(_) => Some("policy_unavailable"),
            Reject::Ratchet(_) => Some("ratchet_withdrawn"),
            _ => None,
        }
    }
}

impl IntoResponse for Reject {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            Reject::NoRoute => (
                StatusCode::NOT_FOUND,
                "no route matches this path".to_string(),
            ),
            Reject::Denied(n) => {
                warn!(secret = %n, "denied: placeholder not allowed toward this upstream");
                (
                    StatusCode::FORBIDDEN,
                    format!("placeholder {{{{seekrit:{n}}}}} is not allowed toward this upstream"),
                )
            }
            Reject::Unknown(n) => {
                warn!(secret = %n, "denied: placeholder references an unavailable secret");
                (
                    StatusCode::FORBIDDEN,
                    format!(
                        "placeholder {{{{seekrit:{n}}}}} references a secret that is not available"
                    ),
                )
            }
            Reject::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            Reject::Upstream(m) => {
                warn!(error = %m, "upstream request failed");
                (
                    StatusCode::BAD_GATEWAY,
                    format!("upstream request failed: {m}"),
                )
            }
            Reject::Operation(decision) => {
                warn!(
                    reason = decision.reason(),
                    "denied: operation not permitted"
                );
                (StatusCode::FORBIDDEN, describe_operation(decision))
            }
            Reject::NoPolicy(m) => {
                warn!(error = %m, "denied: no usable policy");
                (StatusCode::FORBIDDEN, m)
            }
            Reject::Ratchet(m) => {
                warn!(reason = "ratchet", "denied: withdrawn earlier in this run");
                (StatusCode::FORBIDDEN, m)
            }
        };
        (status, format!("seekrit-proxy: {msg}\n")).into_response()
    }
}

/// Note one authorization outcome in the activity ledger.
///
/// A free function rather than a method so the denial sites can call it before a
/// `return`, which is the only place each of them knows both the host and *why*.
/// No-op when `[activity]` is not configured.
fn note(
    state: &AppState,
    host: &str,
    method: &str,
    decision: &'static str,
    rule_index: Option<usize>,
) {
    if let Some(log) = state.activity.as_ref() {
        log.record(
            Cell {
                host: host.to_string(),
                method: method.to_string(),
                decision,
                rule_index,
            },
            &[],
        );
    }
}

async fn forward(state: AppState, req: Request, span: &tracing::Span) -> Result<Response, Reject> {
    let (parts, body) = req.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let path = uri.path();

    let route = state.config.match_route(path).ok_or(Reject::NoRoute)?;
    span.record(seekrit_telemetry::attr::UPSTREAM_HOST, &route.host);
    span.record(seekrit_telemetry::attr::ROUTE_PREFIX, &route.prefix);

    // The upstream-facing path is what a rule is written against, so authorize
    // against the *stripped* path — the same string the upstream will see.
    let rest = route.strip(path);

    // Resolve what the request presented (if anything) before policy: it decides
    // which agent identity this request is, and can only narrow what that
    // identity may do. A ticket resolves locally; a dispatched task costs one
    // (cached) call to the API, and failing to verify one refuses the request.
    let presented = ticket_from_headers(&parts.headers);
    let session = state.sessions.resolve(presented).await.map_err(|e| {
        note(
            &state,
            &route.host,
            method.as_str(),
            "policy_unavailable",
            None,
        );
        Reject::NoPolicy(e)
    })?;
    let scopes = session.as_ref().and_then(|s| s.scopes.as_ref());

    // Ratchet state is per run, keyed by whatever credential identifies it.
    let session_key = presented.unwrap_or(DEFAULT_SESSION);
    let ratchet = state.ratchet.as_ref().map(|r| r.gate(session_key));

    // Whichever policy source is in force, one evaluator answers.
    let snapshot = match state.policy.as_ref() {
        Some(policy) => {
            let agent = session.as_ref().map(|s| s.agent.as_str());
            Some(policy.snapshot(agent).ok_or_else(|| {
                note(
                    &state,
                    &route.host,
                    method.as_str(),
                    "policy_unavailable",
                    None,
                );
                Reject::NoPolicy(format!(
                    "no policy is loaded for agent {:?}",
                    agent.unwrap_or("<default>")
                ))
            })?)
        }
        None => None,
    };
    let now = now_secs();
    let rules = match (route.rules.as_ref(), snapshot.as_ref()) {
        (Some(local), _) => local,
        (None, Some(snap)) => {
            span.record(seekrit_telemetry::attr::POLICY_VERSION, snap.version as i64);
            span.record(
                seekrit_telemetry::attr::AGENT_IDENTITY,
                snap.agent_id.as_str(),
            );
            snap.active_rules(now).ok_or_else(|| {
                note(
                    &state,
                    &route.host,
                    method.as_str(),
                    "policy_unavailable",
                    None,
                );
                Reject::NoPolicy(format!(
                    "the policy published for this agent expired at {}; republish it",
                    snap.expires_at
                ))
            })?
        }
        // Server mode with no snapshot cannot happen (startup fails closed), but
        // saying so beats permitting a request on an absent policy.
        (None, None) => return Err(Reject::NoPolicy("no policy is loaded".into())),
    };

    let rule: &Rule = match rules.find(&route.host, method.as_str(), rest) {
        Some((index, rule)) => {
            span.record(seekrit_telemetry::attr::POLICY_RULE, index as i64);
            rule
        }
        None => {
            let verdict = rules.evaluate(&route.host, method.as_str(), rest);
            note(
                &state,
                &route.host,
                method.as_str(),
                verdict.decision.reason(),
                verdict.rule_index,
            );
            return Err(Reject::Operation(verdict.decision));
        }
    };

    // The ratchet is an overlay on top of policy, applied after it and only ever
    // subtracting: a run that has already touched something protected loses
    // hosts it would otherwise still be permitted.
    if let Some(gate) = ratchet.as_ref() {
        span.record(seekrit_telemetry::attr::RATCHET_STATE, gate.state.as_str());
        if !gate.permits_host(&route.host) {
            note(
                &state,
                &route.host,
                method.as_str(),
                "ratchet_withdrawn",
                None,
            );
            return Err(Reject::Ratchet(gate.describe_refusal(&route.host)));
        }
    }
    let narrowed = ratchet.as_ref().map(|g| g.narrow(scopes));
    let effective_scopes = match narrowed.as_ref() {
        Some(inner) => inner.as_ref(),
        None => scopes,
    };

    // Permitted — so if this request is a declared protected event, the run
    // narrows now, before the response is fetched. Early is the safe direction.
    if let (Some(store), Some(_)) = (state.ratchet.as_ref(), ratchet.as_ref()) {
        if let Some(advance) = store.advance(session_key, &route.host, method.as_str(), rest) {
            tracing::info!(
                state = %advance.state,
                by = %advance.by,
                "trust ratchet narrowed this run"
            );
        }
    }

    // Per-request lookup: default-deny, then resolve. Values are cloned into the
    // rewritten bytes; nothing here is logged.
    let gate = Gate::new(rule, effective_scopes);
    let store = state.store.load_full();
    let store = store.as_ref();
    let rule_index = rules
        .find(&route.host, method.as_str(), rest)
        .map(|(i, _)| i);
    let activity = state.activity.clone();
    let cell = |decision: &'static str| Cell {
        host: route.host.clone(),
        method: method.as_str().to_string(),
        decision,
        rule_index,
    };
    let lookup = |name: &str| -> Lookup {
        if !gate.permits(name) {
            // Recorded here rather than at the response, which is the only place
            // that knows *which* placeholder was refused — and a review wants the
            // name, since "the agent keeps reaching for a secret it may not use"
            // is the clearest under-permission signal there is.
            if let Some(log) = activity.as_ref() {
                log.record(
                    cell("secret_not_allowed"),
                    std::slice::from_ref(&name.to_string()),
                );
            }
            return Lookup::Denied;
        }
        match store.get(name) {
            Some(v) => Lookup::Value(v.to_string()),
            None => {
                if let Some(log) = activity.as_ref() {
                    log.record(
                        cell("unknown_secret"),
                        std::slice::from_ref(&name.to_string()),
                    );
                }
                Lookup::Unknown
            }
        }
    };

    let mut injected: BTreeSet<String> = BTreeSet::new();

    // 1. Path + query. Substitute over the stripped path.
    let target_pq = match uri.query() {
        Some(q) => format!("{rest}?{q}"),
        None => rest.to_string(),
    };
    let pq_out = substitute(target_pq.as_bytes(), &lookup)?;
    injected.extend(pq_out.names);
    let target_pq = String::from_utf8(pq_out.bytes)
        .map_err(|_| Reject::BadRequest("path is not valid UTF-8 after substitution".into()))?;
    let url = format!("{}{}", route.upstream, target_pq);

    // 2. Headers. Copy everything except hop-by-hop + Host/Content-Length,
    //    substituting inside each value (this is where API keys usually live).
    let mut fwd = HeaderMap::with_capacity(parts.headers.len());
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name) || *name == header::HOST || *name == header::CONTENT_LENGTH {
            continue;
        }
        // The session ticket is between the agent and this proxy; an upstream has
        // no business seeing it.
        if name.as_str().eq_ignore_ascii_case(TICKET_HEADER) {
            continue;
        }
        let out = substitute(value.as_bytes(), &lookup)?;
        injected.extend(out.names);
        let hv = HeaderValue::from_bytes(&out.bytes).map_err(|_| {
            Reject::BadRequest(format!("header {name} became invalid after substitution"))
        })?;
        fwd.insert(name.clone(), hv);
    }

    // 3. Body. Buffered (capped) so placeholders can be substituted, then sent.
    let body_bytes = axum::body::to_bytes(body, state.config.max_body)
        .await
        .map_err(|e| {
            Reject::BadRequest(format!(
                "could not buffer request body (limit {} bytes): {e}",
                state.config.max_body
            ))
        })?;
    let body_out = substitute(body_bytes.as_ref(), &lookup)?;
    injected.extend(body_out.names);

    // Audit: names + upstream only, never values. This is the substitution log,
    // and the span records exactly the same fields for the same reason.
    if !injected.is_empty() {
        info!(
            target: "seekrit_audit",
            %method,
            upstream = %route.host,
            path = %rest,
            secrets = ?injected,
            "injected secret(s) into request",
        );
        span.record(
            seekrit_telemetry::attr::SECRET_NAMES,
            injected.iter().cloned().collect::<Vec<_>>().join(","),
        );
        state.metrics.record_injections(&route.host, injected.len());
    }
    if let Some(log) = state.activity.as_ref() {
        // Outside the `injected.is_empty()` guard above: a permitted request that
        // carried no placeholder still proves its rule is in use, and a review
        // that missed those would propose deleting working rules.
        log.record(cell("allow"), &injected.iter().cloned().collect::<Vec<_>>());
    }

    // Opt-in (see `Config::propagate_trace_upstream`): most upstreams here are
    // third-party APIs that gain nothing from our trace ids.
    if state.config.propagate_trace_upstream {
        seekrit_telemetry::inject_context(&seekrit_telemetry::current_context(), &mut fwd);
    }

    let started = std::time::Instant::now();
    let resp = state
        .client
        .request(method, &url)
        .headers(fwd)
        .body(body_out.bytes)
        .send()
        .await
        .map_err(|e| Reject::Upstream(e.to_string()))?;
    state
        .metrics
        .record_upstream_duration(&route.host, started.elapsed().as_secs_f64() * 1000.0);
    state.metrics.record_request(PLANE_REVERSE, "forwarded");

    // Stream the response back untouched (drop hop-by-hop + framing headers so
    // hyper re-frames it for the downstream connection).
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let mut out = Response::new(Body::from_stream(resp.bytes_stream()));
    *out.status_mut() = status;
    let h = out.headers_mut();
    for (name, value) in resp_headers.iter() {
        if is_hop_by_hop(name)
            || *name == header::CONTENT_LENGTH
            || *name == header::TRANSFER_ENCODING
        {
            continue;
        }
        h.insert(name.clone(), value.clone());
    }
    Ok(out)
}

/// The 403 body for an operation refusal.
///
/// Names the constraint that decided rather than saying "denied": a default-deny
/// policy fails in exactly the confusing direction, and an agent's operator is
/// usually reading this line in a log at 1am.
pub fn describe_operation(decision: Decision) -> String {
    match decision {
        Decision::Allow => "permitted".to_string(),
        Decision::NoRule => "no policy rule covers this upstream".to_string(),
        Decision::MethodNotAllowed => {
            "this method is not permitted toward this upstream".to_string()
        }
        Decision::PathNotAllowed => "this path is not permitted toward this upstream".to_string(),
        Decision::SecretNotAllowed => {
            "that secret is not permitted toward this upstream".to_string()
        }
    }
}

/// Hop-by-hop headers (RFC 7230 §6.1) must not be forwarded by a proxy.
fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}
