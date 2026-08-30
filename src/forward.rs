//! The forward-proxy + TLS-interception data plane (the `HTTPS_PROXY` model).
//!
//! A workload sets `HTTPS_PROXY=http://127.0.0.1:PORT` and trusts our CA. Then:
//!
//! - **HTTPS** arrives as `CONNECT host:443`. For a host with a rule we hijack
//!   the tunnel, terminate TLS with a leaf cert minted for that host (so we can
//!   read the plaintext request), substitute `{{seekrit:NAME}}`, and re-originate
//!   a real TLS request to the upstream. Hosts without a rule are blind-tunneled
//!   (default) or refused (`deny`) — we never MITM traffic we have no reason to.
//! - **HTTP** arrives as an absolute-form request (`GET http://host/…`). No TLS;
//!   we substitute (for ruled hosts) and forward.
//!
//! The substitution engine, secret store, and allowlist are shared with the
//! reverse proxy; only the transport differs. Same default-deny guarantee: a
//! secret is only ever injected toward a host whose rule lists it.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use seekrit_core::policy::Decision;

use crate::activity::{ActivityLog, Cell};
use crate::config::{Config, UnmatchedPolicy};
use crate::policy::{now_secs, Gate, PolicyStore};
use crate::proxy::describe_operation;
use crate::ratchet::{RatchetStore, DEFAULT_SESSION};
use crate::secrets::SecretStore;
use crate::substitute::{substitute, Lookup, SubError};
use crate::tasks::SessionResolver;
use crate::telemetry::PLANE_FORWARD;
use crate::tickets::{ticket_from_headers, TICKET_HEADER};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = BoxBody<Bytes, BoxError>;

/// Shared state for the forward listener. Cheap to clone.
#[derive(Clone)]
pub struct ForwardState {
    pub config: Arc<Config>,
    /// See [`crate::proxy::AppState::store`] — swapped in place on reconnect.
    pub store: Arc<ArcSwap<SecretStore>>,
    pub client: reqwest::Client,
    pub ca: Arc<crate::ca::Ca>,
    pub metrics: Arc<crate::telemetry::Metrics>,
    /// Server-delivered policy in `[policy] source = "server"` mode; `None` when
    /// the rules come from the config file.
    pub policy: Option<Arc<PolicyStore>>,
    /// Resolves whatever a request presented in `x-seekrit-ticket` — a local
    /// ticket or a task dispatched through the API.
    pub sessions: Arc<SessionResolver>,
    /// Trust ratchet, when `[ratchet]` is configured. Shared with the reverse
    /// plane: one run's state must not depend on which plane it used.
    pub ratchet: Option<Arc<RatchetStore>>,
    /// Aggregate decision counts, shared with the reverse plane — one ledger per
    /// proxy, so a review sees both planes' traffic together.
    pub activity: Option<Arc<ActivityLog>>,
}

impl ForwardState {
    /// Note one authorization outcome. Mirrors `note` in `proxy.rs`; kept as a
    /// method here because this plane's decisions all happen inside `authorize`.
    fn note(&self, host: &str, method: &str, decision: &'static str, rule_index: Option<usize>) {
        if let Some(log) = self.activity.as_ref() {
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
}

/// Why the forward plane refused a request before it reached an upstream.
enum ForwardReject {
    /// The operation is not permitted (method, path, or no rule for this host).
    Operation(Decision),
    /// Policy is configured but unusable: expired, or an unknown ticket/identity.
    NoPolicy(String),
    /// Withdrawn earlier in this run by the trust ratchet. Distinct from
    /// `Operation` because policy still permits it — the run does not.
    Ratchet(String),
}

impl ForwardReject {
    fn into_response(self, state: &ForwardState) -> Response<Body> {
        let (reason, message) = match self {
            ForwardReject::Operation(d) => (d.reason(), describe_operation(d)),
            ForwardReject::NoPolicy(m) => ("policy_unavailable", m),
            ForwardReject::Ratchet(m) => ("ratchet_withdrawn", m),
        };
        warn!(reason, "denied: {message}");
        tracing::Span::current().record(seekrit_telemetry::attr::DENY_REASON, reason);
        state.metrics.record_request(PLANE_FORWARD, "denied");
        text(StatusCode::FORBIDDEN, &message)
    }
}

impl ForwardState {
    /// Does *anything* this deployment enforces mention this host? Decided at
    /// `CONNECT`, before a request (and so before its ticket) exists — see
    /// [`PolicyStore::covers_host_any`].
    fn intercepts(&self, host: &str) -> bool {
        match (self.fwd().rules.as_ref(), self.policy.as_ref()) {
            (Some(rules), _) => rules.covers_host(host),
            (None, Some(policy)) => policy.covers_host_any(host),
            (None, None) => false,
        }
    }

    /// Authorize one request on a ruled host, yielding the injection gate.
    ///
    /// Both planes ask the same question through the same evaluator; the only
    /// difference is that here the path is the whole request path (there is no
    /// route prefix to strip).
    async fn authorize(
        &self,
        host: &str,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
    ) -> Result<Gate, ForwardReject> {
        // Resolved before anything is borrowed from a policy snapshot, so the
        // one await here does not straddle a guard.
        let presented = ticket_from_headers(headers);
        let session = self.sessions.resolve(presented).await.map_err(|e| {
            self.note(host, method.as_str(), "policy_unavailable", None);
            ForwardReject::NoPolicy(e)
        })?;
        let scopes = session.as_ref().and_then(|s| s.scopes.as_ref());
        let session_key = presented.unwrap_or(DEFAULT_SESSION);
        let ratchet = self.ratchet.as_ref().map(|r| r.gate(session_key));

        // Hold the snapshot for as long as the rule borrowed from it is in use.
        let snapshot = match self.policy.as_ref() {
            Some(policy) => {
                let agent = session.as_ref().map(|s| s.agent.as_str());
                Some(policy.snapshot(agent).ok_or_else(|| {
                    self.note(host, method.as_str(), "policy_unavailable", None);
                    ForwardReject::NoPolicy(format!(
                        "no policy is loaded for agent {:?}",
                        agent.unwrap_or("<default>")
                    ))
                })?)
            }
            None => None,
        };
        let now = now_secs();
        let rules = match (self.fwd().rules.as_ref(), snapshot.as_ref()) {
            (Some(local), _) => local,
            (None, Some(snap)) => {
                let span = tracing::Span::current();
                span.record(seekrit_telemetry::attr::POLICY_VERSION, snap.version as i64);
                span.record(
                    seekrit_telemetry::attr::AGENT_IDENTITY,
                    snap.agent_id.as_str(),
                );
                snap.active_rules(now).ok_or_else(|| {
                    self.note(host, method.as_str(), "policy_unavailable", None);
                    ForwardReject::NoPolicy(format!(
                        "the policy published for this agent expired at {}; republish it",
                        snap.expires_at
                    ))
                })?
            }
            (None, None) => return Err(ForwardReject::NoPolicy("no policy is loaded".into())),
        };

        let rule = match rules.find(host, method.as_str(), path) {
            Some((index, rule)) => {
                tracing::Span::current().record(seekrit_telemetry::attr::POLICY_RULE, index as i64);
                rule
            }
            None => {
                let verdict = rules.evaluate(host, method.as_str(), path);
                self.note(
                    host,
                    method.as_str(),
                    verdict.decision.reason(),
                    verdict.rule_index,
                );
                return Err(ForwardReject::Operation(verdict.decision));
            }
        };

        // Policy permitted it; the ratchet may still have taken it away earlier
        // in this run. Overlay, applied after policy, only ever subtracting.
        if let Some(gate) = ratchet.as_ref() {
            tracing::Span::current()
                .record(seekrit_telemetry::attr::RATCHET_STATE, gate.state.as_str());
            if !gate.permits_host(host) {
                self.note(host, method.as_str(), "ratchet_withdrawn", None);
                return Err(ForwardReject::Ratchet(gate.describe_refusal(host)));
            }
        }
        let narrowed = ratchet.as_ref().map(|g| g.narrow(scopes));
        let effective = match narrowed.as_ref() {
            Some(inner) => inner.as_ref(),
            None => scopes,
        };
        let gate = Gate::new(rule, effective);

        // Permitted — so a declared protected event narrows the run now, before
        // the response exists. See the module comment in `ratchet.rs` for why
        // early rather than on response release.
        if let Some(store) = self.ratchet.as_ref() {
            if let Some(advance) = store.advance(session_key, host, method.as_str(), path) {
                tracing::info!(
                    state = %advance.state,
                    by = %advance.by,
                    "trust ratchet narrowed this run"
                );
            }
        }
        Ok(gate)
    }

    fn fwd(&self) -> &crate::config::ForwardConfig {
        self.config
            .forward
            .as_ref()
            .expect("forward listener started without [forward] config")
    }
}

/// Accept loop for the forward proxy. Runs until `shutdown` resolves.
pub async fn serve<F: std::future::Future<Output = ()>>(
    listener: TcpListener,
    state: ForwardState,
    shutdown: F,
) {
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (tcp, _peer) = match accepted {
                    Ok(x) => x,
                    Err(e) => { debug!("accept error: {e}"); continue; }
                };
                let st = state.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(tcp);
                    let svc = service_fn(move |req| outer(req, st.clone()));
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, svc)
                        .with_upgrades()
                        .await
                    {
                        debug!("connection error: {e}");
                    }
                });
            }
        }
    }
}

/// First-hop dispatch: CONNECT (HTTPS) vs. absolute-form (HTTP).
async fn outer(req: Request<Incoming>, state: ForwardState) -> Result<Response<Body>, Infallible> {
    if req.method() == Method::CONNECT {
        Ok(handle_connect(req, state))
    } else {
        Ok(handle_absolute_http(req, state).await)
    }
}

/// Handle `CONNECT host:port`: establish the tunnel, then either MITM (ruled
/// host), blind-tunnel (unmatched + tunnel policy), or refuse (deny policy).
fn handle_connect(req: Request<Incoming>, state: ForwardState) -> Response<Body> {
    let Some(authority) = req.uri().authority().cloned() else {
        return text(StatusCode::BAD_REQUEST, "CONNECT requires an authority");
    };
    let host = authority.host().to_ascii_lowercase();
    let port = authority.port_u16().unwrap_or(443);

    let is_ruled = state.intercepts(&host);
    if is_ruled {
        // MITM: on upgrade, terminate TLS with a minted cert and serve.
        let st = state.clone();
        let host_c = host.clone();
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = mitm_serve(upgraded, host_c, port, st).await {
                        debug!("mitm connection ended: {e}");
                    }
                }
                Err(e) => debug!("CONNECT upgrade failed: {e}"),
            }
        });
        return established();
    }

    match state.fwd().unmatched {
        UnmatchedPolicy::Deny => text(
            StatusCode::FORBIDDEN,
            &format!("host {host:?} has no rule and unmatched_host_policy = deny"),
        ),
        UnmatchedPolicy::Tunnel => {
            // Blind-tunnel: never decrypt, just splice bytes to the real host.
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = blind_tunnel(upgraded, host, port).await {
                            debug!("tunnel ended: {e}");
                        }
                    }
                    Err(e) => debug!("CONNECT upgrade failed: {e}"),
                }
            });
            established()
        }
    }
}

/// After the CONNECT tunnel is up: TLS-accept with the host's minted cert, then
/// serve HTTP over the decrypted stream, injecting into each request.
async fn mitm_serve(
    upgraded: Upgraded,
    host: String,
    port: u16,
    state: ForwardState,
) -> Result<(), BoxError> {
    let server_config = state.ca.server_config(&host)?;
    let acceptor = TlsAcceptor::from(server_config);
    let tls = acceptor.accept(TokioIo::new(upgraded)).await?;

    let host = Arc::new(host);
    let svc = service_fn(move |req| {
        let st = state.clone();
        let host = host.clone();
        async move { Ok::<_, Infallible>(mitm_forward(req, host, port, st).await) }
    });
    http1::Builder::new()
        .serve_connection(TokioIo::new(tls), svc)
        .await?;
    Ok(())
}

/// Splice an unmatched CONNECT tunnel straight to its destination, untouched.
async fn blind_tunnel(upgraded: Upgraded, host: String, port: u16) -> std::io::Result<()> {
    let mut client = TokioIo::new(upgraded);
    let mut server = TcpStream::connect((host.as_str(), port)).await?;
    tokio::io::copy_bidirectional(&mut client, &mut server).await?;
    Ok(())
}

/// One decrypted HTTPS request on a MITM'd tunnel — inject and forward over TLS.
async fn mitm_forward(
    req: Request<Incoming>,
    host: Arc<String>,
    port: u16,
    state: ForwardState,
) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let pq = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // Only ruled hosts are intercepted, so policy must have something to say —
    // but *what* it says now depends on the method and path too, and on the
    // session ticket this request carries.
    let path = pq.split('?').next().unwrap_or("/");
    let gate = match state
        .authorize(host.as_str(), &parts.method, path, &parts.headers)
        .await
    {
        Ok(gate) => gate,
        Err(rej) => return rej.into_response(&state),
    };

    let body_bytes = match read_limited(body, state.config.max_body).await {
        Ok(b) => b,
        Err(()) => return text(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };
    // Preserve a non-default port so non-443 HTTPS upstreams work.
    let base_url = if port == 443 {
        format!("https://{host}")
    } else {
        format!("https://{host}:{port}")
    };
    inject_and_forward(
        &state,
        parts.method,
        &base_url,
        &pq,
        &parts.headers,
        body_bytes,
        Some(&gate),
        host.as_str(),
    )
    .await
}

/// Handle an absolute-form HTTP proxy request (`GET http://host/…`).
async fn handle_absolute_http(req: Request<Incoming>, state: ForwardState) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let uri = parts.uri.clone();

    let (Some(scheme), Some(host)) = (uri.scheme_str(), uri.host()) else {
        return text(
            StatusCode::BAD_REQUEST,
            "expected an absolute-form request — configure this as your HTTP proxy",
        );
    };
    if scheme != "http" {
        return text(
            StatusCode::BAD_REQUEST,
            "only http:// is handled here; https must arrive via CONNECT",
        );
    }
    let host = host.to_ascii_lowercase();
    let authority = match uri.port_u16() {
        Some(p) => format!("{host}:{p}"),
        None => host.clone(),
    };
    let base_url = format!("http://{authority}");
    let pq = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // Decide policy for this host. `gate = None` means blind pass-through.
    let gate: Option<Gate> = if state.intercepts(&host) {
        let path = pq.split('?').next().unwrap_or("/");
        match state
            .authorize(&host, &parts.method, path, &parts.headers)
            .await
        {
            Ok(gate) => Some(gate),
            Err(rej) => return rej.into_response(&state),
        }
    } else {
        match state.fwd().unmatched {
            UnmatchedPolicy::Deny => {
                return text(
                    StatusCode::FORBIDDEN,
                    &format!("host {host:?} has no rule and unmatched_host_policy = deny"),
                )
            }
            UnmatchedPolicy::Tunnel => None,
        }
    };

    let body_bytes = match read_limited(body, state.config.max_body).await {
        Ok(b) => b,
        Err(()) => return text(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };
    inject_and_forward(
        &state,
        parts.method,
        &base_url,
        &pq,
        &parts.headers,
        body_bytes,
        gate.as_ref(),
        &host,
    )
    .await
}

/// The shared inject-then-forward core. `gate = Some(..)` substitutes and audits;
/// `gate = None` forwards verbatim (blind pass-through of an unruled host).
#[allow(clippy::too_many_arguments)]
async fn inject_and_forward(
    state: &ForwardState,
    method: Method,
    base_url: &str,
    path_and_query: &str,
    in_headers: &HeaderMap,
    body: Bytes,
    gate: Option<&Gate>,
    audit_host: &str,
) -> Response<Body> {
    // Continue the workload's trace when it sent one. On this plane the request
    // arrived through CONNECT + TLS interception, so `in_headers` are the real
    // decrypted request headers.
    let span = tracing::info_span!(
        "seekrit-proxy forward",
        "http.request.method" = %method,
        { seekrit_telemetry::attr::UPSTREAM_HOST } = %audit_host,
        { seekrit_telemetry::attr::SECRET_NAMES } = tracing::field::Empty,
        { seekrit_telemetry::attr::DENY_REASON } = tracing::field::Empty,
        "http.response.status_code" = tracing::field::Empty,
    );
    seekrit_telemetry::set_parent_context(&span, seekrit_telemetry::extract_context(in_headers));
    let _enter = span.enter();

    let store = state.store.load_full();
    let store = store.as_ref();
    let mut injected: BTreeSet<String> = BTreeSet::new();

    // 1. Path + query.
    let target_pq = match gate {
        Some(gate) => {
            let lookup = mk_lookup(gate, store);
            match substitute(path_and_query.as_bytes(), &lookup) {
                Ok(o) => {
                    injected.extend(o.names);
                    match String::from_utf8(o.bytes) {
                        Ok(s) => s,
                        Err(_) => {
                            return text(
                                StatusCode::BAD_REQUEST,
                                "path is not valid UTF-8 after substitution",
                            )
                        }
                    }
                }
                Err(e) => return deny(state, e),
            }
        }
        None => path_and_query.to_string(),
    };
    let url = format!("{base_url}{target_pq}");

    // 2. Headers.
    let mut fwd = HeaderMap::with_capacity(in_headers.len());
    for (name, value) in in_headers.iter() {
        if is_hop_by_hop(name) || *name == header::HOST || *name == header::CONTENT_LENGTH {
            continue;
        }
        // The session ticket is between the agent and this proxy.
        if name.as_str().eq_ignore_ascii_case(TICKET_HEADER) {
            continue;
        }
        let out = match gate {
            Some(gate) => {
                let lookup = mk_lookup(gate, store);
                match substitute(value.as_bytes(), &lookup) {
                    Ok(o) => {
                        injected.extend(o.names);
                        o.bytes
                    }
                    Err(e) => return deny(state, e),
                }
            }
            None => value.as_bytes().to_vec(),
        };
        match HeaderValue::from_bytes(&out) {
            Ok(hv) => {
                fwd.insert(name.clone(), hv);
            }
            Err(_) => {
                return text(
                    StatusCode::BAD_REQUEST,
                    "a header became invalid after substitution",
                )
            }
        }
    }

    // 3. Body.
    let out_body = match gate {
        Some(gate) => {
            let lookup = mk_lookup(gate, store);
            match substitute(body.as_ref(), &lookup) {
                Ok(o) => {
                    injected.extend(o.names);
                    Bytes::from(o.bytes)
                }
                Err(e) => return deny(state, e),
            }
        }
        None => body,
    };

    if !injected.is_empty() {
        info!(
            target: "seekrit_audit",
            %method,
            upstream = %audit_host,
            path = %path_and_query,
            secrets = ?injected,
            "injected secret(s) into request",
        );
        span.record(
            seekrit_telemetry::attr::SECRET_NAMES,
            injected.iter().cloned().collect::<Vec<_>>().join(","),
        );
        state.metrics.record_injections(audit_host, injected.len());
    }
    if let Some(log) = state.activity.as_ref() {
        // Outside the `injected.is_empty()` guard: a permitted request carrying no
        // placeholder still proves its rule is in use.
        //
        // `rule_index` is `None` on this plane because the matched index is not
        // threaded out of `authorize` — the review still sees the host and method,
        // and per-rule attribution for intercepted traffic is a follow-up.
        log.record(
            Cell {
                host: audit_host.to_string(),
                method: method.as_str().to_string(),
                decision: "allow",
                rule_index: None,
            },
            &injected.iter().cloned().collect::<Vec<_>>(),
        );
    }

    // Opt-in; see `Config::propagate_trace_upstream`. On the MITM plane the
    // upstream is whatever host the workload dialled, so the default-off
    // reasoning applies even more strongly here.
    if state.config.propagate_trace_upstream {
        seekrit_telemetry::inject_context(&seekrit_telemetry::current_context(), &mut fwd);
    }

    let started = std::time::Instant::now();
    let resp = match state
        .client
        .request(method, &url)
        .headers(fwd)
        .body(out_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            state
                .metrics
                .record_request(PLANE_FORWARD, "upstream_error");
            return text(
                StatusCode::BAD_GATEWAY,
                &format!("upstream request failed: {e}"),
            );
        }
    };
    state
        .metrics
        .record_upstream_duration(audit_host, started.elapsed().as_secs_f64() * 1000.0);
    state.metrics.record_request(PLANE_FORWARD, "forwarded");
    span.record("http.response.status_code", resp.status().as_u16());
    streaming_response(resp)
}

/// Build a lookup closure over the request's gate + the secret store
/// (default-deny).
fn mk_lookup<'a>(gate: &'a Gate, store: &'a SecretStore) -> impl Fn(&str) -> Lookup + 'a {
    move |name: &str| {
        if !gate.permits(name) {
            Lookup::Denied
        } else {
            match store.get(name) {
                Some(v) => Lookup::Value(v.to_string()),
                None => Lookup::Unknown,
            }
        }
    }
}

/// Stream a reqwest response back to the client untouched (minus framing headers).
fn streaming_response(resp: reqwest::Response) -> Response<Body> {
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let stream = resp
        .bytes_stream()
        .map(|r| r.map(Frame::data).map_err(|e| Box::new(e) as BoxError));
    let body = BodyExt::boxed(StreamBody::new(stream));

    let mut out = Response::new(body);
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
    out
}

async fn read_limited(body: Incoming, max: usize) -> Result<Bytes, ()> {
    match Limited::new(body, max).collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(_) => Err(()),
    }
}

/// Refuse a request whose placeholder isn't allowed, recording it as a denial.
///
/// Denials are the security-significant event on this path: a workload asking
/// for a secret it has no claim to. They get a metric, a span field, and a log
/// line — the secret *name* in each, never the value.
fn deny(state: &ForwardState, e: SubError) -> Response<Body> {
    let reason = match e {
        SubError::Denied(_) => "not_allowed",
        SubError::Unknown(_) => "unknown_secret",
    };
    tracing::Span::current().record(seekrit_telemetry::attr::DENY_REASON, reason);
    state.metrics.record_request(PLANE_FORWARD, "denied");
    reject(e)
}

fn reject(e: SubError) -> Response<Body> {
    let (n, why) = match e {
        SubError::Denied(n) => (n, "is not allowed toward this upstream"),
        SubError::Unknown(n) => (n, "references a secret that is not available"),
    };
    warn!(secret = %n, "denied placeholder in forward request");
    text(
        StatusCode::FORBIDDEN,
        &format!("placeholder {{{{seekrit:{n}}}}} {why}"),
    )
}

/// `200 Connection Established` — the CONNECT tunnel is ready.
fn established() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .body(empty())
        .expect("valid response")
}

fn text(status: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(full(Bytes::from(format!("seekrit-proxy: {msg}\n"))))
        .expect("valid response")
}

fn full(bytes: Bytes) -> Body {
    Full::new(bytes)
        .map_err(|e| Box::new(e) as BoxError)
        .boxed()
}

fn empty() -> Body {
    full(Bytes::new())
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
