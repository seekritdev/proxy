//! End-to-end proxy tests: a real in-process upstream, a real proxy server, and
//! a real HTTP client. Proves the three properties that matter:
//!   1. placeholders in headers *and* body are substituted before forwarding,
//!   2. a request that names a secret not on the route's allowlist is denied
//!      (default-deny) and never reaches the upstream, and
//!   3. the upstream's response streams back intact.

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;

use axum::extract::State;
use axum::routing::any;
use axum::Router;
use seekrit_proxy::config::Config;
use seekrit_proxy::proxy::{router, AppState};
use seekrit_proxy::secrets::SecretStore;
use tokio::net::TcpListener;

/// A mock upstream that echoes back what it received: the `authorization`
/// header and the request body, as JSON. Also flips a flag if it is ever hit.
#[derive(Clone, Default)]
struct Hits(Arc<std::sync::atomic::AtomicUsize>);

async fn echo(
    State(hits): State<Hits>,
    req: axum::extract::Request,
) -> axum::Json<serde_json::Value> {
    hits.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = axum::body::to_bytes(req.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    axum::Json(serde_json::json!({
        "authorization": auth,
        "body": String::from_utf8_lossy(&body),
    }))
}

async fn spawn(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Bring up a mock upstream and a proxy in front of it. Returns the proxy's
/// base URL and the upstream hit counter.
async fn harness() -> (String, Hits) {
    let hits = Hits::default();
    let upstream = spawn(Router::new().fallback(any(echo)).with_state(hits.clone())).await;

    let cfg = format!(
        "listen = \"127.0.0.1:0\"\n[[route]]\nprefix = \"/up\"\nupstream = \"http://{upstream}\"\nallow = [\"TEST_KEY\"]\n"
    );
    let config = Config::from_toml(&cfg).unwrap();
    let store = SecretStore::from_values([("TEST_KEY".to_string(), "s3cr3t-value".to_string())]);
    let state = AppState {
        config: Arc::new(config),
        store: Arc::new(ArcSwap::from_pointee(store)),
        client: reqwest::Client::new(),
        // No exporter configured in tests, so these instruments are no-ops.
        metrics: std::sync::Arc::new(seekrit_proxy::telemetry::Metrics::new()),
        // These harnesses exercise file policy: no server bundles, no tickets.
        policy: None,
        sessions: Arc::new(SessionResolver::new(None, None)),
        ratchet: None,
        activity: None,
    };
    let proxy = spawn(router(state)).await;
    (format!("http://{proxy}"), hits)
}

#[tokio::test]
async fn substitutes_header_and_body_then_forwards() {
    let (base, hits) = harness().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/up/echo"))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .body("prefix {{seekrit:TEST_KEY}} suffix")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["authorization"], "Bearer s3cr3t-value");
    assert_eq!(json["body"], "prefix s3cr3t-value suffix");
    assert_eq!(hits.0.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn passthrough_when_no_placeholder() {
    let (base, _hits) = harness().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/up/echo"))
        .header("authorization", "Bearer already-literal")
        .body("no placeholders here")
        .send()
        .await
        .unwrap();

    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["authorization"], "Bearer already-literal");
    assert_eq!(json["body"], "no placeholders here");
}

#[tokio::test]
async fn denies_secret_not_on_allowlist_and_never_forwards() {
    let (base, hits) = harness().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/up/echo"))
        // NOT_ALLOWED is not in the route's allow list -> default-deny.
        .header("authorization", "Bearer {{seekrit:NOT_ALLOWED}}")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    // Crucially, the upstream must NOT have been contacted.
    assert_eq!(hits.0.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unmatched_path_is_404() {
    let (base, _hits) = harness().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/nope/here"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// Operation constraints and server-delivered policy
// ---------------------------------------------------------------------------

use std::collections::BTreeSet;
use std::time::Duration;

use seekrit_core::policy::{MethodSet, PathSet, Rule, RuleSet};
use seekrit_proxy::policy::{now_secs, PolicySnapshot, PolicyStore};
use seekrit_proxy::tasks::SessionResolver;
use seekrit_proxy::tickets::{TicketStore, TICKET_HEADER};

/// The echo upstream, plus a proxy built from an arbitrary config and an
/// arbitrary policy/ticket setup. Returns the proxy base URL, the upstream
/// address (so a policy rule can name its host), and the hit counter.
async fn harness_with(
    config_for: impl Fn(&SocketAddr) -> String,
    policy_for: impl Fn(&SocketAddr) -> Option<Arc<PolicyStore>>,
    tickets: Option<Arc<TicketStore>>,
) -> (String, SocketAddr, Hits) {
    let hits = Hits::default();
    let upstream = spawn(Router::new().fallback(any(echo)).with_state(hits.clone())).await;
    let config = Config::from_toml(&config_for(&upstream)).unwrap();
    let store = SecretStore::from_values([
        ("TEST_KEY".to_string(), "s3cr3t-value".to_string()),
        ("OTHER_KEY".to_string(), "other-value".to_string()),
    ]);
    let state = AppState {
        config: Arc::new(config),
        store: Arc::new(ArcSwap::from_pointee(store)),
        client: reqwest::Client::new(),
        metrics: std::sync::Arc::new(seekrit_proxy::telemetry::Metrics::new()),
        policy: policy_for(&upstream),
        sessions: Arc::new(SessionResolver::new(tickets, None)),
        ratchet: None,
        activity: None,
    };
    let proxy = spawn(router(state)).await;
    (format!("http://{proxy}"), upstream, hits)
}

fn rule(host: &str, methods: &[&str], paths: &[&str], allow: &[&str]) -> Rule {
    Rule::new(
        host,
        MethodSet::new(methods.iter().map(|s| s.to_string())),
        PathSet::new(paths.iter().map(|s| s.to_string())),
        allow.iter().map(|s| s.to_string()).collect(),
    )
}

/// A snapshot as if a signed bundle had just been verified. The signature path
/// itself is covered by the cross-language vectors in `policy_vectors.rs`; this
/// is about what the data plane does with a verified one.
fn snapshot(rules: Vec<Rule>, expires_at: i64) -> PolicySnapshot {
    PolicySnapshot {
        rules: RuleSet::new(rules),
        agent_id: "agt_test".to_string(),
        agent_slug: Some("nova".to_string()),
        version: 7,
        expires_at,
        signer: "kNc8test".to_string(),
    }
}

#[tokio::test]
async fn a_method_the_route_does_not_permit_is_refused_before_the_upstream() {
    let (base, _upstream, hits) = harness_with(
        |up| {
            format!(
                "listen = \"127.0.0.1:0\"\n[[route]]\nprefix = \"/up\"\nupstream = \"http://{up}\"\n\
                 allow = [\"TEST_KEY\"]\nmethods = [\"POST\"]\npaths = [\"/echo\"]\n"
            )
        },
        |_| None,
        None,
    )
    .await;
    let client = reqwest::Client::new();

    // The permitted operation still works.
    let ok = client
        .post(format!("{base}/up/echo"))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // A method outside the rule is refused — even with no placeholder at all,
    // because the constraint bounds the operation, not just the credential.
    let denied = client
        .delete(format!("{base}/up/echo"))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert!(denied
        .text()
        .await
        .unwrap()
        .contains("method is not permitted"));

    // And a path outside the rule likewise.
    let off_path = client
        .post(format!("{base}/up/files"))
        .send()
        .await
        .unwrap();
    assert_eq!(off_path.status(), 403);
    assert!(off_path
        .text()
        .await
        .unwrap()
        .contains("path is not permitted"));

    assert_eq!(
        hits.0.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "only the permitted request should have reached the upstream"
    );
}

#[tokio::test]
async fn server_policy_authorizes_the_reverse_plane() {
    let (base, _upstream, hits) = harness_with(
        // In server mode the file keeps routing only; the rules come from policy.
        |up| {
            format!(
                "listen = \"127.0.0.1:0\"\n[[route]]\nprefix = \"/up\"\nupstream = \"http://{up}\"\n\
                 [policy]\nsource = \"server\"\nagent = \"nova\"\nsigners = [\"kNc8test\"]\n"
            )
        },
        |up| {
            let host = up.ip().to_string();
            Some(Arc::new(PolicyStore::new(
                "nova".to_string(),
                vec![(
                    "nova".to_string(),
                    snapshot(
                        vec![rule(&host, &["POST"], &["/echo"], &["TEST_KEY"])],
                        now_secs() + 3600,
                    ),
                )],
            )))
        },
        None,
    )
    .await;
    let client = reqwest::Client::new();

    let ok = client
        .post(format!("{base}/up/echo"))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(
        ok.json::<serde_json::Value>().await.unwrap()["authorization"],
        "Bearer s3cr3t-value"
    );

    // A secret the published policy does not allow toward this host.
    let denied = client
        .post(format!("{base}/up/echo"))
        .header("authorization", "Bearer {{seekrit:OTHER_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(hits.0.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_expired_policy_fails_closed() {
    let (base, _upstream, hits) = harness_with(
        |up| {
            format!(
                "listen = \"127.0.0.1:0\"\n[[route]]\nprefix = \"/up\"\nupstream = \"http://{up}\"\n\
                 [policy]\nsource = \"server\"\nagent = \"nova\"\nsigners = [\"kNc8test\"]\n"
            )
        },
        |up| {
            let host = up.ip().to_string();
            Some(Arc::new(PolicyStore::new(
                "nova".to_string(),
                // Signed and verified, but past its expiry: the bound on how long
                // revoked policy can keep working in a partitioned proxy.
                vec![(
                    "nova".to_string(),
                    snapshot(vec![rule(&host, &[], &[], &["TEST_KEY"])], now_secs() - 1),
                )],
            )))
        },
        None,
    )
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/up/echo"))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert!(resp.text().await.unwrap().contains("expired"));
    assert_eq!(hits.0.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_session_ticket_narrows_but_never_widens() {
    let tickets = Arc::new(TicketStore::new(
        vec!["nova".to_string()],
        Duration::from_secs(60),
        Duration::from_secs(300),
    ));
    // The orchestrator asks for one secret out of the two the policy allows, plus
    // one the policy does not allow at all.
    let (narrow, _) = tickets
        .mint(
            Some("nova".to_string()),
            Some(vec!["TEST_KEY".to_string(), "UNGRANTED".to_string()]),
            None,
        )
        .await
        .unwrap();

    let (base, _upstream, hits) = harness_with(
        |up| {
            format!(
                "listen = \"127.0.0.1:0\"\n[[route]]\nprefix = \"/up\"\nupstream = \"http://{up}\"\n\
                 [policy]\nsource = \"server\"\nagent = \"nova\"\nsigners = [\"kNc8test\"]\n"
            )
        },
        |up| {
            let host = up.ip().to_string();
            Some(Arc::new(PolicyStore::new(
                "nova".to_string(),
                vec![(
                    "nova".to_string(),
                    snapshot(
                        vec![rule(&host, &[], &[], &["TEST_KEY", "OTHER_KEY"])],
                        now_secs() + 3600,
                    ),
                )],
            )))
        },
        Some(tickets.clone()),
    )
    .await;
    let client = reqwest::Client::new();

    // In scope for both the ticket and the policy: injected.
    let ok = client
        .post(format!("{base}/up/echo"))
        .header(TICKET_HEADER, &narrow)
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let body: serde_json::Value = ok.json().await.unwrap();
    assert_eq!(body["authorization"], "Bearer s3cr3t-value");

    // Allowed by policy, left out of the ticket: refused.
    let out_of_scope = client
        .post(format!("{base}/up/echo"))
        .header(TICKET_HEADER, &narrow)
        .header("authorization", "Bearer {{seekrit:OTHER_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(out_of_scope.status(), 403);

    // Without the ticket the same request is fine — a ticket only narrows.
    let unticketed = client
        .post(format!("{base}/up/echo"))
        .header("authorization", "Bearer {{seekrit:OTHER_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(unticketed.status(), 200);

    // An unknown or expired ticket is refused rather than ignored — ignoring it
    // would silently promote a narrowed run to the full policy.
    let bogus = client
        .post(format!("{base}/up/echo"))
        .header(TICKET_HEADER, "skp_not-a-real-ticket")
        .send()
        .await
        .unwrap();
    assert_eq!(bogus.status(), 403);

    assert_eq!(hits.0.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_ticket_header_never_reaches_the_upstream() {
    let tickets = Arc::new(TicketStore::new(
        vec!["default".to_string()],
        Duration::from_secs(60),
        Duration::from_secs(60),
    ));
    let (ticket, _) = tickets.mint(None, None, None).await.unwrap();

    let hits = Hits::default();
    // An upstream that reports back every header it saw.
    let upstream = spawn(
        Router::new()
            .fallback(any(
                |State(hits): State<Hits>, req: axum::extract::Request| async move {
                    hits.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let names: Vec<String> = req
                        .headers()
                        .keys()
                        .map(|k| k.as_str().to_string())
                        .collect();
                    axum::Json(serde_json::json!({ "headers": names }))
                },
            ))
            .with_state(hits.clone()),
    )
    .await;

    let config = Config::from_toml(&format!(
        "listen = \"127.0.0.1:0\"\n[[route]]\nprefix = \"/up\"\nupstream = \"http://{upstream}\"\n\
         allow = [\"TEST_KEY\"]\n"
    ))
    .unwrap();
    let state = AppState {
        config: Arc::new(config),
        store: Arc::new(ArcSwap::from_pointee(SecretStore::from_values([(
            "TEST_KEY".to_string(),
            "s3cr3t-value".to_string(),
        )]))),
        client: reqwest::Client::new(),
        metrics: std::sync::Arc::new(seekrit_proxy::telemetry::Metrics::new()),
        policy: None,
        sessions: Arc::new(SessionResolver::new(Some(tickets), None)),
        ratchet: None,
        activity: None,
    };
    let proxy = spawn(router(state)).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{proxy}/up/echo"))
        .header(TICKET_HEADER, ticket)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let headers: BTreeSet<String> = body["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(
        !headers.contains(TICKET_HEADER),
        "the session ticket is between the agent and the proxy: {headers:?}"
    );
}

/// The trust ratchet, end to end through the reverse plane.
///
/// The unit tests in `src/ratchet.rs` prove the state machine turns one way. This
/// proves the wiring: that a *permitted* request to a declared protected path
/// takes a capability away from the run, that the next request loses it, and that
/// the refusal says so in terms an agent's author can act on. Three requests, one
/// session, and the middle one is the only thing that changed.
#[tokio::test]
async fn the_ratchet_withdraws_a_host_after_a_protected_request() {
    use seekrit_proxy::ratchet::RatchetStore;

    let hits = Hits::default();
    let upstream = spawn(Router::new().fallback(any(echo)).with_state(hits.clone())).await;
    // Two routes onto one upstream: `/reports` is protected, `/hooks` is what the
    // run loses by reading it. The trigger matches the *stripped* path, which is
    // the same string a policy rule is written against.
    let config = Config::from_toml(&format!(
        "listen = \"127.0.0.1:0\"\n\
         [[route]]\nprefix = \"/reports\"\nupstream = \"http://{upstream}\"\nallow = [\"TEST_KEY\"]\n\
         [[route]]\nprefix = \"/hooks\"\nupstream = \"http://{upstream}\"\nallow = [\"TEST_KEY\"]\n\
         [[ratchet.state]]\nname = \"restricted\"\nhosts = []\n\
         [[ratchet.transition]]\nhost = \"127.0.0.1\"\npaths = [\"/exports/**\"]\n\
         to = \"restricted\"\nlabel = \"customer export\"\n"
    ))
    .unwrap();
    let ratchet = Arc::new(RatchetStore::new(config.ratchet.clone().unwrap()));
    let state = AppState {
        config: Arc::new(config),
        store: Arc::new(ArcSwap::from_pointee(SecretStore::from_values([(
            "TEST_KEY".to_string(),
            "s3cr3t-value".to_string(),
        )]))),
        client: reqwest::Client::new(),
        metrics: std::sync::Arc::new(seekrit_proxy::telemetry::Metrics::new()),
        policy: None,
        sessions: Arc::new(SessionResolver::new(None, None)),
        ratchet: Some(ratchet.clone()),
        activity: None,
    };
    let proxy = spawn(router(state)).await;
    let base = format!("http://{proxy}");
    let client = reqwest::Client::new();

    // 1. Baseline: the webhook path is permitted.
    let before = client
        .get(format!("{base}/hooks/services/abc"))
        .send()
        .await
        .unwrap();
    assert_eq!(before.status(), 200, "policy permits this at baseline");
    assert_eq!(ratchet.narrowed_sessions(), 0);

    // 2. The protected read. Permitted — and it is what closes the door.
    let protected = client
        .get(format!("{base}/reports/exports/2026-08.csv"))
        .send()
        .await
        .unwrap();
    assert_eq!(protected.status(), 200);
    assert_eq!(
        ratchet.narrowed_sessions(),
        1,
        "the protected request should have narrowed this run"
    );

    // 3. The same call as (1), now refused — by the ratchet, not by policy.
    let after = client
        .get(format!("{base}/hooks/services/abc"))
        .send()
        .await
        .unwrap();
    assert_eq!(after.status(), 403);
    let body = after.text().await.unwrap();
    assert!(body.contains("withdrawn from this run"), "{body}");
    assert!(body.contains("customer export"), "{body}");
    assert!(body.contains("restricted"), "{body}");
    // The upstream saw exactly the two permitted requests; the refusal never left
    // the proxy.
    assert_eq!(
        hits.0.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "a withdrawn request must not reach upstream"
    );
}

/// Dispatched tasks (`skd_…`), end to end through the reverse plane against a
/// mock API.
///
/// Four things have to hold at once for this feature to be worth shipping, and
/// each is a way it could be quietly wrong: a valid task narrows injection, a
/// refused one fails closed with the API's own words, an identity this proxy does
/// not serve is refused *locally*, and the request path does not make an HTTP call
/// per request.
#[tokio::test]
async fn a_dispatched_task_narrows_the_run_and_is_introspected_once() {
    use seekrit_proxy::tasks::TaskClient;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let calls = Arc::new(AtomicUsize::new(0));
    let api_calls = calls.clone();
    // A mock `POST /v1/tasks/introspect`, keyed on the token in the body: one
    // live task scoped to OTHER_KEY, one revoked, one for an agent this proxy is
    // not configured to serve.
    let api = spawn(
        Router::new().route(
            "/v1/tasks/introspect",
            axum::routing::post(move |body: String| {
                let calls = api_calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
                    let token = parsed["token"].as_str().unwrap_or("");
                    let session = |slug: &str, scopes: serde_json::Value| {
                        (
                            axum::http::StatusCode::OK,
                            axum::Json(serde_json::json!({
                                "session": {
                                    "taskId": "tsk_1",
                                    "agent": { "id": "agt_1", "slug": slug, "name": "Nova" },
                                    "scopes": scopes,
                                    "policyVersion": 3,
                                    "proofThumbprint": null,
                                    "expiresAt": "2099-01-01T00:00:00.000Z",
                                }
                            })),
                        )
                    };
                    match token {
                        "skd_live" => session("nova", serde_json::json!(["OTHER_KEY"])),
                        "skd_stranger" => session("someone-else", serde_json::json!(null)),
                        "skd_revoked" => (
                            axum::http::StatusCode::FORBIDDEN,
                            axum::Json(serde_json::json!({
                                "error": { "code": "forbidden", "message": "this task has been revoked" }
                            })),
                        ),
                        _ => (
                            axum::http::StatusCode::NOT_FOUND,
                            axum::Json(serde_json::json!({
                                "error": { "code": "not_found", "message": "task not found" }
                            })),
                        ),
                    }
                }
            }),
        ),
    )
    .await;

    let hits = Hits::default();
    let upstream = spawn(Router::new().fallback(any(echo)).with_state(hits.clone())).await;
    let config = Config::from_toml(&format!(
        "listen = \"127.0.0.1:0\"\n\
         [[route]]\nprefix = \"/up\"\nupstream = \"http://{upstream}\"\n\
         allow = [\"TEST_KEY\", \"OTHER_KEY\"]\n[tasks]\ncache_ttl = \"60s\"\n"
    ))
    .unwrap();
    // `known_agents = ["nova"]` is the local allowlist: the API can say whatever
    // it likes about which identity a task belongs to, and this proxy still only
    // serves the ones its own file names.
    let tasks = TaskClient::new(
        reqwest::Client::new(),
        format!("http://{api}"),
        "skt_test".to_string(),
        vec!["nova".to_string()],
        std::time::Duration::from_secs(60),
    );
    let state = AppState {
        config: Arc::new(config),
        store: Arc::new(ArcSwap::from_pointee(SecretStore::from_values([
            ("TEST_KEY".to_string(), "s3cr3t-value".to_string()),
            ("OTHER_KEY".to_string(), "other-value".to_string()),
        ]))),
        client: reqwest::Client::new(),
        metrics: std::sync::Arc::new(seekrit_proxy::telemetry::Metrics::new()),
        policy: None,
        sessions: Arc::new(SessionResolver::new(None, Some(tasks))),
        ratchet: None,
        activity: None,
    };
    let proxy = spawn(router(state)).await;
    let base = format!("http://{proxy}");
    let client = reqwest::Client::new();

    // The task is scoped to OTHER_KEY, so that one substitutes…
    let ok = client
        .get(format!("{base}/up/echo"))
        .header(TICKET_HEADER, "skd_live")
        .header("authorization", "Bearer {{seekrit:OTHER_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let body: serde_json::Value = ok.json().await.unwrap();
    assert_eq!(body["authorization"], "Bearer other-value");

    // …and TEST_KEY does not, even though the route's own allowlist names it.
    // The task's scopes intersect with policy; they never add to it.
    let denied = client
        .get(format!("{base}/up/echo"))
        .header(TICKET_HEADER, "skd_live")
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);

    // A revoked task fails closed, in the API's own words.
    let revoked = client
        .get(format!("{base}/up/echo"))
        .header(TICKET_HEADER, "skd_revoked")
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 403);
    assert!(
        revoked.text().await.unwrap().contains("revoked"),
        "the refusal should carry the API's reason"
    );

    // An unknown task likewise.
    let unknown = client
        .get(format!("{base}/up/echo"))
        .header(TICKET_HEADER, "skd_nope")
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 403);

    // A task for an identity this deployment does not serve is refused *here*,
    // not by the API — the local file is what decides which agents exist.
    let stranger = client
        .get(format!("{base}/up/echo"))
        .header(TICKET_HEADER, "skd_stranger")
        .send()
        .await
        .unwrap();
    assert_eq!(stranger.status(), 403);
    assert!(
        stranger.text().await.unwrap().contains("does not serve"),
        "the refusal should name the local allowlist as the reason"
    );

    // Four distinct tokens, six requests: the two repeats of `skd_live` came from
    // the cache. Without that this would be an HTTP call per proxied request.
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "introspection should be cached per token"
    );
}
