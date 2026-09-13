//! End-to-end inline approval: a declared operation stops in the proxy until a
//! human answers.
//!
//! The properties that make this a control rather than a speed bump:
//!
//!   1. a matching request is **held** — it has not reached the upstream — and
//!      resumes on approval,
//!   2. a denial refuses it with the credential never leaving the process,
//!   3. **no answer is a denial**, not a permit,
//!   4. an unmatched operation is never held at all,
//!   5. decisions arrive over the **control listener**, which the agent cannot
//!      reach: without the control token, approving is a 401.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::extract::State;
use axum::routing::any;
use axum::Router;
use seekrit_proxy::approval::{ApprovalStore, Decision};
use seekrit_proxy::config::Config;
use seekrit_proxy::egress::Egress;
use seekrit_proxy::proxy::{router, AppState};
use seekrit_proxy::secrets::SecretStore;
use seekrit_proxy::tasks::SessionResolver;
use seekrit_proxy::tickets::{control_router, ControlState, TicketStore, CONTROL_TOKEN_HEADER};
use tokio::net::TcpListener;

const CONTROL_TOKEN: &str = "test-control-token";

/// What the upstream saw, so "was it held?" is answered by the upstream rather
/// than by a response the proxy may have refused.
#[derive(Clone, Default)]
struct Seen {
    count: Arc<AtomicUsize>,
    authorization: Arc<Mutex<Option<String>>>,
}

async fn echo(State(seen): State<Seen>, req: axum::extract::Request) -> &'static str {
    seen.count.fetch_add(1, SeqCst);
    *seen.authorization.lock().unwrap() = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    "upstream ok"
}

async fn spawn(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

struct Harness {
    base: String,
    control: String,
    approvals: Arc<ApprovalStore>,
    seen: Seen,
}

/// A proxy whose `[approval]` block is whatever `approval` says.
async fn harness(approval: &str) -> Harness {
    let seen = Seen::default();
    let upstream = spawn(Router::new().fallback(any(echo)).with_state(seen.clone())).await;

    let cfg = format!(
        "listen='127.0.0.1:0'\n\
         [[route]]\nprefix='/up'\nupstream='http://{upstream}'\nallow=['TEST_KEY']\n{approval}"
    );
    let config = Config::from_toml(&cfg).unwrap();
    let approvals = Arc::new(ApprovalStore::new(
        config.approval.clone().expect("an [approval] block"),
    ));

    let state = AppState {
        client: seekrit_proxy::upstream_client(Arc::new(Egress::from_config(&config))).unwrap(),
        config: Arc::new(config),
        store: Arc::new(ArcSwap::from_pointee(SecretStore::from_values([(
            "TEST_KEY".to_string(),
            "s3cr3t-value-long-enough".to_string(),
        )]))),
        metrics: Arc::new(seekrit_proxy::telemetry::Metrics::new()),
        policy: None,
        sessions: Arc::new(SessionResolver::new(None, None)),
        ratchet: None,
        activity: None,
        approvals: Some(approvals.clone()),
    };
    let proxy = spawn(router(state)).await;

    let control = spawn(control_router(ControlState {
        tickets: Arc::new(TicketStore::new(
            vec!["default".to_string()],
            Duration::from_secs(60),
            Duration::from_secs(60),
        )),
        token: Arc::new(CONTROL_TOKEN.to_string()),
        approvals: Some(approvals.clone()),
    }))
    .await;

    Harness {
        base: format!("http://{proxy}"),
        control: format!("http://{control}"),
        approvals,
        seen,
    }
}

/// The usual block: POSTs to the route's upstream need a human.
fn requires_post() -> String {
    "[approval]\ntimeout='5s'\n[[approval.require]]\nhost='127.0.0.1'\nmethods=['POST']\nlabel='money movement'\n".into()
}

/// Fire a request at the proxy without waiting for it.
fn send(base: &str, method: &str, path: &str) -> tokio::task::JoinHandle<reqwest::Response> {
    let url = format!("{base}{path}");
    let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
    tokio::spawn(async move {
        reqwest::Client::new()
            .request(method, url)
            .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
            .send()
            .await
            .unwrap()
    })
}

#[tokio::test]
async fn a_declared_operation_is_held_until_approved() {
    let h = harness(&requires_post()).await;
    let request = send(&h.base, "POST", "/up/v1/charges");

    h.approvals.wait_for_pending().await;
    let pending = h.approvals.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].operation, "money movement");
    // The prompt names the credential about to travel.
    assert_eq!(pending[0].secrets, vec!["TEST_KEY"]);
    // And the upstream has not been touched: the request is genuinely held, not
    // merely logged on its way past.
    assert_eq!(h.seen.count.load(SeqCst), 0);

    h.approvals.decide(&pending[0].id, Decision::Approve);

    let resp = request.await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "upstream ok");
    assert_eq!(h.seen.count.load(SeqCst), 1);
    assert_eq!(
        h.seen.authorization.lock().unwrap().clone().unwrap(),
        "Bearer s3cr3t-value-long-enough"
    );
}

#[tokio::test]
async fn a_denial_refuses_the_request_and_never_reaches_the_upstream() {
    let h = harness(&requires_post()).await;
    let request = send(&h.base, "POST", "/up/v1/charges");

    h.approvals.wait_for_pending().await;
    let id = h.approvals.pending()[0].id.clone();
    h.approvals.decide(&id, Decision::Deny);

    let resp = request.await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("money movement"), "{body}");
    assert!(body.contains("declined"), "{body}");
    assert_eq!(h.seen.count.load(SeqCst), 0);
}

#[tokio::test]
async fn nobody_answering_is_a_denial() {
    // The property that makes this fail-closed: a request that waits long enough
    // must not become a permitted one.
    let h = harness(
        "[approval]\ntimeout='5s'\n[[approval.require]]\nhost='127.0.0.1'\nmethods=['POST']\n",
    )
    .await;
    // A one-off store with a short timeout would not exercise the real config
    // path, so the wait here is the configured minimum.
    let started = std::time::Instant::now();
    let resp = reqwest::Client::new()
        .post(format!("{}/up/v1/charges", h.base))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    assert!(
        started.elapsed() >= Duration::from_secs(5),
        "it did not wait"
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("nobody answered"), "{body}");
    assert_eq!(h.seen.count.load(SeqCst), 0);
}

#[tokio::test]
async fn an_unmatched_operation_is_never_held() {
    let h = harness(&requires_post()).await;
    // GET is not in the trigger's method set.
    let resp = reqwest::Client::new()
        .get(format!("{}/up/v1/charges", h.base))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(h.seen.count.load(SeqCst), 1);
    assert!(h.approvals.pending().is_empty());
}

#[tokio::test]
async fn always_stops_asking_for_the_rest_of_the_run() {
    let h = harness(&requires_post()).await;
    let first = send(&h.base, "POST", "/up/v1/charges");
    h.approvals.wait_for_pending().await;
    let id = h.approvals.pending()[0].id.clone();
    h.approvals.decide(&id, Decision::Always);
    assert_eq!(first.await.unwrap().status(), 200);

    // A second POST under the same rule goes straight through.
    let resp = reqwest::Client::new()
        .post(format!("{}/up/v1/refunds", h.base))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(h.seen.count.load(SeqCst), 2);
}

#[tokio::test]
async fn decisions_arrive_over_the_control_listener() {
    let h = harness(&requires_post()).await;
    let request = send(&h.base, "POST", "/up/v1/charges");
    h.approvals.wait_for_pending().await;

    let client = reqwest::Client::new();
    let listed: serde_json::Value = client
        .get(format!("{}/approvals", h.control))
        .header(CONTROL_TOKEN_HEADER, CONTROL_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = listed["pending"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(listed["pending"][0]["operation"], "money movement");
    assert_eq!(listed["pending"][0]["secrets"][0], "TEST_KEY");

    let decided = client
        .post(format!("{}/approvals/{id}", h.control))
        .header(CONTROL_TOKEN_HEADER, CONTROL_TOKEN)
        .json(&serde_json::json!({ "decision": "approve" }))
        .send()
        .await
        .unwrap();
    assert_eq!(decided.status(), 200);
    assert_eq!(request.await.unwrap().status(), 200);
}

#[tokio::test]
async fn the_agent_cannot_approve_its_own_request() {
    // The whole control rests on this: the pending id is never sent to the
    // workload, and the listener that accepts decisions needs a token the
    // workload does not have.
    let h = harness(&requires_post()).await;
    let request = send(&h.base, "POST", "/up/v1/charges");
    h.approvals.wait_for_pending().await;
    let id = h.approvals.pending()[0].id.clone();

    let client = reqwest::Client::new();
    for resp in [
        client
            .get(format!("{}/approvals", h.control))
            .send()
            .await
            .unwrap(),
        client
            .post(format!("{}/approvals/{id}", h.control))
            .json(&serde_json::json!({ "decision": "approve" }))
            .send()
            .await
            .unwrap(),
    ] {
        assert_eq!(resp.status(), 401, "no control token must mean no decision");
    }

    // Still held; clean up so the test does not wait out the timeout.
    assert_eq!(h.approvals.pending().len(), 1);
    h.approvals.decide(&id, Decision::Deny);
    assert_eq!(request.await.unwrap().status(), 403);
}

#[tokio::test]
async fn deciding_an_already_answered_request_reports_it() {
    let h = harness(&requires_post()).await;
    let request = send(&h.base, "POST", "/up/v1/charges");
    h.approvals.wait_for_pending().await;
    let id = h.approvals.pending()[0].id.clone();
    h.approvals.decide(&id, Decision::Approve);
    request.await.unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/approvals/{id}", h.control))
        .header(CONTROL_TOKEN_HEADER, CONTROL_TOKEN)
        .json(&serde_json::json!({ "decision": "approve" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert!(resp.text().await.unwrap().contains("answered already"));
}
