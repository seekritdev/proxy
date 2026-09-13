//! End-to-end address checks on the forward plane — the plane whose destination
//! the agent chooses, and therefore the one SSRF lives on.
//!
//! Four routes to the same attack, and each needs a different enforcement point:
//!
//!   1. a **literal** address in an absolute-form URL, which consults no
//!      resolver at all,
//!   2. a literal address as a `CONNECT` target,
//!   3. a **hostname** that resolves to a blocked address — caught by the
//!      client's own resolver, which is also what pins the approved address to
//!      the one dialled,
//!   4. the far end of a **blind tunnel**, which never goes through the HTTP
//!      client at all.
//!
//! Plus the two escape hatches: `allow_cidr`, and the automatic exemption for a
//! reverse-proxy upstream the operator wrote down themselves.

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::routing::any;
use axum::Router;
use seekrit_proxy::ca::Ca;
use seekrit_proxy::config::Config;
use seekrit_proxy::egress::Egress;
use seekrit_proxy::forward::{self, ForwardState};
use seekrit_proxy::proxy::{router, AppState};
use seekrit_proxy::secrets::SecretStore;
use seekrit_proxy::tasks::SessionResolver;
use tokio::net::TcpListener;

/// A CA in a directory of its own — the load path pairs a cert with a key by
/// file, so parallel tests must not share one.
fn temp_ca() -> Ca {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "seekrit-proxy-egress-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    Ca::load_or_generate(
        dir.join("ca.pem").to_str().unwrap(),
        dir.join("ca-key.pem").to_str().unwrap(),
    )
    .unwrap()
}

async fn spawn(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// A forward proxy built from `cfg`, with the same client wiring `main.rs` uses —
/// the egress gate installed as the HTTP client's resolver.
async fn forward_proxy(cfg: &str) -> String {
    let config = Config::from_toml(cfg).unwrap();
    let egress = Arc::new(Egress::from_config(&config));
    let state = ForwardState {
        client: seekrit_proxy::upstream_client(egress.clone()).unwrap(),
        egress,
        config: Arc::new(config),
        store: Arc::new(ArcSwap::from_pointee(SecretStore::from_values([(
            "TEST_KEY".to_string(),
            "s3cr3t-value-long-enough".to_string(),
        )]))),
        ca: Arc::new(temp_ca()),
        metrics: Arc::new(seekrit_proxy::telemetry::Metrics::new()),
        policy: None,
        sessions: Arc::new(SessionResolver::new(None, None)),
        ratchet: None,
        activity: None,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        async move { forward::serve(listener, state, std::future::pending::<()>()).await },
    );
    format!("http://{addr}")
}

/// An agent whose HTTP and HTTPS both go through `proxy`.
fn agent(proxy: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(proxy).unwrap())
        .proxy(reqwest::Proxy::https(proxy).unwrap())
        .build()
        .unwrap()
}

const RULE_ANY: &str = "[forward]\nlisten='127.0.0.1:0'\nunmatched_host_policy='tunnel'\n";

#[tokio::test]
async fn a_literal_metadata_address_is_refused() {
    // `GET http://169.254.169.254/latest/meta-data/` — the plainest form of the
    // attack. No resolver is consulted, so only the literal check can catch it.
    let proxy = forward_proxy(RULE_ANY).await;

    let resp = agent(&proxy)
        .get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("instance metadata"), "{body}");
    assert!(
        body.contains("allow_cidr"),
        "the refusal says how to override"
    );
}

#[tokio::test]
async fn a_literal_private_address_is_refused_on_connect() {
    // The HTTPS route to the same place: `CONNECT 10.0.0.1:443`. Refused before
    // the tunnel is established, so nothing is ever spliced.
    let proxy = forward_proxy(RULE_ANY).await;

    let err = agent(&proxy)
        .get("https://10.0.0.1/admin")
        .send()
        .await
        .expect_err("the CONNECT should be refused");
    // reqwest surfaces a refused CONNECT as a connection error rather than a
    // response, so the assertion is that it never succeeded.
    assert!(err.is_connect() || err.is_request(), "{err:?}");
}

#[tokio::test]
async fn a_hostname_resolving_to_loopback_is_refused() {
    // The case the name-based allowlist cannot see: a permitted *name* pointing
    // at a blocked *address*. `localhost` is the one hostname every machine
    // resolves this way, so the test needs no DNS fixture.
    let upstream = spawn(Router::new().fallback(any(|| async { "secrets" }))).await;
    let proxy = forward_proxy(&format!(
        "{RULE_ANY}[[forward.host]]\nmatch='localhost'\nallow=['TEST_KEY']\n"
    ))
    .await;

    let resp = agent(&proxy)
        .get(format!("http://localhost:{}/x", upstream.port()))
        .send()
        .await
        .unwrap();

    // The rule permits the name; the gate refuses the address it resolves to.
    assert_eq!(resp.status(), 502);
    let body = resp.text().await.unwrap();
    assert!(body.contains("loopback"), "{body}");
}

#[tokio::test]
async fn allow_cidr_reopens_a_named_range() {
    let upstream = spawn(Router::new().fallback(any(|| async { "reachable" }))).await;
    let proxy = forward_proxy(&format!(
        "[egress]\nallow_cidr=['127.0.0.0/8']\n\
         {RULE_ANY}[[forward.host]]\nmatch='localhost'\nallow=['TEST_KEY']\n"
    ))
    .await;

    let resp = agent(&proxy)
        .get(format!("http://localhost:{}/x", upstream.port()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "reachable");
}

#[tokio::test]
async fn turning_the_gate_off_reopens_everything() {
    let upstream = spawn(Router::new().fallback(any(|| async { "reachable" }))).await;
    let proxy = forward_proxy(&format!(
        "[egress]\nblock_private_ips=false\n\
         {RULE_ANY}[[forward.host]]\nmatch='localhost'\nallow=['TEST_KEY']\n"
    ))
    .await;

    let resp = agent(&proxy)
        .get(format!("http://localhost:{}/x", upstream.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn a_blind_tunnel_is_checked_too() {
    // An unruled host is never decrypted — which is not the same as never
    // checked. It is exactly where an agent would aim a tunnel at something
    // internal, precisely *because* the proxy does not look inside.
    let upstream = spawn(Router::new().fallback(any(|| async { "internal" }))).await;
    let proxy = forward_proxy(RULE_ANY).await;

    // `localhost` matches no rule, so this takes the blind-tunnel path.
    let err = agent(&proxy)
        .get(format!("https://localhost:{}/x", upstream.port()))
        .send()
        .await
        .expect_err("the tunnel should not reach a loopback address");
    assert!(err.is_connect() || err.is_request(), "{err:?}");
}

#[tokio::test]
async fn a_configured_reverse_upstream_stays_reachable() {
    // The exemption that lets the gate default to on: a reverse-proxy upstream is
    // written in this deployment's config by the operator, so it is not an
    // agent-chosen destination and SSRF does not apply to it. Without this, every
    // sidecar and local deployment would break.
    let upstream = spawn(Router::new().fallback(any(|| async { "ok" }))).await;
    let cfg = format!(
        "listen='127.0.0.1:0'\n[[route]]\nprefix='/up'\nupstream='http://{upstream}'\nallow=['TEST_KEY']\n"
    );
    let config = Config::from_toml(&cfg).unwrap();
    assert!(
        Egress::from_config(&config).is_enforcing(),
        "the gate is on; the upstream is exempt from it, which is a different thing"
    );
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
    };
    let proxy = spawn(router(state)).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{proxy}/up/thing"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}
