//! Zero-knowledge enforcement for telemetry.
//!
//! The proxy is the service with the most opportunity to leak: it holds
//! decrypted secrets and substitutes them directly into request bytes, so the
//! plaintext is *right there* in the same function that builds the span. This
//! drives a real request through the real handler, then asserts the exported
//! spans contain the secret's **name** and not one byte of its **value**.
//!
//! Companion to the audit-log rule in CLAUDE.md: names and counts may be
//! recorded, values never. Reviewing that by eye does not scale — a stray
//! `%value` in a span is a one-line diff and an unrecallable disclosure.

use std::sync::Arc;

use arc_swap::ArcSwap;

use seekrit_proxy::config::Config;
use seekrit_proxy::proxy::{router, AppState};
use seekrit_proxy::secrets::SecretStore;
use seekrit_telemetry::testing::Capture;

/// Distinctive enough that a substring match can't be a coincidence.
const SECRET_VALUE: &str = "sk-live-CANARY-9f3a2b8c-must-never-be-exported";
const SECRET_NAME: &str = "EXAMPLE_API_KEY";

/// A mock upstream that accepts anything, so the proxy completes the full
/// substitute-and-forward path (the span is only finished at the end of it).
async fn spawn_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let app = axum::Router::new().fallback(|| async { "ok" });
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn state(upstream: &str) -> AppState {
    let config = Config::from_toml(&format!(
        r#"
listen = "127.0.0.1:0"
[[route]]
prefix = "/up"
upstream = "{upstream}"
allow = ["{SECRET_NAME}"]
"#
    ))
    .expect("valid config");

    AppState {
        config: Arc::new(config),
        store: Arc::new(ArcSwap::from_pointee(SecretStore::from_values([(
            SECRET_NAME.to_string(),
            SECRET_VALUE.to_string(),
        )]))),
        client: reqwest::Client::new(),
        metrics: Arc::new(seekrit_proxy::telemetry::Metrics::new()),
        // File policy, no tickets: this harness is about what reaches a span.
        policy: None,
        sessions: std::sync::Arc::new(seekrit_proxy::tasks::SessionResolver::new(None, None)),
        ratchet: None,
        activity: None,
    }
}

async fn spawn_proxy(upstream: &str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let st = state(upstream);
    tokio::spawn(async move {
        axum::serve(listener, router(st)).await.unwrap();
    });
    format!("http://{addr}")
}

/// A request whose header, body, and query all carry the placeholder — every
/// substitution site the proxy has — must leak none of the resulting value.
#[tokio::test]
async fn substituted_secret_value_never_reaches_telemetry() {
    let capture = Capture::install();

    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(&upstream).await;

    let resp = reqwest::Client::new()
        .post(format!(
            "{proxy}/up/v1/thing?key=%7B%7Bseekrit:{SECRET_NAME}%7D%7D"
        ))
        .header(
            "authorization",
            format!("Bearer {{{{seekrit:{SECRET_NAME}}}}}"),
        )
        .body(format!("{{\"token\":\"{{{{seekrit:{SECRET_NAME}}}}}\"}}"))
        .send()
        .await
        .expect("request should reach the upstream");
    assert!(resp.status().is_success(), "substitution should succeed");

    // The value, and every fragment distinctive enough to identify it.
    capture.assert_absent(&[SECRET_VALUE, "CANARY", "9f3a2b8c"]);

    // Guard against the test passing because nothing was recorded at all.
    let emitted = capture.emitted_strings();
    assert!(
        emitted.iter().any(|s| s.contains(SECRET_NAME)),
        "the secret NAME should be recorded (it is audit-grade); \
         emitted nothing matching it: {emitted:?}"
    );
}

/// A denial records why, and still never records the value the caller was
/// refused. Denials are the path most likely to log "helpful" detail.
#[tokio::test]
async fn denied_placeholder_records_reason_not_value() {
    let capture = Capture::install();

    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(&upstream).await;

    let resp = reqwest::Client::new()
        .get(format!("{proxy}/up/v1/thing"))
        // Not on the route's allowlist.
        .header("authorization", "Bearer {{seekrit:OTHER_SECRET}}")
        .send()
        .await
        .expect("request should be answered");
    assert_eq!(
        resp.status(),
        403,
        "off-allowlist placeholder must be denied"
    );

    capture.assert_absent(&[SECRET_VALUE, "CANARY"]);

    let emitted = capture.emitted_strings();
    assert!(
        emitted.iter().any(|s| s.contains("not_allowed")),
        "the denial reason should be recorded: {emitted:?}"
    );
}

/// The store itself must not be walked into a span — a future "helpful" field
/// like `secrets = ?store` would pass the tests above only by accident.
#[tokio::test]
async fn passthrough_request_records_no_secret_material() {
    let capture = Capture::install();

    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(&upstream).await;

    let resp = reqwest::Client::new()
        .get(format!("{proxy}/up/plain"))
        .send()
        .await
        .expect("request should reach the upstream");
    assert!(resp.status().is_success());

    capture.assert_absent(&[SECRET_VALUE, "CANARY", "9f3a2b8c"]);
}
