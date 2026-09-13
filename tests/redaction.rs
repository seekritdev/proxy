//! End-to-end response redaction: an upstream hands an injected credential back,
//! and the workload must not see it.
//!
//! Five properties, and the third is the one that constrains the design:
//!
//!   1. an echoed value is scrubbed out of the response **body**,
//!   2. and out of a response **header** (the `Location:` redirect case),
//!   3. while the response still **streams** — a chunk the upstream sent reaches
//!      the client before the upstream has finished, which is what makes the
//!      proxy usable in front of SSE and token-streaming APIs,
//!   4. `enabled = false` restores the old pass-through behaviour verbatim,
//!   5. `scan = "all"` catches a credential this request never sent.
//!
//! Plus the redirect rule the `Location:` case depends on: the proxy hands a
//! `3xx` back rather than chasing it (see [`seekrit_proxy::upstream_client`]).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use futures_util::StreamExt;
use seekrit_proxy::config::Config;
use seekrit_proxy::proxy::{router, AppState};
use seekrit_proxy::secrets::SecretStore;
use seekrit_proxy::tasks::SessionResolver;
use tokio::net::TcpListener;

const VALUE: &str = "s3cr3t-value-long-enough-to-scan";
const OTHER: &str = "other-value-long-enough-to-scan";

async fn spawn(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// A proxy in front of `upstream`, with whatever `[redaction]` block is given.
async fn proxy_for(upstream: SocketAddr, redaction: &str) -> String {
    let cfg = format!(
        "listen = \"127.0.0.1:0\"\n\
         [[route]]\nprefix = \"/up\"\nupstream = \"http://{upstream}\"\n\
         allow = [\"TEST_KEY\", \"OTHER_KEY\"]\n{redaction}"
    );
    let config = Config::from_toml(&cfg).unwrap();
    let store = SecretStore::from_values([
        ("TEST_KEY".to_string(), VALUE.to_string()),
        ("OTHER_KEY".to_string(), OTHER.to_string()),
    ]);
    let state = AppState {
        config: Arc::new(config),
        store: Arc::new(ArcSwap::from_pointee(store)),
        client: seekrit_proxy::upstream_client().unwrap(),
        metrics: Arc::new(seekrit_proxy::telemetry::Metrics::new()),
        policy: None,
        sessions: Arc::new(SessionResolver::new(None, None)),
        ratchet: None,
        activity: None,
    };
    let addr = spawn(router(state)).await;
    format!("http://{addr}")
}

/// An upstream that quotes the credential it was sent back into an error body —
/// Stripe's actual behaviour, and the case this whole module exists for.
async fn echoing_upstream() -> SocketAddr {
    spawn(
        Router::new().fallback(any(|req: axum::extract::Request| async move {
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            format!("{{\"error\":{{\"message\":\"Invalid API Key provided: {auth}\"}}}}")
        })),
    )
    .await
}

#[tokio::test]
async fn an_echoed_credential_is_scrubbed_from_the_body() {
    let upstream = echoing_upstream().await;
    let base = proxy_for(upstream, "").await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/up/v1/charges"))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(!text.contains(VALUE), "the credential came back: {text}");
    assert!(text.contains("[redacted by seekrit]"), "{text}");
    // Everything around it is untouched.
    assert!(text.contains("Invalid API Key provided"), "{text}");
}

#[tokio::test]
async fn an_echoed_credential_is_scrubbed_from_a_response_header() {
    // The OAuth case: the upstream bounces the token back in a redirect target,
    // where a body-only scrubber would never look.
    let upstream = spawn(
        Router::new().fallback(any(|req: axum::extract::Request| async move {
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .replace("Bearer ", "");
            Response::builder()
                .status(302)
                .header("location", format!("https://app.test/cb?token={auth}"))
                .body(Body::empty())
                .unwrap()
        })),
    )
    .await;
    let base = proxy_for(upstream, "").await;

    let resp = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(format!("{base}/up/authorize"))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 302);
    let location = resp.headers()["location"].to_str().unwrap();
    assert!(
        !location.contains(VALUE),
        "credential in Location: {location}"
    );
    assert!(location.contains("[redacted by seekrit]"), "{location}");
}

#[tokio::test]
async fn the_response_still_streams_while_being_scanned() {
    // The property that rules out "buffer the body and scan it": the client must
    // see an early chunk before the upstream has finished writing. Without it,
    // every SSE and streaming-completion API behind this proxy would stall until
    // the upstream closed.
    let (release, rx) = tokio::sync::oneshot::channel::<()>();
    let rx = Arc::new(tokio::sync::Mutex::new(Some(rx)));

    let upstream = spawn(Router::new().fallback(any(move || {
        let rx = rx.clone();
        async move {
            let first = futures_util::stream::once(async {
                Ok::<_, Infallible>(bytes::Bytes::from("data: first\n\n"))
            });
            // Nothing more until the test says so.
            let second = futures_util::stream::once(async move {
                if let Some(rx) = rx.lock().await.take() {
                    let _ = rx.await;
                }
                Ok(bytes::Bytes::from("data: second\n\n"))
            });
            Response::builder()
                .header("content-type", "text/event-stream")
                .body(Body::from_stream(first.chain(second)))
                .unwrap()
        }
    })))
    .await;
    let base = proxy_for(upstream, "").await;

    let mut resp = reqwest::Client::new()
        .post(format!("{base}/up/v1/stream"))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();

    // The first chunk must arrive while the upstream is still blocked. A short
    // timeout is the assertion: a buffering proxy never produces it.
    let first = tokio::time::timeout(std::time::Duration::from_secs(2), resp.chunk())
        .await
        .expect("first chunk arrived before the upstream finished")
        .unwrap()
        .expect("a chunk");
    assert_eq!(&first[..], b"data: first\n\n");

    release.send(()).unwrap();
    let rest = resp.text().await.unwrap();
    assert_eq!(rest, "data: second\n\n");
}

#[tokio::test]
async fn a_credential_split_across_stream_chunks_is_still_caught() {
    // The scanner's carry buffer, end to end: the value straddles two frames.
    let (head, tail) = VALUE.split_at(9);
    let head = head.to_string();
    let tail = tail.to_string();
    let upstream = spawn(Router::new().fallback(any(move || {
        let (head, tail) = (head.clone(), tail.clone());
        async move {
            let head = futures_util::stream::once(async move {
                Ok::<_, Infallible>(bytes::Bytes::from(format!("key is {head}")))
            });
            let tail =
                futures_util::stream::once(
                    async move { Ok(bytes::Bytes::from(format!("{tail} ok"))) },
                );
            Response::new(Body::from_stream(head.chain(tail)))
        }
    })))
    .await;
    let base = proxy_for(upstream, "").await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/up/echo"))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    let text = resp.text().await.unwrap();
    assert_eq!(text, "key is [redacted by seekrit] ok");
}

#[tokio::test]
async fn disabling_redaction_restores_pass_through() {
    let upstream = echoing_upstream().await;
    let base = proxy_for(upstream, "[redaction]\nenabled = false\n").await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/up/v1/charges"))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    let text = resp.text().await.unwrap();
    assert!(text.contains(VALUE), "opting out must be honoured: {text}");
}

#[tokio::test]
async fn scan_all_catches_a_secret_this_request_never_sent() {
    // An upstream that returns a *different* credential than the one used to
    // authenticate — outside the default scope, which is why `all` exists.
    let upstream =
        spawn(Router::new().fallback(any(|| async { format!("{{\"stored_key\":\"{OTHER}\"}}") })))
            .await;

    let default_base = proxy_for(upstream, "").await;
    let resp = reqwest::Client::new()
        .post(format!("{default_base}/up/keys"))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    let text = resp.text().await.unwrap();
    assert!(
        text.contains(OTHER),
        "the default scope is this request's own injections"
    );

    let all_base = proxy_for(upstream, "[redaction]\nscan = \"all\"\n").await;
    let resp = reqwest::Client::new()
        .post(format!("{all_base}/up/keys"))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    let text = resp.text().await.unwrap();
    assert!(!text.contains(OTHER), "scan = all missed it: {text}");
}

#[tokio::test]
async fn a_request_that_injected_nothing_is_untouched() {
    // The fast path: no needles, no scanner, and a body that happens to contain
    // the placeholder-free text comes back byte for byte.
    let upstream =
        spawn(Router::new().fallback(any(|| async { "plain body, no credentials" }))).await;
    let base = proxy_for(upstream, "").await;

    let resp = reqwest::Client::new()
        .get(format!("{base}/up/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "plain body, no credentials");
}

#[tokio::test]
async fn an_upstream_redirect_is_returned_rather_than_followed() {
    // Chasing a `3xx` would re-send the substituted credential to a method and
    // path this deployment's policy never authorized, and would turn the echoed
    // token in `Location:` into a live request instead of a scrubbed header.
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = hits.clone();
    let upstream = spawn(Router::new().fallback(any(move || {
        let seen = seen.clone();
        async move {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Response::builder()
                .status(307)
                .header("location", "/somewhere-else")
                .body(Body::empty())
                .unwrap()
        }
    })))
    .await;
    let base = proxy_for(upstream, "").await;

    let resp = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .post(format!("{base}/up/v1/thing"))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 307, "the 3xx reaches the caller");
    assert_eq!(resp.headers()["location"], "/somewhere-else");
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the proxy made a second, unauthorized request"
    );
}
