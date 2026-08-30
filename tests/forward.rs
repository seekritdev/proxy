//! End-to-end tests for the forward proxy (HTTPS_PROXY model).
//!
//!   1. HTTP absolute-form: a ruled host gets placeholders substituted; an
//!      unruled host is denied under `unmatched_host_policy = deny`.
//!   2. HTTPS MITM: a real reqwest client, configured to use the proxy and to
//!      trust the proxy's CA, sends `Authorization: Bearer {{seekrit:…}}` to a
//!      real TLS upstream; the proxy terminates TLS, substitutes, and forwards
//!      to the upstream over its own TLS. The upstream sees the real secret.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;

use arc_swap::ArcSwap;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use seekrit_proxy::ca::Ca;
use seekrit_proxy::config::Config;
use seekrit_proxy::forward::{self, ForwardState};
use seekrit_proxy::secrets::SecretStore;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Default)]
struct Hits(Arc<AtomicUsize>);
impl Hits {
    fn get(&self) -> usize {
        self.0.load(SeqCst)
    }
}

/// Echo the request's `authorization` header and body back as JSON.
async fn echo(req: Request<Incoming>, hits: Hits) -> Result<Response<Full<Bytes>>, Infallible> {
    hits.0.fetch_add(1, SeqCst);
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = Limited::new(req.into_body(), 1 << 20)
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let out = format!(
        "{{\"authorization\":\"{}\",\"body\":\"{}\"}}",
        auth,
        String::from_utf8_lossy(&body)
    );
    Ok(Response::new(Full::new(Bytes::from(out))))
}

/// A plain-HTTP upstream serving [`echo`].
async fn spawn_http_upstream(hits: Hits) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let hits = hits.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| echo(req, hits.clone()));
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    addr
}

/// A TLS upstream serving [`echo`] with a self-signed cert for `host`. Returns
/// its address and the cert PEM (so the proxy's client can trust it).
async fn spawn_tls_upstream(host: &str, hits: Hits) -> (SocketAddr, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![host.to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_pem = cert.pem();
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let hits = hits.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let svc = service_fn(move |req| echo(req, hits.clone()));
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                }
            });
        }
    });
    (addr, cert_pem)
}

fn temp_ca() -> (Ca, String) {
    // A unique dir per call: tests run in parallel and must not share CA files
    // (a shared dir races the load path into pairing a cert with the wrong key).
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "seekrit-proxy-fwd-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let ca = Ca::load_or_generate(
        dir.join("ca.pem").to_str().unwrap(),
        dir.join("ca-key.pem").to_str().unwrap(),
    )
    .unwrap();
    let pem = ca.cert_pem().to_string();
    (ca, pem)
}

fn store() -> SecretStore {
    SecretStore::from_values([("TEST_KEY".to_string(), "s3cr3t-value".to_string())])
}

async fn spawn_forward(state: ForwardState) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        async move { forward::serve(listener, state, std::future::pending::<()>()).await },
    );
    addr
}

#[tokio::test]
async fn http_forward_substitutes_matched_host() {
    let hits = Hits::default();
    let upstream = spawn_http_upstream(hits.clone()).await;
    let (ca, _pem) = temp_ca();

    let cfg = "[forward]\nlisten='127.0.0.1:0'\nunmatched_host_policy='tunnel'\n[[forward.host]]\nmatch='echo.test'\nallow=['TEST_KEY']\n";
    let config = Config::from_toml(cfg).unwrap();
    // The proxy's own client resolves the fake hostname to the real upstream.
    let client = reqwest::Client::builder()
        .resolve("echo.test", upstream)
        .build()
        .unwrap();
    let state = ForwardState {
        config: Arc::new(config),
        store: Arc::new(ArcSwap::from_pointee(store())),
        client,
        ca: Arc::new(ca),
        // No exporter configured in tests, so these instruments are no-ops.
        metrics: std::sync::Arc::new(seekrit_proxy::telemetry::Metrics::new()),
        // These harnesses exercise file policy: no server bundles, no tickets.
        policy: None,
        sessions: std::sync::Arc::new(seekrit_proxy::tasks::SessionResolver::new(None, None)),
        ratchet: None,
        activity: None,
    };
    let proxy = spawn_forward(state).await;

    let agent = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy}")).unwrap())
        .build()
        .unwrap();
    let resp = agent
        .post("http://echo.test/v1/thing")
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .body("b={{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["authorization"], "Bearer s3cr3t-value");
    assert_eq!(json["body"], "b=s3cr3t-value");
    assert_eq!(hits.get(), 1);
}

#[tokio::test]
async fn http_forward_denies_unmatched_host() {
    let hits = Hits::default();
    let upstream = spawn_http_upstream(hits.clone()).await;
    let (ca, _pem) = temp_ca();

    let cfg = "[forward]\nlisten='127.0.0.1:0'\nunmatched_host_policy='deny'\n[[forward.host]]\nmatch='echo.test'\nallow=['TEST_KEY']\n";
    let config = Config::from_toml(cfg).unwrap();
    let client = reqwest::Client::builder()
        .resolve("other.test", upstream)
        .build()
        .unwrap();
    let state = ForwardState {
        config: Arc::new(config),
        store: Arc::new(ArcSwap::from_pointee(store())),
        client,
        ca: Arc::new(ca),
        // No exporter configured in tests, so these instruments are no-ops.
        metrics: std::sync::Arc::new(seekrit_proxy::telemetry::Metrics::new()),
        // These harnesses exercise file policy: no server bundles, no tickets.
        policy: None,
        sessions: std::sync::Arc::new(seekrit_proxy::tasks::SessionResolver::new(None, None)),
        ratchet: None,
        activity: None,
    };
    let proxy = spawn_forward(state).await;

    let agent = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy}")).unwrap())
        .build()
        .unwrap();
    let resp = agent.get("http://other.test/x").send().await.unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(hits.get(), 0); // upstream never contacted
}

#[tokio::test]
async fn https_mitm_substitutes_and_forwards() {
    let hits = Hits::default();
    let (upstream, upstream_cert_pem) = spawn_tls_upstream("upstream.test", hits.clone()).await;
    let (ca, ca_pem) = temp_ca();

    let cfg = "[forward]\nlisten='127.0.0.1:0'\n[[forward.host]]\nmatch='upstream.test'\nallow=['TEST_KEY']\n";
    let config = Config::from_toml(cfg).unwrap();
    // Proxy's client trusts the upstream's cert and resolves its hostname.
    let proxy_client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(upstream_cert_pem.as_bytes()).unwrap())
        .resolve("upstream.test", upstream)
        .build()
        .unwrap();
    let state = ForwardState {
        config: Arc::new(config),
        store: Arc::new(ArcSwap::from_pointee(store())),
        client: proxy_client,
        ca: Arc::new(ca),
        // No exporter configured in tests, so these instruments are no-ops.
        metrics: std::sync::Arc::new(seekrit_proxy::telemetry::Metrics::new()),
        // These harnesses exercise file policy: no server bundles, no tickets.
        policy: None,
        sessions: std::sync::Arc::new(seekrit_proxy::tasks::SessionResolver::new(None, None)),
        ratchet: None,
        activity: None,
    };
    let proxy = spawn_forward(state).await;

    // The agent uses the proxy for HTTPS and trusts the proxy's CA.
    let agent = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(format!("http://{proxy}")).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let resp = agent
        .post(format!("https://upstream.test:{}/v1/chat", upstream.port()))
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    // The upstream, behind real TLS, saw the decrypted secret — proving the
    // proxy terminated, substituted, and re-originated TLS end to end.
    assert_eq!(json["authorization"], "Bearer s3cr3t-value");
    assert_eq!(hits.get(), 1);
}

#[tokio::test]
async fn http_forward_enforces_operation_constraints_on_a_ruled_host() {
    let hits = Hits::default();
    let upstream = spawn_http_upstream(hits.clone()).await;
    let (ca, _pem) = temp_ca();

    // A ruled host with a narrow rule for writes and a broad read rule that
    // carries no credential — the shape an operator writes to let an agent browse
    // an API while only one operation may hold the key.
    let cfg = "[forward]\nlisten='127.0.0.1:0'\nunmatched_host_policy='tunnel'\n\
               [[forward.host]]\nmatch='echo.test'\nmethods=['POST']\npaths=['/v1/thing']\nallow=['TEST_KEY']\n\
               [[forward.host]]\nmatch='echo.test'\nmethods=['GET']\n";
    let config = Config::from_toml(cfg).unwrap();
    let client = reqwest::Client::builder()
        .resolve("echo.test", upstream)
        .build()
        .unwrap();
    let state = ForwardState {
        config: Arc::new(config),
        store: Arc::new(ArcSwap::from_pointee(store())),
        client,
        ca: Arc::new(ca),
        metrics: std::sync::Arc::new(seekrit_proxy::telemetry::Metrics::new()),
        policy: None,
        sessions: std::sync::Arc::new(seekrit_proxy::tasks::SessionResolver::new(None, None)),
        ratchet: None,
        activity: None,
    };
    let proxy = spawn_forward(state).await;

    let agent = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy}")).unwrap())
        .build()
        .unwrap();

    // The permitted write, with the credential.
    let ok = agent
        .post("http://echo.test/v1/thing")
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // A read is permitted as an operation, but may not carry the key.
    let read = agent.get("http://echo.test/v1/thing").send().await.unwrap();
    assert_eq!(read.status(), 200);
    let read_with_key = agent
        .get("http://echo.test/v1/thing")
        .header("authorization", "Bearer {{seekrit:TEST_KEY}}")
        .send()
        .await
        .unwrap();
    assert_eq!(read_with_key.status(), 403);

    // A write to a path outside the write rule is refused outright — anti-misuse,
    // not just anti-theft. The refusal names the *method*, not the path, because
    // the read rule does cover this path and is the rule that declined: that is
    // the more useful thing to tell whoever is reading the log.
    let off_path = agent
        .post("http://echo.test/v1/other")
        .send()
        .await
        .unwrap();
    assert_eq!(off_path.status(), 403);
    assert!(off_path
        .text()
        .await
        .unwrap()
        .contains("method is not permitted"));

    // A method no rule covers at all, likewise.
    let bad_method = agent
        .delete("http://echo.test/v1/thing")
        .send()
        .await
        .unwrap();
    assert_eq!(bad_method.status(), 403);

    assert_eq!(hits.get(), 2, "only the two permitted requests got through");
}
