//! End-to-end peer attestation on the control socket.
//!
//! The motivating threat, concretely: the orchestrator exports
//! `SEEKRIT_PROXY_CONTROL_TOKEN`, the agent it spawns inherits the environment,
//! and the agent then approves its own held request. The token cannot tell the
//! two apart — they are the same user on the same machine — so the listener has
//! to look at *which program* is calling.
//!
//! These tests use the one peer a test can be certain about: itself. The test
//! binary connects to the socket, so allow-listing `current_exe()` is the
//! admitted case and allow-listing anything else is the refused one.
//!
//! Unix only: peer credentials do not exist on a TCP connection, which is the
//! whole reason `[control] socket` exists.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use seekrit_proxy::peer::{self, Peer, PeerPolicy};
use seekrit_proxy::tickets::{control_router, ControlState, TicketStore, CONTROL_TOKEN_HEADER};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CONTROL_TOKEN: &str = "test-control-token";

/// A socket path of its own per test — parallel tests must not share a node.
fn socket_path(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "seekrit-proxy-peer-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(format!("{tag}.sock"))
}

fn state() -> ControlState {
    ControlState {
        tickets: Arc::new(TicketStore::new(
            vec!["default".to_string()],
            Duration::from_secs(60),
            Duration::from_secs(60),
        )),
        token: Arc::new(CONTROL_TOKEN.to_string()),
        approvals: None,
    }
}

/// Serve an attested control socket under `policy`, returning its path.
async fn serve(tag: &str, policy: PeerPolicy) -> PathBuf {
    let path = socket_path(tag);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let router = control_router(state());
    tokio::spawn(peer::serve_attested(
        listener,
        Arc::new(policy),
        router,
        std::future::pending::<()>(),
    ));
    path
}

/// One HTTP/1.1 request over a Unix socket, hand-rolled.
///
/// A full HTTP client would need a Unix connector; the assertions here only ever
/// look at the status line, so the bytes are written directly.
async fn request(path: &PathBuf, token: Option<&str>) -> String {
    let mut stream = tokio::net::UnixStream::connect(path)
        .await
        .expect("connect");
    let auth = match token {
        Some(t) => format!("{CONTROL_TOKEN_HEADER}: {t}\r\n"),
        None => String::new(),
    };
    let req = format!("GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{auth}\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.expect("read");
    String::from_utf8_lossy(&body).to_string()
}

fn current_exe() -> PathBuf {
    std::env::current_exe().expect("a test binary path")
}

#[tokio::test]
async fn an_allow_listed_program_is_admitted() {
    let policy = PeerPolicy {
        uids: [peer::own_uid()].into_iter().collect(),
        binaries: [current_exe()].into_iter().collect(),
        digests: Default::default(),
    };
    let path = serve("admitted", policy).await;

    let resp = request(&path, Some(CONTROL_TOKEN)).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.contains("\"ok\":true"), "{resp}");
}

#[tokio::test]
async fn a_program_that_is_not_allow_listed_is_refused() {
    // The motivating case: same uid, same machine, valid token — different
    // program. This is the agent holding the orchestrator's inherited token.
    let policy = PeerPolicy {
        uids: [peer::own_uid()].into_iter().collect(),
        binaries: [PathBuf::from("/usr/local/bin/some-other-orchestrator")]
            .into_iter()
            .collect(),
        digests: Default::default(),
    };
    let path = serve("refused", policy).await;

    let resp = request(&path, Some(CONTROL_TOKEN)).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(
        resp.contains("not an allow-listed program"),
        "the refusal should say why: {resp}"
    );
    // And it is refused on identity, before the token is even consulted — a
    // valid token does not rescue the wrong program.
    assert!(!resp.contains("\"ok\":true"), "{resp}");
}

#[tokio::test]
async fn the_running_image_digest_admits_this_binary() {
    // Pin the image rather than the path: `identify` must hash what is actually
    // executing, so the digest it computes has to match the one a policy pins.
    let me = current_exe();
    let listener_path = socket_path("digest");
    let listener = tokio::net::UnixListener::bind(&listener_path).unwrap();

    // Hash the same way a policy author would, from the file on disk.
    let digest = {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(&me).expect("readable test binary");
        Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };

    let policy = PeerPolicy {
        uids: [peer::own_uid()].into_iter().collect(),
        binaries: Default::default(),
        digests: [digest].into_iter().collect(),
    };
    tokio::spawn(peer::serve_attested(
        listener,
        Arc::new(policy),
        control_router(state()),
        std::future::pending::<()>(),
    ));

    let resp = request(&listener_path, Some(CONTROL_TOKEN)).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
}

#[tokio::test]
async fn a_wrong_digest_is_refused() {
    let policy = PeerPolicy {
        uids: [peer::own_uid()].into_iter().collect(),
        binaries: Default::default(),
        digests: [format!("{:064x}", 1)].into_iter().collect(),
    };
    let path = serve("wrong-digest", policy).await;

    let resp = request(&path, Some(CONTROL_TOKEN)).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
}

#[tokio::test]
async fn a_different_uid_is_refused_before_the_program_is_considered() {
    let policy = PeerPolicy {
        // A uid this test process certainly is not.
        uids: [peer::own_uid().wrapping_add(1)].into_iter().collect(),
        binaries: [current_exe()].into_iter().collect(),
        digests: Default::default(),
    };
    let path = serve("wrong-uid", policy).await;

    let resp = request(&path, Some(CONTROL_TOKEN)).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(resp.contains("uid"), "{resp}");
}

#[tokio::test]
async fn attestation_does_not_replace_the_token() {
    // Both gates stand: being the right program does not excuse a missing token,
    // any more than holding the token excuses being the wrong program.
    let policy = PeerPolicy {
        uids: [peer::own_uid()].into_iter().collect(),
        binaries: [current_exe()].into_iter().collect(),
        digests: Default::default(),
    };
    let path = serve("token-still-required", policy).await;

    // `/health` needs no token, so use an endpoint that does.
    let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    let body = "{}";
    let req = format!(
        "POST /session HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    let resp = String::from_utf8_lossy(&out);
    assert!(resp.starts_with("HTTP/1.1 401"), "{resp}");
}

#[tokio::test]
async fn a_uid_only_policy_admits_this_process() {
    // The default posture when no allow_binary/allow_sha256 is configured. It is
    // better than a token on a TCP port and explicitly not enough to separate an
    // orchestrator from the agent it spawned — which is why startup says so.
    let policy = PeerPolicy {
        uids: [peer::own_uid()].into_iter().collect(),
        binaries: Default::default(),
        digests: Default::default(),
    };
    assert!(!policy.attests_binary());
    let path = serve("uid-only", policy).await;

    let resp = request(&path, Some(CONTROL_TOKEN)).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
}

#[tokio::test]
async fn identify_reports_this_process_accurately() {
    let path = socket_path("identify");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let accepted = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        peer::identify(&stream).expect("peer credentials")
    });
    let _client = tokio::net::UnixStream::connect(&path).await.unwrap();

    let identified: Peer = accepted.await.unwrap();
    assert_eq!(identified.uid, peer::own_uid());
    assert_eq!(identified.pid, Some(std::process::id() as i32));
    assert_eq!(
        identified.binary.as_deref(),
        Some(current_exe().as_path()),
        "the connecting program is this test binary"
    );
    let sha = identified.sha256.expect("a digest");
    assert_eq!(sha.len(), 64);
}
