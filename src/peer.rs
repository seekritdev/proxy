//! Who is on the other end of the control socket — the process, not the token.
//!
//! The control listener hands out session tickets and, since `[approval]`, also
//! accepts the decision that releases a held request. Both were gated by one
//! thing: possession of `SEEKRIT_PROXY_CONTROL_TOKEN`.
//!
//! That gate has a hole with the shape of this whole product. The orchestrator
//! exports the token; the agent it launches is a **child process and inherits the
//! environment**. So the agent can mint itself a ticket for any identity this
//! proxy serves, and — worse — approve its own held request. "The agent cannot
//! approve its own request" is the property the approval control exists for, and
//! a shared secret in an inherited environment does not establish it.
//!
//! A token answers "does the caller know a secret". This module answers **"which
//! program is calling"**, which is the question that actually distinguishes an
//! orchestrator from the agent it spawned — they run as the same user, on the
//! same machine, often from the same shell.
//!
//! ## What is proven, and what is inferred
//!
//! Stated plainly because the difference decides how much this is worth:
//!
//! - **uid and gid are proven.** The kernel attaches them to the connection at
//!   connect time; nothing the peer says is involved. They stop a *different
//!   user* cold, and they stop nothing else — an agent runs as the same user as
//!   its orchestrator, which is precisely the case that matters here.
//! - **The pid is proven, at connect time.** Same source. What it *names* can
//!   drift: a peer that exits immediately after connecting frees its pid for
//!   reuse, so the process we then inspect may not be the process that connected.
//!   The window is microseconds and closing it entirely needs a pidfd the peer
//!   hands us, which no HTTP client will do.
//! - **The binary is inferred, and how strongly depends on the platform.** On
//!   Linux `/proc/<pid>/exe` resolves to the *running image's inode*, so reading
//!   it reads what is executing even if the path was replaced on disk — the
//!   strong form. On macOS `proc_pidpath` yields a path, which is re-read; a
//!   replacement between execution and inspection would go unnoticed. Neither is
//!   a signature check. This is a strong signal, not a proof.
//!
//! The honest summary: this raises local impersonation from "read an environment
//! variable" to "be the allow-listed program, or replace it on disk". That is a
//! large step and not an absolute one, and the docs say so rather than implying
//! kernel-grade attestation.
//!
//! ## Why a Unix socket
//!
//! Peer credentials do not exist on a TCP connection — loopback or not. A TCP
//! control listener is reachable by every process on the machine and can only
//! ever check the token. So attestation requires `[control] socket`, and a config
//! that asks for attestation without one is refused at startup rather than
//! quietly enforcing nothing.
//!
//! Windows named pipes expose an equivalent (`GetNamedPipeClientProcessId`) and
//! are not implemented here; `socket` is refused on Windows rather than silently
//! degrading to the token alone.

use std::collections::BTreeSet;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

/// The identity the kernel (and then the filesystem) gives for one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub gid: u32,
    /// `None` when the platform does not report it.
    pub pid: Option<i32>,
    /// The peer's executable, if it could be resolved.
    pub binary: Option<PathBuf>,
    /// Lowercase hex SHA-256 of that executable, if it could be read.
    pub sha256: Option<String>,
}

impl Peer {
    /// A one-line description for logs. A uid and a program path are not
    /// credentials, so both may be recorded.
    pub fn describe(&self) -> String {
        let who = match (&self.binary, self.pid) {
            (Some(path), Some(pid)) => format!("{} (pid {pid})", path.display()),
            (Some(path), None) => path.display().to_string(),
            (None, Some(pid)) => format!("pid {pid}"),
            (None, None) => "an unidentified process".to_string(),
        };
        format!("{who} as uid {}", self.uid)
    }
}

/// Why a connection could not be identified at all.
#[derive(Debug)]
pub enum PeerError {
    /// The kernel would not report credentials for this connection.
    Unavailable(String),
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerError::Unavailable(m) => {
                write!(
                    f,
                    "could not read peer credentials for this connection: {m}"
                )
            }
        }
    }
}

impl std::error::Error for PeerError {}

/// Who may talk to the control listener.
///
/// Empty means "only the uid check applies", which is the default and is already
/// meaningfully better than a shared secret on a TCP port.
#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    /// Permitted uids. Empty ⇒ the proxy's own uid only, filled in at validation.
    pub uids: BTreeSet<u32>,
    /// Permitted executable paths, absolute and compared exactly.
    pub binaries: BTreeSet<PathBuf>,
    /// Permitted executable digests, lowercase hex SHA-256.
    ///
    /// Preferable to a path when the caller can be upgraded in place: a path says
    /// "whatever is installed there now", a digest says "this image".
    pub digests: BTreeSet<String>,
}

impl PeerPolicy {
    /// Does this policy look at the program at all, or only at the user?
    pub fn attests_binary(&self) -> bool {
        !self.binaries.is_empty() || !self.digests.is_empty()
    }

    /// May this peer use the control listener?
    ///
    /// `Err` carries a message for the log and the 403 body. It names what was
    /// rejected — a path and a uid, never anything secret.
    pub fn admits(&self, peer: &Peer) -> Result<(), String> {
        if !self.uids.is_empty() && !self.uids.contains(&peer.uid) {
            return Err(format!(
                "uid {} is not permitted on this control listener",
                peer.uid
            ));
        }
        if !self.attests_binary() {
            return Ok(());
        }

        // Either form of identity is enough: an operator who pinned a digest does
        // not also have to pin the path it happens to live at, and vice versa.
        if let Some(sha) = peer.sha256.as_deref() {
            if self.digests.contains(sha) {
                return Ok(());
            }
        }
        if let Some(path) = peer.binary.as_ref() {
            if self.binaries.contains(path) {
                return Ok(());
            }
        }

        // Distinguish "not on the list" from "we could not tell", because the
        // remedies are completely different — one is a config line, the other is a
        // platform or permissions problem.
        match (&peer.binary, &peer.sha256) {
            (None, _) => Err(
                "this connection's program could not be identified, and this control listener \
                 only admits programs it can identify"
                    .to_string(),
            ),
            (Some(path), None) => Err(format!(
                "{} could not be read to verify its digest",
                path.display()
            )),
            (Some(path), Some(_)) => Err(format!(
                "{} is not an allow-listed program for this control listener",
                path.display()
            )),
        }
    }
}

impl PeerPolicy {
    /// Build the effective policy for a control socket.
    ///
    /// `allow_uid` is filled in with the proxy's own uid when the config does not
    /// name one. That substitution happens here rather than in `from_toml` so
    /// parsing stays pure — a config file must not mean different things
    /// depending on which user parsed it.
    pub fn from_control(config: &crate::config::ControlConfig, own_uid: u32) -> PeerPolicy {
        PeerPolicy {
            uids: match &config.allow_uid {
                Some(uids) => uids.iter().copied().collect(),
                None => [own_uid].into_iter().collect(),
            },
            binaries: config.allow_binary.iter().cloned().collect(),
            digests: config.allow_sha256.iter().cloned().collect(),
        }
    }
}

/// The uid this proxy is running as.
#[cfg(unix)]
pub fn own_uid() -> u32 {
    // SAFETY: `getuid` takes no arguments, cannot fail, and returns a plain uid.
    unsafe { libc::getuid() }
}

/// Serve the control router over a Unix socket, admitting only peers the policy
/// allows.
///
/// The check happens **once per connection, before any request is read**, which
/// is the only place it can happen: peer credentials belong to the socket, not
/// to an HTTP request, and an accepted-then-refused connection must not have
/// been able to do anything first.
#[cfg(unix)]
pub async fn serve_attested<F: std::future::Future<Output = ()>>(
    listener: tokio::net::UnixListener,
    policy: std::sync::Arc<PeerPolicy>,
    router: axum::Router,
    shutdown: F,
) {
    use hyper_util::service::TowerToHyperService;

    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _addr) = match accepted {
                    Ok(x) => x,
                    Err(e) => { tracing::debug!("control accept error: {e}"); continue; }
                };
                let policy = policy.clone();
                let router = router.clone();
                tokio::spawn(async move {
                    let verdict = match identify(&stream) {
                        Ok(peer) => match policy.admits(&peer) {
                            Ok(()) => {
                                tracing::debug!(peer = %peer.describe(), "control connection admitted");
                                None
                            }
                            Err(reason) => {
                                // Security-significant: something on this machine
                                // that is not the orchestrator tried to use the
                                // listener that mints tickets and releases held
                                // requests.
                                tracing::warn!(
                                    target: "seekrit_audit",
                                    peer = %peer.describe(),
                                    "refused a control connection: {reason}",
                                );
                                Some(reason)
                            }
                        },
                        Err(e) => {
                            tracing::warn!(target: "seekrit_audit", "refused a control connection: {e}");
                            Some(e.to_string())
                        }
                    };

                    let io = hyper_util::rt::TokioIo::new(stream);
                    let result = match verdict {
                        None => {
                            hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, TowerToHyperService::new(router))
                                .await
                        }
                        // Refused connections still get an answer rather than a
                        // reset: the caller is usually an operator's own tool, and
                        // "connection closed" sends them to the wrong problem.
                        // The reason names a path and a uid, which the caller
                        // already knows about itself.
                        Some(reason) => {
                            let svc = hyper::service::service_fn(move |_req| {
                                let reason = reason.clone();
                                async move {
                                    hyper::Response::builder()
                                        .status(hyper::StatusCode::FORBIDDEN)
                                        .body(format!("seekrit-proxy: {reason}\n"))
                                }
                            });
                            hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, svc)
                                .await
                        }
                    };
                    if let Err(e) = result {
                        tracing::debug!("control connection ended: {e}");
                    }
                });
            }
        }
    }
}

/// Identify the peer of an accepted Unix connection.
///
/// Reads the kernel-attached credentials first and only then touches the
/// filesystem, so the inspection happens as close to the connect as the runtime
/// allows.
#[cfg(unix)]
pub fn identify(stream: &tokio::net::UnixStream) -> Result<Peer, PeerError> {
    let cred = stream
        .peer_cred()
        .map_err(|e| PeerError::Unavailable(e.to_string()))?;
    let pid = cred.pid();
    let binary = pid.and_then(executable_of);
    // On Linux this deliberately re-opens `/proc/<pid>/exe` rather than the
    // resolved path: that descriptor follows the running image's inode, so a
    // binary replaced on disk after exec is still hashed as what is executing.
    let sha256 = match (pid, binary.as_ref()) {
        (Some(pid), Some(_)) => digest_of(pid),
        _ => None,
    };
    Ok(Peer {
        uid: cred.uid(),
        gid: cred.gid(),
        pid,
        binary,
        sha256,
    })
}

/// The executable behind a pid, or `None` when the platform cannot say.
#[cfg(target_os = "linux")]
fn executable_of(pid: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(target_os = "macos")]
fn executable_of(pid: i32) -> Option<PathBuf> {
    // `PROC_PIDPATHINFO_MAXSIZE` is 4 * MAXPATHLEN.
    const MAX: usize = 4 * 1024;
    let mut buf = vec![0u8; MAX];
    // SAFETY: `buf` is a live allocation of `MAX` bytes and the length passed
    // matches it. `proc_pidpath` writes at most that many bytes and returns the
    // number written, or a non-positive value on failure.
    let len = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), MAX as u32) };
    if len <= 0 {
        return None;
    }
    buf.truncate(len as usize);
    String::from_utf8(buf).ok().map(PathBuf::from)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn executable_of(_pid: i32) -> Option<PathBuf> {
    None
}

/// SHA-256 of the image a pid is running.
#[cfg(target_os = "linux")]
fn digest_of(pid: i32) -> Option<String> {
    // The strong form: this descriptor refers to the inode that was executed, so
    // replacing the file at that path afterwards does not change what is read.
    hash_file(&PathBuf::from(format!("/proc/{pid}/exe")))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn digest_of(pid: i32) -> Option<String> {
    // The weaker form: a path, re-read now. A replacement between exec and here
    // would go unnoticed — see the module comment.
    hash_file(&executable_of(pid)?)
}

#[cfg_attr(not(unix), allow(dead_code))]
fn hash_file(path: &std::path::Path) -> Option<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    // Streamed rather than slurped: an allow-listed program can legitimately be
    // a few hundred megabytes, and this runs on every control connection.
    let mut buf = [0u8; 64 * 1024];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(uid: u32, binary: Option<&str>, sha: Option<&str>) -> Peer {
        Peer {
            uid,
            gid: uid,
            pid: Some(1234),
            binary: binary.map(PathBuf::from),
            sha256: sha.map(str::to_string),
        }
    }

    fn policy(uids: &[u32], binaries: &[&str], digests: &[&str]) -> PeerPolicy {
        PeerPolicy {
            uids: uids.iter().copied().collect(),
            binaries: binaries.iter().map(PathBuf::from).collect(),
            digests: digests.iter().map(|d| d.to_string()).collect(),
        }
    }

    #[test]
    fn a_different_uid_is_refused() {
        let p = policy(&[501], &[], &[]);
        assert!(p.admits(&peer(501, None, None)).is_ok());
        let err = p.admits(&peer(502, None, None)).unwrap_err();
        assert!(err.contains("uid 502"), "{err}");
    }

    #[test]
    fn a_uid_only_policy_does_not_look_at_the_program() {
        // The baseline posture: better than a token on a TCP port, and explicitly
        // not enough to tell an orchestrator from the agent it spawned.
        let p = policy(&[501], &[], &[]);
        assert!(!p.attests_binary());
        assert!(p
            .admits(&peer(501, Some("/bin/anything"), Some("ab")))
            .is_ok());
    }

    #[test]
    fn an_allow_listed_path_is_admitted_and_anything_else_is_not() {
        let p = policy(&[501], &["/usr/local/bin/orchestrator"], &[]);
        assert!(p
            .admits(&peer(501, Some("/usr/local/bin/orchestrator"), Some("ab")))
            .is_ok());
        // The motivating case: same user, same machine, different program.
        let err = p
            .admits(&peer(501, Some("/usr/local/bin/agent"), Some("cd")))
            .unwrap_err();
        assert!(err.contains("/usr/local/bin/agent"), "{err}");
        assert!(err.contains("not an allow-listed program"), "{err}");
    }

    #[test]
    fn a_pinned_digest_admits_whatever_path_it_runs_from() {
        // A digest says "this image"; a path says "whatever is installed there
        // now". Pinning one must not require pinning the other.
        let p = policy(&[501], &[], &["abc123"]);
        assert!(p
            .admits(&peer(501, Some("/tmp/wherever"), Some("abc123")))
            .is_ok());
        assert!(p
            .admits(&peer(501, Some("/usr/bin/x"), Some("def456")))
            .is_err());
    }

    #[test]
    fn either_form_of_identity_is_enough() {
        let p = policy(&[501], &["/usr/local/bin/orchestrator"], &["abc123"]);
        // Matches the path, not the digest.
        assert!(p
            .admits(&peer(501, Some("/usr/local/bin/orchestrator"), Some("zzz")))
            .is_ok());
        // Matches the digest, not the path.
        assert!(p
            .admits(&peer(501, Some("/opt/other"), Some("abc123")))
            .is_ok());
    }

    #[test]
    fn an_unidentifiable_program_is_refused_with_a_different_reason() {
        // "Not on the list" and "we could not tell" have completely different
        // remedies, so they must not read the same.
        let p = policy(&[501], &["/usr/local/bin/orchestrator"], &[]);
        let err = p.admits(&peer(501, None, None)).unwrap_err();
        assert!(err.contains("could not be identified"), "{err}");

        let unreadable = p
            .admits(&peer(501, Some("/usr/local/bin/x"), None))
            .unwrap_err();
        assert!(unreadable.contains("could not be read"), "{unreadable}");
    }

    #[test]
    fn an_empty_uid_set_permits_any_user() {
        // Validation fills the proxy's own uid in, so this state is only reachable
        // when an operator deliberately widened it.
        let p = policy(&[], &[], &[]);
        assert!(p.admits(&peer(0, None, None)).is_ok());
        assert!(p.admits(&peer(65534, None, None)).is_ok());
    }

    #[test]
    fn a_peer_describes_itself_without_anything_secret() {
        let described = peer(501, Some("/usr/local/bin/orchestrator"), Some("abc")).describe();
        assert!(
            described.contains("/usr/local/bin/orchestrator"),
            "{described}"
        );
        assert!(described.contains("pid 1234"), "{described}");
        assert!(described.contains("uid 501"), "{described}");
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff, 0xab]), "000fffab");
    }

    #[test]
    fn this_test_binary_hashes_to_something_stable() {
        // The end-to-end property, using the one process a test can be sure
        // about: hashing the same image twice agrees, and it is 64 hex chars.
        let exe = std::env::current_exe().expect("a test binary path");
        let first = hash_file(&exe).expect("readable");
        let second = hash_file(&exe).expect("readable");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn hashing_something_that_is_not_there_reports_nothing() {
        assert!(hash_file(&PathBuf::from("/nonexistent/seekrit/probe")).is_none());
    }
}
