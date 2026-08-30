//! `seekrit-cache`: the opt-in **last-known-good** cache shared by every Rust
//! machine client (`apps/run`, `apps/proxy`, `apps/seekrit-sdk-server`).
//!
//! # What it stores, and why that is safe
//!
//! Exactly one thing: the body of a `GET /v1/resolve` response, verbatim. That
//! body is ciphertext plus per-principal **wrapped** DEKs — the same bytes the
//! API serves and Cloudflare already caches at the edge. Plaintext never enters
//! this crate; neither does a decrypted DEK. Unwrapping still requires the
//! service token's private key, which lives in the token itself.
//!
//! The entry is therefore no more sensitive than the token sitting beside it on
//! the same machine (`~/.config/seekrit/config.json`, `SEEKRIT_TOKEN`, a
//! mounted Kubernetes Secret). An attacker who can read a cache file can already
//! read that token and call `/v1/resolve` themselves. Files are still written
//! `0600` inside a `0700` directory, because "no worse than the token" is only
//! true if the cache is guarded like the token.
//!
//! # Why it is off by default
//!
//! A persisted entry outlives the network. Deleting a key grant stops the *next*
//! resolve immediately (ARCHITECTURE.md → "Revocation"), but a cached entry
//! keeps working offline until it expires, and a client that never calls
//! `/v1/resolve` never trips the `env.resolve_denied` audit row that would
//! otherwise surface a revoked token still in the field. That is a real
//! trade — availability for a bounded revocation tail — so it is a decision the
//! operator makes, per deployment, and [`Cache::max_age`] bounds it.
//!
//! Consumers reinforce this by always attempting a **live** resolve first and
//! treating the cache purely as a fallback; the long-lived services additionally
//! retry on a fast backoff while degraded, so a recovered network is picked up
//! in seconds rather than at the next scheduled refresh.
//!
//! # On-disk format (v1)
//!
//! One JSON file per `(api url, token, branch, group overrides)` tuple, named
//! `<key>.json` where `<key>` is the hex SHA-256 of that tuple:
//!
//! ```json
//! {
//!   "version": 1,
//!   "fetchedAt": 1755100000,
//!   "tokenFingerprint": "9f86d0…",
//!   "body": "{\"scope\":{…},\"layers\":[…]}"
//! }
//! ```
//!
//! `body` is a string, not nested JSON, so the response round-trips byte-exact.
//! The format is shared with the Node CLI (`apps/cli/src/cache.ts`) — the two
//! read each other's entries, and both pin the key derivation to the same test
//! vector. Changing either half means bumping `version`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The on-disk format version. Bump on any incompatible change; entries written
/// by another version are ignored (treated as a miss), never misread.
pub const FORMAT_VERSION: u32 = 1;

/// Domain separator for the cache key. Included so the digest can never collide
/// with another SHA-256 the project computes over similar inputs.
const KEY_DOMAIN: &str = "seekrit-lkg-cache-v1";
/// Domain separator for cached agent policy bundles (see
/// [`CacheKey::for_agent_policy`]) — distinct from resolve entries.
const POLICY_KEY_DOMAIN: &str = "seekrit-policy-cache-v1";
/// Domain separator for the stored token fingerprint.
const TOKEN_DOMAIN: &str = "seekrit-token-fp-v1";

/// How long an entry may be served when the API is unreachable, unless the
/// operator overrides it. A day is long enough to ride out any realistic
/// outage and short enough that a revoked token's offline tail is bounded.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// The envelope as written to disk.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    version: u32,
    /// Seconds since the Unix epoch, at the moment the live response arrived.
    fetched_at: u64,
    /// Hex SHA-256 of the token that fetched it. Checked on read so an entry
    /// can never be served to a different credential, even if a file is copied
    /// into place by hand.
    token_fingerprint: String,
    /// The `/v1/resolve` response body, verbatim.
    body: String,
}

/// A usable cache entry.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The `/v1/resolve` response body, exactly as the API returned it.
    pub body: String,
    /// How long ago it was fetched.
    pub age: Duration,
}

/// What a read found. Callers log the distinction — "no entry yet" and "the
/// entry expired four hours ago" call for very different operator responses.
#[derive(Debug, Clone)]
pub enum Lookup {
    Hit(Entry),
    /// Nothing cached for this key yet.
    Missing,
    /// An entry exists but is older than [`Cache::max_age`].
    Expired {
        age: Duration,
    },
    /// Present but unusable: wrong format version, a different token, corrupt
    /// JSON, or unreadable. Carries a reason for the log line.
    Unusable(String),
}

impl Lookup {
    /// The entry, if this lookup produced a usable one.
    pub fn entry(self) -> Option<Entry> {
        match self {
            Lookup::Hit(e) => Some(e),
            _ => None,
        }
    }
}

/// A failure to *write* the cache. Never fatal to a consumer: a workload that
/// resolved successfully should run even if it could not record the result.
#[derive(Debug)]
pub enum CacheError {
    /// The cache directory could not be determined (no `--cache-dir`, no
    /// `XDG_CACHE_HOME`, no `HOME`).
    NoDirectory,
    Io(String),
    Serialize(String),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::NoDirectory => write!(
                f,
                "no cache directory: pass an explicit path, or set XDG_CACHE_HOME or HOME"
            ),
            CacheError::Io(m) => write!(f, "{m}"),
            CacheError::Serialize(m) => write!(f, "could not serialize the cache entry: {m}"),
        }
    }
}

impl std::error::Error for CacheError {}

/// Identifies one cached resolve. Two requests share an entry only when the API
/// URL, the token, the branch, and the group overrides all match — anything
/// less and a `--with` override could be served a plain environment's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheKey {
    key: String,
    token_fingerprint: String,
}

impl CacheKey {
    /// Derive the key for one resolve request.
    ///
    /// `overrides` are `(group, env)` pairs; they are sorted here, so the caller's
    /// flag order does not split the cache. Keep this byte-for-byte in step with
    /// `cacheKey()` in `apps/cli/src/cache.ts`.
    pub fn new(
        api_url: &str,
        token: &str,
        branch: Option<&str>,
        overrides: &[(String, String)],
    ) -> CacheKey {
        let mut pairs: Vec<String> = overrides.iter().map(|(g, e)| format!("{g}:{e}")).collect();
        pairs.sort();

        let mut hasher = Sha256::new();
        hasher.update(KEY_DOMAIN.as_bytes());
        hasher.update(b"\n");
        hasher.update(api_url.trim_end_matches('/').as_bytes());
        hasher.update(b"\n");
        hasher.update(token.as_bytes());
        hasher.update(b"\n");
        hasher.update(branch.unwrap_or("").as_bytes());
        hasher.update(b"\n");
        hasher.update(pairs.join(",").as_bytes());

        CacheKey {
            key: hex(&hasher.finalize()),
            token_fingerprint: token_fingerprint(token),
        }
    }

    /// Derive the key for one **agent policy** fetch (`apps/proxy`, server
    /// policy mode).
    ///
    /// A separate domain string from the resolve key, so a policy bundle and a
    /// resolve response can never be served for each other's key even though
    /// they share a directory and a token. Caching signed policy is safe on the
    /// same terms as caching ciphertext: the entry carries its own signature, so
    /// a tampered copy is refused by the verifier rather than trusted.
    pub fn for_agent_policy(api_url: &str, token: &str, agent: &str) -> CacheKey {
        let mut hasher = Sha256::new();
        hasher.update(POLICY_KEY_DOMAIN.as_bytes());
        hasher.update(b"\n");
        hasher.update(api_url.trim_end_matches('/').as_bytes());
        hasher.update(b"\n");
        hasher.update(token.as_bytes());
        hasher.update(b"\n");
        hasher.update(agent.as_bytes());

        CacheKey {
            key: hex(&hasher.finalize()),
            token_fingerprint: token_fingerprint(token),
        }
    }

    /// The hex digest that names the file (without the `.json` suffix).
    pub fn as_str(&self) -> &str {
        &self.key
    }
}

/// The hex SHA-256 identifying a token without storing it.
pub fn token_fingerprint(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(TOKEN_DOMAIN.as_bytes());
    hasher.update(b"\n");
    hasher.update(token.as_bytes());
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A directory of last-known-good entries.
pub struct Cache {
    dir: PathBuf,
    max_age: Duration,
}

impl Cache {
    /// A cache rooted at an explicit directory.
    pub fn new(dir: impl Into<PathBuf>, max_age: Duration) -> Cache {
        Cache {
            dir: dir.into(),
            max_age,
        }
    }

    /// A cache at `dir`, or at the platform default when `dir` is `None`.
    pub fn with_optional_dir(
        dir: Option<impl Into<PathBuf>>,
        max_age: Duration,
    ) -> Result<Cache, CacheError> {
        let dir = match dir {
            Some(d) => d.into(),
            None => default_dir().ok_or(CacheError::NoDirectory)?,
        };
        Ok(Cache::new(dir, max_age))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// The file backing `key`.
    pub fn path(&self, key: &CacheKey) -> PathBuf {
        self.dir.join(format!("{}.json", key.as_str()))
    }

    /// Look up `key`. Never errors — an unreadable or corrupt cache is a miss
    /// with a reason, because a broken cache must not break a working boot.
    pub fn read(&self, key: &CacheKey) -> Lookup {
        let path = self.path(key);
        let raw = match fs::read_to_string(&path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Lookup::Missing,
            Err(e) => return Lookup::Unusable(format!("could not read {}: {e}", path.display())),
        };

        let envelope: Envelope = match serde_json::from_str(&raw) {
            Ok(e) => e,
            Err(e) => return Lookup::Unusable(format!("corrupt cache entry: {e}")),
        };
        if envelope.version != FORMAT_VERSION {
            return Lookup::Unusable(format!(
                "cache entry is format v{}, this build reads v{FORMAT_VERSION}",
                envelope.version
            ));
        }
        // Defense in depth: the token is already folded into the file name, so
        // a mismatch means the file was moved or hand-edited.
        if envelope.token_fingerprint != key.token_fingerprint {
            return Lookup::Unusable("cache entry belongs to a different token".to_string());
        }

        // Usable strictly *under* the limit, so a max-age of zero means "never
        // serve from cache" rather than "serve anything written this second".
        let age = age_of(envelope.fetched_at);
        if age >= self.max_age {
            return Lookup::Expired { age };
        }
        Lookup::Hit(Entry {
            body: envelope.body,
            age,
        })
    }

    /// Record a freshly-fetched response body.
    ///
    /// Written to a temporary file and renamed, so a concurrent reader sees
    /// either the old entry or the new one and never a half-written file.
    pub fn write(&self, key: &CacheKey, body: &str) -> Result<(), CacheError> {
        create_dir_private(&self.dir)?;

        let envelope = Envelope {
            version: FORMAT_VERSION,
            fetched_at: now_secs(),
            token_fingerprint: key.token_fingerprint.clone(),
            body: body.to_string(),
        };
        let encoded =
            serde_json::to_string(&envelope).map_err(|e| CacheError::Serialize(e.to_string()))?;

        let final_path = self.path(key);
        // The pid keeps two processes writing the same key from colliding on
        // the temporary file; the rename below is what makes it atomic.
        let tmp_path = self
            .dir
            .join(format!("{}.{}.tmp", key.as_str(), std::process::id()));

        let write_result = (|| -> std::io::Result<()> {
            let mut file = create_private_file(&tmp_path)?;
            file.write_all(encoded.as_bytes())?;
            file.sync_all()
        })();
        if let Err(e) = write_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(CacheError::Io(format!(
                "could not write {}: {e}",
                tmp_path.display()
            )));
        }

        if let Err(e) = fs::rename(&tmp_path, &final_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(CacheError::Io(format!(
                "could not replace {}: {e}",
                final_path.display()
            )));
        }

        // Opportunistic hygiene: a rotated token or a changed `--with` leaves an
        // entry nothing will ever read again. Drop anything past its usefulness
        // so stale ciphertext doesn't accumulate forever.
        self.prune_expired();
        Ok(())
    }

    /// Delete entries older than [`Cache::max_age`]. Best-effort and silent:
    /// this is housekeeping, not part of anyone's correctness.
    pub fn prune_expired(&self) {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Only ever touch files this crate named: `<64 hex>.json`.
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".json") else {
                continue;
            };
            if stem.len() != 64 || !stem.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let expired = fs::read_to_string(&path)
                .ok()
                .and_then(|raw| serde_json::from_str::<Envelope>(&raw).ok())
                .map(|env| age_of(env.fetched_at) >= self.max_age)
                // Unparseable entries are dead weight too.
                .unwrap_or(true);
            if expired {
                let _ = fs::remove_file(&path);
            }
        }
    }

    /// Remove the entry for `key`, if any. Used when a live resolve is rejected
    /// on the merits (a revoked or expired token), where continuing to serve the
    /// cached payload would extend exactly the window the API just closed.
    pub fn invalidate(&self, key: &CacheKey) {
        let _ = fs::remove_file(self.path(key));
    }
}

/// Render a duration for an operator-facing log line, rounded to its largest
/// whole unit ("42s", "7m", "3h", "2d"). Precision past that would be noise in
/// a message whose point is "this is how stale your secrets are".
pub fn humanize(d: Duration) -> String {
    let secs = d.as_secs();
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86_399 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86_400),
    }
}

/// Parse a max-age like `30s`, `15m`, `24h`, `7d`, or a bare seconds count.
/// Shared by every consumer so `--cache-max-age` means the same thing in the
/// launcher, the proxy, the sidecar, and the proxy's TOML config.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (value, unit_secs) = match s.strip_suffix(['s', 'm', 'h', 'd']) {
        Some(rest) => {
            let mult = match s.as_bytes()[s.len() - 1] {
                b's' => 1,
                b'm' => 60,
                b'h' => 3600,
                b'd' => 86_400,
                _ => unreachable!("suffix matched above"),
            };
            (rest, mult)
        }
        None => (s, 1),
    };
    let n: u64 = value
        .trim()
        .parse()
        .map_err(|_| format!("not a duration: {s:?} (try 15m, 24h, 7d)"))?;
    if n == 0 {
        return Err("must be greater than zero".to_string());
    }
    n.checked_mul(unit_secs)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("duration too large: {s:?}"))
}

/// `$XDG_CACHE_HOME/seekrit`, else `$HOME/.cache/seekrit`. Mirrors how
/// `apps/cli/src/config.ts` locates the config directory, so the cache lands
/// beside the credential it belongs to rather than in a shared temp directory.
///
/// Deliberately **not** `/tmp`: a world-writable directory with predictable
/// names invites symlink and TOCTOU games, and `/tmp` is cleared on reboot —
/// exactly when a cold boot most needs the cache.
pub fn default_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(xdg).join("seekrit"));
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(home).join(".cache").join("seekrit"));
    }
    // Windows, where neither of the above is normally set. `seekrit-run` is
    // tested and shipped there, so it gets a real default too.
    if let Some(local) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(local).join("seekrit").join("cache"));
    }
    let profile = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty())?;
    Some(PathBuf::from(profile).join(".cache").join("seekrit"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Age of an entry stamped at `fetched_at`. A stamp in the future (clock skew,
/// or a machine that booted with a bad RTC) reads as brand new rather than
/// wrapping around to something enormous.
fn age_of(fetched_at: u64) -> Duration {
    Duration::from_secs(now_secs().saturating_sub(fetched_at))
}

#[cfg(unix)]
fn create_dir_private(dir: &Path) -> Result<(), CacheError> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.is_dir() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| CacheError::Io(format!("could not create {}: {e}", dir.display())))
}

#[cfg(not(unix))]
fn create_dir_private(dir: &Path) -> Result<(), CacheError> {
    fs::create_dir_all(dir)
        .map_err(|e| CacheError::Io(format!("could not create {}: {e}", dir.display())))
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    fs::File::create(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory that cleans itself up, so tests don't need a crate.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> TempDir {
            let dir = std::env::temp_dir().join(format!(
                "seekrit-cache-test-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn key(token: &str) -> CacheKey {
        CacheKey::new("https://api.seekrit.dev", token, None, &[])
    }

    #[test]
    fn round_trips_a_body() {
        let dir = TempDir::new("roundtrip");
        let cache = Cache::new(dir.0.clone(), DEFAULT_MAX_AGE);
        let k = key("skt_test");

        assert!(matches!(cache.read(&k), Lookup::Missing));
        cache.write(&k, r#"{"scope":{},"layers":[]}"#).unwrap();

        match cache.read(&k) {
            Lookup::Hit(entry) => {
                assert_eq!(entry.body, r#"{"scope":{},"layers":[]}"#);
                assert!(entry.age < Duration::from_secs(5));
            }
            other => panic!("expected a hit, got {other:?}"),
        }
    }

    #[test]
    fn key_is_stable_and_request_specific() {
        // The same request always derives the same key...
        assert_eq!(key("skt_a"), key("skt_a"));
        // ...and anything that changes the response changes the key.
        assert_ne!(key("skt_a"), key("skt_b"));
        assert_ne!(
            key("skt_a"),
            CacheKey::new("https://api.seekrit.dev", "skt_a", Some("pr-1"), &[])
        );
        assert_ne!(
            key("skt_a"),
            CacheKey::new(
                "https://api.seekrit.dev",
                "skt_a",
                None,
                &[("shared".into(), "staging".into())]
            )
        );
        // A trailing slash on the API URL is not a different request.
        assert_eq!(
            key("skt_a"),
            CacheKey::new("https://api.seekrit.dev/", "skt_a", None, &[])
        );
        // Flag order must not split the cache.
        let a = CacheKey::new(
            "https://api.seekrit.dev",
            "skt_a",
            None,
            &[("b".into(), "x".into()), ("a".into(), "y".into())],
        );
        let b = CacheKey::new(
            "https://api.seekrit.dev",
            "skt_a",
            None,
            &[("a".into(), "y".into()), ("b".into(), "x".into())],
        );
        assert_eq!(a, b);
    }

    /// Pins the derivation so the Node CLI (`apps/cli/src/cache.ts`) and this
    /// crate cannot drift apart silently — the same vector is asserted there.
    #[test]
    fn key_matches_the_cross_implementation_vector() {
        let k = CacheKey::new(
            "https://api.seekrit.dev",
            "skt_vector",
            Some("pr-42"),
            &[("shared".into(), "staging".into())],
        );
        assert_eq!(
            k.as_str(),
            "6dba653a0e4d4c47c5a43e561afa08148f18eeb29e2f34a2b108ed39f506fae7"
        );
        assert_eq!(
            token_fingerprint("skt_vector"),
            "8d2db10682b926bb5b635eb7ed7b966ca57c006b325d25b529715280be947af8"
        );
    }

    #[test]
    fn expired_entries_are_not_served() {
        let dir = TempDir::new("expiry");
        let k = key("skt_test");
        // Write with a generous max-age, then read with a strict one.
        Cache::new(dir.0.clone(), DEFAULT_MAX_AGE)
            .write(&k, "{}")
            .unwrap();
        let strict = Cache::new(dir.0.clone(), Duration::from_secs(0));
        // Backdate the entry so it is unambiguously older than zero seconds.
        backdate(&strict.path(&k), 60);
        match strict.read(&k) {
            Lookup::Expired { age } => assert!(age >= Duration::from_secs(60)),
            other => panic!("expected expiry, got {other:?}"),
        }
    }

    #[test]
    fn a_different_token_cannot_read_the_entry() {
        let dir = TempDir::new("fingerprint");
        let cache = Cache::new(dir.0.clone(), DEFAULT_MAX_AGE);
        let mine = key("skt_mine");
        cache.write(&mine, "{}").unwrap();

        // Rename the file to another token's key: the fingerprint inside still
        // says who it belongs to, so it is refused rather than served.
        let theirs = key("skt_theirs");
        fs::rename(cache.path(&mine), cache.path(&theirs)).unwrap();
        match cache.read(&theirs) {
            Lookup::Unusable(msg) => assert!(msg.contains("different token"), "{msg}"),
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn corrupt_and_wrong_version_entries_are_a_miss() {
        let dir = TempDir::new("corrupt");
        let cache = Cache::new(dir.0.clone(), DEFAULT_MAX_AGE);
        let k = key("skt_test");

        fs::write(cache.path(&k), "not json at all").unwrap();
        assert!(matches!(cache.read(&k), Lookup::Unusable(_)));

        let future = format!(
            r#"{{"version":99,"fetchedAt":{},"tokenFingerprint":"{}","body":"{{}}"}}"#,
            now_secs(),
            token_fingerprint("skt_test")
        );
        fs::write(cache.path(&k), future).unwrap();
        match cache.read(&k) {
            Lookup::Unusable(msg) => assert!(msg.contains("format v99"), "{msg}"),
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn write_is_atomic_and_leaves_no_temp_files() {
        let dir = TempDir::new("atomic");
        let cache = Cache::new(dir.0.clone(), DEFAULT_MAX_AGE);
        let k = key("skt_test");
        cache.write(&k, "{}").unwrap();
        cache.write(&k, r#"{"layers":[]}"#).unwrap();

        let names: Vec<String> = fs::read_dir(&dir.0)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![format!("{}.json", k.as_str())]);
        assert_eq!(cache.read(&k).entry().unwrap().body, r#"{"layers":[]}"#);
    }

    #[cfg(unix)]
    #[test]
    fn entries_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("perms");
        // A fresh subdirectory, so we observe what the crate creates.
        let nested = dir.0.join("nested");
        let cache = Cache::new(nested.clone(), DEFAULT_MAX_AGE);
        let k = key("skt_test");
        cache.write(&k, "{}").unwrap();

        let dir_mode = fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(cache.path(&k)).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "cache directory must not be group/world readable"
        );
        assert_eq!(
            file_mode, 0o600,
            "cache entry must not be group/world readable"
        );
    }

    #[test]
    fn prune_drops_expired_entries_and_ignores_strangers() {
        let dir = TempDir::new("prune");
        let long = Cache::new(dir.0.clone(), DEFAULT_MAX_AGE);
        let old = key("skt_old");
        let fresh = key("skt_fresh");
        long.write(&old, "{}").unwrap();
        long.write(&fresh, "{}").unwrap();
        // A file this crate did not write must survive pruning untouched.
        let stranger = dir.0.join("notes.txt");
        fs::write(&stranger, "keep me").unwrap();

        backdate(&long.path(&old), 3600);
        let strict = Cache::new(dir.0.clone(), Duration::from_secs(600));
        strict.prune_expired();

        assert!(!long.path(&old).exists(), "expired entry should be pruned");
        assert!(long.path(&fresh).exists(), "fresh entry should survive");
        assert!(stranger.exists(), "unrelated files must never be removed");
    }

    #[test]
    fn invalidate_removes_the_entry() {
        let dir = TempDir::new("invalidate");
        let cache = Cache::new(dir.0.clone(), DEFAULT_MAX_AGE);
        let k = key("skt_test");
        cache.write(&k, "{}").unwrap();
        cache.invalidate(&k);
        assert!(matches!(cache.read(&k), Lookup::Missing));
        // Invalidating something already gone is not an error.
        cache.invalidate(&k);
    }

    #[test]
    fn humanizes_ages() {
        assert_eq!(humanize(Duration::from_secs(0)), "0s");
        assert_eq!(humanize(Duration::from_secs(59)), "59s");
        assert_eq!(humanize(Duration::from_secs(60)), "1m");
        assert_eq!(humanize(Duration::from_secs(3599)), "59m");
        assert_eq!(humanize(Duration::from_secs(3600)), "1h");
        assert_eq!(humanize(Duration::from_secs(86_399)), "23h");
        assert_eq!(humanize(Duration::from_secs(172_800)), "2d");
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("24h").unwrap(), DEFAULT_MAX_AGE);
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604_800));
        assert!(parse_duration("0h").is_err());
        assert!(parse_duration("later").is_err());
        assert!(parse_duration("99999999999999999999d").is_err());
    }

    #[test]
    fn default_dir_follows_xdg() {
        // Serialized implicitly: this is the only test touching these vars.
        let saved = [
            ("XDG_CACHE_HOME", std::env::var_os("XDG_CACHE_HOME")),
            ("HOME", std::env::var_os("HOME")),
            ("LOCALAPPDATA", std::env::var_os("LOCALAPPDATA")),
            ("USERPROFILE", std::env::var_os("USERPROFILE")),
        ];
        for (name, _) in &saved {
            std::env::remove_var(name);
        }

        std::env::set_var("XDG_CACHE_HOME", "/xdg");
        assert_eq!(default_dir().unwrap(), PathBuf::from("/xdg/seekrit"));

        std::env::remove_var("XDG_CACHE_HOME");
        std::env::set_var("HOME", "/home/someone");
        assert_eq!(
            default_dir().unwrap(),
            PathBuf::from("/home/someone/.cache/seekrit")
        );

        // Windows: neither of the above is set there, but LOCALAPPDATA is.
        std::env::remove_var("HOME");
        std::env::set_var("LOCALAPPDATA", "C:\\Users\\someone\\AppData\\Local");
        assert_eq!(
            default_dir().unwrap(),
            PathBuf::from("C:\\Users\\someone\\AppData\\Local")
                .join("seekrit")
                .join("cache")
        );

        std::env::remove_var("LOCALAPPDATA");
        assert!(default_dir().is_none());

        for (name, value) in saved {
            match value {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
    }

    /// Rewrite an entry's `fetchedAt` to `secs` ago, so age-dependent behavior
    /// is testable without sleeping.
    fn backdate(path: &Path, secs: u64) {
        let raw = fs::read_to_string(path).unwrap();
        let mut env: Envelope = serde_json::from_str(&raw).unwrap();
        env.fetched_at = now_secs().saturating_sub(secs);
        fs::write(path, serde_json::to_string(&env).unwrap()).unwrap();
    }
}
