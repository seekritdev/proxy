//! Proxy configuration (TOML). Deserialized into [`RawConfig`], then validated
//! into a [`Config`] with parsed addresses, normalized route prefixes, and
//! upstream URLs checked up front so a bad config fails at startup, never at
//! request time.
//!
//! ```toml
//! listen = "127.0.0.1:8080"
//! max_request_body_bytes = 2097152   # optional; default 2 MiB
//!
//! [[route]]
//! prefix = "/example"
//! upstream = "https://api.example.com"
//! allow = ["EXAMPLE_API_KEY"]        # secrets injectable toward this upstream
//! methods = ["POST"]                 # optional; absent = any method
//! paths = ["/v1/chat/**"]            # optional; absent = any path
//!
//! [cache]                            # optional; off unless enabled
//! enabled = true
//! max_age = "24h"
//! ```
//!
//! `methods` and `paths` are **operation constraints**: they bound what an agent
//! may *do* to an upstream, not merely which credential may reach it. Absent
//! means any, so a config written before they existed behaves exactly as it did.
//! Both are matched by [`seekrit_core::policy`] — the same evaluator that runs
//! server-delivered policy, so a rule cannot mean two different things depending
//! on where it came from.
//!
//! ## Where policy comes from
//!
//! `[policy] source` picks between the rules in this file (the default, and a
//! legitimate posture: no network dependency for authorization) and signed
//! bundles published from the dashboard. In server mode this file shrinks to a
//! **trust anchor** — which signers to trust, where to listen, and optionally a
//! ceiling — while the churny part (rules and credentials) moves to the UI. See
//! `docs/agent-access-governance.md`.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use seekrit_core::policy::{Ceiling, MethodSet, PathSet, Rule, RuleSet};
use serde::Deserialize;

/// 2 MiB — request bodies are buffered to substitute placeholders, so we cap
/// them. API request payloads are far smaller; large uploads are not the target.
const DEFAULT_MAX_BODY: usize = 2 * 1024 * 1024;
const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
const DEFAULT_CA_CERT: &str = "seekrit-proxy-ca.pem";
const DEFAULT_CA_KEY: &str = "seekrit-proxy-ca-key.pem";

#[derive(Debug, Deserialize)]
struct RawConfig {
    listen: Option<String>,
    max_request_body_bytes: Option<usize>,
    #[serde(default)]
    propagate_trace_upstream: Option<bool>,
    #[serde(default)]
    route: Vec<RawRoute>,
    forward: Option<RawForward>,
    cache: Option<RawCache>,
    policy: Option<RawPolicy>,
    control: Option<RawControl>,
    secrets: Option<RawSecrets>,
    tasks: Option<RawTasks>,
    ratchet: Option<RawRatchet>,
    activity: Option<RawActivity>,
}

#[derive(Debug, Deserialize)]
struct RawCache {
    enabled: Option<bool>,
    dir: Option<String>,
    max_age: Option<String>,
    /// How long to wait before the first reconnect attempt after starting from
    /// the cache. Doubles up to `reconnect_max_interval`.
    reconnect_interval: Option<String>,
    reconnect_max_interval: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawRoute {
    prefix: String,
    upstream: String,
    #[serde(default)]
    allow: Vec<String>,
    /// HTTP methods this route permits. Absent/empty = any.
    #[serde(default)]
    methods: Vec<String>,
    /// Path patterns this route permits, matched against the path *after* the
    /// prefix is stripped — the upstream-facing path, which is what an operator
    /// reasons about. Absent/empty = any.
    #[serde(default)]
    paths: Vec<String>,
    /// Optional note, surfaced in logs when this rule decides.
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawForward {
    listen: Option<String>,
    unmatched_host_policy: Option<String>,
    ca_cert: Option<String>,
    ca_key: Option<String>,
    #[serde(default)]
    host: Vec<RawHostRule>,
}

#[derive(Debug, Deserialize)]
struct RawHostRule {
    #[serde(rename = "match")]
    host: String,
    #[serde(default)]
    allow: Vec<String>,
    /// HTTP methods this host rule permits. Absent/empty = any.
    #[serde(default)]
    methods: Vec<String>,
    /// Path patterns this host rule permits (full request path). Absent = any.
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawPolicy {
    source: Option<String>,
    agent: Option<String>,
    #[serde(default)]
    agents: Vec<String>,
    org: Option<String>,
    refresh_interval: Option<String>,
    #[serde(default)]
    signers: Vec<String>,
    #[serde(default)]
    ceiling: Vec<RawCeilingEntry>,
}

#[derive(Debug, Deserialize)]
struct RawCeilingEntry {
    host: String,
    #[serde(default)]
    allow: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawControl {
    listen: Option<String>,
    ttl: Option<String>,
    max_ttl: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSecrets {
    refresh_interval: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawTasks {
    cache_ttl: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawActivity {
    flush_interval: Option<String>,
    max_cells: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RawRatchet {
    #[serde(default)]
    state: Vec<RawRatchetState>,
    #[serde(default)]
    transition: Vec<RawTransition>,
}

#[derive(Debug, Deserialize)]
struct RawRatchetState {
    name: String,
    hosts: Option<Vec<String>>,
    secrets: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RawTransition {
    host: String,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
    to: String,
    label: Option<String>,
}

/// A validated proxy configuration. Either a reverse proxy (`routes`), a
/// forward/MITM proxy (`forward`), or both may be configured.
#[derive(Debug)]
pub struct Config {
    /// Reverse-proxy listen address (used only when `routes` is non-empty).
    pub listen: SocketAddr,
    pub max_body: usize,
    /// Add W3C `traceparent`/`tracestate` to forwarded requests.
    ///
    /// **Off by default.** The proxy's upstreams are typically third-party APIs
    /// the customer does not operate, where propagation buys nothing and the
    /// header is just correlatable metadata handed to an outside party — a poor
    /// default for a tool whose job is limiting what leaves the workload.
    /// Turn it on (`propagate_trace_upstream = true`) when the upstream is your
    /// own instrumented service and you want one continuous trace.
    ///
    /// Independent of whether telemetry is exported at all: this governs what
    /// the *upstream* receives.
    pub propagate_trace_upstream: bool,
    /// Sorted by prefix length (longest first) so matching is longest-prefix.
    pub routes: Vec<Route>,
    /// Optional forward proxy (HTTPS_PROXY / CONNECT) with TLS interception.
    pub forward: Option<ForwardConfig>,
    /// Opt-in last-known-good cache. `None` (the default) means the proxy
    /// refuses to start when it cannot resolve — the historical behavior.
    pub cache: Option<CacheConfig>,
    /// Where authorization comes from, and (in server mode) who to trust for it.
    pub policy: PolicyConfig,
    /// Optional control listener that mints session tickets for an orchestrator.
    pub control: Option<ControlConfig>,
    /// Optional periodic re-resolve of secrets (see [`SecretsConfig`]).
    pub secrets: SecretsConfig,
    /// Whether this proxy honours tasks dispatched through the seekrit API.
    ///
    /// Absent means it does not: an `skd_…` token is refused by name rather than
    /// silently treated as an unknown ticket. Opting in is a deliberate act
    /// because it makes a running proxy depend on the API to authorize a new run.
    pub tasks: Option<TasksConfig>,
    /// Optional trust ratchet — capability that narrows as a run proceeds.
    pub ratchet: Option<crate::ratchet::RatchetConfig>,
    /// Whether this proxy reports aggregate decisions back for policy review.
    ///
    /// Absent means it does not. Opt-in because it is a new outbound data path,
    /// and one an operator should choose rather than discover — even though what
    /// it carries (hosts, methods, secret names, counts, and never a path) is the
    /// same vocabulary their own telemetry already exports.
    pub activity: Option<ActivityConfig>,
}

/// The validated `[activity]` block.
#[derive(Debug, Clone)]
pub struct ActivityConfig {
    /// How often counts are flushed. One request per interval, and none at all
    /// when nothing was decided.
    pub flush_interval: Duration,
    /// Cap on distinct cells held between flushes, so unusual traffic cannot grow
    /// the map without bound. Overflow is dropped and reported as incomplete.
    pub max_cells: usize,
}

/// The validated `[tasks]` block.
#[derive(Debug, Clone)]
pub struct TasksConfig {
    /// How long an introspection result is reused.
    ///
    /// This is the knob that bounds how quickly a revoke takes effect, so it is
    /// short by default. Raising it trades revocation latency for fewer calls on
    /// the request path; lowering it does the reverse.
    pub cache_ttl: Duration,
}

/// The validated `[cache]` block.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Where entries live. `None` = the platform default
    /// (`$XDG_CACHE_HOME/seekrit`, else `~/.cache/seekrit`).
    pub dir: Option<String>,
    /// How stale a cached response may be and still be used at startup.
    pub max_age: Duration,
    /// First reconnect delay after a degraded start.
    pub reconnect_interval: Duration,
    /// Ceiling the reconnect backoff doubles up to.
    pub reconnect_max_interval: Duration,
}

/// Where the proxy gets the rules it enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySource {
    /// This file. The default, and the posture with no network dependency for
    /// authorization — deliberately kept, not deprecated.
    File,
    /// Signed bundles fetched from the seekrit API and verified against the
    /// signers pinned below.
    Server,
}

/// The validated `[policy]` block.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    pub source: PolicySource,
    /// The agent identity this deployment is by default (id or slug). Required
    /// in server mode; requests with no session ticket are evaluated against it.
    pub agent: Option<String>,
    /// Every agent identity this proxy may serve, `agent` first. Declared up
    /// front on purpose: the set of policies fetched is bounded by the local
    /// file, so a compromised API cannot make the proxy chase identities the
    /// operator never named.
    pub agents: Vec<String>,
    /// Optional org id, checked against the bundle's `org` claim as a second
    /// binding beyond the agent.
    pub org: Option<String>,
    /// How often to re-fetch the bundle. Cheap: a steady state is a 304.
    pub refresh_interval: Duration,
    /// **The trust anchor.** Thumbprints of the keys whose signatures this
    /// deployment accepts. The one input that must not come from the server.
    pub signers: Vec<String>,
    /// Optional fleet ceiling: server policy may only narrow this. `None` means
    /// no ceiling, which is the right default for interactive development —
    /// there the adversary is the local agent, which can edit local files
    /// anyway, so a ceiling adds no security and blocks the whole point of a UI.
    pub ceiling: Option<Ceiling>,
}

impl Default for PolicyConfig {
    fn default() -> PolicyConfig {
        PolicyConfig {
            source: PolicySource::File,
            agent: None,
            agents: Vec::new(),
            org: None,
            refresh_interval: DEFAULT_POLICY_REFRESH,
            signers: Vec::new(),
            ceiling: None,
        }
    }
}

impl PolicyConfig {
    pub fn is_server(&self) -> bool {
        self.source == PolicySource::Server
    }
}

/// The validated `[control]` block: a loopback listener that mints session
/// tickets for an orchestrator (never for the agent itself).
#[derive(Debug, Clone)]
pub struct ControlConfig {
    pub listen: SocketAddr,
    /// Default ticket lifetime when a request does not ask for one.
    pub ttl: Duration,
    /// The longest lifetime the control listener will mint.
    pub max_ttl: Duration,
}

/// The validated `[secrets]` block: periodic re-resolve.
///
/// The proxy historically resolved once and never again, which makes adding a
/// credential in the dashboard invisible to a healthy running proxy. Server
/// policy mode turns this on implicitly (a new rule and the credential it names
/// have to land together, or the first request still fails); file mode can opt
/// in.
#[derive(Debug, Clone, Default)]
pub struct SecretsConfig {
    pub refresh_interval: Option<Duration>,
}

/// What the forward proxy does with a request to a host that has no rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmatchedPolicy {
    /// Blind-tunnel it through untouched (no interception, no injection) so the
    /// workload's other traffic keeps working. The default.
    Tunnel,
    /// Refuse it (HTTP `403`). Strict mode: only allowlisted hosts are reachable.
    Deny,
}

/// The validated forward-proxy configuration.
#[derive(Debug)]
pub struct ForwardConfig {
    pub listen: SocketAddr,
    pub unmatched: UnmatchedPolicy,
    pub ca_cert_path: String,
    pub ca_key_path: String,
    /// Host rules in file order (first match wins), or `None` in server mode —
    /// there the intercepted hosts come from the published policy, which is the
    /// whole point: adding an upstream must not mean editing local TOML.
    pub rules: Option<RuleSet>,
}

/// One `prefix → upstream` mapping.
#[derive(Debug)]
pub struct Route {
    /// Normalized: leading `/`, no trailing `/`. Empty string = catch-all.
    pub prefix: String,
    /// Upstream base URL, validated and trailing-slash trimmed.
    pub upstream: String,
    /// Upstream host (for audit logs and policy matching), from `upstream`.
    pub host: String,
    /// This route's own authorization, as a one-rule set keyed by [`Self::host`]
    /// so the same evaluator serves file and server policy. `None` in server
    /// mode, where the rules come from the published bundle.
    ///
    /// Per-route rather than host-keyed on purpose: two routes may point at the
    /// same upstream with different allowlists, and collapsing them by host
    /// would let the broader one answer for the narrower one.
    pub rules: Option<RuleSet>,
}

#[derive(Debug)]
pub enum ConfigError {
    Read(String),
    Parse(String),
    Listen(String),
    Route(String),
    Forward(String),
    Cache(String),
    Policy(String),
    Control(String),
    Secrets(String),
    Tasks(String),
    Ratchet(String),
    Activity(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Read(m) => write!(f, "could not read config: {m}"),
            ConfigError::Parse(m) => write!(f, "invalid config: {m}"),
            ConfigError::Listen(m) => write!(f, "invalid listen address: {m}"),
            ConfigError::Route(m) => write!(f, "invalid route: {m}"),
            ConfigError::Forward(m) => write!(f, "invalid [forward] config: {m}"),
            ConfigError::Cache(m) => write!(f, "invalid [cache] config: {m}"),
            ConfigError::Policy(m) => write!(f, "invalid [policy] config: {m}"),
            ConfigError::Control(m) => write!(f, "invalid [control] config: {m}"),
            ConfigError::Secrets(m) => write!(f, "invalid [secrets] config: {m}"),
            ConfigError::Tasks(m) => write!(f, "invalid [tasks] config: {m}"),
            ConfigError::Ratchet(m) => write!(f, "invalid [ratchet] config: {m}"),
            ConfigError::Activity(m) => write!(f, "invalid [activity] config: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Default policy refresh. Short, because the motivating flow is a developer
/// adding a rule in the dashboard and expecting the running proxy to pick it up
/// before they give up on it. `ETag`/`If-None-Match` makes the steady state a
/// 304, so this costs almost nothing; fleet deployments can raise it.
const DEFAULT_POLICY_REFRESH: Duration = Duration::from_secs(10);
/// Refusing anything faster keeps a typo (`refresh_interval = "10ms"`) from
/// turning a proxy into a hot loop against the API.
const MIN_POLICY_REFRESH: Duration = Duration::from_secs(1);
const DEFAULT_TICKET_TTL: Duration = Duration::from_secs(3600);
const DEFAULT_TICKET_MAX_TTL: Duration = Duration::from_secs(12 * 3600);

impl Config {
    /// Load and validate a config file from `path`.
    pub fn load(path: &str) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Read(e.to_string()))?;
        Config::from_toml(&text)
    }

    /// Parse + validate config from a TOML string (kept separate for tests).
    pub fn from_toml(text: &str) -> Result<Config, ConfigError> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;

        let listen: SocketAddr = raw
            .listen
            .as_deref()
            .unwrap_or(DEFAULT_LISTEN)
            .parse()
            .map_err(|e| ConfigError::Listen(format!("{e}")))?;

        let policy = PolicyConfig::validate(raw.policy)?;

        let mut routes = Vec::with_capacity(raw.route.len());
        for r in raw.route {
            routes.push(Route::validate(r, &policy)?);
        }
        // Longest prefix first: a request path matches the most specific route.
        routes.sort_by_key(|r| std::cmp::Reverse(r.prefix.len()));

        let forward = raw
            .forward
            .map(|f| ForwardConfig::validate(f, &policy))
            .transpose()?;

        // At least one mode must be configured, or the proxy does nothing.
        if routes.is_empty() && forward.is_none() {
            return Err(ConfigError::Parse(
                "no [[route]] and no [forward] — nothing to proxy".into(),
            ));
        }
        // If both run, they can't share a listen address.
        if let Some(f) = &forward {
            if !routes.is_empty() && f.listen == listen {
                return Err(ConfigError::Forward(format!(
                    "forward listen {} collides with the reverse-proxy listen; use different ports",
                    f.listen
                )));
            }
        }

        let control = raw.control.map(ControlConfig::validate).transpose()?;
        if let Some(control) = &control {
            if control.listen == listen {
                return Err(ConfigError::Control(
                    "control listen collides with the reverse-proxy listen; use different ports"
                        .into(),
                ));
            }
            if forward.as_ref().is_some_and(|f| f.listen == control.listen) {
                return Err(ConfigError::Control(
                    "control listen collides with the forward listen; use different ports".into(),
                ));
            }
        }

        // Server policy implies secret refresh: a rule the dashboard just
        // published and the credential it names have to land together, or the
        // agent's first request still fails on an unknown secret.
        let mut secrets = SecretsConfig::validate(raw.secrets)?;
        if policy.is_server() && secrets.refresh_interval.is_none() {
            secrets.refresh_interval = Some(policy.refresh_interval);
        }

        let tasks = raw.tasks.map(TasksConfig::validate).transpose()?;
        let activity = raw.activity.map(ActivityConfig::validate).transpose()?;
        let ratchet = raw.ratchet.map(validate_ratchet).transpose()?;

        Ok(Config {
            listen,
            max_body: raw.max_request_body_bytes.unwrap_or(DEFAULT_MAX_BODY),
            propagate_trace_upstream: raw.propagate_trace_upstream.unwrap_or(false),
            routes,
            forward,
            // Two layers of "absent": no `[cache]` block at all, and a block
            // that explicitly says `enabled = false`. Both mean no cache.
            cache: raw.cache.map(CacheConfig::validate).transpose()?.flatten(),
            policy,
            control,
            secrets,
            tasks,
            ratchet,
            activity,
        })
    }

    /// Find the most specific route whose prefix matches `path`.
    pub fn match_route(&self, path: &str) -> Option<&Route> {
        self.routes.iter().find(|r| r.matches(path))
    }
}

/// First reconnect attempt after a degraded start. Short: the whole point is to
/// stop serving stale secrets as soon as the API is back.
const DEFAULT_RECONNECT: Duration = Duration::from_secs(5);
/// Ceiling for the reconnect backoff, so a long outage settles into a poll
/// rather than hammering an API that is already having a bad day.
const DEFAULT_RECONNECT_MAX: Duration = Duration::from_secs(300);

/// Parse a duration string with the shared `seekrit-cache` parser, so every
/// interval in this file accepts the same `"5s"` / `"10m"` / `"24h"` forms.
fn duration(
    value: Option<String>,
    default: Duration,
    field: &str,
    wrap: fn(String) -> ConfigError,
) -> Result<Duration, ConfigError> {
    match value {
        Some(raw) => seekrit_cache::parse_duration(&raw).map_err(|e| wrap(format!("{field}: {e}"))),
        None => Ok(default),
    }
}

impl CacheConfig {
    fn validate(raw: RawCache) -> Result<Option<CacheConfig>, ConfigError> {
        // Present but `enabled = false` is an explicit off — same as absent.
        if !raw.enabled.unwrap_or(false) {
            return Ok(None);
        }
        let reconnect_interval = duration(
            raw.reconnect_interval,
            DEFAULT_RECONNECT,
            "reconnect_interval",
            ConfigError::Cache,
        )?;
        let reconnect_max_interval = duration(
            raw.reconnect_max_interval,
            DEFAULT_RECONNECT_MAX,
            "reconnect_max_interval",
            ConfigError::Cache,
        )?;
        if reconnect_max_interval < reconnect_interval {
            return Err(ConfigError::Cache(
                "reconnect_max_interval must be at least reconnect_interval".into(),
            ));
        }

        Ok(Some(CacheConfig {
            dir: raw.dir,
            max_age: duration(
                raw.max_age,
                seekrit_cache::DEFAULT_MAX_AGE,
                "max_age",
                ConfigError::Cache,
            )?,
            reconnect_interval,
            reconnect_max_interval,
        }))
    }
}

impl PolicyConfig {
    fn validate(raw: Option<RawPolicy>) -> Result<PolicyConfig, ConfigError> {
        let Some(raw) = raw else {
            return Ok(PolicyConfig::default());
        };
        let source = match raw
            .source
            .as_deref()
            .unwrap_or("file")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "file" => PolicySource::File,
            "server" => PolicySource::Server,
            other => {
                return Err(ConfigError::Policy(format!(
                    "source must be \"file\" or \"server\", got {other:?}"
                )))
            }
        };

        let refresh_interval = duration(
            raw.refresh_interval,
            DEFAULT_POLICY_REFRESH,
            "refresh_interval",
            ConfigError::Policy,
        )?;
        if refresh_interval < MIN_POLICY_REFRESH {
            return Err(ConfigError::Policy(format!(
                "refresh_interval must be at least {}s",
                MIN_POLICY_REFRESH.as_secs()
            )));
        }

        let agent = raw
            .agent
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty());
        // `agent` first, then any extra identities, de-duplicated but order-stable.
        let mut agents: Vec<String> = Vec::new();
        for candidate in agent.iter().cloned().chain(raw.agents) {
            let candidate = candidate.trim().to_string();
            if !candidate.is_empty() && !agents.contains(&candidate) {
                agents.push(candidate);
            }
        }

        let signers: Vec<String> = raw
            .signers
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let mut ceiling = Ceiling::new();
        for entry in raw.ceiling {
            let host = entry.host.trim().to_ascii_lowercase();
            if host.is_empty() {
                return Err(ConfigError::Policy("a ceiling entry has no host".into()));
            }
            ceiling.add(&host, entry.allow.into_iter().collect::<BTreeSet<String>>());
        }
        let ceiling = if ceiling.is_empty() {
            None
        } else {
            Some(ceiling)
        };

        if source == PolicySource::Server {
            // Fail at startup, not at the first refresh: a server-mode proxy
            // with no pinned signer would either trust anything the API said or
            // refuse every bundle, and both are worse than not starting.
            if signers.is_empty() {
                return Err(ConfigError::Policy(
                    "source = \"server\" requires at least one pinned signer thumbprint \
                     (signers = [\"…\"]) — it is the trust anchor, and without it the API \
                     could rewrite this deployment's authorization"
                        .into(),
                ));
            }
            if agents.is_empty() {
                return Err(ConfigError::Policy(
                    "source = \"server\" requires agent = \"<identity>\"".into(),
                ));
            }
        } else if !signers.is_empty() || ceiling.is_some() {
            // Silently-ignored security config is how a deployment ends up
            // believing it has a control it does not have.
            return Err(ConfigError::Policy(
                "signers/ceiling only apply with source = \"server\"".into(),
            ));
        }

        Ok(PolicyConfig {
            source,
            agent,
            agents,
            org: raw
                .org
                .map(|o| o.trim().to_string())
                .filter(|o| !o.is_empty()),
            refresh_interval,
            signers,
            ceiling,
        })
    }
}

/// Default introspection cache: short, because it is the revocation window.
const DEFAULT_TASK_CACHE_TTL: Duration = Duration::from_secs(30);
/// Nobody wants a request-path HTTP call per request; nobody wants a revoke to
/// take an hour either. Both ends are refused rather than clamped, so a config
/// that means something surprising fails at startup instead of at 3am.
const MAX_TASK_CACHE_TTL: Duration = Duration::from_secs(300);

/// Default flush cadence: frequent enough that a short run is still measured,
/// infrequent enough that reporting is not itself traffic worth noticing.
const DEFAULT_ACTIVITY_FLUSH: Duration = Duration::from_secs(60);
/// Floor on the interval. Below this the reporting is chattier than the thing it
/// reports on, which is a poor trade for data nobody reads in real time.
const MIN_ACTIVITY_FLUSH: Duration = Duration::from_secs(10);
/// Default cell cap. A policy with more distinct (host, method, decision, rule)
/// combinations than this is beyond what a review can usefully narrow.
const DEFAULT_ACTIVITY_MAX_CELLS: usize = 500;

impl ActivityConfig {
    fn validate(raw: RawActivity) -> Result<ActivityConfig, ConfigError> {
        let flush_interval = duration(
            raw.flush_interval,
            DEFAULT_ACTIVITY_FLUSH,
            "flush_interval",
            ConfigError::Activity,
        )?;
        if flush_interval < MIN_ACTIVITY_FLUSH {
            return Err(ConfigError::Activity(format!(
                "flush_interval {}s is below the {}s minimum — reporting would be chattier than what it reports on",
                flush_interval.as_secs(),
                MIN_ACTIVITY_FLUSH.as_secs()
            )));
        }
        let max_cells = raw.max_cells.unwrap_or(DEFAULT_ACTIVITY_MAX_CELLS);
        if max_cells == 0 || max_cells > 5_000 {
            return Err(ConfigError::Activity(
                "max_cells must be between 1 and 5000".into(),
            ));
        }
        Ok(ActivityConfig {
            flush_interval,
            max_cells,
        })
    }
}

impl TasksConfig {
    fn validate(raw: RawTasks) -> Result<TasksConfig, ConfigError> {
        let cache_ttl = duration(
            raw.cache_ttl,
            DEFAULT_TASK_CACHE_TTL,
            "cache_ttl",
            ConfigError::Tasks,
        )?;
        if cache_ttl > MAX_TASK_CACHE_TTL {
            return Err(ConfigError::Tasks(format!(
                "cache_ttl {}s is longer than the {}s maximum — it bounds how long a revoked run keeps working",
                cache_ttl.as_secs(),
                MAX_TASK_CACHE_TTL.as_secs()
            )));
        }
        Ok(TasksConfig { cache_ttl })
    }
}

/// Validate `[ratchet]` into the ordered state machine `crate::ratchet` runs.
///
/// Three things are refused here rather than at runtime, because each one would
/// otherwise be a silent weakening of a control whose whole value is that it only
/// tightens:
///
/// - a duplicate state name, which would make `to = "..."` ambiguous;
/// - a transition naming a state that does not exist, which would never fire;
/// - a transition *to* the baseline, which is the one move a ratchet must not
///   have — it would be a reset dressed as a transition.
fn validate_ratchet(raw: RawRatchet) -> Result<crate::ratchet::RatchetConfig, ConfigError> {
    use crate::ratchet::{RatchetConfig, RatchetState, Transition, BASELINE};

    if raw.state.is_empty() {
        return Err(ConfigError::Ratchet(
            "no [[ratchet.state]] blocks — a ratchet with no narrowed state does nothing".into(),
        ));
    }
    if raw.transition.is_empty() {
        return Err(ConfigError::Ratchet(
            "no [[ratchet.transition]] blocks — nothing would ever move a run out of baseline"
                .into(),
        ));
    }

    let mut narrowed = Vec::with_capacity(raw.state.len());
    for state in raw.state {
        let name = state.name.trim().to_string();
        if name.is_empty() {
            return Err(ConfigError::Ratchet("a state has an empty name".into()));
        }
        if name.eq_ignore_ascii_case(BASELINE) {
            return Err(ConfigError::Ratchet(format!(
                "{BASELINE:?} is the implicit starting state and cannot be declared"
            )));
        }
        if narrowed.iter().any(|s: &RatchetState| s.name == name) {
            return Err(ConfigError::Ratchet(format!(
                "duplicate state {name:?} — `to` would be ambiguous"
            )));
        }
        narrowed.push(RatchetState {
            name,
            // An empty list is meaningful and different from an absent one:
            // `hosts = []` is "nothing is reachable any more", while no `hosts`
            // key leaves policy's answer alone.
            hosts: state
                .hosts
                .map(|h| h.into_iter().map(|s| s.trim().to_lowercase()).collect()),
            secrets: state
                .secrets
                .map(|s| s.into_iter().map(|n| n.trim().to_string()).collect()),
        });
    }

    let mut transitions = Vec::with_capacity(raw.transition.len());
    for t in raw.transition {
        let host = t.host.trim().to_lowercase();
        if host.is_empty() || host.contains('/') || host.contains(':') {
            return Err(ConfigError::Ratchet(format!(
                "transition host {:?} must be a bare hostname",
                t.host
            )));
        }
        let target = t.to.trim();
        if target.eq_ignore_ascii_case(BASELINE) {
            return Err(ConfigError::Ratchet(format!(
                "a transition cannot move to {BASELINE:?} — the ratchet only turns one way, and capability returns in a new run"
            )));
        }
        let to = RatchetConfig::state_index(&narrowed, target).ok_or_else(|| {
            ConfigError::Ratchet(format!(
                "transition on {host:?} moves to unknown state {target:?} — declared states are {:?}",
                narrowed.iter().map(|s| s.name.as_str()).collect::<Vec<_>>()
            ))
        })?;
        transitions.push(Transition {
            host,
            methods: MethodSet::new(t.methods),
            paths: PathSet::new(t.paths),
            to,
            label: t
                .label
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty()),
        });
    }

    Ok(RatchetConfig::new(narrowed, transitions))
}

impl ControlConfig {
    fn validate(raw: RawControl) -> Result<ControlConfig, ConfigError> {
        let listen: SocketAddr = raw
            .listen
            .as_deref()
            .unwrap_or("127.0.0.1:9090")
            .parse()
            .map_err(|e| ConfigError::Control(format!("listen: {e}")))?;
        let ttl = duration(raw.ttl, DEFAULT_TICKET_TTL, "ttl", ConfigError::Control)?;
        let max_ttl = duration(
            raw.max_ttl,
            DEFAULT_TICKET_MAX_TTL,
            "max_ttl",
            ConfigError::Control,
        )?;
        if max_ttl < ttl {
            return Err(ConfigError::Control("max_ttl must be at least ttl".into()));
        }
        Ok(ControlConfig {
            listen,
            ttl,
            max_ttl,
        })
    }
}

impl SecretsConfig {
    fn validate(raw: Option<RawSecrets>) -> Result<SecretsConfig, ConfigError> {
        let Some(raw) = raw else {
            return Ok(SecretsConfig::default());
        };
        let Some(value) = raw.refresh_interval else {
            return Ok(SecretsConfig::default());
        };
        let interval = seekrit_cache::parse_duration(&value)
            .map_err(|e| ConfigError::Secrets(format!("refresh_interval: {e}")))?;
        if interval < MIN_POLICY_REFRESH {
            return Err(ConfigError::Secrets(format!(
                "refresh_interval must be at least {}s",
                MIN_POLICY_REFRESH.as_secs()
            )));
        }
        Ok(SecretsConfig {
            refresh_interval: Some(interval),
        })
    }
}

/// Validate the `methods`/`paths` pair shared by routes and host rules.
fn operation(
    methods: Vec<String>,
    paths: Vec<String>,
    wrap: fn(String) -> ConfigError,
) -> Result<(MethodSet, PathSet), ConfigError> {
    for m in &methods {
        if m.trim().is_empty() || !m.trim().chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(wrap(format!("{m:?} is not an HTTP method name")));
        }
    }
    for p in &paths {
        let p = p.trim();
        if !p.starts_with('/') {
            return Err(wrap(format!(
                "path pattern {p:?} must start with / (it is matched against a request path)"
            )));
        }
        if p.contains('?') {
            return Err(wrap(format!(
                "path pattern {p:?} must not contain a query string; patterns match the path only"
            )));
        }
    }
    Ok((MethodSet::new(methods), PathSet::new(paths)))
}

impl ForwardConfig {
    fn validate(raw: RawForward, policy: &PolicyConfig) -> Result<ForwardConfig, ConfigError> {
        let listen: SocketAddr = raw
            .listen
            .as_deref()
            .unwrap_or(DEFAULT_LISTEN)
            .parse()
            .map_err(|e| ConfigError::Forward(format!("listen: {e}")))?;

        let unmatched = match raw
            .unmatched_host_policy
            .as_deref()
            .unwrap_or("tunnel")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "tunnel" => UnmatchedPolicy::Tunnel,
            "deny" => UnmatchedPolicy::Deny,
            other => {
                return Err(ConfigError::Forward(format!(
                    "unmatched_host_policy must be \"tunnel\" or \"deny\", got {other:?}"
                )))
            }
        };

        if policy.is_server() && !raw.host.is_empty() {
            return Err(ConfigError::Forward(
                "[[forward.host]] rules cannot be combined with [policy] source = \"server\": \
                 the intercepted hosts come from the published policy. Remove them, or move the \
                 ceiling into [[policy.ceiling]] if you meant to bound what policy may say."
                    .into(),
            ));
        }

        let mut rules = Vec::with_capacity(raw.host.len());
        for h in raw.host {
            let host = h.host.trim().to_ascii_lowercase();
            if host.is_empty() {
                return Err(ConfigError::Forward(
                    "a host rule has an empty match".into(),
                ));
            }
            if host.contains('/') || host.contains(':') {
                return Err(ConfigError::Forward(format!(
                    "host {host:?} must be a bare hostname (no scheme, port, or path)"
                )));
            }
            let (methods, paths) = operation(h.methods, h.paths, ConfigError::Forward)?;
            let mut rule = Rule::new(&host, methods, paths, h.allow.into_iter().collect());
            rule.label = h.label;
            rules.push(rule);
        }

        Ok(ForwardConfig {
            listen,
            unmatched,
            ca_cert_path: raw.ca_cert.unwrap_or_else(|| DEFAULT_CA_CERT.to_string()),
            ca_key_path: raw.ca_key.unwrap_or_else(|| DEFAULT_CA_KEY.to_string()),
            rules: if policy.is_server() {
                None
            } else {
                Some(RuleSet::new(rules))
            },
        })
    }
}

impl Route {
    fn validate(raw: RawRoute, policy: &PolicyConfig) -> Result<Route, ConfigError> {
        // Normalize the prefix: ensure a single leading slash, drop trailing.
        let mut prefix = raw.prefix.trim().to_string();
        if !prefix.is_empty() && !prefix.starts_with('/') {
            prefix = format!("/{prefix}");
        }
        while prefix.len() > 1 && prefix.ends_with('/') {
            prefix.pop();
        }
        if prefix == "/" {
            prefix.clear(); // root == catch-all
        }

        let upstream = raw.upstream.trim().trim_end_matches('/').to_string();
        // Validate the upstream is an absolute http(s) URL up front.
        let host = match reqwest::Url::parse(&upstream) {
            Ok(u) if u.scheme() == "http" || u.scheme() == "https" => {
                u.host_str().unwrap_or_default().to_string()
            }
            Ok(_) => {
                return Err(ConfigError::Route(format!(
                    "upstream {upstream:?} must be http(s)"
                )))
            }
            Err(e) => {
                return Err(ConfigError::Route(format!(
                    "upstream {upstream:?} is not a URL: {e}"
                )))
            }
        };

        let authored = !raw.allow.is_empty() || !raw.methods.is_empty() || !raw.paths.is_empty();
        if policy.is_server() && authored {
            return Err(ConfigError::Route(format!(
                "route {prefix:?} carries allow/methods/paths, which [policy] source = \"server\" \
                 takes from the published policy instead. Keep prefix + upstream here (routing is \
                 local), and author the rules in the dashboard."
            )));
        }

        let rules = if policy.is_server() {
            None
        } else {
            let (methods, paths) = operation(raw.methods, raw.paths, ConfigError::Route)?;
            let mut rule = Rule::new(&host, methods, paths, raw.allow.into_iter().collect());
            rule.label = raw.label;
            Some(RuleSet::new(vec![rule]))
        };

        Ok(Route {
            prefix,
            upstream,
            host,
            rules,
        })
    }

    /// True if `path` falls under this route's prefix.
    pub fn matches(&self, path: &str) -> bool {
        if self.prefix.is_empty() {
            return true; // catch-all
        }
        path == self.prefix || path.starts_with(&format!("{}/", self.prefix))
    }

    /// The path remainder to forward upstream (path with the prefix stripped).
    pub fn strip<'a>(&self, path: &'a str) -> &'a str {
        &path[self.prefix.len()..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seekrit_core::policy::Decision;

    fn cfg(t: &str) -> Config {
        Config::from_toml(t).expect("valid config")
    }

    /// The one-rule set a file-mode route carries.
    fn route_rules<'a>(c: &'a Config, path: &str) -> &'a RuleSet {
        c.match_route(path)
            .expect("a route matches")
            .rules
            .as_ref()
            .expect("file mode carries rules")
    }

    #[test]
    fn defaults_apply() {
        let c = cfg("[[route]]\nprefix='/x'\nupstream='https://x.test'\n");
        assert_eq!(c.listen.to_string(), "127.0.0.1:8080");
        assert_eq!(c.max_body, 2 * 1024 * 1024);
        // Off by default: upstreams here are usually third-party APIs, and
        // adding a correlatable header to their requests should be a choice.
        assert!(!c.propagate_trace_upstream);
        // File policy, no ceiling, no refresh: exactly today's behaviour.
        assert_eq!(c.policy.source, PolicySource::File);
        assert!(c.policy.signers.is_empty());
        assert!(c.secrets.refresh_interval.is_none());
        assert!(c.control.is_none());
    }

    #[test]
    fn trace_propagation_is_opt_in() {
        let c = cfg("propagate_trace_upstream = true\n\
             [[route]]\nprefix='/x'\nupstream='https://x.test'\n");
        assert!(c.propagate_trace_upstream);
    }

    #[test]
    fn longest_prefix_wins() {
        let c = cfg("
            [[route]]
            prefix='/a'
            upstream='https://a.test'
            [[route]]
            prefix='/a/b'
            upstream='https://ab.test'
        ");
        assert_eq!(c.match_route("/a/b/c").unwrap().upstream, "https://ab.test");
        assert_eq!(c.match_route("/a/z").unwrap().upstream, "https://a.test");
    }

    #[test]
    fn prefix_normalization_and_strip() {
        let c = cfg("[[route]]\nprefix='openai/'\nupstream='https://api.openai.com/'\n");
        let r = c.match_route("/openai/v1/models").unwrap();
        assert_eq!(r.prefix, "/openai");
        assert_eq!(r.upstream, "https://api.openai.com"); // trailing slash trimmed
        assert_eq!(r.strip("/openai/v1/models"), "/v1/models");
    }

    #[test]
    fn root_is_catch_all() {
        let c = cfg("[[route]]\nprefix='/'\nupstream='https://any.test'\n");
        let r = c.match_route("/whatever/here").unwrap();
        assert!(r.prefix.is_empty());
        assert_eq!(r.strip("/whatever/here"), "/whatever/here");
    }

    #[test]
    fn rejects_non_http_upstream() {
        assert!(Config::from_toml("[[route]]\nprefix='/x'\nupstream='ftp://x.test'\n").is_err());
        assert!(Config::from_toml("[[route]]\nprefix='/x'\nupstream='not a url'\n").is_err());
    }

    #[test]
    fn requires_at_least_one_mode() {
        assert!(Config::from_toml("listen='127.0.0.1:9000'\n").is_err());
    }

    #[test]
    fn route_without_operation_constraints_permits_any() {
        let c = cfg("[[route]]\nprefix='/x'\nupstream='https://x.test'\nallow=['KEY']\n");
        let rules = route_rules(&c, "/x/anything");
        assert_eq!(
            rules
                .decide("x.test", "DELETE", "/anything", Some("KEY"))
                .decision,
            Decision::Allow
        );
    }

    #[test]
    fn route_operation_constraints_are_enforced_against_the_stripped_path() {
        let c = cfg("
            [[route]]
            prefix = '/openai'
            upstream = 'https://api.openai.com'
            allow = ['OPENAI_API_KEY']
            methods = ['post']
            paths = ['/v1/chat/completions', '/v1/embeddings']
        ");
        let route = c.match_route("/openai/v1/chat/completions").unwrap();
        let rules = route.rules.as_ref().unwrap();
        let stripped = route.strip("/openai/v1/chat/completions");
        assert_eq!(stripped, "/v1/chat/completions");
        assert_eq!(
            rules
                .decide(&route.host, "POST", stripped, Some("OPENAI_API_KEY"))
                .decision,
            Decision::Allow
        );
        // Right path, wrong method.
        assert_eq!(
            rules.decide(&route.host, "GET", stripped, None).decision,
            Decision::MethodNotAllowed
        );
        // Right method, path outside the pattern.
        assert_eq!(
            rules
                .decide(&route.host, "POST", "/v1/files", None)
                .decision,
            Decision::PathNotAllowed
        );
    }

    #[test]
    fn two_routes_to_one_upstream_keep_separate_allowlists() {
        // Collapsing these by host would let the permissive route answer for the
        // read-only one — the regression a per-route rule set exists to prevent.
        let c = cfg("
            [[route]]
            prefix = '/openai'
            upstream = 'https://api.openai.com'
            allow = ['OPENAI_API_KEY']
            [[route]]
            prefix = '/openai-ro'
            upstream = 'https://api.openai.com'
        ");
        assert_eq!(
            route_rules(&c, "/openai/v1/models")
                .decide(
                    "api.openai.com",
                    "GET",
                    "/v1/models",
                    Some("OPENAI_API_KEY")
                )
                .decision,
            Decision::Allow
        );
        assert_eq!(
            route_rules(&c, "/openai-ro/v1/models")
                .decide(
                    "api.openai.com",
                    "GET",
                    "/v1/models",
                    Some("OPENAI_API_KEY")
                )
                .decision,
            Decision::SecretNotAllowed
        );
    }

    #[test]
    fn rejects_malformed_operation_constraints() {
        let bad = |extra: &str| {
            Config::from_toml(&format!(
                "[[route]]\nprefix='/x'\nupstream='https://x.test'\n{extra}"
            ))
            .is_err()
        };
        assert!(bad("methods = ['PO ST']\n"));
        assert!(bad("paths = ['v1/models']\n")); // no leading slash
        assert!(bad("paths = ['/v1/models?limit=1']\n")); // query string
    }

    #[test]
    fn parses_forward_with_host_rules() {
        let c = cfg("
            [forward]
            listen = '127.0.0.1:8888'
            [[forward.host]]
            match = 'API.Anthropic.com'
            allow = ['ANTHROPIC_API_KEY']
        ");
        let f = c.forward.as_ref().unwrap();
        assert_eq!(f.listen.to_string(), "127.0.0.1:8888");
        assert_eq!(f.unmatched, UnmatchedPolicy::Tunnel); // default
        assert_eq!(f.ca_cert_path, "seekrit-proxy-ca.pem"); // default
        let rules = f.rules.as_ref().unwrap();
        // Host match is case-insensitive.
        assert!(rules.covers_host("api.anthropic.com"));
        assert!(!rules.covers_host("evil.test"));
        assert_eq!(
            rules
                .decide(
                    "api.anthropic.com",
                    "POST",
                    "/v1/messages",
                    Some("ANTHROPIC_API_KEY")
                )
                .decision,
            Decision::Allow
        );
    }

    #[test]
    fn forward_hosts_may_carry_several_rules_in_order() {
        let c = cfg("
            [forward]
            [[forward.host]]
            match = 'api.github.com'
            methods = ['GET', 'POST']
            paths = ['/repos/*/issues', '/repos/*/issues/**']
            allow = ['GITHUB_TOKEN']
            [[forward.host]]
            match = 'api.github.com'
            methods = ['GET']
        ");
        let rules = c.forward.as_ref().unwrap().rules.as_ref().unwrap();
        assert_eq!(
            rules
                .decide(
                    "api.github.com",
                    "POST",
                    "/repos/seekrit/issues",
                    Some("GITHUB_TOKEN")
                )
                .decision,
            Decision::Allow
        );
        // The second rule covers other reads, but carries no credential.
        assert_eq!(
            rules
                .decide("api.github.com", "GET", "/user", Some("GITHUB_TOKEN"))
                .decision,
            Decision::SecretNotAllowed
        );
        // And writes outside the issue paths are refused outright.
        assert_eq!(
            rules
                .decide("api.github.com", "DELETE", "/repos/seekrit", None)
                .decision,
            Decision::MethodNotAllowed
        );
    }

    #[test]
    fn forward_deny_policy_and_bad_host() {
        let c = cfg("
            [forward]
            unmatched_host_policy = 'deny'
            [[forward.host]]
            match = 'api.test'
        ");
        assert_eq!(c.forward.unwrap().unmatched, UnmatchedPolicy::Deny);
        // A host with a scheme/port/path is rejected.
        assert!(
            Config::from_toml("[forward]\n[[forward.host]]\nmatch = 'https://api.test:443'\n")
                .is_err()
        );
    }

    #[test]
    fn cache_is_off_unless_enabled() {
        // No [cache] block at all.
        let c = cfg("[[route]]\nprefix='/x'\nupstream='https://x.test'\n");
        assert!(c.cache.is_none());
        // Present but explicitly disabled reads the same as absent.
        let c = cfg("[[route]]\nprefix='/x'\nupstream='https://x.test'\n[cache]\nenabled=false\n");
        assert!(c.cache.is_none());
        // A block with no `enabled` key is not an accidental opt-in.
        let c = cfg("[[route]]\nprefix='/x'\nupstream='https://x.test'\n[cache]\nmax_age='1h'\n");
        assert!(c.cache.is_none());
    }

    #[test]
    fn cache_defaults_and_overrides() {
        let c = cfg("[[route]]\nprefix='/x'\nupstream='https://x.test'\n[cache]\nenabled=true\n");
        let cache = c.cache.expect("enabled");
        assert!(cache.dir.is_none());
        assert_eq!(cache.max_age, seekrit_cache::DEFAULT_MAX_AGE);
        assert_eq!(cache.reconnect_interval, DEFAULT_RECONNECT);
        assert_eq!(cache.reconnect_max_interval, DEFAULT_RECONNECT_MAX);

        let c = cfg("
            [[route]]
            prefix='/x'
            upstream='https://x.test'
            [cache]
            enabled = true
            dir = '/var/cache/seekrit'
            max_age = '7d'
            reconnect_interval = '10s'
            reconnect_max_interval = '2m'
        ");
        let cache = c.cache.expect("enabled");
        assert_eq!(cache.dir.as_deref(), Some("/var/cache/seekrit"));
        assert_eq!(cache.max_age, Duration::from_secs(604_800));
        assert_eq!(cache.reconnect_interval, Duration::from_secs(10));
        assert_eq!(cache.reconnect_max_interval, Duration::from_secs(120));
    }

    #[test]
    fn rejects_bad_cache_durations() {
        let bad = |block: &str| {
            Config::from_toml(&format!(
                "[[route]]\nprefix='/x'\nupstream='https://x.test'\n[cache]\nenabled=true\n{block}"
            ))
            .is_err()
        };
        assert!(bad("max_age = 'a while'\n"));
        assert!(bad("max_age = '0h'\n"));
        // A ceiling below the starting delay would make the backoff nonsense.
        assert!(bad(
            "reconnect_interval = '5m'\nreconnect_max_interval = '10s'\n"
        ));
    }

    #[test]
    fn reverse_and_forward_cannot_share_a_port() {
        assert!(Config::from_toml(
            "listen='127.0.0.1:8080'\n[[route]]\nprefix='/x'\nupstream='https://x.test'\n[forward]\nlisten='127.0.0.1:8080'\n"
        )
        .is_err());
    }

    #[test]
    fn server_policy_needs_a_pinned_signer_and_an_agent() {
        let base = "[forward]\nlisten='127.0.0.1:8081'\n";
        // No signers: refuse, because the trust anchor is the whole argument.
        assert!(
            Config::from_toml(&format!("{base}[policy]\nsource='server'\nagent='nova'\n")).is_err()
        );
        // No agent: refuse, there is nothing to fetch.
        assert!(Config::from_toml(&format!(
            "{base}[policy]\nsource='server'\nsigners=['kNc8']\n"
        ))
        .is_err());
        let c = cfg(&format!(
            "{base}[policy]\nsource='server'\nagent='nova'\nsigners=['kNc8']\n"
        ));
        assert!(c.policy.is_server());
        assert_eq!(c.policy.agents, vec!["nova".to_string()]);
        assert_eq!(c.policy.refresh_interval, DEFAULT_POLICY_REFRESH);
        // Server policy implies secret refresh, or a new rule lands before the
        // credential it names.
        assert_eq!(c.secrets.refresh_interval, Some(DEFAULT_POLICY_REFRESH));
        // And the forward plane takes its hosts from the bundle.
        assert!(c.forward.as_ref().unwrap().rules.is_none());
    }

    #[test]
    fn server_policy_refuses_locally_authored_rules() {
        // Silently ignoring these is how an operator ends up believing a rule is
        // in force when the published policy says otherwise.
        assert!(Config::from_toml(
            "[[route]]\nprefix='/x'\nupstream='https://x.test'\nallow=['KEY']\n\
             [policy]\nsource='server'\nagent='nova'\nsigners=['k']\n"
        )
        .is_err());
        assert!(Config::from_toml(
            "[forward]\n[[forward.host]]\nmatch='api.test'\n\
             [policy]\nsource='server'\nagent='nova'\nsigners=['k']\n"
        )
        .is_err());
        // Routing itself stays local — prefix + upstream alone is fine.
        let c = cfg("[[route]]\nprefix='/x'\nupstream='https://x.test'\n\
             [policy]\nsource='server'\nagent='nova'\nsigners=['k']\n");
        assert!(c.routes[0].rules.is_none());
    }

    #[test]
    fn signers_and_ceilings_are_rejected_in_file_mode() {
        assert!(Config::from_toml(
            "[[route]]\nprefix='/x'\nupstream='https://x.test'\n[policy]\nsigners=['k']\n"
        )
        .is_err());
        assert!(Config::from_toml(
            "[[route]]\nprefix='/x'\nupstream='https://x.test'\n\
             [[policy.ceiling]]\nhost='api.test'\nallow=['KEY']\n"
        )
        .is_err());
    }

    #[test]
    fn parses_the_ceiling_and_extra_agents() {
        let c = cfg("
            [forward]
            [policy]
            source = 'server'
            agent = 'nova'
            agents = ['scribe', 'nova']
            org = 'org_2f'
            refresh_interval = '5s'
            signers = ['kNc8', 'R7yq']
            [[policy.ceiling]]
            host = 'api.openai.com'
            allow = ['OPENAI_API_KEY']
        ");
        assert_eq!(c.policy.refresh_interval, Duration::from_secs(5));
        assert_eq!(c.policy.signers.len(), 2);
        assert_eq!(c.policy.org.as_deref(), Some("org_2f"));
        // `agent` leads, duplicates collapse.
        assert_eq!(
            c.policy.agents,
            vec!["nova".to_string(), "scribe".to_string()]
        );
        let ceiling = c.policy.ceiling.expect("ceiling");
        assert!(ceiling.hosts.contains_key("api.openai.com"));
    }

    #[test]
    fn rejects_a_hot_loop_refresh_interval() {
        assert!(Config::from_toml(
            "[forward]\n[policy]\nsource='server'\nagent='n'\nsigners=['k']\nrefresh_interval='10ms'\n"
        )
        .is_err());
        assert!(Config::from_toml(
            "[[route]]\nprefix='/x'\nupstream='https://x.test'\n[secrets]\nrefresh_interval='100ms'\n"
        )
        .is_err());
    }

    #[test]
    fn secret_refresh_is_opt_in_under_file_policy() {
        let c = cfg("[[route]]\nprefix='/x'\nupstream='https://x.test'\n[secrets]\nrefresh_interval='30s'\n");
        assert_eq!(c.secrets.refresh_interval, Some(Duration::from_secs(30)));
    }

    #[test]
    fn control_listener_defaults_and_port_collisions() {
        let c = cfg("[[route]]\nprefix='/x'\nupstream='https://x.test'\n[control]\n");
        let control = c.control.expect("control");
        assert_eq!(control.listen.to_string(), "127.0.0.1:9090");
        assert_eq!(control.ttl, DEFAULT_TICKET_TTL);
        assert_eq!(control.max_ttl, DEFAULT_TICKET_MAX_TTL);

        assert!(Config::from_toml(
            "listen='127.0.0.1:8080'\n[[route]]\nprefix='/x'\nupstream='https://x.test'\n\
             [control]\nlisten='127.0.0.1:8080'\n"
        )
        .is_err());
        assert!(Config::from_toml(
            "[forward]\nlisten='127.0.0.1:8081'\n[control]\nlisten='127.0.0.1:8081'\n"
        )
        .is_err());
        assert!(Config::from_toml(
            "[[route]]\nprefix='/x'\nupstream='https://x.test'\n[control]\nttl='2h'\nmax_ttl='1h'\n"
        )
        .is_err());
    }

    /// A minimal config the ratchet blocks can be appended to.
    fn with_ratchet(extra: &str) -> Result<Config, ConfigError> {
        Config::from_toml(&format!(
            "listen = \"127.0.0.1:8080\"\n[[route]]\nprefix = \"/up\"\nupstream = \"https://api.example.com\"\nallow = [\"K\"]\n{extra}"
        ))
    }

    #[test]
    fn ratchet_parses_states_in_order_with_an_implicit_baseline() {
        let config = with_ratchet(
            "[[ratchet.state]]\nname = \"restricted\"\nhosts = [\"ledger.internal\"]\n             [[ratchet.state]]\nname = \"locked\"\nhosts = []\n             [[ratchet.transition]]\nhost = \"reports.internal\"\nto = \"restricted\"\n",
        )
        .unwrap();
        let ratchet = config.ratchet.unwrap();
        // Baseline is prepended, never declared — so a run always starts wide.
        assert_eq!(
            ratchet.state_names(),
            vec!["baseline", "restricted", "locked"]
        );
        assert_eq!(ratchet.transitions[0].to, 1);
    }

    #[test]
    fn a_transition_to_baseline_is_a_startup_error() {
        // The one move a ratchet must not be able to express. Refused at parse
        // time rather than ignored at runtime, so nobody ships a config that
        // silently does less than it reads like.
        let err = with_ratchet(
            "[[ratchet.state]]\nname = \"restricted\"\nhosts = []\n             [[ratchet.transition]]\nhost = \"a.example.com\"\nto = \"baseline\"\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("only turns one way"), "{err}");
    }

    #[test]
    fn declaring_baseline_as_a_state_is_refused() {
        let err = with_ratchet(
            "[[ratchet.state]]\nname = \"baseline\"\nhosts = []\n             [[ratchet.transition]]\nhost = \"a.example.com\"\nto = \"baseline\"\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("implicit starting state"), "{err}");
    }

    #[test]
    fn a_transition_to_an_unknown_state_names_what_exists() {
        let err = with_ratchet(
            "[[ratchet.state]]\nname = \"restricted\"\nhosts = []\n             [[ratchet.transition]]\nhost = \"a.example.com\"\nto = \"typo\"\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown state"), "{err}");
        assert!(err.to_string().contains("restricted"), "{err}");
    }

    #[test]
    fn duplicate_state_names_are_refused() {
        let err = with_ratchet(
            "[[ratchet.state]]\nname = \"x\"\nhosts = []\n             [[ratchet.state]]\nname = \"x\"\nhosts = []\n             [[ratchet.transition]]\nhost = \"a.example.com\"\nto = \"x\"\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("ambiguous"), "{err}");
    }

    #[test]
    fn a_ratchet_with_no_transition_is_refused_as_inert() {
        let err = with_ratchet("[[ratchet.state]]\nname = \"x\"\nhosts = []\n").unwrap_err();
        assert!(err.to_string().contains("nothing would ever move"), "{err}");
    }

    #[test]
    fn an_absent_host_list_differs_from_an_empty_one() {
        // `hosts = []` means "nothing reachable"; no `hosts` key means "leave
        // policy's answer alone". Collapsing the two would make the strictest
        // state a no-op.
        let config = with_ratchet(
            "[[ratchet.state]]\nname = \"quiet\"\nsecrets = []\n             [[ratchet.transition]]\nhost = \"a.example.com\"\nto = \"quiet\"\n",
        )
        .unwrap();
        let state = &config.ratchet.unwrap().states[1];
        assert!(
            state.hosts.is_none(),
            "no hosts key leaves hosts unrestricted"
        );
        assert_eq!(state.secrets.as_ref().map(|s| s.len()), Some(0));
    }

    #[test]
    fn a_transition_host_must_be_a_bare_hostname() {
        for host in [
            "https://a.example.com",
            "a.example.com:443",
            "a.example.com/x",
        ] {
            let err = with_ratchet(&format!(
                "[[ratchet.state]]\nname = \"x\"\nhosts = []\n                 [[ratchet.transition]]\nhost = \"{host}\"\nto = \"x\"\n"
            ))
            .unwrap_err();
            assert!(err.to_string().contains("bare hostname"), "{host}: {err}");
        }
    }

    #[test]
    fn tasks_cache_ttl_is_bounded_because_it_is_the_revocation_window() {
        let ok = Config::from_toml(
            "listen = \"127.0.0.1:8080\"\n[[route]]\nprefix = \"/u\"\nupstream = \"https://a.example.com\"\n[tasks]\ncache_ttl = \"10s\"\n",
        )
        .unwrap();
        assert_eq!(ok.tasks.unwrap().cache_ttl, Duration::from_secs(10));

        let err = Config::from_toml(
            "listen = \"127.0.0.1:8080\"\n[[route]]\nprefix = \"/u\"\nupstream = \"https://a.example.com\"\n[tasks]\ncache_ttl = \"1h\"\n",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("revoked run keeps working"),
            "{err}"
        );
    }

    #[test]
    fn no_tasks_block_means_dispatched_tasks_are_not_honoured() {
        let config = Config::from_toml(
            "listen = \"127.0.0.1:8080\"\n[[route]]\nprefix = \"/u\"\nupstream = \"https://a.example.com\"\n",
        )
        .unwrap();
        assert!(config.tasks.is_none());
        assert!(config.ratchet.is_none());
    }
}
