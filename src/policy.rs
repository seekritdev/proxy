//! Where the proxy's authorization comes from, and how it stays current.
//!
//! In **file mode** the rules live in the config and never change; the data
//! planes read them straight off `Route`/`ForwardConfig` and this module's store
//! is not used at all.
//!
//! In **server mode** the proxy fetches a signed bundle per agent identity from
//! the seekrit API, verifies it against the signer thumbprints pinned in its
//! local file, checks it against an optional local ceiling, and publishes it
//! into a [`PolicyStore`]. Refresh replaces a whole snapshot behind an `ArcSwap`
//! so readers never block and never see half a policy.
//!
//! Three properties this module exists to hold:
//!
//! - **The server cannot widen policy.** Every bundle is verified against
//!   locally pinned signers before it is published, and a bundle that exceeds
//!   the local ceiling is refused *wholesale* rather than intersected — running
//!   a narrowed version of something nobody authored would make the dashboard
//!   lie about what this proxy is doing.
//! - **Fail closed, always in the same direction.** A fetch that fails keeps the
//!   current snapshot until it expires, then stops permitting anything. A
//!   signature that does not verify is never a reason to fall back to an
//!   unsigned or older-but-broader policy.
//! - **Scope narrowing happens once.** `ticket.scopes ∩ rule.allow` is computed
//!   in [`permits_secret`] and nowhere else, so the reverse and forward planes
//!   cannot drift apart on what a session ticket means.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use seekrit_cache::{Cache, CacheKey, Lookup as CacheLookup};
use seekrit_core::policy::{verify_bundle, Bundle, Rule, RuleSet};
use tracing::{info, warn};

use crate::config::{Config, PolicyConfig};

/// The policy in force for one agent identity, plus what it came from.
#[derive(Debug)]
pub struct PolicySnapshot {
    pub rules: RuleSet,
    /// Agent identity id from the bundle (not the configured alias).
    pub agent_id: String,
    pub agent_slug: Option<String>,
    pub version: u32,
    /// Unix seconds. After this the snapshot permits nothing (fail closed).
    pub expires_at: i64,
    /// Thumbprint of the key that signed it, for logs and `/healthz`-style
    /// introspection. Operator-facing, never a secret.
    pub signer: String,
}

impl PolicySnapshot {
    fn from_bundle(bundle: &Bundle) -> PolicySnapshot {
        PolicySnapshot {
            rules: bundle.rule_set(),
            agent_id: bundle.agent.clone(),
            agent_slug: bundle.agent_slug.clone(),
            version: bundle.policy_version,
            expires_at: bundle.expires_at,
            signer: bundle.signer.kid.clone(),
        }
    }

    /// True once the bundle's own expiry has passed. An expired snapshot is kept
    /// (so the refusal can say *why*) but permits nothing.
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }

    /// The rules to evaluate, or `None` when this snapshot has expired.
    pub fn active_rules(&self, now: i64) -> Option<&RuleSet> {
        if self.is_expired(now) {
            None
        } else {
            Some(&self.rules)
        }
    }
}

/// Per-agent snapshots, each swappable independently.
///
/// The set of agents is fixed at startup from `[policy] agent`/`agents`: the
/// local file decides which identities this proxy will ever fetch, so a
/// compromised API cannot point a deployment at policy its operator never named.
pub struct PolicyStore {
    slots: HashMap<String, Arc<ArcSwap<PolicySnapshot>>>,
    /// The identity used for requests that carry no session ticket.
    default_agent: String,
}

impl PolicyStore {
    /// Build a store over the configured identities, seeded with `initial`
    /// (keyed by the identity as configured).
    pub fn new(default_agent: String, initial: Vec<(String, PolicySnapshot)>) -> PolicyStore {
        PolicyStore {
            slots: initial
                .into_iter()
                .map(|(agent, snapshot)| (agent, Arc::new(ArcSwap::from_pointee(snapshot))))
                .collect(),
            default_agent,
        }
    }

    pub fn default_agent(&self) -> &str {
        &self.default_agent
    }

    /// The snapshot for `agent` (or the default identity when `None`).
    ///
    /// A ticket naming an identity this proxy was not configured for resolves to
    /// `None`, and the request is refused — the alternative would be a proxy
    /// that fetches whatever an agent asks it to.
    pub fn snapshot(&self, agent: Option<&str>) -> Option<Arc<PolicySnapshot>> {
        let key = agent.unwrap_or(&self.default_agent);
        self.slots.get(key).map(|slot| slot.load_full())
    }

    pub fn agents(&self) -> impl Iterator<Item = &String> {
        self.slots.keys()
    }

    /// True if *any* configured agent's policy covers this host.
    ///
    /// The forward plane needs this at `CONNECT` time, before a request (and so
    /// before its session ticket) exists: interception has to be decided from the
    /// union, because a host nobody intercepts is a host nothing can enforce on.
    /// The per-request check then applies the specific agent's rules and can
    /// still refuse.
    pub fn covers_host_any(&self, host: &str) -> bool {
        self.slots
            .values()
            .any(|slot| slot.load().rules.covers_host(host))
    }

    fn publish(&self, agent: &str, snapshot: PolicySnapshot) {
        if let Some(slot) = self.slots.get(agent) {
            slot.store(Arc::new(snapshot));
        }
    }
}

/// The effective injection permission for one request: the matched rule's
/// allowlist, narrowed by any session-ticket scopes.
///
/// `ticket.scopes ∩ rule.allow` is computed here and nowhere else, so the reverse
/// and forward planes cannot drift on what a ticket means. A ticket can only ever
/// *narrow*: an orchestrator that asks for a scope the published policy does not
/// grant gets the policy's answer, not its own.
///
/// Owned rather than borrowed (a handful of short names) so it can outlive the
/// policy snapshot guard it was derived from — the forward plane builds it in one
/// function and injects in another.
#[derive(Debug, Clone)]
pub struct Gate {
    allow: BTreeSet<String>,
    scopes: Option<BTreeSet<String>>,
}

impl Gate {
    pub fn new(rule: &Rule, scopes: Option<&BTreeSet<String>>) -> Gate {
        Gate {
            allow: rule.allow.clone(),
            scopes: scopes.cloned(),
        }
    }

    /// Whether `name` may be injected into this request.
    pub fn permits(&self, name: &str) -> bool {
        if let Some(scopes) = &self.scopes {
            if !scopes.contains(name) {
                return false;
            }
        }
        self.allow.contains(name)
    }

    /// The names this request could inject, for a startup/debug log. Never values.
    pub fn names(&self) -> Vec<&str> {
        self.allow
            .iter()
            .filter(|n| self.permits(n))
            .map(String::as_str)
            .collect()
    }
}

/// Unix seconds now. Policy expiry is expressed in wall-clock seconds because it
/// is published by a server and read by many proxies.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A failure to obtain usable policy from the API.
#[derive(Debug)]
pub enum PolicyError {
    /// The API could not be reached, or answered with a server error. A cached
    /// last-known-good bundle may stand in for this (it is still signed).
    Unavailable(String),
    /// The API answered, and the answer is not usable: no policy published, the
    /// token is not authorized for this agent, the signature does not verify, the
    /// signer is not pinned, the bundle is for another org/agent, or it exceeds
    /// the local ceiling. Never falls back — a refusal is information.
    Refused(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::Unavailable(m) => write!(f, "could not fetch agent policy: {m}"),
            PolicyError::Refused(m) => write!(f, "agent policy refused: {m}"),
        }
    }
}

impl std::error::Error for PolicyError {}

impl PolicyError {
    /// Whether a cached bundle may stand in for this failure.
    pub fn may_fall_back(&self) -> bool {
        matches!(self, PolicyError::Unavailable(_))
    }
}

/// One fetched bundle body plus the `ETag` to send back next time.
pub struct Fetched {
    pub envelope: String,
    pub etag: Option<String>,
}

/// `GET /v1/agents/:agent/policy` — the envelope, or `None` on a 304.
///
/// Conditional on purpose: the interactive flow wants a short refresh interval
/// (a developer adds a rule and expects the running proxy to notice), and a
/// steady state that costs one 304 makes that affordable.
pub async fn fetch(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    agent: &str,
    etag: Option<&str>,
) -> Result<Option<Fetched>, PolicyError> {
    let url = format!(
        "{}/v1/agents/{}/policy",
        api_url.trim_end_matches('/'),
        urlencode(agent)
    );
    let mut req = client.get(&url).bearer_auth(token);
    if let Some(etag) = etag {
        req = req.header(reqwest::header::IF_NONE_MATCH, etag);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| PolicyError::Unavailable(e.to_string()))?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    let etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let detail = summarize(&body);
        // 5xx is "try again"; anything else is the API telling us no.
        return Err(if status.is_server_error() {
            PolicyError::Unavailable(format!("HTTP {status}{detail}"))
        } else {
            PolicyError::Refused(format!("HTTP {status}{detail}"))
        });
    }
    let body = resp
        .text()
        .await
        .map_err(|e| PolicyError::Unavailable(e.to_string()))?;
    let envelope = extract_envelope(&body)?;
    Ok(Some(Fetched { envelope, etag }))
}

/// Pull the `bundle` field out of the policy response.
fn extract_envelope(body: &str) -> Result<String, PolicyError> {
    let parsed: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| PolicyError::Refused(format!("policy response is not JSON: {e}")))?;
    match parsed.get("bundle").and_then(|b| b.as_str()) {
        Some(envelope) if !envelope.is_empty() => Ok(envelope.to_string()),
        _ => Err(PolicyError::Refused(
            "policy response carries no bundle — has a policy been published for this agent?"
                .into(),
        )),
    }
}

/// Verify an envelope end to end and turn it into a snapshot.
///
/// Every check that decides whether this deployment may act on a bundle happens
/// here: pinned signature, org/agent binding, expiry, and the ceiling.
pub fn accept(
    envelope: &str,
    policy: &PolicyConfig,
    agent: &str,
    now: i64,
) -> Result<PolicySnapshot, PolicyError> {
    let bundle = verify_bundle(envelope, &policy.signers)
        .map_err(|e| PolicyError::Refused(e.to_string()))?;
    bundle
        .check_context(policy.org.as_deref(), Some(agent), now)
        .map_err(|e| PolicyError::Refused(e.to_string()))?;
    let snapshot = PolicySnapshot::from_bundle(&bundle);
    if let Some(ceiling) = &policy.ceiling {
        snapshot
            .rules
            .check_ceiling(ceiling)
            .map_err(PolicyError::Refused)?;
    }
    Ok(snapshot)
}

/// The last-known-good cache for policy, when `[cache]` is enabled.
pub struct PolicyCache {
    cache: Cache,
    api_url: String,
    token: String,
}

impl PolicyCache {
    pub fn new(cache: Cache, api_url: String, token: String) -> PolicyCache {
        PolicyCache {
            cache,
            api_url,
            token,
        }
    }

    fn key(&self, agent: &str) -> CacheKey {
        CacheKey::for_agent_policy(&self.api_url, &self.token, agent)
    }

    pub fn write(&self, agent: &str, envelope: &str) {
        if let Err(e) = self.cache.write(&self.key(agent), envelope) {
            warn!(agent, "could not cache the policy bundle: {e}");
        }
    }

    /// The cached envelope for `agent`, if one is present and fresh enough.
    /// Still verified by the caller — a cached bundle is trusted no more than a
    /// fetched one.
    pub fn read(&self, agent: &str) -> Option<String> {
        match self.cache.read(&self.key(agent)) {
            CacheLookup::Hit(entry) => {
                warn!(
                    agent,
                    "starting on the policy cached {} ago; will keep retrying for live policy",
                    seekrit_cache::humanize(entry.age)
                );
                Some(entry.body)
            }
            CacheLookup::Missing => None,
            CacheLookup::Expired { age } => {
                warn!(
                    agent,
                    "cached policy is {} old, past the configured max_age",
                    seekrit_cache::humanize(age)
                );
                None
            }
            CacheLookup::Unusable(why) => {
                warn!(agent, "ignoring the cached policy: {why}");
                None
            }
        }
    }

    pub fn invalidate(&self, agent: &str) {
        self.cache.invalidate(&self.key(agent));
    }
}

/// Load every configured agent's policy once, for startup.
///
/// Fail-closed: any agent whose policy cannot be obtained aborts startup, unless
/// `[cache]` is on and the failure was an unreachable API — the same terms the
/// cache already offers for secrets. A proxy that started with no policy would
/// permit nothing anyway; refusing to start says so where an operator will see
/// it.
pub async fn load_all(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    config: &Config,
    cache: Option<&PolicyCache>,
) -> Result<(PolicyStore, HashMap<String, Option<String>>), PolicyError> {
    let policy = &config.policy;
    let now = now_secs();
    let mut snapshots = Vec::new();
    let mut etags: HashMap<String, Option<String>> = HashMap::new();

    for agent in &policy.agents {
        match fetch(client, api_url, token, agent, None).await {
            Ok(Some(fetched)) => {
                let snapshot = accept(&fetched.envelope, policy, agent, now)?;
                info!(
                    agent,
                    version = snapshot.version,
                    rules = snapshot.rules.rules.len(),
                    signer = %snapshot.signer,
                    "loaded signed agent policy"
                );
                if let Some(cache) = cache {
                    cache.write(agent, &fetched.envelope);
                }
                etags.insert(agent.clone(), fetched.etag);
                snapshots.push((agent.clone(), snapshot));
            }
            // A 304 with no prior ETag cannot happen; treat it as no policy.
            Ok(None) => {
                return Err(PolicyError::Refused(format!(
                    "the API returned 304 for agent {agent} without a prior ETag"
                )))
            }
            Err(e) => {
                let cached = if e.may_fall_back() {
                    cache.and_then(|c| c.read(agent))
                } else {
                    // The API is reachable and says no. Drop any cached copy for
                    // the same reason a revoked token's secrets are dropped.
                    if let Some(cache) = cache {
                        cache.invalidate(agent);
                    }
                    None
                };
                match cached {
                    Some(envelope) => {
                        let snapshot = accept(&envelope, policy, agent, now)?;
                        etags.insert(agent.clone(), None);
                        snapshots.push((agent.clone(), snapshot));
                    }
                    None => return Err(e),
                }
            }
        }
    }

    let default_agent = policy
        .agent
        .clone()
        .or_else(|| policy.agents.first().cloned())
        .ok_or_else(|| PolicyError::Refused("no agent identity configured".into()))?;
    Ok((PolicyStore::new(default_agent, snapshots), etags))
}

/// Everything the refresh task needs. A struct rather than eight parameters, so
/// `main.rs` reads as one hand-off instead of a positional argument list.
pub struct Refresher {
    pub store: Arc<PolicyStore>,
    pub client: reqwest::Client,
    pub api_url: String,
    pub token: String,
    pub config: Arc<Config>,
    pub cache: Option<Arc<PolicyCache>>,
    /// Last `ETag` per agent, so a steady state costs one 304 per interval.
    pub etags: HashMap<String, Option<String>>,
}

impl Refresher {
    /// Keep every agent's policy current until shutdown.
    ///
    /// One task for all identities, on a fixed interval — no backoff, because the
    /// cost of a failed poll is one request and the cost of backing off is a
    /// developer waiting on a rule they already published. A failure leaves the
    /// current snapshot in place; expiry (checked per request) is what eventually
    /// closes the door.
    pub async fn run(mut self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let interval = self.config.policy.refresh_interval;
        let agents: Vec<String> = self.store.agents().cloned().collect();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.wait_for(|stop| *stop) => return,
            }
            let now = now_secs();
            for agent in &agents {
                self.refresh_one(agent, now).await;
            }
        }
    }

    async fn refresh_one(&mut self, agent: &str, now: i64) {
        let etag = self.etags.get(agent).cloned().flatten();
        match fetch(
            &self.client,
            &self.api_url,
            &self.token,
            agent,
            etag.as_deref(),
        )
        .await
        {
            // Unchanged: the common case, and what makes a short interval
            // affordable.
            Ok(None) => {}
            Ok(Some(fetched)) => {
                match accept(&fetched.envelope, &self.config.policy, agent, now) {
                    Ok(snapshot) => {
                        let previous = self.store.snapshot(Some(agent)).map(|s| s.version);
                        if previous != Some(snapshot.version) {
                            info!(
                                agent,
                                version = snapshot.version,
                                rules = snapshot.rules.rules.len(),
                                "agent policy updated"
                            );
                        }
                        if let Some(cache) = &self.cache {
                            cache.write(agent, &fetched.envelope);
                        }
                        self.etags.insert(agent.to_string(), fetched.etag);
                        self.store.publish(agent, snapshot);
                    }
                    Err(e) => {
                        // Keep serving what we have, loudly: a policy the
                        // dashboard shows as live is not the one in force here.
                        warn!(agent, "{e} — keeping the policy already in force");
                        self.etags.insert(agent.to_string(), None);
                    }
                }
            }
            Err(e) => {
                warn!(agent, "{e} — keeping the policy already in force");
                self.etags.insert(agent.to_string(), None);
            }
        }
    }
}

/// Percent-encode the few characters an agent id or slug could plausibly carry
/// that would otherwise change the request path. Ids and slugs are already
/// constrained server-side; this is belt-and-braces on a path we build by hand.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// First line of an error body, capped — enough to diagnose, short enough not to
/// dump an HTML error page into a log.
fn summarize(body: &str) -> String {
    let first = body.lines().next().unwrap_or("").trim();
    if first.is_empty() {
        return String::new();
    }
    let mut text: String = first.chars().take(200).collect();
    if first.chars().count() > 200 {
        text.push('…');
    }
    format!(": {text}")
}

/// How long until the soonest expiry across every snapshot — used only for a
/// startup log line, so an operator sees the window they are running in.
pub fn soonest_expiry(store: &PolicyStore, now: i64) -> Option<Duration> {
    store
        .agents()
        .filter_map(|agent| store.snapshot(Some(agent)))
        .map(|s| (s.expires_at - now).max(0) as u64)
        .min()
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seekrit_core::policy::{MethodSet, PathSet};

    fn rule(allow: &[&str]) -> Rule {
        Rule::new(
            "api.test",
            MethodSet::Any,
            PathSet::Any,
            allow.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn a_ticket_can_only_narrow() {
        let rule = rule(&["KEY", "OTHER"]);
        // No ticket: the rule decides.
        let open = Gate::new(&rule, None);
        assert!(open.permits("KEY"));
        assert!(!open.permits("ABSENT"));
        // A ticket narrows to its scopes.
        let scopes: BTreeSet<String> = ["KEY".to_string()].into_iter().collect();
        let narrowed = Gate::new(&rule, Some(&scopes));
        assert!(narrowed.permits("KEY"));
        assert!(!narrowed.permits("OTHER"));
        assert_eq!(narrowed.names(), vec!["KEY"]);
        // A ticket asking for more than the policy grants gets the policy's answer.
        let greedy: BTreeSet<String> = ["ABSENT".to_string()].into_iter().collect();
        assert!(!Gate::new(&rule, Some(&greedy)).permits("ABSENT"));
    }

    fn snapshot(expires_at: i64) -> PolicySnapshot {
        PolicySnapshot {
            rules: RuleSet::new(vec![rule(&["KEY"])]),
            agent_id: "agt_1".into(),
            agent_slug: Some("nova".into()),
            version: 4,
            expires_at,
            signer: "kNc8".into(),
        }
    }

    #[test]
    fn an_expired_snapshot_permits_nothing() {
        let snap = snapshot(1_000);
        assert!(snap.active_rules(999).is_some());
        assert!(snap.is_expired(1_000));
        assert!(snap.active_rules(1_001).is_none());
    }

    #[test]
    fn the_store_serves_the_default_agent_and_refuses_unknown_ones() {
        let store = PolicyStore::new("nova".into(), vec![("nova".into(), snapshot(9_999))]);
        assert_eq!(store.default_agent(), "nova");
        assert!(store.snapshot(None).is_some());
        assert!(store.snapshot(Some("nova")).is_some());
        // A ticket naming an identity this proxy was not configured for.
        assert!(store.snapshot(Some("scribe")).is_none());
        // Interception is decided from the union of every configured agent.
        assert!(store.covers_host_any("api.test"));
        assert!(!store.covers_host_any("elsewhere.test"));
    }

    #[test]
    fn refusals_do_not_fall_back_but_outages_may() {
        assert!(PolicyError::Unavailable("dns".into()).may_fall_back());
        assert!(!PolicyError::Refused("HTTP 403".into()).may_fall_back());
    }

    #[test]
    fn a_policy_response_without_a_bundle_is_refused() {
        assert!(extract_envelope("{}").is_err());
        assert!(extract_envelope("not json").is_err());
        assert_eq!(
            extract_envelope(r#"{"bundle":"ap1.a.b"}"#).unwrap(),
            "ap1.a.b"
        );
    }

    #[test]
    fn error_bodies_are_summarized_not_dumped() {
        assert_eq!(summarize(""), "");
        let long = "x".repeat(500);
        let out = summarize(&long);
        assert!(out.len() < 220 && out.ends_with('…'));
    }

    #[test]
    fn agent_ids_are_encoded_into_the_path() {
        assert_eq!(urlencode("agt_9cAbc-1.2~x"), "agt_9cAbc-1.2~x");
        assert_eq!(urlencode("../policy"), "..%2Fpolicy");
    }
}
