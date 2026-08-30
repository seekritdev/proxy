//! Agent access policy: the rule set that decides **which secret may be
//! injected toward which upstream, for which operation** — and, in server mode,
//! the signed bundle that carries it.
//!
//! Two sources produce the same [`RuleSet`]:
//!
//! - **file mode** — `[[route]]` / `[[forward.host]]` in the proxy's TOML, which
//!   is authoritative and needs no network.
//! - **server mode** — an [`ap1.` envelope](verify_bundle) published from the
//!   dashboard, signed client-side with a publishing admin's P-256 key and
//!   verified here against thumbprints pinned in that same TOML.
//!
//! Evaluation lives in this crate, once, because the proxy has two data planes
//! (reverse and forward) and two policy sources, and a rule that means something
//! different in one of the four combinations is a security bug. The dashboard's
//! dry-run simulator answers the same question in TypeScript
//! (`packages/core/src/agent-policy.ts`); the two are pinned to the same golden
//! vectors (`apps/proxy/testdata/policy-vectors.json`), so what the UI promises
//! is what the proxy does.
//!
//! ## What the server cannot do
//!
//! The bundle is opaque to the API: it stores and serves bytes it cannot forge,
//! because the signature is made in the browser with a key it never holds. This
//! module is the other half of that claim — it refuses a bundle whose signer is
//! not pinned locally, refuses an unsigned or malformed one outright, and never
//! falls back. A compromised API can withhold policy (fail closed) but cannot
//! widen it.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::b64;
use crate::error::{CoreError, CoreResult};
use crate::sign::VerifyingKey;

/// Envelope prefix for a signed policy bundle, versioned like every other
/// seekrit blob: `ap1.<b64url(body)>.<b64url(signature)>`.
pub const POLICY_PREFIX: &str = "ap1";

/// The bundle schema version this build understands.
pub const BUNDLE_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Rules and evaluation
// ---------------------------------------------------------------------------

/// Which HTTP methods a rule covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodSet {
    /// No `methods` was configured: every method matches.
    ///
    /// Absent-means-any keeps every pre-`methods` config behaving exactly as it
    /// did — this constraint is opt-in, and an empty list would be a
    /// deny-everything rule that only ever arises by mistake.
    Any,
    /// Uppercased method names; only these match.
    Only(BTreeSet<String>),
}

impl MethodSet {
    /// Build from configured names. Empty ⇒ [`MethodSet::Any`].
    pub fn new<I: IntoIterator<Item = String>>(methods: I) -> MethodSet {
        let set: BTreeSet<String> = methods
            .into_iter()
            .map(|m| m.trim().to_ascii_uppercase())
            .filter(|m| !m.is_empty())
            .collect();
        if set.is_empty() {
            MethodSet::Any
        } else {
            MethodSet::Only(set)
        }
    }

    pub fn matches(&self, method: &str) -> bool {
        match self {
            MethodSet::Any => true,
            MethodSet::Only(set) => set.contains(&method.trim().to_ascii_uppercase()),
        }
    }

    /// The configured names, in sorted order (empty for [`MethodSet::Any`]).
    pub fn names(&self) -> Vec<String> {
        match self {
            MethodSet::Any => Vec::new(),
            MethodSet::Only(set) => set.iter().cloned().collect(),
        }
    }
}

/// Which request paths a rule covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSet {
    /// No `paths` was configured: every path matches (see [`MethodSet::Any`]).
    Any,
    Only(Vec<String>),
}

impl PathSet {
    pub fn new<I: IntoIterator<Item = String>>(patterns: I) -> PathSet {
        let list: Vec<String> = patterns
            .into_iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        if list.is_empty() {
            PathSet::Any
        } else {
            PathSet::Only(list)
        }
    }

    pub fn matches(&self, path: &str) -> bool {
        match self {
            PathSet::Any => true,
            PathSet::Only(patterns) => patterns.iter().any(|p| match_path(p, path)),
        }
    }

    pub fn patterns(&self) -> Vec<String> {
        match self {
            PathSet::Any => Vec::new(),
            PathSet::Only(p) => p.clone(),
        }
    }
}

/// Match a request path against a glob pattern.
///
/// Segment-wise, because that is how HTTP paths are read and how a mistake
/// stays legible: `*` matches within one segment, `**` matches any number of
/// segments (including none, so `/v1/**` covers `/v1` itself). Matching is
/// case-sensitive (paths are) and the query string never participates — a rule
/// permits an *operation*, and `?` parameters are not one.
pub fn match_path(pattern: &str, path: &str) -> bool {
    // Compare the path only; a caller that passes "/a?b=c" means the path "/a".
    let path = path.split('?').next().unwrap_or(path);
    let pat: Vec<&str> = pattern.split('/').collect();
    let seg: Vec<&str> = path.split('/').collect();
    match_segments(&pat, &seg)
}

fn match_segments(pat: &[&str], seg: &[&str]) -> bool {
    match pat.first() {
        // Pattern exhausted: a match only if the path is too.
        None => seg.is_empty(),
        Some(&"**") => {
            // `**` consumes zero or more segments; try every split point.
            for skip in 0..=seg.len() {
                if match_segments(&pat[1..], &seg[skip..]) {
                    return true;
                }
            }
            false
        }
        Some(p) => match seg.first() {
            None => false,
            Some(s) => match_segment(p, s) && match_segments(&pat[1..], &seg[1..]),
        },
    }
}

/// Match one path segment, where `*` stands for any run of non-`/` characters.
fn match_segment(pattern: &str, segment: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == segment;
    }
    // Backtrack-free wildcard match: literals between `*`s must appear in order.
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut rest = segment;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            // Leading literal must be a prefix.
            match rest.strip_prefix(*part) {
                Some(r) => rest = r,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            // Trailing literal must be a suffix of what is left.
            return rest.len() >= part.len() && rest.ends_with(*part);
        } else {
            match rest.find(*part) {
                Some(at) => rest = &rest[at + part.len()..],
                None => return false,
            }
        }
    }
    // Pattern ended with `*`: whatever is left is absorbed.
    true
}

/// One upstream host and what an agent may do to it.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Lowercased hostname, no port and no scheme.
    pub host: String,
    pub methods: MethodSet,
    pub paths: PathSet,
    /// Secret names injectable toward this host (default-deny: empty ⇒ none).
    pub allow: BTreeSet<String>,
    /// Free-text label carried through from the publisher, for logs and the
    /// simulator's "which rule decided" answer. Never used in matching.
    pub label: Option<String>,
}

impl Rule {
    pub fn new(host: &str, methods: MethodSet, paths: PathSet, allow: BTreeSet<String>) -> Rule {
        Rule {
            host: host.trim().to_ascii_lowercase(),
            methods,
            paths,
            allow,
            label: None,
        }
    }

    /// True if this rule governs `method` + `path` on its host.
    pub fn covers(&self, method: &str, path: &str) -> bool {
        self.methods.matches(method) && self.paths.matches(path)
    }

    /// Decide one operation against this rule alone — the host is assumed to
    /// have been matched already (a reverse-proxy route knows its upstream).
    ///
    /// `secret` asks the injection question too: `None` means "may the agent
    /// make this request at all", which is the anti-misuse half of the
    /// allowlist and applies whether or not a placeholder is present.
    pub fn decide(&self, method: &str, path: &str, secret: Option<&str>) -> Decision {
        if !self.methods.matches(method) {
            return Decision::MethodNotAllowed;
        }
        if !self.paths.matches(path) {
            return Decision::PathNotAllowed;
        }
        match secret {
            Some(name) if !self.allow.contains(name) => Decision::SecretNotAllowed,
            _ => Decision::Allow,
        }
    }
}

/// Why a request (or a placeholder within it) was permitted or refused.
///
/// The distinctions are load-bearing: a default-deny policy fails in exactly
/// the confusing direction, so both the proxy's 403 and the dashboard's
/// simulator name the constraint that decided rather than saying "denied".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Permitted — and, when a secret name was supplied, on that rule's allowlist.
    Allow,
    /// No rule covers this host at all.
    NoRule,
    /// A rule covers the host and path, but not this method.
    MethodNotAllowed,
    /// A rule covers the host, but no rule's paths cover this path.
    PathNotAllowed,
    /// A rule covers the operation, but the named secret is not injectable here.
    SecretNotAllowed,
}

impl Decision {
    pub fn allowed(self) -> bool {
        matches!(self, Decision::Allow)
    }

    /// Fixed-cardinality label for spans, metrics, and API responses.
    pub fn reason(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::NoRule => "no_rule",
            Decision::MethodNotAllowed => "method_not_allowed",
            Decision::PathNotAllowed => "path_not_allowed",
            Decision::SecretNotAllowed => "secret_not_allowed",
        }
    }
}

/// A decision plus the index of the rule that produced it (when one did), so a
/// caller can say *which* rule decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Decision,
    pub rule_index: Option<usize>,
}

impl Verdict {
    fn of(decision: Decision, rule_index: Option<usize>) -> Verdict {
        Verdict {
            decision,
            rule_index,
        }
    }

    pub fn allowed(self) -> bool {
        self.decision.allowed()
    }
}

/// An ordered set of rules, evaluated first-match-wins.
///
/// Order is the publisher's: a narrow rule placed before a broad one is how you
/// say "POST /v1/chat/completions may carry the key, everything else on this
/// host may not".
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new(rules: Vec<Rule>) -> RuleSet {
        RuleSet { rules }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Every host that has at least one rule — what the forward proxy
    /// intercepts, and nothing more.
    pub fn hosts(&self) -> BTreeSet<String> {
        self.rules.iter().map(|r| r.host.clone()).collect()
    }

    /// True if any rule names this host — what a forward proxy intercepts.
    pub fn covers_host(&self, host: &str) -> bool {
        let host = host.trim().to_ascii_lowercase();
        self.rules.iter().any(|r| r.host == host)
    }

    /// The first rule covering this operation, with its index.
    pub fn find(&self, host: &str, method: &str, path: &str) -> Option<(usize, &Rule)> {
        let host = host.trim().to_ascii_lowercase();
        self.rules
            .iter()
            .enumerate()
            .find(|(_, r)| r.host == host && r.covers(method, path))
    }

    /// Decide an operation, ignoring secrets: is the agent allowed to make this
    /// request at all? This is the anti-misuse half of the allowlist.
    pub fn evaluate(&self, host: &str, method: &str, path: &str) -> Verdict {
        let host = host.trim().to_ascii_lowercase();
        let mut host_matched = false;
        let mut path_matched_index: Option<usize> = None;
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.host != host {
                continue;
            }
            host_matched = true;
            let paths_ok = rule.paths.matches(path);
            if paths_ok && rule.methods.matches(method) {
                return Verdict::of(Decision::Allow, Some(i));
            }
            // Remember the closest near-miss so the refusal names the actual
            // constraint: a path that matched but a method that did not is a
            // different mistake from a path nothing covers.
            if paths_ok && path_matched_index.is_none() {
                path_matched_index = Some(i);
            }
        }
        match (host_matched, path_matched_index) {
            (_, Some(i)) => Verdict::of(Decision::MethodNotAllowed, Some(i)),
            (true, None) => Verdict::of(Decision::PathNotAllowed, None),
            (false, None) => Verdict::of(Decision::NoRule, None),
        }
    }

    /// Decide an operation *and* whether `secret` may be injected into it — the
    /// exact question the proxy asks per placeholder and the simulator asks per
    /// dry run.
    pub fn decide(&self, host: &str, method: &str, path: &str, secret: Option<&str>) -> Verdict {
        let verdict = self.evaluate(host, method, path);
        let (Some(index), Some(secret)) = (verdict.rule_index, secret) else {
            return verdict;
        };
        if !verdict.allowed() {
            return verdict;
        }
        Verdict::of(
            self.rules[index].decide(method, path, Some(secret)),
            Some(index),
        )
    }

    /// Narrow this rule set to what a [`Ceiling`] permits, refusing wholesale if
    /// anything exceeds it.
    ///
    /// Wholesale, not silently intersected: a policy that means something
    /// narrower than what was published is a policy nobody authored, and
    /// running it would make the dashboard lie about what the proxy is doing.
    pub fn check_ceiling(&self, ceiling: &Ceiling) -> Result<(), String> {
        for rule in &self.rules {
            let Some(allowed) = ceiling.hosts.get(&rule.host) else {
                return Err(format!(
                    "policy names host {} which the local ceiling does not permit",
                    rule.host
                ));
            };
            for name in &rule.allow {
                if !allowed.contains(name) {
                    return Err(format!(
                        "policy would inject {name} toward {} which the local ceiling does not permit",
                        rule.host
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The local, deployment-owned bound on any server-supplied policy: the hosts
/// and secret names that are *ever* permissible here.
///
/// A **fleet** control, off by default. On a developer machine the adversary is
/// the local agent, which can edit any file it can reach, so a ceiling there
/// adds no security and would put every new upstream back into a TOML edit —
/// see `docs/agent-access-governance.md` §1.
#[derive(Debug, Clone, Default)]
pub struct Ceiling {
    /// Host → the secret names permissible toward it.
    pub hosts: BTreeMap<String, BTreeSet<String>>,
}

impl Ceiling {
    pub fn new() -> Ceiling {
        Ceiling::default()
    }

    pub fn add(&mut self, host: &str, allow: BTreeSet<String>) {
        self.hosts
            .entry(host.trim().to_ascii_lowercase())
            .or_default()
            .extend(allow);
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

// ---------------------------------------------------------------------------
// The signed bundle
// ---------------------------------------------------------------------------

/// A published policy bundle, as signed in the browser.
///
/// Field names are the wire format and are inside the signature; `serde` does
/// no renaming here on purpose, so the Rust struct reads exactly like the JSON a
/// publisher signed.
#[derive(Debug, Clone, Deserialize)]
pub struct Bundle {
    pub v: u32,
    /// Organization id. Inside the signature, so a bundle cannot be replayed at
    /// another tenant.
    pub org: String,
    /// Agent identity id. Inside the signature, likewise, so a bundle published
    /// for a narrow agent cannot be served to a broad one.
    pub agent: String,
    /// Agent slug, for logs and the proxy's `policy.agent` config match.
    #[serde(default)]
    pub agent_slug: Option<String>,
    pub policy_version: u32,
    /// Unix seconds.
    pub issued_at: i64,
    /// Unix seconds. Required: it bounds how long a revoked policy can keep
    /// working in a proxy partitioned from the API.
    pub expires_at: i64,
    pub rules: Vec<BundleRule>,
    pub signer: Signer,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BundleRule {
    pub host: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub label: Option<String>,
}

/// The publishing admin's key, carried inside the signature.
///
/// Self-certifying on purpose: `kid` is the RFC 7638 thumbprint of `jwk`, so a
/// server that swapped the key would have to break the thumbprint check *and*
/// the pinned-signer check. Nothing needs to be fetched to verify a bundle.
#[derive(Debug, Clone, Deserialize)]
pub struct Signer {
    pub kid: String,
    pub jwk: SignerJwk,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignerJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl SignerJwk {
    /// RFC 7638 JWK thumbprint (SHA-256, base64url, no padding) over the
    /// required EC members in lexicographic order.
    pub fn thumbprint(&self) -> String {
        let json = format!(
            "{{\"crv\":\"{}\",\"kty\":\"{}\",\"x\":\"{}\",\"y\":\"{}\"}}",
            self.crv, self.kty, self.x, self.y
        );
        b64::encode(&Sha256::digest(json.as_bytes()))
    }
}

impl Bundle {
    /// The rule set this bundle authorizes.
    pub fn rule_set(&self) -> RuleSet {
        RuleSet::new(
            self.rules
                .iter()
                .map(|r| Rule {
                    host: r.host.trim().to_ascii_lowercase(),
                    methods: MethodSet::new(r.methods.clone()),
                    paths: PathSet::new(r.paths.clone()),
                    allow: r.allow.iter().cloned().collect(),
                    label: r.label.clone(),
                })
                .collect(),
        )
    }

    /// Check the claims that bind a bundle to *this* deployment and *now*.
    ///
    /// `agent` accepts either the identity id or its slug, because that is what
    /// an operator writes in `policy.agent`.
    pub fn check_context(
        &self,
        org: Option<&str>,
        agent: Option<&str>,
        now: i64,
    ) -> CoreResult<()> {
        if self.v != BUNDLE_VERSION {
            return Err(CoreError::Policy(format!(
                "unsupported policy bundle version {} (this build understands {BUNDLE_VERSION})",
                self.v
            )));
        }
        if let Some(org) = org {
            if self.org != org {
                return Err(CoreError::Policy(format!(
                    "policy bundle is for organization {}, not {org}",
                    self.org
                )));
            }
        }
        if let Some(agent) = agent {
            let matches = self.agent == agent || self.agent_slug.as_deref() == Some(agent);
            if !matches {
                return Err(CoreError::Policy(format!(
                    "policy bundle is for agent {}, not {agent}",
                    self.agent
                )));
            }
        }
        if now >= self.expires_at {
            return Err(CoreError::Policy(format!(
                "policy bundle expired at {} (now {now}); republish it",
                self.expires_at
            )));
        }
        Ok(())
    }

    /// Seconds until this bundle expires (0 once it has).
    pub fn seconds_remaining(&self, now: i64) -> i64 {
        (self.expires_at - now).max(0)
    }
}

/// Verify an `ap1.` envelope and return the bundle it carries.
///
/// Fail-closed and never lenient: an unsigned bundle, a signature that does not
/// check out, or a signer that is not in `pinned` is refused. `pinned` is the
/// list of thumbprints from the proxy's **local file** — the trust anchor, and
/// the one input to this function that must not come from the server.
pub fn verify_bundle(envelope: &str, pinned: &[String]) -> CoreResult<Bundle> {
    if pinned.is_empty() {
        return Err(CoreError::Policy(
            "no policy signers are pinned locally; server policy cannot be trusted".into(),
        ));
    }
    let mut parts = envelope.trim().split('.');
    let prefix = parts.next().unwrap_or_default();
    if prefix != POLICY_PREFIX {
        return Err(CoreError::Policy(format!(
            "not a policy bundle (expected a {POLICY_PREFIX}. envelope)"
        )));
    }
    let body_b64 = parts
        .next()
        .ok_or_else(|| CoreError::Policy("policy bundle is missing its body".into()))?;
    let sig_b64 = parts
        .next()
        .ok_or_else(|| CoreError::Policy("policy bundle is not signed".into()))?;
    if parts.next().is_some() {
        return Err(CoreError::Policy(
            "policy bundle envelope has trailing data".into(),
        ));
    }

    let body = b64::decode(body_b64)
        .map_err(|e| CoreError::Policy(format!("policy bundle body is not base64url: {e}")))?;
    let sig = b64::decode(sig_b64)
        .map_err(|e| CoreError::Policy(format!("policy signature is not base64url: {e}")))?;

    let bundle: Bundle = serde_json::from_slice(&body)
        .map_err(|e| CoreError::Policy(format!("policy bundle is not valid JSON: {e}")))?;

    // The signer claim must be internally consistent before it is compared to
    // anything: a `kid` that is not the thumbprint of the key beside it is a
    // bundle trying to look like one signed by somebody else.
    let computed = bundle.signer.jwk.thumbprint();
    if computed != bundle.signer.kid {
        return Err(CoreError::Policy(
            "policy bundle signer kid does not match its key".into(),
        ));
    }
    if !pinned.iter().any(|p| p == &computed) {
        return Err(CoreError::Policy(format!(
            "policy bundle was signed by {computed}, which is not a pinned signer"
        )));
    }
    if bundle.signer.jwk.kty != "EC" || bundle.signer.jwk.crv != "P-256" {
        return Err(CoreError::Policy(
            "policy bundle signer key is not an EC P-256 key".into(),
        ));
    }

    let x = b64::decode(&bundle.signer.jwk.x)
        .map_err(|e| CoreError::Policy(format!("signer key x is not base64url: {e}")))?;
    let y = b64::decode(&bundle.signer.jwk.y)
        .map_err(|e| CoreError::Policy(format!("signer key y is not base64url: {e}")))?;
    let key = VerifyingKey::from_public_coords(&x, &y)?;
    // Verify over the transported bytes, not a re-serialization of the parsed
    // struct: canonicalization mismatches between two languages are a classic
    // way to make a signature check meaningless, and signing exactly what the
    // verifier reads removes the whole class.
    if !key.verify_p1363(&body, &sig) {
        return Err(CoreError::Policy(
            "policy bundle signature is not valid for the pinned signer".into(),
        ));
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(host: &str, methods: &[&str], paths: &[&str], allow: &[&str]) -> Rule {
        Rule::new(
            host,
            MethodSet::new(methods.iter().map(|s| s.to_string())),
            PathSet::new(paths.iter().map(|s| s.to_string())),
            allow.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn absent_constraints_mean_any() {
        let r = rule("api.test", &[], &[], &["KEY"]);
        assert!(r.covers("DELETE", "/anything/at/all"));
        assert_eq!(r.methods, MethodSet::Any);
        assert_eq!(r.paths, PathSet::Any);
    }

    #[test]
    fn methods_are_case_insensitive() {
        let r = rule("api.test", &["post"], &[], &[]);
        assert!(r.covers("POST", "/x"));
        assert!(r.covers("post", "/x"));
        assert!(!r.covers("GET", "/x"));
    }

    #[test]
    fn single_star_stays_within_a_segment() {
        assert!(match_path("/v1/files/*", "/v1/files/abc"));
        assert!(!match_path("/v1/files/*", "/v1/files/abc/content"));
        assert!(!match_path("/v1/files/*", "/v1/files"));
    }

    #[test]
    fn double_star_spans_segments_including_none() {
        assert!(match_path("/v1/**", "/v1"));
        assert!(match_path("/v1/**", "/v1/a"));
        assert!(match_path("/v1/**", "/v1/a/b/c"));
        assert!(!match_path("/v1/**", "/v2/a"));
    }

    #[test]
    fn partial_segment_wildcards() {
        assert!(match_path("/v1/chat/*completions", "/v1/chat/completions"));
        assert!(match_path("/repos/*/issues", "/repos/seekrit/issues"));
        assert!(!match_path("/repos/*/issues", "/repos/a/b/issues"));
        assert!(match_path("/v1/*.json", "/v1/index.json"));
        assert!(!match_path("/v1/*.json", "/v1/index.yaml"));
    }

    #[test]
    fn query_strings_never_participate() {
        assert!(match_path("/v1/models", "/v1/models?limit=10"));
    }

    #[test]
    fn paths_are_case_sensitive_but_hosts_are_not() {
        assert!(!match_path("/v1/Models", "/v1/models"));
        let set = RuleSet::new(vec![rule("API.Test", &[], &[], &["KEY"])]);
        assert!(set.evaluate("api.test", "GET", "/x").allowed());
    }

    #[test]
    fn first_matching_rule_wins() {
        let set = RuleSet::new(vec![
            rule("api.test", &["POST"], &["/v1/chat/**"], &["KEY"]),
            rule("api.test", &[], &[], &[]),
        ]);
        let v = set.decide("api.test", "POST", "/v1/chat/completions", Some("KEY"));
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(v.rule_index, Some(0));
        // The broad rule still covers other operations — with no secrets.
        let v = set.decide("api.test", "GET", "/v1/models", Some("KEY"));
        assert_eq!(v.decision, Decision::SecretNotAllowed);
        assert_eq!(v.rule_index, Some(1));
    }

    #[test]
    fn refusals_name_the_constraint_that_decided() {
        let set = RuleSet::new(vec![rule(
            "api.test",
            &["POST"],
            &["/v1/chat/completions"],
            &["KEY"],
        )]);
        assert_eq!(
            set.evaluate("other.test", "POST", "/v1/chat/completions")
                .decision,
            Decision::NoRule
        );
        assert_eq!(
            set.evaluate("api.test", "DELETE", "/v1/chat/completions")
                .decision,
            Decision::MethodNotAllowed
        );
        assert_eq!(
            set.evaluate("api.test", "POST", "/v1/files").decision,
            Decision::PathNotAllowed
        );
        assert_eq!(
            set.decide("api.test", "POST", "/v1/chat/completions", Some("OTHER"))
                .decision,
            Decision::SecretNotAllowed
        );
    }

    #[test]
    fn ceiling_refuses_wholesale() {
        let set = RuleSet::new(vec![rule("api.test", &[], &[], &["KEY", "OTHER"])]);
        let mut ceiling = Ceiling::new();
        ceiling.add("api.test", ["KEY".to_string()].into_iter().collect());
        // A secret the ceiling does not permit fails the whole bundle.
        assert!(set.check_ceiling(&ceiling).is_err());
        // An unlisted host likewise.
        let other = RuleSet::new(vec![rule("evil.test", &[], &[], &[])]);
        assert!(other.check_ceiling(&ceiling).is_err());
        // Within the ceiling, fine.
        let narrow = RuleSet::new(vec![rule("api.test", &["POST"], &["/v1/**"], &["KEY"])]);
        assert!(narrow.check_ceiling(&ceiling).is_ok());
    }

    #[test]
    fn hosts_lists_every_ruled_host_once() {
        let set = RuleSet::new(vec![
            rule("api.test", &["GET"], &[], &[]),
            rule("API.test", &["POST"], &[], &["K"]),
            rule("other.test", &[], &[], &[]),
        ]);
        let hosts = set.hosts();
        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains("api.test"));
    }

    #[test]
    fn envelope_must_be_signed_and_pinned() {
        // Structural refusals need no key material.
        assert!(verify_bundle("ap1.body.sig", &[]).is_err()); // nothing pinned
        assert!(verify_bundle("nope.body.sig", &["kid".into()]).is_err()); // wrong prefix
        assert!(verify_bundle("ap1.body", &["kid".into()]).is_err()); // unsigned
        assert!(verify_bundle("ap1.body.sig.extra", &["kid".into()]).is_err());
    }

    #[test]
    fn thumbprint_matches_rfc7638_example() {
        // The P-256 key from RFC 7515 A.3, thumbprinted per RFC 7638 §3.1's
        // rule for EC keys: SHA-256 over `{"crv","kty","x","y"}` in
        // lexicographic order with no whitespace. This test guards the member
        // ordering; the cross-language vectors in apps/proxy/testdata guard that
        // the browser computes the same thing.
        let jwk = SignerJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".into(),
            y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".into(),
        };
        assert_eq!(
            jwk.thumbprint(),
            "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"
        );
    }
}
