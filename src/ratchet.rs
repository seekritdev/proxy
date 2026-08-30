//! The trust ratchet: capability that narrows as a run proceeds, and never
//! widens again.
//!
//! Policy answers "may this agent ever do this". The ratchet answers a question
//! policy cannot, because it has no memory: **"given what this run has already
//! touched, may it still do this?"** A run that has read a customer export has no
//! business posting to a webhook afterwards, even though both are things the
//! agent is broadly allowed to do.
//!
//! Four decisions shape this implementation, and each one is a place a more
//! obvious design would be worse.
//!
//! **1. Triggers are declared, never inferred.** A rule says "touching me is a
//! protected event"; the proxy does not inspect response bodies to decide what
//! was sensitive. Content classification would mean reading the plaintext this
//! whole architecture exists to avoid handling, and it would make the boundary
//! depend on a heuristic. So the trigger is a host (and optionally methods and
//! paths) named in the config.
//!
//! **2. The ratchet is local, not published policy.** It lives in the proxy's own
//! TOML beside the pinned signers, not in the signed bundle. Two reasons: an
//! overlay that can only *subtract* is safe to take from a local file in a way
//! server-delivered rules are not, and the `ap1.` bundle format is versioned and
//! signed — extending it means a new format version and cross-language vectors,
//! which is a lot of machinery for a control that works better locally anyway.
//!
//! **3. States are an ordered list, so monotonicity is structural.** A transition
//! resolves to an index, and advancing takes `max(current, target)`. There is no
//! code path that lowers a session's state, so "one-directional" is not a rule
//! this module remembers to follow — it is the only thing it can express.
//! Capability comes back the way AAM says it should: in a newly authorized run.
//!
//! **4. The transition applies when the protected request is authorized, not when
//! its response returns.** Narrowing early is the safe direction, and it is the
//! only honest option here: this proxy streams responses, so "hold the response
//! until every enforcement point acknowledges the new state" is not something one
//! process can promise on behalf of a fleet. What it *can* promise is that no
//! request authorized after this one sees the wider state.
//!
//! The bound worth stating out loud: state is per-session and in memory. A
//! restart drops it, exactly as it drops tickets, and a session that reaches its
//! most restricted state stays there until a new run is dispatched.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::Instant;

use seekrit_core::policy::{MethodSet, PathSet};

/// The implicit starting state, index 0. Named so refusals and logs can say
/// which state a session is in without a special case for "none yet".
pub const BASELINE: &str = "baseline";

/// One narrowed state. Every field is a *restriction*: absent means "whatever
/// policy already allowed", never "more than policy allowed".
#[derive(Debug, Clone)]
pub struct RatchetState {
    pub name: String,
    /// Hosts still reachable. `None` ⇒ every host policy permits.
    pub hosts: Option<BTreeSet<String>>,
    /// Secrets still injectable. `None` ⇒ whatever policy and the session allow.
    pub secrets: Option<BTreeSet<String>>,
}

/// A declared protected event: the request that moves a session onward.
#[derive(Debug, Clone)]
pub struct Transition {
    pub host: String,
    pub methods: MethodSet,
    pub paths: PathSet,
    /// Index into `RatchetConfig::states`, resolved at config load.
    pub to: usize,
    /// Operator-facing name of the trigger, for the refusal that follows it.
    pub label: Option<String>,
}

impl Transition {
    fn matches(&self, host: &str, method: &str, path: &str) -> bool {
        self.host.eq_ignore_ascii_case(host)
            && self.methods.matches(method)
            && self.paths.matches(path)
    }

    /// What a refusal calls this trigger.
    fn describe(&self) -> String {
        match &self.label {
            Some(label) => format!("{label:?}"),
            None => format!("{:?}", self.host),
        }
    }
}

/// The ratchet as configured. `states[0]` is always the implicit baseline.
#[derive(Debug, Clone)]
pub struct RatchetConfig {
    pub states: Vec<RatchetState>,
    pub transitions: Vec<Transition>,
}

impl RatchetConfig {
    /// Build from validated parts, prepending the implicit baseline.
    ///
    /// `narrowed` is in ratchet order: earlier states are wider. Callers resolve
    /// transition targets against `state_index` before getting here.
    pub fn new(narrowed: Vec<RatchetState>, transitions: Vec<Transition>) -> RatchetConfig {
        let mut states = vec![RatchetState {
            name: BASELINE.to_string(),
            hosts: None,
            secrets: None,
        }];
        states.extend(narrowed);
        RatchetConfig {
            states,
            transitions,
        }
    }

    /// Index of a state by name — how a transition's `to` is resolved. `None`
    /// means the config named a state that does not exist, which is a startup
    /// error rather than a runtime surprise.
    pub fn state_index(narrowed: &[RatchetState], name: &str) -> Option<usize> {
        if name.eq_ignore_ascii_case(BASELINE) {
            // Deliberately rejected by the caller: a transition *to* baseline
            // would be the one thing this module must not be able to express.
            return Some(0);
        }
        narrowed.iter().position(|s| s.name == name).map(|i| i + 1)
    }

    pub fn state_names(&self) -> Vec<&str> {
        self.states.iter().map(|s| s.name.as_str()).collect()
    }
}

/// Where one session currently sits.
struct Entry {
    index: usize,
    /// When it last narrowed, so a refusal can say how long ago the door closed.
    since: Instant,
    /// Which trigger closed it.
    by: Option<String>,
}

/// Per-session ratchet state.
///
/// Keyed by the credential a request presented, or [`DEFAULT_SESSION`] when it
/// presented none. In memory only: a restart resets every session, which is the
/// same lifetime tickets have and the same answer to "how do I clear this".
pub struct RatchetStore {
    config: RatchetConfig,
    sessions: Mutex<HashMap<String, Entry>>,
}

/// Session key for requests carrying no ticket or task — the single-agent
/// sidecar, where the proxy *is* the one run.
pub const DEFAULT_SESSION: &str = "<default>";

impl RatchetStore {
    pub fn new(config: RatchetConfig) -> RatchetStore {
        RatchetStore {
            config,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn config(&self) -> &RatchetConfig {
        &self.config
    }

    /// The restrictions in force for a session right now.
    ///
    /// A poisoned lock resolves to the *most restrictive* state rather than the
    /// baseline: if the ratchet's own bookkeeping is broken, the safe answer is
    /// the narrow one.
    pub fn gate(&self, key: &str) -> Gate {
        let (index, since, by) = match self.sessions.lock() {
            Ok(sessions) => match sessions.get(key) {
                Some(entry) => (entry.index, Some(entry.since), entry.by.clone()),
                None => (0, None, None),
            },
            Err(_) => (self.config.states.len() - 1, None, None),
        };
        let state = &self.config.states[index];
        Gate {
            state: state.name.clone(),
            hosts: state.hosts.clone(),
            secrets: state.secrets.clone(),
            since,
            by,
        }
    }

    /// Advance a session if this request is a declared protected event.
    ///
    /// Returns the state it moved to, for the log line. Only ever moves forward:
    /// `max(current, target)` is the whole enforcement of one-directionality.
    /// Call it only for requests policy has already **permitted** — an attempt
    /// that was refused touched nothing and should narrow nothing.
    pub fn advance(&self, key: &str, host: &str, method: &str, path: &str) -> Option<Advance> {
        let hit = self
            .config
            .transitions
            .iter()
            .filter(|t| t.matches(host, method, path))
            // Several triggers can match; take the most restrictive, so ordering
            // in the config file cannot make the ratchet weaker.
            .max_by_key(|t| t.to)?;

        let mut sessions = self.sessions.lock().ok()?;
        let entry = sessions.entry(key.to_string()).or_insert(Entry {
            index: 0,
            since: Instant::now(),
            by: None,
        });
        if hit.to <= entry.index {
            return None;
        }
        entry.index = hit.to;
        entry.since = Instant::now();
        entry.by = Some(hit.describe());
        Some(Advance {
            state: self.config.states[hit.to].name.clone(),
            by: hit.describe(),
        })
    }

    /// Forget a session's state — used when its ticket is revoked, so a reused
    /// key cannot inherit a stale state.
    pub fn forget(&self, key: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(key);
        }
    }

    /// How many sessions are holding a narrowed state, for the control
    /// listener's health endpoint.
    pub fn narrowed_sessions(&self) -> usize {
        self.sessions
            .lock()
            .map(|s| s.values().filter(|e| e.index > 0).count())
            .unwrap_or(0)
    }
}

/// A state transition that just happened.
#[derive(Debug, Clone)]
pub struct Advance {
    pub state: String,
    pub by: String,
}

/// The ratchet's restrictions for one request.
#[derive(Debug, Clone)]
pub struct Gate {
    pub state: String,
    hosts: Option<BTreeSet<String>>,
    secrets: Option<BTreeSet<String>>,
    since: Option<Instant>,
    by: Option<String>,
}

impl Gate {
    /// True while the session is unnarrowed — the fast path, and the only state
    /// most sessions ever occupy.
    pub fn is_baseline(&self) -> bool {
        self.hosts.is_none() && self.secrets.is_none()
    }

    /// Whether this host is still reachable in the current state.
    pub fn permits_host(&self, host: &str) -> bool {
        match &self.hosts {
            None => true,
            Some(hosts) => hosts.iter().any(|h| h.eq_ignore_ascii_case(host)),
        }
    }

    /// Fold the ratchet's secret restriction into a session's scopes.
    ///
    /// Intersection, both directions optional: `None` means unconstrained on that
    /// side, and two unconstrained sides stay unconstrained. The result can only
    /// be narrower than either input, which is what keeps this an overlay rather
    /// than a second source of permission.
    pub fn narrow(&self, scopes: Option<&BTreeSet<String>>) -> Option<BTreeSet<String>> {
        match (&self.secrets, scopes) {
            (None, None) => None,
            (None, Some(s)) => Some(s.clone()),
            (Some(r), None) => Some(r.clone()),
            (Some(r), Some(s)) => Some(r.intersection(s).cloned().collect()),
        }
    }

    /// Why this request was refused, in the terms the operator configured.
    ///
    /// The wording carries real weight: a bare 403 mid-run is maddening, whereas
    /// one naming the state, the trigger, and how long ago it fired is something
    /// an agent's author can act on — and often something the agent itself can
    /// route around, since it still has its typed output path.
    pub fn describe_refusal(&self, host: &str) -> String {
        let ago = match self.since {
            Some(since) => format!(" {}s ago", since.elapsed().as_secs()),
            None => String::new(),
        };
        let by = match &self.by {
            Some(by) => format!(" by {by}"),
            None => String::new(),
        };
        format!(
            "{host} was withdrawn from this run{ago}{by} — the trust ratchet is in state {:?} and does not permit it. Capability comes back in a new run, not this one.",
            self.state
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(name: &str, hosts: Option<&[&str]>, secrets: Option<&[&str]>) -> RatchetState {
        RatchetState {
            name: name.to_string(),
            hosts: hosts.map(|h| h.iter().map(|s| s.to_string()).collect()),
            secrets: secrets.map(|s| s.iter().map(|x| x.to_string()).collect()),
        }
    }

    fn transition(host: &str, to: usize, paths: &[&str]) -> Transition {
        Transition {
            host: host.to_string(),
            methods: MethodSet::new(Vec::new()),
            paths: PathSet::new(paths.iter().map(|p| p.to_string())),
            to,
            label: Some(format!("{host} trigger")),
        }
    }

    /// baseline → restricted(1) → locked(2)
    fn store() -> RatchetStore {
        let narrowed = vec![
            state("restricted", Some(&["ledger.internal"]), Some(&["LEDGER"])),
            state("locked", Some(&[]), Some(&[])),
        ];
        let transitions = vec![
            transition("reports.internal", 1, &["/exports/**"]),
            transition("vault.internal", 2, &[]),
        ];
        RatchetStore::new(RatchetConfig::new(narrowed, transitions))
    }

    #[test]
    fn starts_at_baseline_and_restricts_nothing() {
        let s = store();
        let gate = s.gate("run-1");
        assert!(gate.is_baseline());
        assert_eq!(gate.state, BASELINE);
        assert!(gate.permits_host("anything.example.com"));
        assert_eq!(gate.narrow(None), None);
    }

    #[test]
    fn a_declared_trigger_narrows_the_session() {
        let s = store();
        let advance = s
            .advance("run-1", "reports.internal", "GET", "/exports/2026-08.csv")
            .expect("the trigger should fire");
        assert_eq!(advance.state, "restricted");

        let gate = s.gate("run-1");
        assert!(!gate.is_baseline());
        assert!(gate.permits_host("ledger.internal"));
        assert!(!gate.permits_host("hooks.slack.com"));
    }

    #[test]
    fn a_path_outside_the_trigger_does_not_fire_it() {
        let s = store();
        assert!(s
            .advance("run-1", "reports.internal", "GET", "/health")
            .is_none());
        assert!(s.gate("run-1").is_baseline());
    }

    #[test]
    fn sessions_do_not_share_state() {
        let s = store();
        s.advance("run-1", "reports.internal", "GET", "/exports/x");
        assert!(!s.gate("run-1").is_baseline());
        // A different run — and the ticketless default — are untouched.
        assert!(s.gate("run-2").is_baseline());
        assert!(s.gate(DEFAULT_SESSION).is_baseline());
    }

    #[test]
    fn the_ratchet_only_turns_one_way() {
        let s = store();
        s.advance("run-1", "vault.internal", "GET", "/keys");
        assert_eq!(s.gate("run-1").state, "locked");
        // Re-firing the *weaker* trigger must not walk the state back.
        assert!(s
            .advance("run-1", "reports.internal", "GET", "/exports/x")
            .is_none());
        assert_eq!(s.gate("run-1").state, "locked");
    }

    #[test]
    fn firing_the_same_trigger_twice_is_not_a_transition() {
        let s = store();
        assert!(s
            .advance("run-1", "reports.internal", "GET", "/exports/x")
            .is_some());
        assert!(s
            .advance("run-1", "reports.internal", "GET", "/exports/y")
            .is_none());
    }

    #[test]
    fn the_most_restrictive_matching_trigger_wins() {
        // Two triggers on one host, listed weakest-first: config order must not
        // make the ratchet weaker than the strictest thing that matched.
        let narrowed = vec![
            state("restricted", Some(&["a"]), None),
            state("locked", Some(&[]), None),
        ];
        let s = RatchetStore::new(RatchetConfig::new(
            narrowed,
            vec![
                transition("reports.internal", 1, &[]),
                transition("reports.internal", 2, &[]),
            ],
        ));
        let advance = s.advance("run-1", "reports.internal", "GET", "/x").unwrap();
        assert_eq!(advance.state, "locked");
    }

    #[test]
    fn secrets_intersect_rather_than_replace() {
        let s = store();
        s.advance("run-1", "reports.internal", "GET", "/exports/x");
        let gate = s.gate("run-1");

        // Session scoped to two names; the ratchet permits one of them.
        let scopes: BTreeSet<String> = ["LEDGER", "SLACK"].iter().map(|s| s.to_string()).collect();
        assert_eq!(
            gate.narrow(Some(&scopes)),
            Some(["LEDGER".to_string()].into_iter().collect())
        );
        // A session with no narrowing still gets the ratchet's restriction.
        assert_eq!(
            gate.narrow(None),
            Some(["LEDGER".to_string()].into_iter().collect())
        );
    }

    #[test]
    fn the_locked_state_permits_nothing() {
        let s = store();
        s.advance("run-1", "vault.internal", "GET", "/keys");
        let gate = s.gate("run-1");
        assert!(!gate.permits_host("ledger.internal"));
        assert_eq!(gate.narrow(None), Some(BTreeSet::new()));
    }

    #[test]
    fn a_refusal_names_the_state_and_the_trigger() {
        let s = store();
        s.advance("run-1", "reports.internal", "GET", "/exports/x");
        let message = s.gate("run-1").describe_refusal("hooks.slack.com");
        assert!(message.contains("hooks.slack.com"), "{message}");
        assert!(message.contains("restricted"), "{message}");
        assert!(message.contains("reports.internal trigger"), "{message}");
        assert!(message.contains("new run"), "{message}");
    }

    #[test]
    fn forgetting_a_session_resets_it() {
        let s = store();
        s.advance("run-1", "reports.internal", "GET", "/exports/x");
        assert_eq!(s.narrowed_sessions(), 1);
        s.forget("run-1");
        assert!(s.gate("run-1").is_baseline());
        assert_eq!(s.narrowed_sessions(), 0);
    }

    #[test]
    fn state_index_resolves_names_in_config_order() {
        let narrowed = vec![state("restricted", None, None), state("locked", None, None)];
        assert_eq!(RatchetConfig::state_index(&narrowed, "restricted"), Some(1));
        assert_eq!(RatchetConfig::state_index(&narrowed, "locked"), Some(2));
        assert_eq!(RatchetConfig::state_index(&narrowed, BASELINE), Some(0));
        assert_eq!(RatchetConfig::state_index(&narrowed, "nope"), None);
    }
}
