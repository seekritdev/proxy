//! Reporting what this proxy decided, so a policy can be reviewed against what an
//! agent actually does.
//!
//! The design constraint that shapes everything here: **this data leaves the
//! customer's network.** Full per-request detail already goes to their own OTLP
//! collector, where it belongs. What crosses the boundary to seekrit is the
//! smallest thing that answers "should this policy be narrower", and nothing more:
//!
//! - **Counts, not requests.** Decisions are aggregated in memory into cells keyed
//!   by (host, method, decision, rule index) and flushed on an interval. A busy
//!   proxy sends data proportional to how *varied* its traffic is, not how much of
//!   it there is.
//! - **No paths, ever.** A path can carry a customer identifier
//!   (`/v1/customers/8814/ssn`), and shipping thousands of them would be a second
//!   data-exfiltration channel out of a component built to prevent the first. The
//!   rule index says which published rule decided, which is what a review needs
//!   and cannot name anybody.
//! - **Secret names, never values.** Same line `seekrit_telemetry` draws.
//!
//! Off unless `[activity]` is configured. Opt-in because it is a new outbound data
//! path, and one an operator should choose rather than discover.
//!
//! Failure is silent-but-logged and never affects a request: a flush that cannot
//! reach the API drops that window rather than retrying forever or blocking the
//! data plane. Losing a window makes a review slightly less complete; making a
//! proxied request wait on our API would make the feature a liability.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tracing::{debug, warn};

/// One aggregated cell's dimensions. Deliberately small — every field here is
/// something an operator already sees in their own logs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cell {
    pub host: String,
    pub method: String,
    /// The vocabulary in `ACTIVITY_DECISIONS` (`packages/core/src/agent-activity.ts`).
    pub decision: &'static str,
    /// Which published rule decided, when one did.
    pub rule_index: Option<usize>,
}

/// One drained cell: its dimensions, how many requests, and the secret names
/// injected through it. Named because the tuple appears in three signatures.
pub type DrainedCell = (Cell, u64, HashMap<String, u64>);

/// Counts for one cell, plus which secrets were injected through it.
#[derive(Debug, Default, Clone)]
struct Counts {
    requests: u64,
    secrets: HashMap<String, u64>,
}

/// In-memory aggregation, drained by the flush task.
pub struct ActivityLog {
    cells: Mutex<HashMap<Cell, Counts>>,
    /// Cap on distinct cells held between flushes.
    ///
    /// A policy broad enough to produce more than this is beyond what a review can
    /// help with, and an unbounded map on the request path is a memory leak waiting
    /// for unusual traffic. Overflow is dropped and *counted*, so the report can
    /// say it was incomplete rather than quietly under-reporting.
    max_cells: usize,
    dropped: Mutex<u64>,
}

impl ActivityLog {
    pub fn new(max_cells: usize) -> ActivityLog {
        ActivityLog {
            cells: Mutex::new(HashMap::new()),
            max_cells,
            dropped: Mutex::new(0),
        }
    }

    /// Record one decision. Called on the request path, so it takes a short lock
    /// and never allocates beyond the first sighting of a cell.
    pub fn record(&self, cell: Cell, secrets: &[String]) {
        let Ok(mut cells) = self.cells.lock() else {
            return;
        };
        if !cells.contains_key(&cell) && cells.len() >= self.max_cells {
            if let Ok(mut dropped) = self.dropped.lock() {
                *dropped += 1;
            }
            return;
        }
        let counts = cells.entry(cell).or_default();
        counts.requests += 1;
        for name in secrets {
            *counts.secrets.entry(name.clone()).or_insert(0) += 1;
        }
    }

    /// Take everything collected so far, leaving the log empty.
    pub fn drain(&self) -> (Vec<DrainedCell>, u64) {
        let taken = match self.cells.lock() {
            Ok(mut cells) => std::mem::take(&mut *cells),
            Err(_) => return (Vec::new(), 0),
        };
        let dropped = match self.dropped.lock() {
            Ok(mut d) => std::mem::replace(&mut *d, 0),
            Err(_) => 0,
        };
        let out = taken
            .into_iter()
            .map(|(cell, counts)| (cell, counts.requests, counts.secrets))
            .collect();
        (out, dropped)
    }

    /// Whether anything is waiting to be sent — so a quiet proxy makes no request.
    pub fn is_empty(&self) -> bool {
        self.cells.lock().map(|c| c.is_empty()).unwrap_or(true)
    }
}

/// Serialize a drained batch into the report body the API accepts.
///
/// Public for its own test: the JSON shape is a contract with
/// `reportAgentActivitySchema`, and the two drifting would be a silent 400 on a
/// path nobody watches.
pub fn report_body(
    window_start: &str,
    policy_version: Option<u32>,
    batch: &[DrainedCell],
) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = batch
        .iter()
        .map(|(cell, count, secrets)| {
            let mut entry = serde_json::json!({
                "host": cell.host,
                "method": cell.method,
                "decision": cell.decision,
                "ruleIndex": cell.rule_index,
                "count": count,
            });
            if !secrets.is_empty() {
                entry["secrets"] = serde_json::json!(secrets);
            }
            entry
        })
        .collect();
    let mut body = serde_json::json!({
        "windowStart": window_start,
        "entries": entries,
    });
    if let Some(version) = policy_version {
        body["policyVersion"] = serde_json::json!(version);
    }
    body
}

/// The periodic flush. Spawned once at startup; ends when `shutdown` resolves.
///
/// `agent` is the identity to report under. In server mode that is the configured
/// default identity: a proxy fronting several agents reports each request under the
/// identity that authorized it, which this first cut does not split — see the
/// caveat in the guide. One report per interval keeps the write path cheap.
#[allow(clippy::too_many_arguments)]
pub async fn flush_loop(
    log: std::sync::Arc<ActivityLog>,
    client: reqwest::Client,
    api_url: String,
    token: String,
    agent: String,
    interval: Duration,
    policy_version: Option<u32>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let url = format!(
        "{}/v1/agents/{}/activity",
        api_url.trim_end_matches('/'),
        urlencode(&agent)
    );
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.changed() => {
                // Last flush on the way out, so a short-lived run's evidence is
                // not lost to a clean shutdown.
                flush_once(&log, &client, &url, &token, policy_version).await;
                return;
            }
        }
        flush_once(&log, &client, &url, &token, policy_version).await;
    }
}

async fn flush_once(
    log: &ActivityLog,
    client: &reqwest::Client,
    url: &str,
    token: &str,
    policy_version: Option<u32>,
) {
    if log.is_empty() {
        return;
    }
    let (batch, dropped) = log.drain();
    if batch.is_empty() {
        return;
    }
    if dropped > 0 {
        // Said out loud rather than swallowed: a truncated report should not read
        // like a complete one.
        warn!(
            dropped,
            "activity reporting hit its cell cap — this window is incomplete"
        );
    }
    // The API caps a report at 500 entries; chunk rather than lose the tail.
    for chunk in batch.chunks(500) {
        let body = report_body(&now_iso(), policy_version, chunk);
        let sent = client
            .post(url)
            .bearer_auth(token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await;
        match sent {
            Ok(resp) if resp.status().is_success() => {
                debug!(cells = chunk.len(), "reported activity");
            }
            Ok(resp) => {
                // Dropped, not retried. A queue that grows while the API is down
                // is a memory leak; a review that is missing an hour is not a
                // problem worth one.
                warn!(status = %resp.status(), cells = chunk.len(), "activity report refused — dropping this window");
            }
            Err(e) => {
                warn!(error = %e, cells = chunk.len(), "could not report activity — dropping this window");
            }
        }
    }
}

/// Wall-clock now, as the ISO-8601 the API buckets on.
///
/// Hand-rolled because this crate carries no date dependency and needs exactly one
/// format. Seconds precision is plenty: the API truncates to the hour.
fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let time = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

/// Howard Hinnant's `civil_from_days`, the standard branch-free conversion from a
/// day count to a calendar date. Used rather than a dependency for one format.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(host: &str, method: &str, decision: &'static str, rule: Option<usize>) -> Cell {
        Cell {
            host: host.to_string(),
            method: method.to_string(),
            decision,
            rule_index: rule,
        }
    }

    #[test]
    fn identical_decisions_collapse_into_one_cell() {
        let log = ActivityLog::new(100);
        let c = cell("api.stripe.com", "GET", "allow", Some(0));
        log.record(c.clone(), &["STRIPE_KEY".to_string()]);
        log.record(c.clone(), &["STRIPE_KEY".to_string()]);
        log.record(c, &[]);

        let (batch, dropped) = log.drain();
        assert_eq!(dropped, 0);
        assert_eq!(batch.len(), 1, "one cell, three requests");
        let (_, count, secrets) = &batch[0];
        assert_eq!(*count, 3);
        assert_eq!(secrets.get("STRIPE_KEY"), Some(&2));
    }

    #[test]
    fn different_dimensions_stay_separate() {
        let log = ActivityLog::new(100);
        log.record(cell("a.example.com", "GET", "allow", Some(0)), &[]);
        log.record(cell("a.example.com", "POST", "allow", Some(0)), &[]);
        log.record(cell("a.example.com", "GET", "no_rule", None), &[]);
        log.record(cell("b.example.com", "GET", "allow", Some(1)), &[]);
        assert_eq!(log.drain().0.len(), 4);
    }

    #[test]
    fn draining_leaves_the_log_empty() {
        let log = ActivityLog::new(100);
        log.record(cell("a.example.com", "GET", "allow", Some(0)), &[]);
        assert!(!log.is_empty());
        log.drain();
        assert!(log.is_empty());
        assert_eq!(log.drain().0.len(), 0);
    }

    #[test]
    fn the_cell_cap_drops_and_counts_rather_than_growing() {
        let log = ActivityLog::new(2);
        log.record(cell("a.example.com", "GET", "allow", Some(0)), &[]);
        log.record(cell("b.example.com", "GET", "allow", Some(0)), &[]);
        log.record(cell("c.example.com", "GET", "allow", Some(0)), &[]);
        // An existing cell still counts after the cap is reached — only *new*
        // dimensions are refused, so a capped log keeps measuring what it knows.
        log.record(cell("a.example.com", "GET", "allow", Some(0)), &[]);

        let (batch, dropped) = log.drain();
        assert_eq!(batch.len(), 2);
        assert_eq!(dropped, 1);
        let a = batch
            .iter()
            .find(|(c, _, _)| c.host == "a.example.com")
            .unwrap();
        assert_eq!(a.1, 2);
    }

    #[test]
    fn the_report_body_matches_the_api_schema() {
        let batch = vec![
            (
                cell("api.stripe.com", "GET", "allow", Some(0)),
                7,
                HashMap::from([("STRIPE_KEY".to_string(), 7u64)]),
            ),
            (
                cell("hooks.slack.com", "POST", "no_rule", None),
                2,
                HashMap::new(),
            ),
        ];
        let body = report_body("2026-08-21T04:00:00.000Z", Some(3), &batch);

        assert_eq!(body["windowStart"], "2026-08-21T04:00:00.000Z");
        assert_eq!(body["policyVersion"], 3);
        let entries = body["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);

        let allow = entries.iter().find(|e| e["decision"] == "allow").unwrap();
        assert_eq!(allow["host"], "api.stripe.com");
        assert_eq!(allow["ruleIndex"], 0);
        assert_eq!(allow["count"], 7);
        assert_eq!(allow["secrets"]["STRIPE_KEY"], 7);

        let deny = entries.iter().find(|e| e["decision"] == "no_rule").unwrap();
        // Null rather than absent: the API distinguishes "no rule decided" from a
        // rule at index 0, and the partial unique index depends on it.
        assert!(deny["ruleIndex"].is_null());
        // No `secrets` key at all when nothing was injected — an empty object
        // would fail the schema's `min(1)` on each count.
        assert!(deny.get("secrets").is_none());
    }

    #[test]
    fn no_paths_reach_the_report() {
        // The property this whole module is shaped around, asserted rather than
        // trusted: a `Cell` has nowhere to put a path, so a report cannot carry
        // one. If a field is ever added, this test is where it gets noticed.
        let batch = vec![(
            cell("api.stripe.com", "GET", "allow", Some(0)),
            1,
            HashMap::new(),
        )];
        let body = report_body("2026-08-21T04:00:00.000Z", None, &batch).to_string();
        assert!(
            !body.contains('/'),
            "a report must carry no request path: {body}"
        );
    }

    #[test]
    fn now_iso_round_trips_a_known_instant() {
        // Pinned against a verified instant, so a broken date conversion fails
        // here rather than by writing counts into the wrong hour — an off-by-one
        // day would put a review's evidence somewhere nobody looks.
        // 2026-08-21T04:05:06Z:
        assert_eq!(
            civil_from_days(1787285106i64.div_euclid(86_400)),
            (2026, 8, 21)
        );
        // A day later, and the day before a leap day:
        assert_eq!(
            civil_from_days((1787285106i64 + 86_400).div_euclid(86_400)),
            (2026, 8, 22)
        );
        assert_eq!(civil_from_days(19_781), (2024, 2, 28));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        let iso = now_iso();
        assert!(iso.ends_with("Z") && iso.len() == 24, "{iso}");
        assert_eq!(&iso[4..5], "-");
    }
}
