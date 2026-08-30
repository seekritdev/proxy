//! Cross-implementation vectors for agent access policy.
//!
//! `apps/proxy/testdata/policy-vectors.json` is produced by the **real**
//! `@seekrit/core` signer and evaluator (see `gen-policy-vectors.mts`). This test
//! asserts that the Rust half agrees on both halves of the contract:
//!
//! 1. **Verification.** Every envelope a browser signs verifies here, and every
//!    forgery the generator builds — a widened allowlist, an unpinned signer, a
//!    swapped `kid`, a malformed envelope — is refused. This is the property the
//!    whole design rests on: the API stores policy it cannot forge, so a
//!    compromised API can withhold policy but never widen it.
//! 2. **The decision.** For each request the dashboard's simulator answered, the
//!    proxy's evaluator reaches the same verdict *and* names the same rule. A
//!    simulator that disagreed with the enforcement point would be worse than no
//!    simulator, because operators would trust it.
//!
//! Regenerate the vectors after changing the format or the matcher; a diff in
//! `canonical_body` is the signal that the wire format moved.

use seekrit_core::policy::{verify_bundle, Decision};
use serde_json::Value;

fn vectors() -> Value {
    let raw = include_str!("../testdata/policy-vectors.json");
    serde_json::from_str(raw).expect("policy-vectors.json is valid JSON")
}

fn pinned(v: &Value) -> Vec<String> {
    v["pinned_signers"]
        .as_array()
        .expect("pinned_signers")
        .iter()
        .map(|s| s.as_str().expect("thumbprint").to_string())
        .collect()
}

#[test]
fn every_browser_signed_bundle_verifies_and_every_forgery_is_refused() {
    let v = vectors();
    let pinned = pinned(&v);
    let bundles = v["bundles"].as_array().expect("bundles");
    assert!(bundles.len() >= 8, "vectors should cover the refusal cases");

    for entry in bundles {
        let label = entry["label"].as_str().unwrap_or("<unlabeled>");
        let envelope = entry["envelope"].as_str().expect("envelope");
        let result = verify_bundle(envelope, &pinned);

        if entry["verifies"].as_bool().unwrap_or(false) {
            let bundle = result.unwrap_or_else(|e| panic!("{label}: should verify, got {e}"));
            if let Some(org) = entry["org"].as_str() {
                assert_eq!(bundle.org, org, "{label}: org");
            }
            if let Some(agent) = entry["agent"].as_str() {
                assert_eq!(bundle.agent, agent, "{label}: agent");
            }
            if let Some(slug) = entry["agent_slug"].as_str() {
                assert_eq!(
                    bundle.agent_slug.as_deref(),
                    Some(slug),
                    "{label}: agent_slug"
                );
            }
            if let Some(version) = entry["policy_version"].as_u64() {
                assert_eq!(bundle.policy_version as u64, version, "{label}: version");
            }
            if let Some(count) = entry["rule_count"].as_u64() {
                assert_eq!(bundle.rules.len() as u64, count, "{label}: rule count");
            }
            if let Some(expires) = entry["expires_at"].as_i64() {
                assert_eq!(bundle.expires_at, expires, "{label}: expires_at");
                // The expiry check is separate from signature verification on
                // purpose: a correctly signed but stale bundle must fail closed
                // at the *context* check, not be mistaken for a bad signature.
                assert!(
                    bundle.check_context(None, None, expires + 1).is_err(),
                    "{label}: an expired bundle must not pass its context check"
                );
                assert!(bundle.check_context(None, None, expires - 1).is_ok());
            }
        } else {
            let err = result
                .err()
                .unwrap_or_else(|| panic!("{label}: must be refused, but verification succeeded"));
            // The message is operator-facing; assert it names the cause so a
            // refusal is diagnosable from a log line alone.
            let text = err.to_string();
            match entry["reject_reason"].as_str() {
                Some("unpinned_signer") => {
                    assert!(text.contains("not a pinned signer"), "{label}: {text}")
                }
                Some("bad_signature") => {
                    assert!(text.contains("signature is not valid"), "{label}: {text}")
                }
                Some("kid_mismatch") => {
                    assert!(text.contains("does not match its key"), "{label}: {text}")
                }
                Some("malformed") => assert!(
                    text.contains("not a policy bundle") || text.contains("not signed"),
                    "{label}: {text}"
                ),
                _ => {}
            }
        }
    }
}

#[test]
fn the_bundle_binds_to_its_org_and_agent() {
    let v = vectors();
    let pinned = pinned(&v);
    let entry = &v["bundles"][0];
    let bundle = verify_bundle(entry["envelope"].as_str().unwrap(), &pinned).expect("verifies");
    let now = bundle.expires_at - 60;

    assert!(bundle
        .check_context(Some(&bundle.org), Some("nova"), now)
        .is_ok());
    // Either the id or the slug names the agent — an operator writes the slug.
    assert!(bundle
        .check_context(Some(&bundle.org), Some(&bundle.agent.clone()), now)
        .is_ok());
    // A bundle replayed at another tenant, or against another agent, is refused
    // even though its signature is perfectly good.
    assert!(bundle
        .check_context(Some("org_someone_else"), None, now)
        .is_err());
    assert!(bundle
        .check_context(None, Some("other-agent"), now)
        .is_err());
}

#[test]
fn decisions_match_the_dashboard_simulator() {
    let v = vectors();
    let pinned = pinned(&v);
    let bundle = verify_bundle(v["bundles"][0]["envelope"].as_str().unwrap(), &pinned)
        .expect("the primary bundle verifies");
    let rules = bundle.rule_set();

    let decisions = v["decisions"].as_array().expect("decisions");
    assert!(!decisions.is_empty());
    for case in decisions {
        let host = case["host"].as_str().expect("host");
        let method = case["method"].as_str().expect("method");
        let path = case["path"].as_str().expect("path");
        let secret = case["secret"].as_str();
        let want = case["decision"].as_str().expect("decision");

        let verdict = rules.decide(host, method, path, secret);
        assert_eq!(
            verdict.decision.reason(),
            want,
            "{method} {host}{path} secret={secret:?}"
        );
        let want_index = case["rule_index"].as_u64().map(|i| i as usize);
        assert_eq!(
            verdict.rule_index, want_index,
            "{method} {host}{path}: the simulator and the proxy must name the same rule"
        );
        // Sanity: only "allow" is permissive, whatever the reason string says.
        assert_eq!(verdict.allowed(), verdict.decision == Decision::Allow);
    }
}
