//! The configs `seekrit proxy init` writes must parse here.
//!
//! `apps/cli/src/proxy-config.ts` generates `seekrit-proxy.toml` so that trying
//! the proxy does not start with reading reference docs. That only helps if the
//! generated file is one this binary actually accepts — and the two failure modes
//! are both invisible to a test on the generator alone:
//!
//! * a field the parser **rejects**, which turns a generated config into a
//!   fail-closed startup error (server mode rejects `allow`/`methods`/`paths` on
//!   a route rather than ignoring them, and that is exactly the mistake a
//!   generator naively copying fetched rules would make); and
//! * a field the parser **ignores**, which is worse — the operator believes they
//!   have a constraint they do not have.
//!
//! So the CLI's test writes its output to `testdata/generated-configs/` and this
//! test parses every file with the real `Config::from_toml`, asserting the shape
//! survived. A change to either half that breaks the other fails here.
//!
//! Regenerate the fixtures with:
//!     pnpm --filter @seekrit/cli test -- --update-fixtures

use std::fs;
use std::path::{Path, PathBuf};

use seekrit_core::policy::Decision;
use seekrit_proxy::config::{Config, PolicySource, UnmatchedPolicy};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/generated-configs")
}

fn load(name: &str) -> Config {
    let path = fixture_dir().join(name);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    Config::from_toml(&text).unwrap_or_else(|e| panic!("{name} did not parse: {e:?}"))
}

#[test]
fn every_generated_config_parses() {
    let dir = fixture_dir();
    let mut seen = 0;
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).expect("name");
        // Parsing is the assertion: `from_toml` validates listen addresses,
        // upstream URLs, route prefixes, duration strings, and the file/server
        // rule split, so a config that survives it is one that would start.
        load(name);
        seen += 1;
    }
    // A silently empty fixture directory would make this whole file vacuous.
    assert!(
        seen >= 5,
        "expected the CLI's generated configs in {} (found {seen}) — run \
         `pnpm --filter @seekrit/cli test` to write them",
        dir.display()
    );
}

#[test]
fn the_openai_preset_permits_what_the_sdk_does_and_nothing_else() {
    let config = load("presets-reverse.toml");
    assert_eq!(config.listen.to_string(), "127.0.0.1:8080");
    assert_eq!(config.policy.source, PolicySource::File);

    // The base URL the generated file tells the operator to export is
    // `…/openai/v1`, so this is the literal path an OpenAI SDK request arrives on.
    let route = config
        .match_route("/openai/v1/chat/completions")
        .expect("the generated /openai route matches an OpenAI SDK request");
    assert_eq!(route.upstream, "https://api.openai.com");
    assert_eq!(route.host, "api.openai.com");
    let rules = route.rules.as_ref().expect("file mode carries rules");
    let upstream_path = route.strip("/openai/v1/chat/completions");
    assert_eq!(upstream_path, "/v1/chat/completions");

    // Permitted: the request the preset exists for, carrying its own credential.
    assert_eq!(
        rules
            .decide(&route.host, "POST", upstream_path, Some("OPENAI_API_KEY"))
            .decision,
        Decision::Allow
    );

    // Refused: a method the preset leaves out, so a legitimate key still cannot
    // reach an operation nobody granted.
    assert_eq!(
        rules
            .decide(&route.host, "DELETE", "/v1/models/gpt-4", None)
            .decision,
        Decision::MethodNotAllowed
    );

    // Refused: another upstream's key, which is the exfiltration case the
    // per-route allowlist exists to stop.
    assert_eq!(
        rules
            .decide(
                &route.host,
                "POST",
                upstream_path,
                Some("ANTHROPIC_API_KEY")
            )
            .decision,
        Decision::SecretNotAllowed
    );

    // The Anthropic route is separate, and its base URL deliberately does NOT
    // carry `/v1` — the SDK appends it. Getting that backwards is the mistake the
    // preset catalogue exists to prevent, and it shows up here as a path miss.
    let anthropic = config
        .match_route("/anthropic/v1/messages")
        .expect("the generated /anthropic route matches an Anthropic SDK request");
    assert_eq!(anthropic.host, "api.anthropic.com");
    assert_eq!(
        anthropic
            .rules
            .as_ref()
            .expect("file mode carries rules")
            .decide(
                &anthropic.host,
                "POST",
                anthropic.strip("/anthropic/v1/messages"),
                Some("ANTHROPIC_API_KEY"),
            )
            .decision,
        Decision::Allow
    );
}

#[test]
fn a_generated_forward_config_declares_hosts_and_a_ca() {
    let config = load("presets-forward.toml");
    let forward = config.forward.as_ref().expect("[forward] block");
    assert_eq!(forward.listen.to_string(), "127.0.0.1:8081");
    assert_eq!(forward.unmatched, UnmatchedPolicy::Deny);
    assert!(!forward.ca_cert_path.is_empty());
    assert!(!forward.ca_key_path.is_empty());
    let rules = forward
        .rules
        .as_ref()
        .expect("file mode carries host rules");
    assert_eq!(
        rules
            .decide(
                "api.github.com",
                "POST",
                "/repos/acme/app/issues",
                Some("GITHUB_TOKEN")
            )
            .decision,
        Decision::Allow,
        "the generated forward host rule permits its credential"
    );
    // A host with no rule is the `unmatched_host_policy` case, not an allow.
    assert_eq!(
        rules
            .decide("evil.example", "POST", "/", Some("GITHUB_TOKEN"))
            .decision,
        Decision::NoRule
    );
}

#[test]
fn a_server_policy_config_pins_a_signer_and_declares_no_local_rules() {
    for name in ["policy-reverse.toml", "policy-forward.toml"] {
        let config = load(name);
        assert_eq!(config.policy.source, PolicySource::Server, "{name}");
        // The trust anchor. `from_toml` refuses server mode without one, so this
        // is really asserting the generator never emits a config that cannot start.
        assert!(!config.policy.signers.is_empty(), "{name} pins a signer");
        assert!(!config.policy.agents.is_empty(), "{name} names an identity");

        // Rules must come from the bundle. A route that also stated them is a
        // startup error, and a forward host list would defeat the point of
        // server mode — adding an upstream must not mean editing this file.
        for route in &config.routes {
            assert!(
                route.rules.is_none(),
                "{name}: route {} carries local rules in server mode",
                route.prefix
            );
        }
        if let Some(forward) = &config.forward {
            assert!(
                forward.rules.is_none(),
                "{name}: forward rules in server mode"
            );
        }

        // Server mode implies secret refresh, so a new rule and the credential
        // it names land together.
        assert!(
            config.secrets.refresh_interval.is_some(),
            "{name}: server mode implies a resolve refresh"
        );
    }
}

#[test]
fn the_optional_blocks_survive_the_round_trip() {
    let config = load("presets-both-with-options.toml");
    assert!(!config.routes.is_empty(), "reverse plane configured");
    assert!(config.forward.is_some(), "forward plane configured");
    let cache = config.cache.as_ref().expect("[cache] block");
    assert_eq!(cache.max_age.as_secs(), 6 * 60 * 60);
    let control = config.control.as_ref().expect("[control] block");
    assert_eq!(control.listen.to_string(), "127.0.0.1:9090");
    assert_eq!(
        config.secrets.refresh_interval.map(|d| d.as_secs()),
        Some(30)
    );
}
