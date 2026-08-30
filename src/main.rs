//! Entry point: parse args → load config → resolve + decrypt secrets
//! (fail-closed) → serve the reverse proxy until interrupted.
//!
//! Unlike `seekrit-run`, the proxy is a **security control**, so it fails
//! closed: if the token is missing/bad, the API is unreachable, or a layer
//! won't decrypt, it refuses to start rather than forward requests with
//! placeholders left intact.
//!
//! `[cache] enabled = true` softens exactly one of those cases — an API that
//! cannot be *reached* — by starting from the last-known-good response. A
//! refused resolve still fails closed, and a proxy that started degraded
//! retries on a short backoff and swaps in live secrets the moment it can, so
//! the stale window is as small as the network allows.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use seekrit_cache::{Cache, CacheKey, Lookup};
use seekrit_proxy::activity::ActivityLog;
use seekrit_proxy::ca::Ca;
use seekrit_proxy::config::{CacheConfig, Config};
use seekrit_proxy::forward::{self, ForwardState};
use seekrit_proxy::policy::{self, PolicyCache};
use seekrit_proxy::proxy::{router, AppState};
use seekrit_proxy::ratchet::RatchetStore;
use seekrit_proxy::resolve::{self, ResolveFailure, DEFAULT_API_URL};
use seekrit_proxy::secrets::{self, SecretStore};
use seekrit_proxy::tasks::{SessionResolver, TaskClient};
use seekrit_proxy::tickets::{control_router, ControlState, TicketStore, CONTROL_TOKEN_ENV};
use tracing::{error, info, warn};

const HELP: &str = "\
seekrit-proxy — swap {{seekrit:NAME}} placeholders in outbound requests for
decrypted secrets, then forward to the upstream. The agent never holds the key.

USAGE:
    seekrit-proxy [OPTIONS]

OPTIONS:
    -c, --config <path>    config file (default: ./seekrit-proxy.toml)
        --listen <addr>    override the config's listen address
    -t, --token <skt_...>  service token (default: SEEKRIT_TOKEN)
        --api-url <url>     API base URL (default: SEEKRIT_API_URL or
                            https://api.seekrit.dev)
    -h, --help             show this help
    -V, --version          show the version

The config maps route prefixes to upstreams and the secrets each may receive:

    listen = \"127.0.0.1:8080\"
    [[route]]
    prefix = \"/example\"
    upstream = \"https://api.example.com\"
    allow = [\"EXAMPLE_API_KEY\"]

Point your agent's base URL at http://127.0.0.1:8080/example and send the key as
`Authorization: Bearer {{seekrit:EXAMPLE_API_KEY}}` — the proxy fills it in.

By default the proxy refuses to start if it cannot resolve. To let it start on
the last response it saw instead — the *encrypted* one; decrypting still needs
this token — add:

    [cache]
    enabled = true
    max_age = \"24h\"           # how stale that copy may be (default: 24h)
    # dir = \"/var/cache/seekrit\"
    # reconnect_interval = \"5s\"      # first retry after a degraded start
    # reconnect_max_interval = \"5m\"  # backoff ceiling

A proxy that started this way keeps retrying and switches to live secrets as
soon as the API answers. A *refused* resolve (401/403) never falls back.

To take the rules from the dashboard instead of this file — so adding an upstream
is a UI change rather than a redeploy — name the agent identity and pin the
signers whose bundles this deployment accepts:

    [policy]
    source = \"server\"
    agent = \"nova\"
    signers = [\"<thumbprint>\"]     # copy from the dashboard trust-anchor panel
    # refresh_interval = \"10s\"

Policy is signed in the browser with a publishing admin's own key, so the API
serves bundles it cannot forge and this proxy refuses anything not signed by a
pinned key. Server mode also re-resolves secrets on the same interval, so a new
rule and the credential it names arrive together.
";

struct Args {
    config: String,
    listen: Option<String>,
    token: Option<String>,
    api_url: Option<String>,
}

enum Parsed {
    Help,
    Version,
    Run(Args),
}

#[tokio::main]
async fn main() {
    std::process::exit(run().await);
}

/// Set telemetry up, run the proxy, then flush.
///
/// `serve` has many early-return paths (fail-closed startup); wrapping it keeps
/// the flush in one place so a new `return` can't silently drop buffered spans.
/// `std::process::exit` above runs no destructors, so the explicit shutdown is
/// what guarantees delivery.
async fn run() -> i32 {
    let telemetry = seekrit_telemetry::init("seekrit-proxy", env!("CARGO_PKG_VERSION"));
    seekrit_telemetry::install_subscriber(&telemetry, "info");

    let code = serve().await;

    telemetry.shutdown();
    code
}

async fn serve() -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(argv) {
        Ok(Parsed::Help) => {
            print!("{HELP}");
            return 0;
        }
        Ok(Parsed::Version) => {
            println!("seekrit-proxy {}", env!("CARGO_PKG_VERSION"));
            return 0;
        }
        Ok(Parsed::Run(a)) => a,
        Err(msg) => {
            eprintln!("seekrit-proxy: {msg}\n\n{HELP}");
            return 2;
        }
    };

    let mut config = match Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            error!("{e}");
            return 1;
        }
    };
    if let Some(listen) = args.listen {
        match listen.parse() {
            Ok(addr) => config.listen = addr,
            Err(e) => {
                error!("invalid --listen address: {e}");
                return 1;
            }
        }
    }

    // Credentials come from flags/env, never the (committable) config file.
    let token = match args.token.or_else(|| env_nonempty("SEEKRIT_TOKEN")) {
        Some(t) => t,
        None => {
            error!("no service token — pass --token skt_… or set SEEKRIT_TOKEN");
            return 2;
        }
    };
    let api_url = args
        .api_url
        .or_else(|| env_nonempty("SEEKRIT_API_URL"))
        .unwrap_or_else(|| DEFAULT_API_URL.to_string());

    let client = match reqwest::Client::builder()
        .user_agent(concat!("seekrit-proxy/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!("could not build HTTP client: {e}");
            return 1;
        }
    };

    // The last-known-good cache, when `[cache] enabled = true`. Opening it can
    // only fail on a directory we cannot determine, which is a warning: the
    // live resolve below may well succeed and make the cache moot.
    let lkg = config
        .cache
        .as_ref()
        .and_then(|c| match open_cache(c, &api_url, &token) {
            Ok(handle) => Some(handle),
            Err(e) => {
                warn!("cache disabled: {e}");
                None
            }
        });

    // Fail-closed: resolve + decrypt up front. No secrets → nothing to inject.
    let (store, degraded) = match resolve_live(&client, &api_url, &token, lkg.as_ref()).await {
        Ok(store) => (store, false),
        Err(e) => match cached_store(lkg.as_ref(), &e, &token) {
            Some(store) => (store, true),
            None => {
                error!("{e}");
                return 1;
            }
        },
    };
    if store.is_empty() {
        info!("no secrets resolved for this token — requests pass through unchanged");
    }

    let store = Arc::new(ArcSwap::from_pointee(store));
    let config = Arc::new(config);
    // One set of instruments shared by both planes, so a deployment running the
    // reverse and forward proxies together aggregates cleanly under `plane`.
    let metrics = Arc::new(seekrit_proxy::telemetry::Metrics::new());

    // Started on cached secrets: chase the live ones. The proxy normally
    // resolves once and never again, so without this it would serve the cached
    // payload for its whole lifetime — long after the API came back.
    if degraded {
        if let (Some(lkg), Some(cache_config)) = (lkg, config.cache.as_ref()) {
            tokio::spawn(reconnect(
                store.clone(),
                client.clone(),
                api_url.clone(),
                token.clone(),
                lkg,
                cache_config.reconnect_interval,
                cache_config.reconnect_max_interval,
            ));
        }
    }

    // One ctrl-c fans out to every listener via a watch flag.
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutting down");
        let _ = tx.send(true);
    });

    // Server policy: fetch + verify every configured agent's bundle before
    // serving. Fail-closed like the resolve above — a proxy with no policy
    // permits nothing, so refusing to start says so where it will be seen.
    let policy_cache = if config.policy.is_server() {
        config
            .cache
            .as_ref()
            .and_then(|c| match open_policy_cache(c, &api_url, &token) {
                Ok(handle) => Some(Arc::new(handle)),
                Err(e) => {
                    warn!("policy cache disabled: {e}");
                    None
                }
            })
    } else {
        None
    };
    let policy_store = if config.policy.is_server() {
        match policy::load_all(&client, &api_url, &token, &config, policy_cache.as_deref()).await {
            Ok((store, etags)) => {
                let store = Arc::new(store);
                if let Some(window) = policy::soonest_expiry(&store, policy::now_secs()) {
                    info!(
                        "policy in force expires in {} — the proxy fails closed after that unless it is republished",
                        seekrit_cache::humanize(window)
                    );
                }
                tokio::spawn(
                    policy::Refresher {
                        store: store.clone(),
                        client: client.clone(),
                        api_url: api_url.clone(),
                        token: token.clone(),
                        config: config.clone(),
                        cache: policy_cache.clone(),
                        etags,
                    }
                    .run(rx.clone()),
                );
                Some(store)
            }
            Err(e) => {
                error!("{e}");
                return 1;
            }
        }
    } else {
        None
    };

    // Periodic re-resolve. Without it a credential added in the dashboard would
    // never reach a healthy running proxy, and a rule that names it would refuse
    // every request as `unknown_secret`.
    if let Some(interval) = config.secrets.refresh_interval {
        info!(
            "re-resolving secrets every {}",
            seekrit_cache::humanize(interval)
        );
        tokio::spawn(refresh_secrets(
            store.clone(),
            client.clone(),
            api_url.clone(),
            token.clone(),
            interval,
            rx.clone(),
        ));
    }

    // Session tickets, when a control listener is configured.
    let tickets = match config.control.as_ref() {
        Some(control) => {
            let Some(control_token) = env_nonempty(CONTROL_TOKEN_ENV) else {
                error!(
                    "[control] is configured but {CONTROL_TOKEN_ENV} is not set — without it any \
                     local process could mint itself a session ticket, which is exactly what the \
                     tickets exist to prevent"
                );
                return 2;
            };
            // In file mode there are no server-side identities, so a ticket can
            // only narrow scopes; name that single subject explicitly rather than
            // inventing agent identities the config never declared.
            let agents = if config.policy.is_server() {
                config.policy.agents.clone()
            } else {
                vec![DEFAULT_FILE_AGENT.to_string()]
            };
            let tickets = Arc::new(TicketStore::new(agents, control.ttl, control.max_ttl));
            let listener = match tokio::net::TcpListener::bind(control.listen).await {
                Ok(l) => l,
                Err(e) => {
                    error!("could not bind control listener {}: {e}", control.listen);
                    return 1;
                }
            };
            info!(listen = %control.listen, "control listener ready (POST /session to mint a ticket)");
            let state = ControlState {
                tickets: tickets.clone(),
                token: Arc::new(control_token),
            };
            let sd = shutdown(rx.clone());
            tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, control_router(state))
                    .with_graceful_shutdown(sd)
                    .await
                {
                    error!("control server error: {e}");
                }
            });
            Some(tickets)
        }
        None => None,
    };

    // Dispatched tasks, when `[tasks]` opts in. Off by default: honouring one
    // makes authorizing a *new run* depend on reaching the API, which is a
    // different availability posture from policy (where a cached bundle stands
    // in) and should be chosen rather than inherited.
    let task_client = config.tasks.as_ref().map(|t| {
        // In file mode there is one local rule set and no per-agent policy to
        // select, so a task's identity cannot widen anything and the list stays
        // empty. In server mode it is the local allowlist of identities.
        let known = if config.policy.is_server() {
            config.policy.agents.clone()
        } else {
            Vec::new()
        };
        info!(
            cache_ttl = %seekrit_cache::humanize(t.cache_ttl),
            "honouring tasks dispatched through the API (skd_… in the ticket header)"
        );
        TaskClient::new(
            client.clone(),
            api_url.clone(),
            token.clone(),
            known,
            t.cache_ttl,
        )
    });
    let sessions = Arc::new(SessionResolver::new(tickets.clone(), task_client));

    // The trust ratchet, when configured. One store shared by both planes: a run
    // that narrows on the forward plane must stay narrowed on the reverse one.
    let ratchet = config.ratchet.clone().map(|cfg| {
        info!(
            states = ?cfg.state_names(),
            transitions = cfg.transitions.len(),
            "trust ratchet armed — capability narrows as a run proceeds and does not return"
        );
        Arc::new(RatchetStore::new(cfg))
    });

    // Activity reporting, when `[activity]` opts in. One ledger shared by both
    // planes and one flush task, so a review sees a proxy's whole traffic rather
    // than whichever plane happened to serve it.
    let activity = config.activity.as_ref().map(|a| {
        info!(
            flush_interval = %seekrit_cache::humanize(a.flush_interval),
            max_cells = a.max_cells,
            "reporting aggregate decisions for policy review (hosts, methods, secret names, counts — never paths)"
        );
        Arc::new(ActivityLog::new(a.max_cells))
    });

    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    if let (Some(log), Some(cfg)) = (activity.clone(), config.activity.as_ref()) {
        // Reported under the default identity: a proxy fronting several agents
        // does not yet split its ledger per identity (see the guide's caveat).
        let agent = policy_store
            .as_ref()
            .map(|p| p.default_agent().to_string())
            .unwrap_or_else(|| DEFAULT_FILE_AGENT.to_string());
        let version = policy_store
            .as_ref()
            .and_then(|p| p.snapshot(None))
            .map(|s| s.version);
        tasks.push(tokio::spawn(seekrit_proxy::activity::flush_loop(
            log,
            client.clone(),
            api_url.clone(),
            token.clone(),
            agent,
            cfg.flush_interval,
            version,
            rx.clone(),
        )));
    }

    // Reverse proxy — runs when routes are configured.
    if !config.routes.is_empty() {
        let listener = match tokio::net::TcpListener::bind(config.listen).await {
            Ok(l) => l,
            Err(e) => {
                error!("could not bind reverse listener {}: {e}", config.listen);
                return 1;
            }
        };
        info!(secrets = store.load().len(), routes = config.routes.len(), listen = %config.listen, "reverse proxy listening");
        let state = AppState {
            config: config.clone(),
            store: store.clone(),
            client: client.clone(),
            metrics: metrics.clone(),
            policy: policy_store.clone(),
            sessions: sessions.clone(),
            ratchet: ratchet.clone(),
            activity: activity.clone(),
        };
        let sd = shutdown(rx.clone());
        tasks.push(tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router(state))
                .with_graceful_shutdown(sd)
                .await
            {
                error!("reverse server error: {e}");
            }
        }));
    }

    // Forward + MITM proxy — runs when [forward] is configured.
    if let Some(fc) = config.forward.as_ref() {
        let ca = match Ca::load_or_generate(&fc.ca_cert_path, &fc.ca_key_path) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                error!("{e}");
                return 1;
            }
        };
        let listener = match tokio::net::TcpListener::bind(fc.listen).await {
            Ok(l) => l,
            Err(e) => {
                error!("could not bind forward listener {}: {e}", fc.listen);
                return 1;
            }
        };
        let ruled_hosts = match (fc.rules.as_ref(), policy_store.as_ref()) {
            (Some(rules), _) => rules.hosts().len(),
            (None, Some(policy)) => policy
                .snapshot(None)
                .map(|s| s.rules.hosts().len())
                .unwrap_or(0),
            (None, None) => 0,
        };
        info!(secrets = store.load().len(), hosts = ruled_hosts, listen = %fc.listen, "forward proxy (MITM) listening");
        info!(
            "trust the CA at {} in the workload, then set HTTPS_PROXY=http://{}",
            fc.ca_cert_path, fc.listen
        );
        let fstate = ForwardState {
            config: config.clone(),
            store: store.clone(),
            client: client.clone(),
            ca,
            metrics: metrics.clone(),
            policy: policy_store.clone(),
            sessions: sessions.clone(),
            ratchet: ratchet.clone(),
            activity: activity.clone(),
        };
        let sd = shutdown(rx.clone());
        tasks.push(tokio::spawn(async move {
            forward::serve(listener, fstate, sd).await
        }));
    }

    for t in tasks {
        let _ = t.await;
    }
    0
}

/// An opened last-known-good cache, bound to this proxy's exact resolve request.
struct Lkg {
    cache: Cache,
    key: CacheKey,
}

/// Open the cache described by `[cache]`. The proxy resolves the plain bound
/// environment — no branch, no `--with` overrides — so the key is just the API
/// URL and the token.
fn open_cache(
    config: &CacheConfig,
    api_url: &str,
    token: &str,
) -> Result<Lkg, seekrit_cache::CacheError> {
    let cache = Cache::with_optional_dir(config.dir.clone(), config.max_age)?;
    Ok(Lkg {
        key: CacheKey::new(api_url, token, None, &[]),
        cache,
    })
}

/// The same cache directory, for policy bundles.
///
/// Policy gets last-known-good on exactly the terms secrets already do: a
/// deployment that opted into surviving a seekrit outage should not be stopped by
/// one for authorization either. A cached bundle is trusted no more than a
/// fetched one — both are verified against the locally pinned signers.
fn open_policy_cache(
    config: &CacheConfig,
    api_url: &str,
    token: &str,
) -> Result<PolicyCache, seekrit_cache::CacheError> {
    let cache = Cache::with_optional_dir(config.dir.clone(), config.max_age)?;
    Ok(PolicyCache::new(
        cache,
        api_url.to_string(),
        token.to_string(),
    ))
}

/// Resolve live and decrypt, refreshing the cached copy on success. A response
/// that will not decrypt is *not* cached — storing a payload we already know is
/// unusable would only guarantee a broken fallback later.
async fn resolve_live(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    lkg: Option<&Lkg>,
) -> Result<SecretStore, ResolveFailure> {
    let body = resolve::fetch_body(client, api_url, token).await?;
    let store = secrets::decode(&body, token)
        // A decrypt failure is the API answering with something we cannot use;
        // the cache must not paper over it.
        .map_err(|e| ResolveFailure::Refused(e.to_string()))?;
    if let Some(lkg) = lkg {
        if let Err(e) = lkg.cache.write(&lkg.key, &body) {
            warn!("could not update the cache: {e}");
        }
    }
    Ok(store)
}

/// The cached store to start from, if the cache may stand in for `err`.
///
/// A *refused* resolve (401/403/…) drops the entry instead: the API has
/// withdrawn this token's access, and a proxy that kept injecting the cached
/// secrets would be handing out exactly what was just revoked.
fn cached_store(lkg: Option<&Lkg>, err: &ResolveFailure, token: &str) -> Option<SecretStore> {
    let lkg = lkg?;
    if !err.may_fall_back() {
        lkg.cache.invalidate(&lkg.key);
        return None;
    }
    match lkg.cache.read(&lkg.key) {
        Lookup::Hit(entry) => match secrets::decode(&entry.body, token) {
            Ok(store) => {
                warn!(
                    "{err} — starting on cached secrets fetched {} ago; will retry for live ones",
                    seekrit_cache::humanize(entry.age)
                );
                Some(store)
            }
            Err(e) => {
                warn!("cached secrets could not be decrypted: {e}");
                None
            }
        },
        Lookup::Missing => None,
        Lookup::Expired { age } => {
            warn!(
                "cached secrets are {} old, past the configured max_age",
                seekrit_cache::humanize(age)
            );
            None
        }
        Lookup::Unusable(why) => {
            warn!("ignoring the cached secrets: {why}");
            None
        }
    }
}

/// Retry the live resolve until it lands, then swap the snapshot in place.
///
/// Runs only after a degraded start. Backoff doubles from `interval` to `max`
/// so a brief blip is corrected in seconds while a long outage settles into a
/// poll instead of a hot loop. Ends as soon as it succeeds — the proxy is back
/// to its normal "resolve once" lifetime, now on live secrets.
async fn reconnect(
    store: Arc<ArcSwap<SecretStore>>,
    client: reqwest::Client,
    api_url: String,
    token: String,
    lkg: Lkg,
    interval: Duration,
    max_interval: Duration,
) {
    let mut delay = interval;
    loop {
        tokio::time::sleep(delay).await;
        match resolve_live(&client, &api_url, &token, Some(&lkg)).await {
            Ok(fresh) => {
                info!(
                    secrets = fresh.len(),
                    "reconnected to the seekrit API — now serving live secrets"
                );
                store.store(Arc::new(fresh));
                return;
            }
            Err(e) if !e.may_fall_back() => {
                // The API is reachable and says no. Stop retrying and drop the
                // entry; the operator has revoked or re-scoped this token, and
                // the proxy is now knowingly serving withdrawn secrets.
                lkg.cache.invalidate(&lkg.key);
                error!("the seekrit API refused this token ({e}) — still serving the secrets cached before that, which are no longer authorized; restart the proxy with a valid token");
                return;
            }
            Err(e) => {
                warn!(
                    "still degraded ({e}); retrying in {}",
                    seekrit_cache::humanize(delay)
                );
                delay = (delay * 2).min(max_interval);
            }
        }
    }
}

/// Re-resolve secrets on an interval and swap the snapshot in place.
///
/// Distinct from [`reconnect`], which exists to climb out of a degraded start and
/// then stops. This one runs for the proxy's whole life, because the thing it
/// serves is different: a *new* secret appearing in an environment this token
/// already has a grant for. No new grant is involved — the DEK the proxy already
/// holds decrypts it.
///
/// Failures are warnings, not exits: the secrets already in memory are still
/// valid, and a proxy that killed itself over a blip would take a workload with
/// it. A resolve the API *refuses* is louder, because it usually means the token
/// was revoked — but the proxy keeps serving rather than dropping traffic, and
/// says plainly that it is now serving withdrawn secrets.
async fn refresh_secrets(
    store: Arc<ArcSwap<SecretStore>>,
    client: reqwest::Client,
    api_url: String,
    token: String,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.wait_for(|stop| *stop) => return,
        }
        match resolve_live(&client, &api_url, &token, None).await {
            Ok(fresh) => {
                let before = store.load().len();
                let after = fresh.len();
                store.store(Arc::new(fresh));
                if before != after {
                    info!(secrets = after, "re-resolved: the secret set changed");
                }
            }
            Err(e) if !e.may_fall_back() => {
                error!("the seekrit API refused this token on re-resolve ({e}) — still serving the secrets already in memory, which may no longer be authorized");
            }
            Err(e) => warn!("could not re-resolve secrets ({e}); keeping the current set"),
        }
    }
}

/// The subject a file-mode session ticket narrows. File policy has no server-side
/// agent identities, so there is exactly one.
const DEFAULT_FILE_AGENT: &str = "default";

/// A shutdown future that resolves when the watch flag flips to `true`.
async fn shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    let _ = rx.wait_for(|flip| *flip).await;
}

fn parse_args(argv: Vec<String>) -> Result<Parsed, String> {
    let mut args = Args {
        config: "seekrit-proxy.toml".to_string(),
        listen: None,
        token: None,
        api_url: None,
    };
    let mut it = argv.into_iter();
    while let Some(arg) = it.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_string(), Some(v.to_string())),
            _ => (arg, None),
        };
        match name.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),
            "-c" | "--config" => args.config = take(&name, inline, &mut it)?,
            "--listen" => args.listen = Some(take(&name, inline, &mut it)?),
            "-t" | "--token" => args.token = Some(take(&name, inline, &mut it)?),
            "--api-url" => args.api_url = Some(take(&name, inline, &mut it)?),
            other => return Err(format!("unknown option: {other}")),
        }
    }
    Ok(Parsed::Run(args))
}

fn take<I: Iterator<Item = String>>(
    flag: &str,
    inline: Option<String>,
    it: &mut I,
) -> Result<String, String> {
    if let Some(v) = inline {
        return Ok(v);
    }
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch cache directory that cleans itself up.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(label: &str) -> TempDir {
            let dir = std::env::temp_dir().join(format!(
                "seekrit-proxy-cache-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            TempDir(dir)
        }

        fn lkg(&self) -> Lkg {
            self.lkg_with_max_age(seekrit_cache::DEFAULT_MAX_AGE)
        }

        fn lkg_with_max_age(&self, max_age: Duration) -> Lkg {
            Lkg {
                cache: Cache::new(self.0.clone(), max_age),
                key: CacheKey::new("https://api.seekrit.dev", TOKEN, None, &[]),
            }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const TOKEN: &str = "skt_test_token";

    #[test]
    fn a_refused_resolve_drops_the_entry_and_does_not_fall_back() {
        let dir = TempDir::new("refused");
        let lkg = dir.lkg();
        lkg.cache.write(&lkg.key, r#"{"layers":[]}"#).unwrap();

        let err = ResolveFailure::Refused("HTTP 403".into());
        assert!(cached_store(Some(&lkg), &err, TOKEN).is_none());
        assert!(
            matches!(lkg.cache.read(&lkg.key), Lookup::Missing),
            "a revoked token's cached secrets must not survive the refusal"
        );
    }

    #[test]
    fn an_unreachable_api_with_no_entry_still_fails_closed() {
        let dir = TempDir::new("empty");
        let err = ResolveFailure::Unavailable("connection refused".into());
        assert!(cached_store(Some(&dir.lkg()), &err, TOKEN).is_none());
        // And with no cache configured at all.
        assert!(cached_store(None, &err, TOKEN).is_none());
    }

    #[test]
    fn an_expired_entry_is_not_served() {
        let dir = TempDir::new("expired");
        let lkg = dir.lkg();
        lkg.cache.write(&lkg.key, r#"{"layers":[]}"#).unwrap();

        let strict = dir.lkg_with_max_age(Duration::from_secs(0));
        let err = ResolveFailure::Unavailable("timeout".into());
        assert!(cached_store(Some(&strict), &err, TOKEN).is_none());
    }

    #[test]
    fn an_undecryptable_entry_fails_closed_rather_than_starting_empty() {
        let dir = TempDir::new("garbage");
        let lkg = dir.lkg();
        // Well-formed envelope, but a body this token cannot decrypt.
        lkg.cache
            .write(&lkg.key, "{\"not\":\"a resolve response\"}")
            .unwrap();

        let err = ResolveFailure::Unavailable("timeout".into());
        assert!(
            cached_store(Some(&lkg), &err, TOKEN).is_none(),
            "a proxy must never start on secrets it could not actually decrypt"
        );
    }

    #[test]
    fn only_unavailability_may_fall_back() {
        assert!(ResolveFailure::Unavailable("dns".into()).may_fall_back());
        assert!(!ResolveFailure::Refused("HTTP 401".into()).may_fall_back());
    }
}
