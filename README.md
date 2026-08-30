# seekrit-proxy

An egress proxy that keeps decrypted secrets **out of the workload's memory**.
Instead of injecting plaintext into a process's environment (that's
[`seekrit-run`](../run)), the proxy sits in front of a workload's outbound HTTP
and swaps `{{seekrit:NAME}}` placeholders for the real, decrypted values on the
way to the upstream. The agent only ever holds placeholders.

```
  agent ──▶  Authorization: Bearer {{seekrit:OPENAI_API_KEY}}
                    │  (localhost / sidecar)
             seekrit-proxy   ── resolves + decrypts once at startup
                    │            substitutes, checks the allowlist
                    ▼
              api.example.com   Authorization: Bearer sk-…real…
```

## Why

`seekrit-run` is right for CI and containers you trust with their own keys —
the process can read its environment. For an **untrusted or agentic** workload
you don't want the key in the process at all, because anything in the process
can exfiltrate it. The proxy moves the plaintext to a separate trust boundary:
it holds a service-token grant (it is "just another principal"), and the only
place a real credential appears is in the request to the **allowlisted**
upstream.

## How it works

1. **Startup (fail-closed).** Reads `SEEKRIT_TOKEN`, calls `GET /v1/resolve`,
   and decrypts every granted secret into memory — then expands any
   `${OTHER_SECRET}` references over the merged set, so a placeholder always
   substitutes the finished value. This is the exact zero-knowledge path
   `seekrit-run` uses, sharing the `seekrit-core` crate. If the token is bad, the
   API is unreachable, a layer won't decrypt, or the references don't resolve
   (a cycle), it refuses to start.
2. **Per request.** Matches the path to a configured route, then substitutes
   `{{seekrit:NAME}}` in the request **path, headers, and body**. Only the
   request is rewritten; the response streams back untouched (so SSE / streaming
   APIs work).
3. **Allowlist (default-deny).** Each route declares which secrets may be
   injected toward its upstream. A placeholder for a secret not on that list —
   or one that didn't resolve — is refused with `403` and never forwarded. This
   is what stops the proxy being an exfiltration oracle. A rule may also bound
   the **methods** and **paths** it permits, which makes the same check
   anti-misuse: an agent holding a legitimate credential still cannot reach an
   operation you never granted it.
4. **Audit.** Every substitution logs the secret **names**, method, path, and
   upstream host (never values) on the `seekrit_audit` target.

## Install

The proxy is a Rust binary, but nothing here requires a Rust toolchain:

| | |
| --- | --- |
| `npx -y @seekrit/proxy` | The released binary, npx-able ([`../proxy-npm`](../proxy-npm)). Fetches it for the host platform, verifies the published SHA-256, and execs it. |
| `npx -y @seekrit/cli proxy run --preset openai` | The same, plus a generated config — the shortest path from nothing to a working proxy. |
| `curl -fsSL https://proxy.seekrit.dev/install.sh \| sh` | A binary on `PATH` ([`install.sh`](install.sh)). |
| `docker run seekritdev/proxy` | Multi-arch, static musl on `scratch`. |
| `cargo build --release` | From source, here. |

Prebuilt binaries are attached to each `proxy-v*` GitHub release and mirrored to
the public R2 bucket at `proxy.seekrit.dev` — both the archives and, under
`bin/`, an unarchived binary per target so the npm launcher needs no archive
reader. See `.github/workflows/build-proxy-binaries.yml` and
`publish-proxy-r2.yml`.

## Usage

```sh
export SEEKRIT_TOKEN=skt_…
seekrit-proxy --config seekrit-proxy.toml
```

Or generate the config instead of writing it. `seekrit proxy init` emits a
commented, committable `seekrit-proxy.toml` from gateway presets or from an
agent's published policy; `seekrit proxy compose` emits a `docker compose`
sidecar. The generator lives in [`../cli/src/proxy-config.ts`](../cli/src/proxy-config.ts),
and the configs it writes are pinned by golden fixtures in
[`testdata/generated-configs/`](testdata/generated-configs) that
[`tests/generated_configs.rs`](tests/generated_configs.rs) parses with the real
`Config::from_toml` — so the generator cannot drift from this parser.

```sh
seekrit proxy init --preset openai --preset anthropic   # writes seekrit-proxy.toml
seekrit proxy init --agent nova                         # from published policy
seekrit proxy run  --preset openai                      # generate + run, writes nothing
```

Config (`seekrit-proxy.toml`; see [`seekrit-proxy.example.toml`](seekrit-proxy.example.toml)):

```toml
listen = "127.0.0.1:8080"

[[route]]
prefix = "/example"
upstream = "https://api.example.com"
allow = ["EXAMPLE_API_KEY"]
```

Point the workload's base URL at the proxy and pass the credential as a
placeholder:

```sh
# e.g. an OpenAI-compatible SDK
export OPENAI_BASE_URL=http://127.0.0.1:8080/example
export OPENAI_API_KEY='{{seekrit:EXAMPLE_API_KEY}}'
```

The token, upstream host, and secret names are all yours to choose — nothing
here is provider-specific.

### Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `-c, --config <path>` | `./seekrit-proxy.toml` | Route/allowlist config. |
| `--listen <addr>` | from config (`127.0.0.1:8080`) | Override the listen address. |
| `-t, --token <skt_…>` | `SEEKRIT_TOKEN` | Service token. |
| `--api-url <url>` | `SEEKRIT_API_URL` or `https://api.seekrit.dev` | API base URL. |

## Forward proxy + TLS interception

The reverse-proxy model above needs the workload to point its base URL at the
proxy. The **forward-proxy** model is transparent instead: the workload sets
`HTTPS_PROXY` and trusts the proxy's CA, and *every* egress flows through
without any per-SDK wiring — the right fit for agents that call many hosts.

```toml
[forward]
listen = "127.0.0.1:8081"
unmatched_host_policy = "tunnel"   # or "deny"
ca_cert = "seekrit-proxy-ca.pem"
ca_key = "seekrit-proxy-ca-key.pem"

[[forward.host]]
match = "api.example.com"
allow = ["EXAMPLE_API_KEY"]
```

For each **ruled** host the proxy answers the client's `CONNECT`, terminates TLS
with a leaf certificate it mints for that host (signed by the persisted local CA
the operator installs into the workload's trust store), reads the plaintext
request, substitutes `{{seekrit:NAME}}`, and re-originates a real TLS request to
the upstream. Hosts with **no** rule are blind-tunneled (default) or refused
(`deny`) — the proxy only intercepts traffic it has a reason to. The
substitution engine, secret store, and allowlist are shared with the reverse
proxy.

```sh
# In the workload:
export HTTPS_PROXY=http://127.0.0.1:8081
export NODE_EXTRA_CA_CERTS=$PWD/seekrit-proxy-ca.pem   # or SSL_CERT_FILE, etc.
export ANTHROPIC_API_KEY='{{seekrit:EXAMPLE_API_KEY}}'
```

Both modes can run at once (on different ports) from one config.

## Operation constraints

`methods` and `paths` are optional on `[[route]]` and `[[forward.host]]`, and
absent means *any* — so an existing config behaves exactly as it did.

```toml
[[route]]
prefix = "/openai"
upstream = "https://api.openai.com"
methods = ["POST"]
paths = ["/v1/chat/completions", "/v1/embeddings"]
allow = ["OPENAI_API_KEY"]
```

Patterns match segment-wise against the upstream-facing path (the request path
minus the route prefix): `*` within one segment, `**` across any number, so
`/v1/**` covers `/v1` and everything under it. Case-sensitive; the query string
never participates. Several rules may name one host in forward mode — they are
checked in order, first match wins, so a narrow rule belongs above a broad one.

Note the asymmetry: empty `methods`/`paths` mean **any**, empty `allow` means
**none**. A rule with no `allow` permits an operation without letting a
credential travel with it. Refusals name the constraint that decided (method,
path, or no rule at all), because a default-deny policy otherwise fails in
exactly the confusing direction.

## Rules from the dashboard (`[policy] source = "server"`)

A file is a legitimate posture — no network dependency for authorization, and a
file seekrit cannot change — and stays supported. But rules are the part that
churns, so they can also come from **agent access policy** in the dashboard:

```toml
[policy]
source = "server"                # "file" (default) keeps today's behaviour
agent = "nova"                   # the agent identity this deployment is
refresh_interval = "10s"
signers = ["kNc8…thumbprint"]    # ← the trust anchor; copy from the dashboard
```

The bundle is signed **in the publishing admin's browser** with their own P-256
key. This proxy refuses any bundle not signed by a pinned signer, so seekrit can
withhold policy (the proxy then fails closed) but cannot widen it — the property
that lets policy live in a dashboard without making the API an authority over
where plaintext goes. A server-mode proxy with no pinned signer refuses to start.

Two consequences: `allow`/`methods`/`paths` in this file are **rejected** in
server mode rather than silently ignored (and the forward proxy's intercepted
hosts come from the policy), and secrets are re-resolved on the same interval —
a new rule and the credential it names have to land together. Under file policy,
opt into re-resolve with `[secrets] refresh_interval = "30s"`.

A fleet may also state a local ceiling that server policy can only narrow
(`[[policy.ceiling]]`); a bundle exceeding it is refused wholesale rather than
silently intersected. It is off by default and inappropriate for interactive
development, where the adversary is a local agent that can edit local files
anyway.

## Session tickets (`[control]`)

When one proxy fronts several agents that should not have the same reach, an
orchestrator mints a ticket per run:

```sh
export SEEKRIT_PROXY_CONTROL_TOKEN=$(openssl rand -hex 32)   # before starting

curl -s localhost:9090/session \
  -H "x-seekrit-control-token: $SEEKRIT_PROXY_CONTROL_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"agent":"scribe","scopes":["GITHUB_TOKEN"],"ttl":"15m"}'
```

The agent presents the ticket in `x-seekrit-ticket`; the proxy strips it before
forwarding. Scopes only ever **narrow** (ticket ∩ policy), an unknown or expired
ticket is refused rather than treated as unticketed, and tickets live only in
memory — a restart drops them all. With no `[control]` block there is no
listener and requests are evaluated against `[policy] agent`, so a single-agent
sidecar needs none of this.

The control token must not be readable by the agent: without it, any local
process could mint itself a ticket for any identity.

## Dispatched runs (`[tasks]`)

A `[control]` ticket is local to one proxy. A **task** is dispatched through the
seekrit API, so one dispatch covers every enforcement point a run talks to:

```toml
[tasks]
cache_ttl = "30s"     # how long an introspected task is reused
```

```sh
TASK=$(seekrit agents dispatch nova --scope GITHUB_TOKEN --ttl 15m)
```

The run presents it in the same `x-seekrit-ticket` header; the prefix decides which
mechanism answers (`skp_` minted here, `skd_` dispatched by the API), so adopting
tasks changes nothing about existing tickets. A proxy with no `[tasks]` block
refuses an `skd_` token by name rather than treating it as an unknown ticket.

Opt-in on purpose. Unlike policy — which has a last-known-good cache — a task has
no offline fallback, because its whole meaning is *is this still live*. If the API
is unreachable, a new run is refused. `cache_ttl` is what bounds how long a revoked
run keeps working, which is why it is short and capped at 5 minutes. And the local
file still decides which identities exist: a task naming an agent outside
`[policy] agents` is refused here, not by the API.

## Reporting decisions (`[activity]`)

```toml
[activity]
flush_interval = "60s"     # one request per interval; none when nothing happened
max_cells = 500            # distinct dimension combinations held between flushes
```

Aggregate counts, so `seekrit agents review` can compare a published policy
against what the agent actually did. What crosses the boundary: hosts, methods,
secret *names*, which rule decided, and how often. **No request paths** — a path
can carry a customer identifier — and no values. Per-request detail keeps going to
your own OTLP collector.

Off unless configured. A flush that cannot reach the API drops that window rather
than queueing: a review missing an hour is cheaper than unbounded memory, and a
proxied request must never wait on it. Overflow past `max_cells` is dropped and
logged, so a truncated window does not read like a complete one.

## The trust ratchet (`[ratchet]`)

Policy has no memory, so it cannot express "this run has already read the customer
export, so it may no longer post to a webhook". The ratchet does:

```toml
[[ratchet.state]]
name = "restricted"
hosts = ["ledger.internal"]      # all that is still reachable
secrets = ["LEDGER_TOKEN"]       # all that may still be injected

[[ratchet.transition]]
host = "reports.internal"
paths = ["/exports/**"]
to = "restricted"
label = "customer export"
```

```text
seekrit-proxy: hooks.slack.com was withdrawn from this run 4s ago by "customer
export" — the trust ratchet is in state "restricted" and does not permit it.
Capability comes back in a new run, not this one.
```

- **Triggers are declared, never inferred.** No response-body classification: that
  would mean inspecting the plaintext this proxy exists to avoid handling.
- **It only turns one way.** States are ordered and advancing takes the later
  index; `to = "baseline"` is a startup error.
- **It only subtracts.** An overlay applied after policy — it can take a host or a
  secret away, never add one. That is what makes it safe from a local file.
- **State is per run, in memory.** A restart clears it. With no ticket or task
  there is one implicit session, so a narrowed sidecar stays narrowed until
  restart — a fleet control, not a developer-machine one.

The transition fires when the protected request is **authorized**, not when its
response returns: narrowing early is the safe direction, and this proxy streams
responses, so "hold the response until every enforcement point acknowledges" is not
something one process can promise for a fleet. What it does promise is that no
request authorized after the protected one sees the wider state.

## Two honest limits on a developer machine

- **The agent must not be able to read `SEEKRIT_TOKEN`.** With it, an agent can
  call `/v1/resolve` itself and skip the proxy — then policy is decoration. Run
  the proxy as a separate OS user or in a container.
- **`HTTPS_PROXY` is not enforcement.** An agent that can unset an environment
  variable is not confined by it; real confinement needs a container network
  namespace or a firewall rule that makes the proxy the only route out.

## Container image

Published to Docker Hub as `seekritdev/proxy` (multi-arch, a single static musl
binary on `scratch` — no OS, no shell). `latest` + `<version>` are cut on
release; `edge` tracks `main`.

```sh
docker run --rm -e SEEKRIT_TOKEN=skt_… \
  -v "$PWD/seekrit-proxy.toml:/seekrit-proxy.toml" \
  -p 8080:8080 seekritdev/proxy --listen 0.0.0.0:8080
```

The image reads its config from `/seekrit-proxy.toml` (override with `--config`)
and the token from `SEEKRIT_TOKEN`. For a **sidecar** sharing the workload's
network namespace, keep the default loopback bind; for a **standalone** container
pass `--listen 0.0.0.0:<port>`. In forward mode, persist the CA (mount a volume
for `ca_cert`/`ca_key`) so the cert the workload trusts survives restarts.

## Build

```sh
cargo build --release   # target/release/seekrit-proxy
cargo test              # unit + end-to-end (mock upstream) tests

# Container (the shared crates are vendored in this repo):
docker build -t seekritdev/proxy .
```

## Telemetry

Exports OpenTelemetry traces, metrics, and logs over OTLP/HTTP to **your** collector — never to
seekrit. Entirely opt-in: with no endpoint set, nothing is exported and no
exporter threads start.

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
```

The standard `OTEL_*` variables all apply (`OTEL_SERVICE_NAME`,
`OTEL_RESOURCE_ATTRIBUTES`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SDK_DISABLED`,
`OTEL_{TRACES,METRICS,LOGS}_EXPORTER=none`). OTLP/HTTP only — there is no gRPC
exporter, which keeps the `scratch` image small.

Instruments: `seekrit.proxy.requests` (by plane and outcome),
`seekrit.proxy.injections`, and `seekrit.proxy.upstream_duration`. A rising
`outcome="denied"` rate means a workload is asking for a secret — or an
operation — its policy has no claim to; that is the one to alert on. Spans also
carry the agent identity, policy version, and the index of the rule that
decided, so a refusal traces back to the line an admin published.

Trace context from inbound requests is continued. Injecting `traceparent` into
*upstream* requests is off by default (`propagate_trace_upstream = true` to
enable): the upstreams here are usually third-party APIs that gain nothing from
your trace ids.

Spans and metrics record secret **names**, counts, and outcomes — **never**
values, tokens, or credentials. `tests/telemetry.rs` enforces this by driving a
real request with a sentinel value and failing if it reaches a span.

Build with `--no-default-features` to compile telemetry out entirely
(+538 KiB in this binary).

Full guide: <https://seekrit.dev/docs/guides/telemetry>
