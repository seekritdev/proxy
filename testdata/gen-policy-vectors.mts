/**
 * Emit cross-implementation vectors for agent access policy, using the REAL
 * `@seekrit/core` signer and evaluator. The Rust half
 * (`crates/seekrit-core/src/policy.rs`, exercised by `tests/policy_vectors.rs`)
 * must agree with every one of them: it has to verify the same envelopes,
 * refuse the same forgeries, and reach the same decision — including *which*
 * rule decided — for the same request.
 *
 * Regenerate (from the repo root, node 24 strips the types itself) with:
 *   node apps/proxy/testdata/gen-policy-vectors.mts > apps/proxy/testdata/policy-vectors.json
 *
 * Inputs are fixed (a hardcoded key, fixed ids and timestamps) so the
 * `canonical_body` strings — the part that pins canonicalization — are stable
 * across runs. The `envelope` signatures are **not**: ECDSA is randomized, so
 * every regeneration produces different signature bytes for the same body. That
 * is expected; what matters is that each envelope still verifies.
 */
// Import the sources directly by path so this runs without workspace module
// resolution (tsx strips types and resolves the extensionless graph).
import {
  type AgentPolicyDraft,
  type AgentPolicyRule,
  canonicalizeAgentPolicy,
  evaluatePolicy,
  POLICY_BUNDLE_VERSION,
  policySignerThumbprint,
  signAgentPolicy,
} from "../../../packages/core/src/agent-policy.ts";

/** A fixed, test-only P-256 keypair, so the vectors name a stable thumbprint. */
const PRIVATE_JWK = await freshKeyOr("SEEKRIT_POLICY_VECTOR_KEY");
/** A second key, used only to produce a bundle signed by an unpinned signer. */
const OTHER_JWK = await freshKeyOr("SEEKRIT_POLICY_VECTOR_KEY_OTHER");

/**
 * Read a fixed JWK from the environment, or mint one.
 *
 * The committed vectors were generated with minted keys and carry the public
 * halves; regenerating produces new ones, which is harmless — nothing pins the
 * key itself, only that the Rust verifier accepts what this signer produced and
 * refuses what it did not.
 */
async function freshKeyOr(envVar: string): Promise<Record<string, string>> {
  const provided = process.env[envVar];
  if (provided) return JSON.parse(provided) as Record<string, string>;
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  return (await crypto.subtle.exportKey("jwk", pair.privateKey)) as Record<string, string>;
}

async function loadSigner(jwk: Record<string, string>) {
  const { kty, crv, d, x, y } = jwk;
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    { kty, crv, d, x, y } as JsonWebKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const publicJwk = { kty: "EC", crv: "P-256", x: x as string, y: y as string } as const;
  return { privateKey, jwk: publicJwk, kid: await policySignerThumbprint(publicJwk) };
}

function rule(partial: Partial<AgentPolicyRule> & { host: string }): AgentPolicyRule {
  return { methods: [], paths: [], allow: [], ...partial };
}

/**
 * The rule set the decision vectors run against. It deliberately covers the
 * cases where two implementations could plausibly disagree: two rules on one
 * host (order matters), a narrow method+path rule, `*` inside a segment, `**`
 * across segments, a rule that allows an operation but no secret, and a host
 * whose name needs lowercasing.
 */
const RULES: AgentPolicyRule[] = [
  rule({
    host: "api.openai.com",
    methods: ["POST"],
    paths: ["/v1/chat/completions", "/v1/embeddings"],
    allow: ["OPENAI_API_KEY"],
    label: "chat + embeddings",
  }),
  rule({ host: "api.openai.com", methods: ["GET"], paths: ["/v1/models", "/v1/models/*"] }),
  rule({
    host: "API.GitHub.com",
    methods: ["GET", "POST"],
    paths: ["/repos/*/issues", "/repos/*/issues/**"],
    allow: ["GITHUB_TOKEN"],
  }),
  rule({ host: "hooks.slack.com", allow: ["SLACK_WEBHOOK_URL"] }),
];

const QUERIES = [
  { host: "api.openai.com", method: "POST", path: "/v1/chat/completions", secret: "OPENAI_API_KEY" },
  { host: "api.openai.com", method: "POST", path: "/v1/chat/completions?stream=true" },
  { host: "api.openai.com", method: "POST", path: "/v1/chat/completions", secret: "GITHUB_TOKEN" },
  { host: "api.openai.com", method: "GET", path: "/v1/models" },
  { host: "api.openai.com", method: "GET", path: "/v1/models/gpt-9", secret: "OPENAI_API_KEY" },
  { host: "api.openai.com", method: "DELETE", path: "/v1/models" },
  { host: "api.openai.com", method: "POST", path: "/v1/files" },
  { host: "api.github.com", method: "POST", path: "/repos/seekrit/issues", secret: "GITHUB_TOKEN" },
  {
    host: "api.github.com",
    method: "POST",
    path: "/repos/seekrit/issues/12/comments",
    secret: "GITHUB_TOKEN",
  },
  { host: "api.github.com", method: "POST", path: "/repos/a/b/issues" },
  { host: "api.github.com", method: "PATCH", path: "/repos/seekrit/issues" },
  {
    host: "hooks.slack.com",
    method: "POST",
    path: "/services/T0/B0/xyz",
    secret: "SLACK_WEBHOOK_URL",
  },
  { host: "evil.example.com", method: "POST", path: "/", secret: "OPENAI_API_KEY" },
] as const;

function draft(overrides: Partial<AgentPolicyDraft> = {}): AgentPolicyDraft {
  return {
    v: POLICY_BUNDLE_VERSION,
    org: "org_2fVectorOrg",
    agent: "agt_9cVectorAgent",
    agent_slug: "nova",
    policy_version: 7,
    issued_at: 1_786_000_000,
    expires_at: 1_786_604_800,
    rules: RULES,
    ...overrides,
  };
}

const main = await loadSigner(PRIVATE_JWK);
const other = await loadSigner(OTHER_JWK);

const primary = draft();
const primaryEnvelope = await signAgentPolicy(main.privateKey, main.jwk, primary);
const expiredEnvelope = await signAgentPolicy(
  main.privateKey,
  main.jwk,
  draft({ issued_at: 1_700_000_000, expires_at: 1_700_604_800, policy_version: 6 }),
);
const emptyEnvelope = await signAgentPolicy(
  main.privateKey,
  main.jwk,
  draft({ rules: [], policy_version: 1 }),
);
const unpinnedEnvelope = await signAgentPolicy(other.privateKey, other.jwk, draft());

/** Swap in a widened allowlist while keeping the original signature. */
function forgeWidenedAllowlist(envelope: string): string {
  const [prefix, body, sig] = envelope.split(".") as [string, string, string];
  const decoded = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  decoded.rules[0].allow.push("EXFILTRATED");
  return [prefix, Buffer.from(JSON.stringify(decoded), "utf8").toString("base64url"), sig].join(
    ".",
  );
}

/** Claim a pinned thumbprint while carrying a different key. */
function forgeSignerKid(envelope: string, kid: string): string {
  const [prefix, body, sig] = envelope.split(".") as [string, string, string];
  const decoded = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  decoded.signer.kid = kid;
  return [prefix, Buffer.from(JSON.stringify(decoded), "utf8").toString("base64url"), sig].join(
    ".",
  );
}

const vectors = {
  note:
    "Generated by apps/proxy/testdata/gen-policy-vectors.mts from @seekrit/core. " +
    "The Rust verifier + evaluator in crates/seekrit-core must agree with every entry.",
  pinned_signers: [main.kid],
  signer: { jwk: main.jwk, kid: main.kid },
  unpinned_signer: { jwk: other.jwk, kid: other.kid },
  bundles: [
    {
      label: "signed by a pinned signer",
      envelope: primaryEnvelope,
      canonical_body: canonicalizeAgentPolicy({
        ...primary,
        signer: { kid: main.kid, jwk: main.jwk },
      }),
      verifies: true,
      org: primary.org,
      agent: primary.agent,
      agent_slug: primary.agent_slug,
      policy_version: primary.policy_version,
      expires_at: primary.expires_at,
      rule_count: RULES.length,
    },
    {
      label: "expired, but correctly signed (verification passes; the context check must not)",
      envelope: expiredEnvelope,
      verifies: true,
      expired: true,
      expires_at: 1_700_604_800,
    },
    {
      label: "no rules at all — a valid deny-everything policy",
      envelope: emptyEnvelope,
      verifies: true,
      rule_count: 0,
    },
    {
      label: "signed by a key that is not pinned",
      envelope: unpinnedEnvelope,
      verifies: false,
      reject_reason: "unpinned_signer",
    },
    {
      label: "allowlist widened after signing",
      envelope: forgeWidenedAllowlist(primaryEnvelope),
      verifies: false,
      reject_reason: "bad_signature",
    },
    {
      label: "signer kid swapped to a pinned thumbprint, key left alone",
      envelope: forgeSignerKid(unpinnedEnvelope, main.kid),
      verifies: false,
      reject_reason: "kid_mismatch",
    },
    {
      label: "not an ap1 envelope",
      envelope: "xx1.eyJ2IjoxfQ.c2ln",
      verifies: false,
      reject_reason: "malformed",
    },
    {
      label: "unsigned (two segments)",
      envelope: primaryEnvelope.split(".").slice(0, 2).join("."),
      verifies: false,
      reject_reason: "malformed",
    },
  ],
  decisions: QUERIES.map((query) => {
    const verdict = evaluatePolicy(
      RULES,
      query as { host: string; method: string; path: string; secret?: string },
    );
    return { ...query, decision: verdict.decision, rule_index: verdict.ruleIndex };
  }),
};

console.log(JSON.stringify(vectors, null, 2));
