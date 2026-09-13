//! Scrubbing an injected credential back out of the upstream's *response*.
//!
//! The proxy exists so a workload never holds a credential. Substitution gets it
//! there on the way out — but the upstream can hand it straight back:
//!
//! - Stripe's error payload is `Invalid API Key provided: sk_live_…`, verbatim.
//! - An OAuth handler echoes the bearer token into a `Location:` redirect.
//! - Any SDK's verbose 4xx quotes the request it just made, headers included.
//!
//! Every one of those lands in the agent's context window, which is the exact
//! place this architecture spends its whole budget keeping credentials out of.
//! Substitution without redaction closes the front door and leaves the back one
//! open.
//!
//! Four decisions shape this module.
//!
//! **1. Only what we injected.** The needles are the values this proxy
//! substituted into *this* request, not everything in the store. A response
//! carrying a credential the request never sent is the upstream's own business;
//! one carrying the value we just added is ours. It also means the cost is
//! proportional to a request's own injections — usually one — and that a request
//! with no placeholder is byte-for-byte untouched, taking the same path it took
//! before this module existed. `scan = "all"` opts into the broader sweep for
//! deployments that want it (see [`Scan`]).
//!
//! **2. Streaming is preserved.** Buffering the response to scan it would break
//! every SSE and streaming-completion API the proxy fronts, which is most of
//! them. So the scanner is incremental, and it holds back only the bytes that
//! could still turn out to be the *start* of a needle — for ordinary text that
//! is nothing at all, so a token stream flows through with no added latency. A
//! simpler scanner that always kept the last `max_needle_len - 1` bytes would
//! strand the tail of an idle SSE stream until the next event; see [`Scanner`].
//!
//! **3. Encodings, because the echo is rarely verbatim.** A value that went out
//! in a header can come back percent-encoded in a redirect or backslash-escaped
//! inside a JSON string, and a byte-for-byte comparison would miss both.
//!
//! **4. No masked-prefix matching.** Other implementations also hunt for
//! `sk_live_51ABC****`. We deliberately do not: a masked echo is not a usable
//! credential, matching it needs a heuristic (how many characters of prefix? how
//! many mask glyphs?), and a heuristic that rewrites response bodies will
//! eventually corrupt a legitimate one. The value of catching it is cosmetic;
//! the cost of a false positive is a mangled payload nobody can explain.
//!
//! Values live here as [`Zeroizing`] buffers for the life of one response, on
//! the same terms as [`crate::secrets::SecretStore`], and — like everything else
//! in this proxy — what gets logged is the secret's *name*.

use std::collections::BTreeSet;

use zeroize::Zeroizing;

/// What replaces a matched value. Fixed text, not a length-preserving mask: both
/// planes already drop the upstream's `Content-Length` and let hyper re-frame the
/// response, so there is nothing to keep in step — and a reader who sees this
/// string learns that the proxy acted, rather than that the field was empty.
pub const DEFAULT_PLACEHOLDER: &str = "[redacted by seekrit]";

/// Values shorter than this are never scanned for.
///
/// A secret whose value is `8080` or `true` would otherwise match constantly and
/// shred unrelated responses. Eight bytes is comfortably below any real
/// credential and comfortably above the values that cause that — and a secret
/// short enough to be skipped is one whose disclosure through an echo is not the
/// interesting risk anyway. The skip is reported, never silent.
pub const DEFAULT_MIN_LENGTH: usize = 8;

/// Which values a response is scanned for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scan {
    /// Only the values substituted into this request. The default: it is what
    /// the proxy is responsible for having put in flight, and it costs nothing
    /// on a request that injected nothing.
    #[default]
    Injected,
    /// Every resolved secret, whether or not this request used it. For an
    /// upstream that can return *other* credentials (a provider's own key-listing
    /// endpoint, say) — strictly stronger, and proportionally more scanning.
    All,
}

impl Scan {
    pub fn as_str(self) -> &'static str {
        match self {
            Scan::Injected => "injected",
            Scan::All => "all",
        }
    }
}

/// The validated `[redaction]` block.
#[derive(Debug, Clone)]
pub struct RedactionConfig {
    pub scan: Scan,
    pub placeholder: String,
    pub min_length: usize,
    /// Also match the percent-encoded form (both hex cases).
    pub percent: bool,
    /// Also match the JSON-string-escaped form.
    pub json: bool,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        RedactionConfig {
            scan: Scan::default(),
            placeholder: DEFAULT_PLACEHOLDER.to_string(),
            min_length: DEFAULT_MIN_LENGTH,
            percent: true,
            json: true,
        }
    }
}

/// One response's worth of needles, plus the names a caller audits from.
///
/// Built per request (cheap: a handful of short byte strings) and dropped with
/// the response, so no plaintext outlives the exchange it belonged to.
pub struct Redactor {
    needles: Vec<Zeroizing<Vec<u8>>>,
    /// `true` at index `b` when some needle starts with byte `b`. This is what
    /// keeps the scanner's inner loop to one array lookup per ordinary byte.
    first_byte: [bool; 256],
    placeholder: Vec<u8>,
    /// Names whose values are in `needles`, for the audit line when one hits.
    names: Vec<String>,
}

impl Redactor {
    /// Build a redactor for the values behind `names`, looked up in the store.
    ///
    /// Returns `None` when there is nothing to scan for — no names, or every
    /// value too short to be safe to match. `None` is the fast path: the caller
    /// streams the response through untouched, exactly as it did before this
    /// module existed.
    pub fn new<'a, I, F>(names: I, lookup: F, config: &RedactionConfig) -> Option<Redactor>
    where
        I: IntoIterator<Item = &'a str>,
        F: Fn(&str) -> Option<&'a str>,
    {
        let mut needles: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut matched_names = Vec::new();

        for name in names {
            let Some(value) = lookup(name) else { continue };
            if value.len() < config.min_length {
                continue;
            }
            let mut any = false;
            for form in forms(value, config) {
                if seen.insert(form.clone()) {
                    needles.push(Zeroizing::new(form));
                    any = true;
                }
            }
            if any {
                matched_names.push(name.to_string());
            }
        }

        if needles.is_empty() {
            return None;
        }

        let mut first_byte = [false; 256];
        for n in &needles {
            first_byte[n[0] as usize] = true;
        }

        Some(Redactor {
            needles,
            first_byte,
            placeholder: config.placeholder.as_bytes().to_vec(),
            names: matched_names,
        })
    }

    /// The secret names this redactor is watching for — for the audit line.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// A fresh incremental scanner over this redactor's needles.
    pub fn scanner(&self) -> Scanner<'_> {
        Scanner {
            redactor: self,
            carry: Vec::new(),
            hits: 0,
        }
    }

    /// Scrub a complete buffer in one pass — response headers, which are not
    /// streamed. Returns `None` when nothing matched, so a caller can leave the
    /// original value in place rather than rebuild it.
    pub fn redact_all(&self, input: &[u8]) -> Option<(Vec<u8>, usize)> {
        let mut scanner = self.scanner();
        let mut out = scanner.push(input);
        out.extend_from_slice(&scanner.finish());
        match scanner.hits {
            0 => None,
            hits => Some((out, hits)),
        }
    }

    /// Scan one chunk against `carry`, returning the bytes safe to emit now and
    /// how many values were replaced.
    ///
    /// Takes the carry by reference rather than owning it so a streaming body can
    /// hold this state in an `Arc<Redactor>` + `Vec<u8>` pair and keep the
    /// redactor itself shareable. [`Scanner`] is the borrowing convenience over
    /// the same two calls.
    pub fn push_into(&self, carry: &mut Vec<u8>, chunk: &[u8]) -> (Vec<u8>, usize) {
        // The carry is at most `max_needle_len - 1` bytes, so this stays
        // proportional to the chunk rather than to the stream.
        let buf: Vec<u8> = if carry.is_empty() {
            chunk.to_vec()
        } else {
            let mut b = std::mem::take(carry);
            b.extend_from_slice(chunk);
            b
        };

        let mut out = Vec::with_capacity(buf.len());
        let mut hits = 0;
        let mut i = 0;
        while i < buf.len() {
            if let Some(len) = self.match_at(&buf, i) {
                out.extend_from_slice(&self.placeholder);
                hits += 1;
                i += len;
                continue;
            }
            if self.partial_at(&buf, i) {
                break;
            }
            out.push(buf[i]);
            i += 1;
        }
        *carry = buf[i..].to_vec();
        (out, hits)
    }

    /// Drain `carry` at end of stream.
    ///
    /// A held prefix can no longer complete, so it is released — but a *shorter*
    /// needle may still match inside it, which [`Redactor::push_into`] could not
    /// conclude while more bytes might yet have arrived.
    pub fn finish_into(&self, carry: &mut Vec<u8>) -> (Vec<u8>, usize) {
        let buf = std::mem::take(carry);
        let mut out = Vec::with_capacity(buf.len());
        let mut hits = 0;
        let mut i = 0;
        while i < buf.len() {
            if let Some(len) = self.match_at(&buf, i) {
                out.extend_from_slice(&self.placeholder);
                hits += 1;
                i += len;
                continue;
            }
            out.push(buf[i]);
            i += 1;
        }
        (out, hits)
    }

    /// The length of the needle matching at `at`, if any. Longest match wins, so
    /// a value that is a prefix of another cannot mask it and leave a tail in the
    /// clear.
    fn match_at(&self, buf: &[u8], at: usize) -> Option<usize> {
        if !self.first_byte[buf[at] as usize] {
            return None;
        }
        self.needles
            .iter()
            .filter(|n| buf[at..].starts_with(n))
            .map(|n| n.len())
            .max()
    }

    /// Could a needle *start* at `at` and run past the end of `buf`? If so the
    /// tail has to be held until more bytes arrive — and if not, it can go out
    /// now, which is what keeps a token stream flowing.
    fn partial_at(&self, buf: &[u8], at: usize) -> bool {
        if !self.first_byte[buf[at] as usize] {
            return false;
        }
        let rest = &buf[at..];
        self.needles
            .iter()
            .any(|n| n.len() > rest.len() && n.starts_with(rest))
    }
}

/// Incremental scanner over one response body.
///
/// Feed it chunks; it returns the bytes that are safe to emit. Held-back bytes
/// are only ever a partial needle prefix, bounded by the longest needle, and
/// [`Scanner::finish`] releases whatever is left when the stream ends (a
/// truncated prefix is not a match, so it goes out verbatim).
pub struct Scanner<'a> {
    redactor: &'a Redactor,
    carry: Vec<u8>,
    hits: usize,
}

impl Scanner<'_> {
    /// Consume one chunk, returning the bytes that may be forwarded now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let (out, hits) = self.redactor.push_into(&mut self.carry, chunk);
        self.hits += hits;
        out
    }

    /// Release whatever is still held. Call once, when the upstream body ends.
    pub fn finish(&mut self) -> Vec<u8> {
        let (out, hits) = self.redactor.finish_into(&mut self.carry);
        self.hits += hits;
        out
    }

    /// How many values this scanner has replaced so far.
    pub fn hits(&self) -> usize {
        self.hits
    }
}

/// Build the redactor for one response, or `None` when there is nothing to scan
/// for.
///
/// The two data planes call this with the same arguments so a credential echo is
/// caught identically whether the workload reached the upstream through a route
/// prefix or through `HTTPS_PROXY`.
pub fn for_response(
    config: Option<&RedactionConfig>,
    injected: &std::collections::BTreeSet<String>,
    store: &crate::secrets::SecretStore,
) -> Option<std::sync::Arc<Redactor>> {
    let config = config?;
    let names: Vec<&str> = match config.scan {
        Scan::Injected => injected.iter().map(String::as_str).collect(),
        Scan::All => store.names().collect(),
    };
    Redactor::new(names, |n| store.get(n), config).map(std::sync::Arc::new)
}

/// Scrub response headers in place, returning how many values were replaced.
///
/// Headers matter as much as the body: a `Location:` redirect carrying the token
/// back as a query parameter, or a service that echoes the request's own
/// `Authorization` into a debug header, both land in the agent's context exactly
/// like a body would.
///
/// Rebuilt rather than patched in place so a multi-valued header (several
/// `Set-Cookie`s, say) keeps all of its values. A replacement that cannot be
/// expressed as a header value — only reachable through a custom `placeholder` —
/// drops the header rather than forwarding the echo.
pub fn redact_headers(redactor: &Redactor, headers: &mut axum::http::HeaderMap) -> usize {
    use axum::http::HeaderValue;

    let mut hits = 0;
    let mut changed = false;
    let mut rebuilt = axum::http::HeaderMap::with_capacity(headers.len());
    for (name, value) in headers.iter() {
        match redactor.redact_all(value.as_bytes()) {
            Some((bytes, n)) => {
                hits += n;
                changed = true;
                if let Ok(hv) = HeaderValue::from_bytes(&bytes) {
                    rebuilt.append(name.clone(), hv);
                }
            }
            None => {
                rebuilt.append(name.clone(), value.clone());
            }
        }
    }
    if changed {
        *headers = rebuilt;
    }
    hits
}

/// Wrap an upstream body stream so every chunk is scrubbed on its way out.
///
/// The redactor is shared (`Arc`) rather than borrowed because the stream
/// outlives the handler that built it: axum returns the response as soon as the
/// headers are ready and the body drains afterwards. That is also why `on_hit`
/// exists — by the time a body match happens, the request span has closed, so the
/// caller reports through a callback it captured rather than by recording a span
/// field that would go nowhere.
///
/// Errors from the upstream pass through untouched, and whatever the scanner is
/// holding at that moment is dropped with the stream: a truncated body that ends
/// mid-credential ends without it.
pub fn redacting_stream<S, E, F>(
    upstream: S,
    redactor: std::sync::Arc<Redactor>,
    on_hit: F,
) -> impl futures_util::Stream<Item = Result<bytes::Bytes, E>> + Send
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, E>> + Send + 'static,
    E: Send + 'static,
    F: Fn(usize) + Send + 'static,
{
    use futures_util::StreamExt;

    // `done` distinguishes "upstream ended, still owe the carry" from "finished".
    struct State<S> {
        upstream: S,
        carry: Vec<u8>,
        done: bool,
    }

    futures_util::stream::unfold(
        (
            State {
                upstream: Box::pin(upstream),
                carry: Vec::new(),
                done: false,
            },
            redactor,
            on_hit,
        ),
        |(mut state, redactor, on_hit)| async move {
            loop {
                if state.done {
                    return None;
                }
                match state.upstream.next().await {
                    Some(Ok(chunk)) => {
                        let (out, hits) = redactor.push_into(&mut state.carry, &chunk);
                        if hits > 0 {
                            on_hit(hits);
                        }
                        // A chunk can scrub down to nothing (it was entirely a
                        // held prefix). Emitting an empty frame is legal but
                        // pointless, so pull again instead.
                        if out.is_empty() {
                            continue;
                        }
                        return Some((Ok(bytes::Bytes::from(out)), (state, redactor, on_hit)));
                    }
                    Some(Err(e)) => {
                        state.done = true;
                        return Some((Err(e), (state, redactor, on_hit)));
                    }
                    None => {
                        state.done = true;
                        let (out, hits) = redactor.finish_into(&mut state.carry);
                        if hits > 0 {
                            on_hit(hits);
                        }
                        if out.is_empty() {
                            return None;
                        }
                        return Some((Ok(bytes::Bytes::from(out)), (state, redactor, on_hit)));
                    }
                }
            }
        },
    )
}

/// Every byte form of `value` worth searching for.
///
/// Ordered exact-first only for readability; [`Redactor::match_at`] takes the
/// longest match regardless of order.
fn forms(value: &str, config: &RedactionConfig) -> Vec<Vec<u8>> {
    let mut out = vec![value.as_bytes().to_vec()];
    if config.percent {
        let upper = percent_encode(value, true);
        if upper != value {
            out.push(upper.into_bytes());
        }
        let lower = percent_encode(value, false);
        if lower != value {
            out.push(lower.into_bytes());
        }
    }
    if config.json {
        if let Some(escaped) = json_escape(value) {
            out.push(escaped.into_bytes());
        }
    }
    out
}

/// Percent-encode everything outside the RFC 3986 unreserved set.
///
/// Hand-rolled rather than pulled from a crate because this proxy's dependency
/// list is deliberately short, and because *both* hex cases are needed: encoders
/// in the wild emit each, and a case-sensitive miss is a leaked credential.
fn percent_encode(value: &str, upper: bool) -> String {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let hex = if upper { HEX_UPPER } else { HEX_LOWER };
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex[(b >> 4) as usize] as char);
            out.push(hex[(b & 0x0f) as usize] as char);
        }
    }
    out
}

/// The value as it would appear *inside* a JSON string literal, or `None` when
/// JSON would not change it (the common case — no point scanning for it twice).
fn json_escape(value: &str) -> Option<String> {
    let encoded = serde_json::to_string(value).ok()?;
    // `to_string` on a `&str` always yields a quoted literal.
    let inner = encoded
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))?
        .to_string();
    (inner != value).then_some(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALUE: &str = "sk-live-abc123def456";

    fn redactor_for(values: &[(&str, &str)]) -> Redactor {
        let owned: Vec<(String, String)> = values
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        // Leaked so the borrows outlive the call, which keeps the test helper's
        // signature the same shape as the real per-request lookup.
        let owned: &'static [(String, String)] = Box::leak(owned.into_boxed_slice());
        let names: Vec<&str> = owned.iter().map(|(k, _)| k.as_str()).collect();
        Redactor::new(
            names,
            |n| owned.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str()),
            &RedactionConfig::default(),
        )
        .expect("a redactor")
    }

    fn scrub(r: &Redactor, chunks: &[&str]) -> (String, usize) {
        let mut s = r.scanner();
        let mut out = Vec::new();
        for c in chunks {
            out.extend_from_slice(&s.push(c.as_bytes()));
        }
        out.extend_from_slice(&s.finish());
        (String::from_utf8(out).unwrap(), s.hits())
    }

    #[test]
    fn replaces_an_exact_echo() {
        let r = redactor_for(&[("K", VALUE)]);
        let (out, hits) = scrub(&r, &[&format!("Invalid API Key provided: {VALUE}")]);
        assert_eq!(
            out,
            format!("Invalid API Key provided: {DEFAULT_PLACEHOLDER}")
        );
        assert_eq!(hits, 1);
        assert!(!out.contains(VALUE));
    }

    #[test]
    fn passes_ordinary_bytes_through_unchanged() {
        let r = redactor_for(&[("K", VALUE)]);
        let (out, hits) = scrub(&r, &["nothing sensitive here at all"]);
        assert_eq!(out, "nothing sensitive here at all");
        assert_eq!(hits, 0);
    }

    #[test]
    fn catches_a_value_split_across_chunks() {
        // The motivating case: a streamed body that happens to break mid-secret.
        let r = redactor_for(&[("K", VALUE)]);
        let (a, b) = VALUE.split_at(7);
        let (out, hits) = scrub(&r, &["before ", a, b, " after"]);
        assert_eq!(out, format!("before {DEFAULT_PLACEHOLDER} after"));
        assert_eq!(hits, 1);
    }

    #[test]
    fn does_not_hold_back_bytes_that_cannot_start_a_needle() {
        // The SSE property: a chunk with no possible prefix is emitted whole, so
        // a stream that then goes idle is not left with a withheld tail.
        let r = redactor_for(&[("K", VALUE)]);
        let mut s = r.scanner();
        let out = s.push(b"data: hello world\n\n");
        assert_eq!(out, b"data: hello world\n\n");
    }

    #[test]
    fn holds_back_only_a_genuine_partial_prefix() {
        let r = redactor_for(&[("K", VALUE)]);
        let mut s = r.scanner();
        // Ends mid-needle: the prefix is withheld, everything before it is not.
        let out = s.push(b"tail sk-live-abc");
        assert_eq!(out, b"tail ");
        // A prefix that turns out to be nothing is released verbatim at the end.
        let rest = s.finish();
        assert_eq!(rest, b"sk-live-abc");
    }

    #[test]
    fn matches_the_percent_encoded_form() {
        // An OAuth redirect echoing the value into a query parameter.
        let value = "sk/live+abc=123";
        let r = redactor_for(&[("K", value)]);
        let (out, hits) = scrub(&r, &["https://x.test/cb?token=sk%2Flive%2Babc%3D123"]);
        assert_eq!(
            out,
            format!("https://x.test/cb?token={DEFAULT_PLACEHOLDER}")
        );
        assert_eq!(hits, 1);
    }

    #[test]
    fn matches_lowercase_percent_hex() {
        let value = "sk/live/abc/123";
        let r = redactor_for(&[("K", value)]);
        let (out, hits) = scrub(&r, &["token=sk%2flive%2fabc%2f123"]);
        assert_eq!(out, format!("token={DEFAULT_PLACEHOLDER}"));
        assert_eq!(hits, 1);
    }

    #[test]
    fn matches_the_json_escaped_form() {
        // A value with a quote in it, echoed inside a JSON error message.
        let value = "sk-live-\"quoted\"-abc";
        let r = redactor_for(&[("K", value)]);
        let body = r#"{"error":"bad key: sk-live-\"quoted\"-abc"}"#;
        let (out, hits) = scrub(&r, &[body]);
        assert_eq!(hits, 1);
        assert!(!out.contains("quoted"));
    }

    #[test]
    fn replaces_every_occurrence() {
        let r = redactor_for(&[("K", VALUE)]);
        let (out, hits) = scrub(&r, &[&format!("{VALUE} and again {VALUE}")]);
        assert_eq!(
            out,
            format!("{DEFAULT_PLACEHOLDER} and again {DEFAULT_PLACEHOLDER}")
        );
        assert_eq!(hits, 2);
    }

    #[test]
    fn longest_needle_wins() {
        // One value being a prefix of another must not let the short one match
        // first and leave the long one's tail in the clear.
        let r = redactor_for(&[("SHORT", "sk-live-abc"), ("LONG", "sk-live-abcdef123")]);
        let (out, _) = scrub(&r, &["sk-live-abcdef123"]);
        assert_eq!(out, DEFAULT_PLACEHOLDER);
    }

    #[test]
    fn short_values_are_never_matched() {
        // A secret whose value is "8080" must not shred every port in a response.
        let owned: &'static [(String, String)] =
            Box::leak(vec![("PORT".to_string(), "8080".to_string())].into_boxed_slice());
        let r = Redactor::new(
            ["PORT"],
            |n| owned.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str()),
            &RedactionConfig::default(),
        );
        assert!(r.is_none(), "a 4-byte value is below min_length");
    }

    #[test]
    fn no_names_means_no_redactor() {
        let r = Redactor::new([], |_| None, &RedactionConfig::default());
        assert!(r.is_none());
    }

    #[test]
    fn redact_all_reports_no_match() {
        let r = redactor_for(&[("K", VALUE)]);
        assert!(r.redact_all(b"https://example.test/callback").is_none());
        let (out, hits) = r
            .redact_all(format!("https://x.test/?t={VALUE}").as_bytes())
            .expect("a match");
        assert_eq!(hits, 1);
        assert_eq!(
            out,
            format!("https://x.test/?t={DEFAULT_PLACEHOLDER}").as_bytes()
        );
    }

    #[test]
    fn names_are_reported_for_the_audit_line() {
        let r = redactor_for(&[("K", VALUE)]);
        assert_eq!(r.names(), ["K"]);
    }
}
