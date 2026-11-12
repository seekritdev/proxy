//! The substitution engine — the transport-agnostic heart of the proxy.
//!
//! It scans a byte buffer (a header value, the request path+query, or the
//! request body) for `{{seekrit:NAME}}` placeholders and replaces each with a
//! looked-up value. It is **fail-closed**: a placeholder that names a secret
//! not permitted toward this upstream, or one that does not resolve, aborts the
//! request rather than forwarding the placeholder (or, worse, the wrong host
//! receiving a real credential). Values never appear in logs — only names.

use std::collections::BTreeSet;

const OPEN: &[u8] = b"{{seekrit:";
const CLOSE: &[u8] = b"}}";

/// The result of looking up a placeholder name for a given upstream.
pub enum Lookup {
    /// Permitted and resolved: substitute this decrypted value.
    Value(String),
    /// Referenced but not on this upstream's allowlist (default-deny).
    Denied,
    /// Permitted but no such secret was resolved (fail-closed).
    Unknown,
}

/// Why a substitution pass refused to proceed. Carries the offending name only.
#[derive(Debug, PartialEq, Eq)]
pub enum SubError {
    Denied(String),
    Unknown(String),
}

/// A completed substitution: the rewritten bytes and the set of names injected.
pub struct Outcome {
    pub bytes: Vec<u8>,
    pub names: BTreeSet<String>,
}

/// Replace every `{{seekrit:NAME}}` in `input` using `lookup`. A malformed or
/// unterminated marker is left verbatim (it is not a valid placeholder).
pub fn substitute<F: Fn(&str) -> Lookup>(input: &[u8], lookup: &F) -> Result<Outcome, SubError> {
    let mut out = Vec::with_capacity(input.len());
    let mut names = BTreeSet::new();
    let mut i = 0;

    while i < input.len() {
        if input[i..].starts_with(OPEN) {
            let after = i + OPEN.len();
            match find(&input[after..], CLOSE) {
                Some(rel) => {
                    let name = std::str::from_utf8(&input[after..after + rel]).ok();
                    match name.filter(|n| is_valid_name(n)) {
                        Some(name) => {
                            match lookup(name) {
                                Lookup::Value(v) => {
                                    out.extend_from_slice(v.as_bytes());
                                    names.insert(name.to_string());
                                }
                                Lookup::Denied => return Err(SubError::Denied(name.to_string())),
                                Lookup::Unknown => return Err(SubError::Unknown(name.to_string())),
                            }
                            i = after + rel + CLOSE.len();
                        }
                        // Not a valid placeholder name: emit the opener literally
                        // and keep scanning from just after it.
                        None => {
                            out.extend_from_slice(OPEN);
                            i = after;
                        }
                    }
                }
                // No closing marker at all: the remainder is literal.
                None => {
                    out.extend_from_slice(&input[i..]);
                    break;
                }
            }
        } else {
            out.push(input[i]);
            i += 1;
        }
    }

    Ok(Outcome { bytes: out, names })
}

/// Substitute inside one request header's value — [`substitute`], plus the one
/// place a client encodes a placeholder before sending it.
///
/// git over HTTPS (and anything else speaking HTTP Basic) sends `user:password`
/// base64-encoded, so `https://x-access-token:{{seekrit:GITHUB_TOKEN}}@github.com`
/// leaves the client as `Authorization: Basic eC1hY2Nlc3Mt…` and the marker is
/// invisible to a byte scan. For exactly that shape — an `Authorization` or
/// `Proxy-Authorization` value of `Basic` (any case), one or more spaces, then
/// canonical padded base64 that decodes to UTF-8 — the decoded text is run
/// through the same `lookup` and re-encoded, keeping the scheme and spacing as
/// sent. A denied or unknown name refuses exactly as it does anywhere else.
///
/// Every other value, a Basic credential failing any of those checks included,
/// is substituted as plain text. That keeps a placeholder standing in for the
/// whole credential (`Basic {{seekrit:GIT_BASIC}}`) working, and means no other
/// header and no other scheme is ever base64-decoded: what looks like a token
/// is not ours to interpret. The rules are pinned by the `header` cases of the
/// shared substitution vectors.
pub fn substitute_header<F: Fn(&str) -> Lookup>(
    name: &str,
    value: &[u8],
    lookup: &F,
) -> Result<Outcome, SubError> {
    let Some((prefix, decoded)) = basic_credential(name, value) else {
        return substitute(value, lookup);
    };
    let inner = substitute(decoded.as_bytes(), lookup)?;
    if inner.names.is_empty() {
        // Nothing injected: forward the credential exactly as it arrived.
        return Ok(Outcome {
            bytes: value.to_vec(),
            names: inner.names,
        });
    }
    let encoded = encode_base64(&inner.bytes);
    let mut bytes = Vec::with_capacity(prefix.len() + encoded.len());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(encoded.as_bytes());
    Ok(Outcome {
        bytes,
        names: inner.names,
    })
}

/// `Some((scheme_and_spaces, decoded_text))` when `value` is a Basic credential
/// in a header that carries one; `None` for anything to be scanned as text.
fn basic_credential<'a>(name: &str, value: &'a [u8]) -> Option<(&'a [u8], String)> {
    const SCHEME: &[u8] = b"basic";
    if !name.eq_ignore_ascii_case("authorization")
        && !name.eq_ignore_ascii_case("proxy-authorization")
    {
        return None;
    }
    if value.len() < SCHEME.len() || !value[..SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
        return None;
    }
    let spaces = value[SCHEME.len()..]
        .iter()
        .take_while(|&&b| b == b' ')
        .count();
    if spaces == 0 {
        return None; // `Basicx…` is some other scheme
    }
    let split = SCHEME.len() + spaces;
    let decoded = decode_canonical_base64(&value[split..])?;
    let text = String::from_utf8(decoded).ok()?;
    Some((&value[..split], text))
}

/// The standard base64 alphabet (RFC 4648 §4) — what HTTP Basic uses. Not
/// `seekrit_core::b64`, which is base64url without padding, the blob encoding.
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with `=` padding.
fn encode_base64(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        out.push(BASE64[(n >> 18) as usize & 63] as char);
        out.push(BASE64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            BASE64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard base64 only if `input` is the *canonical* encoding of its
/// bytes: non-empty, padded to a multiple of four, standard alphabet, zero
/// padding bits. Checked by re-encoding, so every implementation of this rule
/// can make the same check the same way. Lenient decoders accept far more
/// (missing padding, the url-safe alphabet, stray bits), and each one is a
/// different answer to "is this a credential?" — so anything else is not one.
fn decode_canonical_base64(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() || !input.len().is_multiple_of(4) {
        return None;
    }
    let pad = input.iter().rev().take_while(|&&b| b == b'=').count();
    if pad > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in &input[..input.len() - pad] {
        let v = BASE64.iter().position(|&a| a == c)? as u32;
        acc = ((acc << 6) | v) & 0xFFFF;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    (encode_base64(&out).as_bytes() == input).then_some(out)
}

/// Placeholder names are env-var style: `[A-Za-z0-9_]+`.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// First index of `needle` in `hay`, or `None`.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Allow OPENAI_API_KEY -> "sk-live"; deny everything else; STRIPE unknown.
    fn lookup(name: &str) -> Lookup {
        match name {
            "OPENAI_API_KEY" => Lookup::Value("sk-live".into()),
            "STRIPE_KEY" => Lookup::Unknown, // allowed but unresolved
            _ => Lookup::Denied,
        }
    }

    fn run(input: &str) -> Result<(String, Vec<String>), SubError> {
        let o = substitute(input.as_bytes(), &lookup)?;
        Ok((
            String::from_utf8(o.bytes).unwrap(),
            o.names.into_iter().collect(),
        ))
    }

    #[test]
    fn substitutes_and_reports_names() {
        let (out, names) = run("Bearer {{seekrit:OPENAI_API_KEY}}").unwrap();
        assert_eq!(out, "Bearer sk-live");
        assert_eq!(names, vec!["OPENAI_API_KEY"]);
    }

    #[test]
    fn passthrough_without_placeholders() {
        let (out, names) = run("nothing to see here").unwrap();
        assert_eq!(out, "nothing to see here");
        assert!(names.is_empty());
    }

    #[test]
    fn multiple_occurrences() {
        let (out, _) = run("{{seekrit:OPENAI_API_KEY}}::{{seekrit:OPENAI_API_KEY}}").unwrap();
        assert_eq!(out, "sk-live::sk-live");
    }

    #[test]
    fn denied_aborts() {
        assert_eq!(
            run("{{seekrit:SOME_OTHER}}"),
            Err(SubError::Denied("SOME_OTHER".into()))
        );
    }

    #[test]
    fn unknown_aborts() {
        assert_eq!(
            run("{{seekrit:STRIPE_KEY}}"),
            Err(SubError::Unknown("STRIPE_KEY".into()))
        );
    }

    #[test]
    fn unterminated_and_bad_names_are_literal() {
        // No closing braces -> literal.
        let (out, names) = run("value {{seekrit:OPENAI_API_KEY").unwrap();
        assert_eq!(out, "value {{seekrit:OPENAI_API_KEY");
        assert!(names.is_empty());
        // Illegal char in name -> the opener is emitted literally, rest scanned.
        let (out2, _) = run("{{seekrit:bad-name}}").unwrap();
        assert_eq!(out2, "{{seekrit:bad-name}}");
    }

    #[test]
    fn base64_matches_rfc_4648_test_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode_base64(plain.as_bytes()), encoded);
            if !encoded.is_empty() {
                assert_eq!(
                    decode_canonical_base64(encoded.as_bytes()).as_deref(),
                    Some(plain.as_bytes())
                );
            }
        }
    }

    #[test]
    fn non_canonical_base64_is_refused() {
        for bad in [
            "Zg",
            "Zg=",
            "Zh==",
            "Z===",
            "Zm9v====",
            "Zm9v Yg==",
            "Zm-v",
            "Zg=a",
        ] {
            assert_eq!(decode_canonical_base64(bad.as_bytes()), None, "{bad}");
        }
    }

    #[test]
    fn basic_credential_substitutes_inside_and_re_encodes() {
        let value = format!("Basic {}", encode_base64(b"u:{{seekrit:OPENAI_API_KEY}}"));
        let out = substitute_header("authorization", value.as_bytes(), &lookup).unwrap();
        assert_eq!(
            String::from_utf8(out.bytes).unwrap(),
            format!("Basic {}", encode_base64(b"u:sk-live"))
        );
        assert_eq!(
            out.names.into_iter().collect::<Vec<_>>(),
            ["OPENAI_API_KEY"]
        );
    }
}
