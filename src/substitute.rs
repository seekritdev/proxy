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
}
