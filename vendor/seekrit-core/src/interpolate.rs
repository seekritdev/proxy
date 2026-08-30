//! Secret references: `${OTHER_SECRET}` inside a secret value.
//!
//! The Rust mirror of `packages/core/src/interpolate.ts`, which is the canonical
//! specification — read the rules there. Both are pinned to the same cases in
//! the shared golden fixture (`apps/run/testdata/vectors.json`, `interpolation`),
//! so an expansion can never mean one thing in the CLI and another here.
//!
//! In short: `${NAME}` is replaced with `NAME`'s value from the *same merged
//! set* (so it sees whichever layer won the name), recursively; `$${NAME}` is a
//! literal `${NAME}`; a name that is not a valid secret name or is absent from
//! the set is left exactly as written (shell/CI templates pass through
//! untouched) and reported in [`Interpolation::unresolved`]; a reference cycle
//! is an error.
//!
//! This is pure string work over already-decrypted values — it runs in the same
//! trust boundary as decryption and needs no key material.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{CoreError, CoreResult};

/// Cap on a single expanded value; see the TypeScript spec for the rationale.
const MAX_EXPANDED_LENGTH: usize = 1_048_576;

/// The outcome of expanding a variable set. Deliberately does not derive
/// `Debug` — `values` is plaintext, and a stray `{:?}` should not be able to
/// print it.
pub struct Interpolation {
    /// The variable set with every reference expanded.
    pub values: BTreeMap<String, String>,
    /// Names whose value had at least one reference expanded.
    pub expanded: Vec<String>,
    /// Referenced names that exist nowhere in the set (left literal), sorted.
    pub unresolved: Vec<String>,
}

/// A run of literal text, or one well-formed `${NAME}` reference.
enum Segment<'a> {
    Literal(&'a str),
    Reference(&'a str),
}

/// Whether `name` is a valid reference name (`[A-Za-z_][A-Za-z0-9_]*`).
fn is_reference_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(b) if b == b'_' || b.is_ascii_alphabetic() => {}
        _ => return false,
    }
    bytes.all(|b| b == b'_' || b.is_ascii_alphanumeric())
}

/// Split a value into literal runs and references — the single tokenizer both
/// expansion and inspection go through. `$`, `{` and `}` are ASCII, so every
/// index used here lands on a UTF-8 char boundary.
fn segments(text: &str) -> Vec<Segment<'_>> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < text.len() {
        let Some(offset) = text[i..].find('$') else {
            out.push(Segment::Literal(&text[i..]));
            break;
        };
        let dollar = i + offset;
        if dollar > i {
            out.push(Segment::Literal(&text[i..dollar]));
        }

        // `$${` — escape: the `${` is literal, and skipping all three bytes
        // means the `{NAME}` that follows can never be read as a reference.
        if bytes.get(dollar + 1) == Some(&b'$') && bytes.get(dollar + 2) == Some(&b'{') {
            out.push(Segment::Literal(&text[dollar + 1..dollar + 3]));
            i = dollar + 3;
            continue;
        }

        if bytes.get(dollar + 1) == Some(&b'{') {
            if let Some(rel) = text[dollar + 2..].find('}') {
                let close = dollar + 2 + rel;
                let name = &text[dollar + 2..close];
                if is_reference_name(name) {
                    out.push(Segment::Reference(name));
                    i = close + 1;
                    continue;
                }
            }
        }

        // A plain `$`, an unterminated `${`, or a non-name (`${FOO:-bar}`,
        // `${1}`): literal. Advancing one byte lets a `${` later in the run
        // still be recognized.
        out.push(Segment::Literal(&text[dollar..dollar + 1]));
        i = dollar + 1;
    }
    out
}

/// Depth-first expansion with memoization and cycle detection.
struct Expander<'a> {
    source: &'a BTreeMap<String, String>,
    resolved: BTreeMap<String, String>,
    unresolved: BTreeSet<String>,
    /// The chain currently being expanded — the cycle detector.
    stack: Vec<&'a str>,
}

impl<'a> Expander<'a> {
    /// Expand one present name's value, at most once per name.
    fn resolve(&mut self, name: &'a str) -> CoreResult<String> {
        if let Some(done) = self.resolved.get(name) {
            return Ok(done.clone());
        }
        if let Some(at) = self.stack.iter().position(|n| *n == name) {
            let mut chain: Vec<&str> = self.stack[at..].to_vec();
            chain.push(name);
            return Err(CoreError::Reference(format!(
                "secret reference cycle: {}",
                chain.join(" -> ")
            )));
        }

        // Present by construction: callers only resolve names they found in the
        // set (top-level iteration, or a reference checked with `contains_key`).
        let raw = self.source.get(name).map(String::as_str).unwrap_or("");
        self.stack.push(name);
        let mut out = String::with_capacity(raw.len());
        for segment in segments(raw) {
            match segment {
                Segment::Literal(text) => out.push_str(text),
                Segment::Reference(reference) => {
                    // Re-borrow the key out of `source` so the recursive call
                    // (and the cycle stack) can outlive this `raw` borrow.
                    match self.source.get_key_value(reference) {
                        Some((key, _)) => {
                            let value = self.resolve(key.as_str())?;
                            out.push_str(&value);
                        }
                        None => {
                            self.unresolved.insert(reference.to_string());
                            out.push('$');
                            out.push('{');
                            out.push_str(reference);
                            out.push('}');
                        }
                    }
                }
            }
        }
        self.stack.pop();

        if out.len() > MAX_EXPANDED_LENGTH {
            return Err(CoreError::Reference(format!(
                "{name} expands to more than {MAX_EXPANDED_LENGTH} bytes - check its references"
            )));
        }
        self.resolved.insert(name.to_string(), out.clone());
        Ok(out)
    }
}

/// Expand `${NAME}` references throughout a decrypted variable set.
///
/// The input is never mutated. Errors only on a reference cycle or a value that
/// expands past [`MAX_EXPANDED_LENGTH`]; an unknown reference is left literal
/// and reported instead.
pub fn interpolate_secrets(values: &BTreeMap<String, String>) -> CoreResult<Interpolation> {
    let mut expander = Expander {
        source: values,
        resolved: BTreeMap::new(),
        unresolved: BTreeSet::new(),
        stack: Vec::new(),
    };

    let mut out = BTreeMap::new();
    let mut expanded = Vec::new();
    for (name, original) in values {
        let value = expander.resolve(name.as_str())?;
        if &value != original {
            expanded.push(name.clone());
        }
        out.insert(name.clone(), value);
    }

    Ok(Interpolation {
        values: out,
        expanded,
        unresolved: expander.unresolved.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error message from a set that must fail to expand. `Interpolation`
    /// has no `Debug` (it holds plaintext), so `unwrap_err` is not available.
    fn expect_err(values: &BTreeMap<String, String>) -> String {
        match interpolate_secrets(values) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("expected expansion to fail"),
        }
    }

    fn set(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn substitutes_a_reference() {
        let out = interpolate_secrets(&set(&[
            ("HOST", "db.internal"),
            ("DATABASE_URL", "postgres://app@${HOST}:5432/app"),
        ]))
        .unwrap();
        assert_eq!(
            out.values["DATABASE_URL"],
            "postgres://app@db.internal:5432/app"
        );
        assert_eq!(out.expanded, vec!["DATABASE_URL"]);
        assert!(out.unresolved.is_empty());
    }

    #[test]
    fn expands_recursively_and_repeats() {
        let out = interpolate_secrets(&set(&[
            ("HOST", "db.internal"),
            ("PORT", "5432"),
            ("ADDR", "${HOST}:${PORT}"),
            ("PAIR", "${ADDR}|${ADDR}"),
        ]))
        .unwrap();
        assert_eq!(out.values["PAIR"], "db.internal:5432|db.internal:5432");
    }

    #[test]
    fn leaves_unknown_references_literal_and_reports_them() {
        let out = interpolate_secrets(&set(&[
            ("TAG", "build-${GITHUB_SHA}"),
            ("OTHER", "${NOPE}-${GITHUB_SHA}"),
        ]))
        .unwrap();
        assert_eq!(out.values["TAG"], "build-${GITHUB_SHA}");
        assert_eq!(out.values["OTHER"], "${NOPE}-${GITHUB_SHA}");
        assert!(out.expanded.is_empty());
        assert_eq!(out.unresolved, vec!["GITHUB_SHA", "NOPE"]);
    }

    #[test]
    fn escapes_with_a_doubled_dollar() {
        let out = interpolate_secrets(&set(&[
            ("NAME", "expanded"),
            ("TEMPLATE", "$${NAME} stays, ${NAME} goes"),
        ]))
        .unwrap();
        assert_eq!(out.values["TEMPLATE"], "${NAME} stays, expanded goes");
        assert!(out.unresolved.is_empty());
    }

    #[test]
    fn leaves_shell_and_non_name_forms_alone() {
        let input = set(&[
            ("FOO", "value"),
            ("DEFAULTED", "${FOO:-fallback}"),
            ("POSITIONAL", "${1}"),
            ("DOTTED", "${a.b}"),
            ("EMPTY_REF", "${}"),
            ("UNTERMINATED", "${FOO"),
            ("PASSWORD", "p$$w0rd$"),
        ]);
        let out = interpolate_secrets(&input).unwrap();
        assert_eq!(out.values, input);
        assert!(out.expanded.is_empty());
    }

    #[test]
    fn recognizes_a_reference_after_an_unterminated_one() {
        let out = interpolate_secrets(&set(&[("A", "a"), ("T", "${ ${A}")])).unwrap();
        assert_eq!(out.values["T"], "${ a");
    }

    #[test]
    fn handles_multibyte_text_around_references() {
        let out = interpolate_secrets(&set(&[("A", "héllo-🌍"), ("T", "🌍${A}🌍")])).unwrap();
        assert_eq!(out.values["T"], "🌍héllo-🌍🌍");
    }

    #[test]
    fn expands_a_reference_to_an_empty_value() {
        let out = interpolate_secrets(&set(&[("EMPTY", ""), ("PREFIX", "x${EMPTY}y")])).unwrap();
        assert_eq!(out.values["PREFIX"], "xy");
    }

    #[test]
    fn errors_on_a_cycle() {
        let err = expect_err(&set(&[("A", "${B}"), ("B", "${A}")]));
        assert!(err.contains("cycle"), "{err}");
        let err = expect_err(&set(&[("A", "x${A}")]));
        assert!(err.contains("A -> A"), "{err}");
    }

    #[test]
    fn does_not_mistake_a_diamond_for_a_cycle() {
        let out = interpolate_secrets(&set(&[
            ("BASE", "b"),
            ("LEFT", "${BASE}-l"),
            ("RIGHT", "${BASE}-r"),
            ("TOP", "${LEFT}+${RIGHT}"),
        ]))
        .unwrap();
        assert_eq!(out.values["TOP"], "b-l+b-r");
    }

    #[test]
    fn errors_when_an_expansion_exceeds_the_cap() {
        // Each level doubles: 1 KiB x 2^11 = 2 MiB, past the 1 MiB cap.
        let mut values = set(&[("L00", &"x".repeat(1024))]);
        for i in 1..=11 {
            values.insert(
                format!("L{i:02}"),
                format!("${{L{:02}}}${{L{:02}}}", i - 1, i - 1),
            );
        }
        let err = expect_err(&values);
        assert!(err.contains("expands to more than"), "{err}");
    }
}
