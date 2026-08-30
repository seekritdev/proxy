//! The errors the crypto path can produce. Deliberately small: consuming apps
//! wrap these in their own richer error enums (see `apps/run`'s `Error`).

use std::fmt;

#[derive(Debug)]
pub enum CoreError {
    /// The token string is not a well-formed `skt_<id>_<pkcs8>` value.
    MalformedToken(String),
    /// A DEK could not be unwrapped, or a secret failed to decrypt (wrong key,
    /// tampered data, or mismatched context). Never leaks plaintext.
    Crypto(String),
    /// A `${OTHER_SECRET}` reference could not be expanded — a cycle, or a value
    /// that expands without bound. Names only, never plaintext.
    Reference(String),
    /// A policy bundle was malformed, expired, signed by an unpinned key, or
    /// otherwise not something a proxy may act on. Carries hosts, secret
    /// *names*, and thumbprints — never a credential.
    Policy(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::MalformedToken(m) => write!(f, "invalid service token: {m}"),
            CoreError::Crypto(m) => write!(f, "{m}"),
            CoreError::Reference(m) => write!(f, "{m}"),
            CoreError::Policy(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CoreError {}

pub type CoreResult<T> = std::result::Result<T, CoreError>;
