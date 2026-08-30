//! `seekrit-core`: the transport-free heart of every seekrit machine client.
//!
//! A service token carries its own P-256 private key. Given the token and a
//! `/v1/resolve` response, this crate:
//!   1. recovers the token's key ([`crypto::TokenKey`]),
//!   2. unwraps each environment DEK ([`crypto::unwrap_dek`]),
//!   3. decrypts each secret ([`crypto::Dek::decrypt_secret`]), and
//!   4. expands `${OTHER_SECRET}` references across the merged set
//!      ([`interpolate::interpolate_secrets`]).
//!
//! It performs **no I/O**: fetching the resolve response is the consuming app's
//! job (`apps/run` uses blocking `ureq`; `apps/proxy` uses async `reqwest`), so
//! this crate stays tiny and reusable. The crypto is bit-compatible with
//! `packages/crypto` (WebCrypto) and proven so by the vector test in `apps/run`.
//!
//! [`kms`] adds the same-family client-side KMS envelope operations (`ce1`/`dk1`
//! encrypt, decrypt, and data-key generation) that back the AWS-KMS-compatible
//! gateway in `apps/kms`; its cross-impl vectors live there.
//!
//! [`policy`] adds agent access policy: rule evaluation shared by `apps/proxy`'s
//! two data planes, and verification of the signed `ap1.` bundles the dashboard
//! publishes. Its cross-impl vectors live in `apps/proxy`.

pub mod b64;
pub mod crypto;
pub mod error;
pub mod interpolate;
pub mod kms;
pub mod policy;
pub mod resolve;
pub mod sign;

pub use error::{CoreError, CoreResult};
