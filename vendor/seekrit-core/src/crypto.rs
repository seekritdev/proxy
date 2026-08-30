//! Client-side decryption, bit-compatible with `packages/crypto` (WebCrypto).
//!
//! A service token carries its own P-256 private key. With it we:
//!   1. unwrap each environment DEK from its `wd1.` blob
//!      (ECDH P-256 -> HKDF-SHA256 -> AES-256-GCM), and
//!   2. decrypt each secret from its `sc1.` blob
//!      (AES-256-GCM, AAD = `<environmentId>/<NAME>`).
//!
//! Plaintext is produced only here, in-process, and never touches disk or the
//! network. The 32-byte DEK is zeroized as soon as a layer is drained.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::pkcs8::DecodePrivateKey;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::b64;
use crate::error::{CoreError, CoreResult};

/// Must match `HKDF_INFO` in `packages/crypto/src/wrap.ts`.
const WRAP_HKDF_INFO: &[u8] = b"seekrit/wrap-dek/v1";
const TOKEN_PREFIX: &str = "skt_";

/// The private half of a service token, recovered from the `skt_…` string.
pub struct TokenKey {
    secret: SecretKey,
}

impl TokenKey {
    /// Parse `skt_<id>_<pkcs8 base64url>`. Only the first two `_` are
    /// separators — the base64url key segment may itself contain `_`.
    pub fn parse(token: &str) -> CoreResult<TokenKey> {
        if !token.starts_with(TOKEN_PREFIX) {
            return Err(CoreError::MalformedToken("must start with skt_".into()));
        }
        // token = "skt_" + id + "_" + key ; split off the id, keep the rest.
        let rest = &token[TOKEN_PREFIX.len()..];
        let sep = rest
            .find('_')
            .ok_or_else(|| CoreError::MalformedToken("missing key segment".into()))?;
        let key_b64 = &rest[sep + 1..];
        if key_b64.is_empty() {
            return Err(CoreError::MalformedToken("empty key segment".into()));
        }
        let der = b64::decode(key_b64)
            .map_err(|e| CoreError::MalformedToken(format!("key is not base64url: {e}")))?;
        let secret = SecretKey::from_pkcs8_der(&der)
            .map_err(|_| CoreError::MalformedToken("private key is corrupted".into()))?;
        Ok(TokenKey { secret })
    }
}

/// Unwrap a `wd1.<eph>.<salt>.<iv>.<ct>` grant to its raw plaintext bytes using
/// the token's private key: ECDH P-256 → HKDF-SHA256 → AES-256-GCM, matching
/// `wrapDek`/`unwrapDek` in `packages/crypto/src/wrap.ts`.
///
/// The grant may wrap key material of any length: a 32-byte environment/KMS DEK
/// (see [`unwrap_dek`]) or a longer PKCS8 private key for a KMS `sign` key (see
/// [`crate::sign`]). Bytes are returned zeroizing.
pub fn unwrap_wrapped_key(wrapped: &str, key: &TokenKey) -> CoreResult<Zeroizing<Vec<u8>>> {
    let parts = split_blob(wrapped, "wd1", 4)?;
    let eph_raw = b64::decode(parts[0]).map_err(|e| crypto_err("wrapped key", e))?;
    let salt = b64::decode(parts[1]).map_err(|e| crypto_err("wrapped key", e))?;
    let iv = b64::decode(parts[2]).map_err(|e| crypto_err("wrapped key", e))?;
    let ct = b64::decode(parts[3]).map_err(|e| crypto_err("wrapped key", e))?;

    // Ephemeral public key: raw SEC1 uncompressed point (0x04 || X || Y).
    let ephemeral = PublicKey::from_sec1_bytes(&eph_raw)
        .map_err(|_| CoreError::Crypto("wrapped key: bad ephemeral public key".into()))?;

    // ECDH shared secret == X-coordinate of the shared point (matches
    // WebCrypto deriveBits(ECDH, .., 256)).
    let shared = diffie_hellman(self_scalar(key), ephemeral.as_affine());
    let mut ikm = shared.raw_secret_bytes().to_vec();

    // HKDF-SHA256(salt, info) -> 32-byte AES-256-GCM wrapping key.
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut wrapping = [0u8; 32];
    hk.expand(WRAP_HKDF_INFO, &mut wrapping)
        .map_err(|_| CoreError::Crypto("wrapped key: HKDF expand failed".into()))?;
    ikm.zeroize();

    let plaintext = aes_gcm_decrypt(&wrapping, &iv, &ct, &[]).map_err(|_| {
        CoreError::Crypto("key unwrap failed: wrong private key or tampered grant".into())
    })?;
    wrapping.zeroize();
    Ok(Zeroizing::new(plaintext))
}

/// Unwrap an environment/KMS DEK from a `wd1.` grant using the token's private
/// key. Like [`unwrap_wrapped_key`] but pins the result to a 32-byte AES key.
pub fn unwrap_dek(wrapped: &str, key: &TokenKey) -> CoreResult<Dek> {
    let bytes = unwrap_wrapped_key(wrapped, key)?;
    if bytes.len() != 32 {
        return Err(CoreError::Crypto(
            "DEK unwrap produced a non-256-bit key".into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Dek(out))
}

/// A 32-byte environment data-encryption key. Zeroized on drop.
///
/// The same type also carries the raw material of a KMS `encrypt` key — a
/// managed AES-256-GCM key reaches a client as a `wd1.` grant, exactly like an
/// environment DEK, so [`unwrap_dek`] recovers both. The KMS envelope
/// operations live in [`crate::kms`] and read this material via
/// [`Dek::material`].
pub struct Dek([u8; 32]);

impl Dek {
    /// Construct a DEK from raw 32-byte material a client already holds.
    ///
    /// The zero-knowledge invariant is about the *server*, which never possesses
    /// key bytes; a client legitimately does. The usual path is [`unwrap_dek`]
    /// from a `wd1.` grant, but the KMS gateway's tests (and any caller importing
    /// external key material) build a DEK directly. The bytes are copied into a
    /// `Dek`, which zeroizes them on drop.
    pub fn from_material(material: [u8; 32]) -> Dek {
        Dek(material)
    }

    /// The raw 32-byte key. Crate-internal so [`crate::kms`] can drive the
    /// AES-GCM envelope ops without widening `Dek`'s public surface.
    pub(crate) fn material(&self) -> &[u8; 32] {
        &self.0
    }

    /// Decrypt one `sc1.<iv>.<ct>` secret blob. `aad` binds the ciphertext to
    /// `<environmentId>/<NAME>`; a mismatch fails the GCM tag check.
    pub fn decrypt_secret(&self, blob: &str, aad: &[u8]) -> CoreResult<String> {
        let parts = split_blob(blob, "sc1", 2)?;
        let iv = b64::decode(parts[0]).map_err(|e| crypto_err("secret", e))?;
        let ct = b64::decode(parts[1]).map_err(|e| crypto_err("secret", e))?;
        let plaintext = aes_gcm_decrypt(&self.0, &iv, &ct, aad).map_err(|_| {
            CoreError::Crypto(
                "secret decryption failed: wrong key, tampered data, or mismatched context".into(),
            )
        })?;
        // Secret values are UTF-8 (same as the browser/CLI, which TextDecode).
        String::from_utf8(plaintext)
            .map_err(|_| CoreError::Crypto("secret is not valid UTF-8".into()))
    }
}

impl Drop for Dek {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn self_scalar(key: &TokenKey) -> p256::NonZeroScalar {
    key.secret.to_nonzero_scalar()
}

/// AES-256-GCM decrypt. `ct` is ciphertext||tag (WebCrypto layout); `iv` is 12
/// bytes; `aad` is the additional authenticated data (may be empty).
pub(crate) fn aes_gcm_decrypt(
    key32: &[u8; 32],
    iv: &[u8],
    ct: &[u8],
    aad: &[u8],
) -> CoreResult<Vec<u8>> {
    if iv.len() != 12 {
        return Err(CoreError::Crypto("invalid GCM nonce length".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key32)
        .map_err(|_| CoreError::Crypto("invalid AES key length".into()))?;
    let mut nonce = Nonce::default();
    nonce.copy_from_slice(iv);
    cipher
        .decrypt(&nonce, Payload { msg: ct, aad })
        .map_err(|_| CoreError::Crypto("AES-GCM authentication failed".into()))
}

/// AES-256-GCM encrypt. Returns ciphertext||tag (WebCrypto layout, matching what
/// `crypto.subtle.encrypt` produces). `iv` is 12 bytes; `aad` may be empty.
pub(crate) fn aes_gcm_encrypt(
    key32: &[u8; 32],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> CoreResult<Vec<u8>> {
    if iv.len() != 12 {
        return Err(CoreError::Crypto("invalid GCM nonce length".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key32)
        .map_err(|_| CoreError::Crypto("invalid AES key length".into()))?;
    let mut nonce = Nonce::default();
    nonce.copy_from_slice(iv);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CoreError::Crypto("AES-GCM encryption failed".into()))
}

/// Split `prefix.part1.part2.…` into exactly `count` dot-separated parts after
/// verifying the version prefix. Mirrors `splitBlob` in the TS crypto package.
pub(crate) fn split_blob<'a>(
    blob: &'a str,
    prefix: &str,
    count: usize,
) -> CoreResult<Vec<&'a str>> {
    let mut it = blob.split('.');
    let got = it.next();
    if got != Some(prefix) {
        return Err(CoreError::Crypto(format!(
            "expected {prefix}. blob, got {}",
            got.unwrap_or("")
        )));
    }
    let parts: Vec<&str> = it.collect();
    if parts.len() != count {
        return Err(CoreError::Crypto(format!(
            "malformed {prefix} blob: expected {count} parts, got {}",
            parts.len()
        )));
    }
    Ok(parts)
}

fn crypto_err(what: &str, e: String) -> CoreError {
    CoreError::Crypto(format!("{what}: {e}"))
}

/// AAD binding a secret ciphertext to its environment + name.
/// Matches `secretAad` in `packages/crypto/src/aes.ts`.
pub fn secret_aad(environment_id: &str, name: &str) -> Vec<u8> {
    format!("{environment_id}/{name}").into_bytes()
}
