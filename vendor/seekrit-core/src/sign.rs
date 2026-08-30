//! Managed signing keys — ECDSA over P-256 (SHA-256), the Rust twin of
//! `packages/crypto/src/sign.ts`.
//!
//! A `sign` key's private half reaches a client as a `wd1.` grant wrapping its
//! **PKCS8** bytes (unwrap via [`crate::crypto::unwrap_wrapped_key`], then
//! [`SigningKey::from_pkcs8`]); the public half is published per version as a JWK
//! whose affine coordinates feed [`VerifyingKey::from_public_coords`] (parsing
//! the JWK JSON is a transport concern left to the caller). Signatures are
//! `sg1.<keyId>.<version>.<sig>`, where `<sig>` is base64url
//! of the **IEEE P1363** (raw `r‖s`, 64-byte) encoding WebCrypto produces — so a
//! signature from `seekrit kms sign` and one from this crate are interchangeable.
//!
//! The AWS KMS gateway additionally needs the **DER** encoding AWS SDKs expect
//! and the **SPKI** public key for `GetPublicKey`; both conversions live here, so
//! the gateway never touches signature bytes directly.

use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey as EcdsaSigningKey, VerifyingKey as EcdsaVerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};

use crate::b64;
use crate::crypto::split_blob;
use crate::error::{CoreError, CoreResult};
use crate::kms::KmsKeyRef;

const SIGN_PREFIX: &str = "sg1";

/// An ECDSA P-256 private key recovered from a `sign` key's grant.
pub struct SigningKey(EcdsaSigningKey);

/// An ECDSA P-256 public key, for verification and `GetPublicKey`. Public data,
/// so it's cheap to `Clone` (used to cache all of a key's published versions).
#[derive(Clone)]
pub struct VerifyingKey(EcdsaVerifyingKey);

impl SigningKey {
    /// Import the PKCS8 private key bytes an unwrapped `sign` grant yields (what
    /// WebCrypto's `exportKey("pkcs8", …)` produces).
    pub fn from_pkcs8(pkcs8: &[u8]) -> CoreResult<SigningKey> {
        EcdsaSigningKey::from_pkcs8_der(pkcs8)
            .map(SigningKey)
            .map_err(|_| CoreError::Crypto("signing key: invalid PKCS8 private key".into()))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(*self.0.verifying_key())
    }

    /// Sign a message (hashing it with SHA-256) → an `sg1.` signature blob with
    /// the P1363 encoding, byte-for-byte the format `sign.ts` emits.
    pub fn sign_message(&self, key_ref: &KmsKeyRef, message: &[u8]) -> String {
        let sig: Signature = self.0.sign(message);
        join_sig(key_ref, &sig)
    }

    /// Sign a message (SHA-256) and return the DER encoding AWS SDKs expect.
    pub fn sign_der(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.0.sign(message);
        sig.to_der().as_bytes().to_vec()
    }

    /// Sign a caller-supplied 32-byte SHA-256 digest (AWS `MessageType=DIGEST`),
    /// returning DER.
    pub fn sign_prehash_der(&self, digest: &[u8]) -> CoreResult<Vec<u8>> {
        let sig: Signature = self
            .0
            .sign_prehash(digest)
            .map_err(|_| CoreError::Crypto("sign: invalid message digest".into()))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

impl VerifyingKey {
    /// Build a verifying key from a published public key's affine coordinates —
    /// the raw 32-byte `x` and `y` a P-256 JWK carries (base64url-decoded by the
    /// caller; JWK JSON parsing is a transport concern kept out of this crate).
    pub fn from_public_coords(x: &[u8], y: &[u8]) -> CoreResult<VerifyingKey> {
        if x.len() != 32 || y.len() != 32 {
            return Err(CoreError::Crypto(
                "public key coordinates must be 32 bytes".into(),
            ));
        }
        // SEC1 uncompressed point: 0x04 || X || Y.
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(x);
        sec1.extend_from_slice(y);
        EcdsaVerifyingKey::from_sec1_bytes(&sec1)
            .map(VerifyingKey)
            .map_err(|_| CoreError::Crypto("public key: point not on curve".into()))
    }

    /// Verify an `sg1.` (P1363) signature over `message` (hashing with SHA-256).
    pub fn verify_message(&self, signature: &str, message: &[u8]) -> CoreResult<bool> {
        let sig = parse_sg1(signature)?;
        Ok(self.0.verify(message, &sig).is_ok())
    }

    /// Verify a bare P1363 (`r‖s`, 64-byte) signature over `message` (SHA-256).
    ///
    /// The same encoding [`verify_message`](Self::verify_message) reads out of an
    /// `sg1.` blob, but for signatures that travel in an envelope of their own —
    /// the `ap1.` policy bundles in [`crate::policy`], where the key is carried
    /// beside the signature rather than referenced by key id.
    pub fn verify_p1363(&self, message: &[u8], sig: &[u8]) -> bool {
        match Signature::from_slice(sig) {
            Ok(sig) => self.0.verify(message, &sig).is_ok(),
            Err(_) => false,
        }
    }

    /// Verify a DER signature over `message` (SHA-256). `false` = not valid.
    pub fn verify_der(&self, message: &[u8], der: &[u8]) -> bool {
        match Signature::from_der(der) {
            Ok(sig) => self.0.verify(message, &sig).is_ok(),
            Err(_) => false,
        }
    }

    /// Verify a DER signature over a caller-supplied SHA-256 digest (AWS
    /// `MessageType=DIGEST`).
    pub fn verify_prehash_der(&self, digest: &[u8], der: &[u8]) -> bool {
        match Signature::from_der(der) {
            Ok(sig) => self.0.verify_prehash(digest, &sig).is_ok(),
            Err(_) => false,
        }
    }

    /// The SubjectPublicKeyInfo DER encoding AWS KMS `GetPublicKey` returns.
    pub fn to_spki_der(&self) -> CoreResult<Vec<u8>> {
        self.0
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|_| CoreError::Crypto("public key: SPKI encoding failed".into()))
    }
}

/// Read the key id + version an `sg1.` signature was produced under — without the
/// key, so a verifier can fetch the matching version's public key first.
pub fn signature_key_ref(signature: &str) -> CoreResult<KmsKeyRef> {
    let parts = split_blob(signature, SIGN_PREFIX, 3)?;
    let version: u32 = parts[1]
        .parse()
        .map_err(|_| CoreError::Crypto(format!("invalid version in signature: {:?}", parts[1])))?;
    if version < 1 {
        return Err(CoreError::Crypto("invalid version in signature".into()));
    }
    Ok(KmsKeyRef {
        key_id: parts[0].to_string(),
        version,
    })
}

fn join_sig(key_ref: &KmsKeyRef, sig: &Signature) -> String {
    // P1363 fixed-width r||s (64 bytes), matching WebCrypto's ECDSA output.
    format!(
        "{SIGN_PREFIX}.{}.{}.{}",
        key_ref.key_id,
        key_ref.version,
        b64::encode(&sig.to_bytes())
    )
}

fn parse_sg1(signature: &str) -> CoreResult<Signature> {
    let parts = split_blob(signature, SIGN_PREFIX, 3)?;
    let raw = b64::decode(parts[2]).map_err(|e| CoreError::Crypto(format!("sg1 sig: {e}")))?;
    Signature::from_slice(&raw)
        .map_err(|_| CoreError::Crypto("sg1 sig: not a valid P1363 signature".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::DecodePublicKey;

    // A fixed, valid non-zero scalar < n — deterministic keypair, no RNG needed.
    // The cross-impl vectors in apps/kms exercise real WebCrypto-generated keys.
    fn keypair() -> (SigningKey, VerifyingKey) {
        let sk = EcdsaSigningKey::from_slice(&[0x11u8; 32]).expect("valid scalar");
        let vk = *sk.verifying_key();
        (SigningKey(sk), VerifyingKey(vk))
    }

    #[test]
    fn sg1_round_trips() {
        let (sk, vk) = keypair();
        let key_ref = KmsKeyRef {
            key_id: "kms_sign".into(),
            version: 2,
        };
        let sig = sk.sign_message(&key_ref, b"release-v1.2.3");
        assert!(sig.starts_with("sg1.kms_sign.2."));
        assert_eq!(signature_key_ref(&sig).unwrap(), key_ref);
        assert!(vk.verify_message(&sig, b"release-v1.2.3").unwrap());
        assert!(!vk.verify_message(&sig, b"tampered").unwrap());
    }

    #[test]
    fn der_round_trips_raw_and_prehash() {
        use sha2::{Digest, Sha256};
        let (sk, vk) = keypair();
        let msg = b"artifact bytes";

        let der = sk.sign_der(msg);
        assert!(vk.verify_der(msg, &der));
        assert!(!vk.verify_der(b"other", &der));
        assert!(!vk.verify_der(msg, b"not-der"));

        let digest = Sha256::digest(msg);
        let der2 = sk.sign_prehash_der(&digest).unwrap();
        // A DIGEST-mode signature verifies as a RAW signature over the same
        // message (both are ECDSA over SHA-256(msg)).
        assert!(vk.verify_der(msg, &der2));
        assert!(vk.verify_prehash_der(&digest, &der));
    }

    #[test]
    fn spki_export_parses_back() {
        let (_, vk) = keypair();
        let der = vk.to_spki_der().unwrap();
        // A well-formed SPKI re-imports via the p256 public-key decoder.
        assert!(p256::PublicKey::from_public_key_der(&der).is_ok());
    }
}
