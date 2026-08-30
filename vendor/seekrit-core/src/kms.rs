//! Client-side KMS envelope encryption — the Rust twin of
//! `packages/crypto/src/kms.ts`, bit-compatible and proven so by the vector test
//! in `apps/kms`.
//!
//! A managed `encrypt` key is a 256-bit AES-GCM key whose material reaches a
//! client only as a `wd1.` grant (see [`crate::crypto::unwrap_dek`], which yields
//! a [`Dek`]). These functions drive that material directly: the server never
//! sees plaintext or key bytes, exactly as for environment DEKs.
//!
//! Blob formats (identical to the TS package):
//!   `ce1.<keyId>.<version>.<iv>.<ciphertext>`  — [`kms_encrypt`] output
//!   `dk1.<keyId>.<version>.<iv>.<ciphertext>`  — [`generate_data_key`] wrapped key
//!
//! The keyId + version travel in the blob (so decrypt can select the right key
//! version) and are folded into the AAD (so a blob can't be replayed under a
//! different key/version). For `ce1` the caller's encryption *context* is bound
//! too — decrypt must supply the same context, mirroring AWS KMS.
//!
//! Unlike the string-oriented TS API, these operate on **raw bytes**: AWS KMS
//! `Plaintext` is an opaque blob (a data key, a serialized struct, arbitrary
//! bytes), so forcing UTF-8 here would be wrong. A `ce1` blob produced from a
//! UTF-8 string is still byte-identical to the TS output and decrypts under
//! either implementation.

use zeroize::Zeroizing;

use crate::b64;
use crate::crypto::{aes_gcm_decrypt, aes_gcm_encrypt, split_blob, Dek};
use crate::error::{CoreError, CoreResult};

const ENCRYPT_PREFIX: &str = "ce1";
const DATAKEY_PREFIX: &str = "dk1";
const IV_LENGTH: usize = 12;
pub const DATA_KEY_LENGTH: usize = 32;

/// The key id + version a `ce1`/`dk1`/`sg1` blob was produced under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsKeyRef {
    pub key_id: String,
    pub version: u32,
}

/// A freshly generated data key: the plaintext bytes (use, then drop — they
/// zeroize) plus the same key wrapped under the managed key (a `dk1.` blob, safe
/// to store beside the ciphertext it protects).
pub struct DataKey {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub wrapped: String,
}

/// AAD for a `ce1` blob: `<keyId>/<version>/<context>`.
fn encrypt_aad(key_ref: &KmsKeyRef, context: &str) -> Vec<u8> {
    format!("{}/{}/{}", key_ref.key_id, key_ref.version, context).into_bytes()
}

/// AAD for a `dk1` blob: `<keyId>/<version>`.
fn data_key_aad(key_id: &str, version: &str) -> Vec<u8> {
    format!("{key_id}/{version}").into_bytes()
}

fn parse_version(s: &str) -> CoreResult<u32> {
    let v: u32 = s
        .parse()
        .map_err(|_| CoreError::Crypto(format!("invalid key version in KMS blob: {s:?}")))?;
    if v < 1 {
        return Err(CoreError::Crypto("invalid key version in KMS blob".into()));
    }
    Ok(v)
}

/// Read the key id + version a `ce1` or `dk1` blob was produced under — without
/// needing the key material, so a caller can fetch the right version first.
pub fn blob_key_ref(blob: &str) -> CoreResult<KmsKeyRef> {
    let prefix = blob.split('.').next().unwrap_or("");
    if prefix != ENCRYPT_PREFIX && prefix != DATAKEY_PREFIX {
        return Err(CoreError::Crypto(format!("not a KMS blob: {prefix:?}")));
    }
    let parts = split_blob(blob, prefix, 4)?;
    Ok(KmsKeyRef {
        key_id: parts[0].to_string(),
        version: parse_version(parts[1])?,
    })
}

fn random_bytes(n: usize) -> CoreResult<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; n]);
    getrandom::getrandom(&mut buf)
        .map_err(|e| CoreError::Crypto(format!("secure RNG unavailable: {e}")))?;
    Ok(buf)
}

impl Dek {
    /// Encrypt `plaintext` under this managed key, binding `context` as AAD.
    /// Returns a `ce1.` blob. `context` defaults to `""` (pass an empty string).
    pub fn kms_encrypt(
        &self,
        key_ref: &KmsKeyRef,
        plaintext: &[u8],
        context: &str,
    ) -> CoreResult<String> {
        let iv = random_bytes(IV_LENGTH)?;
        let ct = aes_gcm_encrypt(
            self.material(),
            &iv,
            plaintext,
            &encrypt_aad(key_ref, context),
        )?;
        Ok(join_blob(
            ENCRYPT_PREFIX,
            &key_ref.key_id,
            key_ref.version,
            &iv,
            &ct,
        ))
    }

    /// Decrypt a `ce1.` blob under this managed key. The caller must supply the
    /// material for the version named in the blob (see [`blob_key_ref`]) and the
    /// same `context` used to encrypt. Returns raw plaintext bytes.
    pub fn kms_decrypt(&self, blob: &str, context: &str) -> CoreResult<Zeroizing<Vec<u8>>> {
        let parts = split_blob(blob, ENCRYPT_PREFIX, 4)?;
        let key_ref = KmsKeyRef {
            key_id: parts[0].to_string(),
            version: parse_version(parts[1])?,
        };
        let iv = b64::decode(parts[2]).map_err(|e| CoreError::Crypto(format!("ce1 iv: {e}")))?;
        let ct = b64::decode(parts[3]).map_err(|e| CoreError::Crypto(format!("ce1 ct: {e}")))?;
        let pt = aes_gcm_decrypt(self.material(), &iv, &ct, &encrypt_aad(&key_ref, context))
            .map_err(|_| {
                CoreError::Crypto(
                    "KMS decryption failed: wrong key/version, tampered data, or mismatched context"
                        .into(),
                )
            })?;
        Ok(Zeroizing::new(pt))
    }

    /// Generate a fresh `n_bytes`-long data key wrapped under this managed key —
    /// the envelope pattern for bulk payloads (AWS KMS `GenerateDataKey`).
    /// Encrypt data with the returned `plaintext`, store `wrapped` beside it, and
    /// recover the key later with [`Dek::decrypt_data_key`].
    pub fn generate_data_key(&self, key_ref: &KmsKeyRef, n_bytes: usize) -> CoreResult<DataKey> {
        let plaintext = random_bytes(n_bytes)?;
        let iv = random_bytes(IV_LENGTH)?;
        let aad = data_key_aad(&key_ref.key_id, &key_ref.version.to_string());
        let ct = aes_gcm_encrypt(self.material(), &iv, &plaintext, &aad)?;
        Ok(DataKey {
            plaintext,
            wrapped: join_blob(DATAKEY_PREFIX, &key_ref.key_id, key_ref.version, &iv, &ct),
        })
    }

    /// Recover a data key previously produced by [`Dek::generate_data_key`].
    pub fn decrypt_data_key(&self, wrapped: &str) -> CoreResult<Zeroizing<Vec<u8>>> {
        let parts = split_blob(wrapped, DATAKEY_PREFIX, 4)?;
        let aad = data_key_aad(parts[0], parts[1]);
        let iv = b64::decode(parts[2]).map_err(|e| CoreError::Crypto(format!("dk1 iv: {e}")))?;
        let ct = b64::decode(parts[3]).map_err(|e| CoreError::Crypto(format!("dk1 ct: {e}")))?;
        let dk = aes_gcm_decrypt(self.material(), &iv, &ct, &aad).map_err(|_| {
            CoreError::Crypto("data key unwrap failed: wrong key or tampered blob".into())
        })?;
        Ok(Zeroizing::new(dk))
    }
}

/// Assemble `prefix.<keyId>.<version>.<iv>.<ct>` with base64url segments.
fn join_blob(prefix: &str, key_id: &str, version: u32, iv: &[u8], ct: &[u8]) -> String {
    format!(
        "{prefix}.{key_id}.{version}.{}.{}",
        b64::encode(iv),
        b64::encode(ct)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed 32-byte key, imported directly (bypassing the wd1 grant path) so
    // these unit tests need no ECDH setup. The cross-impl vectors in apps/kms
    // exercise the full grant → unwrap → operate chain against @seekrit/crypto.
    fn dek() -> Dek {
        Dek::from_material([7u8; 32])
    }

    #[test]
    fn encrypt_round_trips_with_context() {
        let d = dek();
        let key_ref = KmsKeyRef {
            key_id: "kms_abc".into(),
            version: 3,
        };
        let blob = d
            .kms_encrypt(&key_ref, b"hello bytes", "tenant=acme")
            .unwrap();
        assert!(blob.starts_with("ce1.kms_abc.3."));
        assert_eq!(blob_key_ref(&blob).unwrap(), key_ref);
        let pt = d.kms_decrypt(&blob, "tenant=acme").unwrap();
        assert_eq!(&pt[..], b"hello bytes");
    }

    #[test]
    fn wrong_context_fails() {
        let d = dek();
        let key_ref = KmsKeyRef {
            key_id: "kms_abc".into(),
            version: 1,
        };
        let blob = d.kms_encrypt(&key_ref, b"secret", "field=ssn").unwrap();
        assert!(d.kms_decrypt(&blob, "field=other").is_err());
        assert!(d.kms_decrypt(&blob, "").is_err());
    }

    #[test]
    fn data_key_round_trips() {
        let d = dek();
        let key_ref = KmsKeyRef {
            key_id: "kms_xyz".into(),
            version: 2,
        };
        let dk = d.generate_data_key(&key_ref, DATA_KEY_LENGTH).unwrap();
        assert!(dk.wrapped.starts_with("dk1.kms_xyz.2."));
        assert_eq!(dk.plaintext.len(), DATA_KEY_LENGTH);
        let recovered = d.decrypt_data_key(&dk.wrapped).unwrap();
        assert_eq!(&recovered[..], &dk.plaintext[..]);
    }

    #[test]
    fn blob_ref_rejects_non_kms() {
        assert!(blob_key_ref("sc1.iv.ct").is_err());
        assert!(blob_key_ref("ce1.kms_a.0.iv.ct").is_err()); // version < 1
    }
}
