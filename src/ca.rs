//! The local certificate authority used to intercept TLS in forward mode.
//!
//! To read the plaintext of an HTTPS request the proxy has to terminate TLS,
//! which means presenting a certificate the workload will trust for the host it
//! dialed. We do the standard MITM dance: a **local CA** (generated once and
//! persisted) that the operator installs into the workload's trust store, and a
//! per-host **leaf** certificate minted on demand and signed by that CA.
//!
//! The CA private key never leaves this host, and it only ever signs leaves for
//! hosts the config says to intercept. Everything is in-memory except the two
//! persisted CA files.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;

#[derive(Debug)]
pub enum CaError {
    Io(String),
    Cert(String),
    Tls(String),
}

impl std::fmt::Display for CaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaError::Io(m) => write!(f, "CA file error: {m}"),
            CaError::Cert(m) => write!(f, "certificate error: {m}"),
            CaError::Tls(m) => write!(f, "TLS config error: {m}"),
        }
    }
}

impl std::error::Error for CaError {}

/// The interception CA plus a cache of per-host TLS server configs.
pub struct Ca {
    cert: Certificate,
    key: KeyPair,
    cert_pem: String,
    /// host → a rustls `ServerConfig` presenting that host's minted leaf.
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl Ca {
    /// Load the CA from `cert_path`/`key_path`, generating and persisting a new
    /// one if either file is missing.
    pub fn load_or_generate(cert_path: &str, key_path: &str) -> Result<Ca, CaError> {
        let have_cert = std::path::Path::new(cert_path).exists();
        let have_key = std::path::Path::new(key_path).exists();
        if have_cert && have_key {
            Self::load(cert_path, key_path)
        } else {
            Self::generate(cert_path, key_path)
        }
    }

    fn load(cert_path: &str, key_path: &str) -> Result<Ca, CaError> {
        let key_pem = std::fs::read_to_string(key_path).map_err(|e| CaError::Io(e.to_string()))?;
        let cert_pem =
            std::fs::read_to_string(cert_path).map_err(|e| CaError::Io(e.to_string()))?;
        let key = KeyPair::from_pem(&key_pem).map_err(|e| CaError::Cert(e.to_string()))?;
        // Rebuild the issuer certificate from the persisted key + the same fixed
        // CA parameters. Same key + subject ⇒ leaves signed by it chain to the
        // on-disk CA the operator already trusts, so we don't need to parse the
        // stored X.509 (no x509-parser dependency). `cert_pem` from disk is the
        // one the operator installed; keep it for display.
        let cert = ca_params()?
            .self_signed(&key)
            .map_err(|e| CaError::Cert(e.to_string()))?;
        Ok(Ca::new(cert, key, cert_pem))
    }

    fn generate(cert_path: &str, key_path: &str) -> Result<Ca, CaError> {
        let key = KeyPair::generate().map_err(|e| CaError::Cert(e.to_string()))?;
        let cert = ca_params()?
            .self_signed(&key)
            .map_err(|e| CaError::Cert(e.to_string()))?;
        let cert_pem = cert.pem();

        std::fs::write(cert_path, &cert_pem).map_err(|e| CaError::Io(e.to_string()))?;
        write_private(key_path, &key.serialize_pem())?;

        Ok(Ca::new(cert, key, cert_pem))
    }

    fn new(cert: Certificate, key: KeyPair, cert_pem: String) -> Ca {
        Ca {
            cert,
            key,
            cert_pem,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The CA certificate in PEM — this is what the operator installs into the
    /// workload's trust store. It is not secret.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// A rustls `ServerConfig` presenting a freshly minted (and cached) leaf for
    /// `host`, so we can terminate TLS for that host.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, CaError> {
        if let Some(cfg) = self.cache.lock().unwrap().get(host).cloned() {
            return Ok(cfg);
        }
        let cfg = Arc::new(self.mint_server_config(host)?);
        self.cache
            .lock()
            .unwrap()
            .insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }

    fn mint_server_config(&self, host: &str) -> Result<ServerConfig, CaError> {
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| CaError::Cert(e.to_string()))?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);

        let leaf_key = KeyPair::generate().map_err(|e| CaError::Cert(e.to_string()))?;
        let leaf = params
            .signed_by(&leaf_key, &self.cert, &self.key)
            .map_err(|e| CaError::Cert(e.to_string()))?;

        let cert_chain: Vec<CertificateDer<'static>> = vec![leaf.der().clone()];
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        // Explicit provider so we never depend on a process-wide default.
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| CaError::Tls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .map_err(|e| CaError::Tls(e.to_string()))
    }
}

/// The fixed CA certificate parameters. Kept in one place so `generate` and
/// `load` produce a byte-identical subject (leaves must chain to the same CA).
fn ca_params() -> Result<CertificateParams, CaError> {
    let mut params =
        CertificateParams::new(Vec::new()).map_err(|e| CaError::Cert(e.to_string()))?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "seekrit-proxy local CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "seekrit");
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    Ok(params)
}

/// Write a file containing secret key material with `0600` perms on Unix.
fn write_private(path: &str, contents: &str) -> Result<(), CaError> {
    std::fs::write(path, contents).map_err(|e| CaError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| CaError::Io(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_persists_and_mints() {
        let dir =
            std::env::temp_dir().join(format!("seekrit-proxy-ca-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("ca.pem");
        let key = dir.join("ca-key.pem");
        let cert_s = cert.to_str().unwrap();
        let key_s = key.to_str().unwrap();

        // First call generates + persists.
        let ca = Ca::load_or_generate(cert_s, key_s).unwrap();
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(cert.exists() && key.exists());

        // Minting a leaf for a host builds a usable server config, and is cached.
        let c1 = ca.server_config("api.example.com").unwrap();
        let c2 = ca.server_config("api.example.com").unwrap();
        assert!(Arc::ptr_eq(&c1, &c2));

        // A second load reads the persisted CA back and can still mint.
        let ca2 = Ca::load_or_generate(cert_s, key_s).unwrap();
        assert_eq!(ca2.cert_pem(), ca.cert_pem());
        ca2.server_config("other.example.com").unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }
}
