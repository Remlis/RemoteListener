//! TLS configuration for RemoteListener's mutual-auth protocol.
//!
//! Uses self-signed Ed25519 certificates where identity is verified by
//! Device ID fingerprint (SHA-256 of cert DER), not by CA chain.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use sha2::{Digest, Sha256};

// Ensure a crypto provider is installed (ring, the default).
fn ensure_crypto_provider() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Compute the Device ID fingerprint from a certificate's DER bytes.
pub fn device_id_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Server-side: accept any client cert, extract Device ID
// ---------------------------------------------------------------------------

/// A [`rustls::server::danger::ClientCertVerifier`] that accepts any client
/// certificate. The extracted Device ID is available after the handshake via
/// [`peer_device_id`].
///
/// This is intentionally permissive — pairing/authentication is handled at
/// the application protocol level. A future version can restrict to a
/// whitelist of known Device IDs.
#[derive(Debug)]
pub struct AcceptAnyClientCertVerifier;

impl rustls::server::danger::ClientCertVerifier for AcceptAnyClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        // Client cert is optional — receivers may not present one initially.
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        // No CA roots — we accept any self-signed cert
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Accept any cert — the Device ID will be extracted after handshake
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// Build a [`rustls::ServerConfig`] for the transmitter server.
///
/// - Presents the given self-signed certificate
/// - Requests (but does not require) client certificates
/// - Sets ALPN to `rl/1.0`
/// - Uses [`AcceptAnyClientCertVerifier`]
pub fn build_server_config(
    certified_key: rustls::pki_types::PrivateKeyDer<'static>,
    cert_der: Vec<u8>,
) -> Result<rustls::ServerConfig, TlsError> {
    ensure_crypto_provider();

    let verifier = Arc::new(AcceptAnyClientCertVerifier);

    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from(cert_der)], certified_key)
        .map_err(|e| TlsError::Config(e.to_string()))?;

    config.alpn_protocols = vec![b"rl/1.0".to_vec()];

    Ok(config)
}

/// Extract the peer's Device ID fingerprint from a TLS connection's
/// presented client certificate. Returns `None` if no client cert was
/// presented.
pub fn peer_device_id(
    conn: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<[u8; 32]> {
    let (_, session) = conn.get_ref();
    let certs = session.peer_certificates()?;
    let end_entity = certs.first()?;
    Some(device_id_fingerprint(end_entity.as_ref()))
}

// ---------------------------------------------------------------------------
// Client-side: verify server cert by expected Device ID fingerprint
// ---------------------------------------------------------------------------

/// A [`rustls::client::danger::ServerCertVerifier`] that validates the
/// server's certificate by checking that its SHA-256 fingerprint matches
/// an expected Device ID.
#[derive(Debug)]
pub struct DeviceIdVerifier {
    expected_fingerprint: [u8; 32],
}

impl DeviceIdVerifier {
    pub fn new(expected_fingerprint: [u8; 32]) -> Self {
        Self {
            expected_fingerprint,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for DeviceIdVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fingerprint = device_id_fingerprint(end_entity.as_ref());
        if fingerprint == self.expected_fingerprint {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "Server certificate fingerprint does not match expected Device ID".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// Build a [`rustls::ClientConfig`] for connecting to a transmitter with a
/// known Device ID.
///
/// - Verifies server cert fingerprint matches `expected_fingerprint`
/// - Sets ALPN to `rl/1.0`
/// - Optionally presents a client certificate
pub fn build_client_config(
    expected_fingerprint: [u8; 32],
    client_key: Option<(rustls::pki_types::PrivateKeyDer<'static>, Vec<u8>)>,
) -> Result<rustls::ClientConfig, TlsError> {
    ensure_crypto_provider();

    let verifier = Arc::new(DeviceIdVerifier::new(expected_fingerprint));

    let builder = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier);

    let mut config = match client_key {
        Some((key, cert_der)) => builder
            .with_client_auth_cert(vec![CertificateDer::from(cert_der)], key)
            .map_err(|e| TlsError::Config(e.to_string()))?,
        None => builder.with_no_client_auth(),
    };

    config.alpn_protocols = vec![b"rl/1.0".to_vec()];

    Ok(config)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("TLS configuration error: {0}")]
    Config(String),
    #[error("TLS handshake failed: {0}")]
    Handshake(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;

    #[test]
    fn device_id_fingerprint_deterministic() {
        let (id, certified) = rl_core::device_id::DeviceId::generate().unwrap();
        let fp = device_id_fingerprint(certified.cert.der());
        assert_eq!(fp, *id.fingerprint());
    }

    #[test]
    fn device_id_verifier_accepts_matching() {
        let (id, certified) = rl_core::device_id::DeviceId::generate().unwrap();
        let fp = *id.fingerprint();
        let verifier = DeviceIdVerifier::new(fp);

        let cert_der = certified.cert.der().clone();
        let result = verifier.verify_server_cert(
            &cert_der,
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn device_id_verifier_rejects_mismatched() {
        let (_id1, certified1) = rl_core::device_id::DeviceId::generate().unwrap();
        let (id2, _certified2) = rl_core::device_id::DeviceId::generate().unwrap();
        let verifier = DeviceIdVerifier::new(*id2.fingerprint());

        let cert_der = certified1.cert.der().clone();
        let result = verifier.verify_server_cert(
            &cert_der,
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn build_server_config_works() {
        let (_id, certified) = rl_core::device_id::DeviceId::generate().unwrap();
        let _key_der = certified.signing_key.serialize_der();
        let cert_der = certified.cert.der().to_vec();

        let config = build_server_config(
            rustls::pki_types::PrivateKeyDer::from(certified.signing_key),
            cert_der,
        );
        assert!(config.is_ok());
    }

    #[test]
    fn build_client_config_works() {
        let (id, _certified) = rl_core::device_id::DeviceId::generate().unwrap();
        let config = build_client_config(*id.fingerprint(), None);
        assert!(config.is_ok());
    }
}
