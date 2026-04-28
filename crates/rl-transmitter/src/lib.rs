//! rl-transmitter: remote audio monitoring daemon.
//!
//! Captures audio from multiple inputs, encrypts and saves recordings,
//! and serves them to paired receivers over TLS.

use std::path::Path;
use std::sync::Arc;

use rl_audio::encoder::Bitrate;
use rl_audio::engine::AudioEngine;
use rl_core::config::Config;
use rl_core::device_id::DeviceId;
use rl_crypto::key::KeyPair;
use rl_net::connection::Connection;

pub mod discovery;
pub mod relay;
pub mod server;
pub mod upnp;

/// The transmitter application.
pub struct Transmitter {
    config: Config,
    device_id: DeviceId,
    keypair: KeyPair,
    /// Original certificate DER (preserved across restarts for stable Device ID).
    cert_der: Vec<u8>,
    /// Private signing key DER for TLS.
    signing_key_der: Vec<u8>,
    engine: AudioEngine,
    #[allow(dead_code)]
    connection: Option<Connection>,
}

/// Components needed to run the TLS server, produced by consuming a [`Transmitter`].
pub struct ServerComponents {
    pub state: Arc<server::TransmitterState>,
    pub tls_acceptor: tokio_rustls::TlsAcceptor,
    pub device_id: String,
    pub listen_port: u16,
    pub config: Config,
}

impl Transmitter {
    /// Create a new transmitter instance.
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        // Load or generate Device ID + certificate
        let cert_path = config.effective_cert_path();
        let device_id_path = config.keypair_path.with_extension("device_id");
        let (device_id, cert_der, signing_key_der) =
            Self::load_or_generate_device_id(&device_id_path, &cert_path)?;

        // Load or generate X25519 keypair
        let keypair = Self::load_or_generate_keypair(&config.keypair_path)?;

        Ok(Self {
            config,
            device_id,
            keypair,
            cert_der,
            signing_key_der,
            engine: AudioEngine::new(),
            connection: None,
        })
    }

    /// Consume self and produce the components needed to run the TLS server.
    pub fn into_server_components(self) -> Result<ServerComponents, rl_net::tls::TlsError> {
        let server_config = rl_net::tls::build_server_config(
            rustls::pki_types::PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(
                self.signing_key_der,
            )),
            self.cert_der,
        )?;
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let mut engine = self.engine;
        engine.set_keypair(&self.keypair);

        let state = Arc::new(server::TransmitterState::new(
            Arc::new(tokio::sync::Mutex::new(engine)),
            self.config.device_name.clone(),
            self.keypair,
            self.config.recording_dir.clone(),
            self.config.keypair_path.clone(),
        ));

        Ok(ServerComponents {
            state,
            tls_acceptor,
            device_id: self.device_id.display().to_string(),
            listen_port: self.config.listen_port,
            config: self.config,
        })
    }

    /// Get the device ID display string.
    pub fn device_id_display(&self) -> &str {
        self.device_id.display()
    }

    /// Get the keypair.
    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    /// Get the public key fingerprint.
    pub fn public_key_fingerprint(&self) -> [u8; 32] {
        self.keypair.fingerprint()
    }

    /// Get the certificate DER bytes.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// Add a test sine wave channel.
    pub fn add_test_channel(
        &mut self,
        channel_id: String,
        frequency: f64,
        bitrate: Bitrate,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.engine
            .add_test_channel(channel_id, frequency, bitrate)?;
        Ok(())
    }

    /// Remove a channel.
    pub fn remove_channel(&mut self, channel_id: &str) -> bool {
        self.engine.remove_channel(channel_id).is_some()
    }

    /// Number of channels.
    pub fn channel_count(&self) -> usize {
        self.engine.channel_count()
    }

    /// Get the audio engine.
    pub fn engine(&self) -> &AudioEngine {
        &self.engine
    }

    /// Get the audio engine mutably.
    pub fn engine_mut(&mut self) -> &mut AudioEngine {
        &mut self.engine
    }

    /// Get the listen port.
    pub fn listen_port(&self) -> u16 {
        self.config.listen_port
    }

    /// Get a reference to config.
    pub fn config(&self) -> &Config {
        &self.config
    }

    #[allow(clippy::type_complexity)]
    fn load_or_generate_device_id(
        device_id_path: &Path,
        cert_path: &Path,
    ) -> Result<(DeviceId, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let key_path = cert_path.with_extension("key");

        // Try to load existing key and cert from disk
        if key_path.exists() && cert_path.exists() {
            let key_pem = std::fs::read_to_string(&key_path).ok();
            let cert_der = std::fs::read(cert_path).ok();

            if let (Some(key_pem), Some(cert_der)) = (key_pem, cert_der) {
                if let Ok(key_pair) = rcgen::KeyPair::from_pem(&key_pem) {
                    let id = DeviceId::from_cert_der(&cert_der);
                    let signing_key_der = key_pair.serialize_der();

                    tracing::debug!("Loaded existing certificate from {:?}", cert_path);
                    return Ok((id, cert_der, signing_key_der));
                }
            }
            // If loading fails, fall through to generate new
            tracing::warn!(
                "Failed to load cert from {:?}, generating new one",
                cert_path
            );
        }

        // Generate new
        let (id, certified) = DeviceId::generate()?;
        if let Some(parent) = device_id_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let cert_der = certified.cert.der().to_vec();
        let signing_key_der = certified.signing_key.serialize_der();

        // Persist device ID string
        std::fs::write(device_id_path, id.display())?;

        // Persist cert DER (for stable Device ID) and key PEM
        std::fs::write(cert_path, &cert_der)?;
        std::fs::write(&key_path, certified.signing_key.serialize_pem())?;

        tracing::info!("Generated new certificate, saved to {:?}", cert_path);
        Ok((id, cert_der, signing_key_der))
    }

    fn load_or_generate_keypair(path: &Path) -> Result<KeyPair, Box<dyn std::error::Error>> {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return Ok(KeyPair::from_bytes(key));
            }
        }
        let keypair = KeyPair::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write with restrictive permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            std::fs::write(path, keypair.secret_bytes())?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path, keypair.secret_bytes())?;
        }
        Ok(keypair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn transmitter_starts() {
        let config = Config {
            device_name: "TestTransmitter".into(),
            listen_port: 22001,
            recording_dir: std::env::temp_dir().join("rl-test-tx"),
            auto_delete_days: 0,
            default_bitrate: 16,
            keypair_path: std::env::temp_dir().join("rl-test-tx-keypair.bin"),
            cert_path: PathBuf::new(),
            enable_upnp: false,
            discovery_server_url: String::new(),
            relay_url: String::new(),
        };
        let tx = Transmitter::new(config).unwrap();
        assert!(!tx.device_id_display().is_empty());
        assert_eq!(tx.listen_port(), 22001);
    }

    #[test]
    fn transmitter_adds_channels() {
        let config = Config {
            device_name: "TestTransmitter".into(),
            listen_port: 22002,
            recording_dir: std::env::temp_dir().join("rl-test-tx2"),
            auto_delete_days: 0,
            default_bitrate: 16,
            keypair_path: std::env::temp_dir().join("rl-test-tx2-keypair.bin"),
            cert_path: PathBuf::new(),
            enable_upnp: false,
            discovery_server_url: String::new(),
            relay_url: String::new(),
        };
        let mut tx = Transmitter::new(config).unwrap();
        tx.add_test_channel("ch-001".into(), 440.0, Bitrate::Kbps16)
            .unwrap();
        tx.add_test_channel("ch-002".into(), 880.0, Bitrate::Kbps32)
            .unwrap();
        assert_eq!(tx.channel_count(), 2);
    }

    #[test]
    fn transmitter_removes_channel() {
        let config = Config {
            device_name: "TestTransmitter".into(),
            listen_port: 22003,
            recording_dir: std::env::temp_dir().join("rl-test-tx3"),
            auto_delete_days: 0,
            default_bitrate: 16,
            keypair_path: std::env::temp_dir().join("rl-test-tx3-keypair.bin"),
            cert_path: PathBuf::new(),
            enable_upnp: false,
            discovery_server_url: String::new(),
            relay_url: String::new(),
        };
        let mut tx = Transmitter::new(config).unwrap();
        tx.add_test_channel("ch-001".into(), 440.0, Bitrate::Kbps16)
            .unwrap();
        tx.add_test_channel("ch-002".into(), 880.0, Bitrate::Kbps32)
            .unwrap();
        assert!(tx.remove_channel("ch-001"));
        assert_eq!(tx.channel_count(), 1);
        assert!(!tx.remove_channel("ch-001")); // already removed
    }
}
