//! rl-transmitter: remote audio monitoring daemon.
//!
//! Captures audio from multiple inputs, encrypts and saves recordings,
//! and serves them to paired receivers over TLS.

use std::path::Path;

use rl_audio::encoder::Bitrate;
use rl_audio::engine::AudioEngine;
use rl_core::config::Config;
use rl_core::device_id::DeviceId;
use rl_crypto::key::KeyPair;
use rl_net::connection::Connection;

#[allow(dead_code)]
mod server;

/// The transmitter application.
pub struct Transmitter {
    config: Config,
    device_id: DeviceId,
    keypair: KeyPair,
    engine: AudioEngine,
    #[allow(dead_code)]
    connection: Option<Connection>,
}

impl Transmitter {
    /// Create a new transmitter instance.
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        // Load or generate Device ID + certificate
        let device_id_path = config.keypair_path.with_extension("device_id");
        let (device_id, _cert) = Self::load_or_generate_device_id(&device_id_path)?;

        // Load or generate X25519 keypair
        let keypair = Self::load_or_generate_keypair(&config.keypair_path)?;

        Ok(Self {
            config,
            device_id,
            keypair,
            engine: AudioEngine::new(),
            connection: None,
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

    fn load_or_generate_device_id(
        path: &Path,
    ) -> Result<(DeviceId, rcgen::CertifiedKey<rcgen::KeyPair>), Box<dyn std::error::Error>> {
        if path.exists() {
            let text = std::fs::read_to_string(path)?;
            if let Ok(id) = text.trim().parse::<DeviceId>() {
                // Device ID exists but we don't have the cert — that's OK for display
                // Generate a new cert for TLS but keep the same ID display string
                let (_new_id, cert) = DeviceId::generate()?;
                // Return the persisted ID (but we lose the original cert — acceptable for now)
                return Ok((id, cert));
            }
        }
        let (id, cert) = DeviceId::generate()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, id.display())?;
        Ok((id, cert))
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

    #[test]
    fn transmitter_starts() {
        let config = Config {
            device_name: "TestTransmitter".into(),
            listen_port: 22001,
            recording_dir: std::env::temp_dir().join("rl-test-tx"),
            auto_delete_days: 0,
            default_bitrate: 16,
            keypair_path: std::env::temp_dir().join("rl-test-tx-keypair.bin"),
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
