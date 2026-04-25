//! Configuration: persistent settings for the transmitter.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level configuration for the transmitter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Device name shown to receivers during pairing.
    pub device_name: String,

    /// TCP listen port.
    pub listen_port: u16,

    /// Directory for encrypted recording files.
    pub recording_dir: PathBuf,

    /// Auto-delete recordings older than this many days (0 = never).
    pub auto_delete_days: u32,

    /// Default Opus bitrate in kbps (16/32/64/128).
    pub default_bitrate: u32,

    /// Path to the persistent keypair file.
    pub keypair_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            device_name: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "RemoteListener".into()),
            listen_port: 22000,
            recording_dir: dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("remotelistener")
                .join("recordings"),
            auto_delete_days: 0,
            default_bitrate: 16,
            keypair_path: dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("remotelistener")
                .join("keypair.bin"),
        }
    }
}

impl Config {
    /// Load config from a TOML file, falling back to defaults for missing fields.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            let config = Self::default();
            config.save(path)?;
            return Ok(config);
        }
        let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        let config: Self = toml::from_str(&text).map_err(ConfigError::Parse)?;
        Ok(config)
    }

    /// Save config to a TOML file.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(ConfigError::Io)?;
        }
        let text = toml::to_string_pretty(self).map_err(ConfigError::Serialize)?;
        std::fs::write(path, text).map_err(ConfigError::Io)?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[source] std::io::Error),
    #[error("TOML parse error: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("TOML serialization error: {0}")]
    Serialize(#[source] toml::ser::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let config = Config {
            device_name: "TestDevice".into(),
            listen_port: 22001,
            recording_dir: PathBuf::from("/tmp/rl-test"),
            auto_delete_days: 30,
            default_bitrate: 32,
            keypair_path: PathBuf::from("/tmp/rl-test/keypair.bin"),
        };

        config.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();

        assert_eq!(config.device_name, loaded.device_name);
        assert_eq!(config.listen_port, loaded.listen_port);
        assert_eq!(config.recording_dir, loaded.recording_dir);
        assert_eq!(config.auto_delete_days, loaded.auto_delete_days);
        assert_eq!(config.default_bitrate, loaded.default_bitrate);
        assert_eq!(config.keypair_path, loaded.keypair_path);
    }

    #[test]
    fn config_default_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        // Load from nonexistent file should create defaults
        let config = Config::load(&path).unwrap();
        assert!(!config.device_name.is_empty());
        assert_eq!(config.listen_port, 22000);
        assert!(path.exists());
    }
}
