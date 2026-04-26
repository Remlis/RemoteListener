//! rl-discovery: Global discovery service for RemoteListener.
//!
//! Provides:
//! - **Server**: An HTTPS service that accepts device announcements and lookups
//! - **Client**: Transmitter announcement and receiver lookup functions
//!
//! API:
//! - `POST /announce` — Transmitter announces its address and device info
//! - `GET /lookup?device_id=<id>` — Receiver looks up a transmitter by device ID

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The default port for the discovery server.
pub const DEFAULT_PORT: u16 = 22001;

/// Maximum age of an announcement before it's considered stale (24 hours).
pub const ANNOUNCEMENT_TTL: Duration = Duration::from_secs(86400);

/// An announcement from a transmitter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announcement {
    /// The transmitter's device ID (Base32 with Luhn checksum).
    pub device_id: String,
    /// The transmitter's device name.
    pub device_name: String,
    /// The external address that receivers can connect to.
    pub address: String,
    /// The port number.
    pub port: u16,
    /// Timestamp of the announcement (seconds since epoch).
    pub timestamp: u64,
}

impl Announcement {
    /// Create a new announcement with the current timestamp.
    pub fn new(device_id: String, device_name: String, address: String, port: u16) -> Self {
        Self {
            device_id,
            device_name,
            address,
            port,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Check if this announcement has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.timestamp) > ANNOUNCEMENT_TTL.as_secs()
    }
}

/// Response to a lookup request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupResponse {
    /// The found announcement, if any.
    pub found: Option<Announcement>,
}

/// Client for interacting with the discovery server.
pub struct DiscoveryClient {
    http: reqwest::Client,
    base_url: String,
}

impl DiscoveryClient {
    /// Create a new discovery client pointing at the given server URL.
    pub fn new(server_url: &str) -> Self {
        let base_url = server_url.trim_end_matches('/').to_string();
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            base_url,
        }
    }

    /// Announce this transmitter to the discovery server.
    pub async fn announce(&self, announcement: &Announcement) -> Result<(), DiscoveryError> {
        let url = format!("{}/announce", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(announcement)
            .send()
            .await
            .map_err(DiscoveryError::Network)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(DiscoveryError::Server(format!("HTTP {}: {}", status, body)));
        }

        Ok(())
    }

    /// Look up a transmitter by device ID.
    pub async fn lookup(&self, device_id: &str) -> Result<Option<Announcement>, DiscoveryError> {
        let url = format!("{}/lookup?device_id={}", self.base_url, device_id);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(DiscoveryError::Network)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(DiscoveryError::Server(format!("HTTP {}: {}", status, body)));
        }

        let lookup_resp: LookupResponse = resp.json().await.map_err(DiscoveryError::Parse)?;

        Ok(lookup_resp.found)
    }

    /// Remove this transmitter's announcement from the discovery server.
    pub async fn unannounce(&self, device_id: &str) -> Result<(), DiscoveryError> {
        let url = format!("{}/unannounce?device_id={}", self.base_url, device_id);
        let resp = self
            .http
            .delete(&url)
            .send()
            .await
            .map_err(DiscoveryError::Network)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(DiscoveryError::Server(format!("HTTP {}: {}", status, body)));
        }

        Ok(())
    }
}

/// Errors from discovery operations.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("network error: {0}")]
    Network(#[source] reqwest::Error),
    #[error("server error: {0}")]
    Server(String),
    #[error("parse error: {0}")]
    Parse(#[source] reqwest::Error),
}

/// In-memory store for announcements on the server side.
pub struct AnnouncementStore {
    announcements: std::collections::HashMap<String, Announcement>,
}

impl AnnouncementStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            announcements: std::collections::HashMap::new(),
        }
    }

    /// Add or update an announcement.
    pub fn announce(&mut self, announcement: Announcement) {
        self.announcements
            .insert(announcement.device_id.clone(), announcement);
    }

    /// Look up a transmitter by device ID.
    pub fn lookup(&self, device_id: &str) -> Option<&Announcement> {
        self.announcements.get(device_id)
    }

    /// Remove an announcement.
    pub fn unannounce(&mut self, device_id: &str) -> bool {
        self.announcements.remove(device_id).is_some()
    }

    /// Remove expired announcements.
    pub fn cleanup_expired(&mut self) -> usize {
        let expired: Vec<String> = self
            .announcements
            .iter()
            .filter(|(_, a)| a.is_expired())
            .map(|(id, _)| id.clone())
            .collect();
        let count = expired.len();
        for id in expired {
            self.announcements.remove(&id);
        }
        count
    }

    /// Number of active announcements.
    pub fn len(&self) -> usize {
        self.announcements.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.announcements.is_empty()
    }
}

impl Default for AnnouncementStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcement_store_basic() {
        let mut store = AnnouncementStore::new();
        assert!(store.is_empty());

        let ann = Announcement::new(
            "ABCD-EFGH".to_string(),
            "TestDevice".to_string(),
            "1.2.3.4".to_string(),
            22000,
        );

        store.announce(ann);
        assert_eq!(store.len(), 1);

        let found = store.lookup("ABCD-EFGH");
        assert!(found.is_some());
        assert_eq!(found.unwrap().device_name, "TestDevice");

        assert!(store.unannounce("ABCD-EFGH"));
        assert!(store.is_empty());
    }

    #[test]
    fn announcement_store_overwrite() {
        let mut store = AnnouncementStore::new();

        let ann1 = Announcement::new(
            "ID1".to_string(),
            "Device1".to_string(),
            "1.2.3.4".to_string(),
            22000,
        );
        store.announce(ann1);

        let ann2 = Announcement::new(
            "ID1".to_string(),
            "Device1-Updated".to_string(),
            "5.6.7.8".to_string(),
            22001,
        );
        store.announce(ann2);

        assert_eq!(store.len(), 1);
        let found = store.lookup("ID1").unwrap();
        assert_eq!(found.device_name, "Device1-Updated");
        assert_eq!(found.port, 22001);
    }

    #[test]
    fn announcement_cleanup_expired() {
        let mut store = AnnouncementStore::new();

        let mut ann = Announcement::new(
            "EXPIRED".to_string(),
            "OldDevice".to_string(),
            "1.2.3.4".to_string(),
            22000,
        );
        // Make it expired
        ann.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - ANNOUNCEMENT_TTL.as_secs()
            - 1;

        store.announce(ann);
        assert_eq!(store.len(), 1);

        let cleaned = store.cleanup_expired();
        assert_eq!(cleaned, 1);
        assert!(store.is_empty());
    }

    #[test]
    fn lookup_missing_returns_none() {
        let store = AnnouncementStore::new();
        assert!(store.lookup("NONEXISTENT").is_none());
    }
}
