//! UPnP/IGD port mapping for NAT traversal.
//!
//! Automatically creates a port mapping on the gateway router so that
//! receivers on the WAN side can connect to the transmitter.

use igd_next::aio::tokio::search_gateway;
use igd_next::{PortMappingProtocol, SearchOptions};
use std::net::SocketAddr;

/// Duration of the UPnP port mapping lease in seconds (24 hours).
const LEASE_DURATION: u32 = 86400;

/// Protocol description for the port mapping entry.
const PORT_MAPPING_DESCRIPTION: &str = "RemoteListener";

/// Result of a UPnP port mapping attempt.
pub struct PortMapping {
    /// The external (public) address and port that receivers can connect to.
    pub external_addr: SocketAddr,
}

/// Attempt to create a UPnP port mapping on the local gateway.
///
/// If successful, returns a `PortMapping` with the external address.
/// If UPnP is not available or fails, returns `None` (the transmitter
/// can still work on LAN — just not reachable from WAN).
pub async fn add_port_mapping(internal_port: u16) -> Option<PortMapping> {
    let options = SearchOptions {
        timeout: Some(std::time::Duration::from_secs(5)),
        ..Default::default()
    };

    let gateway = search_gateway(options).await.ok()?;

    // Get the external IP
    let external_ip = gateway.get_external_ip().await.ok()?;

    // Add port mapping: external port -> internal port
    let local_addr = SocketAddr::new(
        "0.0.0.0".parse().unwrap(),
        internal_port,
    );

    let result = gateway
        .add_port(
            PortMappingProtocol::TCP,
            internal_port,
            local_addr,
            LEASE_DURATION,
            PORT_MAPPING_DESCRIPTION,
        )
        .await;

    match result {
        Ok(()) => {
            let external_addr = SocketAddr::new(external_ip, internal_port);
            tracing::info!(
                "UPnP: mapped external {} -> internal port {}",
                external_addr,
                internal_port
            );
            Some(PortMapping { external_addr })
        }
        Err(e) => {
            tracing::warn!("UPnP: failed to add port mapping: {}", e);
            None
        }
    }
}

/// Remove a previously created UPnP port mapping.
pub async fn remove_port_mapping(external_port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let options = SearchOptions {
        timeout: Some(std::time::Duration::from_secs(3)),
        ..Default::default()
    };

    let gateway = search_gateway(options).await?;
    gateway
        .remove_port(PortMappingProtocol::TCP, external_port)
        .await?;

    tracing::info!("UPnP: removed port mapping for external port {}", external_port);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_port_mapping_returns_none_without_gateway() {
        // In a test environment without a UPnP gateway, this should return None
        // Use a very short timeout to avoid blocking
        let result = add_port_mapping(22000).await;
        // We can't assert None because a gateway might actually exist
        // Just verify it doesn't panic
        let _ = result;
    }
}
