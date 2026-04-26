//! mDNS/DNS-SD service advertisement for local network discovery.
//!
//! Registers `_rllistener._tcp` via mDNS so iOS receivers on the same
//! LAN can auto-discover the transmitter without manual IP entry.

use mdns_sd::ServiceDaemon;
use std::collections::HashMap;
use std::net::SocketAddr;

/// The mDNS service type used by RemoteListener transmitters.
pub const SERVICE_TYPE: &str = "_rllistener._tcp.local.";

/// Short service type without .local. suffix (for display).
pub const SERVICE_TYPE_SHORT: &str = "_rllistener._tcp";

/// mDNS discovery advertiser for the transmitter.
pub struct DiscoveryService {
    /// The mDNS daemon handle.
    daemon: ServiceDaemon,
    /// The registered service name (instance name).
    service_name: String,
}

impl DiscoveryService {
    /// Start advertising the transmitter on the local network via mDNS.
    ///
    /// # Arguments
    /// * `device_name` - Human-readable name shown to receivers
    /// * `device_id` - Unique device identifier string
    /// * `addr` - The socket address the TCP server listens on
    pub fn new(
        device_name: &str,
        device_id: &str,
        addr: SocketAddr,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let daemon = ServiceDaemon::new()?;

        let port = addr.port();

        // Build TXT record with device metadata
        let mut properties = HashMap::new();
        properties.insert("device_name".to_string(), device_name.to_string());
        properties.insert("device_id".to_string(), device_id.to_string());

        // Use device_name as the instance name for easy identification
        let service_name = device_name.to_string();

        // Host name must end with .local. per mDNS spec
        let host_name = format!("{}.local.", service_name);

        let service_info = mdns_sd::ServiceInfo::new(
            SERVICE_TYPE,
            &service_name,
            &host_name,
            addr.ip(),
            port,
            properties,
        )?;

        daemon.register(service_info)?;

        tracing::info!(
            "mDNS: registered {}._rllistener._tcp on port {}",
            service_name,
            port
        );

        Ok(Self {
            daemon,
            service_name,
        })
    }

    /// Get the registered service name.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Stop advertising and shut down the mDNS daemon.
    pub fn stop(self) -> Result<(), Box<dyn std::error::Error>> {
        self.daemon.unregister(&format!("{}.{}.local.", self.service_name, SERVICE_TYPE))?;
        tracing::info!("mDNS: unregistered service");
        Ok(())
    }
}

impl Drop for DiscoveryService {
    fn drop(&mut self) {
        // Best-effort cleanup on drop
        let name = format!("{}.{}.local.", self.service_name, SERVICE_TYPE);
        if let Err(e) = self.daemon.unregister(&name) {
            tracing::debug!("mDNS: cleanup unregister failed: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn discovery_service_starts_and_stops() {
        let addr = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(192, 168, 1, 100),
            22000,
        ));
        let svc = DiscoveryService::new("TestDevice", "ABCD-EFGH", addr).unwrap();
        assert_eq!(svc.service_name(), "TestDevice");
        svc.stop().unwrap();
    }
}
