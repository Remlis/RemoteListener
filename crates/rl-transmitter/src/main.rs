//! rl-transmitter: remote audio monitoring daemon.

use rl_core::config::Config;
use rl_transmitter::Transmitter;
use rl_transmitter::discovery::DiscoveryService;
use rl_transmitter::upnp;
use rl_discovery::{Announcement, DiscoveryClient};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rl_transmitter=info".into()),
        )
        .init();

    let config_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("remotelistener")
        .join("config.toml");

    let config = Config::load(&config_path).unwrap_or_else(|e| {
        eprintln!("Failed to load config: {}", e);
        Config::default()
    });

    let tx = Transmitter::new(config).unwrap_or_else(|e| {
        eprintln!("Failed to start transmitter: {}", e);
        std::process::exit(1);
    });

    println!("Device ID: {}", tx.device_id_display());
    println!("Listening on port {}", tx.listen_port());
    println!(
        "Public key fingerprint: {:02x?}",
        tx.public_key_fingerprint()
    );

    // Start mDNS service advertisement
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], tx.listen_port()));
    let discovery = DiscoveryService::new(
        &tx.config().device_name,
        tx.device_id_display(),
        addr,
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to start mDNS discovery: {}", e);
        std::process::exit(1);
    });
    println!("mDNS: advertising as {}.{}", discovery.service_name(), rl_transmitter::discovery::SERVICE_TYPE_SHORT);

    // Attempt UPnP port mapping for WAN access
    let port_mapping = if tx.config().enable_upnp {
        upnp::add_port_mapping(tx.listen_port()).await
    } else {
        None
    };

    // Determine external address for announcement
    let (external_addr, external_port) = if let Some(ref mapping) = port_mapping {
        println!("UPnP: external address {}", mapping.external_addr);
        (mapping.external_addr.ip().to_string(), mapping.external_addr.port())
    } else {
        println!("UPnP: not available (LAN-only mode)");
        (String::new(), tx.listen_port())
    };

    // Announce to global discovery server
    let discovery_client = if !tx.config().discovery_server_url.is_empty() {
        Some(DiscoveryClient::new(&tx.config().discovery_server_url))
    } else {
        None
    };

    if let Some(ref client) = discovery_client {
        let address = if external_addr.is_empty() {
            // No UPnP — the discovery server will see the source IP
            "0.0.0.0".to_string()
        } else {
            external_addr.clone()
        };

        let announcement = Announcement::new(
            tx.device_id_display().to_string(),
            tx.config().device_name.clone(),
            address,
            external_port,
        );

        match client.announce(&announcement).await {
            Ok(()) => println!("Discovery: announced to {}", tx.config().discovery_server_url),
            Err(e) => tracing::warn!("Discovery: announce failed: {}", e),
        }
    }

    println!("Transmitter running. Press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await.unwrap();
    println!("Shutting down.");

    // Unannounce from global discovery server
    if let Some(client) = discovery_client {
        if let Err(e) = client.unannounce(tx.device_id_display()).await {
            tracing::warn!("Discovery: unannounce failed: {}", e);
        }
    }

    // Remove UPnP port mapping
    if let Some(mapping) = port_mapping {
        if let Err(e) = upnp::remove_port_mapping(mapping.external_addr.port()).await {
            tracing::warn!("UPnP cleanup error: {}", e);
        }
    }

    // Stop mDNS advertisement
    if let Err(e) = discovery.stop() {
        tracing::warn!("mDNS shutdown error: {}", e);
    }
}
