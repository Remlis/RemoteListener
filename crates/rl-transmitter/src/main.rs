//! rl-transmitter: remote audio monitoring daemon.

use rl_core::config::Config;
use rl_transmitter::Transmitter;
use rl_transmitter::discovery::DiscoveryService;

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

    println!("Transmitter running. Press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await.unwrap();
    println!("Shutting down.");

    // Stop mDNS advertisement
    if let Err(e) = discovery.stop() {
        tracing::warn!("mDNS shutdown error: {}", e);
    }
}
