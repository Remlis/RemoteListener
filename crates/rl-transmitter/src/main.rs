//! rl-transmitter: remote audio monitoring daemon.

use rl_core::config::Config;
use rl_transmitter::Transmitter;

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

    // TODO: Start audio capture, network server, tray
    println!("Transmitter running. Press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await.unwrap();
    println!("Shutting down.");
}
