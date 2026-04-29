//! rl-transmitter: remote audio monitoring daemon.

use rl_core::config::Config;
use rl_discovery::{Announcement, DiscoveryClient};
use rl_transmitter::discovery::DiscoveryService;
use rl_transmitter::server::run_server;
use rl_transmitter::upnp;
use rl_transmitter::Transmitter;
use rl_tray::TrayCommand;

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

    let mut tx = Transmitter::new(config).unwrap_or_else(|e| {
        eprintln!("Failed to start transmitter: {}", e);
        std::process::exit(1);
    });

    // Scan and register audio input devices
    // Use a timeout since CPAL device enumeration can hang on some macOS configs
    let scan_result = std::thread::scope(|_| {
        let handle = std::thread::spawn(rl_audio::engine::AudioEngine::scan_devices);
        for _ in 0..50 {
            if handle.is_finished() {
                return Some(handle.join().unwrap());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        tracing::warn!("Audio device scan timed out — continuing without audio devices");
        None
    });

    if let Some(Ok(devices)) = scan_result {
        let bitrate = rl_audio::encoder::Bitrate::from_kbps(tx.config().default_bitrate);
        for (i, device) in devices.iter().enumerate() {
            let channel_id = format!("ch-{:03}", i + 1);
            if let Err(e) = tx.engine_mut().add_device_channel(
                channel_id,
                &device.uid,
                device.name.clone(),
                bitrate,
            ) {
                tracing::warn!("Failed to add device {}: {}", device.name, e);
            } else {
                println!("Audio channel: {} ({})", device.name, device.uid);
            }
        }
        if devices.is_empty() {
            tracing::warn!("No audio input devices found");
        }
    } else if matches!(&scan_result, Some(Err(_))) {
        if let Some(Err(e)) = scan_result {
            tracing::warn!("Failed to scan audio devices: {}", e);
        }
    }

    // Save display values before consuming tx
    let device_id_str = tx.device_id_display().to_string();
    let listen_port = tx.listen_port();
    println!("Device ID: {}", device_id_str);
    println!("Listening on port {}", listen_port);
    println!(
        "Public key fingerprint: {:02x?}",
        tx.public_key_fingerprint()
    );

    // Start mDNS service advertisement
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], listen_port));
    let discovery = DiscoveryService::new(&tx.config().device_name, &device_id_str, addr)
        .unwrap_or_else(|e| {
            eprintln!("Failed to start mDNS discovery: {}", e);
            std::process::exit(1);
        });
    println!(
        "mDNS: advertising as {}.{}",
        discovery.service_name(),
        rl_transmitter::discovery::SERVICE_TYPE_SHORT
    );

    // Attempt UPnP port mapping for WAN access
    let port_mapping = if tx.config().enable_upnp {
        upnp::add_port_mapping(listen_port).await
    } else {
        None
    };

    // Determine external address for announcement
    let (external_addr, external_port) = if let Some(ref mapping) = port_mapping {
        println!("UPnP: external address {}", mapping.external_addr);
        (
            mapping.external_addr.ip().to_string(),
            mapping.external_addr.port(),
        )
    } else {
        println!("UPnP: not available (LAN-only mode)");
        (String::new(), listen_port)
    };

    // Announce to global discovery server
    let discovery_server_url = tx.config().discovery_server_url.clone();
    let discovery_client = if !discovery_server_url.is_empty() {
        Some(DiscoveryClient::new(&discovery_server_url))
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

        let device_name = tx.config().device_name.clone();
        let announcement =
            Announcement::new(device_id_str.clone(), device_name, address, external_port);

        match client.announce(&announcement).await {
            Ok(()) => println!("Discovery: announced to {}", discovery_server_url),
            Err(e) => tracing::warn!("Discovery: announce failed: {}", e),
        }
    }

    // Save remaining config values before consuming tx
    let auto_delete_days = tx.config().auto_delete_days;
    let recording_dir = tx.config().recording_dir.clone();

    // Consume tx to build TLS server components
    let components = tx.into_server_components().unwrap_or_else(|e| {
        eprintln!("Failed to build TLS server config: {}", e);
        std::process::exit(1);
    });

    println!("Transmitter running. Press Ctrl+C to stop.");

    // Start auto-delete background task
    if auto_delete_days > 0 {
        println!(
            "Auto-delete: recordings older than {} days will be removed",
            auto_delete_days
        );
        // Run once immediately at startup
        rl_transmitter::server::auto_delete_recordings(&recording_dir, auto_delete_days);
        tokio::spawn(rl_transmitter::server::run_auto_delete_task(
            recording_dir,
            auto_delete_days,
        ));
    }

    // Start the TLS server
    let server_addr = std::net::SocketAddr::from(([0, 0, 0, 0], components.listen_port));
    let state = components.state.clone();
    let relay_tls_acceptor = components.tls_acceptor.clone();
    let relay_url = components.config.relay_url.clone();
    tokio::spawn(run_server(
        server_addr,
        components.state,
        components.device_id,
        components.tls_acceptor,
    ));

    // Start system tray
    let tray_sender = match rl_tray::run_tray() {
        Ok((sender, action_receiver)) => {
            println!("System tray started.");
            // Handle tray actions on a background thread
            let tray_device_id_for_actions = device_id_str.clone();
            std::thread::spawn(move || {
                while let Ok(action) = action_receiver.recv() {
                    match action {
                        rl_tray::TrayAction::ShowDeviceId => {
                            #[cfg(target_os = "macos")]
                            {
                                use std::process::Command;
                                let child = Command::new("pbcopy")
                                    .stdin(std::process::Stdio::piped())
                                    .spawn()
                                    .ok();
                                if let Some(mut child) = child {
                                    use std::io::Write;
                                    if let Some(stdin) = child.stdin.as_mut() {
                                        let _ =
                                            stdin.write_all(tray_device_id_for_actions.as_bytes());
                                    }
                                    let _ = child.wait();
                                    println!(
                                        "Device ID copied to clipboard: {}",
                                        tray_device_id_for_actions
                                    );
                                }
                            }
                            #[cfg(not(target_os = "macos"))]
                            {
                                println!(
                                    "RemoteListener Device ID: {}\n\nUse this ID to pair from the iOS app.",
                                    tray_device_id_for_actions
                                );
                            }
                        }
                        rl_tray::TrayAction::OpenRecordingsDir => {
                            // Handled by the menu item text — user navigates manually
                        }
                        rl_tray::TrayAction::Quit => {}
                    }
                }
            });
            Some(sender)
        }
        Err(e) => {
            tracing::warn!("System tray not available: {}", e);
            None
        }
    };

    // Periodic tray status update
    let tray_device_id = device_id_str.clone();
    let tray_state = state.clone();
    if let Some(sender) = tray_sender.clone() {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                let mut status = tray_state.tray_status().await;
                status.device_id = tray_device_id.clone();
                if sender.send(TrayCommand::UpdateStatus(status)).is_err() {
                    break; // Tray closed
                }
            }
        });
    }

    // Start relay connection if configured
    if !relay_url.is_empty() {
        let relay_state = state.clone();
        let relay_device_id = device_id_str.clone();
        tokio::spawn(async move {
            loop {
                match parse_relay_url(&relay_url) {
                    Some(addr) => {
                        tracing::info!("Connecting to relay {}", addr);
                        match rl_transmitter::relay::join_relay(
                            addr,
                            relay_device_id.as_bytes(),
                            "",
                        )
                        .await
                        {
                            Ok(session) => {
                                tracing::info!(
                                    "Relay session established with {:02x?}...",
                                    &session.remote_device_id
                                        [..8.min(session.remote_device_id.len())]
                                );
                                // Wrap the raw TCP stream in TLS (as server)
                                let tls_stream =
                                    match relay_tls_acceptor.accept(session.stream).await {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::error!("Relay TLS handshake failed: {}", e);
                                            continue;
                                        }
                                    };
                                // Handle as a normal connection
                                if let Err(e) = rl_transmitter::server::handle_relay_connection(
                                    tls_stream,
                                    relay_state.clone(),
                                    relay_device_id.clone(),
                                )
                                .await
                                {
                                    tracing::error!("Relay connection error: {}", e);
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Relay connection failed: {}", e);
                            }
                        }
                    }
                    None => {
                        tracing::error!("Invalid relay URL: {}", relay_url);
                        break;
                    }
                }
                // Reconnect after delay
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
        });
    }

    tokio::signal::ctrl_c().await.unwrap();
    println!("Shutting down.");

    // Unannounce from global discovery server
    if let Some(client) = discovery_client {
        if let Err(e) = client.unannounce(&device_id_str).await {
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

/// Parse "relay://host:port" into a SocketAddr.
fn parse_relay_url(url: &str) -> Option<std::net::SocketAddr> {
    let url = url.strip_prefix("relay://")?;
    let (host, port_str) = url.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    let addr: std::net::IpAddr = host.parse().ok()?;
    Some(std::net::SocketAddr::new(addr, port))
}
