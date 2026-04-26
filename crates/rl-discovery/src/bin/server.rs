//! rl-discovery-server: Global discovery server for RemoteListener.
//!
//! A simple HTTP server that accepts device announcements and lookups.
//! Designed to run as a single Docker container on a VPS.

use rl_discovery::{AnnouncementStore, DEFAULT_PORT};
use std::sync::Arc;
use tokio::sync::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Shared state for the discovery server.
struct ServerState {
    store: AnnouncementStore,
}

/// Simple HTTP server (no external HTTP framework needed for this scale).
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rl_discovery=info".into()),
        )
        .init();

    let port: u16 = std::env::var("RL_DISCOVERY_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await.unwrap_or_else(|e| {
        eprintln!("Failed to bind to {}: {}", addr, e);
        std::process::exit(1);
    });

    let state = Arc::new(Mutex::new(ServerState {
        store: AnnouncementStore::new(),
    }));

    // Periodic cleanup task
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let mut s = cleanup_state.lock().await;
            let removed = s.store.cleanup_expired();
            if removed > 0 {
                tracing::info!("Cleaned up {} expired announcements", removed);
            }
        }
    });

    tracing::info!("Discovery server listening on {}", addr);

    loop {
        let (stream, remote) = listener.accept().await.unwrap_or_else(|e| {
            tracing::error!("Accept error: {}", e);
            std::process::exit(1);
        });

        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, state).await {
                tracing::debug!("Connection from {} error: {}", remote, e);
            }
        });
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    state: Arc<Mutex<ServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut stream = stream;

    // Read the request
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        // Simple check: if we see \r\n\r\n, we have the headers
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            // Check for Content-Length to determine if there's a body
            break;
        }
        if buf.len() > 65536 {
            // Request too large
            send_response(&mut stream, 413, "Request too large").await?;
            return Ok(());
        }
    }

    let request_str = String::from_utf8_lossy(&buf);
    let mut lines = request_str.lines();

    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    let method = parts.first().unwrap_or(&"").to_string();
    let path = parts.get(1).unwrap_or(&"").to_string();

    // Parse Content-Length
    let content_length: usize = request_str
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);

    // Read body if needed
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len());
    let mut body = buf[header_end..].to_vec();

    while body.len() < content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }

    // CORS headers
    let cors = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n";

    // Handle OPTIONS (CORS preflight)
    if method == "OPTIONS" {
        send_raw_response(&mut stream, 204, "No Content", &cors, b"").await?;
        return Ok(());
    }

    match (method.as_str(), path.as_str()) {
        ("POST", "/announce") => {
            let ann: serde_json::Result<rl_discovery::Announcement> = serde_json::from_slice(&body);
            match ann {
                Ok(ann) => {
                    let mut s = state.lock().await;
                    s.store.announce(ann.clone());
                    tracing::info!(
                        "Announced: {} at {}:{}",
                        ann.device_id,
                        ann.address,
                        ann.port
                    );
                    send_response(&mut stream, 200, "OK").await?;
                }
                Err(e) => {
                    send_response(&mut stream, 400, &format!("Invalid JSON: {}", e)).await?;
                }
            }
        }
        ("GET", path) if path.starts_with("/lookup?device_id=") => {
            let device_id = path
                .strip_prefix("/lookup?device_id=")
                .unwrap_or("")
                .to_string();

            let s = state.lock().await;
            let found = s.store.lookup(&device_id);
            let resp = rl_discovery::LookupResponse {
                found: found.cloned(),
            };
            let json = serde_json::to_string(&resp).unwrap_or_default();
            send_json_response(&mut stream, 200, "OK", &cors, &json).await?;
        }
        ("DELETE", path) if path.starts_with("/unannounce?device_id=") => {
            let device_id = path
                .strip_prefix("/unannounce?device_id=")
                .unwrap_or("")
                .to_string();

            let mut s = state.lock().await;
            s.store.unannounce(&device_id);
            send_response(&mut stream, 200, "OK").await?;
        }
        ("GET", "/health") => {
            send_response(&mut stream, 200, "OK").await?;
        }
        _ => {
            send_response(&mut stream, 404, "Not Found").await?;
        }
    }

    Ok(())
}

async fn send_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    message: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let body = format!("{{\"status\": {}, \"message\": \"{}\"}}", status, message);
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
        status, message, body.len(), body
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

async fn send_json_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    message: &str,
    cors: &str,
    json: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}\r\n{}",
        status,
        message,
        json.len(),
        cors,
        json
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

async fn send_raw_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    message: &str,
    cors: &str,
    body: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n{}\r\n",
        status,
        message,
        body.len(),
        cors
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}
