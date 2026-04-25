//! TCP server for handling receiver connections.

use std::net::SocketAddr;

use tokio::net::TcpListener;

use rl_net::connection::Connection;

/// Run the transmitter's TCP server.
#[allow(dead_code)]
pub async fn run_server(
    addr: SocketAddr,
    device_id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Listening on {}", addr);

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        tracing::info!("Connection from {}", remote_addr);

        let device_id = device_id.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, device_id).await {
                tracing::error!("Connection error: {}", e);
            }
        });
    }
}

#[allow(dead_code)]
async fn handle_connection(
    _stream: tokio::net::TcpStream,
    device_id: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = Connection::new(device_id);
    conn.on_tls_established()?; // For now, skip actual TLS

    // Send HELLO
    let _hello_frame = conn.create_hello("0.1.0");
    // TODO: write hello_frame to stream

    Ok(())
}
