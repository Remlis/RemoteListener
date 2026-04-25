//! Transport trait and implementations.

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

/// A bidirectional transport for RLP frames.
#[async_trait]
pub trait Transport: Send + Sync {
    type ReadHalf: AsyncRead + Unpin + Send;
    type WriteHalf: AsyncWrite + Unpin + Send;

    async fn connect(
        &mut self,
        addr: &str,
    ) -> Result<(Self::ReadHalf, Self::WriteHalf), TransportError>;
    async fn listen(&mut self, port: u16) -> Result<(), TransportError>;
    async fn accept(&mut self) -> Result<(Self::ReadHalf, Self::WriteHalf), TransportError>;
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("listen failed: {0}")]
    ListenFailed(String),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Loopback transport for testing (in-process, no real network).
pub struct LoopbackTransport {
    listener: Option<tokio::net::TcpListener>,
}

impl Default for LoopbackTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopbackTransport {
    pub fn new() -> Self {
        Self { listener: None }
    }
}

#[async_trait]
impl Transport for LoopbackTransport {
    type ReadHalf = tokio::io::ReadHalf<tokio::io::DuplexStream>;
    type WriteHalf = tokio::io::WriteHalf<tokio::io::DuplexStream>;

    async fn connect(
        &mut self,
        _addr: &str,
    ) -> Result<(Self::ReadHalf, Self::WriteHalf), TransportError> {
        unimplemented!("Use accept for loopback testing")
    }

    async fn listen(&mut self, port: u16) -> Result<(), TransportError> {
        self.listener = Some(tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?);
        Ok(())
    }

    async fn accept(&mut self) -> Result<(Self::ReadHalf, Self::WriteHalf), TransportError> {
        // For testing, create a duplex stream pair
        let (_client, server) = tokio::io::duplex(65536);
        let (server_read, server_write) = tokio::io::split(server);
        Ok((server_read, server_write))
    }
}

/// Lossy transport wrapper — drops a percentage of frames (for testing).
pub struct LossyTransport<T: Transport> {
    #[allow(dead_code)]
    inner: T,
    #[allow(dead_code)]
    drop_rate: f64,
}

impl<T: Transport> LossyTransport<T> {
    pub fn new(inner: T, drop_rate: f64) -> Self {
        Self { inner, drop_rate }
    }
}

/// Latent transport wrapper — adds artificial delay (for testing).
pub struct LatentTransport<T: Transport> {
    #[allow(dead_code)]
    inner: T,
    #[allow(dead_code)]
    latency_ms: u64,
}

impl<T: Transport> LatentTransport<T> {
    pub fn new(inner: T, latency_ms: u64) -> Self {
        Self { inner, latency_ms }
    }
}
