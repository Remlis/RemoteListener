//! Syncthing relay client for NAT traversal.
//!
//! Implements the Syncthing relay protocol to allow two peers behind
//! different NATs to communicate through a public relay server.
//!
//! Protocol flow:
//! 1. "Server" peer joins a relay and waits for invitations
//! 2. "Client" peer sends ConnectRequest targeting the server's Device ID
//! 3. Relay sends SessionInvitation to both peers with session keys
//! 4. Both peers connect to the relay's session port (plain TCP) and join
//! 5. Relay proxies raw bytes bidirectionally

use std::io::{self, Read};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Magic number for the Syncthing relay protocol.
const MAGIC: u32 = 0x9E79BC40;

/// Maximum payload size for relay messages.
const MAX_MESSAGE_SIZE: usize = 1024;

// ---- Message Types ----

const TYPE_PING: i32 = 0;
const TYPE_PONG: i32 = 1;
const TYPE_JOIN_RELAY_REQUEST: i32 = 2;
const TYPE_JOIN_SESSION_REQUEST: i32 = 3;
const TYPE_RESPONSE: i32 = 4;
const TYPE_CONNECT_REQUEST: i32 = 5;
const TYPE_SESSION_INVITATION: i32 = 6;
const TYPE_RELAY_FULL: i32 = 7;

// ---- Response Codes ----

const CODE_SUCCESS: i32 = 0;
const _CODE_NOT_FOUND: i32 = 1;
const _CODE_ALREADY_CONNECTED: i32 = 2;
const _CODE_WRONG_TOKEN: i32 = 3;
const _CODE_UNEXPECTED: i32 = 100;

// ---- XDR Encoding Helpers ----

/// Encode a u32 in big-endian (XDR format).
fn encode_u32(val: u32) -> [u8; 4] {
    val.to_be_bytes()
}

/// Encode an i32 in big-endian (XDR format).
fn encode_i32(val: i32) -> [u8; 4] {
    val.to_be_bytes()
}

/// Encode length-prefixed bytes with XDR padding.
fn encode_bytes(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + data.len() + 4);
    buf.extend_from_slice(&encode_u32(data.len() as u32));
    buf.extend_from_slice(data);
    // Pad to 4-byte boundary
    let pad = (4 - (data.len() % 4)) % 4;
    buf.extend(std::iter::repeat_n(0u8, pad));
    buf
}

/// Encode the 12-byte message header.
fn encode_header(msg_type: i32, payload_len: usize) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&encode_u32(MAGIC));
    buf[4..8].copy_from_slice(&encode_i32(msg_type));
    buf[8..12].copy_from_slice(&encode_u32(payload_len as u32));
    buf
}

// ---- Message Types ----

/// A relay protocol message.
#[derive(Debug)]
pub enum RelayMessage {
    Ping,
    Pong,
    JoinRelayRequest {
        token: String,
    },
    JoinSessionRequest {
        key: Vec<u8>,
    },
    Response {
        code: i32,
        message: String,
    },
    ConnectRequest {
        id: Vec<u8>,
    },
    SessionInvitation {
        from: Vec<u8>,
        key: Vec<u8>,
        address: Vec<u8>,
        port: u16,
        server_socket: bool,
    },
    RelayFull,
}

impl RelayMessage {
    /// Encode this message into bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RelayMessage::Ping => {
                let header = encode_header(TYPE_PING, 0);
                header.to_vec()
            }
            RelayMessage::Pong => {
                let header = encode_header(TYPE_PONG, 0);
                header.to_vec()
            }
            RelayMessage::JoinRelayRequest { token } => {
                let payload = encode_bytes(token.as_bytes());
                let mut buf = encode_header(TYPE_JOIN_RELAY_REQUEST, payload.len()).to_vec();
                buf.extend_from_slice(&payload);
                buf
            }
            RelayMessage::JoinSessionRequest { key } => {
                let payload = encode_bytes(key);
                let mut buf = encode_header(TYPE_JOIN_SESSION_REQUEST, payload.len()).to_vec();
                buf.extend_from_slice(&payload);
                buf
            }
            RelayMessage::Response { code, message } => {
                let mut payload = Vec::new();
                payload.extend_from_slice(&encode_i32(*code));
                payload.extend(encode_bytes(message.as_bytes()));
                let mut buf = encode_header(TYPE_RESPONSE, payload.len()).to_vec();
                buf.extend_from_slice(&payload);
                buf
            }
            RelayMessage::ConnectRequest { id } => {
                let payload = encode_bytes(id);
                let mut buf = encode_header(TYPE_CONNECT_REQUEST, payload.len()).to_vec();
                buf.extend_from_slice(&payload);
                buf
            }
            RelayMessage::SessionInvitation {
                from,
                key,
                address,
                port,
                server_socket,
            } => {
                let mut payload = Vec::new();
                payload.extend(encode_bytes(from));
                payload.extend(encode_bytes(key));
                payload.extend(encode_bytes(address));
                payload.extend_from_slice(&encode_u32(*port as u32));
                payload.extend_from_slice(&encode_u32(if *server_socket { 1 } else { 0 }));
                let mut buf = encode_header(TYPE_SESSION_INVITATION, payload.len()).to_vec();
                buf.extend_from_slice(&payload);
                buf
            }
            RelayMessage::RelayFull => {
                let header = encode_header(TYPE_RELAY_FULL, 0);
                header.to_vec()
            }
        }
    }

    /// Decode a message from a reader.
    pub fn decode_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut header = [0u8; 12];
        reader.read_exact(&mut header)?;

        let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
        if magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid magic: 0x{:08X}", magic),
            ));
        }

        let msg_type = i32::from_be_bytes(header[4..8].try_into().unwrap());
        let payload_len = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;

        if payload_len > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Payload too large: {} bytes", payload_len),
            ));
        }

        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload)?;

        match msg_type {
            TYPE_PING => Ok(RelayMessage::Ping),
            TYPE_PONG => Ok(RelayMessage::Pong),
            TYPE_RELAY_FULL => Ok(RelayMessage::RelayFull),
            TYPE_JOIN_RELAY_REQUEST => {
                let token = decode_string(&payload)?;
                Ok(RelayMessage::JoinRelayRequest { token })
            }
            TYPE_JOIN_SESSION_REQUEST => {
                let key = decode_bytes(&payload)?;
                Ok(RelayMessage::JoinSessionRequest { key })
            }
            TYPE_RESPONSE => {
                if payload.len() < 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Response too short",
                    ));
                }
                let code = i32::from_be_bytes(payload[0..4].try_into().unwrap());
                let message = decode_string(&payload[4..])?;
                Ok(RelayMessage::Response { code, message })
            }
            TYPE_CONNECT_REQUEST => {
                let id = decode_bytes(&payload)?;
                Ok(RelayMessage::ConnectRequest { id })
            }
            TYPE_SESSION_INVITATION => {
                let (from, rest) = decode_bytes_with_rest(&payload)?;
                let (key, rest) = decode_bytes_with_rest(rest)?;
                let (address, rest) = decode_bytes_with_rest(rest)?;
                if rest.len() < 8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SessionInvitation too short",
                    ));
                }
                let port = u32::from_be_bytes(rest[0..4].try_into().unwrap()) as u16;
                let server_socket = u32::from_be_bytes(rest[4..8].try_into().unwrap()) != 0;
                Ok(RelayMessage::SessionInvitation {
                    from,
                    key,
                    address,
                    port,
                    server_socket,
                })
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown message type: {}", msg_type),
            )),
        }
    }
}

/// Decode a length-prefixed string from XDR payload.
fn decode_string(payload: &[u8]) -> io::Result<String> {
    let (bytes, _) = decode_bytes_with_rest(payload)?;
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Decode a length-prefixed byte array from XDR payload.
fn decode_bytes(payload: &[u8]) -> io::Result<Vec<u8>> {
    let (bytes, _) = decode_bytes_with_rest(payload)?;
    Ok(bytes)
}

/// Decode a length-prefixed byte array, returning remaining payload.
fn decode_bytes_with_rest(payload: &[u8]) -> io::Result<(Vec<u8>, &[u8])> {
    if payload.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Not enough data for length prefix",
        ));
    }
    let len = u32::from_be_bytes(payload[0..4].try_into().unwrap()) as usize;
    if payload.len() < 4 + len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Not enough data: need {} bytes, have {}",
                len,
                payload.len() - 4
            ),
        ));
    }
    let data = payload[4..4 + len].to_vec();
    let padded_len = 4 + len + (4 - (len % 4)) % 4;
    let rest = if payload.len() > padded_len {
        &payload[padded_len..]
    } else {
        &[]
    };
    Ok((data, rest))
}

/// Result of a relay session establishment.
pub struct RelaySession {
    /// The TCP stream for bidirectional data relay.
    pub stream: TcpStream,
    /// The remote peer's device ID.
    pub remote_device_id: Vec<u8>,
}

/// Information about a relay server from the pool API.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RelayInfo {
    pub url: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RelayPoolResponse {
    pub relays: Vec<RelayInfo>,
}

/// Fetch the list of available relays from the Syncthing relay pool.
pub async fn fetch_relay_pool() -> Result<Vec<RelayInfo>, RelayError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(RelayError::Http)?;

    let resp: RelayPoolResponse = client
        .get("https://relays.syncthing.net/endpoint")
        .send()
        .await
        .map_err(RelayError::Http)?
        .json()
        .await
        .map_err(RelayError::Http)?;

    Ok(resp.relays)
}

/// Join a relay as a "server" (waiting for incoming connections).
///
/// Returns when a peer connects through the relay, providing
/// a `RelaySession` with the established TCP stream.
pub async fn join_relay(
    relay_addr: SocketAddr,
    _device_id: &[u8],
    _token: &str,
) -> Result<RelaySession, RelayError> {
    // Connect to relay via TCP (TODO: add TLS with ALPN "bep-relay")
    let mut stream = TcpStream::connect(relay_addr)
        .await
        .map_err(RelayError::Io)?;

    tracing::info!("Connected to relay {}", relay_addr);

    // Send JoinRelayRequest
    let join_msg = RelayMessage::JoinRelayRequest {
        token: _token.to_string(),
    };
    stream
        .write_all(&join_msg.encode())
        .await
        .map_err(RelayError::Io)?;

    // Wait for Response
    let msg = read_message(&mut stream).await?;
    match msg {
        RelayMessage::Response { code, message } if code == CODE_SUCCESS => {
            tracing::info!("Joined relay successfully: {}", message);
        }
        RelayMessage::Response { code, message } => {
            return Err(RelayError::Protocol(format!(
                "Join failed: code={} message={}",
                code, message
            )));
        }
        RelayMessage::RelayFull => {
            return Err(RelayError::Protocol("Relay is full".to_string()));
        }
        other => {
            return Err(RelayError::Protocol(format!(
                "Unexpected message: {:?}",
                other
            )));
        }
    }

    // Wait for SessionInvitation (from a connecting peer)
    loop {
        let msg = read_message(&mut stream).await?;
        match msg {
            RelayMessage::Ping => {
                let pong = RelayMessage::Pong;
                stream
                    .write_all(&pong.encode())
                    .await
                    .map_err(RelayError::Io)?;
            }
            RelayMessage::SessionInvitation {
                from,
                key,
                address,
                port,
                server_socket: _,
            } => {
                tracing::info!("Received session invitation from peer");

                // Connect to the session port (plain TCP)
                let session_addr = if address.is_empty() || address == vec![0u8, 0, 0, 0] {
                    // Use relay's IP
                    SocketAddr::new(relay_addr.ip(), port)
                } else if address.len() == 4 {
                    let ip =
                        std::net::Ipv4Addr::new(address[0], address[1], address[2], address[3]);
                    SocketAddr::new(std::net::IpAddr::V4(ip), port)
                } else if address.len() == 16 {
                    let octets: [u8; 16] = address.try_into().unwrap_or([0; 16]);
                    let ip = std::net::Ipv6Addr::from(octets);
                    SocketAddr::new(std::net::IpAddr::V6(ip), port)
                } else {
                    SocketAddr::new(relay_addr.ip(), port)
                };

                let mut session_stream = TcpStream::connect(session_addr)
                    .await
                    .map_err(RelayError::Io)?;

                // Send JoinSessionRequest
                let join_session = RelayMessage::JoinSessionRequest { key };
                session_stream
                    .write_all(&join_session.encode())
                    .await
                    .map_err(RelayError::Io)?;

                // Wait for Response
                let mut buf = Vec::new();
                // Read enough for a response message
                let mut tmp = [0u8; 1024];
                let n = session_stream
                    .read(&mut tmp)
                    .await
                    .map_err(RelayError::Io)?;
                buf.extend_from_slice(&tmp[..n]);

                let resp = RelayMessage::decode_from(&mut buf.as_slice()).map_err(|e| {
                    RelayError::Protocol(format!("Failed to decode response: {}", e))
                })?;

                match resp {
                    RelayMessage::Response { code, message } if code == CODE_SUCCESS => {
                        tracing::info!("Session joined: {}", message);
                        return Ok(RelaySession {
                            stream: session_stream,
                            remote_device_id: from,
                        });
                    }
                    RelayMessage::Response { code, message } => {
                        return Err(RelayError::Protocol(format!(
                            "Session join failed: code={} message={}",
                            code, message
                        )));
                    }
                    other => {
                        return Err(RelayError::Protocol(format!(
                            "Unexpected session response: {:?}",
                            other
                        )));
                    }
                }
            }
            other => {
                tracing::warn!(
                    "Unexpected message while waiting for invitation: {:?}",
                    other
                );
            }
        }
    }
}

/// Connect to a peer through a relay as a "client" (initiator).
pub async fn connect_via_relay(
    relay_addr: SocketAddr,
    target_device_id: &[u8],
    _token: &str,
) -> Result<RelaySession, RelayError> {
    // Connect to relay via TCP (TODO: add TLS with ALPN "bep-relay")
    let mut stream = TcpStream::connect(relay_addr)
        .await
        .map_err(RelayError::Io)?;

    tracing::info!("Connected to relay {}", relay_addr);

    // Send ConnectRequest
    let connect_msg = RelayMessage::ConnectRequest {
        id: target_device_id.to_vec(),
    };
    stream
        .write_all(&connect_msg.encode())
        .await
        .map_err(RelayError::Io)?;

    // Wait for SessionInvitation
    let msg = read_message(&mut stream).await?;
    let (from, key, address, port) = match msg {
        RelayMessage::SessionInvitation {
            from,
            key,
            address,
            port,
            server_socket: _,
        } => {
            tracing::info!("Received session invitation from relay");
            (from, key, address, port)
        }
        RelayMessage::Response { code, message } => {
            return Err(RelayError::Protocol(format!(
                "Connect failed: code={} message={}",
                code, message
            )));
        }
        RelayMessage::RelayFull => {
            return Err(RelayError::Protocol("Relay is full".to_string()));
        }
        other => {
            return Err(RelayError::Protocol(format!(
                "Unexpected message: {:?}",
                other
            )));
        }
    };

    // Connect to session port
    let session_addr = if address.is_empty() || address == vec![0u8, 0, 0, 0] {
        SocketAddr::new(relay_addr.ip(), port)
    } else if address.len() == 4 {
        let ip = std::net::Ipv4Addr::new(address[0], address[1], address[2], address[3]);
        SocketAddr::new(std::net::IpAddr::V4(ip), port)
    } else if address.len() == 16 {
        let octets: [u8; 16] = address.try_into().unwrap_or([0; 16]);
        let ip = std::net::Ipv6Addr::from(octets);
        SocketAddr::new(std::net::IpAddr::V6(ip), port)
    } else {
        SocketAddr::new(relay_addr.ip(), port)
    };

    let mut session_stream = TcpStream::connect(session_addr)
        .await
        .map_err(RelayError::Io)?;

    // Send JoinSessionRequest
    let join_session = RelayMessage::JoinSessionRequest { key };
    session_stream
        .write_all(&join_session.encode())
        .await
        .map_err(RelayError::Io)?;

    // Wait for Response
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let n = session_stream
        .read(&mut tmp)
        .await
        .map_err(RelayError::Io)?;
    buf.extend_from_slice(&tmp[..n]);

    let resp = RelayMessage::decode_from(&mut buf.as_slice())
        .map_err(|e| RelayError::Protocol(format!("Failed to decode response: {}", e)))?;

    match resp {
        RelayMessage::Response { code, message } if code == CODE_SUCCESS => {
            tracing::info!("Session joined: {}", message);
            Ok(RelaySession {
                stream: session_stream,
                remote_device_id: from,
            })
        }
        RelayMessage::Response { code, message } => Err(RelayError::Protocol(format!(
            "Session join failed: code={} message={}",
            code, message
        ))),
        other => Err(RelayError::Protocol(format!(
            "Unexpected session response: {:?}",
            other
        ))),
    }
}

/// Read a relay message from an async TCP stream.
async fn read_message(stream: &mut TcpStream) -> Result<RelayMessage, RelayError> {
    // Read header
    let mut header = [0u8; 12];
    stream
        .read_exact(&mut header)
        .await
        .map_err(RelayError::Io)?;

    let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
    if magic != MAGIC {
        return Err(RelayError::Protocol(format!(
            "Invalid magic: 0x{:08X}",
            magic
        )));
    }

    let _msg_type = i32::from_be_bytes(header[4..8].try_into().unwrap());
    let payload_len = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;

    if payload_len > MAX_MESSAGE_SIZE {
        return Err(RelayError::Protocol(format!(
            "Payload too large: {} bytes",
            payload_len
        )));
    }

    // Read payload
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream
            .read_exact(&mut payload)
            .await
            .map_err(RelayError::Io)?;
    }

    // Decode using the sync decoder
    RelayMessage::decode_from(&mut payload.as_slice())
        .map_err(|e| RelayError::Protocol(format!("Decode error: {}", e)))
}

/// Errors from relay operations.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("IO error: {0}")]
    Io(#[source] io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("HTTP error: {0}")]
    Http(#[source] reqwest::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_ping() {
        let msg = RelayMessage::Ping;
        let encoded = msg.encode();
        assert_eq!(encoded.len(), 12); // header only
        assert_eq!(&encoded[0..4], &MAGIC.to_be_bytes());
        assert_eq!(&encoded[4..8], &TYPE_PING.to_be_bytes());
        assert_eq!(&encoded[8..12], &0u32.to_be_bytes());

        let decoded = RelayMessage::decode_from(&mut encoded.as_slice()).unwrap();
        if let RelayMessage::Ping = decoded {
            // OK
        } else {
            panic!("Expected Ping, got {:?}", decoded);
        }
    }

    #[test]
    fn encode_decode_pong() {
        let msg = RelayMessage::Pong;
        let encoded = msg.encode();
        let decoded = RelayMessage::decode_from(&mut encoded.as_slice()).unwrap();
        if let RelayMessage::Pong = decoded {
            // OK
        } else {
            panic!("Expected Pong, got {:?}", decoded);
        }
    }

    #[test]
    fn encode_decode_join_relay_request() {
        let msg = RelayMessage::JoinRelayRequest {
            token: "test-token".to_string(),
        };
        let encoded = msg.encode();
        let decoded = RelayMessage::decode_from(&mut encoded.as_slice()).unwrap();
        if let RelayMessage::JoinRelayRequest { token } = decoded {
            assert_eq!(token, "test-token");
        } else {
            panic!("Expected JoinRelayRequest, got {:?}", decoded);
        }
    }

    #[test]
    fn encode_decode_connect_request() {
        let id = vec![1u8; 32];
        let msg = RelayMessage::ConnectRequest { id: id.clone() };
        let encoded = msg.encode();
        let decoded = RelayMessage::decode_from(&mut encoded.as_slice()).unwrap();
        if let RelayMessage::ConnectRequest { id: decoded_id } = decoded {
            assert_eq!(decoded_id, id);
        } else {
            panic!("Expected ConnectRequest, got {:?}", decoded);
        }
    }

    #[test]
    fn encode_decode_session_invitation() {
        let msg = RelayMessage::SessionInvitation {
            from: vec![1u8; 32],
            key: vec![2u8; 32],
            address: vec![192, 168, 1, 1],
            port: 22067,
            server_socket: true,
        };
        let encoded = msg.encode();
        let decoded = RelayMessage::decode_from(&mut encoded.as_slice()).unwrap();
        if let RelayMessage::SessionInvitation {
            from,
            key,
            address,
            port,
            server_socket,
        } = decoded
        {
            assert_eq!(from, vec![1u8; 32]);
            assert_eq!(key, vec![2u8; 32]);
            assert_eq!(address, vec![192, 168, 1, 1]);
            assert_eq!(port, 22067);
            assert!(server_socket);
        } else {
            panic!("Expected SessionInvitation, got {:?}", decoded);
        }
    }

    #[test]
    fn encode_decode_response() {
        let msg = RelayMessage::Response {
            code: 0,
            message: "success".to_string(),
        };
        let encoded = msg.encode();
        let decoded = RelayMessage::decode_from(&mut encoded.as_slice()).unwrap();
        if let RelayMessage::Response { code, message } = decoded {
            assert_eq!(code, 0);
            assert_eq!(message, "success");
        } else {
            panic!("Expected Response, got {:?}", decoded);
        }
    }

    #[test]
    fn invalid_magic_rejected() {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        buf[4..8].copy_from_slice(&TYPE_PING.to_be_bytes());
        buf[8..12].copy_from_slice(&0u32.to_be_bytes());
        let result = RelayMessage::decode_from(&mut buf.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn xdr_padding_roundtrip() {
        // Test with data that's not a multiple of 4
        let msg = RelayMessage::JoinRelayRequest {
            token: "abc".to_string(), // 3 bytes -> 1 byte padding
        };
        let encoded = msg.encode();
        let decoded = RelayMessage::decode_from(&mut encoded.as_slice()).unwrap();
        if let RelayMessage::JoinRelayRequest { token } = decoded {
            assert_eq!(token, "abc");
        } else {
            panic!("Expected JoinRelayRequest");
        }
    }
}
