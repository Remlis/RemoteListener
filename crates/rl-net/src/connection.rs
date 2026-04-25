//! Connection state machine: Connecting → Hello → Paired → Ready.

use rl_core::proto::*;

use crate::frame;
use crate::frame::FrameError;

/// Connection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state, waiting for TLS handshake.
    Connecting,
    /// TLS established, waiting for HELLO exchange.
    Hello,
    /// Paired and ready for normal communication.
    Ready,
    /// Connection closed.
    Closed,
}

/// Events from the connection state machine.
#[derive(Debug)]
pub enum ConnectionEvent {
    /// Remote sent a HELLO message.
    HelloReceived {
        device_name: String,
        version: String,
    },
    /// Pairing requested by remote.
    PairRequested {
        device_name: String,
        public_key: Vec<u8>,
    },
    /// Pairing confirmed.
    PairConfirmed { accepted: bool },
    /// Unpaired.
    Unpaired { fingerprint: Vec<u8> },
    /// Ping received.
    PingReceived { timestamp: i64 },
    /// Connection closed by remote.
    Closed { reason: String },
    /// Received a message that doesn't belong in current state.
    UnexpectedMessage {
        state: ConnectionState,
        msg_type: MessageType,
    },
}

/// Connection state machine.
pub struct Connection {
    state: ConnectionState,
    device_id: String,
    remote_device_name: Option<String>,
}

impl Connection {
    pub fn new(device_id: String) -> Self {
        Self {
            state: ConnectionState::Connecting,
            device_id,
            remote_device_name: None,
        }
    }

    pub fn state(&self) -> &ConnectionState {
        &self.state
    }

    /// Transition to Hello state (after TLS handshake completes).
    pub fn on_tls_established(&mut self) -> Result<(), FrameError> {
        match self.state {
            ConnectionState::Connecting => {
                self.state = ConnectionState::Hello;
                Ok(())
            }
            _ => Err(FrameError::InvalidBody), // Wrong state
        }
    }

    /// Create a HELLO message for this device.
    pub fn create_hello(&self, version: &str) -> Vec<u8> {
        let hello = Hello {
            device_name: self.device_id.clone(),
            client_version: version.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        };
        frame::encode_message(MessageType::Hello, &hello)
    }

    /// Process an incoming frame and return any events.
    pub fn handle_frame(
        &mut self,
        decoded: &frame::DecodedFrame,
    ) -> Result<Vec<ConnectionEvent>, FrameError> {
        let msg_type =
            MessageType::try_from(decoded.header.r#type).map_err(|_| FrameError::InvalidHeader)?;

        let mut events = Vec::new();

        match msg_type {
            MessageType::Hello => {
                if self.state == ConnectionState::Hello {
                    let hello: Hello = frame::decode_message(decoded)?;
                    self.remote_device_name = Some(hello.device_name.clone());
                    self.state = ConnectionState::Ready;
                    events.push(ConnectionEvent::HelloReceived {
                        device_name: hello.device_name,
                        version: hello.client_version,
                    });
                } else {
                    events.push(ConnectionEvent::UnexpectedMessage {
                        state: self.state.clone(),
                        msg_type,
                    });
                }
            }
            MessageType::PairRequest => {
                let req: PairRequest = frame::decode_message(decoded)?;
                events.push(ConnectionEvent::PairRequested {
                    device_name: req.device_name,
                    public_key: req.public_key,
                });
            }
            MessageType::PairConfirm => {
                let conf: PairConfirm = frame::decode_message(decoded)?;
                events.push(ConnectionEvent::PairConfirmed {
                    accepted: conf.accepted,
                });
            }
            MessageType::Unpair => {
                let unpair: Unpair = frame::decode_message(decoded)?;
                events.push(ConnectionEvent::Unpaired {
                    fingerprint: unpair.public_key_fingerprint,
                });
            }
            MessageType::Ping => {
                let ping: Ping = frame::decode_message(decoded)?;
                events.push(ConnectionEvent::PingReceived {
                    timestamp: ping.timestamp,
                });
            }
            MessageType::Close => {
                let close: Close = frame::decode_message(decoded)?;
                self.state = ConnectionState::Closed;
                events.push(ConnectionEvent::Closed {
                    reason: close.reason,
                });
            }
            _ => {
                // Other messages are valid in Ready state
            }
        }

        Ok(events)
    }

    /// Create a PING message.
    pub fn create_ping(&self) -> Vec<u8> {
        let ping = Ping {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        };
        frame::encode_message(MessageType::Ping, &ping)
    }

    /// Create a CLOSE message.
    pub fn create_close(&self, reason: &str) -> Vec<u8> {
        let close = Close {
            reason: reason.to_string(),
        };
        frame::encode_message(MessageType::Close, &close)
    }

    /// Create a PAIR_RESPONSE message.
    pub fn create_pair_response(
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        existing_fingerprints: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let resp = PairResponse {
            public_key,
            private_key,
            existing_key_fingerprints: existing_fingerprints,
        };
        frame::encode_message(MessageType::PairResponse, &resp)
    }

    /// Create a PAIR_CONFIRM message.
    pub fn create_pair_confirm(accepted: bool) -> Vec<u8> {
        let conf = PairConfirm { accepted };
        frame::encode_message(MessageType::PairConfirm, &conf)
    }

    /// Create an UNPAIR message.
    pub fn create_unpair(fingerprint: Vec<u8>) -> Vec<u8> {
        let unpair = Unpair {
            public_key_fingerprint: fingerprint,
        };
        frame::encode_message(MessageType::Unpair, &unpair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_transitions() {
        let mut conn = Connection::new("device-001".into());
        assert_eq!(conn.state(), &ConnectionState::Connecting);

        conn.on_tls_established().unwrap();
        assert_eq!(conn.state(), &ConnectionState::Hello);
    }

    #[test]
    fn hello_exchange() {
        let mut conn = Connection::new("device-001".into());
        conn.on_tls_established().unwrap();

        // Simulate receiving a HELLO
        let remote_hello = Hello {
            device_name: "iPhone".into(),
            client_version: "0.1.0".into(),
            timestamp: 12345,
        };
        let frame_bytes = frame::encode_message(MessageType::Hello, &remote_hello);
        let (decoded, _) = frame::decode_frame(&frame_bytes).unwrap().unwrap();

        let events = conn.handle_frame(&decoded).unwrap();
        assert_eq!(conn.state(), &ConnectionState::Ready);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn ping_pong() {
        let mut conn = Connection::new("device-001".into());
        conn.on_tls_established().unwrap();

        // Receive a HELLO first to get to Ready state
        let hello = Hello {
            device_name: "test".into(),
            client_version: "1".into(),
            timestamp: 0,
        };
        let frame_bytes = frame::encode_message(MessageType::Hello, &hello);
        let (decoded, _) = frame::decode_frame(&frame_bytes).unwrap().unwrap();
        conn.handle_frame(&decoded).unwrap();

        // Now receive a PING
        let ping = Ping { timestamp: 99999 };
        let frame_bytes = frame::encode_message(MessageType::Ping, &ping);
        let (decoded, _) = frame::decode_frame(&frame_bytes).unwrap().unwrap();
        let events = conn.handle_frame(&decoded).unwrap();

        assert!(
            matches!(&events[0], ConnectionEvent::PingReceived { timestamp } if *timestamp == 99999)
        );
    }

    #[test]
    fn close_transitions_to_closed() {
        let mut conn = Connection::new("device-001".into());
        conn.on_tls_established().unwrap();

        let hello = Hello {
            device_name: "test".into(),
            client_version: "1".into(),
            timestamp: 0,
        };
        let frame_bytes = frame::encode_message(MessageType::Hello, &hello);
        let (decoded, _) = frame::decode_frame(&frame_bytes).unwrap().unwrap();
        conn.handle_frame(&decoded).unwrap();

        let close = Close {
            reason: "bye".into(),
        };
        let frame_bytes = frame::encode_message(MessageType::Close, &close);
        let (decoded, _) = frame::decode_frame(&frame_bytes).unwrap().unwrap();
        conn.handle_frame(&decoded).unwrap();

        assert_eq!(conn.state(), &ConnectionState::Closed);
    }
}
