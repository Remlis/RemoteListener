//! TCP server for handling receiver connections with live audio streaming.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Mutex};

use aes_gcm::aead::Aead;
use rl_audio::capture::AudioChunk;
use rl_audio::encoder::Bitrate;
use rl_audio::engine::AudioEngine;
use rl_core::proto::*;
use rl_crypto::key::KeyPair;
use rl_net::connection::{Connection, ConnectionEvent};
use rl_net::frame;

/// Unique ID for a connected receiver.
type ConnectionId = u64;

/// Per-connection state tracked by the ConnectionManager.
struct ReceiverInfo {
    device_name: String,
    is_paired: bool,
    fingerprint: Option<Vec<u8>>,
    subscribed_channels: HashSet<String>,
}

/// Manages all connected receivers.
pub struct ConnectionManager {
    next_id: ConnectionId,
    receivers: HashMap<ConnectionId, ReceiverInfo>,
    /// Paired receiver fingerprints persisted across connections.
    paired_fingerprints: HashSet<Vec<u8>>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            next_id: 0,
            receivers: HashMap::new(),
            paired_fingerprints: HashSet::new(),
        }
    }

    /// Register a new connection, returning its ID.
    pub fn add_connection(&mut self, device_name: String) -> ConnectionId {
        let id = self.next_id;
        self.next_id += 1;
        self.receivers.insert(
            id,
            ReceiverInfo {
                device_name,
                is_paired: false,
                fingerprint: None,
                subscribed_channels: HashSet::new(),
            },
        );
        id
    }

    /// Remove a connection, returning its subscribed channels for cleanup.
    pub fn remove_connection(&mut self, id: ConnectionId) -> HashSet<String> {
        if let Some(info) = self.receivers.remove(&id) {
            info.subscribed_channels
        } else {
            HashSet::new()
        }
    }

    /// Mark a receiver as paired.
    pub fn set_paired(&mut self, id: ConnectionId, fingerprint: Vec<u8>) {
        if let Some(info) = self.receivers.get_mut(&id) {
            info.is_paired = true;
            info.fingerprint = Some(fingerprint.clone());
            self.paired_fingerprints.insert(fingerprint);
        }
    }

    /// Unpair a receiver by fingerprint.
    pub fn unpair(&mut self, fingerprint: &[u8]) {
        self.paired_fingerprints.remove(fingerprint);
        for info in self.receivers.values_mut() {
            if info.fingerprint.as_deref() == Some(fingerprint) {
                info.is_paired = false;
                info.fingerprint = None;
            }
        }
    }

    /// Check if a receiver is paired.
    pub fn is_paired(&self, id: ConnectionId) -> bool {
        self.receivers
            .get(&id)
            .map(|i| i.is_paired)
            .unwrap_or(false)
    }

    /// Add a channel subscription for a receiver.
    pub fn subscribe(&mut self, id: ConnectionId, channel_id: &str) {
        if let Some(info) = self.receivers.get_mut(&id) {
            info.subscribed_channels.insert(channel_id.to_string());
        }
    }

    /// Remove a channel subscription for a receiver.
    pub fn unsubscribe(&mut self, id: ConnectionId, channel_id: &str) {
        if let Some(info) = self.receivers.get_mut(&id) {
            info.subscribed_channels.remove(channel_id);
        }
    }

    /// Get the list of paired fingerprint bytes.
    pub fn paired_fingerprints(&self) -> Vec<Vec<u8>> {
        self.paired_fingerprints.iter().cloned().collect()
    }

    /// Number of connected receivers.
    pub fn connection_count(&self) -> usize {
        self.receivers.len()
    }

    /// Number of paired receivers (including offline).
    pub fn paired_count(&self) -> usize {
        self.paired_fingerprints.len()
    }
}

/// Shared transmitter state accessible by all connections.
pub struct TransmitterState {
    pub engine: Arc<Mutex<AudioEngine>>,
    pub device_name: String,
    pub keypair: KeyPair,
    /// Broadcast senders for live audio per channel.
    audio_senders: Mutex<HashMap<String, broadcast::Sender<Vec<u8>>>>,
    /// Connection manager for tracking receivers.
    connections: Mutex<ConnectionManager>,
}

impl TransmitterState {
    pub fn new(engine: Arc<Mutex<AudioEngine>>, device_name: String, keypair: KeyPair) -> Self {
        Self {
            engine,
            device_name,
            keypair,
            audio_senders: Mutex::new(HashMap::new()),
            connections: Mutex::new(ConnectionManager::new()),
        }
    }

    /// Get or create a broadcast sender for a channel.
    /// Returns the sender and the number of existing receivers.
    async fn get_or_create_sender(&self, channel_id: &str) -> (broadcast::Sender<Vec<u8>>, usize) {
        let mut senders = self.audio_senders.lock().await;
        if let Some(tx) = senders.get(channel_id) {
            let count = tx.receiver_count();
            return (tx.clone(), count);
        }
        // Create a broadcast channel with capacity for ~50 Opus frames (~1 second)
        let (tx, _) = broadcast::channel(50);
        let count = tx.receiver_count();
        senders.insert(channel_id.to_string(), tx.clone());
        (tx, count)
    }

    /// Remove a broadcast sender when no longer needed.
    async fn remove_sender(&self, channel_id: &str) {
        let mut senders = self.audio_senders.lock().await;
        if let Some(tx) = senders.get(channel_id) {
            if tx.receiver_count() == 0 {
                senders.remove(channel_id);
            }
        }
    }
}

/// Run the transmitter's TCP server.
pub async fn run_server(
    addr: SocketAddr,
    state: Arc<TransmitterState>,
    device_id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Listening on {}", addr);

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        tracing::info!("Connection from {}", remote_addr);

        let state = state.clone();
        let device_id = device_id.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, device_id, state).await {
                tracing::error!("Connection error: {}", e);
            }
        });
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    device_id: String,
    state: Arc<TransmitterState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = Connection::new(device_id);
    conn.on_tls_established()?; // For now, skip actual TLS

    let (reader, writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let writer = Arc::new(Mutex::new(writer));

    // Send HELLO
    let hello_frame = conn.create_hello("0.1.0");
    writer.lock().await.write_all(&hello_frame).await?;

    // Register this connection
    let conn_id = {
        let mut mgr = state.connections.lock().await;
        mgr.add_connection("unknown".to_string())
    };

    let mut read_buf = Vec::new();
    let mut tmp = [0u8; 65536];

    loop {
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            break; // Connection closed
        }
        read_buf.extend_from_slice(&tmp[..n]);

        // Try to decode frames from the buffer
        while !read_buf.is_empty() {
            match frame::decode_frame(&read_buf) {
                Ok(Some((decoded, consumed))) => {
                    read_buf.drain(..consumed);
                    let events = conn.handle_frame(&decoded)?;

                    for event in events {
                        let responses = handle_event(&event, &state, conn_id, &writer).await;
                        let mut w = writer.lock().await;
                        for frame_bytes in responses {
                            w.write_all(&frame_bytes).await?;
                        }
                    }
                }
                Ok(None) => break, // Need more data
                Err(_) => {
                    read_buf.clear();
                    break;
                }
            }
        }
    }

    // Cleanup: remove connection and unsubscribe from all channels
    let unsub_channels = {
        let mut mgr = state.connections.lock().await;
        mgr.remove_connection(conn_id)
    };
    for channel_id in &unsub_channels {
        state.remove_sender(channel_id).await;
    }
    tracing::info!(
        "Connection {} closed, unsubscribed from {} channels",
        conn_id,
        unsub_channels.len()
    );

    Ok(())
}

/// Handle a connection event, returning response frames to send back.
async fn handle_event(
    event: &ConnectionEvent,
    state: &Arc<TransmitterState>,
    conn_id: ConnectionId,
    writer: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
) -> Vec<Vec<u8>> {
    let mut responses = Vec::new();

    match event {
        ConnectionEvent::HelloReceived { device_name, .. } => {
            let mut mgr = state.connections.lock().await;
            if let Some(info) = mgr.receivers.get_mut(&conn_id) {
                info.device_name = device_name.clone();
            }
            tracing::info!("Hello from {} (conn {})", device_name, conn_id);
        }
        ConnectionEvent::ChannelListRequested => {
            let engine = state.engine.lock().await;
            let infos = engine.channel_infos();
            responses.push(Connection::create_channel_list(infos));
        }
        ConnectionEvent::LiveAudioStartRequested { channel_id } => {
            let (tx, receiver_count) = state.get_or_create_sender(channel_id).await;

            // Verify channel exists
            let channel_exists = {
                let engine = state.engine.lock().await;
                engine.get_channel(channel_id).is_some()
            };

            if channel_exists {
                responses.push(Connection::create_live_audio_start_response(
                    channel_id, true, "",
                ));

                // Track subscription
                {
                    let mut mgr = state.connections.lock().await;
                    mgr.subscribe(conn_id, channel_id);
                }

                // If this is the first subscriber, start the capture task
                if receiver_count == 0 {
                    spawn_capture_task(state.clone(), channel_id.clone(), tx.clone());
                }

                // Spawn a streaming task for this connection+channel
                let rx = tx.subscribe();
                spawn_stream_task(channel_id.clone(), rx, writer.clone());
            } else {
                responses.push(Connection::create_live_audio_start_response(
                    channel_id,
                    false,
                    "Channel not found",
                ));
            }
        }
        ConnectionEvent::LiveAudioStopRequested { channel_id } => {
            {
                let mut mgr = state.connections.lock().await;
                mgr.unsubscribe(conn_id, channel_id);
            }
            state.remove_sender(channel_id).await;
        }
        ConnectionEvent::ControlCommandReceived { command } => {
            // Only paired receivers can issue control commands
            let is_paired = {
                let mgr = state.connections.lock().await;
                mgr.is_paired(conn_id)
            };
            if is_paired {
                let mut engine = state.engine.lock().await;
                responses.push(handle_control_command(&mut engine, command));

                // Notify all other connected receivers about state change
                let infos = engine.channel_infos();
                let status_frame =
                    Connection::create_device_status(&state.device_name, infos, None, 0);
                // TODO: push status_frame to all other connections
                let _ = status_frame;
            } else {
                responses.push(Connection::create_control_response(false, "Not authorized"));
            }
        }
        ConnectionEvent::PairRequested {
            device_name: _,
            public_key,
        } => {
            // Derive KEK from ECDH with the receiver's public key
            let their_public = x25519_dalek::PublicKey::from(
                <[u8; 32]>::try_from(public_key.as_slice()).unwrap_or([0u8; 32]),
            );
            let shared = state.keypair.diffie_hellman(&their_public);
            let kek = shared.derive_kek(b"rl-pairing/v1");

            // Encrypt the transmitter's private key with the KEK
            let private_key_bytes = state.keypair.secret_bytes();
            let mut nonce_bytes = [0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
            let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
            let encrypted_key = kek
                .encrypt(nonce, private_key_bytes.as_slice())
                .unwrap_or_default();

            // Build the encrypted private key blob: nonce(12) + ciphertext+tag
            let mut private_key_blob = Vec::with_capacity(12 + encrypted_key.len());
            private_key_blob.extend_from_slice(&nonce_bytes);
            private_key_blob.extend_from_slice(&encrypted_key);

            let existing_fps = {
                let mgr = state.connections.lock().await;
                mgr.paired_fingerprints()
            };

            responses.push(Connection::create_pair_response(
                state.keypair.public_key().as_bytes().to_vec(),
                private_key_blob,
                existing_fps,
            ));
        }
        ConnectionEvent::PairConfirmed { accepted } => {
            if *accepted {
                tracing::info!("Pairing confirmed for conn {}", conn_id);
                // The fingerprint will be set when we receive the receiver's
                // public key in the PairRequest. For now, mark as paired.
                let mut mgr = state.connections.lock().await;
                mgr.set_paired(conn_id, vec![]); // TODO: use actual fingerprint
            } else {
                tracing::info!("Pairing rejected for conn {}", conn_id);
            }
        }
        ConnectionEvent::Unpaired { fingerprint } => {
            let mut mgr = state.connections.lock().await;
            mgr.unpair(fingerprint);
            tracing::info!("Unpaired fingerprint (conn {})", conn_id);
        }
        ConnectionEvent::PingReceived { .. } => {
            let ping = Ping {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
            };
            responses.push(frame::encode_message(MessageType::Ping, &ping));
        }
        ConnectionEvent::Closed { reason } => {
            tracing::info!("Connection {} closed: {}", conn_id, reason);
        }
        ConnectionEvent::RecordingListRequested { .. } => {
            responses.push(Connection::create_recording_list_response(vec![]));
        }
        ConnectionEvent::RecordingFetchRequested { recording_id } => {
            responses.push(Connection::create_recording_fetch_error(
                recording_id,
                "Not implemented",
            ));
        }
        ConnectionEvent::DeviceStatusRequested => {
            let engine = state.engine.lock().await;
            let infos = engine.channel_infos();
            responses.push(Connection::create_device_status(
                &state.device_name,
                infos,
                None,
                0,
            ));
        }
        _ => {
            tracing::debug!("Unhandled event: {:?}", event);
        }
    }

    responses
}

/// Spawn a capture task that reads PCM from an AudioChannel, encodes it,
/// and broadcasts the Opus frames to all subscribers.
fn spawn_capture_task(
    state: Arc<TransmitterState>,
    channel_id: String,
    tx: broadcast::Sender<Vec<u8>>,
) {
    tokio::spawn(async move {
        // Start capturing from the channel's AudioInput
        let rx = {
            let mut engine = state.engine.lock().await;
            if let Some(ch) = engine.get_channel_mut(&channel_id) {
                match ch.input_mut().start() {
                    Ok(rx) => rx,
                    Err(e) => {
                        tracing::error!("Failed to start capture for {}: {}", channel_id, e);
                        return;
                    }
                }
            } else {
                tracing::error!("Channel {} not found for capture", channel_id);
                return;
            }
        };

        // Bridge std::sync::mpsc to tokio via spawn_blocking
        let (async_tx, mut async_rx) = tokio::sync::mpsc::channel::<AudioChunk>(50);
        tokio::task::spawn_blocking(move || {
            while let Ok(chunk) = rx.recv() {
                if async_tx.blocking_send(chunk).is_err() {
                    break; // Receiver dropped
                }
            }
        });

        // Read PCM chunks, encode, and broadcast
        while let Some(chunk) = async_rx.recv().await {
            let opus_frames = {
                let mut engine = state.engine.lock().await;
                if let Some(ch) = engine.get_channel_mut(&channel_id) {
                    match ch.encode(&chunk.samples) {
                        Ok(frames) => frames,
                        Err(e) => {
                            tracing::warn!("Encode error for {}: {}", channel_id, e);
                            continue;
                        }
                    }
                } else {
                    break; // Channel removed
                }
            };

            for frame in opus_frames {
                if tx.send(frame).is_err() {
                    break; // No receivers left
                }
            }
        }

        tracing::info!("Capture task ended for channel {}", channel_id);

        let mut engine = state.engine.lock().await;
        if let Some(ch) = engine.get_channel_mut(&channel_id) {
            ch.input_mut().stop();
        }
    });
}

/// Spawn a streaming task that receives Opus frames from a broadcast channel
/// and writes LiveAudioChunk frames to the TCP connection.
fn spawn_stream_task(
    channel_id: String,
    mut rx: broadcast::Receiver<Vec<u8>>,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
) {
    tokio::spawn(async move {
        let mut sequence: u32 = 0;

        loop {
            match rx.recv().await {
                Ok(opus_data) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64;

                    let chunk_frame =
                        Connection::create_live_audio_chunk(&channel_id, &opus_data, sequence, now);
                    sequence = sequence.wrapping_add(1);

                    let mut w = writer.lock().await;
                    if w.write_all(&chunk_frame).await.is_err() {
                        break; // Connection closed
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("Live audio lagged {} frames for channel {}", n, channel_id);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break; // Sender dropped, no more data
                }
            }
        }

        tracing::info!("Stream task ended for channel {}", channel_id);
    });
}

/// Handle a control command and return a response frame.
fn handle_control_command(engine: &mut AudioEngine, cmd: &ControlCommand) -> Vec<u8> {
    match cmd.control_type() {
        ControlType::SetChannelRecording => {
            let enabled = match &cmd.payload {
                Some(control_command::Payload::RecordingEnabled(e)) => *e,
                _ => {
                    return Connection::create_control_response(false, "Missing recording_enabled")
                }
            };
            if let Some(ch) = engine.get_channel_mut(&cmd.channel_id) {
                ch.recording_enabled = enabled;
                Connection::create_control_response(true, "")
            } else {
                Connection::create_control_response(false, "Channel not found")
            }
        }
        ControlType::SetChannelBitrate => {
            let kbps = match &cmd.payload {
                Some(control_command::Payload::Bitrate(k)) => *k,
                _ => return Connection::create_control_response(false, "Missing bitrate"),
            };
            if let Some(ch) = engine.get_channel_mut(&cmd.channel_id) {
                let bitrate = match kbps {
                    16 => Bitrate::Kbps16,
                    32 => Bitrate::Kbps32,
                    64 => Bitrate::Kbps64,
                    128 => Bitrate::Kbps128,
                    _ => return Connection::create_control_response(false, "Invalid bitrate"),
                };
                match ch.set_bitrate(bitrate) {
                    Ok(()) => Connection::create_control_response(true, ""),
                    Err(e) => Connection::create_control_response(false, &e.to_string()),
                }
            } else {
                Connection::create_control_response(false, "Channel not found")
            }
        }
        _ => Connection::create_control_response(false, "Unsupported command"),
    }
}
