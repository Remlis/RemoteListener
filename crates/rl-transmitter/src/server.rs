//! TLS server for handling receiver connections with live audio streaming.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Mutex};
use tokio_rustls::TlsAcceptor;

use rl_audio::capture::AudioChunk;
use rl_audio::encoder::Bitrate;
use rl_audio::engine::AudioEngine;
use rl_core::proto::*;
use rl_crypto::key::KeyPair;
use rl_net::connection::{Connection, ConnectionEvent};
use rl_net::frame;
use rl_net::tls;

/// Type alias for the TLS stream used by server connections.
type TlsServerStream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

/// Type alias for the writer half of a TLS connection.
type TlsWriter = tokio::io::WriteHalf<TlsServerStream>;

/// Unique ID for a connected receiver.
type ConnectionId = u64;

/// Per-connection state tracked by the ConnectionManager.
struct ReceiverInfo {
    device_name: String,
    is_paired: bool,
    fingerprint: Option<Vec<u8>>,
    /// Receiver's X25519 public key (received in PairRequest).
    public_key: Option<[u8; 32]>,
    subscribed_channels: HashSet<String>,
}

/// Manages all connected receivers.
pub struct ConnectionManager {
    next_id: ConnectionId,
    receivers: HashMap<ConnectionId, ReceiverInfo>,
    /// Paired receiver fingerprints persisted across connections.
    paired_fingerprints: HashSet<Vec<u8>>,
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
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
                public_key: None,
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

    /// Mark a receiver as paired by TLS certificate fingerprint.
    pub fn set_paired(&mut self, id: ConnectionId, fingerprint: Vec<u8>) {
        if let Some(info) = self.receivers.get_mut(&id) {
            info.is_paired = true;
            info.fingerprint = Some(fingerprint.clone());
            self.paired_fingerprints.insert(fingerprint);
        }
    }

    /// Store the receiver's X25519 public key (from PairRequest) for recording encryption.
    pub fn set_receiver_public_key(&mut self, id: ConnectionId, public_key: [u8; 32]) {
        if let Some(info) = self.receivers.get_mut(&id) {
            info.public_key = Some(public_key);
        }
    }

    /// Get all paired receivers' (public_key, fingerprint) for recording encryption.
    /// Only returns receivers that have both a public key and a fingerprint.
    pub fn paired_public_keys(&self) -> Vec<([u8; 32], Vec<u8>)> {
        self.receivers
            .values()
            .filter(|info| info.is_paired)
            .filter_map(|info| {
                let pk = info.public_key?;
                let fp = info.fingerprint.clone()?;
                Some((pk, fp))
            })
            .collect()
    }

    /// Get the receiver's public key for a given connection.
    pub fn receiver_public_key(&self, id: ConnectionId) -> Option<[u8; 32]> {
        self.receivers.get(&id).and_then(|info| info.public_key)
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
    /// Directory for encrypted recording files.
    pub recording_dir: std::path::PathBuf,
    /// Path to the X25519 keypair file (for deletion after pairing).
    keypair_path: std::path::PathBuf,
    /// Broadcast senders for live audio per channel.
    audio_senders: Mutex<HashMap<String, broadcast::Sender<Vec<u8>>>>,
    /// Connection manager for tracking receivers.
    connections: Mutex<ConnectionManager>,
    /// Maximum number of concurrent connections.
    max_connections: usize,
    /// Broadcast channel for pushing DeviceStatus updates to all connections.
    /// The sender ID (ConnectionId) is included so each connection can skip its own updates.
    status_push: broadcast::Sender<(ConnectionId, Vec<u8>)>,
}

impl TransmitterState {
    pub fn new(
        engine: Arc<Mutex<AudioEngine>>,
        device_name: String,
        keypair: KeyPair,
        recording_dir: std::path::PathBuf,
        keypair_path: std::path::PathBuf,
    ) -> Self {
        // Ensure recording directory exists
        if let Err(e) = std::fs::create_dir_all(&recording_dir) {
            tracing::warn!(
                "Failed to create recording directory {:?}: {}",
                recording_dir,
                e
            );
        }

        Self {
            engine,
            device_name,
            keypair,
            recording_dir,
            keypair_path,
            audio_senders: Mutex::new(HashMap::new()),
            connections: Mutex::new(ConnectionManager::new()),
            max_connections: 32,
            status_push: broadcast::channel(16).0,
        }
    }

    /// Check if we can accept a new connection.
    async fn can_accept_connection(&self) -> bool {
        let mgr = self.connections.lock().await;
        mgr.connection_count() < self.max_connections
    }

    /// Get or create a broadcast sender for a channel.
    /// Returns the sender and whether a new capture task should be spawned.
    async fn get_or_create_sender(&self, channel_id: &str) -> (broadcast::Sender<Vec<u8>>, bool) {
        let mut senders = self.audio_senders.lock().await;
        if let Some(tx) = senders.get(channel_id) {
            // Existing sender — a capture task should already be running.
            // receiver_count() counts broadcast receivers (stream tasks),
            // so if > 0, capture is running.
            let needs_capture = tx.receiver_count() == 0;
            return (tx.clone(), needs_capture);
        }
        // Create a broadcast channel with capacity for ~50 Opus frames (~1 second)
        let (tx, _) = broadcast::channel(50);
        senders.insert(channel_id.to_string(), tx.clone());
        (tx, true) // New channel, needs capture task
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

    /// Clean up a sender for a channel after a stream task ends.
    /// This handles the dead channel issue by removing the sender
    /// when all stream tasks have ended.
    async fn cleanup_sender(&self, channel_id: &str) {
        let mut senders = self.audio_senders.lock().await;
        if let Some(tx) = senders.get(channel_id) {
            if tx.receiver_count() == 0 {
                senders.remove(channel_id);
            }
        }
    }

    /// Subscribe to status push notifications.
    pub fn subscribe_status(&self) -> broadcast::Receiver<(ConnectionId, Vec<u8>)> {
        self.status_push.subscribe()
    }

    /// Collect current status for the system tray.
    pub async fn tray_status(&self) -> rl_tray::TrayStatus {
        let engine = self.engine.lock().await;
        let channel_count = engine.channel_count();
        let recording_channels = engine
            .channels()
            .iter()
            .filter(|ch| ch.recording_enabled)
            .count();
        drop(engine);

        let connected_receivers = {
            let mgr = self.connections.lock().await;
            mgr.connection_count()
        };

        rl_tray::TrayStatus {
            device_id: String::new(), // Filled by caller
            device_name: self.device_name.clone(),
            channel_count,
            recording_channels,
            connected_receivers,
        }
    }

    /// Push a DeviceStatus frame to all connections except the originating one.
    pub async fn push_status(&self, origin_conn_id: ConnectionId) {
        let engine = self.engine.lock().await;
        let channels = engine.channel_infos();
        drop(engine);

        let storage = compute_storage_info(&self.recording_dir);
        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Approximate uptime — we don't track exact start time here
        let status_frame = Connection::create_device_status(
            &self.device_name,
            channels,
            Some(storage),
            start_time,
        );

        let _ = self.status_push.send((origin_conn_id, status_frame));
    }
}

/// Maximum read buffer size (10 MB).
const MAX_READ_BUF: usize = 10 * 1024 * 1024;

/// Run the transmitter's TLS server.
pub async fn run_server(
    addr: SocketAddr,
    state: Arc<TransmitterState>,
    device_id: String,
    tls_acceptor: TlsAcceptor,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Listening on {} (TLS)", addr);

    loop {
        let (stream, remote_addr) = listener.accept().await?;

        if !state.can_accept_connection().await {
            tracing::warn!(
                "Rejecting connection from {}: max connections reached",
                remote_addr
            );
            drop(stream);
            continue;
        }

        let acceptor = tls_acceptor.clone();
        let state = state.clone();
        let device_id = device_id.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    tracing::info!("TLS handshake completed with {}", remote_addr);

                    // Extract peer Device ID from client cert if presented
                    let peer_id = tls::peer_device_id(&tls_stream);
                    if let Some(ref fp) = peer_id {
                        tracing::info!("Peer Device ID: {:02x?}...", &fp[..8.min(fp.len())]);
                    } else {
                        tracing::info!("No client certificate presented");
                    }

                    if let Err(e) = handle_connection(tls_stream, device_id, state, peer_id).await {
                        tracing::error!("Connection error: {}", e);
                    }
                }
                Err(e) => {
                    tracing::warn!("TLS handshake failed with {}: {}", remote_addr, e);
                }
            }
        });
    }
}

async fn handle_connection(
    stream: TlsServerStream,
    device_id: String,
    state: Arc<TransmitterState>,
    peer_device_id: Option<[u8; 32]>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = Connection::new(device_id);
    conn.on_tls_established()?;

    let (reader, writer) = tokio::io::split(stream);
    let mut reader = tokio::io::BufReader::new(reader);
    let writer = Arc::new(Mutex::new(writer));

    // Send HELLO
    let hello_frame = conn.create_hello("0.1.0");
    writer.lock().await.write_all(&hello_frame).await?;

    // Register this connection with peer Device ID if available
    let conn_id = {
        let mut mgr = state.connections.lock().await;
        let peer_name = peer_device_id
            .as_ref()
            .map(|fp| format!("{:02x?}...", &fp[..8.min(fp.len())]))
            .unwrap_or_else(|| "unknown".to_string());
        let id = mgr.add_connection(peer_name);
        // Store peer Device ID fingerprint if presented
        if let Some(fp) = peer_device_id {
            mgr.set_paired(id, fp.to_vec());
        }
        id
    };

    // Subscribe to status push notifications (DeviceStatus from other connections)
    let mut status_rx = state.subscribe_status();
    let status_writer = writer.clone();
    let status_conn_id = conn_id;
    let status_handle = tokio::spawn(async move {
        loop {
            match status_rx.recv().await {
                Ok((origin_conn_id, frame)) => {
                    // Skip our own updates
                    if origin_conn_id == status_conn_id {
                        continue;
                    }
                    let mut w = status_writer.lock().await;
                    if w.write_all(&frame).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("Status push lagged {} frames", n);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    });

    let mut read_buf = Vec::new();
    let mut tmp = [0u8; 65536];
    let mut missed_pings: u32 = 0;
    const MAX_MISSED_PINGS: u32 = 3;
    let mut heartbeat = tokio::time::interval(tokio::time::Duration::from_secs(30));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            result = reader.read(&mut tmp) => {
                let n = result?;
                if n == 0 {
                    break; // Connection closed
                }
                // Any received data resets the missed ping counter
                missed_pings = 0;
                read_buf.extend_from_slice(&tmp[..n]);

                // Bound read buffer growth to prevent OOM
                if read_buf.len() > MAX_READ_BUF {
                    tracing::warn!("Read buffer exceeded {} bytes, clearing", MAX_READ_BUF);
                    read_buf.clear();
                    break;
                }

                // Try to decode frames from the buffer
                while !read_buf.is_empty() {
                    match frame::decode_frame(&read_buf) {
                        Ok(Some((decoded, consumed))) => {
                            let msg_type = MessageType::try_from(decoded.header.r#type);
                            tracing::info!("Received frame: type={:?}, body_len={}", msg_type, decoded.body.len());
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
            _ = heartbeat.tick() => {
                missed_pings += 1;
                if missed_pings > MAX_MISSED_PINGS {
                    tracing::warn!(
                        "Connection {} missed {} pings, closing",
                        conn_id, missed_pings
                    );
                    break;
                }
                // Send PING
                let ping_frame = conn.create_ping();
                let mut w = writer.lock().await;
                if w.write_all(&ping_frame).await.is_err() {
                    break; // Write failed, connection dead
                }
            }
        }
    }

    // Cleanup: remove connection and unsubscribe from all channels
    status_handle.abort(); // Stop the status push listener
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

/// Handle a relay-originated TLS connection (TLS already established).
pub async fn handle_relay_connection(
    stream: TlsServerStream,
    state: Arc<TransmitterState>,
    device_id: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    handle_connection(stream, device_id, state, None).await
}

/// Handle a connection event, returning response frames to send back.
async fn handle_event(
    event: &ConnectionEvent,
    state: &Arc<TransmitterState>,
    conn_id: ConnectionId,
    writer: &Arc<Mutex<TlsWriter>>,
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
            let (tx, needs_capture) = state.get_or_create_sender(channel_id).await;

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

                // Spawn a streaming task for this connection+channel FIRST,
                // so the broadcast receiver is registered before the capture
                // task starts sending. This prevents the TOCTOU race where
                // receiver_count was checked before the stream task subscribed.
                let rx = tx.subscribe();
                spawn_stream_task(channel_id.clone(), rx, writer.clone(), state.clone());

                // If no capture task is running for this channel, start one
                if needs_capture {
                    spawn_capture_task(state.clone(), channel_id.clone(), tx.clone());
                }
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
                let (resp, channels_changed) = handle_control_command(state, command).await;
                responses.push(resp);

                // Push DeviceStatus to all other connected receivers
                if channels_changed {
                    state.push_status(conn_id).await;
                }
            } else {
                responses.push(Connection::create_control_response(false, "Not authorized"));
            }
        }
        ConnectionEvent::PairRequested {
            device_name: _,
            public_key,
        } => {
            // Compute the fingerprint of the receiver's public key for tracking
            let their_public = x25519_dalek::PublicKey::from(
                <[u8; 32]>::try_from(public_key.as_slice()).unwrap_or([0u8; 32]),
            );
            let receiver_fingerprint = rl_crypto::key::fingerprint(&their_public.to_bytes());
            let receiver_public_bytes = their_public.to_bytes();

            // Respond with our public key and existing fingerprints.
            let existing_fps = {
                let mgr = state.connections.lock().await;
                mgr.paired_fingerprints()
            };

            responses.push(Connection::create_pair_response(
                state.keypair.public_key().as_bytes().to_vec(),
                existing_fps,
            ));

            // Store the receiver's public key and fingerprint for recording encryption
            let mut mgr = state.connections.lock().await;
            mgr.set_paired(conn_id, receiver_fingerprint);
            mgr.set_receiver_public_key(conn_id, receiver_public_bytes);
        }
        ConnectionEvent::PairConfirmed { accepted } => {
            if *accepted {
                tracing::info!("Pairing confirmed for conn {}", conn_id);
                // Delete the X25519 private key from disk (plan: "发射端磁盘上无私钥")
                let keypair_path = state.keypair_path.clone();
                match std::fs::remove_file(&keypair_path) {
                    Ok(()) => {
                        tracing::info!("Deleted transmitter private key from {:?}", keypair_path)
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        tracing::debug!("Keypair file already deleted");
                    }
                    Err(e) => tracing::warn!("Failed to delete keypair file: {}", e),
                }
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
        ConnectionEvent::RecordingListRequested { channel_id } => {
            let recordings = enumerate_recordings(&state.recording_dir, channel_id);
            responses.push(Connection::create_recording_list_response(recordings));
        }
        ConnectionEvent::RecordingFetchRequested { recording_id } => {
            match fetch_recording(&state.recording_dir, recording_id).await {
                Ok(chunks) => responses.extend(chunks),
                Err(e) => responses.push(Connection::create_recording_fetch_error(
                    recording_id,
                    &e.to_string(),
                )),
            }
        }
        ConnectionEvent::DeviceStatusRequested => {
            let engine = state.engine.lock().await;
            let infos = engine.channel_infos();
            let storage = compute_storage_info(&state.recording_dir);
            responses.push(Connection::create_device_status(
                &state.device_name,
                infos,
                Some(storage),
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

            for frame in &opus_frames {
                if tx.send(frame.clone()).is_err() {
                    break; // No receivers left
                }
            }

            // Write Opus frames to recording if enabled
            {
                let mut engine = state.engine.lock().await;
                if let Some(ch) = engine.get_channel_mut(&channel_id) {
                    ch.write_opus_frames(&opus_frames);
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
    writer: Arc<Mutex<TlsWriter>>,
    state: Arc<TransmitterState>,
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

        // Clean up the sender if no more receivers exist (dead channel fix)
        state.cleanup_sender(&channel_id).await;
    });
}

/// Handle a control command and return a response frame and whether channels changed.
async fn handle_control_command(
    state: &Arc<TransmitterState>,
    cmd: &ControlCommand,
) -> (Vec<u8>, bool) {
    match cmd.control_type() {
        ControlType::SetChannelRecording => {
            let enabled = match &cmd.payload {
                Some(control_command::Payload::RecordingEnabled(e)) => *e,
                _ => {
                    return (
                        Connection::create_control_response(false, "Missing recording_enabled"),
                        false,
                    )
                }
            };
            // Get paired receiver public keys outside the engine lock to avoid lock ordering issues
            let paired = state.connections.lock().await.paired_public_keys();
            let mut engine = state.engine.lock().await;
            if let Some(ch) = engine.get_channel_mut(&cmd.channel_id) {
                if enabled && !ch.recording_enabled {
                    // Start recording: create output file
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let filename = format!("{}-{}.rlrec", ch.channel_id, timestamp);
                    let path = state.recording_dir.join(&filename);
                    let cid = ch.channel_id.clone();
                    if let Err(e) = ch.start_recording(path, &cid) {
                        return (
                            Connection::create_control_response(
                                false,
                                &format!("Failed to start recording: {}", e),
                            ),
                            false,
                        );
                    }
                } else if !enabled && ch.recording_enabled {
                    // Stop recording: finalize the file with paired receiver keys
                    match ch.stop_recording(&paired) {
                        Ok(Some(path)) => {
                            tracing::info!("Recording finalized: {}", path.display());
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::error!("Failed to finalize recording: {}", e);
                        }
                    }
                }
                (Connection::create_control_response(true, ""), true)
            } else {
                (
                    Connection::create_control_response(false, "Channel not found"),
                    false,
                )
            }
        }
        ControlType::SetChannelBitrate => {
            let kbps = match &cmd.payload {
                Some(control_command::Payload::Bitrate(k)) => *k,
                _ => {
                    return (
                        Connection::create_control_response(false, "Missing bitrate"),
                        false,
                    )
                }
            };
            let mut engine = state.engine.lock().await;
            if let Some(ch) = engine.get_channel_mut(&cmd.channel_id) {
                let bitrate = match kbps {
                    16 => Bitrate::Kbps16,
                    32 => Bitrate::Kbps32,
                    64 => Bitrate::Kbps64,
                    128 => Bitrate::Kbps128,
                    _ => {
                        return (
                            Connection::create_control_response(false, "Invalid bitrate"),
                            false,
                        )
                    }
                };
                match ch.set_bitrate(bitrate) {
                    Ok(()) => (Connection::create_control_response(true, ""), true),
                    Err(e) => (
                        Connection::create_control_response(false, &e.to_string()),
                        false,
                    ),
                }
            } else {
                (
                    Connection::create_control_response(false, "Channel not found"),
                    false,
                )
            }
        }
        ControlType::DeleteRecording => {
            let recording_id = match &cmd.payload {
                Some(control_command::Payload::RecordingId(id)) => id.clone(),
                _ => {
                    return (
                        Connection::create_control_response(false, "Missing recording_id"),
                        false,
                    )
                }
            };
            let path = state.recording_dir.join(format!("{}.rlrec", recording_id));
            if path.exists() {
                match std::fs::remove_file(&path) {
                    Ok(()) => (Connection::create_control_response(true, ""), false),
                    Err(e) => (
                        Connection::create_control_response(false, &e.to_string()),
                        false,
                    ),
                }
            } else {
                (
                    Connection::create_control_response(false, "Recording not found"),
                    false,
                )
            }
        }
        ControlType::GetStorageInfo => {
            let storage = compute_storage_info(&state.recording_dir);
            (
                Connection::create_control_response_with_storage(true, "", storage),
                false,
            )
        }
        ControlType::SetAutoDeleteDays => {
            let days = match &cmd.payload {
                Some(control_command::Payload::AutoDeleteDays(d)) => *d,
                _ => {
                    return (
                        Connection::create_control_response(false, "Missing auto_delete_days"),
                        false,
                    )
                }
            };
            // Persist the new auto_delete_days to config
            let config_path = dirs::data_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("remotelistener")
                .join("config.toml");
            let mut config = rl_core::config::Config::load(&config_path).unwrap_or_default();
            config.auto_delete_days = days;
            if let Err(e) = config.save(&config_path) {
                return (
                    Connection::create_control_response(false, &e.to_string()),
                    false,
                );
            }
            (Connection::create_control_response(true, ""), false)
        }
        _ => (
            Connection::create_control_response(false, "Unsupported command"),
            false,
        ),
    }
}

/// Enumerate .rlrec files in the recording directory, optionally filtered by channel_id.
fn enumerate_recordings(recording_dir: &std::path::Path, channel_id: &str) -> Vec<RecordingInfo> {
    let Ok(entries) = std::fs::read_dir(recording_dir) else {
        return vec![];
    };

    let mut recordings = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rlrec") {
            continue;
        }

        // Filename format: {channel_id}-{timestamp}.rlrec
        let filename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let (file_channel_id, timestamp_str) = filename.rsplit_once('-').unwrap_or((filename, ""));

        if !channel_id.is_empty() && file_channel_id != channel_id {
            continue;
        }

        let metadata = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let recording_id = filename.to_string();
        let file_size = metadata.len();

        let start_timestamp: u64 = timestamp_str.parse().unwrap_or(0);

        // Use file modification time as end timestamp
        let end_timestamp = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(start_timestamp);

        let duration_seconds = if end_timestamp > start_timestamp {
            (end_timestamp - start_timestamp) as u32
        } else {
            0
        };

        recordings.push(RecordingInfo {
            recording_id,
            channel_id: file_channel_id.to_string(),
            start_timestamp,
            end_timestamp,
            file_size,
            duration_seconds,
        });
    }

    recordings
}

/// Fetch a recording file and return a sequence of RecordingChunk frames followed by a FetchComplete.
async fn fetch_recording(
    recording_dir: &std::path::Path,
    recording_id: &str,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let path = recording_dir.join(format!("{}.rlrec", recording_id));
    if !path.exists() {
        return Err(format!("Recording not found: {}", recording_id).into());
    }

    let data = tokio::fs::read(&path).await?;
    let mut frames = Vec::new();
    let chunk_size = 32768; // 32KB chunks

    for (i, chunk) in data.chunks(chunk_size).enumerate() {
        let chunk_msg = RecordingChunk {
            recording_id: recording_id.to_string(),
            data: chunk.to_vec(),
            chunk_index: i as u32,
            is_last: i == data.len().div_ceil(chunk_size) - 1,
        };
        frames.push(frame::encode_message(
            MessageType::RecordingChunk,
            &chunk_msg,
        ));
    }

    let complete_msg = RecordingFetchComplete {
        recording_id: recording_id.to_string(),
    };
    frames.push(frame::encode_message(
        MessageType::RecordingFetchComplete,
        &complete_msg,
    ));

    Ok(frames)
}

/// Compute storage info for the recording directory.
fn compute_storage_info(recording_dir: &std::path::Path) -> StorageInfo {
    let mut used_bytes: u64 = 0;
    let mut recording_count: u64 = 0;

    if let Ok(entries) = std::fs::read_dir(recording_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("rlrec") {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    used_bytes += metadata.len();
                    recording_count += 1;
                }
            }
        }
    }

    let total_bytes = disk_total_bytes(recording_dir);

    StorageInfo {
        total_bytes,
        used_bytes,
        recording_count,
    }
}

/// Get total disk capacity for the filesystem containing the given path.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn disk_total_bytes(path: &std::path::Path) -> u64 {
    let c_path = match std::ffi::CString::new(path.to_str().unwrap_or("")) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    unsafe {
        let mut buf = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if libc::statvfs(c_path.as_ptr(), buf.as_mut_ptr()) == 0 {
            let vfs = buf.assume_init();
            (vfs.f_blocks as u64) * vfs.f_frsize
        } else {
            0
        }
    }
}

#[cfg(not(unix))]
fn disk_total_bytes(_path: &std::path::Path) -> u64 {
    0
}

/// Delete recordings older than `days` days from the recording directory.
/// Returns the number of files deleted.
pub fn auto_delete_recordings(recording_dir: &std::path::Path, days: u32) -> usize {
    if days == 0 {
        return 0; // 0 means never auto-delete
    }

    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(days as u64 * 86400);

    let Ok(entries) = std::fs::read_dir(recording_dir) else {
        return 0;
    };

    let mut deleted = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rlrec") {
            continue;
        }
        if let Ok(metadata) = std::fs::metadata(&path) {
            if let Ok(modified) = metadata.modified() {
                if modified < cutoff && std::fs::remove_file(&path).is_ok() {
                    tracing::info!("Auto-deleted old recording: {:?}", path);
                    deleted += 1;
                }
            }
        }
    }

    if deleted > 0 {
        tracing::info!("Auto-delete: removed {} old recordings", deleted);
    }

    deleted
}

/// Run the auto-delete task periodically (once per hour).
pub async fn run_auto_delete_task(recording_dir: std::path::PathBuf, auto_delete_days: u32) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));

    loop {
        interval.tick().await;
        auto_delete_recordings(&recording_dir, auto_delete_days);
    }
}
