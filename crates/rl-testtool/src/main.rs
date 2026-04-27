//! rl-testtool: CLI tool for testing the RemoteListener transmitter.

use std::sync::Arc;

use clap::{Parser, Subcommand};
use rl_core::proto::*;
use rl_net::connection::Connection;
use rl_net::frame;

#[derive(Parser)]
#[command(name = "rl-testtool", version, about = "RemoteListener test tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Pair with a transmitter
    Pair {
        /// Transmitter address (host:port)
        addr: String,
        /// Device ID of the transmitter (Base32+Luhn fingerprint)
        device_id: String,
        /// Key file path (X25519 private key, 32 bytes)
        #[arg(short, long)]
        keyfile: Option<String>,
    },
    /// List audio channels on a transmitter
    Channels {
        /// Transmitter address
        addr: String,
        /// Device ID of the transmitter
        device_id: String,
        /// Key file path
        #[arg(short, long)]
        keyfile: Option<String>,
    },
    /// Fetch a recording from a transmitter
    Fetch {
        /// Transmitter address
        addr: String,
        /// Device ID of the transmitter
        device_id: String,
        /// Recording ID to fetch
        recording_id: String,
        /// Output file path
        #[arg(short, long)]
        output: String,
        /// Key file path
        #[arg(short, long)]
        keyfile: Option<String>,
    },
    /// Decrypt a .rlrec recording file
    Decrypt {
        /// Input .rlrec file
        input: String,
        /// Output file (decrypted raw data)
        output: String,
        /// Key file path (X25519 private key, 32 bytes)
        #[arg(short, long)]
        keyfile: String,
    },
    /// Send a control command
    Control {
        /// Transmitter address
        addr: String,
        /// Device ID of the transmitter
        device_id: String,
        /// Control type (set-recording, set-bitrate, delete-recording, get-storage, set-auto-delete)
        command: String,
        /// Channel ID (for channel-specific commands)
        #[arg(short, long)]
        channel: Option<String>,
        /// Value for the command
        #[arg(short, long)]
        value: Option<String>,
        /// Key file path
        #[arg(short, long)]
        keyfile: Option<String>,
    },
    /// Export private key to an encrypted file
    ExportKey {
        /// Key file path
        keyfile: String,
        /// Output path for encrypted key blob
        output: String,
    },
    /// Import private key from an encrypted file
    ImportKey {
        /// Encrypted key blob path
        input: String,
        /// Output key file path
        output: String,
    },
    /// Start live audio listening
    Live {
        /// Transmitter address
        addr: String,
        /// Device ID of the transmitter
        device_id: String,
        /// Channel ID to listen to
        channel: String,
        /// Duration (e.g. 3s)
        #[arg(short, long, default_value = "10s")]
        duration: String,
        /// Key file path
        #[arg(short, long)]
        keyfile: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Pair {
            addr,
            device_id,
            keyfile,
        } => cmd_pair(&addr, &device_id, keyfile.as_deref()).await,
        Commands::Channels {
            addr,
            device_id,
            keyfile,
        } => cmd_channels(&addr, &device_id, keyfile.as_deref()).await,
        Commands::Fetch {
            addr,
            device_id,
            recording_id,
            output,
            keyfile,
        } => {
            cmd_fetch(
                &addr,
                &device_id,
                &recording_id,
                &output,
                keyfile.as_deref(),
            )
            .await
        }
        Commands::Decrypt {
            input,
            output,
            keyfile,
        } => cmd_decrypt(&input, &output, &keyfile),
        Commands::Control {
            addr,
            device_id,
            command,
            channel,
            value,
            keyfile,
        } => {
            cmd_control(
                &addr,
                &device_id,
                &command,
                channel.as_deref(),
                value.as_deref(),
                keyfile.as_deref(),
            )
            .await
        }
        Commands::ExportKey { keyfile, output } => match do_export_key(&keyfile, &output) {
            Ok(()) => {
                println!("Key exported to {}", output);
                Ok(())
            }
            Err(e) => Err(e),
        },
        Commands::ImportKey { input, output } => match do_import_key(&input, &output) {
            Ok(()) => {
                println!("Key imported to {}", output);
                Ok(())
            }
            Err(e) => Err(e),
        },
        Commands::Live {
            addr,
            device_id,
            channel,
            duration,
            keyfile,
        } => cmd_live(&addr, &device_id, &channel, &duration, keyfile.as_deref()).await,
    }
}

/// A simpler approach: connect, do HELLO, then run a callback with read/write
/// access to the stream for the specific command.
async fn with_connection<F, Fut>(
    addr: &str,
    device_id_str: &str,
    keyfile: Option<&str>,
    f: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce(tokio_rustls::client::TlsStream<tokio::net::TcpStream>, Connection) -> Fut,
    Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    // Parse Device ID → fingerprint
    let device_id: rl_core::device_id::DeviceId = device_id_str.parse()?;
    let fingerprint = *device_id.fingerprint();

    // Build TLS client config
    let client_key = if let Some(_kf) = keyfile {
        // Present a self-signed client cert for mTLS
        let (my_id, my_certified) = rl_core::device_id::DeviceId::generate()?;
        let _ = my_id;
        Some((
            rustls::pki_types::PrivateKeyDer::from(my_certified.signing_key),
            my_certified.cert.der().to_vec(),
        ))
    } else {
        None
    };

    let tls_config = rl_net::tls::build_client_config(fingerprint, client_key)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    // Parse address
    let addr = if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{}:22050", addr)
    };
    let tcp_stream = tokio::net::TcpStream::connect(&addr).await?;

    let domain = rustls::pki_types::ServerName::try_from("localhost").map_err(|e| e.to_string())?;
    let mut tls_stream = connector.connect(domain, tcp_stream).await?;

    // Perform HELLO exchange
    let my_device_id = format!(
        "rl-testtool-{}",
        &device_id_str[..8.min(device_id_str.len())]
    );
    let mut conn = Connection::new(my_device_id);
    conn.on_tls_established()?;

    // Send HELLO
    let hello_frame = conn.create_hello("0.1.0");
    tls_stream.write_all(&hello_frame).await?;

    // Read server HELLO
    let mut buf = Vec::new();
    let mut tmp = [0u8; 65536];
    loop {
        let n = tls_stream.read(&mut tmp).await?;
        if n == 0 {
            return Err("Connection closed before HELLO".into());
        }
        buf.extend_from_slice(&tmp[..n]);

        if let Some((decoded, consumed)) = frame::decode_frame(&buf)? {
            buf.drain(..consumed);
            let events = conn.handle_frame(&decoded)?;
            for event in &events {
                if let rl_net::connection::ConnectionEvent::HelloReceived {
                    device_name,
                    version,
                } = event
                {
                    println!("Connected to '{}' (v{})", device_name, version);
                }
            }
            break;
        }
    }

    // Write back any leftover buffered data by reading it first
    // (the leftover bytes are still in `buf` — we need to process them later)
    // For now, just pass the stream + conn + leftover buffer
    f(tls_stream, conn).await
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

async fn cmd_pair(
    addr: &str,
    device_id: &str,
    keyfile: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    with_connection(
        addr,
        device_id,
        keyfile,
        |mut stream, mut conn| async move {
            // Generate our keypair for pairing
            let keypair = rl_crypto::key::KeyPair::generate();
            let public_key = keypair.public_key().as_bytes().to_vec();
            let fingerprint = keypair.fingerprint();

            // Send PAIR_REQUEST
            let pair_frame = frame::encode_message(
                MessageType::PairRequest,
                &PairRequest {
                    device_name: "rl-testtool".to_string(),
                    public_key: public_key.clone(),
                },
            );
            stream.write_all(&pair_frame).await?;

            // Read PAIR_RESPONSE
            let (resp, _conn) = read_one_message(&mut stream, &mut conn).await?;
            match resp {
                RelayMessage::PairResponse {
                    public_key: _their_public,
                    existing_fingerprints,
                } => {
                    println!("Pairing successful!");
                    println!("Their public key fingerprint: {:02x?}", &fingerprint);
                    if !existing_fingerprints.is_empty() {
                        println!("Existing paired fingerprints:");
                        for fp in &existing_fingerprints {
                            println!("  {:02x?}", fp);
                        }
                    }

                    // Save our keypair
                    let keyfile = format!("testtool-key-{:02x?}.bin", &fingerprint[..4]);
                    std::fs::write(&keyfile, keypair.secret_bytes())?;
                    println!("Our key saved to: {}", keyfile);
                }
                _ => {
                    println!("Unexpected response to PAIR_REQUEST");
                }
            }

            // Send PAIR_CONFIRM
            let confirm_frame =
                frame::encode_message(MessageType::PairConfirm, &PairConfirm { accepted: true });
            stream.write_all(&confirm_frame).await?;

            Ok(())
        },
    )
    .await
}

async fn cmd_channels(
    addr: &str,
    device_id: &str,
    keyfile: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    with_connection(
        addr,
        device_id,
        keyfile,
        |mut stream, mut conn| async move {
            // Send CHANNEL_LIST_REQUEST
            let req_frame =
                frame::encode_message(MessageType::ChannelListRequest, &ChannelListRequest {});
            stream.write_all(&req_frame).await?;

            // Read CHANNEL_LIST response
            let (msg, _) = read_one_message(&mut stream, &mut conn).await?;
            if let RelayMessage::ChannelList { channels } = msg {
                if channels.is_empty() {
                    println!("No channels available.");
                } else {
                    println!("Channels ({}):", channels.len());
                    for ch in &channels {
                        println!(
                            "  {} - {} ({} kbps, {}active)",
                            ch.channel_id,
                            ch.device_name,
                            ch.bitrate,
                            if ch.is_active { "" } else { "in" },
                        );
                    }
                }
            }

            Ok(())
        },
    )
    .await
}

async fn cmd_fetch(
    addr: &str,
    device_id: &str,
    recording_id: &str,
    output: &str,
    keyfile: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    with_connection(
        addr,
        device_id,
        keyfile,
        |mut stream, mut conn| async move {
            // Send RECORDING_FETCH_REQUEST
            let req_frame = frame::encode_message(
                MessageType::RecordingFetchRequest,
                &RecordingFetchRequest {
                    recording_id: recording_id.to_string(),
                },
            );
            stream.write_all(&req_frame).await?;

            // Read chunks until RecordingFetchComplete or error
            let mut file_data = Vec::new();
            let mut done = false;

            while !done {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 65536];
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    return Err("Connection closed during fetch".into());
                }
                buf.extend_from_slice(&tmp[..n]);

                while let Some((decoded, consumed)) = frame::decode_frame(&buf)? {
                    buf.drain(..consumed);

                    match decoded.header.r#type() {
                        MessageType::RecordingChunk => {
                            let chunk: RecordingChunk =
                                frame::decode_message(&decoded).map_err(|e| e.to_string())?;
                            file_data.extend_from_slice(&chunk.data);
                            if chunk.is_last {
                                println!(
                                    "Received chunk {} (last, {} bytes)",
                                    chunk.chunk_index,
                                    chunk.data.len()
                                );
                            }
                        }
                        MessageType::RecordingFetchComplete => {
                            let complete: RecordingFetchComplete =
                                frame::decode_message(&decoded).map_err(|e| e.to_string())?;
                            println!("Fetch complete: {}", complete.recording_id);
                            done = true;
                        }
                        MessageType::RecordingFetchError => {
                            let err: RecordingFetchError =
                                frame::decode_message(&decoded).map_err(|e| e.to_string())?;
                            return Err(format!("Fetch error: {}", err.error).into());
                        }
                        other => {
                            // Handle connection events
                            let events = conn.handle_frame(&decoded)?;
                            for event in &events {
                                tracing::debug!("Event during fetch: {:?}", event);
                            }
                            let _ = other;
                        }
                    }
                }
            }

            std::fs::write(output, &file_data)?;
            println!("Saved {} bytes to {}", file_data.len(), output);

            Ok(())
        },
    )
    .await
}

fn cmd_decrypt(
    input: &str,
    _output: &str,
    keyfile: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read key file — 32-byte X25519 secret key
    let key_bytes = std::fs::read(keyfile)?;
    if key_bytes.len() != 32 {
        return Err("Key file must be exactly 32 bytes".into());
    }

    // Read recording file
    let data = std::fs::read(input)?;
    let recording = rl_crypto::format::RecordingFile::from_bytes(&data)
        .map_err(|e| format!("Failed to parse recording: {}", e))?;

    println!(
        "Recording: channel={}, segments={}, keys={}",
        recording.header.channel_id,
        recording.header.segment_count,
        recording.header.key_entries.len(),
    );

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&key_bytes);
    let keypair = rl_crypto::key::KeyPair::from_bytes(secret);
    let my_fingerprint = keypair.fingerprint();

    // Find the matching key entry
    let _key_entry = recording
        .header
        .find_key_entry(&my_fingerprint)
        .ok_or_else(|| {
            format!(
                "No key entry matching fingerprint {:02x?}... Check that the keyfile matches one of the authorized receivers",
                &my_fingerprint[..4]
            )
        })?;

    println!("Found matching key entry for this receiver.");
    println!(
        "Note: Full decryption requires the transmitter's public key for ECDH KEK derivation."
    );
    println!("The recording format does not store the sender's public key.");

    Err("Decryption requires sender's public key (not yet in CLI)".into())
}

async fn cmd_control(
    addr: &str,
    device_id: &str,
    command: &str,
    channel: Option<&str>,
    value: Option<&str>,
    keyfile: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    with_connection(
        addr,
        device_id,
        keyfile,
        |mut stream, mut conn| async move {
            let control_type = match command {
                "set-recording" => ControlType::SetChannelRecording,
                "set-bitrate" => ControlType::SetChannelBitrate,
                "delete-recording" => ControlType::DeleteRecording,
                "get-storage" => ControlType::GetStorageInfo,
                "set-auto-delete" => ControlType::SetAutoDeleteDays,
                _ => return Err(format!("Unknown control command: {}", command).into()),
            };

            let channel_id = channel.unwrap_or("").to_string();
            let payload = match control_type {
                ControlType::SetChannelRecording => {
                    let enabled = value == Some("true") || value == Some("1");
                    Some(control_command::Payload::RecordingEnabled(enabled))
                }
                ControlType::SetChannelBitrate => {
                    let kbps: u32 = value.and_then(|v| v.parse().ok()).unwrap_or(16);
                    Some(control_command::Payload::Bitrate(kbps))
                }
                ControlType::DeleteRecording => {
                    let id = value.unwrap_or("").to_string();
                    Some(control_command::Payload::RecordingId(id))
                }
                ControlType::SetAutoDeleteDays => {
                    let days: u32 = value.and_then(|v| v.parse().ok()).unwrap_or(0);
                    Some(control_command::Payload::AutoDeleteDays(days))
                }
                _ => None,
            };

            let cmd_msg = ControlCommand {
                channel_id,
                control_type: control_type as i32,
                payload,
            };
            let req_frame = frame::encode_message(MessageType::ControlCommand, &cmd_msg);
            stream.write_all(&req_frame).await?;

            // Read CONTROL_RESPONSE
            let (msg, _) = read_one_message(&mut stream, &mut conn).await?;
            if let RelayMessage::ControlResponse { success, error } = msg {
                if success {
                    println!("Command '{}' succeeded", command);
                    if !error.is_empty() {
                        println!("  Info: {}", error);
                    }
                } else {
                    println!("Command '{}' failed: {}", command, error);
                }
            }

            Ok(())
        },
    )
    .await
}

async fn cmd_live(
    addr: &str,
    device_id: &str,
    channel_id: &str,
    duration: &str,
    keyfile: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let dur = parse_duration(duration)?;

    with_connection(
        addr,
        device_id,
        keyfile,
        |mut stream, mut conn| async move {
            // Send LIVE_AUDIO_START
            let start_frame = frame::encode_message(
                MessageType::LiveAudioStart,
                &LiveAudioStart {
                    channel_id: channel_id.to_string(),
                },
            );
            stream.write_all(&start_frame).await?;

            // Read LIVE_AUDIO_START_RESPONSE
            let (msg, _) = read_one_message(&mut stream, &mut conn).await?;
            if let RelayMessage::LiveAudioStartResponse { success, error, .. } = msg {
                if !success {
                    return Err(format!("Live audio start failed: {}", error).into());
                }
                println!("Live audio started on channel {}", channel_id);
            }

            // Read audio chunks for the specified duration
            let start_time = std::time::Instant::now();
            let mut chunk_count = 0u32;

            while start_time.elapsed() < dur {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 65536];
                let n = tokio::select! {
                    result = stream.read(&mut tmp) => result?,
                    _ = tokio::time::sleep(dur - start_time.elapsed()) => break,
                };
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);

                while let Some((decoded, consumed)) = frame::decode_frame(&buf)? {
                    buf.drain(..consumed);
                    if decoded.header.r#type() == MessageType::LiveAudioChunk {
                        let chunk: LiveAudioChunk =
                            frame::decode_message(&decoded).map_err(|e| e.to_string())?;
                        chunk_count += 1;
                        if chunk_count <= 5 || chunk_count.is_multiple_of(50) {
                            println!(
                                "Chunk #{}: {} bytes, seq={}, ts={}",
                                chunk_count,
                                chunk.data.len(),
                                chunk.sequence,
                                chunk.timestamp,
                            );
                        }
                    }
                }
            }

            // Send LIVE_AUDIO_STOP
            let stop_frame = frame::encode_message(
                MessageType::LiveAudioStop,
                &LiveAudioStop {
                    channel_id: channel_id.to_string(),
                },
            );
            let _ = stream.write_all(&stop_frame).await;

            println!(
                "Live audio ended. Received {} chunks in {:.1}s",
                chunk_count,
                start_time.elapsed().as_secs_f64()
            );

            Ok(())
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Temporary enum for reading messages in the testtool.
/// We don't use the full ConnectionEvent system here — we directly
/// decode the protobuf messages we care about.
enum RelayMessage {
    PairResponse {
        public_key: Vec<u8>,
        existing_fingerprints: Vec<Vec<u8>>,
    },
    ChannelList {
        channels: Vec<ChannelInfo>,
    },
    ControlResponse {
        success: bool,
        error: String,
    },
    LiveAudioStartResponse {
        success: bool,
        error: String,
    },
    Other,
}

/// Read one protocol message from the stream.
async fn read_one_message(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    conn: &mut Connection,
) -> Result<(RelayMessage, Vec<rl_net::connection::ConnectionEvent>), Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 65536];

    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err("Connection closed".into());
        }
        buf.extend_from_slice(&tmp[..n]);

        if let Some((decoded, consumed)) = frame::decode_frame(&buf)? {
            buf.drain(..consumed);
            let events = conn.handle_frame(&decoded)?;

            let msg = match decoded.header.r#type() {
                MessageType::PairResponse => {
                    let resp: PairResponse =
                        frame::decode_message(&decoded).map_err(|e| e.to_string())?;
                    RelayMessage::PairResponse {
                        public_key: resp.public_key,
                        existing_fingerprints: resp.existing_key_fingerprints,
                    }
                }
                MessageType::ChannelList => {
                    let resp: ChannelList =
                        frame::decode_message(&decoded).map_err(|e| e.to_string())?;
                    RelayMessage::ChannelList {
                        channels: resp.channels,
                    }
                }
                MessageType::ControlResponse => {
                    let resp: ControlResponse =
                        frame::decode_message(&decoded).map_err(|e| e.to_string())?;
                    RelayMessage::ControlResponse {
                        success: resp.success,
                        error: resp.error,
                    }
                }
                MessageType::LiveAudioStartResponse => {
                    let resp: LiveAudioStartResponse =
                        frame::decode_message(&decoded).map_err(|e| e.to_string())?;
                    RelayMessage::LiveAudioStartResponse {
                        success: resp.success,
                        error: resp.error,
                    }
                }
                _ => RelayMessage::Other,
            };

            return Ok((msg, events));
        }
    }
}

/// Parse a duration string like "10s", "5m", "2h".
fn parse_duration(s: &str) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    let s = s.trim();
    if let Some(num) = s.strip_suffix('s') {
        let secs: u64 = num.parse()?;
        Ok(std::time::Duration::from_secs(secs))
    } else if let Some(num) = s.strip_suffix('m') {
        let mins: u64 = num.parse()?;
        Ok(std::time::Duration::from_secs(mins * 60))
    } else if let Some(num) = s.strip_suffix('h') {
        let hours: u64 = num.parse()?;
        Ok(std::time::Duration::from_secs(hours * 3600))
    } else {
        let secs: u64 = s.parse()?;
        Ok(std::time::Duration::from_secs(secs))
    }
}

fn do_export_key(keyfile: &str, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key_bytes = std::fs::read(keyfile)?;
    if key_bytes.len() != 32 {
        return Err("Key file must be exactly 32 bytes".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    println!("Enter passphrase to encrypt the key:");
    let passphrase = rpassword::read_password()?;

    let exported = rl_crypto::key_export::export_key(&key, passphrase.as_bytes())?;
    std::fs::write(output, exported)?;
    Ok(())
}

fn do_import_key(input: &str, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    let blob_bytes = std::fs::read(input)?;
    if blob_bytes.len() != 93 {
        return Err("Invalid key blob (expected 93 bytes)".into());
    }
    let mut blob = [0u8; 93];
    blob.copy_from_slice(&blob_bytes);

    println!("Enter passphrase to decrypt the key:");
    let passphrase = rpassword::read_password()?;

    let key = rl_crypto::key_export::import_key(&blob, passphrase.as_bytes())?;
    std::fs::write(output, key)?;
    Ok(())
}
