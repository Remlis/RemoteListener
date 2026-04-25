//! TCP server for handling receiver connections.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use rl_audio::engine::AudioEngine;
use rl_audio::encoder::Bitrate;
use rl_core::proto::*;
use rl_net::connection::{Connection, ConnectionEvent};
use rl_net::frame;

/// Shared transmitter state accessible by all connections.
pub struct TransmitterState {
    pub engine: Arc<Mutex<AudioEngine>>,
    pub device_name: String,
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

    let (reader, mut writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);

    // Send HELLO
    let hello_frame = conn.create_hello("0.1.0");
    writer.write_all(&hello_frame).await?;

    // Track which channels this connection is listening to live
    let mut live_channels: HashSet<String> = HashSet::new();

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
                        let response = handle_event(
                            &event,
                            &state,
                            &mut live_channels,
                        )
                        .await;
                        for frame_bytes in response {
                            writer.write_all(&frame_bytes).await?;
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

    Ok(())
}

/// Handle a connection event, returning response frames to send back.
async fn handle_event(
    event: &ConnectionEvent,
    state: &Arc<TransmitterState>,
    live_channels: &mut HashSet<String>,
) -> Vec<Vec<u8>> {
    let mut responses = Vec::new();

    match event {
        ConnectionEvent::ChannelListRequested => {
            let engine = state.engine.lock().await;
            let infos = engine.channel_infos();
            responses.push(Connection::create_channel_list(infos));
        }
        ConnectionEvent::LiveAudioStartRequested { channel_id } => {
            let engine = state.engine.lock().await;
            if engine.get_channel(channel_id).is_some() {
                responses.push(Connection::create_live_audio_start_response(
                    channel_id, true, "",
                ));
                live_channels.insert(channel_id.clone());
                // TODO: spawn audio streaming task for this channel
            } else {
                responses.push(Connection::create_live_audio_start_response(
                    channel_id, false, "Channel not found",
                ));
            }
        }
        ConnectionEvent::LiveAudioStopRequested { channel_id } => {
            live_channels.remove(channel_id);
            // TODO: stop audio streaming task
        }
        ConnectionEvent::ControlCommandReceived { command } => {
            let mut engine = state.engine.lock().await;
            responses.push(handle_control_command(&mut engine, command));
        }
        ConnectionEvent::HelloReceived { .. } => {
            tracing::info!("Hello exchange completed");
        }
        ConnectionEvent::PingReceived { .. } => {
            // TODO: send pong
        }
        ConnectionEvent::Closed { reason } => {
            tracing::info!("Connection closed: {}", reason);
        }
        ConnectionEvent::RecordingListRequested { .. } => {
            // TODO: implement recording list
            responses.push(Connection::create_recording_list_response(vec![]));
        }
        ConnectionEvent::RecordingFetchRequested { recording_id } => {
            responses.push(Connection::create_recording_fetch_error(
                recording_id, "Not implemented",
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

/// Handle a control command and return a response frame.
fn handle_control_command(
    engine: &mut AudioEngine,
    cmd: &ControlCommand,
) -> Vec<u8> {
    match cmd.control_type() {
        ControlType::SetChannelRecording => {
            let enabled = match &cmd.payload {
                Some(control_command::Payload::RecordingEnabled(e)) => *e,
                _ => return Connection::create_control_response(false, "Missing recording_enabled"),
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
