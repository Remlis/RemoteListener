//! AudioChannel: single audio input with independent recording state.

use crate::capture::{AudioError, AudioInput, SineWaveInput};
use crate::encoder::{Bitrate, OpusEncoder};
use crate::recorder::RecordingWriter;
use rl_core::proto::ChannelInfo;
use rl_crypto::format::RecordingFileBuilder;
use rl_crypto::key::KeyPair;
use std::path::PathBuf;

/// A single audio channel with independent recording state.
pub struct AudioChannel {
    pub channel_id: String,
    pub device_name: String,
    pub device_uid: String,
    pub recording_enabled: bool,
    pub bitrate: Bitrate,
    pub is_active: bool,
    pub recorded_bytes: u64,

    input: Box<dyn AudioInput>,
    encoder: OpusEncoder,
    recorder: Option<RecordingWriter>,
    keypair: Option<KeyPair>,
}

impl AudioChannel {
    /// Create a test channel with a sine wave input.
    pub fn new_test(
        channel_id: String,
        frequency: f64,
        bitrate: Bitrate,
    ) -> Result<Self, AudioError> {
        let encoder = OpusEncoder::new(bitrate)?;
        let input = Box::new(SineWaveInput::new(frequency, 48000, 10.0));

        Ok(Self {
            channel_id,
            device_name: format!("Sine {}Hz", frequency),
            device_uid: format!("sine-{}", frequency as u32),
            recording_enabled: false,
            bitrate,
            is_active: true,
            recorded_bytes: 0,
            input,
            encoder,
            recorder: None,
            keypair: None,
        })
    }

    /// Create a channel with a custom audio input.
    pub fn with_input(
        channel_id: String,
        device_name: String,
        device_uid: String,
        bitrate: Bitrate,
        input: Box<dyn AudioInput>,
    ) -> Result<Self, AudioError> {
        let encoder = OpusEncoder::new(bitrate)?;
        Ok(Self {
            channel_id,
            device_name,
            device_uid,
            recording_enabled: false,
            bitrate,
            is_active: true,
            recorded_bytes: 0,
            input,
            encoder,
            recorder: None,
            keypair: None,
        })
    }

    /// Start recording to a file.
    pub fn start_recording(&mut self, path: PathBuf, channel_id: &str) -> Result<(), AudioError> {
        self.recording_enabled = true;
        self.recorder = Some(RecordingWriter::new(path, channel_id.to_string()));
        Ok(())
    }

    /// Stop recording and finalize the file.
    pub fn stop_recording(&mut self) -> Result<Option<std::path::PathBuf>, AudioError> {
        self.recording_enabled = false;
        if let Some(writer) = self.recorder.take() {
            // Build the RecordingFileBuilder with paired receiver keys
            if let Some(ref kp) = self.keypair {
                let mut builder = RecordingFileBuilder::new(self.channel_id.clone())
                    .with_sender_public_key(*kp.public_key().as_bytes());
                // Add self as a receiver (so the transmitter can decrypt its own recordings)
                let self_kek = kp.diffie_hellman(kp.public_key()).derive_kek(b"rl-keks/v1");
                builder = builder.add_receiver(&self_kek, kp.fingerprint()).map_err(|e| {
                    AudioError::Opus(format!("Failed to add receiver: {}", e))
                })?;
                // TODO: Add paired receivers' key entries when public keys are available

                let result = writer.finalize(builder).map_err(|e| {
                    AudioError::Opus(format!("Failed to finalize recording: {}", e))
                })?;
                Ok(Some(result))
            } else {
                // No keypair set — discard the recording
                tracing::warn!(
                    "Discarding recording for {}: no keypair configured",
                    self.channel_id
                );
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Set the keypair for encrypting recordings.
    pub fn set_keypair(&mut self, keypair: KeyPair) {
        self.keypair = Some(keypair);
    }

    /// Set the bitrate.
    pub fn set_bitrate(&mut self, bitrate: Bitrate) -> Result<(), AudioError> {
        self.encoder = OpusEncoder::new(bitrate)?;
        self.bitrate = bitrate;
        Ok(())
    }

    /// Record a chunk: encode → write.
    pub fn record_chunk(&mut self, pcm: &[i16]) -> Result<Vec<u8>, AudioError> {
        let frames = self.encoder.encode_all(pcm)?;
        let mut data = Vec::new();
        for frame in &frames {
            // Write frame length prefix + data
            data.extend_from_slice(&(frame.len() as u32).to_be_bytes());
            data.extend_from_slice(frame);
        }
        self.recorded_bytes += data.len() as u64;
        Ok(data)
    }

    /// Write already-encoded Opus frames to the recording writer.
    /// Returns true if frames were written.
    pub fn write_opus_frames(&mut self, opus_frames: &[Vec<u8>]) -> bool {
        if !self.recording_enabled {
            return false;
        }
        if let Some(ref mut writer) = self.recorder {
            for frame in opus_frames {
                writer.write_chunk(&(frame.len() as u32).to_be_bytes());
                writer.write_chunk(frame);
            }
            true
        } else {
            false
        }
    }

    /// Encode PCM to Opus frames.
    pub fn encode(&mut self, pcm: &[i16]) -> Result<Vec<Vec<u8>>, AudioError> {
        self.encoder.encode_all(pcm)
    }

    /// Convert to protobuf ChannelInfo.
    pub fn to_channel_info(&self) -> ChannelInfo {
        ChannelInfo {
            channel_id: self.channel_id.clone(),
            device_name: self.device_name.clone(),
            device_uid: self.device_uid.clone(),
            recording_enabled: self.recording_enabled,
            is_active: self.is_active,
            bitrate: self.bitrate.kbps(),
            recorded_bytes: self.recorded_bytes,
        }
    }

    /// Get mutable reference to the input.
    pub fn input_mut(&mut self) -> &mut dyn AudioInput {
        self.input.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::OpusDecoder;
    use rl_crypto::format::RecordingFileBuilder;
    use rl_crypto::key::KeyPair;

    #[test]
    fn sine_encode_decode_roundtrip() {
        let mut channel = AudioChannel::new_test("ch-001".into(), 440.0, Bitrate::Kbps16).unwrap();
        let pcm: Vec<i16> = (0..960)
            .map(|i| {
                let t = i as f64 / 48000.0;
                ((440.0 * 2.0 * std::f64::consts::PI * t).sin() * 8000.0) as i16
            })
            .collect();

        let frames = channel.encode(&pcm).unwrap();
        let mut decoder = OpusDecoder::new().unwrap();
        let decoded = decoder.decode_all(&frames).unwrap();

        // Opus is lossy, but length should match and signal should be non-silent
        assert_eq!(decoded.len(), pcm.len());
        assert!(decoded.iter().any(|&s| s != 0));
    }

    #[test]
    fn full_pipeline_sine_to_encrypted_file() {
        // Generate sine wave
        let pcm: Vec<i16> = (0..960 * 5)
            .map(|i| {
                let t = i as f64 / 48000.0;
                ((440.0 * 2.0 * std::f64::consts::PI * t).sin() * 8000.0) as i16
            })
            .collect();

        // Encode
        let mut encoder = OpusEncoder::new(Bitrate::Kbps16).unwrap();
        let frames = encoder.encode_all(&pcm).unwrap();

        // Flatten opus frames to raw bytes for encryption
        let mut opus_data = Vec::new();
        for frame in &frames {
            opus_data.extend_from_slice(frame);
        }

        // Encrypt with multi-key header
        let tx = KeyPair::generate();
        let rx = KeyPair::generate();
        let kek = tx.diffie_hellman(rx.public_key()).derive_kek(b"rl-keks/v1");

        let file = RecordingFileBuilder::new("ch-001".into())
            .add_receiver(&kek, rx.fingerprint())
            .unwrap()
            .build(&opus_data)
            .unwrap();

        // Serialize and deserialize
        let bytes = file.to_bytes();
        let parsed = rl_crypto::format::RecordingFile::from_bytes(&bytes).unwrap();

        // Decrypt
        let kek_rx = rx.diffie_hellman(tx.public_key()).derive_kek(b"rl-keks/v1");
        let _decrypted =
            rl_crypto::decrypt::decrypt_recording(&parsed, &rx.fingerprint(), &kek_rx).unwrap();

        // Decode back to PCM
        let mut decoder = OpusDecoder::new().unwrap();
        let decoded = decoder
            .decode_all(&frames.iter().map(|f| f.clone()).collect::<Vec<_>>())
            .unwrap();

        assert_eq!(decoded.len(), pcm.len());
        assert!(decoded.iter().any(|&s| s != 0));
    }
}
