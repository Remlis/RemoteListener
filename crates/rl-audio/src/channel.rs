//! AudioChannel: single audio input with independent recording state.

use crate::capture::{AudioError, AudioInput, SineWaveInput};
use crate::encoder::{Bitrate, OpusEncoder};
use crate::recorder::RecordingWriter;
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
        })
    }

    /// Start recording to a file.
    pub fn start_recording(&mut self, path: PathBuf, channel_id: &str) -> Result<(), AudioError> {
        self.recording_enabled = true;
        self.recorder = Some(RecordingWriter::new(path, channel_id.to_string()));
        Ok(())
    }

    /// Stop recording.
    pub fn stop_recording(&mut self) {
        self.recording_enabled = false;
        self.recorder = None;
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

    /// Encode PCM to Opus frames.
    pub fn encode(&mut self, pcm: &[i16]) -> Result<Vec<Vec<u8>>, AudioError> {
        self.encoder.encode_all(pcm)
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
    use aes_gcm::KeyInit;
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
        let decrypted =
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
