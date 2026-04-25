//! Opus encoder wrapper.

use opus::{Application, Encoder};

use crate::capture::AudioError;

/// Supported Opus bitrates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bitrate {
    Kbps16,
    Kbps32,
    Kbps64,
    Kbps128,
}

impl Bitrate {
    pub fn kbps(&self) -> u32 {
        match self {
            Bitrate::Kbps16 => 16,
            Bitrate::Kbps32 => 32,
            Bitrate::Kbps64 => 64,
            Bitrate::Kbps128 => 128,
        }
    }
}

/// Opus encoder for mono 48kHz audio.
pub struct OpusEncoder {
    encoder: Encoder,
    frame_size: usize, // samples per frame (e.g., 960 for 20ms at 48kHz)
}

impl OpusEncoder {
    pub fn new(bitrate: Bitrate) -> Result<Self, AudioError> {
        let mut encoder = Encoder::new(48000, opus::Channels::Mono, Application::Audio)
            .map_err(|e| AudioError::Opus(e.to_string()))?;

        encoder
            .set_bitrate(opus::Bitrate::Bits(
                (bitrate.kbps() * 1000).try_into().unwrap(),
            ))
            .map_err(|e| AudioError::Opus(e.to_string()))?;

        Ok(Self {
            encoder,
            frame_size: 960, // 20ms at 48kHz
        })
    }

    /// Encode a frame of PCM samples (i16, mono, 48kHz) to Opus.
    pub fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>, AudioError> {
        // Max compressed size: 4000 bytes per frame is more than enough
        let mut output = vec![0u8; 4000];
        let len = self
            .encoder
            .encode(pcm, &mut output)
            .map_err(|e| AudioError::Opus(e.to_string()))?;
        output.truncate(len);
        Ok(output)
    }

    /// The expected frame size in samples.
    pub fn frame_size(&self) -> usize {
        self.frame_size
    }

    /// Encode all PCM data into Opus frames.
    pub fn encode_all(&mut self, pcm: &[i16]) -> Result<Vec<Vec<u8>>, AudioError> {
        let mut frames = Vec::new();
        for chunk in pcm.chunks(self.frame_size) {
            // Pad last chunk with silence if needed
            let mut padded = chunk.to_vec();
            padded.resize(self.frame_size, 0i16);
            let frame = self.encode(&padded)?;
            frames.push(frame);
        }
        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_produces_output() {
        let mut encoder = OpusEncoder::new(Bitrate::Kbps16).unwrap();
        let pcm: Vec<i16> = vec![0i16; 960];
        let output = encoder.encode(&pcm).unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn encode_all_frames() {
        let mut encoder = OpusEncoder::new(Bitrate::Kbps32).unwrap();
        // 3 frames worth of audio
        let pcm: Vec<i16> = vec![0i16; 960 * 3];
        let frames = encoder.encode_all(&pcm).unwrap();
        assert_eq!(frames.len(), 3);
    }
}
