//! Opus decoder wrapper.

use opus::Decoder;

use crate::capture::AudioError;

/// Opus decoder for mono 48kHz audio.
pub struct OpusDecoder {
    decoder: Decoder,
}

impl OpusDecoder {
    pub fn new() -> Result<Self, AudioError> {
        let decoder = Decoder::new(48000, opus::Channels::Mono)
            .map_err(|e| AudioError::Opus(e.to_string()))?;
        Ok(Self { decoder })
    }

    /// Decode an Opus frame to PCM (i16, mono, 48kHz).
    pub fn decode(&mut self, opus_data: &[u8]) -> Result<Vec<i16>, AudioError> {
        let max_output = 5760; // max frame size: 120ms at 48kHz
        let mut output = vec![0i16; max_output];
        let len = self
            .decoder
            .decode(opus_data, &mut output, false)
            .map_err(|e| AudioError::Opus(e.to_string()))?;
        output.truncate(len);
        Ok(output)
    }

    /// Decode multiple Opus frames into a single PCM buffer.
    pub fn decode_all(&mut self, frames: &[Vec<u8>]) -> Result<Vec<i16>, AudioError> {
        let mut pcm = Vec::new();
        for frame in frames {
            let decoded = self.decode(frame)?;
            pcm.extend_from_slice(&decoded);
        }
        Ok(pcm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::OpusEncoder;

    #[test]
    fn encode_decode_roundtrip() {
        let mut encoder = OpusEncoder::new(crate::encoder::Bitrate::Kbps16).unwrap();
        let mut decoder = OpusDecoder::new().unwrap();

        // Generate a simple sine wave
        let pcm: Vec<i16> = (0..960)
            .map(|i| {
                let t = i as f64 / 48000.0;
                ((440.0 * 2.0 * std::f64::consts::PI * t).sin() * 1000.0) as i16
            })
            .collect();

        let encoded = encoder.encode(&pcm).unwrap();
        let decoded = decoder.decode(&encoded).unwrap();

        // Opus is lossy, so we check the length matches and the signal is non-silent
        assert_eq!(decoded.len(), pcm.len());
        assert!(decoded.iter().any(|&s| s != 0));
    }
}
