//! AudioEngine: manages multiple AudioChannels simultaneously.

use std::collections::HashMap;

use crate::capture::{AudioError, AudioInput, CpalInput, DeviceInfo};
use crate::channel::AudioChannel;
use crate::encoder::Bitrate;
use rl_core::proto::ChannelInfo;

/// Multi-channel audio engine.
pub struct AudioEngine {
    channels: HashMap<String, AudioChannel>,
}

impl Default for AudioEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AudioEngine {
    /// Create a new empty audio engine.
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
        }
    }

    /// Scan system audio input devices.
    pub fn scan_devices() -> Result<Vec<DeviceInfo>, AudioError> {
        let input = CpalInput::new()?;
        input.list_devices()
    }

    /// Add a channel for a real audio device.
    pub fn add_device_channel(
        &mut self,
        channel_id: String,
        device_uid: &str,
        device_name: String,
        bitrate: Bitrate,
    ) -> Result<(), AudioError> {
        let input = Box::new(CpalInput::with_device_uid(device_uid)?);
        let channel = AudioChannel::with_input(
            channel_id.clone(),
            device_name,
            device_uid.to_string(),
            bitrate,
            input,
        )?;
        self.channels.insert(channel_id, channel);
        Ok(())
    }

    /// Add a test sine wave channel.
    pub fn add_test_channel(
        &mut self,
        channel_id: String,
        frequency: f64,
        bitrate: Bitrate,
    ) -> Result<(), AudioError> {
        let channel = AudioChannel::new_test(channel_id.clone(), frequency, bitrate)?;
        self.channels.insert(channel_id, channel);
        Ok(())
    }

    /// Remove a channel by ID.
    pub fn remove_channel(&mut self, channel_id: &str) -> Option<AudioChannel> {
        self.channels.remove(channel_id)
    }

    /// Get a channel by ID.
    pub fn get_channel(&self, channel_id: &str) -> Option<&AudioChannel> {
        self.channels.get(channel_id)
    }

    /// Get a mutable channel by ID.
    pub fn get_channel_mut(&mut self, channel_id: &str) -> Option<&mut AudioChannel> {
        self.channels.get_mut(channel_id)
    }

    /// List all channel IDs.
    pub fn channel_ids(&self) -> Vec<String> {
        self.channels.keys().cloned().collect()
    }

    /// List all channels.
    pub fn channels(&self) -> Vec<&AudioChannel> {
        self.channels.values().collect()
    }

    /// Number of channels.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Get ChannelInfo for all channels.
    pub fn channel_infos(&self) -> Vec<ChannelInfo> {
        self.channels
            .values()
            .map(|ch| ch.to_channel_info())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_add_remove_channels() {
        let mut engine = AudioEngine::new();
        engine
            .add_test_channel("ch-001".into(), 440.0, Bitrate::Kbps16)
            .unwrap();
        engine
            .add_test_channel("ch-002".into(), 880.0, Bitrate::Kbps32)
            .unwrap();
        engine
            .add_test_channel("ch-003".into(), 1000.0, Bitrate::Kbps64)
            .unwrap();

        assert_eq!(engine.channel_count(), 3);
        assert!(engine.get_channel("ch-001").is_some());
        assert!(engine.get_channel("ch-002").is_some());
        assert!(engine.get_channel("ch-003").is_some());

        engine.remove_channel("ch-002");
        assert_eq!(engine.channel_count(), 2);
        assert!(engine.get_channel("ch-002").is_none());
    }

    #[test]
    fn multi_channel_independent_encode() {
        let mut engine = AudioEngine::new();
        engine
            .add_test_channel("ch-A".into(), 440.0, Bitrate::Kbps16)
            .unwrap();
        engine
            .add_test_channel("ch-B".into(), 880.0, Bitrate::Kbps32)
            .unwrap();
        engine
            .add_test_channel("ch-C".into(), 1000.0, Bitrate::Kbps64)
            .unwrap();

        // Generate different PCM for each channel
        let pcm_a: Vec<i16> = (0..960)
            .map(|i| {
                let t = i as f64 / 48000.0;
                ((440.0 * 2.0 * std::f64::consts::PI * t).sin() * 8000.0) as i16
            })
            .collect();
        let pcm_b: Vec<i16> = (0..960)
            .map(|i| {
                let t = i as f64 / 48000.0;
                ((880.0 * 2.0 * std::f64::consts::PI * t).sin() * 8000.0) as i16
            })
            .collect();
        let pcm_c: Vec<i16> = (0..960)
            .map(|i| {
                let t = i as f64 / 48000.0;
                ((1000.0 * 2.0 * std::f64::consts::PI * t).sin() * 8000.0) as i16
            })
            .collect();

        // Encode each channel independently
        let frames_a = engine
            .get_channel_mut("ch-A")
            .unwrap()
            .encode(&pcm_a)
            .unwrap();
        let frames_b = engine
            .get_channel_mut("ch-B")
            .unwrap()
            .encode(&pcm_b)
            .unwrap();
        let frames_c = engine
            .get_channel_mut("ch-C")
            .unwrap()
            .encode(&pcm_c)
            .unwrap();

        // Each should produce output
        assert!(!frames_a.is_empty());
        assert!(!frames_b.is_empty());
        assert!(!frames_c.is_empty());

        // Decode and verify each independently
        use crate::decoder::OpusDecoder;

        let mut dec = OpusDecoder::new().unwrap();
        let decoded_a = dec.decode_all(&frames_a).unwrap();
        assert_eq!(decoded_a.len(), 960);
        assert!(decoded_a.iter().any(|&s| s != 0));

        let decoded_b = dec.decode_all(&frames_b).unwrap();
        assert_eq!(decoded_b.len(), 960);
        assert!(decoded_b.iter().any(|&s| s != 0));

        let decoded_c = dec.decode_all(&frames_c).unwrap();
        assert_eq!(decoded_c.len(), 960);
        assert!(decoded_c.iter().any(|&s| s != 0));
    }

    #[test]
    fn channel_bitrate_independent() {
        let mut engine = AudioEngine::new();
        engine
            .add_test_channel("ch-16".into(), 440.0, Bitrate::Kbps16)
            .unwrap();
        engine
            .add_test_channel("ch-32".into(), 440.0, Bitrate::Kbps32)
            .unwrap();

        assert_eq!(
            engine.get_channel("ch-16").unwrap().bitrate,
            Bitrate::Kbps16
        );
        assert_eq!(
            engine.get_channel("ch-32").unwrap().bitrate,
            Bitrate::Kbps32
        );

        // Change bitrate on one channel
        engine
            .get_channel_mut("ch-16")
            .unwrap()
            .set_bitrate(Bitrate::Kbps128)
            .unwrap();
        assert_eq!(
            engine.get_channel("ch-16").unwrap().bitrate,
            Bitrate::Kbps128
        );
        // Other channel unchanged
        assert_eq!(
            engine.get_channel("ch-32").unwrap().bitrate,
            Bitrate::Kbps32
        );
    }
}
