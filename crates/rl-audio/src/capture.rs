//! Audio input trait and implementations.

use std::sync::mpsc;

use cpal::traits::{DeviceTrait, HostTrait};

/// A chunk of raw PCM audio samples (i16 mono, 48kHz).
#[derive(Debug, Clone)]
pub struct AudioChunk {
    pub samples: Vec<i16>,
    pub timestamp_us: u64,
}

/// Trait for audio input sources.
pub trait AudioInput {
    /// Start capturing audio. Returns a receiver for audio chunks.
    fn start(&mut self) -> Result<mpsc::Receiver<AudioChunk>, AudioError>;

    /// Stop capturing audio.
    fn stop(&mut self);

    /// List available input devices.
    fn list_devices(&self) -> Result<Vec<DeviceInfo>, AudioError>;
}

/// Information about an audio device.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub name: String,
    pub uid: String,
    pub is_default: bool,
}

/// Sine wave generator for testing (no real audio hardware needed).
pub struct SineWaveInput {
    frequency: f64,
    sample_rate: u32,
    duration_secs: f64,
}

impl SineWaveInput {
    pub fn new(frequency: f64, sample_rate: u32, duration_secs: f64) -> Self {
        Self {
            frequency,
            sample_rate,
            duration_secs,
        }
    }
}

impl AudioInput for SineWaveInput {
    fn start(&mut self) -> Result<mpsc::Receiver<AudioChunk>, AudioError> {
        let (tx, rx) = mpsc::channel();
        let total_samples = (self.sample_rate as f64 * self.duration_secs) as usize;
        let freq = self.frequency;
        let sr = self.sample_rate;

        let samples: Vec<i16> = (0..total_samples)
            .map(|i| {
                let t = i as f64 / sr as f64;
                let val = (2.0 * std::f64::consts::PI * freq * t).sin();
                (val * i16::MAX as f64 * 0.5) as i16
            })
            .collect();

        let chunk = AudioChunk {
            samples,
            timestamp_us: 0,
        };

        tx.send(chunk).map_err(|_| AudioError::CaptureFailed)?;
        Ok(rx)
    }

    fn stop(&mut self) {}

    fn list_devices(&self) -> Result<Vec<DeviceInfo>, AudioError> {
        Ok(vec![DeviceInfo {
            name: "Sine Wave Generator".into(),
            uid: "sine-wave".into(),
            is_default: true,
        }])
    }
}

/// cpal-based real audio input.
pub struct CpalInput {
    #[allow(dead_code)]
    device_name: String,
    #[allow(dead_code)]
    device_uid: String,
    stream: Option<cpal::Stream>,
}

impl CpalInput {
    /// Create a new cpal input using the default input device.
    pub fn new() -> Result<Self, AudioError> {
        let host = cpal::default_host();
        let device = host.default_input_device().ok_or(AudioError::NoDevice)?;

        let name = device
            .description()
            .map(|d| d.to_string())
            .unwrap_or_else(|_| "Unknown".into());
        let uid = device
            .id()
            .map(|id| id.1.clone())
            .unwrap_or_else(|_| "unknown".into());

        Ok(Self {
            device_name: name,
            device_uid: uid,
            stream: None,
        })
    }
}

impl AudioInput for CpalInput {
    fn start(&mut self) -> Result<mpsc::Receiver<AudioChunk>, AudioError> {
        // Full cpal streaming will be wired up in the transmitter
        Err(AudioError::CaptureFailed)
    }

    fn stop(&mut self) {
        self.stream = None;
    }

    fn list_devices(&self) -> Result<Vec<DeviceInfo>, AudioError> {
        let host = cpal::default_host();
        let default = host.default_input_device();
        let devices: Vec<DeviceInfo> = host
            .input_devices()
            .map_err(|_| AudioError::NoDevice)?
            .filter_map(|d| {
                let name = d.description().ok()?.to_string();
                let uid = d.id().ok()?;
                let is_default = default
                    .as_ref()
                    .map(|def| def.id().map(|did| did.1 == uid.1).unwrap_or(false))
                    .unwrap_or(false);
                Some(DeviceInfo {
                    name,
                    uid: uid.1,
                    is_default,
                })
            })
            .collect();
        Ok(devices)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AudioError {
    #[error("no audio input device found")]
    NoDevice,
    #[error("no audio config available")]
    NoConfig,
    #[error("audio capture failed")]
    CaptureFailed,
    #[error("opus encoding error: {0}")]
    Opus(String),
}
