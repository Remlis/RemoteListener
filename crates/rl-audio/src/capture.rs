//! Audio input trait and implementations.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

/// A chunk of raw PCM audio samples (i16 mono, 48kHz).
#[derive(Debug, Clone)]
pub struct AudioChunk {
    pub samples: Vec<i16>,
    pub timestamp_us: u64,
}

/// Trait for audio input sources.
pub trait AudioInput: Send {
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
        let freq = self.frequency;
        let sr = self.sample_rate;
        let total_samples = (sr as f64 * self.duration_secs) as usize;

        // Generate samples in chunks of 960 (20ms at 48kHz) to avoid
        // allocating all samples in memory at once.
        std::thread::spawn(move || {
            let chunk_size = 960usize;
            let mut sample_idx = 0usize;

            while sample_idx < total_samples {
                let end = (sample_idx + chunk_size).min(total_samples);
                let samples: Vec<i16> = (sample_idx..end)
                    .map(|i| {
                        let t = i as f64 / sr as f64;
                        let val = (2.0 * std::f64::consts::PI * freq * t).sin();
                        (val * i16::MAX as f64 * 0.5) as i16
                    })
                    .collect();

                let chunk = AudioChunk {
                    samples,
                    timestamp_us: (sample_idx as u64 * 1_000_000) / sr as u64,
                };

                if tx.send(chunk).is_err() {
                    break; // Receiver dropped
                }
                sample_idx = end;
            }
        });

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
    device: Option<cpal::Device>,
    device_name: String,
    device_uid: String,
    stream: Option<cpal::Stream>,
    sample_rate: u32,
    /// Per-instance sample position counter (avoids the static sharing bug).
    sample_pos: Arc<AtomicU64>,
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

        let sample_rate = device
            .default_input_config()
            .map(|c| c.sample_rate())
            .unwrap_or(48000);

        Ok(Self {
            device: Some(device),
            device_name: name,
            device_uid: uid,
            stream: None,
            sample_rate,
            sample_pos: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Create a cpal input targeting a specific device by UID.
    pub fn with_device_uid(uid: &str) -> Result<Self, AudioError> {
        let host = cpal::default_host();
        let default = host.default_input_device();

        let device = host
            .input_devices()
            .map_err(|_| AudioError::NoDevice)?
            .find(|d| d.id().map(|id| id.1 == uid).unwrap_or(false))
            .ok_or(AudioError::NoDevice)?;

        let name = device
            .description()
            .map(|d| d.to_string())
            .unwrap_or_else(|_| "Unknown".into());

        let _is_default = default
            .as_ref()
            .map(|def| def.id().map(|did| did.1 == uid).unwrap_or(false))
            .unwrap_or(false);

        let sample_rate = device
            .default_input_config()
            .map(|c| c.sample_rate())
            .unwrap_or(48000);

        Ok(Self {
            device: Some(device),
            device_name: name,
            device_uid: uid.to_string(),
            stream: None,
            sample_rate,
            sample_pos: Arc::new(AtomicU64::new(0)),
        })
    }

    /// The device name.
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// The device UID.
    pub fn device_uid(&self) -> &str {
        &self.device_uid
    }

    /// Find a supported config close to 48kHz mono i16.
    fn find_config(
        device: &cpal::Device,
    ) -> Result<(cpal::StreamConfig, cpal::SampleFormat, u32), AudioError> {
        let supported = device
            .supported_input_configs()
            .map_err(|_| AudioError::NoConfig)?;

        let target_rate: cpal::SampleRate = 48000;
        let mut best: Option<(cpal::StreamConfig, cpal::SampleFormat, u32)> = None;

        for cfg in supported {
            if cfg.channels() > 2 {
                continue;
            }
            let min = cfg.min_sample_rate();
            let max = cfg.max_sample_rate();
            let rate: cpal::SampleRate = if min <= target_rate && target_rate <= max {
                48000
            } else {
                // Pick the closest available rate
                let min_dist = (min as i64 - 48000).unsigned_abs();
                let max_dist = (max as i64 - 48000).unsigned_abs();
                if min_dist < max_dist {
                    min
                } else {
                    max
                }
            };

            let config = cpal::StreamConfig {
                channels: cfg.channels().min(2),
                sample_rate: rate,
                buffer_size: cpal::BufferSize::Default,
            };

            // Prefer i16, then f32
            match cfg.sample_format() {
                cpal::SampleFormat::I16 => {
                    return Ok((config, cpal::SampleFormat::I16, rate));
                }
                cpal::SampleFormat::F32 => {
                    if best.is_none() || best.as_ref().unwrap().1 != cpal::SampleFormat::I16 {
                        best = Some((config, cpal::SampleFormat::F32, rate));
                    }
                }
                _ => continue,
            }
        }

        best.ok_or(AudioError::NoConfig)
    }
}

impl AudioInput for CpalInput {
    fn start(&mut self) -> Result<mpsc::Receiver<AudioChunk>, AudioError> {
        let device = self.device.take().ok_or(AudioError::NoDevice)?;
        let (config, sample_format, native_rate) = Self::find_config(&device)?;
        let channels = config.channels;
        let target_rate = 48000u32;
        let chunk_size = 960usize; // 20ms at 48kHz mono
        let sample_pos = self.sample_pos.clone();

        let (tx, rx) = mpsc::channel();

        let err_tx = tx.clone();

        let stream = match sample_format {
            cpal::SampleFormat::I16 => device.build_input_stream::<i16, _, _>(
                &config,
                move |data: &[i16], _info: &cpal::InputCallbackInfo| {
                    capture_callback(data, channels, native_rate, target_rate, chunk_size, &tx, &sample_pos);
                },
                move |err| {
                    tracing::error!("Audio capture error: {}", err);
                    let _ = err_tx.send(AudioChunk {
                        samples: vec![],
                        timestamp_us: 0,
                    });
                },
                None,
            ),
            cpal::SampleFormat::F32 => device.build_input_stream::<f32, _, _>(
                &config,
                move |data: &[f32], _info: &cpal::InputCallbackInfo| {
                    capture_callback_f32(data, channels, native_rate, target_rate, chunk_size, &tx, &sample_pos);
                },
                move |err| {
                    tracing::error!("Audio capture error: {}", err);
                    let _ = err_tx.send(AudioChunk {
                        samples: vec![],
                        timestamp_us: 0,
                    });
                },
                None,
            ),
            _ => return Err(AudioError::NoConfig),
        };

        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to build input stream: {}", e);
                self.device = Some(device);
                return Err(AudioError::CaptureFailed);
            }
        };

        stream.play().map_err(|e| {
            tracing::error!("Failed to start input stream: {}", e);
            AudioError::CaptureFailed
        })?;

        self.stream = Some(stream);
        // Keep the device reference so we can restart later
        self.device = Some(device);
        self.sample_rate = native_rate;

        Ok(rx)
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

/// Capture callback for i16 input samples.
fn capture_callback(
    data: &[i16],
    channels: u16,
    native_rate: u32,
    target_rate: u32,
    chunk_size: usize,
    tx: &mpsc::Sender<AudioChunk>,
    sample_pos: &AtomicU64,
) {

    // Convert to mono
    let mono: Vec<i16> = if channels > 1 {
        data.chunks(channels as usize)
            .map(|frame| {
                let sum: i64 = frame.iter().map(|&s| s as i64).sum();
                (sum / frame.len() as i64) as i16
            })
            .collect()
    } else {
        data.to_vec()
    };

    // Simple linear resampling if native rate != 48kHz
    let resampled: Vec<i16> = if native_rate != target_rate {
        let ratio = native_rate as f64 / target_rate as f64;
        let out_len = (mono.len() as f64 / ratio) as usize;
        (0..out_len)
            .map(|i| {
                let src_idx = (i as f64 * ratio) as usize;
                mono[src_idx.min(mono.len() - 1)]
            })
            .collect()
    } else {
        mono
    };

    // Accumulate into chunks
    let mut pos = sample_pos.load(Ordering::Relaxed);
    for chunk in resampled.chunks(chunk_size) {
        if chunk.len() < chunk_size {
            // Partial chunk — pad with zeros
            let mut padded = chunk.to_vec();
            padded.resize(chunk_size, 0);
            let ts = (pos * 1_000_000) / target_rate as u64;
            pos += chunk_size as u64;
            if tx
                .send(AudioChunk {
                    samples: padded,
                    timestamp_us: ts,
                })
                .is_err()
            {
                break;
            }
        } else {
            let ts = (pos * 1_000_000) / target_rate as u64;
            pos += chunk_size as u64;
            if tx
                .send(AudioChunk {
                    samples: chunk.to_vec(),
                    timestamp_us: ts,
                })
                .is_err()
            {
                break;
            }
        }
    }
    sample_pos.store(pos, Ordering::Relaxed);
}

/// Capture callback for f32 input samples.
fn capture_callback_f32(
    data: &[f32],
    channels: u16,
    native_rate: u32,
    target_rate: u32,
    chunk_size: usize,
    tx: &mpsc::Sender<AudioChunk>,
    sample_pos: &AtomicU64,
) {

    // Convert f32 to i16 mono
    let mono: Vec<i16> = if channels > 1 {
        data.chunks(channels as usize)
            .map(|frame| {
                let sum: f64 = frame.iter().map(|&s| s as f64).sum();
                let avg = sum / frame.len() as f64;
                f32_to_i16(avg as f32)
            })
            .collect()
    } else {
        data.iter().map(|&s| f32_to_i16(s)).collect()
    };

    // Simple linear resampling if native rate != 48kHz
    let resampled: Vec<i16> = if native_rate != target_rate {
        let ratio = native_rate as f64 / target_rate as f64;
        let out_len = (mono.len() as f64 / ratio) as usize;
        (0..out_len)
            .map(|i| {
                let src_idx = (i as f64 * ratio) as usize;
                mono[src_idx.min(mono.len() - 1)]
            })
            .collect()
    } else {
        mono
    };

    // Accumulate into chunks
    let mut pos = sample_pos.load(Ordering::Relaxed);
    for chunk in resampled.chunks(chunk_size) {
        if chunk.len() < chunk_size {
            let mut padded = chunk.to_vec();
            padded.resize(chunk_size, 0);
            let ts = (pos * 1_000_000) / target_rate as u64;
            pos += chunk_size as u64;
            if tx
                .send(AudioChunk {
                    samples: padded,
                    timestamp_us: ts,
                })
                .is_err()
            {
                break;
            }
        } else {
            let ts = (pos * 1_000_000) / target_rate as u64;
            pos += chunk_size as u64;
            if tx
                .send(AudioChunk {
                    samples: chunk.to_vec(),
                    timestamp_us: ts,
                })
                .is_err()
            {
                break;
            }
        }
    }
    sample_pos.store(pos, Ordering::Relaxed);
}

/// Convert f32 sample to i16 with clamping.
fn f32_to_i16(s: f32) -> i16 {
    let clamped = s.clamp(-1.0, 1.0);
    (clamped * i16::MAX as f32) as i16
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
