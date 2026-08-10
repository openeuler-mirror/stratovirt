// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

pub mod auth;
pub mod backend;
pub mod volume;

pub use auth::{get_record_authority, set_record_authority};

use std::{
    fmt::Debug,
    str::FromStr,
    sync::{Arc, RwLock},
};

use anyhow::{Result, bail};

#[cfg(target_env = "gnu")]
use crate::backend::alsa;
#[cfg(target_env = "ohos")]
use crate::backend::ohaudio;

/// Supported PCM sample formats.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PcmFmt {
    FmtS16,
    FmtS24,
    FmtS32,
}

impl PcmFmt {
    /// Get the bits per sample for this format.
    pub fn bits_per_sample(&self) -> u8 {
        match self {
            PcmFmt::FmtS16 => 16,
            PcmFmt::FmtS24 => 24,
            PcmFmt::FmtS32 => 32,
        }
    }

    /// Get the bytes per sample for this format.
    pub fn bytes_per_sample(&self) -> u8 {
        self.bits_per_sample().div_ceil(8)
    }
}

/// Supported PCM frame rates.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PcmRate {
    Rate44100,
    Rate48000,
}

impl PcmRate {
    /// Get the sample rate in Hz.
    pub fn hz(&self) -> u32 {
        match self {
            PcmRate::Rate44100 => 44100,
            PcmRate::Rate48000 => 48000,
        }
    }
}

/// Default number of channels.
pub const DEFAULT_CHANNEL_NUM: u8 = 2;

/// Audio stream direction.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AudioStreamDirection {
    /// Playback (output) direction.
    Playback,
    /// Record (input) direction.
    Record,
}

/// PCM stream parameters.
#[derive(Debug, Clone)]
pub struct AudioStreamParams {
    /// Sample rate.
    pub rate: PcmRate,
    /// Sample format (bits per sample).
    pub format: PcmFmt,
    /// Number of channels.
    pub channels: u8,
    /// Direction (playback or record).
    pub direction: AudioStreamDirection,
    /// Period size in bytes.
    pub period_bytes: u32,
}

impl AudioStreamParams {
    /// Calculate frame size in bytes (channels * bytes_per_sample).
    pub fn frame_size(&self) -> u32 {
        (self.channels * self.format.bytes_per_sample()) as u32
    }
}

/// Audio backend trait for audio I/O operations.
///
/// This trait abstracts different audio backends (ALSA, OHAudio, etc.) to provide
/// a unified interface for audio playback and capture.
///
/// - Backend has its own event loop/thread
/// - Backend calls `io_handler.read()` for playback, `io_handler.write()` for capture
pub trait AudioInterface: Debug + Send {
    /// Initialize the backend with stream parameters.
    ///
    /// # Arguments
    ///
    /// * `params` - PCM stream parameters.
    /// * `io_handler` - Handler for reading/writing audio data called by backend.
    /// * `token_id` - Optional token ID for permission control (OHOS specific).
    fn new(
        params: AudioStreamParams,
        io_handler: Arc<dyn AudioStreamIo>,
        token_id: Option<Arc<RwLock<u64>>>,
    ) -> Result<Box<Self>>
    where
        Self: Sized;

    /// Start the audio stream.
    fn start(&mut self) -> Result<()>;

    /// Stop the audio stream.
    fn stop(&mut self) -> Result<()>;

    /// Release resources held by the backend.
    fn release(&mut self) -> Result<()> {
        self.stop()
    }
}

/// Trait for stream I/O operations in Pull mode.
///
/// We intentionally use `&self` instead of `&mut self` to avoid forcing audio backends
/// to wrap the handler in an outer `Mutex`. Implementations should use interior
/// mutability where needed.
pub trait AudioStreamIo: Sync + Send {
    /// Pull playback PCM data into `buf`. Returns bytes written into `buf`.
    ///
    /// Implementations should be non-blocking; returning 0 indicates no data available.
    fn read(&self, buf: &mut [u8]) -> Result<usize>;

    /// Push captured PCM data from `buf` into the device. Returns bytes consumed from `buf`.
    ///
    /// Implementations should be non-blocking; returning 0 indicates no destination available.
    fn write(&self, buf: &[u8]) -> Result<usize>;
}

/// Audio backend type enumeration.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum AudioBackend {
    /// OHAudio backend for OpenHarmony.
    #[cfg(target_env = "ohos")]
    OHAudio,
    /// ALSA backend for Linux.
    #[cfg(target_env = "gnu")]
    Alsa,
    /// Null backend (no actual audio output).
    #[default]
    Null,
}

impl FromStr for AudioBackend {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            #[cfg(target_env = "ohos")]
            "ohaudio" => Ok(AudioBackend::OHAudio),
            #[cfg(target_env = "gnu")]
            "alsa" => Ok(AudioBackend::Alsa),
            "null" => Ok(AudioBackend::Null),
            _ => bail!("Unknown audio backend type: {}", s),
        }
    }
}

/// Create an audio interface for the specified backend.
///
/// # Arguments
///
/// * `backend` - The audio backend type to create.
/// * `params` - PCM stream parameters.
/// * `io_handler` - Handler for reading/writing audio data.
/// * `token_id` - Optional token ID for permission control.
///
/// # Returns
///
/// A boxed AudioInterface trait object, or an error if creation fails.
#[allow(unused_variables)]
pub fn create_audio_interface(
    backend: AudioBackend,
    params: AudioStreamParams,
    io_handler: Arc<dyn AudioStreamIo>,
    token_id: Option<Arc<RwLock<u64>>>,
) -> Result<Box<dyn AudioInterface>> {
    match backend {
        #[cfg(target_env = "ohos")]
        AudioBackend::OHAudio => ohaudio::OhAudio::new(params, io_handler, token_id)
            .map(|i| i as Box<dyn AudioInterface>),
        #[cfg(target_env = "gnu")]
        AudioBackend::Alsa => {
            alsa::Alsa::new(params, io_handler, token_id).map(|i| i as Box<dyn AudioInterface>)
        }
        AudioBackend::Null => {
            bail!("Null audio backend is not implemented; use a real backend");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_pcm_fmt_debug_and_clone() {
        let fmt = PcmFmt::FmtS16;
        let fmt_clone = fmt;
        assert_eq!(fmt, fmt_clone);
        let debug_str = format!("{:?}", fmt);
        assert!(!debug_str.is_empty());
    }

    #[test]
    fn test_pcm_rate_debug_and_clone() {
        let rate = PcmRate::Rate44100;
        let rate_clone = rate;
        assert_eq!(rate, rate_clone);
    }

    #[test]
    fn test_default_channel_num() {
        assert_eq!(DEFAULT_CHANNEL_NUM, 2);
    }

    #[test]
    fn test_audio_stream_direction() {
        assert_eq!(AudioStreamDirection::Playback as u8, 0);
        assert_eq!(AudioStreamDirection::Record as u8, 1);

        // Test Debug and Clone
        let dir = AudioStreamDirection::Playback;
        let dir_clone = dir;
        assert_eq!(dir, dir_clone);
    }

    #[test]
    fn test_audio_stream_params_frame_size() {
        // Mono, S16: 1 * 2 = 2 bytes per frame
        let params = AudioStreamParams {
            rate: PcmRate::Rate44100,
            format: PcmFmt::FmtS16,
            channels: 1,
            direction: AudioStreamDirection::Playback,
            period_bytes: 8192,
        };
        assert_eq!(params.frame_size(), 2);

        // Stereo, S16: 2 * 2 = 4 bytes per frame
        let params = AudioStreamParams {
            rate: PcmRate::Rate48000,
            format: PcmFmt::FmtS16,
            channels: 2,
            direction: AudioStreamDirection::Record,
            period_bytes: 4096,
        };
        assert_eq!(params.frame_size(), 4);

        // Stereo, S24: 2 * 3 = 6 bytes per frame
        let params = AudioStreamParams {
            rate: PcmRate::Rate44100,
            format: PcmFmt::FmtS24,
            channels: 2,
            direction: AudioStreamDirection::Playback,
            period_bytes: 0,
        };
        assert_eq!(params.frame_size(), 6);

        // 5.1 surround, S32: 6 * 4 = 24 bytes per frame
        let params = AudioStreamParams {
            rate: PcmRate::Rate48000,
            format: PcmFmt::FmtS32,
            channels: 6,
            direction: AudioStreamDirection::Record,
            period_bytes: 1024,
        };
        assert_eq!(params.frame_size(), 24);
    }

    #[test]
    fn test_audio_stream_params_debug_and_clone() {
        let params = AudioStreamParams {
            rate: PcmRate::Rate44100,
            format: PcmFmt::FmtS16,
            channels: 2,
            direction: AudioStreamDirection::Playback,
            period_bytes: 8192,
        };
        let params_clone = params.clone();
        assert_eq!(params.rate, params_clone.rate);
        assert_eq!(params.format, params_clone.format);
        assert_eq!(params.channels, params_clone.channels);
        assert_eq!(params.direction, params_clone.direction);
        assert_eq!(params.period_bytes, params_clone.period_bytes);
    }

    // ============ AudioBackend tests ============
    #[test]
    fn test_audio_backend_from_str_invalid() {
        let result = AudioBackend::from_str("unknown");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unknown audio backend type")
        );

        let result = AudioBackend::from_str("");
        assert!(result.is_err());
    }

    #[test]
    fn test_audio_backend_debug_and_clone() {
        let backend = AudioBackend::Null;
        let backend_clone = backend.clone();
        assert_eq!(backend, backend_clone);
        let debug_str = format!("{:?}", backend);
        assert!(!debug_str.is_empty());
    }

    // ============ create_audio_interface tests ============

    #[test]
    fn test_create_audio_interface_null_backend() {
        struct MockIo;
        impl AudioStreamIo for MockIo {
            fn read(&self, _buf: &mut [u8]) -> Result<usize> {
                Ok(0)
            }
            fn write(&self, _buf: &[u8]) -> Result<usize> {
                Ok(0)
            }
        }

        let params = AudioStreamParams {
            rate: PcmRate::Rate44100,
            format: PcmFmt::FmtS16,
            channels: 2,
            direction: AudioStreamDirection::Playback,
            period_bytes: 8192,
        };
        let io_handler = Arc::new(MockIo);

        let result = create_audio_interface(AudioBackend::Null, params, io_handler, None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Null audio backend is not implemented")
        );
    }

    #[test]
    fn test_mock_audio_stream_io() {
        /// A mock IO handler that satisfies both `Send` and `Sync`.
        ///
        /// Uses `Arc<[u8]>` instead of `Vec<u8>` because `Vec<u8>` is not `Sync`,
        /// while `[u8]` is `Sync` (immutable slice access is thread-safe).
        struct TestIo {
            read_data: Arc<[u8]>,
        }
        impl AudioStreamIo for TestIo {
            fn read(&self, buf: &mut [u8]) -> Result<usize> {
                let len = self.read_data.len().min(buf.len());
                buf[..len].copy_from_slice(&self.read_data[..len]);
                Ok(len)
            }
            fn write(&self, buf: &[u8]) -> Result<usize> {
                // Intentionally use interior mutability concept via Send+Sync
                // but for a simple test we just return the length
                Ok(buf.len())
            }
        }

        // Verify that TestIo satisfies Send + Sync bounds required by AudioStreamIo
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TestIo>();

        let io = TestIo {
            read_data: Arc::from(vec![1u8, 2, 3, 4]),
        };

        let mut buf = vec![0u8; 8];
        let n = io.read(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], &[1, 2, 3, 4]);

        let n = io.write(&[5, 6, 7]).unwrap();
        assert_eq!(n, 3);
    }
}
