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
    io::{Read, Write},
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
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
pub trait AudioInterface: Send {
    /// Initialize the backend with stream parameters.
    ///
    /// # Arguments
    ///
    /// * `params` - PCM stream parameters.
    /// * `io_handler` - Handler for reading/writing audio data called by backend.
    /// * `token_id` - Optional token ID for permission control (OHOS specific).
    fn new(
        params: AudioStreamParams,
        io_handler: Arc<Mutex<dyn AudioStreamIo>>,
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

/// Trait for stream I/O operations.
///
/// This trait combines Read and Write for bidirectional audio data transfer.
/// It's used as a callback interface between the audio backend and the
/// device:
/// - `Read::read()` is called by playback backends to get audio data.
/// - `Write::write()` is called by capture backends to send audio data.
pub trait AudioStreamIo: Read + Write + Sync + Send {}

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
    io_handler: Arc<Mutex<dyn AudioStreamIo>>,
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
