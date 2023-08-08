// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

mod alsa;
mod audio_demo;
mod pulseaudio;

use std::{
    mem,
    sync::{
        atomic::{fence, Ordering},
        Arc, Mutex, Weak,
    },
    thread,
};

use address_space::{GuestAddress, HostMemMapping, Region};
use anyhow::{bail, Context, Result};
use core::time;
use log::{error, warn};

use self::{alsa::AlsaStreamData, audio_demo::AudioDemo};
use super::ivshmem::Ivshmem;
use crate::pci::{PciBus, PciDevOps};
use machine_manager::config::scream::ScreamConfig;
use pulseaudio::{PulseStreamData, TARGET_LATENCY_MS};

pub const AUDIO_SAMPLE_RATE_44KHZ: u32 = 44100;
pub const AUDIO_SAMPLE_RATE_48KHZ: u32 = 48000;

pub const WINDOWS_SAMPLE_BASE_RATE: u8 = 128;

// A frame of back-end audio data is 50ms, and the next frame of audio data needs
// to be trained in polling within 50ms. Theoretically, the shorter the polling time,
// the better. However, if the value is too small, the overhead is high. So take a
// compromise: 50 * 1000 / 8 us.
const POLL_DELAY_US: u64 = (TARGET_LATENCY_MS as u64) * 1000 / 8;

pub const SCREAM_MAGIC: u64 = 0x02032023;

/// The scream device defines the audio directions.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ScreamDirection {
    Playback,
    Record,
}

/// Audio stream header information in the shared memory.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct ShmemStreamHeader {
    /// Whether audio is started.
    pub is_started: u32,
    /// Current audio chunk position.
    pub chunk_idx: u16,
    /// Maximum number of audio chunk.
    pub max_chunks: u16,
    /// Size of a single audio chunk.
    pub chunk_size: u32,
    /// Offset of the first audio data based on shared memory.
    pub offset: u32,
    start_time_ns: i64,
    /// Audio stream format.
    pub fmt: ShmemStreamFmt,
}

impl ShmemStreamHeader {
    pub fn check(&self, shmem_size: u64, last_end: u64) -> bool {
        if (self.offset as u64) < last_end {
            warn!(
                "Guest set bad offset {} exceeds last stream buffer end {}",
                self.offset, last_end
            );
        }

        let boundary = self.offset as u64 + self.chunk_size as u64 * self.max_chunks as u64;
        if boundary > shmem_size {
            error!(
                "Guest set bad stream params: offset {:x} max chunk num is {}, chunk size is {}",
                self.offset, self.max_chunks, self.chunk_size
            );
            return false;
        }

        if self.chunk_idx > self.max_chunks {
            error!(
                "The chunk index of stream {} exceeds the maximum number of chunks {}",
                self.chunk_idx, self.max_chunks
            );
            return false;
        }
        if self.fmt.channels == 0 || self.fmt.channel_map == 0 {
            error!(
                "The fmt channels {} or channel_map {} is invalid",
                self.fmt.channels, self.fmt.channel_map
            );
            return false;
        }
        true
    }
}

/// First Header data in the shared memory.
#[repr(C)]
#[derive(Default)]
pub struct ShmemHeader {
    magic: u64,
    /// PlayBack audio stream header.
    play: ShmemStreamHeader,
    /// Record audio stream header.
    capt: ShmemStreamHeader,
}

/// Audio stream format in the shared memory.
#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct ShmemStreamFmt {
    /// Indicates whether the audio format is changed.
    pub fmt_generation: u32,
    /// Audio sampling rate.
    pub rate: u8,
    /// Number of audio sampling bits.
    pub size: u8,
    /// Number of audio channel.
    pub channels: u8,
    pad: u8,
    /// Mapping of audio channel.
    pub channel_map: u32,
    pad2: u32,
}

impl Default for ShmemStreamFmt {
    fn default() -> Self {
        Self {
            fmt_generation: 0,
            rate: 0,
            size: 0,
            channels: 2,
            pad: 0,
            channel_map: 0x03,
            pad2: 0,
        }
    }
}

/// Audio stream data structure.
#[derive(Default)]
pub struct StreamData {
    pub fmt: ShmemStreamFmt,
    chunk_idx: u16,
    /// Size of the data to be played or recorded.
    pub audio_size: u32,
    /// Location of the played or recorded audio data in the shared memory.
    pub audio_base: u64,
}

impl StreamData {
    fn init(&mut self, header: &ShmemStreamHeader) {
        fence(Ordering::Acquire);
        self.fmt = header.fmt;
        self.chunk_idx = header.chunk_idx;
    }

    fn wait_for_ready(
        &mut self,
        interface: Arc<Mutex<dyn AudioInterface>>,
        dir: ScreamDirection,
        poll_delay_us: u64,
        hva: u64,
        shmem_size: u64,
    ) {
        // SAFETY: hva is the shared memory base address. It already verifies the validity
        // of the address range during the scream realize.
        let mut header = &unsafe { std::slice::from_raw_parts(hva as *const ShmemHeader, 1) }[0];

        let stream_header = match dir {
            ScreamDirection::Playback => &header.play,
            ScreamDirection::Record => &header.capt,
        };

        loop {
            if header.magic != SCREAM_MAGIC || stream_header.is_started == 0 {
                interface.lock().unwrap().destroy();
                while header.magic != SCREAM_MAGIC || stream_header.is_started == 0 {
                    thread::sleep(time::Duration::from_millis(10));
                    header =
                        &unsafe { std::slice::from_raw_parts(hva as *const ShmemHeader, 1) }[0];
                }
                self.init(stream_header);
            }

            // Audio playback requires waiting for the guest to play audio data.
            if dir == ScreamDirection::Playback && self.chunk_idx == stream_header.chunk_idx {
                thread::sleep(time::Duration::from_micros(poll_delay_us));
                continue;
            }

            let mut last_end = 0;
            // The recording buffer is behind the playback buffer. Thereforce, the end position of
            // the playback buffer must be calculted to determine whether the two buffers overlap.
            if dir == ScreamDirection::Record && header.play.is_started != 0 {
                last_end = header.play.offset as u64
                    + header.play.chunk_size as u64 * header.play.max_chunks as u64;
            }

            if !stream_header.check(shmem_size, last_end) {
                continue;
            }

            // Guest reformats the audio, and the scream device also needs to be init.
            if self.fmt != stream_header.fmt {
                self.init(stream_header);
                continue;
            }

            return;
        }
    }

    fn update_buffer_by_chunk_idx(&mut self, hva: u64, stream_header: &ShmemStreamHeader) {
        self.audio_size = stream_header.chunk_size;
        self.audio_base = hva
            + stream_header.offset as u64
            + (stream_header.chunk_size as u64) * (self.chunk_idx as u64);
    }

    fn playback_trans(&mut self, hva: u64, interface: Arc<Mutex<dyn AudioInterface>>) {
        // SAFETY: hva is the shared memory base address. It already verifies the validity
        // of the address range during the header check.
        let header = &mut unsafe { std::slice::from_raw_parts_mut(hva as *mut ShmemHeader, 1) }[0];
        let play = &header.play;

        while play.fmt.fmt_generation == self.fmt.fmt_generation && self.chunk_idx != play.chunk_idx
        {
            // If the difference between the currently processed chunk_idx and the chunk_idx in
            // the shared memory is greater than 4, the processing of the backend device is too
            // slow and the backward data is skipped.
            if (play.chunk_idx + play.max_chunks - self.chunk_idx) % play.max_chunks > 4 {
                self.chunk_idx = (play.chunk_idx + play.max_chunks - 1) % play.max_chunks;
            } else {
                self.chunk_idx = (self.chunk_idx + 1) % play.max_chunks;
            }

            self.update_buffer_by_chunk_idx(hva, play);
            interface.lock().unwrap().send(self);
        }
    }

    fn capture_trans(&mut self, hva: u64, interface: Arc<Mutex<dyn AudioInterface>>) {
        // SAFETY: hva is the shared memory base address. It already verifies the validity
        // of the address range during the header check.
        let header = &mut unsafe { std::slice::from_raw_parts_mut(hva as *mut ShmemHeader, 1) }[0];
        let capt = &mut header.capt;

        while capt.is_started != 0 {
            self.update_buffer_by_chunk_idx(hva, capt);

            if interface.lock().unwrap().receive(self) {
                self.chunk_idx = (self.chunk_idx + 1) % capt.max_chunks;

                // Make sure chunk_idx write does not bypass audio chunk write.
                fence(Ordering::SeqCst);

                capt.chunk_idx = self.chunk_idx;
            }
        }
    }
}

/// Scream sound card device structure.
pub struct Scream {
    hva: u64,
    size: u64,
    interface: String,
    playback: String,
    record: String,
}

impl Scream {
    pub fn new(size: u64, dev_cfg: &ScreamConfig) -> Self {
        Self {
            hva: 0,
            size,
            interface: dev_cfg.interface.clone(),
            playback: dev_cfg.playback.clone(),
            record: dev_cfg.record.clone(),
        }
    }

    fn interface_init(&self, name: &str, dir: ScreamDirection) -> Arc<Mutex<dyn AudioInterface>> {
        match self.interface.as_str() {
            "ALSA" => Arc::new(Mutex::new(AlsaStreamData::init(name, dir))),
            "PulseAudio" => Arc::new(Mutex::new(PulseStreamData::init(name, dir))),
            "Demo" => Arc::new(Mutex::new(AudioDemo::init(
                dir,
                self.playback.clone(),
                self.record.clone(),
            ))),
            _ => {
                error!(
                    "Unsupported audio interface {}, falling back to ALSA",
                    self.interface
                );
                Arc::new(Mutex::new(AlsaStreamData::init(name, dir)))
            }
        }
    }

    fn start_play_thread_fn(&self) -> Result<()> {
        let hva = self.hva;
        let shmem_size = self.size;
        let interface = self.interface_init("ScreamPlay", ScreamDirection::Playback);
        thread::Builder::new()
            .name("scream audio play worker".to_string())
            .spawn(move || {
                let clone_interface = interface.clone();
                let mut play_data = StreamData::default();

                loop {
                    play_data.wait_for_ready(
                        clone_interface.clone(),
                        ScreamDirection::Playback,
                        POLL_DELAY_US,
                        hva,
                        shmem_size,
                    );

                    play_data.playback_trans(hva, clone_interface.clone());
                }
            })
            .with_context(|| "Failed to create thread scream")?;
        Ok(())
    }

    fn start_record_thread_fn(&self) -> Result<()> {
        let hva = self.hva;
        let shmem_size = self.size;
        let interface = self.interface_init("ScreamCapt", ScreamDirection::Record);
        thread::Builder::new()
            .name("scream audio capt worker".to_string())
            .spawn(move || {
                let clone_interface = interface.clone();
                let mut capt_data = StreamData::default();

                loop {
                    capt_data.wait_for_ready(
                        clone_interface.clone(),
                        ScreamDirection::Record,
                        POLL_DELAY_US,
                        hva,
                        shmem_size,
                    );

                    capt_data.capture_trans(hva, clone_interface.clone());
                }
            })
            .with_context(|| "Failed to create thread scream")?;
        Ok(())
    }

    pub fn realize(mut self, devfn: u8, parent_bus: Weak<Mutex<PciBus>>) -> Result<()> {
        let header_size = mem::size_of::<ShmemHeader>() as u64;
        if self.size < header_size {
            bail!(
                "The size {} of the shared memory is smaller then audio header {}",
                self.size,
                header_size
            );
        }

        let host_mmap = Arc::new(HostMemMapping::new(
            GuestAddress(0),
            None,
            self.size,
            None,
            false,
            true,
            false,
        )?);
        self.hva = host_mmap.host_address();

        let mem_region = Region::init_ram_region(host_mmap, "ivshmem_ram");

        let ivshmem = Ivshmem::new("ivshmem".to_string(), devfn, parent_bus, mem_region);
        ivshmem.realize()?;

        self.start_play_thread_fn()?;
        self.start_record_thread_fn()
    }
}

pub trait AudioInterface: Send {
    fn send(&mut self, recv_data: &StreamData);
    fn receive(&mut self, recv_data: &StreamData) -> bool;
    fn destroy(&mut self);
}
