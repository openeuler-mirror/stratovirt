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

#[cfg(feature = "scream_alsa")]
mod alsa;
mod audio_demo;
#[cfg(all(target_env = "ohos", feature = "scream_ohaudio"))]
mod ohos;
#[cfg(feature = "scream_pulseaudio")]
mod pulseaudio;

use std::{
    mem,
    str::FromStr,
    sync::{
        atomic::{fence, Ordering},
        Arc, Mutex, RwLock, Weak,
    },
    thread,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use core::time;
use log::{error, warn};

#[cfg(feature = "scream_alsa")]
use self::alsa::AlsaStreamData;
use self::audio_demo::AudioDemo;
use super::ivshmem::Ivshmem;
use crate::pci::{PciBus, PciDevOps};
use address_space::{GuestAddress, HostMemMapping, Region};
use machine_manager::config::{get_pci_df, valid_id};
#[cfg(all(target_env = "ohos", feature = "scream_ohaudio"))]
use ohos::ohaudio::OhAudio;
#[cfg(feature = "scream_pulseaudio")]
use pulseaudio::PulseStreamData;
#[cfg(all(target_env = "ohos", feature = "scream_ohaudio"))]
use util::ohos_binding::misc::{get_firstcaller_tokenid, set_firstcaller_tokenid};

pub const AUDIO_SAMPLE_RATE_44KHZ: u32 = 44100;
pub const AUDIO_SAMPLE_RATE_48KHZ: u32 = 48000;

pub const WINDOWS_SAMPLE_BASE_RATE: u8 = 128;

pub const TARGET_LATENCY_MS: u32 = 50;

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
#[derive(Default, Clone, Copy, Debug)]
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
    pub fn check(&self, last_end: u64) -> bool {
        if (self.offset as u64) < last_end {
            warn!(
                "Guest set bad offset {} exceeds last stream buffer end {}",
                self.offset, last_end
            );
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
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
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

impl ShmemStreamFmt {
    pub fn get_rate(&self) -> u32 {
        let sample_rate = if self.rate >= WINDOWS_SAMPLE_BASE_RATE {
            AUDIO_SAMPLE_RATE_44KHZ
        } else {
            AUDIO_SAMPLE_RATE_48KHZ
        };
        sample_rate * (self.rate % WINDOWS_SAMPLE_BASE_RATE) as u32
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
    ) {
        // SAFETY: hva is the shared memory base address. It already verifies the validity
        // of the address range during the scream realize.
        let mut header = &unsafe { std::slice::from_raw_parts(hva as *const ShmemHeader, 1) }[0];

        let stream_header = match dir {
            ScreamDirection::Playback => &header.play,
            ScreamDirection::Record => &header.capt,
        };
        trace::scream_init(&dir, &stream_header);

        loop {
            if header.magic != SCREAM_MAGIC || stream_header.is_started == 0 {
                interface.lock().unwrap().destroy();
                while header.magic != SCREAM_MAGIC || stream_header.is_started == 0 {
                    thread::sleep(time::Duration::from_millis(10));
                    header =
                        // SAFETY: hva is allocated by libc:::mmap, it can be guaranteed to be legal.
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

            if !stream_header.check(last_end) {
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

    fn update_buffer_by_chunk_idx(
        &mut self,
        hva: u64,
        shmem_size: u64,
        stream_header: &ShmemStreamHeader,
    ) -> bool {
        self.audio_size = stream_header.chunk_size;
        self.audio_base = hva
            + stream_header.offset as u64
            + (stream_header.chunk_size as u64) * (self.chunk_idx as u64);

        if (self.audio_base + self.audio_size as u64) > (hva + shmem_size) {
            error!(
                "Scream: wrong header: offset {} chunk_idx {} chunk_size {} max_chunks {}",
                stream_header.offset,
                stream_header.chunk_idx,
                stream_header.chunk_size,
                stream_header.max_chunks,
            );
            return false;
        }
        true
    }

    fn playback_trans(
        &mut self,
        hva: u64,
        shmem_size: u64,
        interface: Arc<Mutex<dyn AudioInterface>>,
    ) {
        // SAFETY: hva is the shared memory base address. It already verifies the validity
        // of the address range during the header check.
        let header = &mut unsafe { std::slice::from_raw_parts_mut(hva as *mut ShmemHeader, 1) }[0];
        let play = &header.play;

        while play.fmt.fmt_generation == self.fmt.fmt_generation && self.chunk_idx != play.chunk_idx
        {
            // If the difference between the currently processed chunk_idx and the chunk_idx in
            // the shared memory is greater than 4, the processing of the backend device is too
            // slow and the backward data is skipped.
            if play
                .chunk_idx
                .wrapping_add(play.max_chunks)
                .wrapping_sub(self.chunk_idx)
                % play.max_chunks
                > 4
            {
                self.chunk_idx =
                    play.chunk_idx.wrapping_add(play.max_chunks).wrapping_sub(1) % play.max_chunks;
            } else {
                self.chunk_idx = (self.chunk_idx + 1) % play.max_chunks;
            }

            if !self.update_buffer_by_chunk_idx(hva, shmem_size, play) {
                return;
            }
            interface.lock().unwrap().send(self);
        }
    }

    fn capture_trans(
        &mut self,
        hva: u64,
        shmem_size: u64,
        interface: Arc<Mutex<dyn AudioInterface>>,
    ) {
        // SAFETY: hva is the shared memory base address. It already verifies the validity
        // of the address range during the header check.
        let header = &mut unsafe { std::slice::from_raw_parts_mut(hva as *mut ShmemHeader, 1) }[0];
        let capt = &mut header.capt;
        let addr = hva + capt.offset as u64;
        let mut locked_interface = interface.lock().unwrap();

        locked_interface.pre_receive(addr, capt);
        while capt.is_started != 0 {
            if !self.update_buffer_by_chunk_idx(hva, shmem_size, capt) {
                return;
            }

            let recv_chunks_cnt = locked_interface.receive(self);
            if recv_chunks_cnt > 0 {
                self.chunk_idx = (self.chunk_idx + recv_chunks_cnt as u16) % capt.max_chunks;

                // Make sure chunk_idx write does not bypass audio chunk write.
                fence(Ordering::SeqCst);

                capt.chunk_idx = self.chunk_idx;
            }
        }
    }
}

#[cfg(all(target_env = "ohos", feature = "scream_ohaudio"))]
fn bound_tokenid(token_id: u64) -> Result<()> {
    if token_id == 0 {
        bail!("UI token ID not passed.");
    } else if token_id != get_firstcaller_tokenid()? {
        set_firstcaller_tokenid(token_id)?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
enum ScreamInterface {
    #[cfg(feature = "scream_alsa")]
    Alsa,
    #[cfg(feature = "scream_pulseaudio")]
    PulseAudio,
    #[cfg(all(target_env = "ohos", feature = "scream_ohaudio"))]
    OhAudio,
    Demo,
}

impl FromStr for ScreamInterface {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            #[cfg(feature = "scream_alsa")]
            "ALSA" => Ok(ScreamInterface::Alsa),
            #[cfg(feature = "scream_pulseaudio")]
            "PulseAudio" => Ok(ScreamInterface::PulseAudio),
            #[cfg(all(target_env = "ohos", feature = "scream_ohaudio"))]
            "OhAudio" => Ok(ScreamInterface::OhAudio),
            "Demo" => Ok(ScreamInterface::Demo),
            _ => Err(anyhow!("Unknown scream interface")),
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(name = "ivshmem_scream")]
pub struct ScreamConfig {
    #[arg(long, value_parser = valid_id)]
    id: String,
    #[arg(long)]
    pub bus: String,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: (u8, u8),
    #[arg(long)]
    pub memdev: String,
    #[arg(long)]
    interface: ScreamInterface,
    #[arg(long, default_value = "")]
    playback: String,
    #[arg(long, default_value = "")]
    record: String,
}

/// Scream sound card device structure.
pub struct Scream {
    hva: u64,
    size: u64,
    config: ScreamConfig,
    token_id: Option<Arc<RwLock<u64>>>,
}

impl Scream {
    pub fn new(size: u64, config: ScreamConfig, token_id: Option<Arc<RwLock<u64>>>) -> Self {
        Self {
            hva: 0,
            size,
            config,
            token_id,
        }
    }

    #[allow(unused_variables)]
    fn interface_init(&self, name: &str, dir: ScreamDirection) -> Arc<Mutex<dyn AudioInterface>> {
        match self.config.interface {
            #[cfg(feature = "scream_alsa")]
            ScreamInterface::Alsa => Arc::new(Mutex::new(AlsaStreamData::init(name, dir))),
            #[cfg(feature = "scream_pulseaudio")]
            ScreamInterface::PulseAudio => Arc::new(Mutex::new(PulseStreamData::init(name, dir))),
            #[cfg(all(target_env = "ohos", feature = "scream_ohaudio"))]
            ScreamInterface::OhAudio => Arc::new(Mutex::new(OhAudio::init(dir))),
            ScreamInterface::Demo => Arc::new(Mutex::new(AudioDemo::init(
                dir,
                self.config.playback.clone(),
                self.config.record.clone(),
            ))),
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
                    );

                    play_data.playback_trans(hva, shmem_size, clone_interface.clone());
                }
            })
            .with_context(|| "Failed to create thread scream")?;
        Ok(())
    }

    fn start_record_thread_fn(&self) -> Result<()> {
        let hva = self.hva;
        let shmem_size = self.size;
        let interface = self.interface_init("ScreamCapt", ScreamDirection::Record);
        let _ti = self.token_id.clone();
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
                    );

                    #[cfg(all(target_env = "ohos", feature = "scream_ohaudio"))]
                    if let Some(token_id) = &_ti {
                        bound_tokenid(*token_id.read().unwrap())
                            .unwrap_or_else(|e| error!("bound token ID failed: {}", e));
                    }
                    capt_data.capture_trans(hva, shmem_size, clone_interface.clone());
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
    // For OHOS's audio task. It confirms shmem info.
    #[allow(unused_variables)]
    fn pre_receive(&mut self, start_addr: u64, sh_header: &ShmemStreamHeader) {}
    fn receive(&mut self, recv_data: &StreamData) -> i32;
    fn destroy(&mut self);
}
