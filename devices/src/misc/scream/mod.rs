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
mod ohaudio;
#[cfg(feature = "scream_pulseaudio")]
mod pulseaudio;

use std::str::FromStr;
use std::sync::atomic::{fence, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, Weak};
use std::{mem, thread};

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Parser};
use core::time;
use log::{error, info, warn};
use once_cell::sync::Lazy;

#[cfg(feature = "scream_alsa")]
use self::alsa::AlsaStreamData;
use self::audio_demo::AudioDemo;
use super::ivshmem::Ivshmem;
use crate::pci::{le_read_u32, le_write_u32};
use crate::{Bus, Device};
use address_space::{GuestAddress, HostMemMapping, Region};
use machine_manager::config::{get_pci_df, parse_bool, valid_id};
use machine_manager::notifier::register_vm_pause_notifier;
use machine_manager::state_query::register_state_query_callback;
#[cfg(all(target_env = "ohos", feature = "scream_ohaudio"))]
use ohaudio::{OhAudio, OhAudioVolume};
#[cfg(feature = "scream_pulseaudio")]
use pulseaudio::PulseStreamData;
#[cfg(all(target_env = "ohos", feature = "scream_ohaudio"))]
use util::ohos_binding::misc::bound_tokenid;

pub const AUDIO_SAMPLE_RATE_44KHZ: u32 = 44100;
pub const AUDIO_SAMPLE_RATE_48KHZ: u32 = 48000;

pub const WINDOWS_SAMPLE_BASE_RATE: u8 = 128;

pub const TARGET_LATENCY_MS: u32 = 50;

#[cfg(all(target_env = "ohos", feature = "scream_ohaudio"))]
const IVSHMEM_VOLUME_SYNC_VECTOR: u16 = 0;
const IVSHMEM_STATUS_CHANGE_VECTOR: u16 = 1;
const IVSHMEM_VECTORS_NR: u32 = 2;
const IVSHMEM_BAR0_VOLUME: u64 = 240;
const IVSHMEM_BAR0_STATUS: u64 = 244;

const STATUS_PLAY_BIT: u32 = 0x1;
const STATUS_START_BIT: u32 = 0x2;
const STATUS_MIC_AVAIL_BIT: u32 = 0x4;

// A frame of back-end audio data is 50ms, and the next frame of audio data needs
// to be trained in polling within 50ms. Theoretically, the shorter the polling time,
// the better. However, if the value is too small, the overhead is high. So take a
// compromise: 50 * 1000 / 8 us.
const POLL_DELAY_US: u64 = (TARGET_LATENCY_MS as u64) * 1000 / 8;

pub const SCREAM_MAGIC: u64 = 0x02032023;

#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd)]
pub enum AudioStatus {
    // Processor is ready and waiting for play/capture.
    #[default]
    Ready,
    // Processor is started and doing job.
    Started,
    // OH audio framework error occurred.
    Error,
}

type AuthorityNotify = dyn Fn() + Send + Sync;

#[derive(Clone)]
pub struct AuthorityInformation {
    state: bool,
    notify: Option<Arc<AuthorityNotify>>,
}

impl AuthorityInformation {
    const fn default() -> AuthorityInformation {
        AuthorityInformation {
            state: true,
            notify: None,
        }
    }
}

type AuthInfo = RwLock<AuthorityInformation>;
static AUTH_INFO: Lazy<AuthInfo> = Lazy::new(|| RwLock::new(AuthorityInformation::default()));

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

pub fn set_record_authority(auth: bool) {
    AUTH_INFO.write().unwrap().state = auth;
    if let Some(auth_notify) = &AUTH_INFO.read().unwrap().notify {
        auth_notify();
    }
}

pub fn set_authority_notify(notify: Option<Arc<AuthorityNotify>>) {
    AUTH_INFO.write().unwrap().notify = notify;
}

pub fn get_record_authority() -> bool {
    AUTH_INFO.read().unwrap().state
}

impl ShmemStreamHeader {
    pub fn check(&self, last_end: u64) -> bool {
        if u64::from(self.offset) < last_end {
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
        sample_rate * u32::from(self.rate % WINDOWS_SAMPLE_BASE_RATE)
    }
}

struct ScreamCond {
    cond: Condvar,
    paused: Mutex<u8>,
}

impl ScreamCond {
    const STREAM_PAUSE_BIT: u8 = 0x1;
    const VM_PAUSE_BIT: u8 = 0x2;

    fn new() -> Arc<Self> {
        Arc::new(Self {
            cond: Condvar::default(),
            paused: Mutex::new(Self::STREAM_PAUSE_BIT),
        })
    }

    fn wait_if_paused(&self, interface: Arc<Mutex<dyn AudioInterface>>) {
        let mut locked_pause = self.paused.lock().unwrap();
        while *locked_pause != 0 {
            interface.lock().unwrap().destroy();
            locked_pause = self.cond.wait(locked_pause).unwrap();
        }
    }

    fn set_value(&self, bv: u8, set: bool) {
        let mut locked_pause = self.paused.lock().unwrap();
        let old_val = *locked_pause;
        match set {
            true => *locked_pause = old_val | bv,
            false => *locked_pause = old_val & !bv,
        }
        if *locked_pause == 0 {
            self.cond.notify_all();
        }
    }

    fn set_vm_pause(&self, paused: bool) {
        self.set_value(Self::VM_PAUSE_BIT, paused);
    }

    fn set_stream_pause(&self, paused: bool) {
        self.set_value(Self::STREAM_PAUSE_BIT, paused);
    }
}

/// Audio stream data structure.
#[derive(Debug, Default)]
pub struct StreamData {
    pub fmt: ShmemStreamFmt,
    chunk_idx: u16,
    /// Size of the data to be played or recorded.
    pub audio_size: u32,
    /// Location of the played or recorded audio data in the shared memory.
    pub audio_base: u64,
    /// VM pause notifier id.
    pause_notifier_id: u64,
}

impl StreamData {
    fn init(&mut self, header: &ShmemStreamHeader) {
        fence(Ordering::Acquire);
        self.fmt = header.fmt;
        self.chunk_idx = header.chunk_idx;
    }

    fn register_pause_notifier(&mut self, cond: Arc<ScreamCond>) {
        let pause_notify = Arc::new(move |paused: bool| {
            cond.set_vm_pause(paused);
        });
        self.pause_notifier_id = register_vm_pause_notifier(pause_notify);
    }

    fn wait_for_ready(
        &mut self,
        interface: Arc<Mutex<dyn AudioInterface>>,
        dir: ScreamDirection,
        hva: u64,
        cond: Arc<ScreamCond>,
    ) {
        // SAFETY: hva is the shared memory base address. It already verifies the validity
        // of the address range during the scream realize.
        let mut header = &unsafe { std::slice::from_raw_parts(hva as *const ShmemHeader, 1) }[0];

        let stream_header = match dir {
            ScreamDirection::Playback => &header.play,
            ScreamDirection::Record => &header.capt,
        };

        loop {
            let mut locked_paused = cond.paused.lock().unwrap();
            while *locked_paused != 0 {
                interface.lock().unwrap().destroy();
                locked_paused = cond.cond.wait(locked_paused).unwrap();
            }

            if header.magic != SCREAM_MAGIC || stream_header.is_started == 0 {
                *locked_paused |= ScreamCond::STREAM_PAUSE_BIT;
                continue;
            }

            header =
                // SAFETY: hva is allocated by libc:::mmap, it can be guaranteed to be legal.
                &unsafe { std::slice::from_raw_parts(hva as *const ShmemHeader, 1) }[0];
            self.init(stream_header);

            let mut last_end = 0_u64;
            // The recording buffer is behind the playback buffer. Thereforce, the end position of
            // the playback buffer must be calculted to determine whether the two buffers overlap.
            if dir == ScreamDirection::Record && header.play.is_started != 0 {
                last_end = u64::from(header.play.offset)
                    + u64::from(header.play.chunk_size) * u64::from(header.play.max_chunks);
            }

            if !stream_header.check(last_end) {
                *locked_paused |= ScreamCond::STREAM_PAUSE_BIT;
                continue;
            }

            trace::scream_init(&dir, &stream_header);

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
            + u64::from(stream_header.offset)
            + u64::from(stream_header.chunk_size) * u64::from(self.chunk_idx);

        if (self.audio_base + u64::from(self.audio_size)) > (hva + shmem_size) {
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
        cond: Arc<ScreamCond>,
    ) {
        // SAFETY: hva is the shared memory base address. It already verifies the validity
        // of the address range during the header check.
        let header = &mut unsafe { std::slice::from_raw_parts_mut(hva as *mut ShmemHeader, 1) }[0];
        let play = &header.play;

        loop {
            cond.wait_if_paused(interface.clone());

            if play.fmt.fmt_generation != self.fmt.fmt_generation {
                break;
            }
            if self.chunk_idx == play.chunk_idx {
                thread::sleep(time::Duration::from_micros(POLL_DELAY_US));
                continue;
            }
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
        cond: Arc<ScreamCond>,
    ) {
        // SAFETY: hva is the shared memory base address. It already verifies the validity
        // of the address range during the header check.
        let header = &mut unsafe { std::slice::from_raw_parts_mut(hva as *mut ShmemHeader, 1) }[0];
        let capt = &mut header.capt;
        let addr = hva + u64::from(capt.offset);

        interface.lock().unwrap().pre_receive(addr, capt);
        while capt.is_started != 0 {
            cond.wait_if_paused(interface.clone());

            if capt.fmt.fmt_generation != self.fmt.fmt_generation {
                return;
            }

            if !self.update_buffer_by_chunk_idx(hva, shmem_size, capt) {
                return;
            }

            let recv_chunks_cnt: i32 = if get_record_authority() {
                interface.lock().unwrap().receive(self)
            } else {
                interface.lock().unwrap().destroy();
                0
            };

            match recv_chunks_cnt.cmp(&0) {
                std::cmp::Ordering::Less => thread::sleep(time::Duration::from_millis(100)),
                std::cmp::Ordering::Greater => {
                    self.chunk_idx = match (self.chunk_idx + recv_chunks_cnt as u16)
                        .checked_rem(capt.max_chunks)
                    {
                        Some(idx) => idx,
                        None => {
                            warn!("Scream: capture header might be cleared by driver");
                            return;
                        }
                    };
                    // Make sure chunk_idx write does not bypass audio chunk write.
                    fence(Ordering::SeqCst);
                    capt.chunk_idx = self.chunk_idx;
                }
                std::cmp::Ordering::Equal => continue,
            }
        }
    }
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
#[command(no_binary_name(true))]
pub struct ScreamConfig {
    #[arg(long)]
    pub classtype: String,
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
    #[arg(long, default_value = "on", action = ArgAction::Append, value_parser = parse_bool)]
    record_auth: bool,
}

/// Scream sound card device structure.
pub struct Scream {
    hva: u64,
    size: u64,
    config: ScreamConfig,
    token_id: Option<Arc<RwLock<u64>>>,
    interface_resource: Vec<Arc<Mutex<dyn AudioInterface>>>,
}

impl Scream {
    pub fn new(
        size: u64,
        config: ScreamConfig,
        token_id: Option<Arc<RwLock<u64>>>,
    ) -> Result<Self> {
        set_record_authority(config.record_auth);
        let header_size = mem::size_of::<ShmemHeader>() as u64;
        if size < header_size {
            bail!(
                "The size {} of the shared memory is smaller than audio header {}",
                size,
                header_size
            );
        }
        Ok(Self {
            hva: 0,
            size,
            config,
            token_id,
            interface_resource: Vec::new(),
        })
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

    fn start_play_thread_fn(&mut self, cond: Arc<ScreamCond>) -> Result<()> {
        let hva = self.hva;
        let shmem_size = self.size;
        let interface = self.interface_init("ScreamPlay", ScreamDirection::Playback);
        self.interface_resource.push(interface.clone());
        let cloned_interface = interface.clone();
        self.register_state_query("scream-play".to_string(), cloned_interface);
        thread::Builder::new()
            .name("scream audio play worker".to_string())
            .spawn(move || {
                let clone_interface = interface.clone();
                let mut play_data = StreamData::default();
                play_data.register_pause_notifier(cond.clone());

                loop {
                    play_data.wait_for_ready(
                        clone_interface.clone(),
                        ScreamDirection::Playback,
                        hva,
                        cond.clone(),
                    );

                    play_data.playback_trans(
                        hva,
                        shmem_size,
                        clone_interface.clone(),
                        cond.clone(),
                    );
                }
            })
            .with_context(|| "Failed to create thread scream")?;
        Ok(())
    }

    fn start_record_thread_fn(&mut self, cond: Arc<ScreamCond>) -> Result<()> {
        let hva = self.hva;
        let shmem_size = self.size;
        let interface = self.interface_init("ScreamCapt", ScreamDirection::Record);
        let _ti = self.token_id.clone();
        self.interface_resource.push(interface.clone());
        let cloned_interface = interface.clone();
        self.register_state_query("scream-record".to_string(), cloned_interface);
        thread::Builder::new()
            .name("scream audio capt worker".to_string())
            .spawn(move || {
                let clone_interface = interface.clone();
                let mut capt_data = StreamData::default();
                capt_data.register_pause_notifier(cond.clone());

                loop {
                    capt_data.wait_for_ready(
                        clone_interface.clone(),
                        ScreamDirection::Record,
                        hva,
                        cond.clone(),
                    );

                    #[cfg(all(target_env = "ohos", feature = "scream_ohaudio"))]
                    if let Some(token_id) = &_ti {
                        bound_tokenid(*token_id.read().unwrap())
                            .unwrap_or_else(|e| error!("bound token ID failed: {}", e));
                    }
                    capt_data.capture_trans(hva, shmem_size, clone_interface.clone(), cond.clone());
                }
            })
            .with_context(|| "Failed to create thread scream")?;
        Ok(())
    }

    fn register_state_query(&self, module: String, interface: Arc<Mutex<dyn AudioInterface>>) {
        register_state_query_callback(
            module,
            Arc::new(move || match interface.lock().unwrap().get_status() {
                AudioStatus::Started => "On".to_string(),
                _ => "Off".to_string(),
            }),
        );
    }

    pub fn realize(&mut self, parent_bus: Weak<Mutex<dyn Bus>>) -> Result<()> {
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

        let devfn = (self.config.addr.0 << 3) + self.config.addr.1;
        let mem_region = Region::init_ram_region(host_mmap, "ivshmem_ram");
        let ivshmem = Ivshmem::new(
            "ivshmem".to_string(),
            devfn,
            parent_bus,
            mem_region,
            IVSHMEM_VECTORS_NR,
        );
        let ivshmem = ivshmem.realize()?;
        let ivshmem_cloned = ivshmem.clone();

        let play_cond = ScreamCond::new();
        let capt_cond = ScreamCond::new();
        self.set_ivshmem_ops(ivshmem, play_cond.clone(), capt_cond.clone());

        let author_notify = Arc::new(move || {
            ivshmem_cloned
                .lock()
                .unwrap()
                .trigger_msix(IVSHMEM_STATUS_CHANGE_VECTOR);
        });
        set_authority_notify(Some(author_notify));

        self.start_play_thread_fn(play_cond)?;
        self.start_record_thread_fn(capt_cond)
    }

    fn set_ivshmem_ops(
        &mut self,
        ivshmem: Arc<Mutex<Ivshmem>>,
        play_cond: Arc<ScreamCond>,
        capt_cond: Arc<ScreamCond>,
    ) {
        let cloned_play_cond = play_cond.clone();
        let cloned_capt_cond = capt_cond.clone();
        let cb = Box::new(move || {
            info!("Scream: device is reset.");
            cloned_play_cond.set_stream_pause(true);
            cloned_capt_cond.set_stream_pause(true);
        });
        ivshmem.lock().unwrap().register_reset_callback(cb);

        let interface = self.create_audio_extension(ivshmem.clone());
        let interface2 = interface.clone();
        let bar0_write = Arc::new(move |data: &[u8], offset: u64| {
            match offset {
                IVSHMEM_BAR0_VOLUME => {
                    interface.set_host_volume(le_read_u32(data, 0).unwrap());
                }
                IVSHMEM_BAR0_STATUS => {
                    let val = le_read_u32(data, 0).unwrap();
                    if val & STATUS_PLAY_BIT == STATUS_PLAY_BIT {
                        play_cond.set_stream_pause(val & STATUS_START_BIT != STATUS_START_BIT);
                    } else {
                        capt_cond.set_stream_pause(val & STATUS_START_BIT != STATUS_START_BIT);
                    }
                }
                _ => {
                    info!("ivshmem-scream: unsupported write: {offset}");
                }
            }
            true
        });
        let bar0_read = Arc::new(move |data: &mut [u8], offset: u64| {
            match offset {
                IVSHMEM_BAR0_VOLUME => {
                    let _ = le_write_u32(data, 0, interface2.get_host_volume());
                }
                IVSHMEM_BAR0_STATUS => {
                    let _ = le_write_u32(data, 0, interface2.get_status_register());
                }
                _ => {
                    info!("ivshmem-scream: unsupported read: {offset}");
                }
            }
            true
        });
        ivshmem
            .lock()
            .unwrap()
            .set_bar0_ops((bar0_write, bar0_read));
    }

    fn create_audio_extension(&self, _ivshmem: Arc<Mutex<Ivshmem>>) -> Arc<dyn AudioExtension> {
        match self.config.interface {
            #[cfg(all(target_env = "ohos", feature = "scream_ohaudio"))]
            ScreamInterface::OhAudio => OhAudioVolume::new(_ivshmem),
            _ => Arc::new(AudioExtensionDummy {}),
        }
    }
}

pub trait AudioInterface: Send {
    fn send(&mut self, recv_data: &StreamData);
    // For OHOS's audio task. It confirms shmem info.
    #[allow(unused_variables)]
    fn pre_receive(&mut self, start_addr: u64, sh_header: &ShmemStreamHeader) {}
    fn receive(&mut self, recv_data: &StreamData) -> i32;
    fn destroy(&mut self);
    fn get_status(&self) -> AudioStatus;
}

pub trait AudioExtension: Send + Sync {
    fn set_host_volume(&self, _vol: u32) {}
    fn get_host_volume(&self) -> u32 {
        0
    }
    fn get_status_register(&self) -> u32 {
        match get_record_authority() {
            true => STATUS_MIC_AVAIL_BIT,
            false => 0,
        }
    }
}

struct AudioExtensionDummy;
impl AudioExtension for AudioExtensionDummy {}
// SAFETY: it is a dummy
unsafe impl Send for AudioExtensionDummy {}
// SAFETY: it is a dummy
unsafe impl Sync for AudioExtensionDummy {}
