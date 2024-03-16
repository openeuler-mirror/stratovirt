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

use std::{
    cmp::min,
    io::{Read, Write},
    sync::atomic::{fence, Ordering},
};

use alsa::{
    pcm::{Access, Format, HwParams},
    Direction, ValueOr, PCM,
};
use anyhow::Result;
use log::{debug, error, warn};

use super::{
    AudioInterface, ScreamDirection, ShmemStreamFmt, StreamData, AUDIO_SAMPLE_RATE_44KHZ,
    TARGET_LATENCY_MS,
};

const MAX_CHANNELS: u8 = 8;
const MIN_CHANNELS: u8 = 1;
const MAX_FRAME_NUM: u32 = 240;

pub struct AlsaStreamData {
    pcm: Option<PCM>,
    dir: Direction,
    format: Format,
    bytes_per_sample: u32,
    stream_fmt: ShmemStreamFmt,
    rate: u32,
    latency: u32,
    app_name: String,
    init: bool,
}

impl ScreamDirection {
    fn trans_to_alsa(&self) -> Direction {
        match self {
            Self::Playback => Direction::Playback,
            Self::Record => Direction::Capture,
        }
    }
}

impl AlsaStreamData {
    pub fn init(name: &str, dir: ScreamDirection) -> Self {
        // Init receiver format to track changes.
        let stream_fmt = ShmemStreamFmt::default();

        let alsa_dir = dir.trans_to_alsa();

        Self {
            pcm: None,
            dir: alsa_dir,
            format: Format::S16LE,
            bytes_per_sample: 0,
            stream_fmt,
            rate: AUDIO_SAMPLE_RATE_44KHZ,
            latency: TARGET_LATENCY_MS,
            app_name: name.to_string(),
            init: false,
        }
    }

    fn setup(&mut self, channels: u8) -> Result<()> {
        let pcm = PCM::new("default", self.dir, false)?;
        {
            // Set hardware parameters of the stream.
            let hwp = HwParams::any(&pcm)?;
            hwp.set_rate_resample(true)?;
            hwp.set_access(Access::RWInterleaved)?;
            hwp.set_format(self.format)?;
            hwp.set_channels(channels as u32)?;
            hwp.set_rate(self.rate, ValueOr::Nearest)?;
            // Set the latency in microseconds.
            hwp.set_buffer_time_near(self.latency * 1000, ValueOr::Nearest)?;
            pcm.hw_params(&hwp)?;
            trace::scream_setup_alsa_hwp(&self.app_name, &hwp);

            // Set software parameters of the stream.
            let hwp = pcm.hw_params_current()?;
            let swp = pcm.sw_params_current()?;
            swp.set_start_threshold(hwp.get_buffer_size().unwrap())?;
            pcm.sw_params(&swp)?;
            trace::scream_setup_alsa_swp(&self.app_name, &swp);
        }
        self.pcm = Some(pcm);
        Ok(())
    }

    fn check_fmt_update(&mut self, recv_data: &StreamData) -> bool {
        if self.init && self.stream_fmt.fmt_generation == recv_data.fmt.fmt_generation {
            return true;
        }

        self.destroy();

        // If audio format changed, reconfigure.
        self.stream_fmt = recv_data.fmt;
        self.rate = recv_data.fmt.get_rate();

        match recv_data.fmt.size {
            16 => {
                self.format = Format::S16LE;
                self.bytes_per_sample = 2;
            }
            24 => {
                self.format = Format::S243LE;
                self.bytes_per_sample = 3;
            }
            32 => {
                self.format = Format::S32LE;
                self.bytes_per_sample = 4;
            }
            _ => {
                warn!(
                    "Unsupported sample size {} for {}, wait next format switch",
                    self.app_name, recv_data.fmt.size
                );
                self.rate = 0;
            }
        }

        if self.rate == 0 {
            self.init = false;
            warn!("Configure wrong rate {} for {}", self.app_name, self.rate);
            return false;
        }

        if recv_data.fmt.channels < MIN_CHANNELS || recv_data.fmt.channels > MAX_CHANNELS {
            self.init = false;
            warn!(
                "Configure wrong channels {} for {}",
                self.app_name, recv_data.fmt.channels
            );
            return false;
        }

        match self.setup(recv_data.fmt.channels) {
            Err(e) => {
                error!(
                    "Failed to set up ALSA HW parameters and SW parameters for {}: {:?}",
                    self.app_name, e
                );
                self.init = false;
            }
            Ok(_) => self.init = true,
        }
        self.init
    }
}

impl AudioInterface for AlsaStreamData {
    fn send(&mut self, recv_data: &StreamData) {
        if !self.check_fmt_update(recv_data) {
            self.destroy();
            return;
        }

        let mut frames = 0;
        let mut io = self.pcm.as_ref().unwrap().io_bytes();

        // Make sure audio read does not bypass chunk_idx read.
        fence(Ordering::Acquire);

        // SAFETY: audio_base is the shared memory. It already verifies the validity
        // of the address range during the header check.
        let data = unsafe {
            std::slice::from_raw_parts(
                recv_data.audio_base as *const u8,
                recv_data.audio_size as usize,
            )
        };

        let samples =
            recv_data.audio_size / (self.bytes_per_sample * recv_data.fmt.channels as u32);
        while frames < samples {
            let send_frame_num = min(samples - frames, MAX_FRAME_NUM);
            let offset = (frames * self.bytes_per_sample * recv_data.fmt.channels as u32) as usize;
            let end = offset
                + (send_frame_num * self.bytes_per_sample * recv_data.fmt.channels as u32) as usize;
            match io.write(&data[offset..end]) {
                Err(e) => {
                    debug!("Failed to write data to ALSA buffer: {:?}", e);
                    match self.pcm.as_ref().unwrap().prepare() {
                        Err(e) => {
                            error!("Can't recovery from underrun for playback: {:?}", e);
                            self.init = false;
                        }
                        Ok(_) => continue,
                    };
                }
                Ok(n) => {
                    trace::scream_alsa_send_frames(frames, offset, end);
                    frames += n as u32 / (self.bytes_per_sample * recv_data.fmt.channels as u32);
                }
            }
        }
    }

    fn receive(&mut self, recv_data: &StreamData) -> i32 {
        if !self.check_fmt_update(recv_data) {
            self.destroy();
            return 0;
        }

        let mut frames = 0;
        let mut io = self.pcm.as_ref().unwrap().io_bytes();

        // Make sure audio read does not bypass chunk_idx read.
        fence(Ordering::Acquire);

        // SAFETY: audio_base is the shared memory. It already verifies the validity
        // of the address range during the header check.
        let data = unsafe {
            std::slice::from_raw_parts_mut(
                recv_data.audio_base as *mut u8,
                recv_data.audio_size as usize,
            )
        };

        let samples =
            recv_data.audio_size / (self.bytes_per_sample * recv_data.fmt.channels as u32);
        while frames < samples {
            let offset = (frames * self.bytes_per_sample * recv_data.fmt.channels as u32) as usize;
            let end = offset
                + ((samples - frames) * self.bytes_per_sample * recv_data.fmt.channels as u32)
                    as usize;
            match io.read(&mut data[offset..end]) {
                Err(e) => {
                    debug!("Failed to read data from ALSA buffer: {:?}", e);
                    match self.pcm.as_ref().unwrap().prepare() {
                        Err(e) => {
                            error!("Can't recovery from overrun for capture: {:?}", e);
                            self.init = false;
                        }
                        Ok(_) => continue,
                    };
                }
                Ok(n) => {
                    trace::scream_alsa_receive_frames(frames, offset, end);
                    frames += n as u32 / (self.bytes_per_sample * recv_data.fmt.channels as u32);

                    // During the host headset switchover, io.read is blocked for a long time.
                    // As a result, the VM recording delay exceeds 1s. Thereforce, check whether
                    // the delay exceeds 500ms. If the delay exceeds 500ms, start recording again.
                    let delay = self.pcm.as_ref().unwrap().delay().unwrap_or_else(|e| {
                        warn!("Scream alsa can't get frames delay: {e:?}");
                        0
                    });
                    if delay > self.rate as i64 >> 1 {
                        warn!("Scream alsa read audio blocked too long, delay {delay} frames, init again!");
                        self.init = false;
                    }
                }
            }
        }
        1
    }

    fn destroy(&mut self) {
        if self.pcm.is_some() {
            if self.dir == Direction::Playback {
                self.pcm
                    .as_ref()
                    .unwrap()
                    .drain()
                    .unwrap_or_else(|e| error!("Failed to drain: {:?}", e));
            }
            self.pcm = None;
        }

        self.init = false;
    }
}
