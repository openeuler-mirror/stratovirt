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

use std::sync::atomic::{fence, Ordering};

use log::{error, warn};
use psimple::Simple;
use pulse::{
    channelmap::{Map, MapDef, Position},
    def::BufferAttr,
    sample::{Format, Spec},
    stream::Direction,
    time::MicroSeconds,
};

use super::{AudioInterface, AUDIO_SAMPLE_RATE_44KHZ};
use crate::misc::scream::{ScreamDirection, ShmemStreamFmt, StreamData, TARGET_LATENCY_MS};

const MAX_LATENCY_MS: u32 = 100;

const STREAM_NAME: &str = "Audio";

const WINDOWS_POSITION_CNT: usize = 11;
const PULSEAUDIO_POSITION: [Position; WINDOWS_POSITION_CNT] = [
    Position::FrontLeft,
    Position::FrontRight,
    Position::FrontCenter,
    Position::Lfe,
    Position::RearLeft,
    Position::RearRight,
    Position::FrontLeftOfCenter,
    Position::FrontRightOfCenter,
    Position::RearCenter,
    Position::SideLeft,
    Position::SideRight,
];

impl ScreamDirection {
    fn transform(&self) -> Direction {
        match self {
            Self::Playback => Direction::Playback,
            Self::Record => Direction::Record,
        }
    }
}

/// Data structure of the audio processed by the pulseaudio.
pub struct PulseStreamData {
    simple: Option<Simple>,
    ss: Spec,
    channel_map: Map,
    buffer_attr: BufferAttr,
    stream_fmt: ShmemStreamFmt,
    latency: u32,
    app_name: String,
    stream_name: String,
    dir: Direction,
}

impl PulseStreamData {
    pub fn init(name: &str, dir: ScreamDirection) -> Self {
        // Map to stereo, it's the default number of channels.
        let mut channel_map = Map::default();
        channel_map.init_stereo();

        // Start with base default format, rate and channels. Will switch to actual format later.
        let ss = Spec {
            format: Format::S16le,
            rate: AUDIO_SAMPLE_RATE_44KHZ,
            channels: 2,
        };

        // Init receiver format to track changes.
        let stream_fmt = ShmemStreamFmt::default();

        // Set buffer size for requested latency.
        let buffer_attr = BufferAttr {
            maxlength: ss.usec_to_bytes(MicroSeconds(MAX_LATENCY_MS as u64 * 1000)) as u32,
            tlength: ss.usec_to_bytes(MicroSeconds(TARGET_LATENCY_MS as u64 * 1000)) as u32,
            prebuf: std::u32::MAX,
            minreq: std::u32::MAX,
            fragsize: std::u32::MAX,
        };

        let pa_dir = dir.transform();

        #[cfg(not(test))]
        let simple = Some(
            Simple::new(
                None,
                name,
                pa_dir,
                None,
                STREAM_NAME,
                &ss,
                Some(&channel_map),
                Some(&buffer_attr),
            )
            .unwrap_or_else(|e| panic!("PulseAudio init failed : {}", e)),
        );
        #[cfg(test)]
        let simple = None;

        Self {
            simple,
            ss,
            channel_map,
            buffer_attr,
            stream_fmt,
            latency: TARGET_LATENCY_MS,
            app_name: name.to_string(),
            stream_name: STREAM_NAME.to_string(),
            dir: pa_dir,
        }
    }

    fn transfer_channel_map(&mut self, format: &ShmemStreamFmt) {
        self.channel_map.init();
        self.channel_map.set_len(format.channels);
        let map: &mut [Position] = self.channel_map.get_mut();
        // In Windows, the channel mask shows as following figure.
        //   31    11   10   9   8     7    6   5    4     3   2     1   0
        //  |     |  | SR | SL | BC | FRC| FLC| BR | BL | LFE| FC | FR | FL |
        //
        //  Each bit in the channel mask represents a particular speaker position.
        //  Now, it map a windows SPEAKER_* position to a PA_CHANNEL_POSITION_*.
        let mut key: i32 = -1;
        for (i, item) in map.iter_mut().enumerate().take(format.channels as usize) {
            for j in (key + 1)..32 {
                if (format.channel_map >> j) & 0x01 == 1 {
                    key = j;
                    break;
                }
            }
            // Map the key value to a pulseaudio channel position.
            if (key as usize) < WINDOWS_POSITION_CNT {
                *item = PULSEAUDIO_POSITION[key as usize];
            } else {
                warn!("Channel {} can not be mapped, Falling back to 'center'.", i);
                *item = Position::FrontCenter;
            }
        }
    }

    fn check_fmt_update(&mut self, recv_data: &StreamData) {
        if self.stream_fmt == recv_data.fmt {
            return;
        }

        // Flush left data when audio format changed.
        self.destroy();

        // If audio format changed, reconfigure
        self.stream_fmt = recv_data.fmt;
        self.ss.channels = recv_data.fmt.channels;
        self.ss.rate = recv_data.fmt.get_rate();

        match recv_data.fmt.size {
            16 => self.ss.format = Format::S16le,
            24 => self.ss.format = Format::S24le,
            32 => self.ss.format = Format::S32le,
            _ => {
                warn!(
                    "Unsupported sample size {}, not playing until next format switch",
                    recv_data.fmt.size
                );
                self.ss.rate = 0;
            }
        }

        if recv_data.fmt.channels == 1 {
            self.channel_map.init_mono();
        } else if recv_data.fmt.channels == 2 {
            self.channel_map.init_stereo();
        } else {
            self.transfer_channel_map(&recv_data.fmt);
        }

        if !self.channel_map.is_valid() {
            warn!("Invalid channel mapping, falling back to MapDef::WAVEEx");
            self.channel_map
                .init_extend(recv_data.fmt.channels, MapDef::WAVEEx);
        }
        if !self.channel_map.is_compatible_with_sample_spec(&self.ss) {
            warn!("Incompatible channel mapping.");
            self.ss.rate = 0;
        }

        if self.ss.rate > 0 {
            // Sample spec has changed, so the playback buffer size for the requested latency must
            // be recalculated as well.
            self.buffer_attr.tlength =
                self.ss
                    .usec_to_bytes(MicroSeconds(self.latency as u64 * 1000)) as u32;

            self.simple = Simple::new(
                None,
                self.app_name.as_str(),
                self.dir,
                None,
                self.stream_name.as_str(),
                &self.ss,
                Some(&self.channel_map),
                Some(&self.buffer_attr),
            )
            .map_or_else(
                |_| {
                    warn!(
                "Unable to open PulseAudio with sample rate {}, sample size {} and channels {}",
                self.ss.rate, recv_data.fmt.size, recv_data.fmt.channels
            );
                    None
                },
                Some,
            );
        }
    }
}

impl AudioInterface for PulseStreamData {
    fn send(&mut self, recv_data: &StreamData) {
        self.check_fmt_update(recv_data);

        if self.ss.rate == 0 || self.simple.is_none() {
            return;
        }

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

        if let Err(e) = self.simple.as_ref().unwrap().write(data) {
            error!("PulseAudio write data failed: {:?}", e);
        }
    }

    fn receive(&mut self, recv_data: &StreamData) -> i32 {
        self.check_fmt_update(recv_data);

        if self.simple.is_none() {
            return 0;
        }

        // SAFETY: audio_base is the shared memory. It already verifies the validity
        // of the address range during the header check.
        let data = unsafe {
            std::slice::from_raw_parts_mut(
                recv_data.audio_base as *mut u8,
                recv_data.audio_size as usize,
            )
        };

        if let Err(e) = self.simple.as_ref().unwrap().read(data) {
            error!("PulseAudio read data failed: {:?}", e);
            self.ss.rate = 0;
            return 0;
        }

        1
    }

    fn destroy(&mut self) {
        if self.simple.is_none() {
            return;
        }
        if self.dir == Direction::Playback {
            if let Err(e) = self.simple.as_ref().unwrap().drain() {
                error!("Failed to drain Playback stream: {:?}", e);
            }
        } else if let Err(e) = self.simple.as_ref().unwrap().flush() {
            error!("Failed to flush Capture stream: {:?}", e);
        }
        self.simple = None;
    }
}

#[cfg(test)]
mod tests {
    use pulse::{channelmap::Position, sample::Format};

    use super::PulseStreamData;
    use crate::misc::scream::{
        ScreamDirection, StreamData, AUDIO_SAMPLE_RATE_44KHZ, AUDIO_SAMPLE_RATE_48KHZ,
        WINDOWS_SAMPLE_BASE_RATE,
    };

    #[test]
    fn test_channel_map_transfer() {
        let mut pulse = PulseStreamData::init("test", ScreamDirection::Playback);
        let mut test_data = StreamData::default();

        // set 8: BC, 6: FLC, 4: BL, 2: FC, 0: FL
        test_data.fmt.channels = 5;
        test_data.fmt.channel_map = 0b1_0101_0101;
        pulse.transfer_channel_map(&test_data.fmt);

        assert_eq!(pulse.channel_map.len(), 5);
        let map = pulse.channel_map.get_mut();
        assert_eq!(map[0], Position::FrontLeft);
        assert_eq!(map[1], Position::FrontCenter);
        assert_eq!(map[2], Position::RearLeft);
        assert_eq!(map[3], Position::FrontLeftOfCenter);
        assert_eq!(map[4], Position::RearCenter);

        // The first 12 bits are set to 1.
        test_data.fmt.channels = 12;
        test_data.fmt.channel_map = 0b1111_1111_1111;
        pulse.transfer_channel_map(&test_data.fmt);

        assert_eq!(pulse.channel_map.len(), 12);
        let map = pulse.channel_map.get_mut();
        assert_eq!(map[11], Position::FrontCenter);
    }

    #[test]
    fn test_pulseaudio_fmt_update() {
        let mut pulse = PulseStreamData::init("test", ScreamDirection::Playback);
        let mut test_data = StreamData::default();

        // Setting sample rate to AUDIO_SAMPLE_RATE_44KHZ, sample size to 16.
        test_data.fmt.rate = WINDOWS_SAMPLE_BASE_RATE + 1;
        test_data.fmt.size = 16;

        pulse.check_fmt_update(&test_data);

        assert_eq!(pulse.ss.rate, AUDIO_SAMPLE_RATE_44KHZ);
        assert_eq!(pulse.ss.format, Format::S16le);

        // Setting sample rate to AUDIO_SAMPLE_RATE_48KHZ, sample size to 24.
        test_data.fmt.rate = 1;
        test_data.fmt.size = 24;

        pulse.check_fmt_update(&test_data);

        assert_eq!(pulse.ss.rate, AUDIO_SAMPLE_RATE_48KHZ);
        assert_eq!(pulse.ss.format, Format::S24le);

        // Settint invalid sample size to 100.
        test_data.fmt.size = 100;

        pulse.check_fmt_update(&test_data);

        assert_eq!(pulse.ss.rate, 0);
    }
}
