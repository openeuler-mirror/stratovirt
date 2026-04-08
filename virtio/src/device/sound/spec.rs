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

use util::byte_code::ByteCode;

pub const VIRTIO_SND_JACK_DEFAULT: u32 = 0;
pub const VIRTIO_SND_STREAM_DEFAULT: u32 = 2;
pub const VIRTIO_SND_CHMAP_DEFAULT: u32 = 0;

pub const VIRTIO_SND_R_PCM_INFO: u32 = 0x100;
pub const VIRTIO_SND_R_PCM_SET_PARAMS: u32 = 0x101;
pub const VIRTIO_SND_R_PCM_PREPARE: u32 = 0x102;
pub const VIRTIO_SND_R_PCM_RELEASE: u32 = 0x103;
pub const VIRTIO_SND_R_PCM_START: u32 = 0x104;
pub const VIRTIO_SND_R_PCM_STOP: u32 = 0x105;
pub const VIRTIO_SND_R_VOL_SET: u32 = 0x0300;

pub const VIRTIO_SND_EVT_VOLUME_CHANGED: u32 = 0x1200;

pub const VIRTIO_SND_S_OK: u32 = 0x8000;
pub const VIRTIO_SND_S_BAD_MSG: u32 = 0x8001;
pub const VIRTIO_SND_S_NOT_SUPP: u32 = 0x8002;
pub const VIRTIO_SND_S_IO_ERR: u32 = 0x8003;

pub const VIRTIO_SND_D_OUTPUT: u8 = 0;
pub const VIRTIO_SND_D_INPUT: u8 = 1;

pub const VIRTIO_SND_PCM_FMT_S16: u8 = 5;
pub const VIRTIO_SND_PCM_FMT_S24: u8 = 11;
pub const VIRTIO_SND_PCM_FMT_S32: u8 = 17;

pub const VIRTIO_SND_PCM_RATE_44100: u8 = 6;
pub const VIRTIO_SND_PCM_RATE_48000: u8 = 7;

pub const VIRTIO_QUEUE_CTRL_IDX: usize = 0;
pub const VIRTIO_QUEUE_EVENT_IDX: usize = 1;
pub const VIRTIO_QUEUE_TX_IDX: usize = 2;
pub const VIRTIO_QUEUE_RX_IDX: usize = 3;
pub const VIRTIO_QUEUE_MAX: usize = 4;

pub const VIRTIO_SND_QUEUE_SIZE: u16 = 64;

pub const VIRTIO_SND_MAX_VOLUME: u32 = 65535;

#[repr(C)]
#[derive(Clone, Default)]
pub struct CtrlHdr {
    pub code: u32,
}

impl ByteCode for CtrlHdr {}

impl std::fmt::Debug for CtrlHdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = u32::from_le(self.code);
        let msg = match code {
            VIRTIO_SND_R_PCM_INFO => stringify!(VIRTIO_SND_R_PCM_INFO),
            VIRTIO_SND_R_PCM_SET_PARAMS => stringify!(VIRTIO_SND_R_PCM_SET_PARAMS),
            VIRTIO_SND_R_PCM_PREPARE => stringify!(VIRTIO_SND_R_PCM_PREPARE),
            VIRTIO_SND_R_PCM_RELEASE => stringify!(VIRTIO_SND_R_PCM_RELEASE),
            VIRTIO_SND_R_PCM_START => stringify!(VIRTIO_SND_R_PCM_START),
            VIRTIO_SND_R_PCM_STOP => stringify!(VIRTIO_SND_R_PCM_STOP),
            VIRTIO_SND_R_VOL_SET => stringify!(VIRTIO_SND_R_VOL_SET),
            _ => "unknown control code",
        };

        f.debug_struct("CtrlHdr")
            .field("code", &code)
            .field("message", &msg)
            .finish()
    }
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Default)]
pub struct QueryInfo {
    pub hdr: CtrlHdr,
    pub start_id: u32,
    pub count: u32,
    pub size: u32,
}

impl ByteCode for QueryInfo {}

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Default)]
pub struct SoundInfo {
    pub hda_fn_nid: u32,
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Default)]
pub struct PcmInfo {
    pub hdr: SoundInfo,
    pub features: u32,
    pub formats: u64,
    pub rates: u64,
    pub direction: u8,
    pub channels_min: u8,
    pub channels_max: u8,
    pub padding: [u8; 5],
}

impl ByteCode for PcmInfo {}

impl PcmInfo {
    pub fn to_le_bytes(&self) -> Vec<u8> {
        self.to_le().as_bytes().to_vec()
    }

    pub fn to_le(&self) -> Self {
        Self {
            hdr: SoundInfo {
                hda_fn_nid: self.hdr.hda_fn_nid.to_le(),
            },
            features: self.features.to_le(),
            formats: self.formats.to_le(),
            rates: self.rates.to_le(),
            direction: self.direction,
            channels_min: self.channels_min,
            channels_max: self.channels_max,
            padding: [0u8; 5],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SndHdr {
    pub code: u32,
}

impl ByteCode for SndHdr {}

#[allow(dead_code)]
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct PcmHdr {
    pub hdr: SndHdr,
    pub stream_id: u32,
}

impl ByteCode for PcmHdr {}

impl PcmHdr {
    pub fn from_le(other: &Self) -> Self {
        Self {
            hdr: SndHdr {
                code: u32::from_le(other.hdr.code),
            },
            stream_id: u32::from_le(other.stream_id),
        }
    }
}

#[derive(Clone, Default)]
#[repr(C)]
pub struct SndEvent {
    pub hdr: SndHdr,
    pub data: u32,
}

impl ByteCode for SndEvent {}

impl SndEvent {
    pub fn new(code: u32, data: u32) -> Self {
        Self {
            hdr: SndHdr { code: code.to_le() },
            data: data.to_le(),
        }
    }
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct PcmSetParams {
    pub hdr: PcmHdr,
    pub buffer_bytes: u32,
    pub period_bytes: u32,
    pub features: u32,
    pub channels: u8,
    pub format: u8,
    pub rate: u8,
    pub padding: u8,
}

impl ByteCode for PcmSetParams {}

impl PcmSetParams {
    pub fn from_le(other: &Self) -> Self {
        Self {
            hdr: PcmHdr::from_le(&other.hdr),
            buffer_bytes: u32::from_le(other.buffer_bytes),
            period_bytes: u32::from_le(other.period_bytes),
            features: u32::from_le(other.features),
            channels: other.channels,
            format: other.format,
            rate: other.rate,
            padding: 0,
        }
    }
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Default)]
pub struct PcmSetVol {
    pub hdr: SndHdr,
    pub vol: u32,
    pub mute: u32,
}

impl ByteCode for PcmSetVol {}

#[repr(C)]
#[derive(Clone, Default)]
pub struct PcmXfer {
    pub stream_id: u32,
}

impl ByteCode for PcmXfer {}

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Default)]
pub struct VirtioSndConfig {
    pub jacks: u32,
    pub streams: u32,
    pub chmaps: u32,
}

impl ByteCode for VirtioSndConfig {}

#[repr(C)]
#[derive(Clone, Default)]
pub struct PcmStatus {
    pub status: u32,
    pub latency_bytes: u32,
}

impl ByteCode for PcmStatus {}

impl PcmStatus {
    pub fn new(status: u32, latency_bytes: u32) -> Self {
        Self {
            status: status.to_le(),
            latency_bytes: latency_bytes.to_le(),
        }
    }
}
