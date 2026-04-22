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

#![allow(dead_code)]

use util::byte_code::ByteCode;

pub const VIRTIO_SND_JACK_DEFAULT: u32 = 1;
pub const VIRTIO_SND_STREAM_DEFAULT: u32 = 2;
pub const VIRTIO_SND_CHMAP_DEFAULT: u32 = 0;
pub const VIRTIO_SND_CTL_DEFAULT: u32 = 2;

// Feature bits
pub const VIRTIO_SND_F_CTLS: u32 = 0;

// Jack request codes
pub const VIRTIO_SND_R_JACK_INFO: u32 = 0x1;
pub const VIRTIO_SND_R_JACK_REMAP: u32 = 0x2;

// Jack event codes
pub const VIRTIO_SND_EVT_JACK_CONNECTED: u32 = 0x1000;
pub const VIRTIO_SND_EVT_JACK_DISCONNECTED: u32 = 0x1001;

// Jack feature bits
pub const VIRTIO_SND_JACK_F_REMAP: u32 = 0;

// PCM request codes
pub const VIRTIO_SND_R_PCM_INFO: u32 = 0x100;
pub const VIRTIO_SND_R_PCM_SET_PARAMS: u32 = 0x101;
pub const VIRTIO_SND_R_PCM_PREPARE: u32 = 0x102;
pub const VIRTIO_SND_R_PCM_RELEASE: u32 = 0x103;
pub const VIRTIO_SND_R_PCM_START: u32 = 0x104;
pub const VIRTIO_SND_R_PCM_STOP: u32 = 0x105;

// CTL request codes
pub const VIRTIO_SND_R_CTL_INFO: u32 = 0x0300;
pub const VIRTIO_SND_R_CTL_ENUM_ITEMS: u32 = 0x0301;
pub const VIRTIO_SND_R_CTL_READ: u32 = 0x0302;
pub const VIRTIO_SND_R_CTL_WRITE: u32 = 0x0303;
pub const VIRTIO_SND_R_CTL_TLV_READ: u32 = 0x0304;
pub const VIRTIO_SND_R_CTL_TLV_WRITE: u32 = 0x0305;
pub const VIRTIO_SND_R_CTL_TLV_COMMAND: u32 = 0x0306;

// CTL event code
pub const VIRTIO_SND_EVT_CTL_NOTIFY: u32 = 0x1200;

// Status codes
pub const VIRTIO_SND_S_OK: u32 = 0x8000;
pub const VIRTIO_SND_S_BAD_MSG: u32 = 0x8001;
pub const VIRTIO_SND_S_NOT_SUPP: u32 = 0x8002;
pub const VIRTIO_SND_S_IO_ERR: u32 = 0x8003;

// Stream direction
pub const VIRTIO_SND_D_OUTPUT: u8 = 0;
pub const VIRTIO_SND_D_INPUT: u8 = 1;

// PCM format
pub const VIRTIO_SND_PCM_FMT_S16: u8 = 5;
pub const VIRTIO_SND_PCM_FMT_S24: u8 = 11;
pub const VIRTIO_SND_PCM_FMT_S32: u8 = 17;

// PCM rate
pub const VIRTIO_SND_PCM_RATE_44100: u8 = 6;
pub const VIRTIO_SND_PCM_RATE_48000: u8 = 7;

// Queue indices
pub const VIRTIO_QUEUE_CTRL_IDX: usize = 0;
pub const VIRTIO_QUEUE_EVENT_IDX: usize = 1;
pub const VIRTIO_QUEUE_TX_IDX: usize = 2;
pub const VIRTIO_QUEUE_RX_IDX: usize = 3;
pub const VIRTIO_QUEUE_MAX: usize = 4;

// CTL element value types
pub const VIRTIO_SND_CTL_TYPE_BOOLEAN: u32 = 0;
pub const VIRTIO_SND_CTL_TYPE_INTEGER: u32 = 1;
pub const VIRTIO_SND_CTL_TYPE_INTEGER64: u32 = 2;
pub const VIRTIO_SND_CTL_TYPE_ENUMERATED: u32 = 3;
pub const VIRTIO_SND_CTL_TYPE_BYTES: u32 = 4;
pub const VIRTIO_SND_CTL_TYPE_IEC958: u32 = 5;

// CTL element access bits
pub const VIRTIO_SND_CTL_ACCESS_READ: u32 = 0;
pub const VIRTIO_SND_CTL_ACCESS_WRITE: u32 = 1;
pub const VIRTIO_SND_CTL_ACCESS_VOLATILE: u32 = 2;
pub const VIRTIO_SND_CTL_ACCESS_INACTIVE: u32 = 3;
pub const VIRTIO_SND_CTL_ACCESS_TLV_READ: u32 = 4;
pub const VIRTIO_SND_CTL_ACCESS_TLV_WRITE: u32 = 5;
pub const VIRTIO_SND_CTL_ACCESS_TLV_COMMAND: u32 = 6;

// CTL event masks
pub const VIRTIO_SND_CTL_EVT_MASK_VALUE: u32 = 0;
pub const VIRTIO_SND_CTL_EVT_MASK_INFO: u32 = 1;
pub const VIRTIO_SND_CTL_EVT_MASK_TLV: u32 = 2;

pub const VIRTIO_SND_QUEUE_SIZE: u16 = 64;

// CTL element roles
pub const VIRTIO_SND_CTL_ROLE_UNDEFINED: u32 = 0;
pub const VIRTIO_SND_CTL_ROLE_VOLUME: u32 = 1;
pub const VIRTIO_SND_CTL_ROLE_MUTE: u32 = 2;
pub const VIRTIO_SND_CTL_ROLE_GAIN: u32 = 3;

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
            VIRTIO_SND_R_JACK_INFO => stringify!(VIRTIO_SND_R_JACK_INFO),
            VIRTIO_SND_R_JACK_REMAP => stringify!(VIRTIO_SND_R_JACK_REMAP),
            VIRTIO_SND_R_PCM_INFO => stringify!(VIRTIO_SND_R_PCM_INFO),
            VIRTIO_SND_R_PCM_SET_PARAMS => stringify!(VIRTIO_SND_R_PCM_SET_PARAMS),
            VIRTIO_SND_R_PCM_PREPARE => stringify!(VIRTIO_SND_R_PCM_PREPARE),
            VIRTIO_SND_R_PCM_RELEASE => stringify!(VIRTIO_SND_R_PCM_RELEASE),
            VIRTIO_SND_R_PCM_START => stringify!(VIRTIO_SND_R_PCM_START),
            VIRTIO_SND_R_PCM_STOP => stringify!(VIRTIO_SND_R_PCM_STOP),
            VIRTIO_SND_R_CTL_INFO => stringify!(VIRTIO_SND_R_CTL_INFO),
            VIRTIO_SND_R_CTL_ENUM_ITEMS => stringify!(VIRTIO_SND_R_CTL_ENUM_ITEMS),
            VIRTIO_SND_R_CTL_READ => stringify!(VIRTIO_SND_R_CTL_READ),
            VIRTIO_SND_R_CTL_WRITE => stringify!(VIRTIO_SND_R_CTL_WRITE),
            VIRTIO_SND_R_CTL_TLV_READ => stringify!(VIRTIO_SND_R_CTL_TLV_READ),
            VIRTIO_SND_R_CTL_TLV_WRITE => stringify!(VIRTIO_SND_R_CTL_TLV_WRITE),
            VIRTIO_SND_R_CTL_TLV_COMMAND => stringify!(VIRTIO_SND_R_CTL_TLV_COMMAND),
            _ => "unknown control code",
        };

        f.debug_struct("CtrlHdr")
            .field("code", &code)
            .field("message", &msg)
            .finish()
    }
}

#[repr(C)]
#[derive(Clone, Default, Debug)]
pub struct QueryInfo {
    pub hdr: CtrlHdr,
    pub start_id: u32,
    pub count: u32,
    pub size: u32,
}

impl ByteCode for QueryInfo {}

#[repr(C)]
#[derive(Clone, Default)]
pub struct SoundInfo {
    pub hda_fn_nid: u32,
}

#[repr(C)]
#[derive(Clone, Default)]
pub struct JackInfo {
    pub hdr: SoundInfo,
    pub features: u32,
    pub hda_reg_defconf: u32,
    pub hda_reg_caps: u32,
    pub connected: u8,
    pub padding: [u8; 7],
}

impl ByteCode for JackInfo {}

impl JackInfo {
    pub fn to_le(&self) -> Self {
        Self {
            hdr: SoundInfo {
                hda_fn_nid: self.hdr.hda_fn_nid.to_le(),
            },
            features: self.features.to_le(),
            hda_reg_defconf: self.hda_reg_defconf.to_le(),
            hda_reg_caps: self.hda_reg_caps.to_le(),
            connected: self.connected.to_le(),
            padding: [0u8; 7],
        }
    }
}

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
#[derive(Copy, Clone, Default, Debug)]
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

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct CtlHdr {
    pub hdr: SndHdr,
    pub control_id: u32,
}

impl ByteCode for CtlHdr {}

#[repr(C)]
#[derive(Clone)]
pub struct CtlInfo {
    pub hdr: SoundInfo,
    pub role: u32,
    pub ctl_type: u32,
    pub access: u32,
    pub count: u32,
    pub index: u32,
    pub name: [u8; 44],
    pub value: CtlInfoValue,
}

impl Default for CtlInfo {
    fn default() -> Self {
        Self {
            hdr: SoundInfo::default(),
            role: 0,
            ctl_type: 0,
            access: 0,
            count: 0,
            index: 0,
            name: [0u8; 44],
            value: CtlInfoValue::default(),
        }
    }
}

impl ByteCode for CtlInfo {}

impl CtlInfo {
    pub fn to_le(&self) -> Self {
        Self {
            hdr: SoundInfo {
                hda_fn_nid: self.hdr.hda_fn_nid.to_le(),
            },
            role: self.role.to_le(),
            ctl_type: self.ctl_type.to_le(),
            access: self.access.to_le(),
            count: self.count.to_le(),
            index: self.index.to_le(),
            name: self.name,
            value: CtlInfoValue {
                integer: CtlIntegerRange {
                    // SAFETY: it's safe to access 'min' due to previously successful initialization.
                    min: unsafe { self.value.integer.min.to_le() },
                    // SAFETY: it's safe to access 'max' due to previously successful initialization.
                    max: unsafe { self.value.integer.max.to_le() },
                    // SAFETY: it's safe to access 'step' due to previously successful initialization.
                    step: unsafe { self.value.integer.step.to_le() },
                },
            },
        }
    }

    pub fn to_le_bytes(&self) -> Vec<u8> {
        self.to_le().as_bytes().to_vec()
    }
}

#[repr(C)]
#[derive(Clone, Default, Copy)]
pub struct CtlIntegerRange {
    pub min: u32,
    pub max: u32,
    pub step: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct CtlInteger64Range {
    pub min: u64,
    pub max: u64,
    pub step: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct CtlEnumerated {
    pub items: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union CtlInfoValue {
    pub integer: CtlIntegerRange,
    pub integer64: CtlInteger64Range,
    pub enumerated: CtlEnumerated,
}

impl Default for CtlInfoValue {
    fn default() -> Self {
        Self {
            integer64: CtlInteger64Range::default(),
        }
    }
}

pub const CTL_VAL_INT_SIZE: usize = 128;

#[repr(C)]
#[derive(Clone)]
pub struct CtlValue {
    pub integer: [u32; CTL_VAL_INT_SIZE],
}

impl Default for CtlValue {
    fn default() -> Self {
        Self {
            integer: [0u32; CTL_VAL_INT_SIZE],
        }
    }
}

impl ByteCode for CtlValue {}

#[repr(C)]
#[derive(Clone, Default, Debug)]
pub struct CtlEvent {
    pub hdr: SndHdr,
    pub control_id: u16,
    pub mask: u16,
}

impl ByteCode for CtlEvent {}

impl CtlEvent {
    pub fn new_le(code: u32, control_id: u16, mask: u16) -> Self {
        Self {
            hdr: SndHdr { code: code.to_le() },
            control_id: control_id.to_le(),
            mask: mask.to_le(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Default, Debug)]
pub struct SndEvent {
    pub hdr: SndHdr,
    pub data: u32,
}

impl ByteCode for SndEvent {}

impl SndEvent {
    pub fn new_le(code: u32, data: u32) -> Self {
        Self {
            hdr: SndHdr { code: code.to_le() },
            data: data.to_le(),
        }
    }

    pub fn new_je_le(has_authority: bool, data: u32) -> Self {
        let code = if has_authority {
            VIRTIO_SND_EVT_JACK_CONNECTED
        } else {
            VIRTIO_SND_EVT_JACK_DISCONNECTED
        };

        Self::new_le(code, data)
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

#[repr(C)]
#[derive(Clone, Default)]
pub struct PcmXfer {
    pub stream_id: u32,
}

impl ByteCode for PcmXfer {}

#[repr(C)]
#[derive(Clone, Default)]
pub struct VirtioSndConfig {
    pub jacks: u32,
    pub streams: u32,
    pub chmaps: u32,
    pub controls: u32,
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
