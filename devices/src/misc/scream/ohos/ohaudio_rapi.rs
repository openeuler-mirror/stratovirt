// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::os::raw::c_void;
use std::ptr;

use log::error;

use super::ohaudio_bindings as capi;
use crate::misc::scream::{AUDIO_SAMPLE_RATE_44KHZ, AUDIO_SAMPLE_RATE_48KHZ};

macro_rules! call_capi {
    ( $f: ident ( $($x: expr),* ) ) => {
        {
            // SAFETY: OH Audio FrameWork's APIs guarantee safety.
            let r = unsafe { capi::$f( $($x),* ) };
            if r != capi::OH_AUDIO_STREAM_RESULT_AUDIOSTREAM_SUCCESS {
                error!("ohauadio_rapi: failed at {:?}", stringify!($f));
                Err(OAErr::from(r))
            } else {
                Ok(())
            }
        }
    };
}

macro_rules! call_capi_nocheck {
    ( $f: ident ( $($x: expr),* ) ) => {
        // SAFETY: OH Audio FrameWork's APIs guarantee safety.
        unsafe { capi::$f( $($x),* ) }
    };
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OAErr {
    Ok,
    InvalidParam,
    IllegalState,
    SysErr,
    UnknownErr,
}

impl std::error::Error for OAErr {}

impl std::fmt::Display for OAErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                OAErr::Ok => "Ok",
                OAErr::InvalidParam => "InvalidParam",
                OAErr::IllegalState => "IllegalState",
                OAErr::SysErr => "SysErr",
                OAErr::UnknownErr => "UnknownErr",
            }
        )
    }
}

impl From<capi::OhAudioStreamResult> for OAErr {
    #[inline]
    fn from(c: capi::OhAudioStreamResult) -> Self {
        match c {
            capi::OH_AUDIO_STREAM_RESULT_AUDIOSTREAM_SUCCESS => Self::Ok,
            capi::OH_AUDIO_STREAM_RESULT_AUDIOSTREAM_ERROR_INVALID_PARAM => Self::InvalidParam,
            capi::OH_AUDIO_STREAM_RESULT_AUDIOSTREAM_ERROR_ILLEGAL_STATE => Self::IllegalState,
            capi::OH_AUDIO_STREAM_RESULT_AUDIOSTREAM_ERROR_SYSTEM => Self::SysErr,
            _ => Self::UnknownErr,
        }
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
struct SampleSize(pub capi::OhAudioStreamType);

impl TryFrom<u8> for SampleSize {
    type Error = OAErr;

    #[inline]
    fn try_from(s: u8) -> Result<Self, Self::Error> {
        match s {
            16 => Ok(SampleSize(
                capi::OH_AUDIO_STREAM_SAMPLE_FORMAT_AUDIOSTREAM_SAMPLE_S16_LE,
            )),
            24 => Ok(SampleSize(
                capi::OH_AUDIO_STREAM_SAMPLE_FORMAT_AUDIOSTREAM_SAMPLE_S24_LE,
            )),
            32 => Ok(SampleSize(
                capi::OH_AUDIO_STREAM_SAMPLE_FORMAT_AUDIOSTREAM_SAMPLE_S32_LE,
            )),
            _ => Err(OAErr::InvalidParam),
        }
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct SampleRate(pub i32);

impl TryFrom<u32> for SampleRate {
    type Error = OAErr;

    #[inline]
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            AUDIO_SAMPLE_RATE_44KHZ => Ok(SampleRate(value as i32)),
            AUDIO_SAMPLE_RATE_48KHZ => Ok(SampleRate(value as i32)),
            _ => Err(OAErr::InvalidParam),
        }
    }
}

impl Default for SampleRate {
    fn default() -> Self {
        Self(AUDIO_SAMPLE_RATE_44KHZ as i32)
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, Default)]
struct AudioSpec {
    size: SampleSize,
    rate: SampleRate,
    channels: u8,
}

impl PartialEq for AudioSpec {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.rate == other.rate && self.channels == other.channels
    }
}

impl AudioSpec {
    fn set(&mut self, size: u8, rate: u32, channels: u8) -> Result<(), OAErr> {
        self.size = SampleSize::try_from(size)?;
        self.rate = SampleRate::try_from(rate)?;
        self.channels = channels;
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AudioStreamType {
    Render,
    Capturer,
}

#[allow(clippy::from_over_into)]
impl Into<capi::OhAudioStreamType> for AudioStreamType {
    fn into(self) -> capi::OhAudioStreamType {
        match self {
            AudioStreamType::Render => capi::OH_AUDIO_STREAM_TYPE_AUDIOSTREAM_TYPE_RERNDERER,
            AudioStreamType::Capturer => capi::OH_AUDIO_STREAM_TYPE_AUDIOSTREAM_TYPE_CAPTURER,
        }
    }
}

pub enum AudioProcessCb {
    CapturerCb(
        Option<
            extern "C" fn(
                capturer: *mut capi::OhAudioCapturer,
                userData: *mut c_void,
                buffer: *mut c_void,
                length: i32,
            ) -> i32,
        >,
    ),
    RendererCb(
        Option<
            extern "C" fn(
                renderer: *mut capi::OhAudioRenderer,
                userData: *mut c_void,
                buffer: *mut c_void,
                length: i32,
            ) -> i32,
        >,
    ),
}

pub struct AudioContext {
    stream_type: AudioStreamType,
    spec: AudioSpec,
    builder: *mut capi::OhAudioStreamBuilder,
    capturer: *mut capi::OhAudioCapturer,
    renderer: *mut capi::OhAudioRenderer,
    userdata: *mut c_void,
}

impl Drop for AudioContext {
    fn drop(&mut self) {
        if !self.capturer.is_null() || !self.renderer.is_null() {
            self.stop();
        }
        if !self.builder.is_null() {
            call_capi_nocheck!(OH_AudioStreamBuilder_Destroy(self.builder));
            self.builder = ptr::null_mut();
        }
    }
}

impl AudioContext {
    #[inline(always)]
    fn set_userdata(&mut self, userdata: *mut c_void) {
        self.userdata = userdata;
    }

    fn create_builder(&mut self) -> Result<(), OAErr> {
        call_capi!(OH_AudioStreamBuilder_Create(
            &mut self.builder,
            self.stream_type.into()
        ))
    }

    fn set_sample_rate(&self) -> Result<(), OAErr> {
        call_capi!(OH_AudioStreamBuilder_SetSamplingRate(
            self.builder,
            self.spec.rate.0
        ))
    }

    fn set_sample_format(&self) -> Result<(), OAErr> {
        call_capi!(OH_AudioStreamBuilder_SetSampleFormat(
            self.builder,
            self.spec.size.0
        ))
    }

    #[allow(unused)]
    fn set_latency_mode(&self) -> Result<(), OAErr> {
        call_capi!(OH_AudioStreamBuilder_SetLatencyMode(
            self.builder,
            capi::OH_AUDIO_STREAM_LATENCY_MODE_FAST
        ))
    }

    fn create_renderer(&mut self, cb: AudioProcessCb) -> Result<(), OAErr> {
        let mut cbs = capi::OhAudioRendererCallbacks::default();
        if let AudioProcessCb::RendererCb(f) = cb {
            cbs.oh_audio_renderer_on_write_data = f;
        }
        call_capi!(OH_AudioStreamBuilder_SetRendererCallback(
            self.builder,
            cbs,
            self.userdata
        ))?;
        call_capi!(OH_AudioStreamBuilder_GenerateRenderer(
            self.builder,
            &mut self.renderer
        ))
    }

    fn create_capturer(&mut self, cb: AudioProcessCb) -> Result<(), OAErr> {
        let mut cbs = capi::OhAudioCapturerCallbacks::default();
        if let AudioProcessCb::CapturerCb(v) = cb {
            cbs.oh_audio_capturer_on_read_data = v;
        }
        call_capi!(OH_AudioStreamBuilder_SetCapturerCallback(
            self.builder,
            cbs,
            self.userdata
        ))?;
        call_capi!(OH_AudioStreamBuilder_GenerateCapturer(
            self.builder,
            &mut self.capturer
        ))
    }

    fn create_processor(&mut self, cb: AudioProcessCb) -> Result<(), OAErr> {
        match self.stream_type {
            AudioStreamType::Capturer => self.create_capturer(cb),
            AudioStreamType::Render => self.create_renderer(cb),
        }
    }

    fn start_capturer(&self) -> Result<(), OAErr> {
        call_capi!(OH_AudioCapturer_Start(self.capturer))
    }

    fn start_renderer(&self) -> Result<(), OAErr> {
        call_capi!(OH_AudioRenderer_Start(self.renderer))
    }

    pub fn new(stream_type: AudioStreamType) -> Self {
        Self {
            stream_type,
            spec: AudioSpec::default(),
            builder: ptr::null_mut(),
            capturer: ptr::null_mut(),
            renderer: ptr::null_mut(),
            userdata: std::ptr::null_mut::<c_void>(),
        }
    }

    pub fn init(
        &mut self,
        size: u8,
        rate: u32,
        channels: u8,
        cb: AudioProcessCb,
        userdata: *mut c_void,
    ) -> Result<(), OAErr> {
        self.set_userdata(userdata);
        self.create_builder()?;
        self.set_fmt(size, rate, channels)?;
        self.set_sample_rate()?;
        self.set_sample_format()?;
        self.create_processor(cb)
    }

    pub fn start(&self) -> Result<(), OAErr> {
        match self.stream_type {
            AudioStreamType::Capturer => self.start_capturer(),
            AudioStreamType::Render => self.start_renderer(),
        }
    }

    pub fn stop(&mut self) {
        match self.stream_type {
            AudioStreamType::Capturer => {
                call_capi_nocheck!(OH_AudioCapturer_Stop(self.capturer));
                call_capi_nocheck!(OH_AudioCapturer_Release(self.capturer));
                self.capturer = ptr::null_mut();
            }
            AudioStreamType::Render => {
                call_capi_nocheck!(OH_AudioRenderer_Stop(self.renderer));
                call_capi_nocheck!(OH_AudioRenderer_Release(self.renderer));
                self.renderer = ptr::null_mut();
            }
        }
    }

    pub fn set_fmt(&mut self, size: u8, rate: u32, channels: u8) -> Result<(), OAErr> {
        self.spec.set(size, rate, channels)
    }

    pub fn check_fmt(&self, size: u8, rate: u32, channels: u8) -> bool {
        let mut other = AudioSpec::default();
        other
            .set(size, rate, channels)
            .map_or(false, |_| (self.spec == other))
    }
}
