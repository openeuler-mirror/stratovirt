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

use std::os::raw::c_void;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use log::{error, info, warn};

use crate::volume::VolumeListener;
use crate::{
    AudioInterface, AudioStreamDirection, AudioStreamIo, AudioStreamParams, PcmFmt, PcmRate,
    auth::{
        AuthorityNotifier, get_record_authority, register_authority_notifier,
        unregister_authority_notifier,
    },
    volume::VolumeControl,
};
use machine_manager::event_loop::EventLoop;
use util::ohos_binding::audio::*;
use util::ohos_binding::misc::bound_tokenid;

/// Audio scene types for different use cases.
pub const AUDIO_SCENE_MUSIC: u8 = 0;
pub const AUDIO_SCENE_VOIP_DOWNLINK: u8 = 1;
pub const AUDIO_SCENE_VOIP_UPLINK: u8 = 1;
pub const AUDIO_SCENE_MIC: u8 = 0;
const AUDIO_SCENE_MAX: u8 = 2;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd)]
pub enum OhAudioStatus {
    // Processor is ready and waiting for play/capture.
    #[default]
    Ready,
    // Processor is started and doing job.
    Started,
    // OH audio framework error occurred.
    Error,
    // OH audio stream is interrupted.
    Intr,
    // OH audio stream interruption ends.
    IntrResume,
}

pub struct OhAudio {
    /// Audio contexts for different scenes (index by scene).
    ctx: Vec<Option<AudioContext>>,
    /// Current active scene.
    scene: usize,
    /// IO handler for audio data transfer.
    io_handler: Arc<dyn AudioStreamIo>,
    /// Direction of the stream (playback or record).
    direction: AudioStreamDirection,
    /// Current ohaudio status.
    status: Arc<RwLock<OhAudioStatus>>,
    /// Period size in bytes for capture silence or playback consume.
    period_bytes: usize,
    /// Period duration in milliseconds.
    period_ms: u64,
    /// Whether to allow concurrent mixing of the playback stream with other streams.
    play_concurrency: bool,
    /// Audio format: sample size in bits.
    sample_size: u8,
    /// Audio format: sample rate.
    sample_rate: u32,
    /// Audio format: number of channels.
    channels: u8,
    /// Record authority notifier.
    auth_notifier: Option<Arc<dyn AuthorityNotifier>>,
}

// SAFETY: It's a kind of implementation of audio backend which is maintained just by
// one audio device. Raw pointers in AudioContext are only accessed via OH Audio C API
// which is assumed thread-safe.
unsafe impl Send for OhAudio {}

impl AudioInterface for OhAudio {
    fn new(
        params: AudioStreamParams,
        io_handler: Arc<dyn AudioStreamIo>,
        token_id: Option<Arc<RwLock<u64>>>,
    ) -> Result<Box<Self>> {
        let (rate, size) = Self::convert_params(&params)?;
        let period_ms =
            params.period_bytes as u64 * 1000 / (params.frame_size() * params.rate.hz()) as u64;

        let mut ctx = Vec::with_capacity(AUDIO_SCENE_MAX as usize);
        for _ in 0..AUDIO_SCENE_MAX {
            ctx.push(None);
        }

        let ohaudio = Box::new(Self {
            ctx,
            scene: if params.direction == AudioStreamDirection::Playback {
                AUDIO_SCENE_MUSIC as usize
            } else {
                AUDIO_SCENE_MIC as usize
            },
            io_handler,
            direction: params.direction,
            status: Arc::new(RwLock::new(OhAudioStatus::Ready)),
            period_bytes: params.period_bytes as usize,
            period_ms,
            play_concurrency: false,
            sample_size: size,
            sample_rate: rate,
            channels: params.channels,
            auth_notifier: None,
        });

        if params.direction == AudioStreamDirection::Record {
            if let Some(token_id) = token_id {
                let tid = *token_id.read().unwrap();
                if tid == 0 {
                    error!("invalid tokenid: 0 for capture stream");
                    bail!("invalid tokenId");
                }
                bound_tokenid(tid).map_err(|e| {
                    error!("failed to bind tokenid {}: {}", tid, e);
                    anyhow!("tokenid bind failed")
                })?;
            } else {
                bail!("no tokenid provided for capture stream");
            }
        }

        Ok(ohaudio)
    }

    fn start(&mut self) -> Result<()> {
        if self.direction == AudioStreamDirection::Record && !get_record_authority() {
            info!("start mute timer for record due to authority");
            *self.status.write().unwrap() = OhAudioStatus::Started;
            start_mute_timer(
                self.status.clone(),
                self.io_handler.clone(),
                self.period_bytes,
                self.period_ms,
            );
            return Ok(());
        }

        self.init_ctx()?;
        self.start_ctx()
            .map_err(|e| anyhow::anyhow!("Failed to start: {:?}", e))?;

        if self.direction == AudioStreamDirection::Record {
            self.register_auth_notify();
        }

        *self.status.write().unwrap() = OhAudioStatus::Started;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        if let Some(notifier) = self.auth_notifier.take() {
            unregister_authority_notifier(&notifier);
        }

        self.stop_ctx();
        *self.status.write().unwrap() = OhAudioStatus::Ready;
        Ok(())
    }
}

impl OhAudio {
    fn get_audio_scene_playback(&self) -> capi::OhAudioScene {
        match self.scene as u8 {
            AUDIO_SCENE_VOIP_DOWNLINK => {
                capi::OH_AUDIO_STREAM_USAGE_AUDIOSTREAM_USAGE_COMMUNICATION
            }
            _ => capi::OH_AUDIO_STREAM_USAGE_AUDIOSTREAM_USAGE_MUSIC,
        }
    }

    fn get_audio_scene_capture(&self) -> capi::OhAudioScene {
        match self.scene as u8 {
            AUDIO_SCENE_VOIP_UPLINK => {
                capi::OH_AUDIO_STREAM_SOURCE_TYPE_AUDIOSTREAM_SOURCE_TYPE_VOICE_COMMUNICATION
            }
            _ => capi::OH_AUDIO_STREAM_SOURCE_TYPE_AUDIOSTREAM_SOURCE_TYPE_MIC,
        }
    }

    fn convert_params(params: &AudioStreamParams) -> Result<(u32, u8)> {
        let rate = match params.rate {
            PcmRate::Rate44100 => 44100,
            PcmRate::Rate48000 => 48000,
        };

        let size = match params.format {
            PcmFmt::FmtS16 => 16,
            PcmFmt::FmtS24 => 24,
            PcmFmt::FmtS32 => 32,
        };

        Ok((rate, size))
    }

    #[inline(always)]
    fn get_ctx(&self) -> &Option<AudioContext> {
        &self.ctx[self.scene]
    }

    #[inline(always)]
    fn get_ctx_mut(&mut self) -> &mut Option<AudioContext> {
        &mut self.ctx[self.scene]
    }

    #[inline(always)]
    fn set_ctx(&mut self, ctx: Option<AudioContext>) {
        self.ctx[self.scene] = ctx;
    }

    fn init_ctx(&mut self) -> Result<()> {
        if self.get_ctx().is_some() {
            return Ok(());
        }

        let ptr = self as *mut Self as *mut c_void;
        match self.direction {
            AudioStreamDirection::Playback => {
                let mut context = AudioContext::new(AudioStreamType::Render);
                context.init(
                    self.sample_size,
                    self.sample_rate,
                    self.channels,
                    self.get_audio_scene_playback(),
                    AudioProcessCb::RendererCb(
                        Some(Self::render_on_write_data),
                        Some(Self::render_on_interrupt_cb),
                    ),
                    ptr,
                )?;
                self.set_ctx(Some(context));
            }
            AudioStreamDirection::Record => {
                let mut context = AudioContext::new(AudioStreamType::Capturer);
                context.init(
                    self.sample_size,
                    self.sample_rate,
                    self.channels,
                    self.get_audio_scene_capture(),
                    AudioProcessCb::CapturerCb(
                        Some(Self::capture_on_read_data),
                        Some(Self::capture_on_interrupt_cb),
                    ),
                    ptr,
                )?;
                self.set_ctx(Some(context));
            }
        }
        Ok(())
    }

    fn start_ctx(&mut self) -> Result<()> {
        if self.play_concurrency
            && self.direction == AudioStreamDirection::Playback
            && let Err(e) = self
                .get_ctx_mut()
                .as_mut()
                .unwrap()
                .activate_audio_session(capi::CONCURRENCY_MIX_WITH_OTHERS)
        {
            error!("Failed to set renderer concurrency with others: {}", e);
        }

        match self.get_ctx().as_ref().unwrap().start() {
            Ok(()) => {
                info!("OHAudio {:?} start scene {}", self.direction, self.scene);
                *self.status.write().unwrap() = OhAudioStatus::Started;
                Ok(())
            }
            Err(e) => {
                error!("failed to start oh audio, {:?}", e);
                *self.status.write().unwrap() = OhAudioStatus::Error;
                Err(anyhow!("Failed to start audio context"))
            }
        }
    }

    fn stop_ctx(&mut self) {
        if let Some(ctx) = self.get_ctx().as_ref() {
            ctx.stop();
            if self.play_concurrency && self.direction == AudioStreamDirection::Playback {
                ctx.deactivate_audio_session();
            }
        }
    }

    fn register_auth_notify(&mut self) {
        let io_handler = self.io_handler.clone();
        let status = self.status.clone();
        let period_bytes = self.period_bytes;
        let period_ms = self.period_ms;

        let notifier = Arc::new(OhAudioAuthNotifier {
            io_handler,
            status,
            period_bytes,
            period_ms,
        });

        register_authority_notifier(notifier.clone());
        self.auth_notifier = Some(notifier);
    }

    extern "C" fn render_on_write_data(
        _renderer: *mut OhAudioRenderer,
        user_data: *mut ::std::os::raw::c_void,
        buffer: *mut ::std::os::raw::c_void,
        length: i32,
    ) -> i32 {
        // SAFETY: 'user_data' should be valid while this callback is being called. We will
        // stop audio play before destroy user_data.
        let ohaudio = unsafe { &mut *(user_data as *mut OhAudio) };
        let length = length as usize;

        // SAFETY: 'buffer' pointer should be always valid according to OH Audio C API document.
        let dest = unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, length) };

        match ohaudio.io_handler.read(dest) {
            Ok(len) => {
                if len != length {
                    warn!("the data written {} is less than {}", len, length);
                }
            }
            Err(e) => error!("failed to read pcm data by io handler, {:?}", e),
        }
        0
    }

    extern "C" fn capture_on_read_data(
        _capturer: *mut OhAudioCapturer,
        user_data: *mut ::std::os::raw::c_void,
        buffer: *mut ::std::os::raw::c_void,
        length: i32,
    ) -> i32 {
        // SAFETY: 'user_data' should be valid while this callback is being called. We will
        // stop audio capture before destroy user_data.
        let ohaudio = unsafe { &mut *(user_data as *mut OhAudio) };
        let length = length as usize;

        // SAFETY: 'buffer' pointer should be always valid according to OH Audio C API document.
        let src = unsafe { std::slice::from_raw_parts(buffer as *mut u8, length) };

        if let Err(e) = ohaudio.io_handler.write(src) {
            error!("Failed to write pcm data by io handler, {:?}", e);
        }
        0
    }

    extern "C" fn render_on_interrupt_cb(
        _renderer: *mut OhAudioRenderer,
        user_data: *mut ::std::os::raw::c_void,
        source_type: capi::OHAudioInterruptSourceType,
        hint: capi::OHAudioInterruptHint,
    ) -> i32 {
        info!(
            "Render interrupts, type is {}, hint is {}",
            source_type, hint
        );

        // SAFETY: we make sure it is valid when callback is being called.
        let ohaudio = unsafe { &mut *(user_data as *mut OhAudio) };

        if hint == capi::AUDIOSTREAM_INTERRUPT_HINT_PAUSE {
            *ohaudio.status.write().unwrap() = OhAudioStatus::Intr;
            // Start timer to consume playback data.
            start_consume_timer(
                ohaudio.status.clone(),
                ohaudio.io_handler.clone(),
                ohaudio.period_bytes,
                ohaudio.period_ms,
            );
        } else if hint == capi::AUDIOSTREAM_INTERRUPT_HINT_RESUME {
            *ohaudio.status.write().unwrap() = OhAudioStatus::IntrResume;
            if let Some(ctx) = ohaudio.get_ctx().as_ref() {
                if let Err(e) = ctx.start() {
                    error!("failed to resume audio context, {:?}", e);
                    *ohaudio.status.write().unwrap() = OhAudioStatus::Error;
                } else {
                    *ohaudio.status.write().unwrap() = OhAudioStatus::Started;
                }
            }
        }
        0
    }

    extern "C" fn capture_on_interrupt_cb(
        _capturer: *mut OhAudioCapturer,
        user_data: *mut ::std::os::raw::c_void,
        source_type: capi::OHAudioInterruptSourceType,
        hint: capi::OHAudioInterruptHint,
    ) -> i32 {
        info!(
            "Capture interrupts, type is {}, hint is {}",
            source_type, hint
        );

        // SAFETY: we make sure it is valid when callback is being called.
        let ohaudio = unsafe { &mut *(user_data as *mut OhAudio) };

        if hint == capi::AUDIOSTREAM_INTERRUPT_HINT_PAUSE {
            *ohaudio.status.write().unwrap() = OhAudioStatus::Intr;
            // Start timer to produce mute data.
            start_mute_timer(
                ohaudio.status.clone(),
                ohaudio.io_handler.clone(),
                ohaudio.period_bytes,
                ohaudio.period_ms,
            );
        } else if hint == capi::AUDIOSTREAM_INTERRUPT_HINT_RESUME {
            *ohaudio.status.write().unwrap() = OhAudioStatus::IntrResume;
            if let Some(ctx) = ohaudio.get_ctx().as_ref() {
                if let Err(e) = ctx.start() {
                    error!("failed to resume audio context, {:?}", e);
                    *ohaudio.status.write().unwrap() = OhAudioStatus::Error;
                } else {
                    *ohaudio.status.write().unwrap() = OhAudioStatus::Started;
                }
            }
        }
        0
    }
}

fn start_consume_timer(
    status: Arc<RwLock<OhAudioStatus>>,
    io_handler: Arc<dyn AudioStreamIo>,
    period_bytes: usize,
    period_ms: u64,
) {
    let timer_cb = Box::new(move || {
        // Check if we are still interrupted
        if *status.read().unwrap() == OhAudioStatus::Intr {
            let mut buffer: Vec<u8> = vec![0; period_bytes];
            if let Err(e) = io_handler.read(&mut buffer) {
                error!("Failed to read playback data: {:?}", e);
            }
            // Continue the timer
            start_consume_timer(status.clone(), io_handler.clone(), period_bytes, period_ms);
        }
        // If we are not interrupted, don't schedule next timer.
    });

    if let Some(event_loop) = EventLoop::get_ctx(None) {
        event_loop.timer_add(timer_cb, Duration::from_millis(period_ms));
    }
}

fn start_mute_timer(
    status: Arc<RwLock<OhAudioStatus>>,
    io_handler: Arc<dyn AudioStreamIo>,
    period_bytes: usize,
    period_ms: u64,
) {
    let timer_cb = Box::new(move || {
        // Check if we are still interrupted or not granted with record authority.
        let audio_status = *status.read().unwrap();
        if audio_status == OhAudioStatus::Intr
            || (audio_status == OhAudioStatus::Started && !get_record_authority())
        {
            let buffer: Vec<u8> = vec![0; period_bytes];
            if let Err(e) = io_handler.write(&buffer) {
                error!("Failed to read playback data: {:?}", e);
            }
            // Continue the timer
            start_mute_timer(status.clone(), io_handler.clone(), period_bytes, period_ms);
        }
        // If we are not interrupted, don't schedule next timer.
    });

    if let Some(event_loop) = EventLoop::get_ctx(None) {
        event_loop.timer_add(timer_cb, Duration::from_millis(period_ms));
    }
}

// ============================================================================
// Authority Notifier for Ohaudio
// ============================================================================

/// Authority notifier for OHAudio capture streams.
///
/// This notifier handles authority changes for capture streams, managing silence
/// generation when authority is revoked.
struct OhAudioAuthNotifier {
    io_handler: Arc<dyn AudioStreamIo>,
    status: Arc<RwLock<OhAudioStatus>>,
    period_bytes: usize,
    period_ms: u64,
}

impl AuthorityNotifier for OhAudioAuthNotifier {
    fn on_authority_changed(&self, has_authority: bool) {
        info!("Record authority changed to: {}", has_authority);

        if !has_authority {
            start_mute_timer(
                self.status.clone(),
                self.io_handler.clone(),
                self.period_bytes,
                self.period_ms,
            );
        }
    }
}

// ============================================================================
// Volume Control Implementation
// ============================================================================

/// OHOS volume control with normalized 0-65535 scale.
///
/// This implementation converts between the normalized volume scale (0-65535)
/// used by audio devices and the OHOS native scale (typically 0-15).
pub struct OhosVolumeControl {
    listener: RwLock<Option<Arc<dyn VolumeListener>>>,
    host_max: u32,
    host_min: u32,
}

impl OhosVolumeControl {
    /// Create a new OHOS volume control.
    pub fn new() -> Arc<Self> {
        let ctrl = Arc::new(Self {
            listener: RwLock::new(None),
            host_max: get_ohos_volume_max(),
            host_min: get_ohos_volume_min(),
        });

        // Register callback for host volume changes
        register_guest_volume_notifier(ctrl.clone());
        ctrl
    }

    /// Notify all registered notifiers of a volume change.
    fn notify_volume_change(&self, volume: u32, mute: bool) {
        if let Some(listener) = self.listener.read().unwrap().as_ref() {
            listener.notify(volume, mute);
        }
    }
}

impl VolumeControl for OhosVolumeControl {
    fn get_volume_range(&self) -> (u32, u32) {
        (self.host_min, self.host_max)
    }

    fn get_volume(&self) -> u32 {
        get_ohos_volume()
    }

    fn get_mute(&self) -> bool {
        get_ohos_mute()
    }

    fn set_volume(&self, volume: u32) {
        set_ohos_volume(volume);
    }

    fn set_mute(&self, mute: bool) {
        set_ohos_mute(mute);
    }

    fn register_listener(&self, listener: Arc<dyn VolumeListener>) -> u64 {
        *self.listener.write().unwrap() = Some(listener);
        0
    }

    fn unregister_listener(&self, _id: u64) {
        *self.listener.write().unwrap() = None;
    }
}

impl GuestVolumeNotifier for OhosVolumeControl {
    fn notify(&self, volume: u32) {
        self.notify_volume_change(volume, self.get_mute());
    }
}
