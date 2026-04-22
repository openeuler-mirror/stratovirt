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

use std::os::fd::{AsRawFd, RawFd};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, RwLock,
};

use anyhow::{bail, Context, Result};
use audio::auth::{register_authority_notifier, unregister_authority_notifier, AuthorityNotifier};
use audio::volume::{create_volume_control, VolumeControl};
use audio::{get_record_authority, set_record_authority};
use log::{error, info, warn};
use vmm_sys_util::eventfd::EventFd;

use super::spec::*;
use super::{
    read_request, CtrlIoHandler, EventIoHandler, IoHandler, RxIoHandler, SoundConfig, Stream,
    TxIoHandler, SUPPORTED_FORMATS, SUPPORTED_MAX_CHANNELS, SUPPORTED_RATES,
};
use crate::{
    error::*, read_config_default, Element, Queue, VirtioBase, VirtioDevice, VirtioInterrupt,
    VirtioInterruptType, VIRTIO_F_VERSION_1, VIRTIO_TYPE_SOUND,
};
use address_space::{AddressSpace, RegionCache};
use audio::{
    create_audio_interface, AudioBackend, AudioStreamDirection, AudioStreamParams, PcmFmt, PcmRate,
};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use util::byte_code::ByteCode;
use util::gen_base_func;

pub struct Sound {
    base: VirtioBase,
    config: SoundConfig,
    token_id: Option<Arc<RwLock<u64>>>,
    volume_ctrl: Arc<dyn VolumeControl>,
    volume_listener_id: Option<u64>,
    event_handler: Option<Arc<EventIoHandler>>,
}

impl Sound {
    /// Create a sound device.
    ///
    /// # Arguments
    ///
    /// * `config` - sound configuration.
    /// * `token_id` - HAP's token id to create capture stream.
    pub fn new(config: SoundConfig, token_id: Option<Arc<RwLock<u64>>>) -> Sound {
        set_record_authority(config.record_auth);

        let volume_ctrl = create_volume_control(config.backendtype.clone());

        Sound {
            base: VirtioBase::new(VIRTIO_TYPE_SOUND, VIRTIO_QUEUE_MAX, VIRTIO_SND_QUEUE_SIZE),
            config,
            token_id,
            volume_ctrl,
            volume_listener_id: None,
            event_handler: None,
        }
    }

    fn register_notifier<T: IoHandler>(
        &mut self,
        handler: Arc<T>,
        iothread: Option<String>,
        fd: RawFd,
    ) -> Result<()> {
        let notifiers = T::register_notifier(handler, fd);
        register_event_helper(notifiers, iothread.as_ref(), &mut self.base.deactivate_evts)
    }
}

impl VirtioDevice for Sound {
    gen_base_func!(virtio_base, virtio_base_mut, VirtioBase, base);

    fn realize(&mut self) -> Result<()> {
        self.init_config_features()
    }

    fn init_config_features(&mut self) -> Result<()> {
        self.base.device_features = (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_SND_F_CTLS);
        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        let config = VirtioSndConfig {
            jacks: VIRTIO_SND_JACK_DEFAULT,
            streams: VIRTIO_SND_STREAM_DEFAULT,
            chmaps: VIRTIO_SND_CHMAP_DEFAULT,
            controls: VIRTIO_SND_CTL_DEFAULT,
        };
        read_config_default(config.as_bytes(), offset, data)
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let queues = self.base.queues.clone();

        let ctl = Arc::new(Mutex::new(Ctl::new(self.volume_ctrl.clone())));

        let pcm = Arc::new(Mutex::new(Pcm::new(
            VIRTIO_SND_STREAM_DEFAULT,
            self.token_id.clone(),
            self.config.backendtype.clone(),
        )));
        let tx_virtq = VirtQ::new(
            self.base.driver_features,
            mem_space.clone(),
            queues[VIRTIO_QUEUE_TX_IDX].clone(),
            self.base.broken.clone(),
            interrupt_cb.clone(),
        );
        let rx_virtq = VirtQ::new(
            self.base.driver_features,
            mem_space.clone(),
            queues[VIRTIO_QUEUE_RX_IDX].clone(),
            self.base.broken.clone(),
            interrupt_cb.clone(),
        );
        pcm.lock()
            .unwrap()
            .init_stream(VIRTIO_SND_STREAM_DEFAULT, tx_virtq, rx_virtq);

        // queues[0] is for control.
        self.register_notifier(
            CtrlIoHandler::new(
                VirtQ::new(
                    self.base.driver_features,
                    mem_space.clone(),
                    queues[VIRTIO_QUEUE_CTRL_IDX].clone(),
                    self.base.broken.clone(),
                    interrupt_cb.clone(),
                ),
                pcm.clone(),
                ctl.clone(),
            ),
            self.config.iothread.clone(),
            queue_evts[VIRTIO_QUEUE_CTRL_IDX].as_raw_fd(),
        )
        .with_context(|| "Failed to register sound ctrl notifier to MainLoop")?;

        // queues[1] is for event.
        let event_handler = EventIoHandler::new(
            VirtQ::new(
                self.base.driver_features,
                mem_space.clone(),
                queues[VIRTIO_QUEUE_EVENT_IDX].clone(),
                self.base.broken.clone(),
                interrupt_cb.clone(),
            ),
            ctl,
        );
        register_authority_notifier(event_handler.clone());
        self.volume_listener_id = Some(self.volume_ctrl.register_listener(event_handler.clone()));
        self.event_handler = Some(event_handler);

        // queues[2] is for tx.
        self.register_notifier(
            TxIoHandler::new(
                VirtQ::new(
                    self.base.driver_features,
                    mem_space.clone(),
                    queues[VIRTIO_QUEUE_TX_IDX].clone(),
                    self.base.broken.clone(),
                    interrupt_cb.clone(),
                ),
                pcm.clone(),
            ),
            self.config.iothread.clone(),
            queue_evts[VIRTIO_QUEUE_TX_IDX].as_raw_fd(),
        )
        .with_context(|| "Failed to register sound tx notifier to MainLoop")?;

        // queues[3] is for rx.
        self.register_notifier(
            RxIoHandler::new(
                VirtQ::new(
                    self.base.driver_features,
                    mem_space.clone(),
                    queues[VIRTIO_QUEUE_RX_IDX].clone(),
                    self.base.broken.clone(),
                    interrupt_cb.clone(),
                ),
                pcm.clone(),
            ),
            self.config.iothread.clone(),
            queue_evts[VIRTIO_QUEUE_RX_IDX].as_raw_fd(),
        )
        .with_context(|| "Failed to register sound rx notifier to MainLoop")?;

        self.base.broken.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        if let Some(id) = self.volume_listener_id.take() {
            self.volume_ctrl.unregister_listener(id);
        }

        if let Some(handler) = self.event_handler.take() {
            unregister_authority_notifier(&(handler as Arc<dyn AuthorityNotifier>));
        }

        unregister_event_helper(
            self.config.iothread.as_ref(),
            &mut self.base.deactivate_evts,
        )
    }
}

#[derive(Clone)]
pub struct VirtQ {
    /// The features of driver.
    driver_features: u64,
    /// Address space.
    mem_space: Arc<AddressSpace>,
    /// Queue.
    queue: Arc<Mutex<Queue>>,
    /// Device is broken or not.
    device_broken: Arc<AtomicBool>,
    /// The interrupt call back function.
    interrupt_cb: Arc<VirtioInterrupt>,
}

impl VirtQ {
    pub fn new(
        driver_features: u64,
        mem_space: Arc<AddressSpace>,
        queue: Arc<Mutex<Queue>>,
        device_broken: Arc<AtomicBool>,
        interrupt_cb: Arc<VirtioInterrupt>,
    ) -> Self {
        Self {
            driver_features,
            mem_space,
            queue,
            device_broken,
            interrupt_cb,
        }
    }

    pub fn pop_elem(&self) -> Result<Element> {
        self.queue
            .lock()
            .unwrap()
            .vring
            .pop_avail(&self.mem_space, self.driver_features)
    }

    pub fn add_used(&self, index: u16, len: u32) -> Result<()> {
        let mut locked_queue = self.queue.lock().unwrap();
        locked_queue.vring.add_used(index, len)?;
        if locked_queue.vring.should_notify(self.driver_features) {
            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&locked_queue), false)
                .with_context(|| {
                    VirtioError::InterruptTrigger("sound", VirtioInterruptType::Vring)
                })?;
        }
        Ok(())
    }

    #[inline]
    pub fn sys_mem(&self) -> Arc<AddressSpace> {
        self.mem_space.clone()
    }

    #[inline]
    pub fn get_cache(&self) -> Option<RegionCache> {
        *self.queue.lock().unwrap().vring.get_cache()
    }

    #[inline]
    pub fn device_broken(&self) -> bool {
        self.device_broken.load(Ordering::SeqCst)
    }
}

// ============================================================================
// PCM handler
// ============================================================================

pub struct Pcm {
    streams: Vec<Stream>,
    token_id: Option<Arc<RwLock<u64>>>,
    backend_type: AudioBackend,
}

impl Pcm {
    pub fn new(
        streams: u32,
        token_id: Option<Arc<RwLock<u64>>>,
        backend_type: AudioBackend,
    ) -> Self {
        Self {
            streams: Vec::with_capacity(streams as usize),
            token_id,
            backend_type,
        }
    }

    pub fn init_stream(&mut self, streams: u32, tx_virtq: VirtQ, rx_virtq: VirtQ) {
        for i in 0..streams {
            if i % 2 == 0 {
                self.streams
                    .push(Stream::new(VIRTIO_SND_D_OUTPUT, tx_virtq.clone()));
            } else {
                self.streams
                    .push(Stream::new(VIRTIO_SND_D_INPUT, rx_virtq.clone()));
            };
        }
    }

    pub fn handle_pcm_info(
        &mut self,
        mem_space: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: QueryInfo = match read_request(mem_space, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        let start_id = u32::from_le(req.start_id);
        let count = u32::from_le(req.count);
        let len = self.streams.len() as u32;
        if start_id >= len || (start_id + count) > len {
            error!(
                "handle_pcm_info: invalid stream id range [{}, {})",
                start_id,
                start_id + count
            );
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        let mut info_bytes = Vec::with_capacity(size_of::<PcmInfo>() * count as usize);

        for i in 0..count {
            let stream = self.get_stream_mut(i + start_id);
            info_bytes.extend_from_slice(&stream.info.to_le_bytes());
        }

        if let Err(e) = elem.iov_from_buf_with_offset(
            mem_space,
            cache,
            size_of::<SndHdr>() as u64,
            &info_bytes[..],
        ) {
            error!("{:?}", e);
            return (VIRTIO_SND_S_IO_ERR, info_bytes.len() as u32);
        }

        (VIRTIO_SND_S_OK, info_bytes.len() as u32)
    }

    pub fn handle_pcm_set_params(
        &mut self,
        mem_space: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: PcmSetParams = match read_request(mem_space, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        if (SUPPORTED_RATES & (1 << req.rate)) == 0 {
            return (VIRTIO_SND_S_NOT_SUPP, 0);
        }

        if (SUPPORTED_FORMATS & (1 << req.format)) == 0 {
            return (VIRTIO_SND_S_NOT_SUPP, 0);
        }

        if req.channels < 1 || req.channels > SUPPORTED_MAX_CHANNELS {
            return (VIRTIO_SND_S_NOT_SUPP, 0);
        }

        let stream_id = u32::from_le(req.hdr.stream_id);
        if stream_id as usize >= self.streams.len() {
            error!("invalid stream_id {}", stream_id);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        self.set_params(stream_id, &req);

        (VIRTIO_SND_S_OK, 0)
    }

    pub fn set_params(&mut self, stream_id: u32, other: &PcmSetParams) {
        let id = stream_id as usize;

        assert!(id < self.streams.len());
        self.streams[id].params = PcmSetParams::from_le(other);
        self.streams[id]
            .io_handler
            .set_period_bytes(u32::from_le(other.period_bytes) as usize);
    }

    pub fn get_stream_mut(&mut self, stream_id: u32) -> &mut Stream {
        &mut self.streams[stream_id as usize]
    }

    pub fn check_record_auth(stream: &Stream) -> bool {
        if stream.info.direction == VIRTIO_SND_D_OUTPUT {
            return true;
        }
        get_record_authority()
    }

    pub fn handle_pcm_prepare(
        &mut self,
        mem_space: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: PcmHdr = match read_request(mem_space, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        let stream_id = u32::from_le(req.stream_id);
        if stream_id as usize >= self.streams.len() {
            error!("invalid stream_id {}", stream_id);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        let backend_type = self.backend_type.clone();
        let token_id = self.token_id.clone();
        let stream = self.get_stream_mut(stream_id);

        let io_handler = stream.io_handler.clone();
        let mut interface = stream.interface.lock().unwrap();
        if interface.is_some() {
            warn!("audio interface already created");
            return (VIRTIO_SND_S_OK, 0);
        }

        let Ok(params) = convert_params(
            &stream.params,
            stream.info.direction,
            stream.params.period_bytes,
        ) else {
            return (VIRTIO_SND_S_IO_ERR, 0);
        };
        info!("handle_pcm_prepare: {:?}", params);

        let result = create_audio_interface(backend_type, params, io_handler, token_id);

        match result {
            Ok(audio) => {
                *interface = Some(audio);
                (VIRTIO_SND_S_OK, 0)
            }
            Err(e) => {
                error!("Failed to create audio backend: {}", e);
                (VIRTIO_SND_S_IO_ERR, 0)
            }
        }
    }

    pub fn handle_pcm_start(
        &mut self,
        mem_space: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: PcmHdr = match read_request(mem_space, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        let stream_id = u32::from_le(req.stream_id);
        if stream_id as usize >= self.streams.len() {
            error!("invalid stream_id {}", stream_id);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        let stream = self.get_stream_mut(stream_id);
        if !Self::check_record_auth(stream) {
            return (VIRTIO_SND_S_IO_ERR, 0);
        }

        stream.register_vm_pause_notifier();

        let mut interface = stream.interface.lock().unwrap();
        if let Some(i) = interface.as_mut() {
            if let Err(e) = i.start() {
                error!("Failed to start stream, {:?}", e);
                return (VIRTIO_SND_S_IO_ERR, 0);
            }
        }
        (VIRTIO_SND_S_OK, 0)
    }

    pub fn handle_pcm_stop(
        &mut self,
        mem_space: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: PcmHdr = match read_request(mem_space, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        let stream_id = u32::from_le(req.stream_id);
        if stream_id as usize >= self.streams.len() {
            error!("invalid stream_id {}", stream_id);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        let stream = self.get_stream_mut(stream_id);
        stream.unregister_vm_pause_notifier();

        let mut interface = stream.interface.lock().unwrap();
        if let Some(audio) = interface.as_mut() {
            if let Err(e) = audio.stop() {
                error!("Failed to stop stream, {:?}", e);
                return (VIRTIO_SND_S_IO_ERR, 0);
            }
        }
        (VIRTIO_SND_S_OK, 0)
    }

    pub fn handle_pcm_release(
        &mut self,
        mem_space: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: PcmHdr = match read_request(mem_space, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        let stream_id = u32::from_le(req.stream_id);
        if stream_id as usize >= self.streams.len() {
            error!("invalid stream_id {}", stream_id);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        let stream = self.get_stream_mut(stream_id);
        if let Err(e) = stream.flush() {
            error!("Failed to flush stream {}, {:?}", stream_id, e);
        }
        if let Some(mut interface) = stream.interface.lock().unwrap().take() {
            if let Err(e) = interface.stop() {
                error!("Failed to stop interface, {:?}", e);
            }
        }
        (VIRTIO_SND_S_OK, 0)
    }
}

fn convert_params(
    params: &PcmSetParams,
    direction: u8,
    period_bytes: u32,
) -> Result<AudioStreamParams> {
    let rate = match params.rate {
        VIRTIO_SND_PCM_RATE_44100 => PcmRate::Rate44100,
        VIRTIO_SND_PCM_RATE_48000 => PcmRate::Rate48000,
        _ => bail!("unsupported pcm rate"),
    };

    let format = match params.format {
        VIRTIO_SND_PCM_FMT_S16 => PcmFmt::FmtS16,
        VIRTIO_SND_PCM_FMT_S24 => PcmFmt::FmtS24,
        VIRTIO_SND_PCM_FMT_S32 => PcmFmt::FmtS32,
        _ => bail!("unsupported pcm format"),
    };

    let direction = match direction {
        VIRTIO_SND_D_OUTPUT => AudioStreamDirection::Playback,
        VIRTIO_SND_D_INPUT => AudioStreamDirection::Record,
        _ => bail!("unsupported direction"),
    };

    Ok(AudioStreamParams {
        rate,
        format,
        channels: SUPPORTED_MAX_CHANNELS,
        direction,
        period_bytes,
    })
}

// ============================================================================
// CTL (Control Element) handler
// ============================================================================

// The structure definition are referenced from include/uapi/linux/virtio_snd.h.
pub struct CtlElement {
    pub role: u32,
    pub ctl_type: u32,
    pub access: u32,
    pub count: u32,
    pub index: u32,
    pub name: [u8; 44],
    pub min: u32,
    pub max: u32,
    pub step: u32,
    pub values: [u32; CTL_VAL_INT_SIZE],
}

impl CtlElement {
    fn volume(volume: u32, min: u32, max: u32) -> Self {
        let mut name = [0u8; 44];
        let vol_name = b"Master Playback Volume";
        name[..vol_name.len()].copy_from_slice(vol_name);

        let mut values = [0u32; CTL_VAL_INT_SIZE];
        values[0] = volume;
        values[1] = volume;

        Self {
            role: VIRTIO_SND_CTL_ROLE_VOLUME,
            ctl_type: VIRTIO_SND_CTL_TYPE_INTEGER,
            access: (1 << VIRTIO_SND_CTL_ACCESS_READ) | (1 << VIRTIO_SND_CTL_ACCESS_WRITE),
            count: 2,
            index: 0,
            name,
            min,
            max,
            step: 1,
            values,
        }
    }

    fn mute(mute: bool) -> Self {
        let mut name = [0u8; 44];
        let mute_name = b"Master Playback Switch";
        name[..mute_name.len()].copy_from_slice(mute_name);

        let mut values = [0u32; CTL_VAL_INT_SIZE];
        values[0] = u32::from(!mute);

        Self {
            role: VIRTIO_SND_CTL_ROLE_MUTE,
            ctl_type: VIRTIO_SND_CTL_TYPE_BOOLEAN,
            access: (1 << VIRTIO_SND_CTL_ACCESS_READ) | (1 << VIRTIO_SND_CTL_ACCESS_WRITE),
            count: 1,
            index: 0,
            name,
            min: 0,
            max: 1,
            step: 1,
            values,
        }
    }
}

pub struct Ctl {
    elements: Vec<CtlElement>,
    volume_ctrl: Arc<dyn VolumeControl>,
    pub range: (u32, u32),
    pub volume: u32,
    pub mute: bool,
}

impl Ctl {
    pub fn new(volume_ctrl: Arc<dyn VolumeControl>) -> Self {
        let (min, max) = volume_ctrl.get_volume_range();
        let volume = volume_ctrl.get_volume();
        let mute = volume_ctrl.get_mute();
        Self {
            elements: vec![CtlElement::volume(volume, min, max), CtlElement::mute(mute)],
            volume_ctrl: volume_ctrl.clone(),
            range: (min, max),
            volume,
            mute,
        }
    }

    fn validate_control_id(&self, control_id: u32) -> Result<()> {
        if control_id as usize >= self.elements.len() {
            bail!("Invalid control_id {}", control_id);
        }
        Ok(())
    }

    pub fn update_volume(&mut self, new_vol: u32, new_mute: bool) {
        self.volume = new_vol;
        self.mute = new_mute;

        let id = self.get_ctl_id_by_role(VIRTIO_SND_CTL_ROLE_VOLUME);
        let elem = &mut self.elements[id];
        elem.values[0] = new_vol;
        elem.values[1] = new_vol;

        let id = self.get_ctl_id_by_role(VIRTIO_SND_CTL_ROLE_MUTE);
        let elem = &mut self.elements[id];
        elem.values[0] = u32::from(!new_mute);
    }

    pub fn handle_ctl_info(&self, control_id: u32) -> Result<CtlInfo> {
        self.validate_control_id(control_id)?;
        let elem = &self.elements[control_id as usize];

        Ok(CtlInfo {
            hdr: SoundInfo { hda_fn_nid: 0 },
            role: elem.role,
            ctl_type: elem.ctl_type,
            access: elem.access,
            count: elem.count,
            index: elem.index,
            name: elem.name,
            value: CtlInfoValue {
                integer: CtlIntegerRange {
                    min: elem.min,
                    max: elem.max,
                    step: elem.step,
                },
            },
        })
    }

    pub fn handle_ctl_read(&self, control_id: u32) -> Result<CtlValue> {
        self.validate_control_id(control_id)?;
        let elem = &self.elements[control_id as usize];

        let mut result = CtlValue::default();
        for (i, &v) in elem.values.iter().enumerate() {
            if i >= CTL_VAL_INT_SIZE {
                break;
            }
            result.integer[i] = v.to_le();
        }

        Ok(result)
    }

    pub fn handle_ctl_write(&mut self, control_id: u32, value: &CtlValue) -> Result<()> {
        self.validate_control_id(control_id)?;
        let elem = &mut self.elements[control_id as usize];

        // Check write access
        if (elem.access & (1 << VIRTIO_SND_CTL_ACCESS_WRITE)) == 0 {
            bail!("Control element {} is not writable", control_id);
        }

        let new_val = u32::from_le(value.integer[0]);

        match elem.role {
            VIRTIO_SND_CTL_ROLE_VOLUME => {
                if new_val < self.range.0 || new_val > self.range.1 {
                    bail!("volume value {} is out of range {:?}", new_val, self.range);
                }
                elem.values[0] = new_val;
                elem.values[1] = new_val;
                self.volume = new_val;

                let mute_elem = &self.elements[self.get_ctl_id_by_role(VIRTIO_SND_CTL_ROLE_MUTE)];
                let is_muted = mute_elem.values[0] == 0;
                if !is_muted {
                    self.volume_ctrl.set_volume(new_val);
                }
            }
            VIRTIO_SND_CTL_ROLE_MUTE => {
                elem.values[0] = new_val;
                elem.values[1] = new_val;
                self.mute = new_val == 0;
                self.volume_ctrl.set_mute(self.mute);
            }
            _ => {
                bail!("Write not supported for control role {}", elem.role);
            }
        }

        Ok(())
    }

    pub fn get_ctl_id_by_role(&self, role: u32) -> usize {
        for (i, elem) in self.elements.iter().enumerate() {
            if elem.role == role {
                return i;
            }
        }
        0
    }
}
