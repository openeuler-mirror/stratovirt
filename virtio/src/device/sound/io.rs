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

use std::collections::VecDeque;
use std::os::unix::io::RawFd;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use log::{error, info};
use vmm_sys_util::epoll::EventSet;

use super::{
    ctl::Ctl, dev::VirtQ, pcm::Pcm, read_request, spec::*, SUPPORTED_FORMATS,
    SUPPORTED_MAX_CHANNELS, SUPPORTED_RATES,
};
use crate::Element;
use address_space::{AddressSpace, RegionCache};
use audio::{
    auth::AuthorityNotifier, get_record_authority, volume::VolumeListener, AudioInterface,
    AudioStreamIo,
};
use machine_manager::notifier::{register_vm_pause_notifier, unregister_vm_pause_notifier};
use util::byte_code::ByteCode;
use util::loop_context::{read_fd, EventNotifier, NotifierCallback, NotifierOperation};

struct StreamElem {
    elem: Element,
    buf: Option<Vec<u8>>,
    pos: usize,
}

impl StreamElem {
    fn new(elem: Element) -> Self {
        Self {
            elem,
            buf: None,
            pos: 0,
        }
    }

    #[inline]
    fn index(&self) -> u16 {
        self.elem.index
    }

    fn in_avail(&self) -> usize {
        Element::iovec_size(&self.elem.in_iovec) as usize
    }

    #[inline]
    fn write_offset(
        &self,
        sys_mem: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        offset: u64,
        buf: &[u8],
    ) -> Result<usize> {
        self.elem
            .iov_from_buf_with_offset(sys_mem, cache, offset, buf)
    }

    fn populate(&mut self, sys_mem: &Arc<AddressSpace>, cache: &Option<RegionCache>) {
        if self.buf.is_none() {
            let size = Element::iovec_size(&self.elem.out_iovec) as usize - size_of::<PcmXfer>();
            let mut buf = vec![0u8; size];
            let len = self
                .elem
                .iov_to_buf_with_offset(sys_mem, cache, size_of::<PcmXfer>() as u64, &mut buf)
                .unwrap();
            assert!(len == buf.len());
            self.buf = Some(buf);
            self.pos = 0;
        }
    }

    fn copy_to_buf(&mut self, dst: &mut [u8]) -> usize {
        if self.buf.is_none() {
            return 0;
        }
        let start = self.pos;
        let buf = self.buf.as_ref().unwrap();
        let left = buf.len() - start;
        let to_copy = dst.len().min(left);
        let end = start + to_copy;

        dst[..to_copy].copy_from_slice(&buf[start..end]);
        self.pos = end;
        to_copy
    }

    fn consumed_all(&self) -> bool {
        if let Some(buf) = self.buf.as_ref() {
            buf.len() == self.pos
        } else {
            true
        }
    }
}

pub struct StreamIoHandler {
    queue: Mutex<VecDeque<StreamElem>>,
    pub vq: VirtQ,
    pub period_bytes: AtomicUsize,
}

impl StreamIoHandler {
    pub fn set_period_bytes(&self, period_bytes: usize) {
        self.period_bytes.store(period_bytes, Ordering::Release);
    }

    fn period_bytes(&self) -> usize {
        self.period_bytes.load(Ordering::Acquire)
    }

    fn flush(&self) -> Result<()> {
        let sys_mem = self.vq.sys_mem();
        let cache = self.vq.get_cache();
        let mut queue = std::mem::take(&mut *self.queue.lock().unwrap());

        loop {
            let Some(elem) = queue.pop_front() else {
                break;
            };

            let resp = PcmStatus::new(VIRTIO_SND_S_OK, 0);
            let len = elem.write_offset(&sys_mem, &cache, 0, resp.as_bytes())?;
            self.vq.add_used(elem.index(), len as u32)?;
        }
        Ok(())
    }

    pub fn append(&self, elem: Element) {
        self.queue.lock().unwrap().push_back(StreamElem::new(elem));
    }
}

impl AudioStreamIo for StreamIoHandler {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut copied = 0;
        let sys_mem = self.vq.sys_mem();
        let cache = self.vq.get_cache();

        loop {
            if copied >= buf.len() {
                break;
            }

            let mut locked_queue = self.queue.lock().unwrap();
            let Some(elem) = locked_queue.front_mut() else {
                break;
            };

            elem.populate(&sys_mem, &cache);
            copied += elem.copy_to_buf(&mut buf[copied..]);

            if elem.consumed_all() {
                let resp = PcmStatus::new(VIRTIO_SND_S_OK, 0);
                let elem = locked_queue.pop_front().unwrap();
                let len = elem.write_offset(&sys_mem, &cache, 0, resp.as_bytes())?;
                self.vq.add_used(elem.index(), len as u32)?;
            }
        }

        Ok(copied)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut copied = 0;
        let mut left = buf.len();
        let sys_mem = self.vq.sys_mem();
        let cache = self.vq.get_cache();
        let period_bytes = self.period_bytes();

        loop {
            if copied >= buf.len() {
                break;
            }

            let mut locked_queue = self.queue.lock().unwrap();
            let Some(elem) = locked_queue.front_mut() else {
                break;
            };

            // We have to take care about the size of in buffer to guarantee there's enough space
            // to save PCM data blob and PcmStatus.
            let max_size = elem.in_avail().saturating_sub(size_of::<PcmStatus>());
            let avail = max_size.saturating_sub(elem.pos);
            if max_size == 0 || avail == 0 {
                let resp = PcmStatus::new(VIRTIO_SND_S_OK, 0);
                let elem = locked_queue.pop_front().unwrap();
                let len = elem.write_offset(&sys_mem, &cache, 0, resp.as_bytes())?;
                self.vq.add_used(elem.index(), len as u32)?;
                continue;
            }

            let to_copy = left.min(avail);
            let len = elem.write_offset(
                &sys_mem,
                &cache,
                elem.pos as u64,
                &buf[copied..copied + to_copy],
            )?;
            elem.pos += len;
            copied += len;
            left -= len;

            if elem.pos >= period_bytes {
                let resp = PcmStatus::new(VIRTIO_SND_S_OK, 0);
                let mut elem = locked_queue.pop_front().unwrap();
                elem.pos +=
                    elem.write_offset(&sys_mem, &cache, elem.pos as u64, resp.as_bytes())?;
                self.vq.add_used(elem.index(), elem.pos as u32)?;
            }
        }
        Ok(copied)
    }
}

#[derive(Clone)]
pub struct Stream {
    pub info: PcmInfo,
    pub params: PcmSetParams,
    pub interface: Arc<Mutex<Option<Box<dyn AudioInterface>>>>,
    pub io_handler: Arc<StreamIoHandler>,
    vm_pause_notifier: Option<u64>,
}

impl Stream {
    pub fn new(direction: u8, vq: VirtQ) -> Self {
        Self {
            info: PcmInfo {
                hdr: SoundInfo::default(),
                direction,
                features: 0,
                channels_min: SUPPORTED_MAX_CHANNELS,
                channels_max: SUPPORTED_MAX_CHANNELS,
                formats: SUPPORTED_FORMATS as u64,
                rates: SUPPORTED_RATES as u64,
                padding: [0; 5],
            },
            params: PcmSetParams::default(),
            interface: Arc::new(Mutex::new(None)),
            io_handler: Arc::new(StreamIoHandler {
                queue: Mutex::new(VecDeque::new()),
                vq,
                period_bytes: AtomicUsize::new(0),
            }),
            vm_pause_notifier: None,
        }
    }

    pub fn flush(&self) -> Result<()> {
        if let Err(e) = self.io_handler.flush() {
            error!("Failed to flush all elements, {:?}", e);
        }
        Ok(())
    }

    pub fn register_vm_pause_notifier(&mut self) {
        let interface = self.interface.clone();
        let notifier = Arc::new(move |pause| {
            if let Some(interface) = interface.lock().unwrap().as_mut() {
                if pause {
                    info!("vm paused, stop audio stream");
                    if let Err(e) = interface.stop() {
                        error!("failed to stop audio stream: {:?}", e);
                    }
                } else {
                    info!("vm resumed, start audio stream");
                    if let Err(e) = interface.start() {
                        error!("failed to start audio stream: {:?}", e);
                    }
                }
            }
        });
        self.vm_pause_notifier = Some(register_vm_pause_notifier(notifier));
    }

    pub fn unregister_vm_pause_notifier(&mut self) {
        if let Some(id) = self.vm_pause_notifier.take() {
            unregister_vm_pause_notifier(id);
        }
    }
}

pub trait IoHandler
where
    Self: 'static,
{
    fn register_notifier(handler: Arc<Self>, fd: RawFd) -> Vec<EventNotifier> {
        let cb: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);

            if handler.device_broken() {
                return None;
            }
            handler.handle_queue().unwrap_or_else(|e| {
                error!("Failed to handle virtqueue, error is {:?}.", e);
            });
            None
        });

        let notifiers = vec![EventNotifier::new(
            NotifierOperation::AddShared,
            fd,
            None,
            EventSet::IN,
            vec![cb],
        )];
        notifiers
    }

    fn handle_elem(
        &self,
        sys_mem: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: Element,
    ) -> Result<()>;

    fn handle_queue(&self) -> Result<()> {
        let vq = self.get_vq();
        let sys_mem = vq.sys_mem();
        let cache = vq.get_cache();

        loop {
            let elem = vq.pop_elem().with_context(|| "Failed to pop avail ring")?;
            if elem.desc_num == 0 {
                break;
            }

            self.handle_elem(&sys_mem, &cache, elem)?;
        }

        Ok(())
    }

    fn device_broken(&self) -> bool;

    fn get_vq(&self) -> &VirtQ;
}

pub struct CtrlIoHandler {
    vq: VirtQ,
    pcm: Arc<Mutex<Pcm>>,
    ctl: Arc<Mutex<Ctl>>,
}

impl IoHandler for CtrlIoHandler {
    fn handle_elem(
        &self,
        sys_mem: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: Element,
    ) -> Result<()> {
        let ctrl_hdr: CtrlHdr =
            read_request(sys_mem, cache, &elem).with_context(|| "Failed to get control header")?;
        info!("CtrlQueue: {:?}", ctrl_hdr);

        let (code, payload_size) = match u32::from_le(ctrl_hdr.code) {
            // Jack requests
            code @ VIRTIO_SND_R_JACK_INFO..=VIRTIO_SND_R_JACK_REMAP => {
                self.handle_jack(code, sys_mem, cache, &elem)
            }
            // PCM requests
            code @ VIRTIO_SND_R_PCM_INFO..=VIRTIO_SND_R_PCM_STOP => self
                .pcm
                .lock()
                .unwrap()
                .handle_pcm(code, sys_mem, cache, &elem),
            // CTL requests
            code @ VIRTIO_SND_R_CTL_INFO..=VIRTIO_SND_R_CTL_TLV_COMMAND => self
                .ctl
                .lock()
                .unwrap()
                .handle_ctl(code, sys_mem, cache, &elem),
            // unsupported request
            _ => {
                error!("Control command {:#x} not supported", ctrl_hdr.code);
                (VIRTIO_SND_S_NOT_SUPP, 0)
            }
        };

        if code != VIRTIO_SND_S_OK {
            error!("CtrlQueue: response err code {:#x}", code);
        }

        let resp = SndHdr { code: code.to_le() };
        elem.iov_from_buf_with_offset(sys_mem, cache, 0, resp.as_bytes())?;

        self.vq
            .add_used(elem.index, size_of::<SndHdr>() as u32 + payload_size)
            .with_context(|| format!("Failed to add used ring {}", elem.index))
    }

    #[inline]
    fn get_vq(&self) -> &VirtQ {
        &self.vq
    }

    #[inline]
    fn device_broken(&self) -> bool {
        self.vq.device_broken()
    }
}

impl CtrlIoHandler {
    pub fn new(vq: VirtQ, pcm: Arc<Mutex<Pcm>>, ctl: Arc<Mutex<Ctl>>) -> Arc<Self> {
        Arc::new(Self { vq, pcm, ctl })
    }

    fn handle_jack(
        &self,
        code: u32,
        sys_mem: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        match code {
            VIRTIO_SND_R_JACK_INFO => self.handle_jack_info(sys_mem, cache, elem),
            VIRTIO_SND_R_JACK_REMAP => (VIRTIO_SND_S_NOT_SUPP, 0),
            _ => (VIRTIO_SND_S_BAD_MSG, 0),
        }
    }

    fn handle_jack_info(
        &self,
        sys_mem: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: QueryInfo = match read_request(sys_mem, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        let start_id = u32::from_le(req.start_id);
        if start_id >= VIRTIO_SND_JACK_DEFAULT {
            error!("invalid jack query info: {:?}", req);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        let count = u32::from_le(req.count);
        let size = u32::from_le(req.size);
        let len = count.saturating_mul(size) as usize;
        if len != size_of::<JackInfo>() * VIRTIO_SND_JACK_DEFAULT as usize {
            error!("invalid jack query info: {:?}", req);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        let info = JackInfo {
            hdr: SoundInfo { hda_fn_nid: 0 },
            features: 0,
            // 31:30: Port Connectivity, 1 means integrated
            // 23:20: Device Type, 0xa means Mic
            hda_reg_defconf: 0x40a00000,
            // bit 5 is 1, means support presence detect.
            hda_reg_caps: 0x20,
            connected: u8::from(get_record_authority()),
            padding: [0u8; 7],
        }
        .to_le();

        match elem.iov_from_buf_with_offset(
            sys_mem,
            cache,
            size_of::<SndHdr>() as u64,
            info.as_bytes(),
        ) {
            Ok(ret) => {
                if ret != len {
                    return (VIRTIO_SND_S_IO_ERR, 0);
                }
                (VIRTIO_SND_S_OK, len as u32)
            }
            Err(e) => {
                error!("{:?}", e);
                (VIRTIO_SND_S_IO_ERR, 0)
            }
        }
    }
}

pub struct TxIoHandler {
    vq: VirtQ,
    pcm: Arc<Mutex<Pcm>>,
}

impl IoHandler for TxIoHandler {
    fn handle_elem(
        &self,
        sys_mem: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: Element,
    ) -> Result<()> {
        let hdr: PcmXfer =
            read_request(sys_mem, cache, &elem).with_context(|| "Failed to get tx PcmXfer")?;

        let stream_id = u32::from_le(hdr.stream_id) as usize;
        if let Some(elem) = self
            .pcm
            .lock()
            .unwrap()
            .push_elem_to_stream(stream_id, elem)
        {
            error!("invalid stream id {}", stream_id);
            let resp = PcmStatus::new(VIRTIO_SND_S_BAD_MSG, 0);
            let len = elem.iov_from_buf_with_offset(sys_mem, cache, 0, resp.as_bytes())?;
            self.vq.add_used(elem.index, len as u32)?;
        }

        Ok(())
    }

    #[inline]
    fn get_vq(&self) -> &VirtQ {
        &self.vq
    }

    #[inline]
    fn device_broken(&self) -> bool {
        self.vq.device_broken()
    }
}

impl TxIoHandler {
    pub fn new(vq: VirtQ, pcm: Arc<Mutex<Pcm>>) -> Arc<Self> {
        Arc::new(Self { vq, pcm })
    }
}

pub struct RxIoHandler {
    vq: VirtQ,
    pcm: Arc<Mutex<Pcm>>,
}

impl IoHandler for RxIoHandler {
    fn handle_elem(
        &self,
        sys_mem: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: Element,
    ) -> Result<()> {
        let hdr: PcmXfer =
            read_request(sys_mem, cache, &elem).with_context(|| "Failed to get rx PcmXfer")?;

        let stream_id = u32::from_le(hdr.stream_id) as usize;
        if let Some(elem) = self
            .pcm
            .lock()
            .unwrap()
            .push_elem_to_stream(stream_id, elem)
        {
            error!("invalid stream id {}", stream_id);
            let resp = PcmStatus::new(VIRTIO_SND_S_BAD_MSG, 0);
            let len = elem.iov_from_buf_with_offset(sys_mem, cache, 0, resp.as_bytes())?;
            self.vq.add_used(elem.index, len as u32)?;
        }

        Ok(())
    }

    #[inline]
    fn get_vq(&self) -> &VirtQ {
        &self.vq
    }

    #[inline]
    fn device_broken(&self) -> bool {
        self.vq.device_broken()
    }
}

impl RxIoHandler {
    pub fn new(vq: VirtQ, pcm: Arc<Mutex<Pcm>>) -> Arc<Self> {
        Arc::new(Self { vq, pcm })
    }
}

pub struct EventIoHandler {
    vq: VirtQ,
    ctl: Arc<Mutex<Ctl>>,
}

impl EventIoHandler {
    pub fn new(vq: VirtQ, ctl: Arc<Mutex<Ctl>>) -> Arc<Self> {
        Arc::new(Self { vq, ctl })
    }

    fn event_notify<T: ByteCode + std::fmt::Debug>(&self, event: T) -> Result<()> {
        if self.vq.device_broken() {
            return Ok(());
        }

        let elem = self
            .vq
            .pop_elem()
            .with_context(|| "Failed to pop avail ring for process event queue")?;
        if elem.desc_num == 0 {
            return Ok(());
        }

        let sys_mem = self.vq.sys_mem();
        let cache = self.vq.get_cache();
        let len = elem.iov_from_buf_with_offset(&sys_mem, &cache, 0, event.as_bytes())?;
        self.vq
            .add_used(elem.index, len as u32)
            .with_context(|| format!("Failed to add event {:?} to queue", event))
    }

    fn update_guest_volume(&self, new_vol: u32, new_mute: bool) -> Result<()> {
        let mut ctl = self.ctl.lock().unwrap();
        if ctl.mute == new_mute && ctl.volume == new_vol {
            return Ok(());
        }

        // Special case for ohos volume
        #[cfg(target_env = "ohos")]
        let new_vol = if new_mute {
            // Drop to 0 if at step 1, otherwise hold current volume for state persistence
            if ctl.volume == 1 {
                0
            } else {
                ctl.volume
            }
        } else {
            new_vol
        };

        ctl.update_volume(new_vol, new_mute);

        let event = CtlEvent::new_le(
            VIRTIO_SND_EVT_CTL_NOTIFY,
            ctl.get_ctl_id_by_role(VIRTIO_SND_CTL_ROLE_VOLUME) as u16,
            1u16 << VIRTIO_SND_CTL_EVT_MASK_VALUE,
        );
        self.event_notify(event)
    }
}

impl VolumeListener for EventIoHandler {
    fn notify(&self, host_vol: u32, host_mute: bool) {
        if let Err(e) = self.update_guest_volume(host_vol, host_mute) {
            error!("Failed to notify the guest volume change, {:?}", e);
        }
    }
}

impl AuthorityNotifier for EventIoHandler {
    fn on_authority_changed(&self, has_authority: bool) {
        let jack_event = SndEvent::new_je_le(has_authority, 0);
        if let Err(e) = self.event_notify(jack_event) {
            error!(
                "Failed to notify the guest mic authority {}, {:?}",
                has_authority, e
            );
        }
    }
}
