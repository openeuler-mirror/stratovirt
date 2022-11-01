// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::cmp;
use std::collections::HashMap;
use std::io::Write;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};

use super::super::{
    Element, Queue, VirtioDevice, VirtioInterrupt, VirtioInterruptType, VIRTIO_F_VERSION_1,
    VIRTIO_SCSI_F_CHANGE, VIRTIO_SCSI_F_HOTPLUG, VIRTIO_TYPE_SCSI,
};
use crate::ScsiBus::{virtio_scsi_get_lun, ScsiBus, ScsiRequest, EMULATE_SCSI_OPS, GOOD};
use crate::VirtioError;
use address_space::{AddressSpace, GuestAddress};
use log::{error, info};
use machine_manager::{
    config::{ConfigCheck, ScsiCntlrConfig},
    event_loop::EventLoop,
};
use util::aio::{Aio, AioCb, AioCompleteFunc, Iovec};
use util::byte_code::ByteCode;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::num_ops::read_u32;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

/// Virtio Scsi Controller has 1 ctrl queue, 1 event queue and at least 1 cmd queue.
const SCSI_CTRL_QUEUE_NUM: usize = 1;
const SCSI_EVENT_QUEUE_NUM: usize = 1;
const SCSI_MIN_QUEUE_NUM: usize = 3;
/// Size of each virtqueue.
const QUEUE_SIZE_SCSI: u16 = 256;

/// Default values of the cdb and sense data size configuration fields. Cannot change cdb size
/// and sense data size Now.
/// To do: support Override CDB/sense data size.(Guest controlled)
pub const VIRTIO_SCSI_CDB_DEFAULT_SIZE: usize = 32;
pub const VIRTIO_SCSI_SENSE_DEFAULT_SIZE: usize = 96;

/// The key is bus name, the value is the attached Scsi Controller.
pub type ScsiCntlrMap = Arc<Mutex<HashMap<String, Arc<Mutex<ScsiCntlr>>>>>;

/// Control type codes.
/// Task Management Function.
pub const VIRTIO_SCSI_T_TMF: u32 = 0;
/// Asynchronous notification query.
pub const VIRTIO_SCSI_T_AN_QUERY: u32 = 1;
/// Asynchronous notification subscription.
pub const VIRTIO_SCSI_T_AN_SUBSCRIBE: u32 = 2;

/// Valid TMF Subtypes.
pub const VIRTIO_SCSI_T_TMF_ABORT_TASK: u32 = 0;
pub const VIRTIO_SCSI_T_TMF_ABORT_TASK_SET: u32 = 1;
pub const VIRTIO_SCSI_T_TMF_CLEAR_ACA: u32 = 2;
pub const VIRTIO_SCSI_T_TMF_CLEAR_TASK_SET: u32 = 3;
pub const VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET: u32 = 4;
pub const VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET: u32 = 5;
pub const VIRTIO_SCSI_T_TMF_QUERY_TASK: u32 = 6;
pub const VIRTIO_SCSI_T_TMF_QUERY_TASK_SET: u32 = 7;

/// Response codes.
pub const VIRTIO_SCSI_S_OK: u8 = 0;
pub const VIRTIO_SCSI_S_OVERRUN: u8 = 1;
pub const VIRTIO_SCSI_S_ABORTED: u8 = 2;
pub const VIRTIO_SCSI_S_BAD_TARGET: u8 = 3;
pub const VIRTIO_SCSI_S_RESET: u8 = 4;
pub const VIRTIO_SCSI_S_BUSY: u8 = 5;
pub const VIRTIO_SCSI_S_TRANSPORT_FAILURE: u8 = 6;
pub const VIRTIO_SCSI_S_TARGET_FAILURE: u8 = 7;
pub const VIRTIO_SCSI_S_NEXUS_FAILURE: u8 = 8;
pub const VIRTIO_SCSI_S_FAILURE: u8 = 9;
pub const VIRTIO_SCSI_S_FUNCTION_SUCCEEDED: u8 = 10;
pub const VIRTIO_SCSI_S_FUNCTION_REJECTED: u8 = 11;
pub const VIRTIO_SCSI_S_INCORRECT_LUN: u8 = 12;

#[derive(Clone)]
pub enum ScsiXferMode {
    /// TEST_UNIT_READY, ...
    ScsiXferNone,
    /// READ, INQUIRY, MODE_SENSE, ...
    ScsiXferFromDev,
    /// WRITE, MODE_SELECT, ...
    ScsiXferToDev,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioScsiConfig {
    num_queues: u32,
    seg_max: u32,
    max_sectors: u32,
    cmd_per_lun: u32,
    event_info_size: u32,
    sense_size: u32,
    cdb_size: u32,
    max_channel: u32,
    max_target: u32,
    max_lun: u32,
}

impl ByteCode for VirtioScsiConfig {}

/// State of virtio scsi controller.
#[derive(Clone, Copy, Default)]
pub struct ScsiCntlrState {
    /// Bitmask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Config space of the virtio scsi controller.
    config_space: VirtioScsiConfig,
}

/// Virtio Scsi Controller device structure.
#[derive(Default)]
pub struct ScsiCntlr {
    /// Configuration of the virtio scsi controller.
    config: ScsiCntlrConfig,
    /// Status of virtio scsi controller.
    state: ScsiCntlrState,
    /// Scsi bus.
    pub bus: Option<Arc<Mutex<ScsiBus>>>,
}

impl ScsiCntlr {
    pub fn new(config: ScsiCntlrConfig) -> ScsiCntlr {
        Self {
            config,
            state: ScsiCntlrState::default(),
            bus: None,
        }
    }
}

impl VirtioDevice for ScsiCntlr {
    /// Realize virtio scsi controller, which is a pci device.
    fn realize(&mut self) -> Result<()> {
        // If iothread not found, return err.
        if self.config.iothread.is_some()
            && EventLoop::get_ctx(self.config.iothread.as_ref()).is_none()
        {
            bail!(
                "IOThread {:?} of virtio scsi is not configured in params.",
                self.config.iothread,
            );
        }

        self.state.config_space.num_queues = self.config.queues;

        self.state.config_space.max_sectors = 0xFFFF_u32;
        // cmd_per_lun: maximum nuber of linked commands can be sent to one LUN. 32bit.
        self.state.config_space.cmd_per_lun = 128;
        // seg_max: queue size - 2, 32 bit.
        self.state.config_space.seg_max = self.queue_size() as u32 - 2;

        self.state.device_features |= (1_u64 << VIRTIO_F_VERSION_1)
            | (1_u64 << VIRTIO_SCSI_F_HOTPLUG)
            | (1_u64 << VIRTIO_SCSI_F_CHANGE);
        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_SCSI
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        self.config.queues as usize + SCSI_CTRL_QUEUE_NUM + SCSI_EVENT_QUEUE_NUM
    }

    /// Get the queue size of virtio device.
    fn queue_size(&self) -> u16 {
        QUEUE_SIZE_SCSI
    }

    /// Get device features from host.
    fn get_device_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.device_features, features_select)
    }

    /// Set driver features by guest.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        self.state.driver_features = self.checked_driver_features(page, value);
    }

    /// Get driver features by guest.
    fn get_driver_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.driver_features, features_select)
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config_slice = self.state.config_space.as_bytes();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            return Err(anyhow!(VirtioError::DevConfigOverflow(offset, config_len)));
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])?;
        }

        Ok(())
    }

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let config_slice = self.state.config_space.as_mut_bytes();
        let config_len = config_slice.len();
        if offset as usize + data_len > config_len {
            return Err(anyhow!(VirtioError::DevConfigOverflow(
                offset,
                config_len as u64
            )));
        }

        config_slice[(offset as usize)..(offset as usize + data_len)].copy_from_slice(data);

        Ok(())
    }

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<Queue>>],
        mut queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        let queue_num = queues.len();
        if queue_num < SCSI_MIN_QUEUE_NUM {
            bail!("virtio scsi controller queues num can not be less than 3!");
        }

        let ctrl_queue = queues[0].clone();
        let ctrl_queue_evt = queue_evts.remove(0);
        let ctrl_handler = ScsiCtrlHandler {
            queue: ctrl_queue,
            queue_evt: ctrl_queue_evt,
            mem_space: mem_space.clone(),
            interrupt_cb: interrupt_cb.clone(),
            driver_features: self.state.driver_features,
        };
        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(ctrl_handler))),
            self.config.iothread.as_ref(),
        )?;

        let event_queue = queues[1].clone();
        let event_queue_evt = queue_evts.remove(0);
        let event_handler = ScsiEventHandler {
            _queue: event_queue,
            queue_evt: event_queue_evt,
            _mem_space: mem_space.clone(),
            _interrupt_cb: interrupt_cb.clone(),
            _driver_features: self.state.driver_features,
        };
        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(event_handler))),
            self.config.iothread.as_ref(),
        )?;

        let queues_num = queues.len();
        for cmd_queue in queues.iter().take(queues_num).skip(2) {
            if let Some(bus) = &self.bus {
                let mut cmd_handler = ScsiCmdHandler {
                    aio: None,
                    scsibus: bus.clone(),
                    queue: cmd_queue.clone(),
                    queue_evt: queue_evts.remove(0),
                    mem_space: mem_space.clone(),
                    interrupt_cb: interrupt_cb.clone(),
                    driver_features: self.state.driver_features,
                };

                cmd_handler.aio = Some(cmd_handler.build_aio()?);

                EventLoop::update_event(
                    EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(cmd_handler))),
                    self.config.iothread.as_ref(),
                )?;
            } else {
                bail!("Scsi controller has no bus!");
            }
        }

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        Ok(())
    }

    fn update_config(&mut self, _dev_config: Option<Arc<dyn ConfigCheck>>) -> Result<()> {
        Ok(())
    }
}

fn build_event_notifier(fd: RawFd, handler: Box<NotifierCallback>) -> EventNotifier {
    EventNotifier::new(
        NotifierOperation::AddShared,
        fd,
        None,
        EventSet::IN,
        vec![Arc::new(Mutex::new(handler))],
    )
}

/// Task Managememt Request.
#[derive(Copy, Clone, Debug, Default)]
pub struct VirtioScsiCtrlTmfReq {
    pub ctrltype: u32,
    pub subtype: u32,
    pub lun: [u8; 8],
    pub tag: u64,
}

impl ByteCode for VirtioScsiCtrlTmfReq {}

#[derive(Copy, Clone, Debug, Default)]
pub struct VirtioScsiCtrlTmfResp {
    pub response: u8,
}

impl ByteCode for VirtioScsiCtrlTmfResp {}

/// Asynchronous notification query/subscription.
#[derive(Copy, Clone, Debug, Default)]
pub struct VirtioScsiCtrlAnReq {
    pub ctrltype: u32,
    pub lun: [u8; 8],
    pub event_requested: u32,
}

impl ByteCode for VirtioScsiCtrlAnReq {}

#[derive(Copy, Clone, Debug, Default)]
pub struct VirtioScsiCtrlAnResp {
    pub evnet_actual: u32,
    pub response: u8,
}

impl ByteCode for VirtioScsiCtrlAnResp {}

#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
pub struct VirtioScsiCmdReq {
    /// Logical Unit Number.
    lun: [u8; 8],
    /// Command identifier.
    tag: u64,
    /// Task attribute.
    task_attr: u8,
    /// SAM command priority field.
    prio: u8,
    crn: u8,
    pub cdb: [u8; VIRTIO_SCSI_CDB_DEFAULT_SIZE],
}

impl ByteCode for VirtioScsiCmdReq {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtioScsiCmdResp {
    /// Sense data length.
    pub sense_len: u32,
    /// Resudual bytes in data buffer.
    pub resid: u32,
    /// Status qualifier.
    status_qualifier: u16,
    /// Command completion status.
    pub status: u8,
    /// Respinse value.
    pub response: u8,
    /// Sense buffer data.
    pub sense: [u8; VIRTIO_SCSI_SENSE_DEFAULT_SIZE],
}

impl Default for VirtioScsiCmdResp {
    fn default() -> Self {
        VirtioScsiCmdResp {
            sense_len: 0,
            resid: 0,
            status_qualifier: 0,
            status: 0,
            response: 0,
            sense: [0; VIRTIO_SCSI_SENSE_DEFAULT_SIZE],
        }
    }
}

impl ByteCode for VirtioScsiCmdResp {}

/// T: request; U: response.
pub struct VirtioScsiRequest<T: Clone + ByteCode, U: Clone + ByteCode> {
    queue: Arc<Mutex<Queue>>,
    desc_index: u16,
    /// Read or Write data, HVA, except resp.
    pub iovec: Vec<Iovec>,
    data_len: u32,
    _cdb_size: u32,
    _sense_size: u32,
    mode: ScsiXferMode,
    _interrupt_cb: Option<Arc<VirtioInterrupt>>,
    _driver_features: u64,
    /// resp GPA.
    resp_addr: GuestAddress,
    pub req: T,
    pub resp: U,
}

/// T: request; U:response.
impl<T: Clone + ByteCode, U: Clone + ByteCode> VirtioScsiRequest<T, U> {
    fn new(
        mem_space: &Arc<AddressSpace>,
        queue: Arc<Mutex<Queue>>,
        interrupt_cb: Option<Arc<VirtioInterrupt>>,
        driver_features: u64,
        elem: &Element,
    ) -> Result<Self> {
        let out_iov_elem = elem.out_iovec.get(0).unwrap();
        if out_iov_elem.len < size_of::<T>() as u32 {
            bail!(
                "Invalid virtio scsi request: get length {}, expected length {}",
                out_iov_elem.len,
                size_of::<T>(),
            );
        }

        let scsi_req = mem_space
            .read_object::<T>(out_iov_elem.addr)
            .with_context(|| VirtioError::ReadObjectErr("the scsi request", out_iov_elem.addr.0))?;

        let in_iov_elem = elem.in_iovec.get(0).unwrap();
        if in_iov_elem.len < size_of::<U>() as u32 {
            bail!(
                "Invalid virtio scsi response: get length {}, expected length {}",
                in_iov_elem.len,
                size_of::<U>()
            );
        }
        let scsi_resp = mem_space
            .read_object::<U>(in_iov_elem.addr)
            .with_context(|| VirtioError::ReadObjectErr("the scsi response", in_iov_elem.addr.0))?;

        let mut request = VirtioScsiRequest {
            queue,
            desc_index: elem.index,
            iovec: Vec::with_capacity(elem.desc_num as usize),
            data_len: 0,
            _cdb_size: VIRTIO_SCSI_CDB_DEFAULT_SIZE as u32,
            _sense_size: VIRTIO_SCSI_SENSE_DEFAULT_SIZE as u32,
            mode: ScsiXferMode::ScsiXferNone,
            _interrupt_cb: interrupt_cb,
            _driver_features: driver_features,
            resp_addr: in_iov_elem.addr,
            req: scsi_req,
            resp: scsi_resp,
        };

        let mut out_len: u32 = 0;
        let mut skip_out_size: u32 = size_of::<T>() as u32;
        for (_index, elem_iov) in elem.out_iovec.iter().enumerate() {
            if skip_out_size >= elem_iov.len {
                skip_out_size -= elem_iov.len;
            } else if let Some(hva) = mem_space.get_host_address(elem_iov.addr) {
                let len = elem_iov.len - skip_out_size;
                let iov = Iovec {
                    iov_base: hva + skip_out_size as u64,
                    iov_len: u64::from(len),
                };
                out_len += len;
                skip_out_size = 0;
                request.iovec.push(iov);
            }
        }

        let mut in_len: u32 = 0;
        let mut skip_in_size: u32 = size_of::<U>() as u32;
        for (_index, elem_iov) in elem.in_iovec.iter().enumerate() {
            if skip_in_size >= elem_iov.len {
                skip_in_size -= elem_iov.len;
            } else {
                if out_len > 0 {
                    bail!("Wrong scsi request!");
                }
                if let Some(hva) = mem_space.get_host_address(elem_iov.addr) {
                    let len = elem_iov.len - skip_in_size;
                    let iov = Iovec {
                        iov_base: hva + skip_in_size as u64,
                        iov_len: u64::from(len),
                    };
                    in_len += len;
                    skip_in_size = 0;
                    request.iovec.push(iov);
                }
            }
        }

        if out_len > 0 {
            request.mode = ScsiXferMode::ScsiXferToDev;
            request.data_len = out_len;
        } else if in_len > 0 {
            request.mode = ScsiXferMode::ScsiXferFromDev;
            request.data_len = in_len;
        }

        Ok(request)
    }

    pub fn complete(&self, mem_space: &Arc<AddressSpace>) -> bool {
        if let Err(ref e) = mem_space.write_object(&self.resp, self.resp_addr) {
            error!("Failed to write the scsi response {:?}", e);
            return false;
        }
        let mut queue_lock = self.queue.lock().unwrap();
        if let Err(ref e) = queue_lock.vring.add_used(
            mem_space,
            self.desc_index,
            self.data_len + (size_of::<U>() as u32),
        ) {
            error!(
                "Failed to add used ring(scsi completion), index {}, len {} {:?}",
                self.desc_index, self.data_len, e
            );
            return false;
        }
        true
    }
}

pub struct ScsiCtrlHandler {
    /// The ctrl virtqueue.
    queue: Arc<Mutex<Queue>>,
    /// EventFd for the ctrl virtqueue.
    queue_evt: EventFd,
    /// The address space to which the scsi HBA belongs.
    mem_space: Arc<AddressSpace>,
    /// The interrupt callback function.
    interrupt_cb: Arc<VirtioInterrupt>,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
}

impl ScsiCtrlHandler {
    fn handle_ctrl(&mut self) -> Result<()> {
        let mut queue = self.queue.lock().unwrap();

        while let Ok(elem) = queue.vring.pop_avail(&self.mem_space, self.driver_features) {
            drop(queue);
            let ctrl_desc = elem.out_iovec.get(0).unwrap();
            let ctrl_type = self
                .mem_space
                .read_object::<u32>(ctrl_desc.addr)
                .with_context(|| "Failed to get control queue descriptor")?;
            match ctrl_type {
                VIRTIO_SCSI_T_TMF => {
                    match VirtioScsiRequest::<VirtioScsiCtrlTmfReq, VirtioScsiCtrlTmfResp>::new(
                        &self.mem_space,
                        self.queue.clone(),
                        Some(self.interrupt_cb.clone()),
                        self.driver_features,
                        &elem,
                    ) {
                        Ok(mut tmf) => {
                            info!("incomplete tmf req, subtype {}!", tmf.req.subtype);

                            tmf.resp.response = VIRTIO_SCSI_S_OK;
                            tmf.complete(&self.mem_space);
                        }
                        Err(ref e) => {
                            let mut queue = self.queue.lock().unwrap();
                            queue
                                .vring
                                .add_used(&self.mem_space, elem.index, 0)
                                .with_context(|| "Failed to add used ring")?;
                            drop(queue);

                            error!("Failed to create VIRTIO_SCSI_T_TMF request, {:?}", e);
                        }
                    }
                }

                VIRTIO_SCSI_T_AN_QUERY | VIRTIO_SCSI_T_AN_SUBSCRIBE => {
                    match VirtioScsiRequest::<VirtioScsiCtrlAnReq, VirtioScsiCtrlAnResp>::new(
                        &self.mem_space,
                        self.queue.clone(),
                        Some(self.interrupt_cb.clone()),
                        self.driver_features,
                        &elem,
                    ) {
                        Ok(mut an) => {
                            info!("incomplete An req!");
                            an.resp.evnet_actual = 0;
                            an.resp.response = VIRTIO_SCSI_S_OK;
                            an.complete(&self.mem_space);
                        }
                        Err(ref e) => {
                            let mut queue = self.queue.lock().unwrap();
                            queue
                                .vring
                                .add_used(&self.mem_space, elem.index, 0)
                                .with_context(|| "Failed to add used ring")?;
                            drop(queue);

                            error!("Failed to create scsi ctrl an req, {:?}", e)
                        }
                    }
                }
                _ => {
                    bail!("Control queue type doesn't support {}", ctrl_type);
                }
            }
            queue = self.queue.lock().unwrap();
        }

        (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue)).with_context(|| {
            VirtioError::InterruptTrigger("scsi ctrl", VirtioInterruptType::Vring)
        })?;
        Ok(())
    }
}

impl EventNotifierHelper for ScsiCtrlHandler {
    fn internal_notifiers(handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let h_locked = handler.lock().unwrap();
        let h_clone = handler.clone();
        let h: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            h_clone
                .lock()
                .unwrap()
                .handle_ctrl()
                .unwrap_or_else(|e| error!("Failed to handle ctrl queue, error is {}.", e));
            None
        });

        let mut notifiers = Vec::new();
        let ctrl_fd = h_locked.queue_evt.as_raw_fd();
        notifiers.push(build_event_notifier(ctrl_fd, h));

        notifiers
    }
}

pub struct ScsiEventHandler {
    /// The Event virtqueue.
    _queue: Arc<Mutex<Queue>>,
    /// EventFd for the Event virtqueue.
    queue_evt: EventFd,
    /// The address space to which the scsi HBA belongs.
    _mem_space: Arc<AddressSpace>,
    /// The interrupt callback function.
    _interrupt_cb: Arc<VirtioInterrupt>,
    /// Bit mask of features negotiated by the backend and the frontend.
    _driver_features: u64,
}

impl EventNotifierHelper for ScsiEventHandler {
    fn internal_notifiers(handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let h_locked = handler.lock().unwrap();
        let h_clone = handler.clone();
        let h: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            h_clone
                .lock()
                .unwrap()
                .handle_event()
                .unwrap_or_else(|e| error!("Failed to handle event queue, err is {}", e));
            None
        });

        let mut notifiers = Vec::new();
        let event_fd = h_locked.queue_evt.as_raw_fd();
        notifiers.push(build_event_notifier(event_fd, h));

        notifiers
    }
}

impl ScsiEventHandler {
    fn handle_event(&mut self) -> Result<()> {
        Ok(())
    }
}

pub struct ScsiCmdHandler {
    /// The scsi controller.
    scsibus: Arc<Mutex<ScsiBus>>,
    /// The Cmd virtqueue.
    queue: Arc<Mutex<Queue>>,
    /// EventFd for the Cmd virtqueue.
    queue_evt: EventFd,
    /// The address space to which the scsi HBA belongs.
    mem_space: Arc<AddressSpace>,
    /// The interrupt callback function.
    interrupt_cb: Arc<VirtioInterrupt>,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Aio context.
    aio: Option<Box<Aio<ScsiCompleteCb>>>,
}

impl EventNotifierHelper for ScsiCmdHandler {
    fn internal_notifiers(handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let h_locked = handler.lock().unwrap();
        let h_clone = handler.clone();
        let h: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            h_clone
                .lock()
                .unwrap()
                .handle_cmd()
                .unwrap_or_else(|e| error!("Failed to handle cmd queue, err is {}", e));

            None
        });

        let mut notifiers = Vec::new();
        let event_fd = h_locked.queue_evt.as_raw_fd();
        notifiers.push(build_event_notifier(event_fd, h));

        notifiers
    }
}

impl ScsiCmdHandler {
    fn handle_cmd(&mut self) -> Result<()> {
        let mut queue = self.queue.lock().unwrap();

        while let Ok(elem) = queue.vring.pop_avail(&self.mem_space, self.driver_features) {
            match VirtioScsiRequest::<VirtioScsiCmdReq, VirtioScsiCmdResp>::new(
                &self.mem_space,
                self.queue.clone(),
                Some(self.interrupt_cb.clone()),
                self.driver_features,
                &elem,
            ) {
                Ok(mut cmd) => {
                    drop(queue);
                    let lun: [u8; 8] = cmd.req.lun;
                    let scsibus = self.scsibus.lock().unwrap();

                    if let Some(scsidevice) = scsibus.get_device(lun[1], virtio_scsi_get_lun(lun)) {
                        drop(scsibus);
                        let cmd_req = Arc::new(Mutex::new(cmd));
                        let req = if let Ok(scsireq) =
                            ScsiRequest::new(cmd_req, self.scsibus.clone(), scsidevice.clone())
                        {
                            Some(scsireq)
                        } else {
                            let mut queue = self.queue.lock().unwrap();
                            queue
                                .vring
                                .add_used(&self.mem_space, elem.index, 0)
                                .with_context(|| "Failed to add used ring")?;
                            drop(queue);
                            error!("Failed to create scsi request");

                            None
                        };

                        if let Some(scsireq) = req {
                            if scsireq.opstype == EMULATE_SCSI_OPS {
                                let scsicompletecb = ScsiCompleteCb::new(
                                    self.mem_space.clone(),
                                    Arc::new(Mutex::new(scsireq.clone())),
                                );
                                scsireq.emulate_execute(scsicompletecb)?;
                            } else if let Some(disk_img) =
                                scsidevice.lock().unwrap().disk_image.as_mut()
                            {
                                let scsicompletecb = ScsiCompleteCb::new(
                                    self.mem_space.clone(),
                                    Arc::new(Mutex::new(scsireq.clone())),
                                );
                                if let Some(ref mut aio) = self.aio {
                                    scsireq.execute(aio, disk_img, false, true, scsicompletecb)?;
                                }
                            }
                        }
                    } else {
                        cmd.resp.response = VIRTIO_SCSI_S_BAD_TARGET;
                        cmd.complete(&self.mem_space);
                        error!(
                            "no such scsi device target {}, lun {}",
                            lun[1],
                            virtio_scsi_get_lun(lun)
                        );
                    };
                }
                Err(ref e) => {
                    // If it fails, also need to free descriptor table entry.
                    let mut queue = self.queue.lock().unwrap();
                    queue
                        .vring
                        .add_used(&self.mem_space, elem.index, 0)
                        .with_context(|| "Failed to add used ring")?;
                    drop(queue);

                    error!("Failed to create cmd request, {:?}", e);
                }
            }

            queue = self.queue.lock().unwrap();
        }

        (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue)).with_context(|| {
            anyhow!(VirtioError::InterruptTrigger(
                "scsi cmd",
                VirtioInterruptType::Vring
            ))
        })?;

        Ok(())
    }

    fn build_aio(&self) -> Result<Box<Aio<ScsiCompleteCb>>> {
        let complete_fun = Arc::new(Box::new(move |aiocb: &AioCb<ScsiCompleteCb>, ret: i64| {
            let complete_cb = &aiocb.iocompletecb;
            let request = &aiocb.iocompletecb.req.lock().unwrap();
            let mut virtio_scsi_req = request.virtioscsireq.lock().unwrap();

            virtio_scsi_req.resp.response = if ret < 0 {
                VIRTIO_SCSI_S_FAILURE
            } else {
                VIRTIO_SCSI_S_OK
            };

            virtio_scsi_req.resp.status = GOOD;
            virtio_scsi_req.resp.resid = 0;
            virtio_scsi_req.resp.sense_len = 0;
            virtio_scsi_req.complete(&complete_cb.mem_space);
        }) as AioCompleteFunc<ScsiCompleteCb>);

        Ok(Box::new(Aio::new(complete_fun, None)?))
    }
}

#[derive(Clone)]
pub struct ScsiCompleteCb {
    pub mem_space: Arc<AddressSpace>,
    req: Arc<Mutex<ScsiRequest>>,
}

impl ScsiCompleteCb {
    fn new(mem_space: Arc<AddressSpace>, req: Arc<Mutex<ScsiRequest>>) -> Self {
        ScsiCompleteCb { mem_space, req }
    }
}
