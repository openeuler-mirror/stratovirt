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
use std::io::Write;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};

use crate::ScsiBus::{
    virtio_scsi_get_lun, ScsiBus, ScsiRequest, ScsiSense, CHECK_CONDITION, EMULATE_SCSI_OPS, GOOD,
    SCSI_SENSE_INVALID_OPCODE,
};
use crate::{
    report_virtio_error, Element, Queue, VirtioDevice, VirtioError, VirtioInterrupt,
    VirtioInterruptType, VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_RING_INDIRECT_DESC, VIRTIO_F_VERSION_1,
    VIRTIO_SCSI_F_CHANGE, VIRTIO_SCSI_F_HOTPLUG, VIRTIO_TYPE_SCSI,
};
use address_space::{AddressSpace, GuestAddress};
use log::{debug, error, info};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use machine_manager::{
    config::{ScsiCntlrConfig, VIRTIO_SCSI_MAX_LUN, VIRTIO_SCSI_MAX_TARGET},
    event_loop::EventLoop,
};
use util::aio::{Aio, AioCb, Iovec, OpCode};
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

/// Default values of the cdb and sense data size configuration fields. Cannot change cdb size
/// and sense data size Now.
/// To do: support Override CDB/sense data size.(Guest controlled)
pub const VIRTIO_SCSI_CDB_DEFAULT_SIZE: usize = 32;
pub const VIRTIO_SCSI_SENSE_DEFAULT_SIZE: usize = 96;

/// Basic length of fixed format sense data.
pub const SCSI_SENSE_LEN: u32 = 18;

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
    max_channel: u16,
    max_target: u16,
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
pub struct ScsiCntlr {
    /// Configuration of the virtio scsi controller.
    pub config: ScsiCntlrConfig,
    /// Status of virtio scsi controller.
    state: ScsiCntlrState,
    /// Scsi bus.
    pub bus: Option<Arc<Mutex<ScsiBus>>>,
    /// Eventfd for Scsi Controller deactivates.
    deactivate_evts: Vec<RawFd>,
    /// Device is broken or not.
    broken: Arc<AtomicBool>,
}

impl ScsiCntlr {
    pub fn new(config: ScsiCntlrConfig) -> ScsiCntlr {
        Self {
            config,
            state: ScsiCntlrState::default(),
            bus: None,
            deactivate_evts: Vec::new(),
            broken: Arc::new(AtomicBool::new(false)),
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
        self.state.config_space.max_target = VIRTIO_SCSI_MAX_TARGET;
        self.state.config_space.max_lun = VIRTIO_SCSI_MAX_LUN as u32;
        // num_queues: request queues number.
        self.state.config_space.num_queues = self.config.queues;

        self.state.device_features |= (1_u64 << VIRTIO_F_VERSION_1)
            | (1_u64 << VIRTIO_SCSI_F_HOTPLUG)
            | (1_u64 << VIRTIO_SCSI_F_CHANGE)
            | (1_u64 << VIRTIO_F_RING_EVENT_IDX)
            | (1_u64 << VIRTIO_F_RING_INDIRECT_DESC);

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
        // Note: self.config.queues <= MAX_VIRTIO_QUEUE(32).
        self.config.queues as usize + SCSI_CTRL_QUEUE_NUM + SCSI_EVENT_QUEUE_NUM
    }

    /// Get the queue size of virtio device.
    fn queue_size(&self) -> u16 {
        self.config.queue_size
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
        let config_slice = self.state.config_space.as_mut_bytes();
        let config_len = config_slice.len() as u64;

        if offset
            .checked_add(data.len() as u64)
            .filter(|&end| end <= config_len)
            .is_none()
        {
            return Err(anyhow!(VirtioError::DevConfigOverflow(offset, config_len)));
        }

        // Guest can only set sense_size and cdb_size, which are fixed default values
        // (VIRTIO_SCSI_CDB_DEFAULT_SIZE; VIRTIO_SCSI_SENSE_DEFAULT_SIZE) and cannot be
        // changed in stratovirt now. So, do nothing when guest writes config.
        Ok(())
    }

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<Queue>>],
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let queue_num = queues.len();
        if queue_num < SCSI_MIN_QUEUE_NUM {
            bail!("virtio scsi controller queues num can not be less than 3!");
        }

        let ctrl_queue = queues[0].clone();
        let ctrl_queue_evt = queue_evts[0].clone();
        let ctrl_handler = ScsiCtrlHandler {
            queue: ctrl_queue,
            queue_evt: ctrl_queue_evt,
            mem_space: mem_space.clone(),
            interrupt_cb: interrupt_cb.clone(),
            driver_features: self.state.driver_features,
            device_broken: self.broken.clone(),
        };
        let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(ctrl_handler)));
        register_event_helper(
            notifiers,
            self.config.iothread.as_ref(),
            &mut self.deactivate_evts,
        )?;

        let event_queue = queues[1].clone();
        let event_queue_evt = queue_evts[1].clone();
        let event_handler = ScsiEventHandler {
            _queue: event_queue,
            queue_evt: event_queue_evt,
            _mem_space: mem_space.clone(),
            _interrupt_cb: interrupt_cb.clone(),
            _driver_features: self.state.driver_features,
            device_broken: self.broken.clone(),
        };
        let notifiers =
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(event_handler)));
        register_event_helper(
            notifiers,
            self.config.iothread.as_ref(),
            &mut self.deactivate_evts,
        )?;

        for (index, cmd_queue) in queues[2..].iter().enumerate() {
            let bus = self.bus.as_ref().unwrap();
            let cmd_handler = ScsiCmdHandler {
                scsibus: bus.clone(),
                queue: cmd_queue.clone(),
                queue_evt: queue_evts[index + 2].clone(),
                mem_space: mem_space.clone(),
                interrupt_cb: interrupt_cb.clone(),
                driver_features: self.state.driver_features,
                device_broken: self.broken.clone(),
            };

            let notifiers =
                EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(cmd_handler)));
            if notifiers.is_empty() {
                bail!("Error in create scsi device aio!");
            }

            register_event_helper(
                notifiers,
                self.config.iothread.as_ref(),
                &mut self.deactivate_evts,
            )?;
        }
        self.broken.store(false, Ordering::SeqCst);

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        unregister_event_helper(self.config.iothread.as_ref(), &mut self.deactivate_evts)
    }
}

fn build_event_notifier(fd: RawFd, handler: Rc<NotifierCallback>) -> EventNotifier {
    EventNotifier::new(
        NotifierOperation::AddShared,
        fd,
        None,
        EventSet::IN,
        vec![handler],
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

impl VirtioScsiCmdResp {
    pub fn set_scsi_sense(&mut self, sense: ScsiSense) {
        // Response code: current errors(0x70).
        self.sense[0] = 0x70;
        self.sense[2] = sense.key;
        // Additional sense length: sense len - 8.
        self.sense[7] = SCSI_SENSE_LEN as u8 - 8;
        self.sense[12] = sense.asc;
        self.sense[13] = sense.ascq;
        self.sense_len = SCSI_SENSE_LEN;
    }
}

impl ByteCode for VirtioScsiCmdResp {}

/// T: request; U: response.
pub struct VirtioScsiRequest<T: Clone + ByteCode, U: Clone + ByteCode> {
    queue: Arc<Mutex<Queue>>,
    desc_index: u16,
    /// Read or Write data, HVA, except resp.
    pub iovec: Vec<Iovec>,
    pub data_len: u32,
    _cdb_size: u32,
    _sense_size: u32,
    mode: ScsiXferMode,
    interrupt_cb: Arc<VirtioInterrupt>,
    driver_features: u64,
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
        interrupt_cb: Arc<VirtioInterrupt>,
        driver_features: u64,
        elem: &Element,
    ) -> Result<Self> {
        if elem.out_iovec.is_empty() || elem.in_iovec.is_empty() {
            bail!(
                "Missed header for scsi request: out {} in {} desc num {}",
                elem.out_iovec.len(),
                elem.in_iovec.len(),
                elem.desc_num
            );
        }

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
            interrupt_cb,
            driver_features,
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

    pub fn complete(&self, mem_space: &Arc<AddressSpace>) -> Result<()> {
        if let Err(ref e) = mem_space.write_object(&self.resp, self.resp_addr) {
            bail!("Failed to write the scsi response {:?}", e);
        }

        let mut queue_lock = self.queue.lock().unwrap();
        // Note: U(response) is the header part of in_iov and self.data_len is the rest part of the in_iov or
        // the out_iov. in_iov and out_iov total len is no more than DESC_CHAIN_MAX_TOTAL_LEN(1 << 32). So,
        // it will not overflow here.
        if let Err(ref e) = queue_lock.vring.add_used(
            mem_space,
            self.desc_index,
            self.data_len + (size_of::<U>() as u32),
        ) {
            bail!(
                "Failed to add used ring(scsi completion), index {}, len {} {:?}",
                self.desc_index,
                self.data_len,
                e
            );
        }

        if queue_lock
            .vring
            .should_notify(mem_space, self.driver_features)
        {
            if let Err(e) =
                (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue_lock), false)
            {
                bail!(
                    "Failed to trigger interrupt(aio completion) for scsi controller, error is {:?}",
                    e
                );
            }
        }

        Ok(())
    }
}

pub struct ScsiCtrlHandler {
    /// The ctrl virtqueue.
    queue: Arc<Mutex<Queue>>,
    /// EventFd for the ctrl virtqueue.
    queue_evt: Arc<EventFd>,
    /// The address space to which the scsi HBA belongs.
    mem_space: Arc<AddressSpace>,
    /// The interrupt callback function.
    interrupt_cb: Arc<VirtioInterrupt>,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Device is broken or not.
    device_broken: Arc<AtomicBool>,
}

impl ScsiCtrlHandler {
    fn handle_ctrl(&mut self) -> Result<()> {
        let result = self.handle_ctrl_request();
        if result.is_err() {
            report_virtio_error(
                self.interrupt_cb.clone(),
                self.driver_features,
                &self.device_broken,
            );
        }

        result
    }

    fn handle_ctrl_request(&mut self) -> Result<()> {
        loop {
            let mut queue = self.queue.lock().unwrap();
            let elem = queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)?;
            drop(queue);
            if elem.desc_num == 0 {
                break;
            }

            let ctrl_desc = elem.out_iovec.get(0).unwrap();
            let ctrl_type = self
                .mem_space
                .read_object::<u32>(ctrl_desc.addr)
                .with_context(|| "Failed to get control queue descriptor")?;

            match ctrl_type {
                VIRTIO_SCSI_T_TMF => {
                    let mut tmf =
                        VirtioScsiRequest::<VirtioScsiCtrlTmfReq, VirtioScsiCtrlTmfResp>::new(
                            &self.mem_space,
                            self.queue.clone(),
                            self.interrupt_cb.clone(),
                            self.driver_features,
                            &elem,
                        )?;
                    info!("incomplete tmf req, subtype {}!", tmf.req.subtype);
                    // Scsi Task Management Function is not supported.
                    // So, do nothing when stratovirt receives TMF request except responsing guest scsi drivers.
                    tmf.resp.response = VIRTIO_SCSI_S_OK;
                    tmf.complete(&self.mem_space)?;
                }
                VIRTIO_SCSI_T_AN_QUERY | VIRTIO_SCSI_T_AN_SUBSCRIBE => {
                    let mut an =
                        VirtioScsiRequest::<VirtioScsiCtrlAnReq, VirtioScsiCtrlAnResp>::new(
                            &self.mem_space,
                            self.queue.clone(),
                            self.interrupt_cb.clone(),
                            self.driver_features,
                            &elem,
                        )?;
                    an.resp.evnet_actual = 0;
                    an.resp.response = VIRTIO_SCSI_S_OK;
                    an.complete(&self.mem_space)?;
                }
                _ => {
                    bail!("Invalid ctrl type {}", ctrl_type);
                }
            }
        }

        Ok(())
    }
}

impl EventNotifierHelper for ScsiCtrlHandler {
    fn internal_notifiers(handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        let h_locked = handler.lock().unwrap();
        let h_clone = handler.clone();
        let h: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let mut h_lock = h_clone.lock().unwrap();
            if h_lock.device_broken.load(Ordering::SeqCst) {
                return None;
            }
            h_lock
                .handle_ctrl()
                .unwrap_or_else(|e| error!("Failed to handle ctrl queue, error is {:?}", e));
            None
        });
        notifiers.push(build_event_notifier(h_locked.queue_evt.as_raw_fd(), h));

        notifiers
    }
}

pub struct ScsiEventHandler {
    /// The Event virtqueue.
    _queue: Arc<Mutex<Queue>>,
    /// EventFd for the Event virtqueue.
    queue_evt: Arc<EventFd>,
    /// The address space to which the scsi HBA belongs.
    _mem_space: Arc<AddressSpace>,
    /// The interrupt callback function.
    _interrupt_cb: Arc<VirtioInterrupt>,
    /// Bit mask of features negotiated by the backend and the frontend.
    _driver_features: u64,
    /// Device is broken or not.
    device_broken: Arc<AtomicBool>,
}

impl EventNotifierHelper for ScsiEventHandler {
    fn internal_notifiers(handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        let h_locked = handler.lock().unwrap();
        let h_clone = handler.clone();
        let h: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let mut h_lock = h_clone.lock().unwrap();
            if h_lock.device_broken.load(Ordering::SeqCst) {
                return None;
            }
            h_lock
                .handle_event()
                .unwrap_or_else(|e| error!("Failed to handle event queue, err is {:?}", e));
            None
        });
        notifiers.push(build_event_notifier(h_locked.queue_evt.as_raw_fd(), h));

        notifiers
    }
}

impl ScsiEventHandler {
    fn handle_event(&mut self) -> Result<()> {
        Ok(())
    }
}

fn complete_func(aiocb: &AioCb<ScsiCompleteCb>, ret: i64) -> Result<()> {
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
    virtio_scsi_req.complete(&complete_cb.mem_space)
}

pub struct ScsiCmdHandler {
    /// The scsi controller.
    scsibus: Arc<Mutex<ScsiBus>>,
    /// The Cmd virtqueue.
    queue: Arc<Mutex<Queue>>,
    /// EventFd for the Cmd virtqueue.
    queue_evt: Arc<EventFd>,
    /// The address space to which the scsi HBA belongs.
    mem_space: Arc<AddressSpace>,
    /// The interrupt callback function.
    interrupt_cb: Arc<VirtioInterrupt>,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Device is broken or not.
    device_broken: Arc<AtomicBool>,
}

impl EventNotifierHelper for ScsiCmdHandler {
    fn internal_notifiers(handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        // Register event notifier for queue evt.
        let h_locked = handler.lock().unwrap();
        let h_clone = handler.clone();
        let h: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let mut h_lock = h_clone.lock().unwrap();
            if h_lock.device_broken.load(Ordering::SeqCst) {
                return None;
            }
            h_lock
                .handle_cmd()
                .unwrap_or_else(|e| error!("Failed to handle cmd queue, err is {:?}", e));

            None
        });
        notifiers.push(build_event_notifier(h_locked.queue_evt.as_raw_fd(), h));

        // Register event notifier for device aio.
        let locked_bus = h_locked.scsibus.lock().unwrap();
        for device in locked_bus.devices.values() {
            let mut locked_device = device.lock().unwrap();

            let aio = if let Ok(engine_aio) =
                Aio::new(Arc::new(complete_func), locked_device.config.aio_type)
            {
                engine_aio
            } else {
                return Vec::new();
            };
            let dev_aio = Arc::new(Mutex::new(aio));
            let dev_aio_h = dev_aio.clone();
            locked_device.aio = Some(dev_aio.clone());

            let h_clone = handler.clone();
            let h: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
                read_fd(fd);
                let mut h_lock = h_clone.lock().unwrap();
                if h_lock.device_broken.load(Ordering::SeqCst) {
                    return None;
                }
                if let Err(ref e) = h_lock.aio_complete_handler(&dev_aio_h) {
                    error!("Failed to handle aio {:?}", e);
                }
                None
            });
            notifiers.push(build_event_notifier(
                (*dev_aio).lock().unwrap().fd.as_raw_fd(),
                h,
            ));
        }

        notifiers
    }
}

impl ScsiCmdHandler {
    fn aio_complete_handler(&mut self, aio: &Arc<Mutex<Aio<ScsiCompleteCb>>>) -> Result<bool> {
        aio.lock().unwrap().handle_complete().map_err(|e| {
            report_virtio_error(
                self.interrupt_cb.clone(),
                self.driver_features,
                &self.device_broken,
            );
            e
        })
    }

    fn handle_cmd(&mut self) -> Result<()> {
        let result = self.handle_cmd_request();
        if result.is_err() {
            report_virtio_error(
                self.interrupt_cb.clone(),
                self.driver_features,
                &self.device_broken,
            );
        }

        result
    }

    fn handle_cmd_request(&mut self) -> Result<()> {
        loop {
            let mut queue = self.queue.lock().unwrap();
            let elem = queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)?;
            if elem.desc_num == 0 {
                break;
            }
            drop(queue);

            let mut cmd = VirtioScsiRequest::<VirtioScsiCmdReq, VirtioScsiCmdResp>::new(
                &self.mem_space,
                self.queue.clone(),
                self.interrupt_cb.clone(),
                self.driver_features,
                &elem,
            )?;

            let lun = cmd.req.lun;
            let scsibus = self.scsibus.lock().unwrap();
            let req_lun_id = virtio_scsi_get_lun(lun);

            let scsidevice = if let Some(scsi_device) = scsibus.get_device(lun[1], req_lun_id) {
                scsi_device
            } else {
                // No such target. Response VIRTIO_SCSI_S_BAD_TARGET to guest scsi drivers.
                // It's not an error!
                cmd.resp.response = VIRTIO_SCSI_S_BAD_TARGET;
                cmd.complete(&self.mem_space)?;
                debug!(
                    "no such scsi device target {}, lun {}",
                    lun[1],
                    virtio_scsi_get_lun(lun)
                );
                continue;
            };
            drop(scsibus);

            let cmd_h = Arc::new(Mutex::new(cmd));
            let scsi_req = if let Ok(req) =
                ScsiRequest::new(cmd_h.clone(), self.scsibus.clone(), scsidevice.clone())
            {
                req
            } else {
                // Wrong scsi cdb. Response CHECK_CONDITION / SCSI_SENSE_INVALID_OPCODE to guest scsi drivers.
                let mut cmd_lock = cmd_h.lock().unwrap();
                cmd_lock.resp.set_scsi_sense(SCSI_SENSE_INVALID_OPCODE);
                cmd_lock.resp.status = CHECK_CONDITION;
                cmd_lock.complete(&self.mem_space)?;
                drop(cmd_lock);

                error!("Failed to create scsi request");
                continue;
            };

            let scsi_device_lock = scsidevice.lock().unwrap();
            if scsi_req.opstype == EMULATE_SCSI_OPS {
                let lun = scsi_device_lock.config.lun;
                drop(scsi_device_lock);
                let scsicompletecb = ScsiCompleteCb::new(
                    self.mem_space.clone(),
                    Arc::new(Mutex::new(scsi_req.clone())),
                );
                // If found device's lun id is not equal to request lun id, this request is a target request.
                scsi_req.emulate_execute(scsicompletecb, req_lun_id, lun)?;
            } else {
                let direct = scsi_device_lock.config.direct;
                let disk_img = scsi_device_lock.disk_image.as_ref().unwrap().clone();
                let req_align = scsi_device_lock.req_align;
                let buf_align = scsi_device_lock.buf_align;
                drop(scsi_device_lock);

                let scsicompletecb = ScsiCompleteCb::new(
                    self.mem_space.clone(),
                    Arc::new(Mutex::new(scsi_req.clone())),
                );

                let aiocb = AioCb {
                    direct,
                    req_align,
                    buf_align,
                    file_fd: disk_img.as_raw_fd(),
                    opcode: OpCode::Noop,
                    iovec: Vec::new(),
                    offset: 0,
                    nbytes: 0,
                    user_data: 0,
                    iocompletecb: scsicompletecb,
                };
                scsi_req.execute(aiocb)?;
            }
        }

        Ok(())
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
