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

use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use log::{error, info, warn};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use crate::{
    check_config_space_rw, gpa_hva_iovec_map, iov_discard_front, iov_to_buf, read_config_default,
    report_virtio_error, Element, Queue, VirtioBase, VirtioDevice, VirtioError, VirtioInterrupt,
    VirtioInterruptType, VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_RING_INDIRECT_DESC, VIRTIO_F_VERSION_1,
    VIRTIO_TYPE_SCSI,
};
use address_space::{AddressSpace, GuestAddress};
use block_backend::BlockIoErrorCallback;
use devices::ScsiBus::{
    ScsiBus, ScsiRequest, ScsiRequestOps, ScsiSense, ScsiXferMode, CHECK_CONDITION,
    EMULATE_SCSI_OPS, SCSI_CMD_BUF_SIZE, SCSI_SENSE_INVALID_OPCODE,
};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use machine_manager::{
    config::{ScsiCntlrConfig, VIRTIO_SCSI_MAX_LUN, VIRTIO_SCSI_MAX_TARGET},
    event_loop::EventLoop,
};
use util::aio::Iovec;
use util::byte_code::ByteCode;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};

/// Virtio Scsi Controller has 1 ctrl queue, 1 event queue and at least 1 cmd queue.
const SCSI_CTRL_QUEUE_NUM: usize = 1;
const SCSI_EVENT_QUEUE_NUM: usize = 1;
const SCSI_MIN_QUEUE_NUM: usize = 3;

/// Default values of the cdb and sense data size configuration fields. Cannot change cdb size
/// and sense data size Now.
/// To do: support Override CDB/sense data size.(Guest controlled)
const VIRTIO_SCSI_CDB_DEFAULT_SIZE: usize = 32;
const VIRTIO_SCSI_SENSE_DEFAULT_SIZE: usize = 96;

/// Basic length of fixed format sense data.
const SCSI_SENSE_LEN: u32 = 18;

/// Control type codes.
/// Task Management Function.
const VIRTIO_SCSI_T_TMF: u32 = 0;
/// Asynchronous notification query.
const VIRTIO_SCSI_T_AN_QUERY: u32 = 1;
/// Asynchronous notification subscription.
const VIRTIO_SCSI_T_AN_SUBSCRIBE: u32 = 2;

/// Valid TMF Subtypes.
pub const VIRTIO_SCSI_T_TMF_ABORT_TASK: u32 = 0;
pub const VIRTIO_SCSI_T_TMF_ABORT_TASK_SET: u32 = 1;
pub const VIRTIO_SCSI_T_TMF_CLEAR_ACA: u32 = 2;
pub const VIRTIO_SCSI_T_TMF_CLEAR_TASK_SET: u32 = 3;
pub const VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET: u32 = 4;
pub const VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET: u32 = 5;
pub const VIRTIO_SCSI_T_TMF_QUERY_TASK: u32 = 6;
pub const VIRTIO_SCSI_T_TMF_QUERY_TASK_SET: u32 = 7;

/// Command-specific response values.
/// The request was completed and the status byte if filled with a SCSI status code.
const VIRTIO_SCSI_S_OK: u8 = 0;
/// If the content of the CDB(such as the allocation length, parameter length or transfer size)
/// requires more data than is available in the datain and dataout buffers.
const VIRTIO_SCSI_S_OVERRUN: u8 = 1;
/// The request was never processed because the target indicated by lun does not exist.
const VIRTIO_SCSI_S_BAD_TARGET: u8 = 3;
/// Other host or driver error. In particular, if neither dataout nor datain is empty, and the
/// VIRTIO_SCSI_F_INOUT feature has not been negotiated, the request will be immediately returned
/// with a response equal to VIRTIO_SCSI_S_FAILURE.
const VIRTIO_SCSI_S_FAILURE: u8 = 9;

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

/// Virtio Scsi Controller device structure.
#[derive(Default)]
pub struct ScsiCntlr {
    /// Virtio device base property.
    base: VirtioBase,
    /// Configuration of the virtio scsi controller.
    pub config: ScsiCntlrConfig,
    /// Config space of the virtio scsi controller.
    config_space: VirtioScsiConfig,
    /// Scsi bus.
    pub bus: Option<Arc<Mutex<ScsiBus>>>,
}

impl ScsiCntlr {
    pub fn new(config: ScsiCntlrConfig) -> ScsiCntlr {
        // Note: config.queues <= MAX_VIRTIO_QUEUE(32).
        let queue_num = config.queues as usize + SCSI_CTRL_QUEUE_NUM + SCSI_EVENT_QUEUE_NUM;
        let queue_size = config.queue_size;

        Self {
            base: VirtioBase::new(VIRTIO_TYPE_SCSI, queue_num, queue_size),
            config,
            ..Default::default()
        }
    }

    fn gen_error_cb(&self, interrupt_cb: Arc<VirtioInterrupt>) -> BlockIoErrorCallback {
        let cloned_features = self.base.driver_features;
        let clone_broken = self.base.broken.clone();
        Arc::new(move || {
            report_virtio_error(interrupt_cb.clone(), cloned_features, &clone_broken);
        })
    }
}

impl VirtioDevice for ScsiCntlr {
    fn virtio_base(&self) -> &VirtioBase {
        &self.base
    }

    fn virtio_base_mut(&mut self) -> &mut VirtioBase {
        &mut self.base
    }

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
        self.init_config_features()?;
        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        self.config_space.num_queues = self.config.queues;
        self.config_space.max_sectors = 0xFFFF_u32;
        // cmd_per_lun: maximum number of linked commands can be sent to one LUN. 32bit.
        self.config_space.cmd_per_lun = 128;
        // seg_max: queue size - 2, 32 bit.
        self.config_space.seg_max = self.queue_size_max() as u32 - 2;
        self.config_space.max_target = VIRTIO_SCSI_MAX_TARGET;
        self.config_space.max_lun = VIRTIO_SCSI_MAX_LUN as u32;
        // num_queues: request queues number.
        self.config_space.num_queues = self.config.queues;

        self.base.device_features |= (1_u64 << VIRTIO_F_VERSION_1)
            | (1_u64 << VIRTIO_F_RING_EVENT_IDX)
            | (1_u64 << VIRTIO_F_RING_INDIRECT_DESC);

        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        read_config_default(self.config_space.as_bytes(), offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        check_config_space_rw(self.config_space.as_bytes(), offset, data)?;
        // Guest can only set sense_size and cdb_size, which are fixed default values
        // (VIRTIO_SCSI_CDB_DEFAULT_SIZE; VIRTIO_SCSI_SENSE_DEFAULT_SIZE) and cannot be
        // changed in stratovirt now. So, do nothing when guest writes config.
        Ok(())
    }

    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let queues = self.base.queues.clone();
        if queues.len() < SCSI_MIN_QUEUE_NUM {
            bail!("virtio scsi controller queues num can not be less than 3!");
        }

        // Register event notifier for ctrl queue.
        let ctrl_queue = queues[0].clone();
        let ctrl_queue_evt = queue_evts[0].clone();
        let ctrl_handler = ScsiCtrlQueueHandler {
            queue: ctrl_queue,
            queue_evt: ctrl_queue_evt,
            mem_space: mem_space.clone(),
            interrupt_cb: interrupt_cb.clone(),
            driver_features: self.base.driver_features,
            device_broken: self.base.broken.clone(),
        };
        let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(ctrl_handler)));
        register_event_helper(
            notifiers,
            self.config.iothread.as_ref(),
            &mut self.base.deactivate_evts,
        )?;

        // Register event notifier for event queue.
        let event_queue = queues[1].clone();
        let event_queue_evt = queue_evts[1].clone();
        let event_handler = ScsiEventQueueHandler {
            _queue: event_queue,
            queue_evt: event_queue_evt,
            _mem_space: mem_space.clone(),
            _interrupt_cb: interrupt_cb.clone(),
            _driver_features: self.base.driver_features,
            device_broken: self.base.broken.clone(),
        };
        let notifiers =
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(event_handler)));
        register_event_helper(
            notifiers,
            self.config.iothread.as_ref(),
            &mut self.base.deactivate_evts,
        )?;

        // Register event notifier for command queues.
        for (index, cmd_queue) in queues[2..].iter().enumerate() {
            let bus = self.bus.as_ref().unwrap();
            let cmd_handler = ScsiCmdQueueHandler {
                scsibus: bus.clone(),
                queue: cmd_queue.clone(),
                queue_evt: queue_evts[index + 2].clone(),
                mem_space: mem_space.clone(),
                interrupt_cb: interrupt_cb.clone(),
                driver_features: self.base.driver_features,
                device_broken: self.base.broken.clone(),
            };

            let notifiers =
                EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(cmd_handler)));

            register_event_helper(
                notifiers,
                self.config.iothread.as_ref(),
                &mut self.base.deactivate_evts,
            )?;
        }
        self.base.broken.store(false, Ordering::SeqCst);

        // Register event notifier for device aio.
        let bus = self.bus.as_ref().unwrap();
        let locked_bus = bus.lock().unwrap();
        for device in locked_bus.devices.values() {
            let locked_device = device.lock().unwrap();
            let err_cb = self.gen_error_cb(interrupt_cb.clone());
            // SAFETY: the disk_image is assigned after device realized.
            let disk_image = locked_device.block_backend.as_ref().unwrap();
            let mut locked_backend = disk_image.lock().unwrap();
            locked_backend.register_io_event(self.base.broken.clone(), err_cb)?;
        }
        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        unregister_event_helper(
            self.config.iothread.as_ref(),
            &mut self.base.deactivate_evts,
        )?;
        let bus = self.bus.as_ref().unwrap();
        let locked_bus = bus.lock().unwrap();
        for device in locked_bus.devices.values() {
            let locked_dev = device.lock().unwrap();
            // SAFETY: the disk_image is assigned after device realized.
            let disk_image = locked_dev.block_backend.as_ref().unwrap();
            let mut locked_backend = disk_image.lock().unwrap();
            locked_backend.unregister_io_event()?;
        }
        Ok(())
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
#[allow(unused)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioScsiCtrlTmfReq {
    ctrltype: u32,
    subtype: u32,
    lun: [u8; 8],
    tag: u64,
}

impl ByteCode for VirtioScsiCtrlTmfReq {}

#[allow(unused)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioScsiCtrlTmfResp {
    response: u8,
}

impl ByteCode for VirtioScsiCtrlTmfResp {}

/// Asynchronous notification query/subscription.
#[allow(unused)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioScsiCtrlAnReq {
    ctrltype: u32,
    lun: [u8; 8],
    event_requested: u32,
}

impl ByteCode for VirtioScsiCtrlAnReq {}

#[allow(unused)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioScsiCtrlAnResp {
    event_actual: u32,
    response: u8,
}

impl ByteCode for VirtioScsiCtrlAnResp {}

#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
struct VirtioScsiCmdReq {
    /// Logical Unit Number.
    lun: [u8; 8],
    /// Command identifier.
    tag: u64,
    /// Task attribute.
    task_attr: u8,
    /// SAM command priority field.
    prio: u8,
    crn: u8,
    cdb: [u8; VIRTIO_SCSI_CDB_DEFAULT_SIZE],
}

impl ByteCode for VirtioScsiCmdReq {}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioScsiCmdResp {
    /// Sense data length.
    sense_len: u32,
    /// Resudual bytes in data buffer.
    resid: u32,
    /// Status qualifier.
    status_qualifier: u16,
    /// Command completion status.
    status: u8,
    /// Response value.
    response: u8,
    /// Sense buffer data.
    sense: [u8; VIRTIO_SCSI_SENSE_DEFAULT_SIZE],
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
    fn set_scsi_sense(&mut self, sense: ScsiSense) {
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
#[derive(Clone)]
struct VirtioScsiRequest<T: Clone + ByteCode, U: Clone + ByteCode> {
    mem_space: Arc<AddressSpace>,
    queue: Arc<Mutex<Queue>>,
    desc_index: u16,
    /// Read or Write data, HVA, except resp.
    iovec: Vec<Iovec>,
    data_len: u32,
    mode: ScsiXferMode,
    interrupt_cb: Arc<VirtioInterrupt>,
    driver_features: u64,
    /// resp GPA.
    resp_addr: GuestAddress,
    req: T,
    resp: U,
}

// Requests in Command Queue.
type CmdQueueRequest = VirtioScsiRequest<VirtioScsiCmdReq, VirtioScsiCmdResp>;
// TMF Requests in Ctrl Queue.
type CtrlQueueTmfRequest = VirtioScsiRequest<VirtioScsiCtrlTmfReq, VirtioScsiCtrlTmfResp>;
// An Requests in Command Queue.
type CtrlQueueAnRequest = VirtioScsiRequest<VirtioScsiCtrlAnReq, VirtioScsiCtrlAnResp>;

/// T: request; U:response.
impl<T: Clone + ByteCode + Default, U: Clone + ByteCode + Default> VirtioScsiRequest<T, U> {
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

        // Get request from virtqueue Element.
        let mut req = T::default();
        iov_to_buf(mem_space, &elem.out_iovec, req.as_mut_bytes()).and_then(|size| {
            if size < size_of::<T>() {
                bail!(
                    "Invalid length for request: get {}, expected {}",
                    size,
                    size_of::<T>(),
                );
            }
            Ok(())
        })?;

        // Get response from virtqueue Element.
        let mut resp = U::default();
        iov_to_buf(mem_space, &elem.in_iovec, resp.as_mut_bytes()).and_then(|size| {
            if size < size_of::<U>() {
                bail!(
                    "Invalid length for response: get {}, expected {}",
                    size,
                    size_of::<U>(),
                );
            }
            Ok(())
        })?;

        let mut request = VirtioScsiRequest {
            mem_space: mem_space.clone(),
            queue,
            desc_index: elem.index,
            iovec: Vec::with_capacity(elem.desc_num as usize),
            data_len: 0,
            mode: ScsiXferMode::ScsiXferNone,
            interrupt_cb,
            driver_features,
            // Safety: in_iovec will not be empty since it has been checked after "iov_to_buf".
            resp_addr: elem.in_iovec[0].addr,
            req,
            resp,
        };

        // Get possible dataout buffer from virtqueue Element.
        let mut iovec = elem.out_iovec.clone();
        let elemiov = iov_discard_front(&mut iovec, size_of::<T>() as u64).unwrap_or_default();
        let (out_len, out_iovec) = gpa_hva_iovec_map(elemiov, mem_space)?;

        // Get possible dataout buffer from virtqueue Element.
        let mut iovec = elem.in_iovec.clone();
        let elemiov = iov_discard_front(&mut iovec, size_of::<U>() as u64).unwrap_or_default();
        let (in_len, in_iovec) = gpa_hva_iovec_map(elemiov, mem_space)?;

        if out_len > 0 && in_len > 0 {
            warn!("Wrong scsi request! Don't support both datain and dataout buffer");
            request.data_len = u32::MAX;
            return Ok(request);
        }

        if out_len > 0 {
            request.mode = ScsiXferMode::ScsiXferToDev;
            request.data_len = out_len as u32;
            request.iovec = out_iovec;
        } else if in_len > 0 {
            request.mode = ScsiXferMode::ScsiXferFromDev;
            request.data_len = in_len as u32;
            request.iovec = in_iovec;
        }

        Ok(request)
    }

    fn complete(&self) -> Result<()> {
        self.mem_space
            .write_object(&self.resp, self.resp_addr)
            .with_context(|| "Failed to write the scsi response")?;

        let mut queue_lock = self.queue.lock().unwrap();
        // Note: U(response) is the header part of in_iov and self.data_len is the rest part of the
        // in_iov or the out_iov. in_iov and out_iov total len is no more than
        // DESC_CHAIN_MAX_TOTAL_LEN(1 << 32). So, it will not overflow here.
        queue_lock
            .vring
            .add_used(
                &self.mem_space,
                self.desc_index,
                self.data_len + (size_of::<U>() as u32),
            )
            .with_context(|| {
                format!(
                    "Failed to add used ring(scsi completion), index {}, len {}",
                    self.desc_index, self.data_len
                )
            })?;

        if queue_lock
            .vring
            .should_notify(&self.mem_space, self.driver_features)
        {
            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue_lock), false)
                .with_context(|| {
                    VirtioError::InterruptTrigger(
                        "scsi controller aio completion",
                        VirtioInterruptType::Vring,
                    )
                })?;
            trace::virtqueue_send_interrupt("ScsiCntlr", &*queue_lock as *const _ as u64);
        }

        Ok(())
    }
}

struct ScsiCtrlQueueHandler {
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

impl ScsiCtrlQueueHandler {
    fn handle_ctrl(&mut self) -> Result<()> {
        trace::virtio_receive_request("ScsiCntlr".to_string(), "to ctrl".to_string());
        let result = self.handle_ctrl_queue_requests();
        if result.is_err() {
            report_virtio_error(
                self.interrupt_cb.clone(),
                self.driver_features,
                &self.device_broken,
            );
        }

        result
    }

    fn handle_ctrl_queue_requests(&mut self) -> Result<()> {
        loop {
            let mut queue = self.queue.lock().unwrap();
            let elem = queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)?;
            drop(queue);
            if elem.desc_num == 0 {
                break;
            }

            let ctrl_desc = elem
                .out_iovec
                .get(0)
                .with_context(|| "Error request in ctrl queue. Empty dataout buf!")?;
            let ctrl_type = self
                .mem_space
                .read_object::<u32>(ctrl_desc.addr)
                .with_context(|| "Failed to get control queue descriptor")?;

            match ctrl_type {
                VIRTIO_SCSI_T_TMF => {
                    let mut tmf = CtrlQueueTmfRequest::new(
                        &self.mem_space,
                        self.queue.clone(),
                        self.interrupt_cb.clone(),
                        self.driver_features,
                        &elem,
                    )?;
                    info!("incomplete tmf req, subtype {}!", tmf.req.subtype);
                    // Scsi Task Management Function is not supported.
                    // So, do nothing when stratovirt receives TMF request except responding guest
                    // scsi drivers.
                    tmf.resp.response = VIRTIO_SCSI_S_OK;
                    tmf.complete()?;
                }
                VIRTIO_SCSI_T_AN_QUERY | VIRTIO_SCSI_T_AN_SUBSCRIBE => {
                    let mut an = CtrlQueueAnRequest::new(
                        &self.mem_space,
                        self.queue.clone(),
                        self.interrupt_cb.clone(),
                        self.driver_features,
                        &elem,
                    )?;
                    an.resp.event_actual = 0;
                    an.resp.response = VIRTIO_SCSI_S_OK;
                    an.complete()?;
                }
                _ => {
                    bail!("Invalid ctrl type {}", ctrl_type);
                }
            }
        }

        Ok(())
    }
}

impl EventNotifierHelper for ScsiCtrlQueueHandler {
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

struct ScsiEventQueueHandler {
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

impl EventNotifierHelper for ScsiEventQueueHandler {
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

impl ScsiEventQueueHandler {
    fn handle_event(&mut self) -> Result<()> {
        Ok(())
    }
}

impl ScsiRequestOps for CmdQueueRequest {
    fn scsi_request_complete_cb(&mut self, status: u8, scsisense: Option<ScsiSense>) -> Result<()> {
        if let Some(sense) = scsisense {
            self.resp.set_scsi_sense(sense);
        }
        self.resp.response = VIRTIO_SCSI_S_OK;
        self.resp.status = status;
        trace::virtio_scsi_handle_cmd_resp(
            self.req.lun[1],
            virtio_scsi_get_lun_id(self.req.lun),
            self.req.tag,
            self.resp.status,
            self.resp.response,
        );
        self.complete()?;

        Ok(())
    }
}

//   lun: [u8, 8]
//   | Byte 0 | Byte 1 | Byte 2 | Byte 3 | Byte 4 | Byte 5 | Byte 6 | Byte 7 |
//   |    1   | target |       lun       |                 0                 |
fn virtio_scsi_get_lun_id(lun: [u8; 8]) -> u16 {
    (((lun[2] as u16) << 8) | (lun[3] as u16)) & 0x3FFF
}

struct ScsiCmdQueueHandler {
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

impl EventNotifierHelper for ScsiCmdQueueHandler {
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

        notifiers
    }
}

impl ScsiCmdQueueHandler {
    fn handle_cmd(&mut self) -> Result<()> {
        trace::virtio_receive_request("ScsiCntlr".to_string(), "to cmd".to_string());
        let result = self.handle_cmd_queue_requests();
        if result.is_err() {
            report_virtio_error(
                self.interrupt_cb.clone(),
                self.driver_features,
                &self.device_broken,
            );
        }

        result
    }

    fn handle_cmd_queue_requests(&mut self) -> Result<()> {
        let mut sreq_queue = Vec::new();

        loop {
            let mut queue = self.queue.lock().unwrap();
            let elem = queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)?;
            if elem.desc_num == 0 {
                break;
            }
            drop(queue);

            let mut cmdq_request = CmdQueueRequest::new(
                &self.mem_space,
                self.queue.clone(),
                self.interrupt_cb.clone(),
                self.driver_features,
                &elem,
            )?;
            trace::virtio_scsi_handle_cmd_req(
                cmdq_request.req.lun[1],
                virtio_scsi_get_lun_id(cmdq_request.req.lun),
                cmdq_request.req.tag,
                cmdq_request.req.cdb[0],
            );
            let mut need_handle = false;
            self.check_cmd_queue_request(&mut cmdq_request, &mut need_handle)?;
            if !need_handle {
                continue;
            }

            self.enqueue_scsi_request(&mut cmdq_request, &mut sreq_queue)?;
        }

        if sreq_queue.is_empty() {
            return Ok(());
        }

        for sreq in sreq_queue.into_iter() {
            self.handle_scsi_request(sreq)?;
        }

        Ok(())
    }

    fn check_cmd_queue_request(
        &mut self,
        qrequest: &mut CmdQueueRequest,
        need_handle: &mut bool,
    ) -> Result<()> {
        if qrequest.data_len == u32::MAX && qrequest.mode == ScsiXferMode::ScsiXferNone {
            // If neither dataout nor datain is empty, return VIRTIO_SCSI_S_FAILURE immediately.
            qrequest.resp.response = VIRTIO_SCSI_S_FAILURE;
            qrequest.complete()?;
            trace::virtio_scsi_handle_cmd_resp(
                qrequest.req.lun[1],
                virtio_scsi_get_lun_id(qrequest.req.lun),
                qrequest.req.tag,
                qrequest.resp.status,
                qrequest.resp.response,
            );
            return Ok(());
        }

        let target_id = qrequest.req.lun[1];
        let lun_id = virtio_scsi_get_lun_id(qrequest.req.lun);
        let bus = self.scsibus.lock().unwrap();
        let device = bus.get_device(target_id, lun_id);
        if device.is_none() {
            // No such target. Response VIRTIO_SCSI_S_BAD_TARGET to guest scsi drivers.
            // It's not an error!
            qrequest.resp.response = VIRTIO_SCSI_S_BAD_TARGET;
            qrequest.complete()?;
            trace::virtio_scsi_handle_cmd_resp(
                qrequest.req.lun[1],
                virtio_scsi_get_lun_id(qrequest.req.lun),
                qrequest.req.tag,
                qrequest.resp.status,
                qrequest.resp.response,
            );
            return Ok(());
        }

        *need_handle = true;
        Ok(())
    }

    fn enqueue_scsi_request(
        &mut self,
        qrequest: &mut CmdQueueRequest,
        sreq_queue: &mut Vec<ScsiRequest>,
    ) -> Result<()> {
        let cdb: [u8; SCSI_CMD_BUF_SIZE] =
            qrequest.req.cdb[0..SCSI_CMD_BUF_SIZE].try_into().unwrap();

        let lun_id = virtio_scsi_get_lun_id(qrequest.req.lun);
        let bus = self.scsibus.lock().unwrap();
        // Device will not be None because check_virtio_scsi_request has checked it.
        let device = bus.get_device(qrequest.req.lun[1], lun_id).unwrap();

        let scsi_req = ScsiRequest::new(
            cdb,
            lun_id,
            qrequest.iovec.clone(),
            qrequest.data_len,
            device,
            Box::new(qrequest.clone()),
        );
        if scsi_req.is_err() {
            // Wrong scsi cdb. Response CHECK_CONDITION / SCSI_SENSE_INVALID_OPCODE to guest scsi
            // drivers.
            qrequest.resp.set_scsi_sense(SCSI_SENSE_INVALID_OPCODE);
            qrequest.resp.status = CHECK_CONDITION;
            qrequest.complete()?;
            error!("Failed to create scsi request, error virtio scsi request!");
            return Ok(());
        }

        let sreq = scsi_req.unwrap();
        if sreq.cmd.xfer > sreq.datalen && sreq.cmd.mode != ScsiXferMode::ScsiXferNone {
            // Wrong virtio scsi request which doesn't provide enough datain/dataout buffer.
            qrequest.resp.response = VIRTIO_SCSI_S_OVERRUN;
            qrequest.complete()?;
            trace::virtio_scsi_handle_cmd_resp(
                qrequest.req.lun[1],
                virtio_scsi_get_lun_id(qrequest.req.lun),
                qrequest.req.tag,
                qrequest.resp.status,
                qrequest.resp.response,
            );
            return Ok(());
        }

        sreq_queue.push(sreq);
        Ok(())
    }

    fn handle_scsi_request(&mut self, sreq: ScsiRequest) -> Result<()> {
        if sreq.opstype == EMULATE_SCSI_OPS {
            sreq.emulate_execute()?;
        } else {
            sreq.execute()?;
        }

        Ok(())
    }
}

pub fn scsi_cntlr_create_scsi_bus(
    bus_name: &str,
    scsi_cntlr: &Arc<Mutex<ScsiCntlr>>,
) -> Result<()> {
    let mut locked_scsi_cntlr = scsi_cntlr.lock().unwrap();
    let bus = ScsiBus::new(bus_name.to_string());
    locked_scsi_cntlr.bus = Some(Arc::new(Mutex::new(bus)));
    Ok(())
}
