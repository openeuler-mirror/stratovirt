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

use super::errors::{ErrorKind, Result, ResultExt};
use super::{
    Queue, VirtioDevice, VirtioInterrupt, VirtioInterruptType, VIRTIO_F_VERSION_1, VIRTIO_TYPE_GPU,
};
use address_space::AddressSpace;
use error_chain::bail;
use log::{error, warn};
use machine_manager::config::{GpuConfig, VIRTIO_GPU_MAX_SCANOUTS};
use machine_manager::event_loop::EventLoop;
use migration::{DeviceStateDesc, FieldDesc};
use migration_derive::{ByteCode, Desc};
use std::cmp;
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::{ptr, vec};
use util::aio::Iovec;
use util::byte_code::ByteCode;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::num_ops::{read_u32, write_u32};
use util::pixman::pixman_image_t;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};
use vnc::{DisplayMouse, DisplaySurface};

/// Number of virtqueues.
const QUEUE_NUM_GPU: usize = 2;
/// Size of each virtqueue.
const QUEUE_SIZE_GPU: u16 = 256;
/// Flags for virtio gpu base conf.
const VIRTIO_GPU_FLAG_VIRGL_ENABLED: u32 = 1;
//const VIRTIO_GPU_FLAG_STATS_ENABLED: u32 = 2;
const VIRTIO_GPU_FLAG_EDID_ENABLED: u32 = 3;

#[derive(Clone, Copy, Debug, ByteCode)]
pub struct VirtioGpuConfig {
    events_read: u32,
    events_clear: u32,
    num_scanouts: u32,
    reserved: u32,
}

#[derive(Clone, Copy, Debug, ByteCode)]
pub struct VirtioGpuBaseConf {
    max_outputs: u32,
    flags: u32,
    xres: u32,
    yres: u32,
}

#[allow(unused)]
#[derive(Debug)]
struct GpuResource {
    resource_id: u32,
    width: u32,
    height: u32,
    format: u32,
    iov: Vec<Iovec>,
    scanouts_bitmask: u32,
    host_mem: u64,
    pixman_image: *mut pixman_image_t,
}
impl Default for GpuResource {
    fn default() -> Self {
        GpuResource {
            resource_id: 0,
            width: 0,
            height: 0,
            format: 0,
            iov: Vec::new(),
            scanouts_bitmask: 0,
            host_mem: 0,
            pixman_image: ptr::null_mut(),
        }
    }
}

#[allow(unused)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuReqState {
    width: u32,
    height: u32,
    x_coor: i32,
    y_coor: i32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuCtrlHdr {
    hdr_type: u32,
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuCursorPos {
    scanout_id: u32,
    x_coord: u32,
    y_coord: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuCursorPos {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuUpdateCursor {
    header: VirtioGpuCtrlHdr,
    pos: VirtioGpuCursorPos,
    resource_id: u32,
    hot_x: u32,
    hot_y: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuUpdateCursor {}

#[allow(unused)]
#[derive(Clone, Default)]
struct GpuScanout {
    surface: Option<DisplaySurface>,
    mouse: Option<DisplayMouse>,
    width: u32,
    height: u32,
    x: u32,
    y: u32,
    invalidate: i32,
    resource_id: u32,
    cursor: VirtioGpuUpdateCursor,
}

#[allow(unused)]
impl GpuScanout {
    fn clear(&mut self) {
        self.resource_id = 0;
        self.surface = None;
        self.width = 0;
        self.height = 0;
    }
}

/// Control block of GPU IO.
#[allow(unused)]
struct GpuIoHandler {
    /// The virtqueue for for sending control commands.
    ctrl_queue: Arc<Mutex<Queue>>,
    /// The virtqueue for sending cursor updates
    cursor_queue: Arc<Mutex<Queue>>,
    /// The address space to which the GPU device belongs.
    mem_space: Arc<AddressSpace>,
    /// Eventfd for contorl virtqueue.
    ctrl_queue_evt: EventFd,
    /// Eventfd for cursor virtqueue.
    cursor_queue_evt: EventFd,
    /// Eventfd for device deactivate.
    deactivate_evt: RawFd,
    /// Callback to trigger an interrupt.
    interrupt_cb: Arc<VirtioInterrupt>,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Vector for resources.
    resources_list: Vec<GpuResource>,
    /// The bit mask of whether scanout is enabled or not.
    enable_output_bitmask: u32,
    /// Baisc Configure of GPU device.
    base_conf: VirtioGpuBaseConf,
    /// States of all request in scanout.
    req_states: [VirtioGpuReqState; VIRTIO_GPU_MAX_SCANOUTS],
    ///
    scanouts: Vec<GpuScanout>,
    /// Max host mem for resource.
    max_hostmem: u64,
    /// Current usage of host mem.
    used_hostmem: u64,
}

impl GpuIoHandler {
    fn ctrl_queue_evt_handler(&mut self) -> Result<()> {
        let mut queue = self.ctrl_queue.lock().unwrap();
        if !queue.is_valid(&self.mem_space) {
            bail!("Failed to handle any request, the queue is not ready");
        }
        while let Ok(elem) = queue.vring.pop_avail(&self.mem_space, self.driver_features) {
            queue
                .vring
                .add_used(&self.mem_space, elem.index, 0)
                .chain_err(|| "Failed to add used ring")?;
        }
        drop(queue);
        (self.interrupt_cb)(
            &VirtioInterruptType::Vring,
            Some(&self.cursor_queue.lock().unwrap()),
        )
        .chain_err(|| ErrorKind::InterruptTrigger("gpu", VirtioInterruptType::Vring))?;

        Ok(())
    }

    fn cursor_queue_evt_handler(&mut self) -> Result<()> {
        let mut queue = self.cursor_queue.lock().unwrap();
        if !queue.is_valid(&self.mem_space) {
            bail!("Failed to handle any request, the queue is not ready");
        }

        while let Ok(elem) = queue.vring.pop_avail(&self.mem_space, self.driver_features) {
            queue
                .vring
                .add_used(&self.mem_space, elem.index, 0)
                .chain_err(|| "Failed to add used ring")?;

            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue))
                .chain_err(|| ErrorKind::InterruptTrigger("gpu", VirtioInterruptType::Vring))?;
        }

        Ok(())
    }

    fn deactivate_evt_handler(&mut self) -> Vec<EventNotifier> {
        let notifiers = vec![
            EventNotifier::new(
                NotifierOperation::Delete,
                self.ctrl_queue_evt.as_raw_fd(),
                None,
                EventSet::IN,
                Vec::new(),
            ),
            EventNotifier::new(
                NotifierOperation::Delete,
                self.cursor_queue_evt.as_raw_fd(),
                None,
                EventSet::IN,
                Vec::new(),
            ),
            EventNotifier::new(
                NotifierOperation::Delete,
                self.deactivate_evt,
                None,
                EventSet::IN,
                Vec::new(),
            ),
        ];
        notifiers
    }
}

impl EventNotifierHelper for GpuIoHandler {
    fn internal_notifiers(gpu_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        // Register event notifier for deactivate_evt.
        let gpu_handler_clone = gpu_handler.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            Some(gpu_handler_clone.lock().unwrap().deactivate_evt_handler())
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            gpu_handler.lock().unwrap().deactivate_evt,
            None,
            EventSet::IN,
            vec![Arc::new(Mutex::new(handler))],
        ));

        // Register event notifier for ctrl_queue_evt.
        let gpu_handler_clone = gpu_handler.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            if let Err(e) = gpu_handler_clone.lock().unwrap().ctrl_queue_evt_handler() {
                error!(
                    "Failed to process queue for virtio gpu, err: {}",
                    error_chain::ChainedError::display_chain(&e),
                );
            }

            None
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            gpu_handler.lock().unwrap().ctrl_queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![Arc::new(Mutex::new(handler))],
        ));

        // Register event notifier for cursor_queue_evt.
        let gpu_handler_clone = gpu_handler.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            if let Err(e) = gpu_handler_clone.lock().unwrap().cursor_queue_evt_handler() {
                error!(
                    "Failed to process queue for virtio gpu, err: {}",
                    error_chain::ChainedError::display_chain(&e),
                );
            }

            None
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            gpu_handler.lock().unwrap().cursor_queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![Arc::new(Mutex::new(handler))],
        ));

        notifiers
    }
}

/// State of gpu device.
#[repr(C)]
#[derive(Clone, Copy, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct GpuState {
    /// Bitmask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Config space of the GPU device.
    config: VirtioGpuConfig,
    /// Baisc Configure of GPU device.
    base_conf: VirtioGpuBaseConf,
}

/// GPU device structure.
pub struct Gpu {
    /// Configuration of the GPU device.
    gpu_conf: GpuConfig,
    /// Status of the GPU device.
    state: GpuState,
    /// Callback to trigger interrupt.
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    /// Eventfd for device deactivate.
    deactivate_evt: EventFd,
}

impl Default for Gpu {
    fn default() -> Self {
        Gpu {
            gpu_conf: GpuConfig::default(),
            state: GpuState::default(),
            interrupt_cb: None,
            deactivate_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }
}

impl Gpu {
    pub fn new(gpu_conf: GpuConfig) -> Gpu {
        let mut state = GpuState::default();
        state.base_conf.xres = gpu_conf.xres;
        state.base_conf.yres = gpu_conf.yres;
        if gpu_conf.edid {
            state.base_conf.flags &= 1 << VIRTIO_GPU_FLAG_EDID_ENABLED;
        }
        state.base_conf.max_outputs = gpu_conf.max_outputs;
        state.device_features = 1u64 << VIRTIO_F_VERSION_1;
        Self {
            gpu_conf,
            state,
            interrupt_cb: None,
            deactivate_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }
}

impl VirtioDevice for Gpu {
    /// Realize virtio gpu device.
    fn realize(&mut self) -> Result<()> {
        if self.gpu_conf.max_outputs > VIRTIO_GPU_MAX_SCANOUTS as u32 {
            bail!(
                "Invalid max_outputs {} which is bigger than {}",
                self.gpu_conf.max_outputs,
                VIRTIO_GPU_MAX_SCANOUTS
            );
        }

        // Virgl is not supported.
        self.state.base_conf.flags &= !(1 << VIRTIO_GPU_FLAG_VIRGL_ENABLED);
        self.state.config.num_scanouts = self.state.base_conf.max_outputs;
        self.state.config.reserved = 0;
        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_GPU
    }

    /// Get the count of virtio gpu queues.
    fn queue_num(&self) -> usize {
        QUEUE_NUM_GPU
    }

    /// Get the queue size of virtio gpu.
    fn queue_size(&self) -> u16 {
        QUEUE_SIZE_GPU
    }

    /// Get device features from host.
    fn get_device_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.device_features, features_select)
    }

    /// Set driver features by guest.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        let mut v = write_u32(value, page);
        let unrequested_features = v & !self.state.device_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request with unknown feature: {:x}", v);
            v &= !unrequested_features;
        }
        self.state.driver_features |= v;
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config_slice = self.state.config.as_bytes();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            return Err(ErrorKind::DevConfigOverflow(offset, config_len).into());
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])?;
        }
        Ok(())
    }

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let config_slice = self.state.config.as_mut_bytes();
        let config_len = config_slice.len();
        if offset as usize + data_len > config_len {
            return Err(ErrorKind::DevConfigOverflow(offset, config_len as u64).into());
        }

        config_slice[(offset as usize)..(offset as usize + data_len)].copy_from_slice(data);

        if self.state.config.events_clear != 0 {
            self.state.config.events_read &= !self.state.config.events_clear;
        }

        Ok(())
    }

    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<Queue>>],
        mut queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        if queues.len() != QUEUE_NUM_GPU {
            return Err(ErrorKind::IncorrectQueueNum(QUEUE_NUM_GPU, queues.len()).into());
        }

        self.interrupt_cb = Some(interrupt_cb.clone());
        let req_states = [VirtioGpuReqState::default(); VIRTIO_GPU_MAX_SCANOUTS];
        let mut scanouts = vec![];
        for _i in 0..VIRTIO_GPU_MAX_SCANOUTS {
            let scanout = GpuScanout::default();
            scanouts.push(scanout);
        }

        let mut gpu_handler = GpuIoHandler {
            ctrl_queue: queues[0].clone(),
            cursor_queue: queues[1].clone(),
            mem_space,
            ctrl_queue_evt: queue_evts.remove(0),
            cursor_queue_evt: queue_evts.remove(0),
            deactivate_evt: self.deactivate_evt.as_raw_fd(),
            interrupt_cb,
            driver_features: self.state.driver_features,
            resources_list: Vec::new(),
            enable_output_bitmask: 1,
            base_conf: self.state.base_conf,
            scanouts,
            req_states,
            max_hostmem: self.gpu_conf.max_hostmem,
            used_hostmem: 0,
        };
        gpu_handler.req_states[0].width = self.state.base_conf.xres;
        gpu_handler.req_states[0].height = self.state.base_conf.yres;

        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(gpu_handler))),
            None,
        )?;

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        self.deactivate_evt
            .write(1)
            .chain_err(|| ErrorKind::EventFdWrite)
    }
}
