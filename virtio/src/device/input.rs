// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::prelude::OpenOptionsExt;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Parser};
use libc::c_int;
use log::{error, warn};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use crate::{
    check_config_space_rw, error::*, iov_read_object, read_config_default, report_virtio_error,
    Queue, VirtioBase, VirtioDevice, VirtioInterrupt, VirtioInterruptType, VIRTIO_F_VERSION_1,
    VIRTIO_TYPE_INPUT,
};
use address_space::AddressSpace;
use machine_manager::{
    config::{get_pci_df, parse_bool, valid_id, DEFAULT_VIRTQUEUE_SIZE},
    event_loop::{register_event_helper, unregister_event_helper},
};
use util::byte_code::ByteCode;
use util::evdev::*;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};

/// Unset select cfg.
const VIRTIO_INPUT_CFG_UNSET: u8 = 0x00;
/// Returns the name of the device
const VIRTIO_INPUT_CFG_ID_NAME: u8 = 0x01;
/// Returns the serial number of the device.
const VIRTIO_INPUT_CFG_ID_SERIAL: u8 = 0x02;
/// Returns ID information of the device.
const VIRTIO_INPUT_CFG_ID_DEVIDS: u8 = 0x03;
/// Returns input properties of the device.
const VIRTIO_INPUT_CFG_PROP_BITS: u8 = 0x10;
/// subsel specifies the event type using EV_* constants in the underlying evdev implementation.
const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;
/// subsel specifies the absolute axis using ABS_* constants in the underlying evdev implementation.
const VIRTIO_INPUT_CFG_ABS_INFO: u8 = 0x12;

/// Number of virtqueues.
const QUEUE_NUM_INPUT: usize = 2;

#[derive(Parser, Debug, Clone, Default)]
#[command(no_binary_name(true))]
pub struct InputConfig {
    #[arg(long, value_parser = ["virtio-input-device", "virtio-input-pci"])]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub bus: Option<String>,
    #[arg(long, value_parser=get_pci_df)]
    pub addr: Option<(u8, u8)>,
    #[arg(long, value_parser=parse_bool, action = ArgAction::Append)]
    pub multifunction: Option<bool>,
    #[arg(long)]
    pub evdev: String,
}

#[derive(Copy, Clone, Default)]
#[repr(C)]
struct virtio_input_device_ids {
    bustype: [u8; size_of::<u16>()],
    vendor: [u8; size_of::<u16>()],
    product: [u8; size_of::<u16>()],
    version: [u8; size_of::<u16>()],
}

impl virtio_input_device_ids {
    fn from_evdevid(evdev_id: EvdevId) -> Self {
        Self {
            bustype: evdev_id.bustype.to_le_bytes(),
            vendor: evdev_id.vendor.to_le_bytes(),
            product: evdev_id.product.to_le_bytes(),
            version: evdev_id.version.to_le_bytes(),
        }
    }
}

impl ByteCode for virtio_input_device_ids {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
struct VirtioInputAbsInfo {
    min: [u8; size_of::<u32>()],
    max: [u8; size_of::<u32>()],
    fuzz: [u8; size_of::<u32>()],
    flat: [u8; size_of::<u32>()],
}

impl VirtioInputAbsInfo {
    fn from_absinfo(absinfo: InputAbsInfo) -> Self {
        Self {
            min: absinfo.minimum.to_le_bytes(),
            max: absinfo.maximum.to_le_bytes(),
            fuzz: absinfo.fuzz.to_le_bytes(),
            flat: absinfo.flat.to_le_bytes(),
        }
    }
}

impl ByteCode for VirtioInputAbsInfo {}

#[repr(C)]
#[derive(Copy, Clone)]
struct VirtioInputConfig {
    select: u8,
    subsel: u8,
    size: u8,
    reserved: [u8; 5],
    payload: [u8; VIRTIO_INPUT_CFG_PAYLOAD_SIZE],
}

impl VirtioInputConfig {
    fn new() -> Self {
        Self {
            select: VIRTIO_INPUT_CFG_UNSET,
            subsel: 0,
            size: 0,
            reserved: [0_u8; 5],
            payload: [0_u8; VIRTIO_INPUT_CFG_PAYLOAD_SIZE],
        }
    }

    fn set_payload(&mut self, payload: &[u8]) {
        let len = (&mut self.payload[..]).write(payload).unwrap();
        self.size = len as u8;
    }
}

impl Default for VirtioInputConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ByteCode for VirtioInputConfig {}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct VirtioInputEvent {
    ev_type: [u8; size_of::<u16>()],
    code: [u8; size_of::<u16>()],
    value: [u8; size_of::<u32>()],
}

impl VirtioInputEvent {
    fn to_evt(self) -> InputEvent {
        use byteorder::{ByteOrder, LittleEndian};
        InputEvent {
            timestamp: [0_u64, 2],
            ev_type: LittleEndian::read_u16(&self.ev_type),
            code: LittleEndian::read_u16(&self.code),
            value: LittleEndian::read_i32(&self.value),
        }
    }

    fn from_evt(evt: &InputEvent) -> Self {
        Self {
            ev_type: evt.ev_type.to_le_bytes(),
            code: evt.code.to_le_bytes(),
            value: evt.value.to_le_bytes(),
        }
    }
}

impl ByteCode for VirtioInputEvent {}

struct EvdevConfig {
    /// config select
    select: u8,
    /// config sub select
    subsel: u8,
    /// ID information of the device
    device_ids: virtio_input_device_ids,
    /// Name of the device
    name: Vec<u8>,
    /// Serial of the device
    serial: Vec<u8>,
    /// Properties of the device
    properties: EvdevBuf,
    /// Events supported of the device
    event_supported: BTreeMap<u8, EvdevBuf>,
    /// Axis information of the device
    abs_info: BTreeMap<u8, InputAbsInfo>,
}

impl EvdevConfig {
    fn new(fd: &File) -> Result<Self> {
        if evdev_ioctl(fd, EVIOCGVERSION(), size_of::<c_int>()).len == 0 {
            bail!("It's not an evdev device");
        }

        let id = EvdevId::from_buf(evdev_ioctl(fd, EVIOCGID(), size_of::<EvdevId>()));
        Ok(Self {
            select: VIRTIO_INPUT_CFG_UNSET,
            subsel: 0,
            device_ids: virtio_input_device_ids::from_evdevid(id),
            name: evdev_ioctl(fd, EVIOCGNAME(), 0).to_vec(),
            serial: evdev_ioctl(fd, EVIOCGUNIQ(), 0).to_vec(),
            properties: evdev_ioctl(fd, EVIOCGPROP(), 0),
            event_supported: evdev_evt_supported(fd)?,
            abs_info: evdev_abs(fd)?,
        })
    }

    fn get_device_config(&self) -> VirtioInputConfig {
        let mut cfg = VirtioInputConfig {
            select: self.select,
            subsel: self.subsel,
            ..Default::default()
        };

        match self.select {
            VIRTIO_INPUT_CFG_ID_NAME => {
                cfg.set_payload(self.name.as_slice());
            }
            VIRTIO_INPUT_CFG_ID_SERIAL => {
                cfg.set_payload(self.serial.as_slice());
            }
            VIRTIO_INPUT_CFG_ID_DEVIDS => {
                cfg.set_payload(self.device_ids.as_bytes());
            }
            VIRTIO_INPUT_CFG_PROP_BITS => {
                cfg.set_payload(self.properties.to_vec().as_slice());
            }
            VIRTIO_INPUT_CFG_EV_BITS => {
                if let Some(bitmap) = self.event_supported.get(&self.subsel) {
                    cfg.set_payload(bitmap.as_bytes());
                }
            }
            VIRTIO_INPUT_CFG_ABS_INFO => {
                if let Some(absinfo) = self.abs_info.get(&self.subsel) {
                    cfg.set_payload(VirtioInputAbsInfo::from_absinfo(*absinfo).as_bytes());
                }
            }
            VIRTIO_INPUT_CFG_UNSET => {}
            _ => {
                log::warn!("select type {} is not supported", self.select);
            }
        }
        cfg
    }
}

struct InputIoHandler {
    /// The features of driver
    driver_features: u64,
    /// Address space
    mem_space: Arc<AddressSpace>,
    /// event queue.
    event_queue: Arc<Mutex<Queue>>,
    /// event queue EventFd
    event_queue_evt: Arc<EventFd>,
    /// status queue
    status_queue: Arc<Mutex<Queue>>,
    /// status queue EventFd
    status_queue_evt: Arc<EventFd>,
    /// Used to cache events
    event_buf: Vec<VirtioInputEvent>,
    /// Device is broken or not
    device_broken: Arc<AtomicBool>,
    /// The interrupt call back function.
    interrupt_cb: Arc<VirtioInterrupt>,
    /// fd of the evdev file
    evdev_fd: Option<Arc<File>>,
}

impl InputIoHandler {
    fn process_status_queue(&mut self) -> Result<()> {
        let mut locked_status_queue = self.status_queue.lock().unwrap();
        loop {
            let elem = locked_status_queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
                .with_context(|| "Failed to pop avail ring for process input status queue")?;
            if elem.desc_num == 0 {
                break;
            }
            let evt = iov_read_object::<VirtioInputEvent>(
                &self.mem_space,
                &elem.out_iovec,
                locked_status_queue.vring.get_cache(),
            )?
            .to_evt();
            match &self.evdev_fd.clone() {
                Some(evdev_fd) => {
                    let _ = evdev_fd.as_ref().write(evt.as_bytes());
                }
                None => {}
            }
            locked_status_queue
                .vring
                .add_used(elem.index, 0)
                .with_context(|| {
                    format!(
                        "Failed to add input response into used status queue, index {}, len {}",
                        elem.index, 0
                    )
                })?;
            (self.interrupt_cb)(
                &VirtioInterruptType::Vring,
                Some(&locked_status_queue),
                false,
            )
            .with_context(|| VirtioError::InterruptTrigger("Input", VirtioInterruptType::Vring))?;
        }
        Ok(())
    }

    fn input_event_send(&mut self, evt: &InputEvent) -> Result<()> {
        let mut locked_event_queue = self.event_queue.lock().unwrap();
        self.event_buf.push(VirtioInputEvent::from_evt(evt));
        if evt.ev_type != EV_SYN || evt.code != SYN_REPORT {
            return Ok(());
        }
        let mut event_index_list = Vec::new();
        for event in self.event_buf.iter() {
            let elem = locked_event_queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
                .with_context(|| "Failed to pop avail ring for process input queue")?;
            if elem.desc_num == 0 {
                warn!("event queue buffer is full, drop current events");
                for _ in event_index_list.iter() {
                    locked_event_queue.vring.push_back();
                }
                self.event_buf.clear();
                return Ok(());
            }
            self.mem_space.write_object(
                event,
                elem.in_iovec[0].addr,
                address_space::AddressAttr::Ram,
            )?;
            event_index_list.push(elem.index);
        }
        for index in event_index_list.iter() {
            locked_event_queue
                .vring
                .add_used(*index, size_of::<VirtioInputEvent>() as u32)
                .with_context(|| "Failed to add input response into used queue")?;
        }
        (self.interrupt_cb)(
            &VirtioInterruptType::Vring,
            Some(&locked_event_queue),
            false,
        )
        .with_context(|| VirtioError::InterruptTrigger("input", VirtioInterruptType::Vring))?;
        self.event_buf.clear();
        Ok(())
    }

    fn do_event(&mut self) {
        let event_fd = &self.evdev_fd.clone().unwrap();
        loop {
            let mut evt = InputEvent::default();
            match event_fd.as_ref().read(evt.as_mut_bytes()) {
                Ok(sz) => {
                    if sz != size_of::<InputEvent>() {
                        warn!("mismatch InputEvent length");
                        return;
                    }
                    if let Err(e) = self.input_event_send(&evt) {
                        error!("Failed to send event: {:?}", e);
                        report_virtio_error(
                            self.interrupt_cb.clone(),
                            self.driver_features,
                            &self.device_broken,
                        );
                        return;
                    }
                }
                Err(e) => {
                    error!("Failed to read event from evdev_fd: {:?}", e);
                    return;
                }
            }
        }
    }
}

/// Create a new EventNotifier.
///
/// # Arguments
///
/// * `fd` - Raw file descriptor.
/// * `handler` - Handle function.
fn build_event_notifier(fd: RawFd, handler: Rc<NotifierCallback>) -> EventNotifier {
    EventNotifier::new(
        NotifierOperation::AddShared,
        fd,
        None,
        EventSet::IN,
        vec![handler],
    )
}

impl EventNotifierHelper for InputIoHandler {
    fn internal_notifiers(input: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();
        let locked_input = input.lock().unwrap();
        // register event notifier for event queue.
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            // Do nothing.
            None
        });
        notifiers.push(build_event_notifier(
            locked_input.event_queue_evt.as_raw_fd(),
            handler,
        ));
        // register event notifier for status queue.
        let local_input = input.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let mut locked_local_input = local_input.lock().unwrap();
            if locked_local_input.device_broken.load(Ordering::SeqCst) {
                return None;
            }
            if locked_local_input.process_status_queue().is_err() {
                report_virtio_error(
                    locked_local_input.interrupt_cb.clone(),
                    locked_local_input.driver_features,
                    &locked_local_input.device_broken,
                );
            };
            None
        });
        notifiers.push(build_event_notifier(
            locked_input.status_queue_evt.as_raw_fd(),
            handler,
        ));

        // register evdev fd handler
        if let Some(fd) = &locked_input.evdev_fd {
            let local_input = input.clone();
            let handler: Rc<NotifierCallback> = Rc::new(move |_, _| {
                let mut locked_local_input = local_input.lock().unwrap();
                if locked_local_input.device_broken.load(Ordering::SeqCst) {
                    // The virtio-input device has broken, drop event
                    let event_fd = &locked_local_input.evdev_fd.clone().unwrap();
                    let mut evt = InputEvent::default();
                    let _ = event_fd.as_ref().read(evt.as_mut_bytes());
                    return None;
                }
                locked_local_input.do_event();
                None
            });
            notifiers.push(build_event_notifier(fd.as_raw_fd(), handler));
        };
        notifiers
    }
}

pub struct Input {
    /// Virtio device base property.
    base: VirtioBase,
    /// Interrupt callback function.
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    /// Input device config data.
    evdev_cfg: EvdevConfig,
    /// EventFd for device deactivate.
    deactivate_evts: Vec<RawFd>,
    /// Event file fd.
    fd: Option<Arc<File>>,
}

impl Input {
    pub fn new(option: InputConfig) -> Result<Self> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(option.evdev.clone())
            .with_context(|| {
                format!(
                    "Open evdev {} failed({:?})",
                    option.evdev,
                    std::io::Error::last_os_error()
                )
            })?;
        let evdev_cfg = EvdevConfig::new(&fd)?;
        Ok(Self {
            base: VirtioBase::new(VIRTIO_TYPE_INPUT, QUEUE_NUM_INPUT, DEFAULT_VIRTQUEUE_SIZE),
            interrupt_cb: None,
            evdev_cfg,
            deactivate_evts: Vec::new(),
            fd: Some(Arc::new(fd)),
        })
    }
}

impl VirtioDevice for Input {
    fn virtio_base(&self) -> &VirtioBase {
        &self.base
    }

    fn virtio_base_mut(&mut self) -> &mut VirtioBase {
        &mut self.base
    }

    fn realize(&mut self) -> Result<()> {
        self.init_config_features()
    }

    fn init_config_features(&mut self) -> Result<()> {
        self.base.device_features = 1u64 << VIRTIO_F_VERSION_1;
        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        let config = self.evdev_cfg.get_device_config();
        read_config_default(config.as_bytes(), offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let mut config = self.evdev_cfg.get_device_config();
        let config_slice = config.as_mut_bytes();
        check_config_space_rw(config_slice, offset, data)?;
        config_slice[(offset as usize)..(offset as usize + data.len())].copy_from_slice(data);

        self.evdev_cfg.select = config.select;
        self.evdev_cfg.subsel = config.subsel;
        Ok(())
    }

    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let queues = &self.base.queues;
        if queues.len() != self.queue_num() {
            return Err(anyhow!(VirtioError::IncorrectQueueNum(
                self.queue_num(),
                queues.len()
            )));
        }

        let event_queue = queues[0].clone();
        let event_queue_evt = queue_evts[0].clone();
        let status_queue = queues[1].clone();
        let status_queue_evt = queue_evts[1].clone();

        self.interrupt_cb = Some(interrupt_cb.clone());
        let handler = InputIoHandler {
            driver_features: self.base.driver_features,
            mem_space,
            event_queue,
            event_queue_evt,
            status_queue,
            status_queue_evt,
            event_buf: Vec::new(),
            device_broken: self.base.broken.clone(),
            interrupt_cb: interrupt_cb.clone(),
            evdev_fd: self.fd.clone(),
        };
        register_event_helper(
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler))),
            None,
            &mut self.deactivate_evts,
        )
        .with_context(|| "Failed to register input handler to Mainloop")?;
        self.base.broken.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        unregister_event_helper(None, &mut self.deactivate_evts)
    }

    fn reset(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use machine_manager::config::str_slip_to_clap;

    #[test]
    fn test_input_config_cmdline_parse() {
        // Test1: virtio-input-device(mmio).
        let input_cmd = "virtio-input-device,id=input0,evdev=/dev/input/event0";
        let input_config =
            InputConfig::try_parse_from(str_slip_to_clap(input_cmd, true, false)).unwrap();
        assert_eq!(input_config.multifunction, None);

        // Test2: virtio-input-pci.
        let input_cmd = "virtio-input-pci,bus=pcie.0,addr=0x1,id=input0,evdev=/dev/input/event0";
        let input_config =
            InputConfig::try_parse_from(str_slip_to_clap(input_cmd, true, false)).unwrap();
        assert_eq!(input_config.bus.unwrap(), "pcie.0");
        assert_eq!(input_config.addr.unwrap(), (1, 0));
        assert_eq!(input_config.evdev, "/dev/input/event0");
    }

    #[test]
    fn test_input_init() {
        let input_config = InputConfig {
            classtype: "virtio-input-pci".to_string(),
            id: "input0".to_string(),
            evdev: "/evdev/path".to_string(),
            bus: Some("pcie.0".to_string()),
            addr: Some((3, 0)),
            ..Default::default()
        };
        let input = Input::new(input_config);
        assert!(input.is_err());
    }
}
