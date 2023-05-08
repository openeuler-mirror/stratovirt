// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::{cmp, usize};

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, error};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use crate::{
    iov_discard_front, iov_to_buf, report_virtio_error, Element, Queue, VirtioDevice, VirtioError,
    VirtioInterrupt, VirtioInterruptType, VirtioTrace, VIRTIO_CONSOLE_F_MULTIPORT,
    VIRTIO_CONSOLE_F_SIZE, VIRTIO_F_VERSION_1, VIRTIO_TYPE_CONSOLE,
};
use address_space::AddressSpace;
use devices::legacy::{Chardev, InputReceiver};
use machine_manager::{
    config::{VirtioSerialInfo, VirtioSerialPort, DEFAULT_VIRTQUEUE_SIZE},
    event_loop::EventLoop,
    event_loop::{register_event_helper, unregister_event_helper},
};
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::num_ops::read_u32;

// Buffer size for chardev backend.
const BUF_SIZE: usize = 4096;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioConsoleConfig {
    // The size of the console is supplied if VIRTIO_CONSOLE_F_SIZE feature is set.
    cols: u16,
    rows: u16,
    // The maximum number of ports supported by the device can be fetched
    // if VIRTIO_CONSOLE_F_MULTIPORT feature is set.
    max_nr_ports: u32,
    // The driver can use emergency write to output a single character without
    // initializing virtio queues if VIRTIO_CONSOLE_F_EMERG_WRITE is set.
    emerg_wr: u32,
}

impl ByteCode for VirtioConsoleConfig {}

impl VirtioConsoleConfig {
    /// Create configuration of virtio-serial devices.
    pub fn new(max_nr_ports: u32) -> Self {
        VirtioConsoleConfig {
            cols: 0_u16,
            rows: 0_u16,
            max_nr_ports,
            emerg_wr: 0_u32,
        }
    }
}

/// Status of serial device.
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct VirtioSerialState {
    /// Bit mask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Virtio serial config space.
    config_space: VirtioConsoleConfig,
}

/// Virtio serial device structure.
#[allow(dead_code)]
pub struct Serial {
    /// Status of virtio serial device.
    state: VirtioSerialState,
    /// EventFd for device deactivate.
    deactivate_evts: Vec<RawFd>,
    /// Max serial ports number.
    pub max_nr_ports: u32,
    /// Serial port vector for serialport.
    pub ports: Arc<Mutex<Vec<Arc<Mutex<SerialPort>>>>>,
    /// Device is broken or not.
    device_broken: Arc<AtomicBool>,
}

impl Serial {
    /// Create a virtio-serial device.
    ///
    /// # Arguments
    ///
    /// * `serial_cfg` - Device configuration set by user.
    pub fn new(serial_cfg: VirtioSerialInfo) -> Self {
        Serial {
            state: VirtioSerialState {
                device_features: 0_u64,
                driver_features: 0_u64,
                config_space: VirtioConsoleConfig::new(serial_cfg.max_ports),
            },
            deactivate_evts: Vec::new(),
            max_nr_ports: serial_cfg.max_ports,
            ports: Arc::new(Mutex::new(Vec::new())),
            device_broken: Arc::new(AtomicBool::new(false)),
        }
    }

    fn control_queues_activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<Queue>>],
        queue_evts: Vec<Arc<EventFd>>,
        device_broken: Arc<AtomicBool>,
    ) -> Result<()> {
        // queue[2]: control receiveq(host to guest).
        // queue[3]: control transmitq(guest to host).
        let handler = SerialControlHandler {
            input_queue: queues[2].clone(),
            output_queue: queues[3].clone(),
            output_queue_evt: queue_evts[3].clone(),
            mem_space,
            interrupt_cb,
            driver_features: self.state.driver_features,
            device_broken,
            ports: self.ports.clone(),
        };

        let handler_h = Arc::new(Mutex::new(handler));
        for port in self.ports.lock().unwrap().iter_mut() {
            port.lock().unwrap().ctrl_handler = Some(Arc::downgrade(&handler_h.clone()));
        }
        let notifiers = EventNotifierHelper::internal_notifiers(handler_h);
        register_event_helper(notifiers, None, &mut self.deactivate_evts)?;

        Ok(())
    }
}

pub fn find_port_by_nr(
    ports: &Arc<Mutex<Vec<Arc<Mutex<SerialPort>>>>>,
    nr: u32,
) -> Option<Arc<Mutex<SerialPort>>> {
    for port in ports.lock().unwrap().iter() {
        if port.lock().unwrap().nr == nr {
            return Some(port.clone());
        }
    }
    None
}

impl VirtioDevice for Serial {
    /// Realize virtio serial device.
    fn realize(&mut self) -> Result<()> {
        self.state.device_features = 1_u64 << VIRTIO_F_VERSION_1
            | 1_u64 << VIRTIO_CONSOLE_F_SIZE
            | 1_u64 << VIRTIO_CONSOLE_F_MULTIPORT;

        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_CONSOLE
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        // Each port has 2 queues(receiveq/transmitq).
        // And there exist 2 control queues(control receiveq/control transmitq).
        self.max_nr_ports as usize * 2 + 2
    }

    /// Get the queue size of virtio device.
    fn queue_size(&self) -> u16 {
        DEFAULT_VIRTQUEUE_SIZE
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
    fn write_config(&mut self, _offset: u64, _data: &[u8]) -> Result<()> {
        bail!("Writing device config space for virtio serial is not supported.")
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
        if queues.len() != self.queue_num() {
            return Err(anyhow!(VirtioError::IncorrectQueueNum(
                self.queue_num(),
                queues.len()
            )));
        }

        for queue_id in 0..queues.len() / 2 {
            // queues[i * 2] (note: i != 1): receiveq(host to guest).
            // queues[i * 2 + 1] (note: i != 1): transmitq(guest to host).
            let nr = match queue_id {
                0 => 0,
                1 => continue,
                _ => queue_id - 1,
            };
            let port = find_port_by_nr(&self.ports, nr as u32);
            let handler = SerialPortHandler {
                input_queue: queues[queue_id * 2].clone(),
                output_queue: queues[queue_id * 2 + 1].clone(),
                output_queue_evt: queue_evts[queue_id * 2 + 1].clone(),
                mem_space: mem_space.clone(),
                interrupt_cb: interrupt_cb.clone(),
                driver_features: self.state.driver_features,
                device_broken: self.device_broken.clone(),
                port: port.clone(),
            };
            let handler_h = Arc::new(Mutex::new(handler));
            let notifiers = EventNotifierHelper::internal_notifiers(handler_h.clone());
            register_event_helper(notifiers, None, &mut self.deactivate_evts)?;

            if let Some(port_h) = port {
                port_h.lock().unwrap().activate(&handler_h);
            }
        }

        self.control_queues_activate(
            mem_space,
            interrupt_cb,
            queues,
            queue_evts,
            self.device_broken.clone(),
        )?;

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        for port in self.ports.lock().unwrap().iter_mut() {
            port.lock().unwrap().deactivate();
        }
        unregister_event_helper(None, &mut self.deactivate_evts)?;

        Ok(())
    }
}

impl StateTransfer for Serial {
    fn get_state_vec(&self) -> migration::Result<Vec<u8>> {
        Ok(self.state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> migration::Result<()> {
        self.state = *VirtioSerialState::from_bytes(state)
            .with_context(|| migration::error::MigrationError::FromBytesError("SERIAL"))?;

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&VirtioSerialState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for Serial {}

/// Virtio serial port structure.
#[allow(dead_code)]
#[derive(Clone)]
pub struct SerialPort {
    name: Option<String>,
    /// Chardev vector for serialport.
    pub chardev: Arc<Mutex<Chardev>>,
    /// Number id.
    nr: u32,
    /// Whether the port is a console port.
    is_console: bool,
    /// Whether the guest open the serial port.
    guest_connected: bool,
    /// Whether the host open the serial socket.
    host_connected: bool,
    /// The handler used to send control event to guest.
    ctrl_handler: Option<Weak<Mutex<SerialControlHandler>>>,
}

impl SerialPort {
    pub fn new(port_cfg: VirtioSerialPort) -> Self {
        SerialPort {
            name: Some(port_cfg.id),
            chardev: Arc::new(Mutex::new(Chardev::new(port_cfg.chardev))),
            nr: port_cfg.nr,
            is_console: port_cfg.is_console,
            guest_connected: false,
            host_connected: false,
            ctrl_handler: None,
        }
    }

    pub fn realize(&mut self) -> Result<()> {
        self.chardev
            .lock()
            .unwrap()
            .realize()
            .with_context(|| "Failed to realize chardev")?;
        self.chardev.lock().unwrap().deactivated = true;
        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(self.chardev.clone()),
            None,
        )?;
        Ok(())
    }

    fn activate(&mut self, handler: &Arc<Mutex<SerialPortHandler>>) {
        self.chardev.lock().unwrap().set_input_callback(handler);
        self.chardev.lock().unwrap().deactivated = false;
    }

    fn deactivate(&mut self) {
        self.chardev.lock().unwrap().deactivated = true;
        self.guest_connected = false;
    }
}

/// Handler for queues which are used for port.
#[allow(dead_code)]
struct SerialPortHandler {
    input_queue: Arc<Mutex<Queue>>,
    output_queue: Arc<Mutex<Queue>>,
    output_queue_evt: Arc<EventFd>,
    mem_space: Arc<AddressSpace>,
    interrupt_cb: Arc<VirtioInterrupt>,
    driver_features: u64,
    /// Virtio serial device is broken or not.
    device_broken: Arc<AtomicBool>,
    port: Option<Arc<Mutex<SerialPort>>>,
}

/// Handler for queues which are used for control.
#[allow(dead_code)]
struct SerialControlHandler {
    input_queue: Arc<Mutex<Queue>>,
    output_queue: Arc<Mutex<Queue>>,
    output_queue_evt: Arc<EventFd>,
    mem_space: Arc<AddressSpace>,
    interrupt_cb: Arc<VirtioInterrupt>,
    driver_features: u64,
    /// Virtio serial device is broken or not.
    device_broken: Arc<AtomicBool>,
    ports: Arc<Mutex<Vec<Arc<Mutex<SerialPort>>>>>,
}

impl SerialPortHandler {
    fn output_handle(&mut self) {
        self.trace_request("Serial".to_string(), "to IO".to_string());

        self.output_handle_internal().unwrap_or_else(|e| {
            error!("Port handle output error: {:?}", e);
            report_virtio_error(
                self.interrupt_cb.clone(),
                self.driver_features,
                &self.device_broken,
            );
        });
    }

    fn output_handle_internal(&mut self) -> Result<()> {
        let mut queue_lock = self.output_queue.lock().unwrap();

        loop {
            let elem = queue_lock
                .vring
                .pop_avail(&self.mem_space, self.driver_features)?;
            if elem.desc_num == 0 {
                break;
            }
            debug!("elem desc_unm: {}", elem.desc_num);

            // Discard requests when there is no port using this queue or this port's socket is not connected.
            // Popping elements without processing means discarding the request.
            if self.port.is_some() && self.port.as_ref().unwrap().lock().unwrap().host_connected {
                let mut iovec = elem.out_iovec;
                let mut iovec_size = Element::iovec_size(&iovec);
                while iovec_size > 0 {
                    let mut buffer = [0_u8; BUF_SIZE];
                    let size = iov_to_buf(&self.mem_space, &iovec, &mut buffer)?;

                    self.write_chardev_msg(&buffer, size);

                    iovec = iov_discard_front(&mut iovec, size as u64)
                        .unwrap_or_default()
                        .to_vec();
                    // Safety: iovec follows the iov_discard_front operation and
                    // iovec_size always equals Element::iovec_size(&iovec).
                    iovec_size -= size as u64;
                    debug!("iovec size {}, write size {}", iovec_size, size);
                }
            }

            queue_lock
                .vring
                .add_used(&self.mem_space, elem.index, 0)
                .with_context(|| {
                    format!(
                        "Failed to add used ring for virtio serial port output, index: {} len: {}",
                        elem.index, 0,
                    )
                })?;
        }

        if queue_lock
            .vring
            .should_notify(&self.mem_space, self.driver_features)
        {
            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue_lock), false)
                .with_context(|| {
                    VirtioError::InterruptTrigger(
                        "serial port output queue",
                        VirtioInterruptType::Vring,
                    )
                })?;
        }

        Ok(())
    }

    fn write_chardev_msg(&self, buffer: &[u8], write_len: usize) {
        let chardev = self.port.as_ref().unwrap().lock().unwrap();
        if let Some(output) = &mut chardev.chardev.lock().unwrap().output {
            let mut locked_output = output.lock().unwrap();
            // To do:
            // If the buffer is not fully written to chardev, the incomplete part will be discarded.
            // This may occur when chardev is abnormal. Consider optimizing this logic in the future.
            if let Err(e) = locked_output.write_all(&buffer[..write_len]) {
                error!("Failed to write msg to chardev: {:?}", e);
            }
            if let Err(e) = locked_output.flush() {
                error!("Failed to flush msg to chardev: {:?}", e);
            }
        } else {
            error!("Failed to get output fd");
        };
    }

    fn input_handle_internal(&mut self, buffer: &[u8]) -> Result<()> {
        let mut queue_lock = self.input_queue.lock().unwrap();

        let count = buffer.len();
        if count == 0
            || self.port.is_some() && !self.port.as_ref().unwrap().lock().unwrap().guest_connected
        {
            return Ok(());
        }

        loop {
            let elem = queue_lock
                .vring
                .pop_avail(&self.mem_space, self.driver_features)?;
            if elem.desc_num == 0 {
                break;
            }

            let mut written_count = 0_usize;
            for elem_iov in elem.in_iovec.iter() {
                let allow_write_count = cmp::min(written_count + elem_iov.len as usize, count);
                let mut source_slice = &buffer[written_count..allow_write_count];
                let len = source_slice.len();

                self.mem_space
                    .write(&mut source_slice, elem_iov.addr, len as u64)
                    .with_context(|| {
                        format!(
                            "Failed to write slice for virtio serial port input: addr {:X} len {}",
                            elem_iov.addr.0, len
                        )
                    })?;

                written_count = allow_write_count;
                if written_count >= count {
                    break;
                }
            }

            queue_lock
                .vring
                .add_used(&self.mem_space, elem.index, written_count as u32)
                .with_context(|| {
                    format!(
                        "Failed to add used ring for virtio serial port input: index {} len {}",
                        elem.index, written_count
                    )
                })?;

            if queue_lock
                .vring
                .should_notify(&self.mem_space, self.driver_features)
            {
                (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue_lock), false)
                    .with_context(|| {
                        VirtioError::InterruptTrigger(
                            "serial port input queue",
                            VirtioInterruptType::Vring,
                        )
                    })?;
            }

            if written_count >= count {
                break;
            }
        }

        Ok(())
    }
}

impl VirtioTrace for SerialPortHandler {}

impl EventNotifierHelper for SerialPortHandler {
    fn internal_notifiers(serial_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        let cloned_cls = serial_handler.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let mut h_lock = cloned_cls.lock().unwrap();
            if h_lock.device_broken.load(Ordering::SeqCst) {
                return None;
            }
            h_lock.output_handle();
            None
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            serial_handler.lock().unwrap().output_queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![handler],
        ));

        notifiers
    }
}

impl InputReceiver for SerialPortHandler {
    fn input_handle(&mut self, buffer: &[u8]) {
        self.input_handle_internal(buffer).unwrap_or_else(|e| {
            error!("Port handle input error: {:?}", e);
            report_virtio_error(
                self.interrupt_cb.clone(),
                self.driver_features,
                &self.device_broken,
            );
        });
    }

    fn get_remain_space_size(&mut self) -> usize {
        BUF_SIZE
    }
}

impl SerialControlHandler {
    fn output_control(&mut self) {}
}

impl EventNotifierHelper for SerialControlHandler {
    fn internal_notifiers(serial_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        let cloned_cls = serial_handler.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let mut h_lock = cloned_cls.lock().unwrap();
            if h_lock.device_broken.load(Ordering::SeqCst) {
                return None;
            }
            h_lock.output_control();
            None
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            serial_handler.lock().unwrap().output_queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![handler],
        ));

        notifiers
    }
}
