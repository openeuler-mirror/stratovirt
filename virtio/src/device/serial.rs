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

use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::{cmp, usize};

use anyhow::{anyhow, bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};
use log::{error, info, warn};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use crate::{
    gpa_hva_iovec_map, iov_discard_front, iov_to_buf, read_config_default, report_virtio_error,
    Element, Queue, VirtioBase, VirtioDevice, VirtioError, VirtioInterrupt, VirtioInterruptType,
    VIRTIO_CONSOLE_F_MULTIPORT, VIRTIO_CONSOLE_F_SIZE, VIRTIO_F_VERSION_1, VIRTIO_TYPE_CONSOLE,
};
use address_space::AddressSpace;
use chardev_backend::chardev::{Chardev, ChardevNotifyDevice, ChardevStatus, InputReceiver};
use machine_manager::{
    config::{ChardevType, VirtioSerialInfo, VirtioSerialPort, DEFAULT_VIRTQUEUE_SIZE},
    event_loop::EventLoop,
    event_loop::{register_event_helper, unregister_event_helper},
};
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::{ByteCode, Desc};
use util::aio::iov_from_buf_direct;
use util::byte_code::ByteCode;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};

// Buffer size for chardev backend.
const BUF_SIZE: usize = 4096;

// The values for event.
// Sent by the driver at initialization to indicate that it is ready to receive control message.
const VIRTIO_CONSOLE_DEVICE_READY: u16 = 0;
// Sent by the device, to create a new port.
const VIRTIO_CONSOLE_PORT_ADD: u16 = 1;
// Sent by the device, to remove an existing port.
#[allow(unused)]
const VIRTIO_CONSOLE_PORT_REMOVE: u16 = 2;
// Sent by the driver in response to the device's VIRTIO_CONSOLE_PORT_ADD message.
// To indicate that the port is ready to be used.
const VIRTIO_CONSOLE_PORT_READY: u16 = 3;
// Sent by the device to nominate a port as a console port.
// There may be more than one console port.
const VIRTIO_CONSOLE_CONSOLE_PORT: u16 = 4;
// Sent by the device to indicate a console size change.
#[allow(unused)]
const VIRTIO_CONSOLE_RESIZE: u16 = 5;
// This message is sent by both the device and the driver. This allows for ports to be used
// directly by guest and host processes to communicate in an application-defined manner.
const VIRTIO_CONSOLE_PORT_OPEN: u16 = 6;
// Sent by the device to give a tag to the port.
const VIRTIO_CONSOLE_PORT_NAME: u16 = 7;

/// If the driver negotiated the VIRTIO_CONSOLE_F_MULTIPORT, the two control queues are used.
/// The layout of the control message is VirtioConsoleControl.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioConsoleControl {
    // Port number.
    id: u32,
    // The kind of control event.
    event: u16,
    // Extra information for event.
    value: u16,
}

impl ByteCode for VirtioConsoleControl {}

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
    fn new(max_nr_ports: u32) -> Self {
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
#[derive(Default)]
pub struct Serial {
    /// Virtio device base property.
    base: VirtioBase,
    /// Virtio serial config space.
    config_space: VirtioConsoleConfig,
    /// Max serial ports number.
    pub max_nr_ports: u32,
    /// Serial port vector for serialport.
    pub ports: Arc<Mutex<Vec<Arc<Mutex<SerialPort>>>>>,
}

impl Serial {
    /// Create a virtio-serial device.
    ///
    /// # Arguments
    ///
    /// * `serial_cfg` - Device configuration set by user.
    pub fn new(serial_cfg: VirtioSerialInfo) -> Self {
        // Each port has 2 queues(receiveq/transmitq).
        // And there exist 2 control queues(control receiveq/control transmitq).
        let queue_num = serial_cfg.max_ports as usize * 2 + 2;
        let queue_size = DEFAULT_VIRTQUEUE_SIZE;

        Serial {
            base: VirtioBase::new(VIRTIO_TYPE_CONSOLE, queue_num, queue_size),
            config_space: VirtioConsoleConfig::new(serial_cfg.max_ports),
            max_nr_ports: serial_cfg.max_ports,
            ..Default::default()
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
            driver_features: self.base.driver_features,
            device_broken,
            ports: self.ports.clone(),
        };

        let handler_h = Arc::new(Mutex::new(handler));
        for port in self.ports.lock().unwrap().iter_mut() {
            port.lock().unwrap().ctrl_handler = Some(Arc::downgrade(&handler_h.clone()));
        }
        let notifiers = EventNotifierHelper::internal_notifiers(handler_h);
        register_event_helper(notifiers, None, &mut self.base.deactivate_evts)?;

        Ok(())
    }
}

pub fn get_max_nr(ports: &Arc<Mutex<Vec<Arc<Mutex<SerialPort>>>>>) -> u32 {
    let mut max = 0;
    for port in ports.lock().unwrap().iter() {
        let nr = port.lock().unwrap().nr;
        if nr > max {
            max = nr;
        }
    }
    max
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
    fn virtio_base(&self) -> &VirtioBase {
        &self.base
    }

    fn virtio_base_mut(&mut self) -> &mut VirtioBase {
        &mut self.base
    }

    fn realize(&mut self) -> Result<()> {
        self.init_config_features()?;
        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        self.base.device_features = 1_u64 << VIRTIO_F_VERSION_1
            | 1_u64 << VIRTIO_CONSOLE_F_SIZE
            | 1_u64 << VIRTIO_CONSOLE_F_MULTIPORT;
        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        read_config_default(self.config_space.as_bytes(), offset, data)
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) -> Result<()> {
        bail!("Writing device config space for virtio serial is not supported.")
    }

    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let queues = self.base.queues.clone();
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
                input_queue_evt: queue_evts[queue_id * 2].clone(),
                output_queue: queues[queue_id * 2 + 1].clone(),
                output_queue_evt: queue_evts[queue_id * 2 + 1].clone(),
                mem_space: mem_space.clone(),
                interrupt_cb: interrupt_cb.clone(),
                driver_features: self.base.driver_features,
                device_broken: self.base.broken.clone(),
                port: port.clone(),
            };
            let handler_h = Arc::new(Mutex::new(handler));
            let notifiers = EventNotifierHelper::internal_notifiers(handler_h.clone());
            register_event_helper(notifiers, None, &mut self.base.deactivate_evts)?;

            if let Some(port_h) = port {
                port_h.lock().unwrap().activate(&handler_h);
            }
        }

        self.control_queues_activate(
            mem_space,
            interrupt_cb,
            &queues,
            queue_evts,
            self.base.broken.clone(),
        )?;

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        for port in self.ports.lock().unwrap().iter_mut() {
            port.lock().unwrap().deactivate();
        }
        unregister_event_helper(None, &mut self.base.deactivate_evts)?;

        Ok(())
    }
}

impl StateTransfer for Serial {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let state = VirtioSerialState {
            device_features: self.base.device_features,
            driver_features: self.base.driver_features,
            config_space: self.config_space,
        };
        Ok(state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
        let state = VirtioSerialState::from_bytes(state)
            .with_context(|| migration::error::MigrationError::FromBytesError("SERIAL"))?;
        self.base.device_features = state.device_features;
        self.base.driver_features = state.driver_features;
        self.config_space = state.config_space;
        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&VirtioSerialState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for Serial {}

/// Virtio serial port structure.
#[derive(Clone)]
pub struct SerialPort {
    name: Option<String>,
    /// Whether rx paused
    paused: bool,
    /// Chardev vector for serialport.
    pub chardev: Arc<Mutex<Chardev>>,
    /// Number id.
    nr: u32,
    /// Whether the port is a console port.
    pub is_console: bool,
    /// Whether the guest open the serial port.
    guest_connected: bool,
    /// Whether the host open the serial socket.
    host_connected: bool,
    /// The handler used to send control event to guest.
    ctrl_handler: Option<Weak<Mutex<SerialControlHandler>>>,
}

impl SerialPort {
    pub fn new(port_cfg: VirtioSerialPort) -> Self {
        // Console is default host connected. And pty chardev has opened by default in realize()
        // function.
        let host_connected = port_cfg.is_console || port_cfg.chardev.backend == ChardevType::Pty;

        SerialPort {
            name: Some(port_cfg.id),
            paused: false,
            chardev: Arc::new(Mutex::new(Chardev::new(port_cfg.chardev))),
            nr: port_cfg.nr,
            is_console: port_cfg.is_console,
            guest_connected: false,
            host_connected,
            ctrl_handler: None,
        }
    }

    pub fn realize(&mut self) -> Result<()> {
        self.chardev
            .lock()
            .unwrap()
            .realize()
            .with_context(|| "Failed to realize chardev")?;
        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(self.chardev.clone()),
            None,
        )?;
        Ok(())
    }

    fn unpause_chardev_rx(&mut self) {
        trace::virtio_serial_unpause_chardev_rx();
        if self.paused {
            self.paused = false;
            self.chardev.lock().unwrap().unpause_rx();
        }
    }

    fn activate(&mut self, handler: &Arc<Mutex<SerialPortHandler>>) {
        self.chardev.lock().unwrap().set_receiver(handler);
    }

    fn deactivate(&mut self) {
        self.guest_connected = false;
    }
}

/// Handler for queues which are used for port.
struct SerialPortHandler {
    input_queue: Arc<Mutex<Queue>>,
    input_queue_evt: Arc<EventFd>,
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
        trace::virtio_receive_request("Serial".to_string(), "to IO".to_string());
        self.output_handle_internal().unwrap_or_else(|e| {
            error!("Port handle output error: {:?}", e);
            report_virtio_error(
                self.interrupt_cb.clone(),
                self.driver_features,
                &self.device_broken,
            );
        });
    }

    fn input_avail_handle(&mut self) {
        // new buffer appeared in input queue. Unpause RX
        trace::virtio_serial_new_inputqueue_buf();

        self.enable_inputqueue_notify(false);
        let mut port_locked = self.port.as_ref().unwrap().lock().unwrap();
        port_locked.unpause_chardev_rx();
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

            // Discard requests when there is no port using this queue. Popping elements without
            // processing means discarding the request.
            if self.port.is_some() {
                let mut iovec = elem.out_iovec;
                let mut iovec_size = Element::iovec_size(&iovec);
                while iovec_size > 0 {
                    let mut buffer = [0_u8; BUF_SIZE];
                    let size = iov_to_buf(&self.mem_space, &iovec, &mut buffer)? as u64;

                    self.write_chardev_msg(&buffer, size as usize);

                    iovec = iov_discard_front(&mut iovec, size)
                        .unwrap_or_default()
                        .to_vec();
                    // Safety: iovec follows the iov_discard_front operation and
                    // iovec_size always equals Element::iovec_size(&iovec).
                    iovec_size -= size;
                    trace::virtio_serial_output_data(iovec_size, size);
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
            trace::virtqueue_send_interrupt("Serial", &*queue_lock as *const _ as u64);
        }

        Ok(())
    }

    fn write_chardev_msg(&self, buffer: &[u8], write_len: usize) {
        let port_locked = self.port.as_ref().unwrap().lock().unwrap();
        // Discard output buffer if this port's chardev is not connected.
        if !port_locked.host_connected {
            return;
        }

        if let Some(output) = &mut port_locked.chardev.lock().unwrap().output {
            let mut locked_output = output.lock().unwrap();
            // To do:
            // If the buffer is not fully written to chardev, the incomplete part will be discarded.
            // This may occur when chardev is abnormal. Consider optimizing this logic in the
            // future.
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

    fn get_input_avail_bytes(&mut self, max_size: usize) -> usize {
        let port = self.port.as_ref();
        if port.is_none() || !port.unwrap().lock().unwrap().guest_connected {
            trace::virtio_serial_disconnected_port();
            return 0;
        }

        if self.device_broken.load(Ordering::SeqCst) {
            warn!("virtio-serial device is broken");
            return 0;
        }

        let mut locked_queue = self.input_queue.lock().unwrap();
        match locked_queue
            .vring
            .get_avail_bytes(&self.mem_space, max_size, true)
        {
            Ok(n) => n,
            Err(_) => {
                warn!("error occurred while getting available bytes of vring");
                0
            }
        }
    }

    fn enable_inputqueue_notify(&mut self, enable: bool) {
        if self.device_broken.load(Ordering::SeqCst) {
            return;
        }

        let mut queue_lock = self.input_queue.lock().unwrap();
        let _ =
            queue_lock
                .vring
                .suppress_queue_notify(&self.mem_space, self.driver_features, !enable);
    }

    fn input_handle_internal(&mut self, buffer: &[u8]) -> Result<()> {
        let mut queue_lock = self.input_queue.lock().unwrap();

        let mut left = buffer.len();
        let port = self.port.as_ref();
        if left == 0 || port.is_none() {
            return Ok(());
        }
        let port_locked = port.unwrap().lock().unwrap();
        if !port_locked.guest_connected {
            return Ok(());
        }

        let mut written_count = 0_usize;
        loop {
            let elem = queue_lock
                .vring
                .pop_avail(&self.mem_space, self.driver_features)?;
            if elem.desc_num == 0 {
                break;
            }

            let mut once_count = 0_usize;
            for elem_iov in elem.in_iovec.iter() {
                let len = cmp::min(elem_iov.len as usize, left);
                let write_end = written_count + len;
                let mut source_slice = &buffer[written_count..write_end];

                self.mem_space
                    .write(&mut source_slice, elem_iov.addr, len as u64)
                    .with_context(|| {
                        format!(
                            "Failed to write slice for virtio serial port input: addr {:X} len {}",
                            elem_iov.addr.0, len
                        )
                    })?;

                written_count = write_end;
                once_count += len;
                left -= len;
                if left == 0 {
                    break;
                }
            }

            queue_lock
                .vring
                .add_used(&self.mem_space, elem.index, once_count as u32)
                .with_context(|| {
                    format!(
                        "Failed to add used ring for virtio serial port input: index {} len {}",
                        elem.index, once_count
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
                trace::virtqueue_send_interrupt("Serial", &*queue_lock as *const _ as u64);
            }

            if left == 0 {
                break;
            }
        }

        Ok(())
    }
}

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

        let cloned_inp_cls = serial_handler.clone();
        let input_avail_handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let mut h_lock = cloned_inp_cls.lock().unwrap();
            if h_lock.device_broken.load(Ordering::SeqCst) {
                return None;
            }
            h_lock.input_avail_handle();
            None
        });

        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            serial_handler.lock().unwrap().output_queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![handler],
        ));

        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            serial_handler.lock().unwrap().input_queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![input_avail_handler],
        ));

        notifiers
    }
}

impl InputReceiver for SerialPortHandler {
    fn receive(&mut self, buffer: &[u8]) {
        self.input_handle_internal(buffer).unwrap_or_else(|e| {
            error!("Port handle input error: {:?}", e);
            report_virtio_error(
                self.interrupt_cb.clone(),
                self.driver_features,
                &self.device_broken,
            );
        });
    }

    fn remain_size(&mut self) -> usize {
        self.get_input_avail_bytes(BUF_SIZE)
    }

    fn set_paused(&mut self) {
        trace::virtio_serial_pause_rx();
        if self.port.is_none() {
            return;
        }

        if self.port.as_ref().unwrap().lock().unwrap().guest_connected {
            self.enable_inputqueue_notify(true);
        }

        let mut locked_port = self.port.as_ref().unwrap().lock().unwrap();
        locked_port.paused = true;
    }
}

impl SerialControlHandler {
    fn output_control(&mut self) {
        self.output_control_internal().unwrap_or_else(|e| {
            error!("handle output control error: {:?}", e);
            report_virtio_error(
                self.interrupt_cb.clone(),
                self.driver_features,
                &self.device_broken,
            );
        });
    }

    fn output_control_internal(&mut self) -> Result<()> {
        let output_queue = self.output_queue.clone();
        let mut queue_lock = output_queue.lock().unwrap();

        loop {
            let elem = queue_lock
                .vring
                .pop_avail(&self.mem_space, self.driver_features)?;
            if elem.desc_num == 0 {
                break;
            }

            let mut req = VirtioConsoleControl::default();
            iov_to_buf(&self.mem_space, &elem.out_iovec, req.as_mut_bytes()).and_then(|size| {
                if size < size_of::<VirtioConsoleControl>() {
                    bail!(
                        "Invalid length for request: get {}, expected {}",
                        size,
                        size_of::<VirtioConsoleControl>(),
                    );
                }
                Ok(())
            })?;
            req.id = LittleEndian::read_u32(req.id.as_bytes());
            req.event = LittleEndian::read_u16(req.event.as_bytes());
            req.value = LittleEndian::read_u16(req.value.as_bytes());

            info!(
                "Serial port {} handle control message: event({}), value({})",
                req.id, req.event, req.value
            );
            self.handle_control_message(&mut req);

            queue_lock
                .vring
                .add_used(&self.mem_space, elem.index, 0)
                .with_context(|| {
                    format!(
                        "Failed to add used ring for control port, index: {} len: {}.",
                        elem.index, 0
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
                        "serial input control queue",
                        VirtioInterruptType::Vring,
                    )
                })?;
            trace::virtqueue_send_interrupt("Serial", &*queue_lock as *const _ as u64);
        }

        Ok(())
    }

    fn handle_control_message(&mut self, ctrl: &mut VirtioConsoleControl) {
        if ctrl.event == VIRTIO_CONSOLE_DEVICE_READY {
            if ctrl.value == 0 {
                error!("Guest is not ready to receive control message.");
                return;
            }

            let cloned_ports = self.ports.clone();
            let mut locked_ports = cloned_ports.lock().unwrap();
            for port in locked_ports.iter_mut() {
                self.send_control_event(port.lock().unwrap().nr, VIRTIO_CONSOLE_PORT_ADD, 1);
            }
            return;
        }

        let port = if let Some(port) = find_port_by_nr(&self.ports, ctrl.id) {
            port
        } else {
            error!("Invalid port id {}", ctrl.id);
            return;
        };

        match ctrl.event {
            VIRTIO_CONSOLE_PORT_READY => {
                if ctrl.value == 0 {
                    error!("Driver failed to add port {}", ctrl.id);
                    return;
                }

                let locked_port = port.lock().unwrap();
                if locked_port.is_console {
                    self.send_control_event(locked_port.nr, VIRTIO_CONSOLE_CONSOLE_PORT, 1);
                }

                if let Some(name) = &locked_port.name {
                    let mut extra_data: Vec<u8> = Vec::new();
                    extra_data.extend(name.as_bytes());
                    extra_data.push(0);
                    self.send_input_control_msg(
                        locked_port.nr,
                        VIRTIO_CONSOLE_PORT_NAME,
                        1,
                        &extra_data,
                    )
                    .unwrap_or_else(|e| {
                        error!("Send input control message error: {:?}", e);
                        report_virtio_error(
                            self.interrupt_cb.clone(),
                            self.driver_features,
                            &self.device_broken,
                        );
                    });
                }

                if locked_port.host_connected {
                    self.send_control_event(locked_port.nr, VIRTIO_CONSOLE_PORT_OPEN, 1);
                }
            }
            VIRTIO_CONSOLE_PORT_OPEN => {
                let mut locked_port = port.lock().unwrap();
                locked_port.guest_connected = ctrl.value != 0;
                if ctrl.value != 0 {
                    locked_port.unpause_chardev_rx();
                }
            }
            _ => (),
        }
    }

    fn send_control_event(&mut self, id: u32, event: u16, value: u16) {
        info!(
            "Serial port {} send control message: event({}), value({})",
            id, event, value
        );
        self.send_input_control_msg(id, event, value, &[])
            .unwrap_or_else(|e| {
                error!("send input control message error: {:?}", e);
                report_virtio_error(
                    self.interrupt_cb.clone(),
                    self.driver_features,
                    &self.device_broken,
                );
            });
    }

    fn send_input_control_msg(
        &mut self,
        id: u32,
        event: u16,
        value: u16,
        extra: &[u8],
    ) -> Result<()> {
        let mut queue_lock = self.input_queue.lock().unwrap();
        let elem = queue_lock
            .vring
            .pop_avail(&self.mem_space, self.driver_features)?;
        if elem.desc_num == 0 {
            warn!("empty input queue buffer!");
            return Ok(());
        }

        let (in_size, ctrl_vec) = gpa_hva_iovec_map(&elem.in_iovec, &self.mem_space)?;
        let len = size_of::<VirtioConsoleControl>() + extra.len();
        if in_size < len as u64 {
            bail!(
                "Invalid length for input control msg: get {}, expected {}",
                in_size,
                len,
            );
        }

        let ctrl_msg = VirtioConsoleControl { id, event, value };
        let mut msg_data: Vec<u8> = Vec::new();
        msg_data.extend(ctrl_msg.as_bytes());
        if !extra.is_empty() {
            msg_data.extend(extra);
        }

        iov_from_buf_direct(&ctrl_vec, &msg_data).and_then(|size| {
            if size != len {
                bail!(
                    "Expected send msg length is {}, actual send length {}.",
                    len,
                    size
                );
            }
            Ok(())
        })?;

        queue_lock
            .vring
            .add_used(&self.mem_space, elem.index, len as u32)
            .with_context(|| {
                format!(
                    "Failed to add used ring(serial input control queue), index {}, len {}",
                    elem.index, len,
                )
            })?;

        if queue_lock
            .vring
            .should_notify(&self.mem_space, self.driver_features)
        {
            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue_lock), false)
                .with_context(|| {
                    VirtioError::InterruptTrigger(
                        "serial input control queue",
                        VirtioInterruptType::Vring,
                    )
                })?;
            trace::virtqueue_send_interrupt("Serial", &*queue_lock as *const _ as u64);
        }

        Ok(())
    }
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

impl ChardevNotifyDevice for SerialPort {
    fn chardev_notify(&mut self, status: ChardevStatus) {
        match (&status, self.host_connected) {
            (ChardevStatus::Close, _) => self.host_connected = false,
            (ChardevStatus::Open, false) => self.host_connected = true,
            (ChardevStatus::Open, true) => return,
        }

        if self.ctrl_handler.is_none() {
            warn!("No control handler for port {}.", self.nr);
            return;
        }

        let handler = self.ctrl_handler.as_ref().unwrap().upgrade();
        if handler.is_none() {
            warn!("Control handler for port {} is invalid", self.nr);
            return;
        }

        // Note: when virtio serial devices are deactivated, all handlers will be unregistered.
        // For this action is in the same thread with `chardev_notify`, these two operations will
        // not be executed concurrently. So, `handler` must be effective here.
        handler.unwrap().lock().unwrap().send_control_event(
            self.nr,
            VIRTIO_CONSOLE_PORT_OPEN,
            status as u16,
        );
    }
}

#[cfg(test)]
mod tests {
    pub use super::*;

    use machine_manager::config::PciBdf;

    #[test]
    fn test_set_driver_features() {
        let mut serial = Serial::new(VirtioSerialInfo {
            id: "serial".to_string(),
            pci_bdf: Some(PciBdf {
                bus: "pcie.0".to_string(),
                addr: (0, 0),
            }),
            multifunction: false,
            max_ports: 31,
        });

        // If the device feature is 0, all driver features are not supported.
        serial.base.device_features = 0;
        let driver_feature: u32 = 0xFF;
        let page = 0_u32;
        serial.set_driver_features(page, driver_feature);
        assert_eq!(serial.base.driver_features, 0_u64);
        assert_eq!(serial.driver_features(page) as u64, 0_u64);

        let driver_feature: u32 = 0xFF;
        let page = 1_u32;
        serial.set_driver_features(page, driver_feature);
        assert_eq!(serial.base.driver_features, 0_u64);
        assert_eq!(serial.driver_features(page) as u64, 0_u64);

        // If both the device feature bit and the front-end driver feature bit are
        // supported at the same time, this driver feature bit is supported.
        serial.base.device_features = 1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_CONSOLE_F_SIZE;
        let driver_feature: u32 = (1_u64 << VIRTIO_CONSOLE_F_SIZE) as u32;
        let page = 0_u32;
        serial.set_driver_features(page, driver_feature);
        assert_eq!(
            serial.base.driver_features,
            (1_u64 << VIRTIO_CONSOLE_F_SIZE)
        );
        assert_eq!(
            serial.driver_features(page) as u64,
            (1_u64 << VIRTIO_CONSOLE_F_SIZE)
        );
        serial.base.driver_features = 0;

        serial.base.device_features = 1_u64 << VIRTIO_F_VERSION_1;
        let driver_feature: u32 = (1_u64 << VIRTIO_CONSOLE_F_SIZE) as u32;
        let page = 0_u32;
        serial.set_driver_features(page, driver_feature);
        assert_eq!(serial.base.driver_features, 0);
        serial.base.driver_features = 0;

        serial.base.device_features = 1_u64 << VIRTIO_F_VERSION_1
            | 1_u64 << VIRTIO_CONSOLE_F_SIZE
            | 1_u64 << VIRTIO_CONSOLE_F_MULTIPORT;
        let driver_feature: u32 = (1_u64 << VIRTIO_CONSOLE_F_MULTIPORT) as u32;
        let page = 0_u32;
        serial.set_driver_features(page, driver_feature);
        assert_eq!(
            serial.base.driver_features,
            (1_u64 << VIRTIO_CONSOLE_F_MULTIPORT)
        );
        let driver_feature: u32 = ((1_u64 << VIRTIO_F_VERSION_1) >> 32) as u32;
        let page = 1_u32;
        serial.set_driver_features(page, driver_feature);
        assert_eq!(
            serial.base.driver_features,
            (1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_CONSOLE_F_MULTIPORT)
        );
    }

    #[test]
    fn test_read_config() {
        let max_ports: u8 = 31;
        let serial = Serial::new(VirtioSerialInfo {
            id: "serial".to_string(),
            pci_bdf: Some(PciBdf {
                bus: "pcie.0".to_string(),
                addr: (0, 0),
            }),
            multifunction: false,
            max_ports: max_ports as u32,
        });

        // The offset of configuration that needs to be read exceeds the maximum.
        let offset = size_of::<VirtioConsoleConfig>() as u64;
        let mut read_data: Vec<u8> = vec![0; 8];
        assert_eq!(serial.read_config(offset, &mut read_data).is_ok(), false);

        // Check the configuration that needs to be read.
        let offset = 0_u64;
        let mut read_data: Vec<u8> = vec![0; 12];
        let expect_data: Vec<u8> = vec![0, 0, 0, 0, max_ports, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(serial.read_config(offset, &mut read_data).is_ok(), true);
        assert_eq!(read_data, expect_data);
    }
}
