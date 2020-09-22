// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use address_space::AddressSpace;
use machine_manager::config::ConsoleConfig;
use util::byte_code::ByteCode;
use util::epoll_context::{read_fd, EventNotifier, EventNotifierHelper, NotifierOperation};
use util::num_ops::{read_u32, write_u32};
use util::unix::limit_permission;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use super::super::micro_vm::main_loop::MainLoop;
use super::errors::{ErrorKind, Result, ResultExt};
use super::{
    Queue, VirtioDevice, VIRTIO_CONSOLE_F_SIZE, VIRTIO_F_VERSION_1, VIRTIO_MMIO_INT_VRING,
    VIRTIO_TYPE_CONSOLE,
};

/// Number of virtqueues.
const QUEUE_NUM_CONSOLE: usize = 2;
/// Size of virtqueue.
const QUEUE_SIZE_CONSOLE: u16 = 256;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct VirtioConsoleConfig {
    max_nr_ports: u32,
    emerg_wr: u32,
}

impl ByteCode for VirtioConsoleConfig {}

impl VirtioConsoleConfig {
    /// Create configuration of virtio-console devices.
    pub fn new() -> Self {
        VirtioConsoleConfig {
            max_nr_ports: 1_u32,
            emerg_wr: 0_u32,
        }
    }
}

/// Console device's IO handle context.
struct ConsoleHandler {
    /// Virtqueue for console input.
    input_queue: Arc<Mutex<Queue>>,
    /// Virtqueue for console output.
    output_queue: Arc<Mutex<Queue>>,
    /// Eventfd of output_queue.
    output_queue_evt: EventFd,
    /// The address space to which the console device belongs.
    mem_space: Arc<AddressSpace>,
    /// Eventfd for triggering interrupts.
    interrupt_evt: EventFd,
    /// State of the interrupt in the device/function.
    interrupt_status: Arc<AtomicU32>,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Unix domain socket server.
    listener: UnixListener,
    /// Unix stream socket got by the incoming connection.
    client: Option<UnixStream>,
}

impl ConsoleHandler {
    #[allow(clippy::useless_asref)]
    /// Handler for console input.
    ///
    /// # Arguments
    ///
    /// * `buffer` - where to put the input data.
    pub fn input_handle(&mut self, buffer: &mut [u8]) -> Result<()> {
        let mut queue_lock = self.input_queue.lock().unwrap();

        let count = buffer.len();
        if count == 0 {
            return Ok(());
        }

        while let Ok(elem) = queue_lock
            .vring
            .pop_avail(&self.mem_space, self.driver_features)
        {
            let mut write_count = 0_usize;
            for elem_iov in elem.in_iovec.iter() {
                let allow_write_count = cmp::min(write_count + elem_iov.len as usize, count);
                let source_slice = &mut buffer[write_count..allow_write_count];

                let write_result = self.mem_space.write(
                    &mut source_slice.as_ref(),
                    elem_iov.addr,
                    source_slice.len() as u64,
                );
                match write_result {
                    Ok(_) => {
                        write_count = allow_write_count;
                    }
                    Err(e) => {
                        error!("Failed to write slice: {:?}", e);
                        break;
                    }
                }
            }

            match queue_lock
                .vring
                .add_used(&self.mem_space, elem.index, write_count as u32)
            {
                Ok(_) => (),
                Err(e) => {
                    error!("Failed to add used ring {}: {:?}", elem.index, e);
                    break;
                }
            }

            if write_count >= count {
                break;
            }
        }

        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING, Ordering::SeqCst);
        self.interrupt_evt
            .write(1)
            .chain_err(|| ErrorKind::EventFdWrite)?;
        Ok(())
    }

    /// Handler for console output.
    pub fn output_handle(&mut self) -> Result<()> {
        let mut queue_lock = self.output_queue.lock().unwrap();
        let mut buffer = [0_u8; 4096];

        while let Ok(elem) = queue_lock
            .vring
            .pop_avail(&self.mem_space, self.driver_features)
        {
            let mut read_count = 0_usize;
            for elem_iov in elem.out_iovec.iter() {
                let allow_read_count = cmp::min(read_count + elem_iov.len as usize, buffer.len());
                let mut slice = &mut buffer[read_count..allow_read_count];

                let read_result = self.mem_space.read(
                    &mut slice,
                    elem_iov.addr,
                    (allow_read_count - read_count) as u64,
                );
                match read_result {
                    Ok(_) => {
                        read_count = allow_read_count;
                    }
                    Err(e) => {
                        error!("Failed to read buffer: {:?}", e);
                        break;
                    }
                };
            }

            if let Some(mut client) = self.client.as_ref() {
                if let Err(e) = client.write(&buffer[..read_count as usize]) {
                    error!("Failed to write console output: {}.", e);
                };
            }

            if let Err(e) = queue_lock.vring.add_used(&self.mem_space, elem.index, 0) {
                error!("Failed to add used ring {}: {:?}", elem.index, e);
                break;
            }
        }

        Ok(())
    }
}

impl EventNotifierHelper for ConsoleHandler {
    fn internal_notifiers(console_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        let cls_outer = console_handler.clone();
        let handler = Box::new(move |_, _| {
            let cls = cls_outer.clone();
            let (stream, _) = cls.lock().unwrap().listener.accept().unwrap();
            let listener_fd = cls.lock().unwrap().listener.as_raw_fd();
            let stream_fd = stream.as_raw_fd();
            cls.lock().unwrap().client = Some(stream);
            let cls_inner = cls.clone();

            let cls_mid = cls;
            let handler = Box::new(move |event, _| {
                if event == EventSet::IN {
                    let cls_inner = cls_mid.clone();
                    let mut cls_inner_lk = cls_inner.lock().unwrap();

                    if let Some(client) = &cls_inner_lk.client {
                        let mut client_inner = client.try_clone().unwrap();

                        let mut buffer = [0_u8; 4096];
                        if let Ok(nr) = client_inner.read(&mut buffer) {
                            let _ = cls_inner_lk.input_handle(&mut buffer[..nr]);
                        }
                    }
                }

                if event & EventSet::HANG_UP == EventSet::HANG_UP {
                    cls_inner.lock().unwrap().client = None;
                    Some(vec![EventNotifier::new(
                        NotifierOperation::Delete,
                        stream_fd,
                        Some(listener_fd),
                        EventSet::IN | EventSet::HANG_UP,
                        Vec::new(),
                    )])
                } else {
                    None as Option<Vec<EventNotifier>>
                }
            });

            Some(vec![EventNotifier::new(
                NotifierOperation::AddShared,
                stream_fd,
                Some(listener_fd),
                EventSet::IN | EventSet::HANG_UP,
                vec![Arc::new(Mutex::new(handler))],
            )])
        });

        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            console_handler.lock().unwrap().listener.as_raw_fd(),
            None,
            EventSet::IN,
            vec![Arc::new(Mutex::new(handler))],
        ));

        let cls = console_handler.clone();
        let handler = Box::new(move |_, fd: RawFd| {
            read_fd(fd);

            let _ = cls.clone().lock().unwrap().output_handle();

            None as Option<Vec<EventNotifier>>
        });

        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            console_handler.lock().unwrap().output_queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![Arc::new(Mutex::new(handler))],
        ));

        notifiers
    }
}

/// Virtio console device structure.
pub struct Console {
    /// Virtio configuration.
    config: Arc<Mutex<VirtioConsoleConfig>>,
    /// Bit mask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// UnixListener for virtio-console to communicate in host.
    listener: UnixListener,
}

impl Console {
    /// Create a virtio-console device.
    ///
    /// # Arguments
    ///
    /// * `console_cfg` - Device configuration set by user.
    pub fn new(console_cfg: ConsoleConfig) -> Self {
        let path = console_cfg.socket_path;
        let listener = UnixListener::bind(path.as_str())
            .unwrap_or_else(|_| panic!("Failed to bind socket {}", path));

        limit_permission(path.as_str())
            .unwrap_or_else(|_| panic!("Failed to change file permission for {}", path));

        Console {
            config: Arc::new(Mutex::new(VirtioConsoleConfig::new())),
            device_features: 0_u64,
            driver_features: 0_u64,
            listener,
        }
    }
}

impl VirtioDevice for Console {
    /// Realize vhost virtio network device.
    fn realize(&mut self) -> Result<()> {
        self.device_features = 1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_CONSOLE_F_SIZE;

        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_CONSOLE
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        QUEUE_NUM_CONSOLE
    }

    /// Get the queue size of virtio device.
    fn queue_size(&self) -> u16 {
        QUEUE_SIZE_CONSOLE
    }

    /// Get device features from host.
    fn get_device_features(&self, features_select: u32) -> u32 {
        read_u32(self.device_features, features_select)
    }

    /// Set driver features by guest.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        let mut v = write_u32(value, page);
        let unrequested_features = v & !self.device_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request with unknown feature.");
            v &= !unrequested_features;
        }
        self.driver_features |= v;
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config = *self.config.lock().unwrap();
        let config_slice = config.as_bytes();
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
    fn write_config(&mut self, _offset: u64, _data: &[u8]) -> Result<()> {
        bail!("No device config space")
    }

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_evt: EventFd,
        interrupt_status: Arc<AtomicU32>,
        mut queues: Vec<Arc<Mutex<Queue>>>,
        mut queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        queue_evts.remove(0); // input_queue_evt never used

        let handler = ConsoleHandler {
            input_queue: queues.remove(0),
            output_queue: queues.remove(0),
            output_queue_evt: queue_evts.remove(0),
            mem_space,
            interrupt_evt: interrupt_evt.try_clone()?,
            interrupt_status,
            driver_features: self.driver_features,
            listener: self.listener.try_clone()?,
            client: None,
        };

        MainLoop::update_event(EventNotifierHelper::internal_notifiers(Arc::new(
            Mutex::new(handler),
        )))?;

        Ok(())
    }
}
