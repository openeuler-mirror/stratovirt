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
use machine_manager::{config::ConsoleConfig, event_loop::EventLoop, temp_cleaner::TempCleaner};
use util::byte_code::ByteCode;
use util::loop_context::{read_fd, EventNotifier, EventNotifierHelper, NotifierOperation};
use util::num_ops::{read_u32, write_u32};
use util::unix::limit_permission;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

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
                    Err(ref e) => {
                        error!(
                            "Failed to write slice for input console: addr {:X} len {} {}",
                            elem_iov.addr.0,
                            source_slice.len(),
                            error_chain::ChainedError::display_chain(e)
                        );
                        break;
                    }
                }
            }

            if let Err(ref e) =
                queue_lock
                    .vring
                    .add_used(&self.mem_space, elem.index, write_count as u32)
            {
                error!(
                    "Failed to add used ring for input console, index: {} len: {} {}",
                    elem.index,
                    write_count,
                    error_chain::ChainedError::display_chain(e)
                );
                break;
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
                    Err(ref e) => {
                        error!(
                            "Failed to read buffer for output console: addr: {:X}, len: {} {}",
                            elem_iov.addr.0,
                            allow_read_count - read_count,
                            error_chain::ChainedError::display_chain(e)
                        );
                        break;
                    }
                };
            }

            if let Some(mut client) = self.client.as_ref() {
                if let Err(e) = client.write(&buffer[..read_count as usize]) {
                    error!("Failed to write console output: {}.", e);
                };
            }

            if let Err(ref e) = queue_lock.vring.add_used(&self.mem_space, elem.index, 0) {
                error!(
                    "Failed to add used ring for output console, index: {} len: {} {}",
                    elem.index,
                    0,
                    error_chain::ChainedError::display_chain(e)
                );
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
    listener: Option<UnixListener>,
    /// Path to console socket file.
    path: String,
}

impl Console {
    /// Create a virtio-console device.
    ///
    /// # Arguments
    ///
    /// * `console_cfg` - Device configuration set by user.
    pub fn new(console_cfg: ConsoleConfig) -> Self {
        let path = console_cfg.socket_path;
        Console {
            config: Arc::new(Mutex::new(VirtioConsoleConfig::new())),
            device_features: 0_u64,
            driver_features: 0_u64,
            listener: None,
            path,
        }
    }
}

impl VirtioDevice for Console {
    /// Realize virtio console device.
    fn realize(&mut self) -> Result<()> {
        self.device_features = 1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_CONSOLE_F_SIZE;
        let sock = UnixListener::bind(self.path.clone())
            .chain_err(|| format!("Failed to bind socket for console, path:{}", &self.path))?;
        self.listener = Some(sock);

        // add file to temporary pool, so it could be clean when vm exit.
        TempCleaner::add_path(self.path.clone());

        limit_permission(&self.path).chain_err(|| {
            format!(
                "Failed to change file permission for console, path:{}",
                &self.path
            )
        })?;

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
            warn!("Received acknowledge request with unknown feature for console.");
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
        bail!("Device config space for console is not supported")
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

        if self.listener.is_none() {
            bail!("The console socket is empty");
        }

        let handler = ConsoleHandler {
            input_queue: queues.remove(0),
            output_queue: queues.remove(0),
            output_queue_evt: queue_evts.remove(0),
            mem_space,
            interrupt_evt: interrupt_evt.try_clone()?,
            interrupt_status,
            driver_features: self.driver_features,
            listener: self.listener.as_ref().unwrap().try_clone()?,
            client: None,
        };

        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler))),
            None,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    pub use super::super::*;
    pub use super::*;
    use std::fs::remove_file;
    use std::mem::size_of;

    #[test]
    fn test_set_driver_features() {
        let console_cfg = ConsoleConfig {
            console_id: "console".to_string(),
            socket_path: "test_console.sock".to_string(),
        };
        let mut console = Console::new(console_cfg);
        assert!(console.realize().is_ok());

        //If the device feature is 0, all driver features are not supported.
        console.device_features = 0;
        let driver_feature: u32 = 0xFF;
        let page = 0_u32;
        console.set_driver_features(page, driver_feature);
        assert_eq!(console.driver_features, 0_u64);

        let driver_feature: u32 = 0xFF;
        let page = 1_u32;
        console.set_driver_features(page, driver_feature);
        assert_eq!(console.driver_features, 0_u64);

        //If both the device feature bit and the front-end driver feature bit are
        //supported at the same time,  this driver feature bit is supported.
        console.device_features = 1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_CONSOLE_F_SIZE;
        let driver_feature: u32 = (1_u64 << VIRTIO_CONSOLE_F_SIZE) as u32;
        let page = 0_u32;
        console.set_driver_features(page, driver_feature);
        assert_eq!(console.driver_features, (1_u64 << VIRTIO_CONSOLE_F_SIZE));
        console.driver_features = 0;

        console.device_features = 1_u64 << VIRTIO_F_VERSION_1;
        let driver_feature: u32 = (1_u64 << VIRTIO_CONSOLE_F_SIZE) as u32;
        let page = 0_u32;
        console.set_driver_features(page, driver_feature);
        assert_eq!(console.driver_features, 0);
        console.driver_features = 0;

        console.device_features = 1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_CONSOLE_F_SIZE;
        let driver_feature: u32 = (1_u64 << VIRTIO_CONSOLE_F_SIZE) as u32;
        let page = 0_u32;
        console.set_driver_features(page, driver_feature);
        assert_eq!(console.driver_features, (1_u64 << VIRTIO_CONSOLE_F_SIZE));

        let driver_feature: u32 = ((1_u64 << VIRTIO_F_VERSION_1) >> 32) as u32;
        let page = 1_u32;
        console.set_driver_features(page, driver_feature);
        assert_eq!(
            console.driver_features,
            (1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_CONSOLE_F_SIZE)
        );

        //Clean up the test environment
        remove_file("test_console.sock").unwrap();
    }

    #[test]
    fn test_read_config() {
        let console_cfg = ConsoleConfig {
            console_id: "console".to_string(),
            socket_path: "test_console1.sock".to_string(),
        };

        let mut console = Console::new(console_cfg);
        assert!(console.realize().is_ok());

        //The offset of configuration that needs to be read exceeds the maximum
        let offset = size_of::<VirtioConsoleConfig>() as u64;
        let mut read_data: Vec<u8> = vec![0; 8];
        assert_eq!(console.read_config(offset, &mut read_data).is_ok(), false);

        //Check the configuration that needs to be read
        let offset = 0_u64;
        let mut read_data: Vec<u8> = vec![0; 8];
        let expect_data: Vec<u8> = vec![1, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(console.read_config(offset, &mut read_data).is_ok(), true);
        assert_eq!(read_data, expect_data);

        let offset = 0_u64;
        let mut read_data: Vec<u8> = vec![0; 1];
        let expect_data: Vec<u8> = vec![1];
        assert_eq!(console.read_config(offset, &mut read_data).is_ok(), true);
        assert_eq!(read_data, expect_data);

        //Clean up the test environment
        remove_file("test_console1.sock").unwrap();
    }
}
