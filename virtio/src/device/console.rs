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

use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::{cmp, usize};

use crate::{
    Queue, VirtioDevice, VirtioError, VirtioInterrupt, VirtioInterruptType, VirtioTrace,
    VIRTIO_CONSOLE_F_SIZE, VIRTIO_F_VERSION_1, VIRTIO_TYPE_CONSOLE,
};
use address_space::AddressSpace;
use anyhow::{anyhow, bail, Context, Result};
use devices::legacy::{Chardev, InputReceiver};
use log::{debug, error};
use machine_manager::{
    config::{VirtioConsole, DEFAULT_VIRTQUEUE_SIZE},
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
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

/// Number of virtqueues.
const QUEUE_NUM_CONSOLE: usize = 2;

const BUFF_SIZE: usize = 4096;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioConsoleConfig {
    cols: u16,
    rows: u16,
    max_nr_ports: u32,
    emerg_wr: u32,
}

impl ByteCode for VirtioConsoleConfig {}

impl VirtioConsoleConfig {
    /// Create configuration of virtio-console devices.
    pub fn new() -> Self {
        VirtioConsoleConfig {
            cols: 0_u16,
            rows: 0_u16,
            max_nr_ports: 1_u32,
            emerg_wr: 0_u32,
        }
    }
}

struct ConsoleHandler {
    input_queue: Arc<Mutex<Queue>>,
    output_queue: Arc<Mutex<Queue>>,
    output_queue_evt: Arc<EventFd>,
    mem_space: Arc<AddressSpace>,
    interrupt_cb: Arc<VirtioInterrupt>,
    driver_features: u64,
    chardev: Arc<Mutex<Chardev>>,
}

impl InputReceiver for ConsoleHandler {
    #[allow(clippy::useless_asref)]
    fn input_handle(&mut self, buffer: &[u8]) {
        let mut queue_lock = self.input_queue.lock().unwrap();

        let count = buffer.len();
        if count == 0 {
            return;
        }

        while let Ok(elem) = queue_lock
            .vring
            .pop_avail(&self.mem_space, self.driver_features)
        {
            if elem.desc_num == 0 {
                break;
            }
            let mut write_count = 0_usize;
            for elem_iov in elem.in_iovec.iter() {
                let allow_write_count = cmp::min(write_count + elem_iov.len as usize, count);
                let source_slice = &buffer[write_count..allow_write_count];

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
                            "Failed to write slice for input console: addr {:X} len {} {:?}",
                            elem_iov.addr.0,
                            source_slice.len(),
                            e
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
                    "Failed to add used ring for input console, index: {} len: {} {:?}",
                    elem.index, write_count, e
                );
                break;
            }

            if write_count >= count {
                break;
            }
        }

        if let Err(ref e) =
            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue_lock), false)
        {
            error!(
                "Failed to trigger interrupt for console, int-type {:?} {:?} ",
                VirtioInterruptType::Vring,
                e
            )
        }
    }

    fn get_remain_space_size(&mut self) -> usize {
        BUFF_SIZE
    }
}

impl ConsoleHandler {
    fn output_handle(&mut self) {
        self.trace_request("Console".to_string(), "to IO".to_string());
        let mut queue_lock = self.output_queue.lock().unwrap();
        let mut buffer = [0_u8; 4096];

        while let Ok(elem) = queue_lock
            .vring
            .pop_avail(&self.mem_space, self.driver_features)
        {
            if elem.desc_num == 0 {
                break;
            }
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
                            "Failed to read buffer for output console: addr: {:X}, len: {} {:?}",
                            elem_iov.addr.0,
                            allow_read_count - read_count,
                            e
                        );
                        break;
                    }
                };
            }
            if let Some(output) = &mut self.chardev.lock().unwrap().output {
                let mut locked_output = output.lock().unwrap();
                if let Err(e) = locked_output.write_all(&buffer[..read_count]) {
                    error!("Failed to write to console output: {:?}", e);
                }
                if let Err(e) = locked_output.flush() {
                    error!("Failed to flush console output: {:?}", e);
                }
            } else {
                debug!("Failed to get output fd");
            }

            if let Err(ref e) = queue_lock.vring.add_used(&self.mem_space, elem.index, 0) {
                error!(
                    "Failed to add used ring for output console, index: {} len: {} {:?}",
                    elem.index, 0, e
                );
                break;
            }
        }
    }
}

impl EventNotifierHelper for ConsoleHandler {
    fn internal_notifiers(console_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        let cloned_cls = console_handler.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            cloned_cls.lock().unwrap().output_handle();
            None
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            console_handler.lock().unwrap().output_queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![handler],
        ));

        notifiers
    }
}

/// Status of console device.
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct VirtioConsoleState {
    /// Bit mask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Virtio Console config space.
    config_space: VirtioConsoleConfig,
}

/// Virtio console device structure.
pub struct Console {
    /// Status of console device.
    state: VirtioConsoleState,
    /// EventFd for device deactivate.
    deactivate_evts: Vec<RawFd>,
    /// Character device for redirection.
    chardev: Arc<Mutex<Chardev>>,
}

impl Console {
    /// Create a virtio-console device.
    ///
    /// # Arguments
    ///
    /// * `console_cfg` - Device configuration set by user.
    pub fn new(console_cfg: VirtioConsole) -> Self {
        Console {
            state: VirtioConsoleState {
                device_features: 0_u64,
                driver_features: 0_u64,
                config_space: VirtioConsoleConfig::new(),
            },
            deactivate_evts: Vec::new(),
            chardev: Arc::new(Mutex::new(Chardev::new(console_cfg.chardev))),
        }
    }
}

impl VirtioDevice for Console {
    /// Realize virtio console device.
    fn realize(&mut self) -> Result<()> {
        self.state.device_features = 1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_CONSOLE_F_SIZE;
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
        bail!("Device config space for console is not supported")
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
        let handler = ConsoleHandler {
            input_queue: queues[0].clone(),
            output_queue: queues[1].clone(),
            // input_queue_evt never used
            output_queue_evt: queue_evts[1].clone(),
            mem_space,
            interrupt_cb,
            driver_features: self.state.driver_features,
            chardev: self.chardev.clone(),
        };

        let dev = Arc::new(Mutex::new(handler));
        let notifiers = EventNotifierHelper::internal_notifiers(dev.clone());
        register_event_helper(notifiers, None, &mut self.deactivate_evts)?;

        self.chardev.lock().unwrap().set_input_callback(&dev);
        self.chardev.lock().unwrap().deactivated = false;
        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        self.chardev.lock().unwrap().deactivated = true;
        unregister_event_helper(None, &mut self.deactivate_evts)
    }
}

impl StateTransfer for Console {
    fn get_state_vec(&self) -> migration::Result<Vec<u8>> {
        Ok(self.state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> migration::Result<()> {
        self.state = *VirtioConsoleState::from_bytes(state)
            .ok_or_else(|| anyhow!(migration::error::MigrationError::FromBytesError("CONSOLE")))?;

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        if let Some(alias) =
            MigrationManager::get_desc_alias(&VirtioConsoleState::descriptor().name)
        {
            alias
        } else {
            !0
        }
    }
}

impl MigrationHook for Console {}

impl VirtioTrace for ConsoleHandler {}

#[cfg(test)]
mod tests {
    pub use super::super::*;
    pub use super::*;
    use std::mem::size_of;

    use machine_manager::config::{ChardevConfig, ChardevType};

    #[test]
    fn test_set_driver_features() {
        let chardev_cfg = ChardevConfig {
            id: "chardev".to_string(),
            backend: ChardevType::Stdio,
        };
        let mut console = Console::new(VirtioConsole {
            id: "console".to_string(),
            chardev: chardev_cfg.clone(),
        });
        let mut chardev = Chardev::new(chardev_cfg);
        chardev.output = Some(Arc::new(Mutex::new(std::io::stdout())));
        console.chardev = Arc::new(Mutex::new(chardev));

        //If the device feature is 0, all driver features are not supported.
        console.state.device_features = 0;
        let driver_feature: u32 = 0xFF;
        let page = 0_u32;
        console.set_driver_features(page, driver_feature);
        assert_eq!(console.state.driver_features, 0_u64);
        assert_eq!(console.get_driver_features(page) as u64, 0_u64);

        let driver_feature: u32 = 0xFF;
        let page = 1_u32;
        console.set_driver_features(page, driver_feature);
        assert_eq!(console.state.driver_features, 0_u64);
        assert_eq!(console.get_driver_features(page) as u64, 0_u64);

        //If both the device feature bit and the front-end driver feature bit are
        //supported at the same time,  this driver feature bit is supported.
        console.state.device_features =
            1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_CONSOLE_F_SIZE;
        let driver_feature: u32 = (1_u64 << VIRTIO_CONSOLE_F_SIZE) as u32;
        let page = 0_u32;
        console.set_driver_features(page, driver_feature);
        assert_eq!(
            console.state.driver_features,
            (1_u64 << VIRTIO_CONSOLE_F_SIZE)
        );
        assert_eq!(
            console.get_driver_features(page) as u64,
            (1_u64 << VIRTIO_CONSOLE_F_SIZE)
        );
        console.state.driver_features = 0;

        console.state.device_features = 1_u64 << VIRTIO_F_VERSION_1;
        let driver_feature: u32 = (1_u64 << VIRTIO_CONSOLE_F_SIZE) as u32;
        let page = 0_u32;
        console.set_driver_features(page, driver_feature);
        assert_eq!(console.state.driver_features, 0);
        console.state.driver_features = 0;

        console.state.device_features =
            1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_CONSOLE_F_SIZE;
        let driver_feature: u32 = (1_u64 << VIRTIO_CONSOLE_F_SIZE) as u32;
        let page = 0_u32;
        console.set_driver_features(page, driver_feature);
        assert_eq!(
            console.state.driver_features,
            (1_u64 << VIRTIO_CONSOLE_F_SIZE)
        );

        let driver_feature: u32 = ((1_u64 << VIRTIO_F_VERSION_1) >> 32) as u32;
        let page = 1_u32;
        console.set_driver_features(page, driver_feature);
        assert_eq!(
            console.state.driver_features,
            (1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_CONSOLE_F_SIZE)
        );
    }

    #[test]
    fn test_read_config() {
        let chardev_cfg = ChardevConfig {
            id: "chardev".to_string(),
            backend: ChardevType::Stdio,
        };
        let mut console = Console::new(VirtioConsole {
            id: "console".to_string(),
            chardev: chardev_cfg.clone(),
        });
        let mut chardev = Chardev::new(chardev_cfg);
        chardev.output = Some(Arc::new(Mutex::new(std::io::stdout())));
        console.chardev = Arc::new(Mutex::new(chardev));

        //The offset of configuration that needs to be read exceeds the maximum
        let offset = size_of::<VirtioConsoleConfig>() as u64;
        let mut read_data: Vec<u8> = vec![0; 8];
        assert_eq!(console.read_config(offset, &mut read_data).is_ok(), false);

        //Check the configuration that needs to be read
        let offset = 0_u64;
        let mut read_data: Vec<u8> = vec![0; 12];
        let expect_data: Vec<u8> = vec![0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(console.read_config(offset, &mut read_data).is_ok(), true);
        assert_eq!(read_data, expect_data);

        let offset = 4_u64;
        let mut read_data: Vec<u8> = vec![0; 1];
        let expect_data: Vec<u8> = vec![1];
        assert_eq!(console.read_config(offset, &mut read_data).is_ok(), true);
        assert_eq!(read_data, expect_data);
    }
}
