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

use std::cmp::min;
use std::fs::File;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use log::error;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use crate::error::VirtioError;
use crate::{
    ElemIovec, Queue, VirtioBase, VirtioDevice, VirtioInterrupt, VirtioInterruptType,
    VIRTIO_F_VERSION_1, VIRTIO_TYPE_RNG,
};
use address_space::AddressSpace;
use machine_manager::{
    config::{RngConfig, DEFAULT_VIRTQUEUE_SIZE},
    event_loop::EventLoop,
    event_loop::{register_event_helper, unregister_event_helper},
};
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::{ByteCode, Desc};
use util::aio::raw_read;
use util::byte_code::ByteCode;
use util::leak_bucket::LeakBucket;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};

const QUEUE_NUM_RNG: usize = 1;
const RNG_SIZE_MAX: u32 = 1 << 20;

fn get_req_data_size(in_iov: &[ElemIovec]) -> Result<u32> {
    let mut size = 0_u32;
    for iov in in_iov {
        size = match size.checked_add(iov.len) {
            Some(size_) => size_,
            None => bail!("The size of request for virtio rng overflows"),
        };
    }

    size = min(size, RNG_SIZE_MAX);

    Ok(size)
}

struct RngHandler {
    queue: Arc<Mutex<Queue>>,
    queue_evt: Arc<EventFd>,
    interrupt_cb: Arc<VirtioInterrupt>,
    driver_features: u64,
    mem_space: Arc<AddressSpace>,
    random_file: File,
    leak_bucket: Option<LeakBucket>,
}

impl RngHandler {
    fn write_req_data(&self, in_iov: &[ElemIovec], buffer: &mut [u8], size: u32) -> Result<()> {
        let mut offset = 0_usize;
        for iov in in_iov {
            if offset as u32 >= size {
                break;
            }
            self.mem_space
                .write(
                    &mut buffer[offset..].as_ref(),
                    iov.addr,
                    min(size - offset as u32, iov.len) as u64,
                )
                .with_context(|| "Failed to write request data for virtio rng")?;

            offset += iov.len as usize;
        }
        trace::virtio_rng_write_req_data(size);

        Ok(())
    }

    fn process_queue(&mut self) -> Result<()> {
        trace::virtio_receive_request("Rng".to_string(), "to IO".to_string());
        let mut queue_lock = self.queue.lock().unwrap();
        let mut need_interrupt = false;

        while let Ok(elem) = queue_lock
            .vring
            .pop_avail(&self.mem_space, self.driver_features)
        {
            if elem.desc_num == 0 {
                break;
            }
            let mut size =
                get_req_data_size(&elem.in_iovec).with_context(|| "Failed to get request size")?;

            if let Some(leak_bucket) = self.leak_bucket.as_mut() {
                if leak_bucket.throttled(EventLoop::get_ctx(None).unwrap(), size as u64) {
                    queue_lock.vring.push_back();
                    break;
                }
            }

            let mut buffer = vec![0_u8; size as usize];
            let ret = raw_read(
                self.random_file.as_raw_fd(),
                buffer.as_mut_ptr() as u64,
                size as usize,
                0,
            );
            if ret < 0 {
                bail!("Failed to read random file, size: {}", size);
            }
            size = ret as u32;

            self.write_req_data(&elem.in_iovec, &mut buffer, size)?;

            queue_lock
                .vring
                .add_used(&self.mem_space, elem.index, size)
                .with_context(|| {
                    format!(
                        "Failed to add used ring, index: {}, size: {}",
                        elem.index, size
                    )
                })?;

            need_interrupt = true;
        }

        if need_interrupt {
            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue_lock), false)
                .with_context(|| {
                    VirtioError::InterruptTrigger("rng", VirtioInterruptType::Vring)
                })?;
            trace::virtqueue_send_interrupt("Rng", &*queue_lock as *const _ as u64)
        }

        Ok(())
    }
}

impl EventNotifierHelper for RngHandler {
    fn internal_notifiers(rng_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        // Register event notifier for queue_evt
        let rng_handler_clone = rng_handler.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            if let Err(ref e) = rng_handler_clone.lock().unwrap().process_queue() {
                error!("Failed to process queue for virtio rng, err: {:?}", e,);
            }
            None
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            rng_handler.lock().unwrap().queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![handler],
        ));

        // Register timer event notifier for the limit of request bytes per second
        if let Some(lb) = rng_handler.lock().unwrap().leak_bucket.as_ref() {
            let rng_handler_clone = rng_handler.clone();
            let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
                read_fd(fd);
                if let Some(leak_bucket) = rng_handler_clone.lock().unwrap().leak_bucket.as_mut() {
                    leak_bucket.clear_timer();
                }
                if let Err(ref e) = rng_handler_clone.lock().unwrap().process_queue() {
                    error!("Failed to process queue for virtio rng, err: {:?}", e,);
                }
                None
            });
            notifiers.push(EventNotifier::new(
                NotifierOperation::AddShared,
                lb.as_raw_fd(),
                None,
                EventSet::IN,
                vec![handler],
            ));
        }

        notifiers
    }
}

/// State of block device.
#[repr(C)]
#[derive(Clone, Copy, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct RngState {
    /// Bitmask of features supported by the backend.
    device_features: u64,
    /// Bitmask of features negotiated by the backend and the frontend.
    driver_features: u64,
}

/// Random number generator device structure
#[derive(Default)]
pub struct Rng {
    /// Virtio device base property.
    base: VirtioBase,
    /// Configuration of virtio rng device
    rng_cfg: RngConfig,
    /// The file descriptor of random number generator
    random_file: Option<File>,
}

impl Rng {
    pub fn new(rng_cfg: RngConfig) -> Self {
        Rng {
            base: VirtioBase::new(VIRTIO_TYPE_RNG, QUEUE_NUM_RNG, DEFAULT_VIRTQUEUE_SIZE),
            rng_cfg,
            ..Default::default()
        }
    }

    fn check_random_file(&self) -> Result<()> {
        let path = Path::new(&self.rng_cfg.random_file);
        if !path.exists() {
            bail!(
                "The path of random file {} is not existed",
                self.rng_cfg.random_file
            );
        }

        if !path.metadata().unwrap().file_type().is_char_device() {
            bail!(
                "The type of random file {} is not a character special file",
                self.rng_cfg.random_file
            );
        }

        Ok(())
    }
}

impl VirtioDevice for Rng {
    fn virtio_base(&self) -> &VirtioBase {
        &self.base
    }

    fn virtio_base_mut(&mut self) -> &mut VirtioBase {
        &mut self.base
    }

    fn realize(&mut self) -> Result<()> {
        self.check_random_file()
            .with_context(|| "Failed to check random file")?;
        let file = File::open(&self.rng_cfg.random_file)
            .with_context(|| "Failed to open file of random number generator")?;
        self.random_file = Some(file);
        self.init_config_features()?;
        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        self.base.device_features = 1 << VIRTIO_F_VERSION_1 as u64;
        Ok(())
    }

    fn read_config(&self, offset: u64, _data: &mut [u8]) -> Result<()> {
        bail!(
            "Reading device config space for rng is not supported, offset: {}",
            offset
        );
    }

    fn write_config(&mut self, offset: u64, _data: &[u8]) -> Result<()> {
        bail!(
            "Writing device config space for rng is not supported, offset: {}",
            offset
        );
    }

    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let queues = &self.base.queues;
        let handler = RngHandler {
            queue: queues[0].clone(),
            queue_evt: queue_evts[0].clone(),
            interrupt_cb,
            driver_features: self.base.driver_features,
            mem_space,
            random_file: self
                .random_file
                .as_ref()
                .unwrap()
                .try_clone()
                .with_context(|| "Failed to clone random file for virtio rng")?,
            leak_bucket: match self.rng_cfg.bytes_per_sec {
                Some(bps) => Some(LeakBucket::new(bps)?),
                None => None,
            },
        };

        let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler)));
        register_event_helper(notifiers, None, &mut self.base.deactivate_evts)?;

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        unregister_event_helper(None, &mut self.base.deactivate_evts)
    }
}

impl StateTransfer for Rng {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let state = RngState {
            device_features: self.base.device_features,
            driver_features: self.base.driver_features,
        };
        Ok(state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
        let state = RngState::from_bytes(state)
            .with_context(|| migration::error::MigrationError::FromBytesError("RNG"))?;
        self.base.device_features = state.device_features;
        self.base.driver_features = state.driver_features;
        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&RngState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for Rng {}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::mem::size_of;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::*;
    use address_space::{AddressSpace, GuestAddress, HostMemMapping, Region};
    use machine_manager::config::{RngConfig, DEFAULT_VIRTQUEUE_SIZE};

    const VIRTQ_DESC_F_NEXT: u16 = 0x01;
    const VIRTQ_DESC_F_WRITE: u16 = 0x02;
    const SYSTEM_SPACE_SIZE: u64 = (1024 * 1024) as u64;

    // build dummy address space of vm
    fn address_space_init() -> Arc<AddressSpace> {
        let root = Region::init_container_region(1 << 36, "sysmem");
        let sys_space = AddressSpace::new(root, "sysmem", None).unwrap();
        let host_mmap = Arc::new(
            HostMemMapping::new(
                GuestAddress(0),
                None,
                SYSTEM_SPACE_SIZE,
                None,
                false,
                false,
                false,
            )
            .unwrap(),
        );
        sys_space
            .root()
            .add_subregion(
                Region::init_ram_region(host_mmap.clone(), "sysmem"),
                host_mmap.start_address().raw_value(),
            )
            .unwrap();
        sys_space
    }

    #[test]
    fn test_rng_init() {
        let file = TempFile::new().unwrap();
        let random_file = file.as_path().to_str().unwrap().to_string();
        let rng_config = RngConfig {
            id: "".to_string(),
            random_file: random_file.clone(),
            bytes_per_sec: Some(64),
        };
        let rng = Rng::new(rng_config);
        assert!(rng.random_file.is_none());
        assert_eq!(rng.base.driver_features, 0_u64);
        assert_eq!(rng.base.device_features, 0_u64);
        assert_eq!(rng.rng_cfg.random_file, random_file);
        assert_eq!(rng.rng_cfg.bytes_per_sec, Some(64));

        assert_eq!(rng.queue_num(), QUEUE_NUM_RNG);
        assert_eq!(rng.queue_size_max(), DEFAULT_VIRTQUEUE_SIZE);
        assert_eq!(rng.device_type(), VIRTIO_TYPE_RNG);
    }

    #[test]
    fn test_rng_features() {
        let random_file = TempFile::new()
            .unwrap()
            .as_path()
            .to_str()
            .unwrap()
            .to_string();
        let rng_config = RngConfig {
            id: "".to_string(),
            random_file,
            bytes_per_sec: Some(64),
        };
        let mut rng = Rng::new(rng_config);

        // If the device feature is 0, all driver features are not supported.
        rng.base.device_features = 0;
        let driver_feature: u32 = 0xFF;
        let page = 0_u32;
        rng.set_driver_features(page, driver_feature);
        assert_eq!(rng.base.driver_features, 0_u64);
        assert_eq!(rng.driver_features(page) as u64, 0_u64);
        assert_eq!(rng.device_features(0_u32), 0_u32);

        let driver_feature: u32 = 0xFF;
        let page = 1_u32;
        rng.set_driver_features(page, driver_feature);
        assert_eq!(rng.base.driver_features, 0_u64);
        assert_eq!(rng.driver_features(page) as u64, 0_u64);
        assert_eq!(rng.device_features(1_u32), 0_u32);

        // If both the device feature bit and the front-end driver feature bit are
        // supported at the same time, this driver feature bit is supported.
        rng.base.device_features =
            1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_F_RING_INDIRECT_DESC as u64;
        let driver_feature: u32 = 1_u32 << VIRTIO_F_RING_INDIRECT_DESC;
        let page = 0_u32;
        rng.set_driver_features(page, driver_feature);
        assert_eq!(
            rng.base.driver_features,
            (1_u64 << VIRTIO_F_RING_INDIRECT_DESC as u64)
        );
        assert_eq!(
            rng.driver_features(page) as u64,
            (1_u64 << VIRTIO_F_RING_INDIRECT_DESC as u64)
        );
        assert_eq!(
            rng.device_features(page),
            (1_u32 << VIRTIO_F_RING_INDIRECT_DESC)
        );
        rng.base.driver_features = 0;

        rng.base.device_features = 1_u64 << VIRTIO_F_VERSION_1;
        let driver_feature: u32 = 1_u32 << VIRTIO_F_RING_INDIRECT_DESC;
        let page = 0_u32;
        rng.set_driver_features(page, driver_feature);
        assert_eq!(rng.base.driver_features, 0);
        assert_eq!(rng.device_features(page), 0_u32);
        rng.base.driver_features = 0;
    }

    #[test]
    fn test_get_req_data_size() {
        // The size of request overflows
        let in_iov = vec![
            ElemIovec {
                addr: GuestAddress(0_u64),
                len: u32::max_value(),
            },
            ElemIovec {
                addr: GuestAddress(u32::max_value() as u64),
                len: 1_u32,
            },
        ];
        assert!(get_req_data_size(&in_iov).is_err());

        // It is ok to get the size of request
        let len = 1000_u32;
        let in_iov = vec![
            ElemIovec {
                addr: GuestAddress(0_u64),
                len,
            },
            ElemIovec {
                addr: GuestAddress(u32::max_value() as u64),
                len,
            },
        ];
        if let Ok(size) = get_req_data_size(&in_iov) {
            assert_eq!(size, len * 2);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_rng_process_queue_01() {
        let mem_space = address_space_init();
        let interrupt_evt = Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());
        let cloned_interrupt_evt = interrupt_evt.clone();
        let interrupt_status = Arc::new(AtomicU32::new(0));
        let interrupt_cb = Arc::new(Box::new(
            move |int_type: &VirtioInterruptType, _queue: Option<&Queue>, _needs_reset: bool| {
                let status = match int_type {
                    VirtioInterruptType::Config => VIRTIO_MMIO_INT_CONFIG,
                    VirtioInterruptType::Vring => VIRTIO_MMIO_INT_VRING,
                };
                interrupt_status.fetch_or(status, Ordering::SeqCst);
                interrupt_evt
                    .write(1)
                    .with_context(|| VirtioError::EventFdWrite)
            },
        ) as VirtioInterrupt);

        let mut queue_config = QueueConfig::new(DEFAULT_VIRTQUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.addr_cache.desc_table_host =
            mem_space.get_host_address(queue_config.desc_table).unwrap();
        queue_config.avail_ring = GuestAddress(16 * DEFAULT_VIRTQUEUE_SIZE as u64);
        queue_config.addr_cache.avail_ring_host =
            mem_space.get_host_address(queue_config.avail_ring).unwrap();
        queue_config.used_ring = GuestAddress(32 * DEFAULT_VIRTQUEUE_SIZE as u64);
        queue_config.addr_cache.used_ring_host =
            mem_space.get_host_address(queue_config.used_ring).unwrap();
        queue_config.size = DEFAULT_VIRTQUEUE_SIZE;
        queue_config.ready = true;

        let file = TempFile::new().unwrap();
        let mut rng_handler = RngHandler {
            queue: Arc::new(Mutex::new(Queue::new(queue_config, 1).unwrap())),
            queue_evt: Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()),
            interrupt_cb,
            driver_features: 0_u64,
            mem_space: mem_space.clone(),
            random_file: file.into_file(),
            leak_bucket: None,
        };

        let data_len = 64;
        let desc = SplitVringDesc {
            addr: GuestAddress(0x40000),
            len: data_len,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
        // write table descriptor for queue
        mem_space
            .write_object(&desc, queue_config.desc_table)
            .unwrap();
        // write avail_ring idx
        mem_space
            .write_object::<u16>(&0, GuestAddress(queue_config.avail_ring.0 + 4 as u64))
            .unwrap();
        // write avail_ring idx
        mem_space
            .write_object::<u16>(&1, GuestAddress(queue_config.avail_ring.0 + 2 as u64))
            .unwrap();

        let buffer = vec![1_u8; data_len as usize];
        rng_handler.random_file.write(&buffer).unwrap();
        assert!(rng_handler.process_queue().is_ok());
        let mut read_buffer = vec![0_u8; data_len as usize];
        assert!(mem_space
            .read(
                &mut read_buffer.as_mut_slice(),
                GuestAddress(0x40000),
                data_len as u64
            )
            .is_ok());
        assert_eq!(read_buffer, buffer);

        let idx = mem_space
            .read_object::<u16>(GuestAddress(queue_config.used_ring.0 + 2 as u64))
            .unwrap();
        assert_eq!(idx, 1);
        assert_eq!(cloned_interrupt_evt.read().unwrap(), 1);
    }

    #[test]
    fn test_rng_process_queue_02() {
        let mem_space = address_space_init();
        let interrupt_evt = Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());
        let cloned_interrupt_evt = interrupt_evt.clone();
        let interrupt_status = Arc::new(AtomicU32::new(0));
        let interrupt_cb = Arc::new(Box::new(
            move |int_type: &VirtioInterruptType, _queue: Option<&Queue>, _needs_reset: bool| {
                let status = match int_type {
                    VirtioInterruptType::Config => VIRTIO_MMIO_INT_CONFIG,
                    VirtioInterruptType::Vring => VIRTIO_MMIO_INT_VRING,
                };
                interrupt_status.fetch_or(status, Ordering::SeqCst);
                interrupt_evt
                    .write(1)
                    .with_context(|| VirtioError::EventFdWrite)
            },
        ) as VirtioInterrupt);

        let mut queue_config = QueueConfig::new(DEFAULT_VIRTQUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.addr_cache.desc_table_host =
            mem_space.get_host_address(queue_config.desc_table).unwrap();
        queue_config.avail_ring = GuestAddress(16 * DEFAULT_VIRTQUEUE_SIZE as u64);
        queue_config.addr_cache.avail_ring_host =
            mem_space.get_host_address(queue_config.avail_ring).unwrap();
        queue_config.used_ring = GuestAddress(32 * DEFAULT_VIRTQUEUE_SIZE as u64);
        queue_config.addr_cache.used_ring_host =
            mem_space.get_host_address(queue_config.used_ring).unwrap();
        queue_config.size = DEFAULT_VIRTQUEUE_SIZE;
        queue_config.ready = true;

        let file = TempFile::new().unwrap();
        let mut rng_handler = RngHandler {
            queue: Arc::new(Mutex::new(Queue::new(queue_config, 1).unwrap())),
            queue_evt: Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()),
            interrupt_cb,
            driver_features: 0_u64,
            mem_space: mem_space.clone(),
            random_file: file.into_file(),
            leak_bucket: None,
        };

        let data_len = 64;
        let desc = SplitVringDesc {
            addr: GuestAddress(0x40000),
            len: data_len,
            flags: VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
            next: 1,
        };
        // write table descriptor for queue
        mem_space
            .write_object(&desc, queue_config.desc_table)
            .unwrap();

        let desc = SplitVringDesc {
            addr: GuestAddress(0x50000),
            len: data_len,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
        // write table descriptor for queue
        mem_space
            .write_object(
                &desc,
                GuestAddress(queue_config.desc_table.0 + size_of::<SplitVringDesc>() as u64),
            )
            .unwrap();

        // write avail_ring idx
        mem_space
            .write_object::<u16>(&0, GuestAddress(queue_config.avail_ring.0 + 4 as u64))
            .unwrap();
        // write avail_ring idx
        mem_space
            .write_object::<u16>(&1, GuestAddress(queue_config.avail_ring.0 + 2 as u64))
            .unwrap();

        let mut buffer1 = vec![1_u8; data_len as usize];
        let mut buffer2 = vec![2_u8; data_len as usize];
        let buffer1_check = vec![1_u8; data_len as usize];
        let buffer2_check = vec![2_u8; data_len as usize];
        buffer1.append(&mut buffer2);
        rng_handler.random_file.write(&buffer1).unwrap();

        assert!(rng_handler.process_queue().is_ok());
        let mut read_buffer = vec![0_u8; data_len as usize];
        assert!(mem_space
            .read(
                &mut read_buffer.as_mut_slice(),
                GuestAddress(0x40000),
                data_len as u64
            )
            .is_ok());
        assert_eq!(read_buffer, buffer1_check);
        assert!(mem_space
            .read(
                &mut read_buffer.as_mut_slice(),
                GuestAddress(0x50000),
                data_len as u64
            )
            .is_ok());
        assert_eq!(read_buffer, buffer2_check);

        let idx = mem_space
            .read_object::<u16>(GuestAddress(queue_config.used_ring.0 + 2 as u64))
            .unwrap();
        assert_eq!(idx, 1);
        assert_eq!(cloned_interrupt_evt.read().unwrap(), 1);
    }
}
