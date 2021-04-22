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

use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use address_space::AddressSpace;
use machine_manager::{config::RngConfig, event_loop::EventLoop};
use util::aio::raw_read;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::num_ops::{read_u32, write_u32};

use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use super::errors::{ErrorKind, Result, ResultExt};
use super::{
    ElemIovec, Queue, VirtioDevice, VIRTIO_F_VERSION_1, VIRTIO_MMIO_INT_VRING, VIRTIO_TYPE_RNG,
};

const QUEUE_NUM_RNG: usize = 1;
const QUEUE_SIZE_RNG: u16 = 256;

fn get_req_data_size(in_iov: &[ElemIovec]) -> Result<u32> {
    let mut size = 0_u32;
    for iov in in_iov {
        size = match size.checked_add(iov.len) {
            Some(size_) => size_,
            None => bail!("The size of request for virtio rng overflows"),
        };
    }

    Ok(size)
}

struct RngHandler {
    queue: Arc<Mutex<Queue>>,
    queue_evt: EventFd,
    interrupt_evt: EventFd,
    interrupt_status: Arc<AtomicU32>,
    driver_features: u64,
    mem_space: Arc<AddressSpace>,
    random_file: File,
}

impl RngHandler {
    fn write_req_data(&self, in_iov: &[ElemIovec], buffer: &mut [u8]) -> Result<()> {
        let mut offset = 0_usize;
        for iov in in_iov {
            self.mem_space
                .write(&mut buffer[offset..].as_ref(), iov.addr, iov.len as u64)
                .chain_err(|| "Failed to write request data for virtio rng")?;
            offset += iov.len as usize;
        }

        Ok(())
    }
    fn process_queue(&mut self) -> Result<()> {
        let mut queue_lock = self.queue.lock().unwrap();
        let mut need_interrupt = false;

        while let Ok(elem) = queue_lock
            .vring
            .pop_avail(&self.mem_space, self.driver_features)
        {
            let size =
                get_req_data_size(&elem.in_iovec).chain_err(|| "Failed to get request size")?;
            let mut buffer = vec![0_u8; size as usize];
            raw_read(
                self.random_file.as_raw_fd(),
                buffer.as_mut_ptr() as u64,
                size as usize,
                0,
            )
            .chain_err(|| format!("Failed to read random file, size: {}", size))?;

            self.write_req_data(&elem.in_iovec, &mut buffer)?;

            queue_lock
                .vring
                .add_used(&self.mem_space, elem.index, size)
                .chain_err(|| {
                    format!(
                        "Failed to add used ring, index: {}, size: {}",
                        elem.index, size
                    )
                })?;

            need_interrupt = true;
        }

        if need_interrupt {
            self.interrupt_status
                .fetch_or(VIRTIO_MMIO_INT_VRING, Ordering::SeqCst);
            self.interrupt_evt
                .write(1)
                .chain_err(|| ErrorKind::EventFdWrite)?;
        }

        Ok(())
    }
}

impl EventNotifierHelper for RngHandler {
    fn internal_notifiers(rng_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        // Register event notifier for queue_evt
        let rng_handler_clone = rng_handler.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);

            if let Err(ref e) = rng_handler_clone.lock().unwrap().process_queue() {
                error!(
                    "Failed to process queue for virtio rng, err: {}",
                    error_chain::ChainedError::display_chain(e),
                );
            }

            None
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            rng_handler.lock().unwrap().queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![Arc::new(Mutex::new(handler))],
        ));

        notifiers
    }
}

/// Random number generator device structure
pub struct Rng {
    /// Configuration of virtio rng device
    rng_cfg: RngConfig,
    /// The file descriptor of random number generator
    random_file: Option<File>,
    /// Bit mask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
}

impl Rng {
    #[allow(dead_code)]
    pub fn new(rng_cfg: RngConfig) -> Self {
        Rng {
            rng_cfg,
            random_file: None,
            device_features: 0,
            driver_features: 0,
        }
    }
}

impl VirtioDevice for Rng {
    /// Realize virtio network device.
    fn realize(&mut self) -> Result<()> {
        let file = File::open(&self.rng_cfg.random_file)
            .chain_err(|| "Failed to open file of random number generator")?;

        self.random_file = Some(file);
        self.device_features = 1 << VIRTIO_F_VERSION_1 as u64;
        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_RNG
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        QUEUE_NUM_RNG
    }

    /// Get the queue size of virtio device.
    fn queue_size(&self) -> u16 {
        QUEUE_SIZE_RNG
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
            warn!("Received acknowledge request with unknown feature: {:x}", v);
            v &= !unrequested_features;
        }
        self.driver_features |= v;
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, _data: &mut [u8]) -> Result<()> {
        bail!(
            "Reading device config space for rng is not supported, offset: {}",
            offset
        );
    }

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, _data: &[u8]) -> Result<()> {
        bail!(
            "Writing device config space for rng is not supported, offset: {}",
            offset
        );
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
        let handler = RngHandler {
            queue: queues.remove(0),
            queue_evt: queue_evts.remove(0),
            interrupt_evt: interrupt_evt
                .try_clone()
                .chain_err(|| "Failed to clone interrupt eventfd for virtio rng")?,
            interrupt_status,
            driver_features: self.driver_features,
            mem_space,
            random_file: self
                .random_file
                .as_ref()
                .unwrap()
                .try_clone()
                .chain_err(|| "Failed to clone random file for virtio rng")?,
        };

        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler))),
            None,
        )?;

        Ok(())
    }
}
