// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
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
use std::os::fd::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Parser};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use crate::{
    alloc_base_addr, iov_read_object, iov_write_object, read_config_default, report_virtio_error,
    Queue, VirtioBase, VirtioDevice, VirtioError, VirtioInterrupt, VirtioInterruptType,
    INVALID_ADDR, VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_VERSION_1, VIRTIO_TYPE_PMEM,
};
use address_space::{AddressSpace, GuestAddress, HostMemMapping, Region};
use machine_manager::config::{
    get_pci_df, parse_bool, valid_id, MemBackendObjConfig, MemoryBackend, DEFAULT_VIRTQUEUE_SIZE,
    MEM_BACKEND_TYPE_FILE,
};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use migration::{
    DeviceStateDesc, MigrationError, MigrationHook, MigrationManager, MigrationStatus,
    StateTransfer,
};
use migration_derive::DescSerde;
use util::aio::{wait_io_done, IoRef, DEFAULT_IO_TIMEOUT};
use util::byte_code::ByteCode;
use util::gen_base_func;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::unix::do_mmap;

const VIRTIO_PMEM_BLOCK_SIZE: u64 = 0x20_0000;

const VIRTIO_PMEM_REQ_FLUSH: u32 = 0;
const VIRTIO_PMEM_RESP_OK: i32 = 0;
const VIRTIO_PMEM_RESP_FAIL: i32 = -1;

const QUEUE_NUM_PMEM: usize = 1;

#[derive(Parser, Debug, Clone, Default)]
#[command(no_binary_name(true))]
pub struct VirtioPmemDevConfig {
    #[arg(long, value_parser = ["virtio-pmem-pci", "virtio-pmem-device"])]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub bus: Option<String>,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: Option<(u8, u8)>,
    #[arg(long, value_parser = parse_bool, action = ArgAction::Append)]
    pub multifunction: Option<bool>,
    #[arg(long)]
    pub memaddr: Option<u64>,
    #[arg(long)]
    pub memdev: String,
}

#[derive(Default, Clone)]
struct VirtioPmemReq {
    type_: u32,
}

impl ByteCode for VirtioPmemReq {}

struct PmemIoHandler {
    /// The virtqueue.
    queue: Arc<Mutex<Queue>>,
    /// Eventfd of the virtqueue for IO event.
    queue_evt: Arc<EventFd>,
    /// The address space to which the device belongs.
    mem_space: Arc<AddressSpace>,
    /// Bit mask of features negotiated by the backend and the frontend
    driver_features: u64,
    /// Virtio mem device is broken or not.
    device_broken: Arc<AtomicBool>,
    /// Interrupt callback function.
    interrupt_cb: Arc<VirtioInterrupt>,
    /// The backend file.
    file: Arc<File>,
    /// If the vm is doing memory snapshot.
    migrating: Arc<AtomicBool>,
    /// Indicate if IO is inflight.
    io_inflight: IoRef,
}

impl PmemIoHandler {
    fn process_queue(&self) -> Result<()> {
        loop {
            if self.migrating.load(Ordering::SeqCst) {
                break;
            }

            let mut locked_queue = self.queue.lock().unwrap();
            let elem = locked_queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
                .with_context(|| "Failed to pop avail ring for process pmem queue")?;
            if elem.desc_num == 0 {
                break;
            }

            // Handle req from guest.
            let pmem_req = iov_read_object::<VirtioPmemReq>(
                &self.mem_space,
                &elem.out_iovec,
                locked_queue.vring.get_cache(),
            )?;
            let ret = if pmem_req.type_ == VIRTIO_PMEM_REQ_FLUSH {
                if let Err(e) = self.file.sync_all() {
                    error!("Virtio pmem flush failed: {:?}", e);
                    VIRTIO_PMEM_RESP_FAIL
                } else {
                    VIRTIO_PMEM_RESP_OK
                }
            } else {
                error!("Invalid virtio pmem request type {}", pmem_req.type_);
                VIRTIO_PMEM_RESP_FAIL
            };

            // Send resp to guest.
            iov_write_object(
                &self.mem_space,
                &elem.in_iovec,
                locked_queue.vring.get_cache(),
                ret,
            )?;
            locked_queue
                .vring
                .add_used(elem.index, size_of::<i32>() as u32)
                .with_context(|| "Failed to add pmem response into used queue")?;
            if locked_queue.vring.should_notify(self.driver_features) {
                (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&locked_queue), false)
                    .with_context(|| {
                        VirtioError::InterruptTrigger("pmem", VirtioInterruptType::Vring)
                    })?
            }
        }
        Ok(())
    }
}

impl EventNotifierHelper for PmemIoHandler {
    fn internal_notifiers(pmem_io: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let evt_fd = pmem_io.lock().unwrap().queue_evt.as_raw_fd();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let locked_pmem_io = pmem_io.lock().unwrap();
            if locked_pmem_io.device_broken.load(Ordering::SeqCst) {
                return None;
            }
            let _inflight = locked_pmem_io.io_inflight.inc_ref();
            if let Err(e) = locked_pmem_io.process_queue() {
                error!("Failed to process pmem queue: {:?}", e);
                report_virtio_error(
                    locked_pmem_io.interrupt_cb.clone(),
                    locked_pmem_io.driver_features,
                    &locked_pmem_io.device_broken,
                );
            };
            None
        });

        vec![EventNotifier::new(
            NotifierOperation::AddShared,
            evt_fd,
            None,
            EventSet::IN,
            vec![handler],
        )]
    }
}

#[derive(Default, Copy, Clone, Serialize, Deserialize)]
struct VirtioPmemConfig {
    start: u64,
    _size: u64,
}

impl ByteCode for VirtioPmemConfig {}

#[derive(Default)]
pub struct Pmem {
    /// Virtio device base property.
    base: VirtioBase,
    /// Virtio mem device id
    id: String,
    /// Configuration space of virtio pmem device.
    config: VirtioPmemConfig,
    /// Memory backend.
    backend: MemoryBackend,
    /// The address space to which the device belongs.
    mem_space: Option<Arc<AddressSpace>>,
    /// The memory subregion belongs to this device.
    mem_region: Option<Region>,
    /// Interrupt callback function.
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    /// If the vm is doing memory snapshot.
    migrating: Arc<AtomicBool>,
    /// Indicate if IO is inflight.
    io_inflight: IoRef,
    /// The queue notify events for handling IO.
    queue_evts: Arc<Mutex<Vec<Arc<EventFd>>>>,
}

impl Pmem {
    pub fn new(config: VirtioPmemDevConfig, memobj: MemBackendObjConfig) -> Self {
        info!("virtio-pmem: new Config {:?}", config);
        let pmem_config = VirtioPmemConfig {
            start: alloc_base_addr(config.memaddr, memobj.size, VIRTIO_PMEM_BLOCK_SIZE),
            _size: memobj.size,
        };
        Self {
            base: VirtioBase::new(VIRTIO_TYPE_PMEM, QUEUE_NUM_PMEM, DEFAULT_VIRTQUEUE_SIZE),
            id: config.id.clone(),
            config: pmem_config,
            backend: MemoryBackend::new(memobj),
            mem_space: None,
            mem_region: None,
            interrupt_cb: None,
            migrating: Arc::new(AtomicBool::new(false)),
            io_inflight: IoRef::default(),
            queue_evts: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl VirtioDevice for Pmem {
    gen_base_func!(virtio_base, virtio_base_mut, VirtioBase, base);

    fn realize(&mut self) -> Result<()> {
        if self.config.start == INVALID_ADDR {
            bail!("Invalid maddr configuration options");
        }
        if !self.config.start.is_multiple_of(VIRTIO_PMEM_BLOCK_SIZE) {
            bail!(
                "Guest address should align to 2MB for virtio-pmem@{}",
                self.id
            );
        }
        if self.backend.mb_type != MEM_BACKEND_TYPE_FILE {
            bail!("Need file backend for virtio-pmem@{}", self.id);
        }
        if !self.backend.size.is_multiple_of(VIRTIO_PMEM_BLOCK_SIZE) {
            bail!("File size should align to 2MB for virtio-pmem@{}", self.id);
        }

        self.backend.realize()?;
        self.init_config_features()?;
        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        self.base.device_features = 1u64 << VIRTIO_F_VERSION_1 | 1u64 << VIRTIO_F_RING_EVENT_IDX;
        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        MigrationManager::unregister_device_instance(PmemState::descriptor(), &self.id);
        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        read_config_default(self.config.as_bytes(), offset, data)?;
        Ok(())
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        warn!(
            "virtio-pmem write config: offset = {}, data = {:?}",
            offset, data
        );
        Ok(())
    }

    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        info!("virtio-pmem@{} activate", self.id);
        let queues = &self.base.queues;
        if queues.len() != self.queue_num() {
            return Err(anyhow!(VirtioError::IncorrectQueueNum(
                self.queue_num(),
                queues.len()
            )));
        }
        self.mem_space = Some(mem_space.clone());
        self.interrupt_cb = Some(interrupt_cb.clone());
        self.queue_evts.lock().unwrap().push(queue_evts[0].clone());

        let host_addr = match &self.backend.backend {
            Some(file) => do_mmap(
                &Some(file.as_ref()),
                self.backend.size,
                0,
                false,
                self.backend.share,
                false,
            )?,
            None => bail!("No file opened for virtio-pmem@{}", self.id),
        };
        let mapping = Arc::new(
            HostMemMapping::new(
                GuestAddress(0),
                Some(host_addr),
                self.backend.size,
                None,
                false,
                self.backend.share,
                false,
            )
            .unwrap(),
        );
        let region = Region::init_ram_region(mapping, format!("viopmem@{}", self.id).as_str());
        self.mem_region = Some(region.clone());
        mem_space.root().add_subregion(region, self.config.start)?;

        let handler = PmemIoHandler {
            queue: queues[0].clone(),
            queue_evt: queue_evts[0].clone(),
            mem_space,
            driver_features: self.base.driver_features,
            device_broken: self.base.broken.clone(),
            interrupt_cb: interrupt_cb.clone(),
            file: self.backend.backend.clone().unwrap(),
            migrating: self.migrating.clone(),
            io_inflight: self.io_inflight.clone(),
        };

        let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler)));
        register_event_helper(notifiers, None, &mut self.base.deactivate_evts)
            .with_context(|| "Failed to register pmem event notifier to MainLoop")?;
        self.base.broken.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        info!("virtio-pmem@{} deactivate", self.id);
        unregister_event_helper(None, &mut self.base.deactivate_evts)?;
        if let Some(mem_space) = &self.mem_space {
            if let Some(mem_region) = self.mem_region.take() {
                mem_space.root().delete_subregion(&mem_region)?;
            }
        }
        self.queue_evts.lock().unwrap().clear();
        Ok(())
    }
}

/// State of block device.
#[derive(Clone, Copy, DescSerde, Serialize, Deserialize)]
#[desc_version(current_version = "0.1.0")]
pub struct PmemState {
    /// Bitmask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Device broken status.
    broken: bool,
    /// Config space of the pmem device.
    config: VirtioPmemConfig,
}

impl StateTransfer for Pmem {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let state = PmemState {
            device_features: self.base.device_features,
            driver_features: self.base.driver_features,
            broken: self.base.broken.load(Ordering::SeqCst),
            config: self.config,
        };
        Ok(serde_json::to_vec(&state)?)
    }

    fn set_state_mut(&mut self, state: &[u8], _version: u32) -> Result<()> {
        let state: PmemState = serde_json::from_slice(state)
            .with_context(|| MigrationError::FromBytesError("Pmem"))?;
        self.base.device_features = state.device_features;
        self.base.driver_features = state.driver_features;
        self.base.broken.store(state.broken, Ordering::SeqCst);
        self.config = state.config;
        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&PmemState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for Pmem {
    fn resume(&mut self) -> Result<()> {
        let locked_evts = self.queue_evts.lock().unwrap();
        for evt in locked_evts.iter() {
            if let Err(e) = evt.write(1) {
                error!("Failed to trigger queue event {}, {:?}", evt.as_raw_fd(), e);
            }
        }
        Ok(())
    }

    fn notify_status(&self, save: bool, status: MigrationStatus) -> Result<()> {
        if save {
            match status {
                MigrationStatus::Active => {
                    self.migrating.store(true, Ordering::SeqCst);
                    info!("Drain the request for virtio-pmem@{}", self.id);
                    wait_io_done(&self.io_inflight, DEFAULT_IO_TIMEOUT, &self.id);
                }
                MigrationStatus::Failed => self.migrating.store(false, Ordering::SeqCst),
                _ => {}
            }
        }
        Ok(())
    }
}
