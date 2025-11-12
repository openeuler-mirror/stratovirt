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

use std::collections::HashMap;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::vec::Vec;

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Parser};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use address_space::{AddressSpace, GuestAddress, HostMemMapping, Region};
use log::{error, info, warn};
use machine_manager::config::{
    get_pci_df, parse_bool, valid_id, MemBackendObjConfig, MemoryBackend, DEFAULT_VIRTQUEUE_SIZE,
};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use util::bitmap::Bitmap;
use util::byte_code::ByteCode;
use util::gen_base_func;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::unix::do_mmap;

use crate::error::VirtioError;
use crate::{
    iov_read_object, iov_write_object, read_config_default, report_virtio_error, Queue, VirtioBase,
    VirtioDevice, VirtioInterrupt, VirtioInterruptType, VIRTIO_F_RING_EVENT_IDX,
    VIRTIO_F_VERSION_1, VIRTIO_TYPE_MEM,
};

const QUEUE_NUM_MEM: usize = 1;

const VIRTIO_MEM_REQ_PLUG: u16 = 0;
const VIRTIO_MEM_REQ_UNPLUG: u16 = 1;
const VIRTIO_MEM_REQ_UNPLUG_ALL: u16 = 2;
const VIRTIO_MEM_REQ_STATE: u16 = 3;

const VIRTIO_MEM_RESP_ACK: u16 = 0;
const VIRTIO_MEM_RESP_NACK: u16 = 1;
const VIRTIO_MEM_RESP_BUSY: u16 = 2;
const VIRTIO_MEM_RESP_ERROR: u16 = 3;

const VIRTIO_MEM_STATE_PLUGGED: u16 = 0;
const VIRTIO_MEM_STATE_UNPLUGGED: u16 = 1;
const VIRTIO_MEM_STATE_MIXED: u16 = 2;

const VIRTIO_MEM_F_ACPI_PXM: u32 = 0;
const VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE: u32 = 1;

const DEFAULT_MEM_BLOCK_SIZE: u64 = 33554432; // 32 MB
const DEFAULT_MEM_BLOCK_ALIGN_SIZE: u64 = 16384; // 16 KB

const NUMA_NONE: u16 = 4097;
const INVALID_ADDR: u64 = 0;

type ViomemDeviceTable = HashMap<String, Arc<Mutex<Memory>>>;
static VIOMEM_DEV_LIST: OnceLock<Arc<Mutex<ViomemDeviceTable>>> = OnceLock::new();
static DEFAULT_PLUGGABLE_ADDR_BASE: OnceLock<Arc<Mutex<PluggableAddrBase>>> = OnceLock::new();

#[derive(Copy, Clone, Default)]
struct PluggableAddrBase {
    addr: u64,
    auto_alloc: bool,
}

fn alloc_base_addr(
    max_size: u64,
    maddr_cfg: Option<u64>,
    region_size: u64,
    block_size: u64,
) -> u64 {
    let auto_alloc = maddr_cfg.is_none();
    let mut pluggable = DEFAULT_PLUGGABLE_ADDR_BASE
        .get_or_init(|| {
            Arc::new(Mutex::new(PluggableAddrBase {
                addr: max_size,
                auto_alloc,
            }))
        })
        .lock()
        .unwrap();
    if auto_alloc != pluggable.auto_alloc {
        error!("inconsistent maddr configuration options");
        return INVALID_ADDR;
    }

    let base_addr = match maddr_cfg {
        Some(maddr) => maddr,
        None => pluggable.addr.div_ceil(block_size) * block_size,
    };
    pluggable.addr = base_addr + region_size;

    base_addr
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct ViomemInfo {
    pub node: u16,
    #[serde(rename = "size")]
    pub region_size: u64,
    #[serde(rename = "block-size")]
    pub block_size: u64,
    #[serde(rename = "requested-size")]
    pub requested_size: u64,
    #[serde(rename = "plugged-size")]
    pub plugged_size: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct VirtioMemConfig {
    /// size and the alignment in bytes of a memory block.
    block_size: u64,
    /// has no meaning without VIRTIO_MEM_F_ACPI_PXM.
    node_id: u16,
    /// reserved for future use.
    padding: [u8; 6],
    /// start guest physical address of device-managed memory region.
    addr: u64,
    /// the size of device-managed memory region in bytes.
    region_size: u64,
    /// the size of the usable device-managed memory region.
    usable_region_size: u64,
    /// the amount of plugged memory in bytes within the usable device-managed memory region.
    plugged_size: u64,
    /// the requested amount of plugged memory within the usable device-managed memory region.
    requested_size: u64,
}

impl VirtioMemConfig {
    pub(crate) fn qmp_query(&self) -> Value {
        let node_id = if self.node_id == NUMA_NONE {
            0
        } else {
            self.node_id
        };

        serde_json::to_value(ViomemInfo {
            node: node_id,
            region_size: self.region_size,
            block_size: self.block_size,
            requested_size: self.requested_size,
            plugged_size: self.plugged_size,
        })
        .unwrap()
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioMemReq {
    req_type: u16,
    padding: [u16; 3],
    req_union: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioMemReqPlug {
    addr: u64,
    nb_blocks: u16,
    padding: [u16; 3],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioMemReqUnplug {
    addr: u64,
    nb_blocks: u16,
    padding: [u16; 3],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioMemReqState {
    addr: u64,
    nb_blocks: u16,
    padding: [u16; 3],
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct VirtioMemResp {
    resp_type: u16,
    padding: [u16; 3],
    state: VirtioMemRespState,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct VirtioMemRespState {
    state_type: u16,
}

impl ByteCode for VirtioMemConfig {}
impl ByteCode for VirtioMemReq {}
impl ByteCode for VirtioMemReqPlug {}
impl ByteCode for VirtioMemReqUnplug {}
impl ByteCode for VirtioMemReqState {}
impl ByteCode for VirtioMemResp {}
impl ByteCode for VirtioMemRespState {}

#[derive(Parser, Debug, Clone, Default)]
#[command(no_binary_name(true))]
pub struct MemoryConfig {
    #[arg(long, value_parser = ["virtio-mem-device", "virtio-mem-pci"])]
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
    #[arg(long)]
    pub block_size: Option<u64>,
    #[arg(long)]
    pub node: Option<u16>,
    #[arg(long)]
    pub requested_size: Option<u64>,
    #[arg(long, default_value = "false", value_parser = parse_bool, action = ArgAction::Append)]
    pub unplugged_inaccessible: bool,
}

struct MemRegionState {
    base_gpa: u64,
    block_size: u64,
    nr_blocks: u64,
    plugged_size: u64,
    plugged_regions: Bitmap<u64>,
    /// The memory backend host address
    host_addr: u64,
}

impl MemRegionState {
    fn new(addr: u64, region_size: u64, block_size: u64, host_addr: u64) -> Self {
        assert!(block_size != 0);
        assert!((region_size % block_size) == 0);
        let nr_blocks = region_size / block_size;
        Self {
            base_gpa: addr,
            block_size,
            nr_blocks,
            plugged_size: 0,
            plugged_regions: Bitmap::new(nr_blocks as usize),
            host_addr,
        }
    }

    fn get_regions(&self, first_gpa: u64, nb_blocks: u64) -> Vec<Region> {
        let mut regs = Vec::new();
        for n in 0..nb_blocks {
            let gpa = first_gpa + n * self.block_size;
            let block_addr = self.host_addr + (gpa - self.base_gpa);
            let block = Arc::new(
                HostMemMapping::new(
                    GuestAddress(gpa),
                    Some(block_addr),
                    self.block_size,
                    None,
                    false,
                    true,
                    false,
                )
                .unwrap(),
            );

            regs.push(Region::init_ram_region(
                block,
                format!("viomem@{}-{}", gpa, self.block_size).as_str(),
            ));
        }
        regs
    }

    fn valid_range(&self, gpa: u64, nb_blocks: u64) -> u16 {
        // 1. check gpa above region base gpa
        if gpa < self.base_gpa || nb_blocks == 0 {
            return VIRTIO_MEM_RESP_ERROR;
        }

        // 2. check gpa addr aligned with block size
        let addr_offset = gpa - self.base_gpa;
        let block_offset: u64 = if addr_offset % self.block_size == 0 {
            addr_offset / self.block_size
        } else {
            return VIRTIO_MEM_RESP_ERROR;
        };

        // 3. gpa + nb_blocks no overflow
        let (end_block, overflow) = block_offset.overflowing_add(nb_blocks);

        if overflow {
            return VIRTIO_MEM_RESP_ERROR;
        }

        // 4. check add mem segment in the region
        if end_block > self.nr_blocks {
            return VIRTIO_MEM_RESP_ERROR;
        }

        VIRTIO_MEM_RESP_ACK
    }

    fn top_plugged_range(&self) -> (u64, u16) {
        let first_block = 0;
        match self.plugged_regions.find_next_bit(first_block) {
            Ok(begin) => match self.plugged_regions.find_next_zero(begin) {
                Ok(end) => (
                    self.base_gpa + begin as u64 * self.block_size,
                    (end - begin) as u16,
                ),
                Err(_) => (0, 0),
            },
            Err(_) => (0, 0),
        }
    }

    fn check_range_unplugged(&self, gpa: u64, nb_blocks: u64) -> u16 {
        let first_block = (gpa - self.base_gpa) / self.block_size;
        let last_block = first_block + nb_blocks - 1;
        match self.plugged_regions.find_next_bit(first_block as usize) {
            Ok(found_block) => {
                if found_block as u64 > last_block {
                    VIRTIO_MEM_RESP_ACK
                } else {
                    VIRTIO_MEM_RESP_ERROR
                }
            }
            Err(_) => VIRTIO_MEM_RESP_ERROR,
        }
    }

    fn check_range_plugged(&self, gpa: u64, nb_blocks: u64) -> u16 {
        let first_block = (gpa - self.base_gpa) / self.block_size;
        let last_block = first_block + nb_blocks - 1;
        match self.plugged_regions.find_next_zero(first_block as usize) {
            Ok(found_block) => {
                if found_block as u64 > last_block {
                    VIRTIO_MEM_RESP_ACK
                } else {
                    VIRTIO_MEM_RESP_ERROR
                }
            }
            Err(_) => VIRTIO_MEM_RESP_ERROR,
        }
    }

    fn plug_range(&mut self, mem_space: Arc<AddressSpace>, gpa: u64, nb_blocks: usize) -> u16 {
        let first_block = ((gpa - self.base_gpa) / self.block_size) as usize;
        if self.valid_range(gpa, nb_blocks as u64) != VIRTIO_MEM_RESP_ACK {
            error!("plug request region illegal");
            return VIRTIO_MEM_RESP_ERROR;
        }
        if self.check_range_unplugged(gpa, nb_blocks as u64) != VIRTIO_MEM_RESP_ACK {
            error!("plug request region conflict");
            return VIRTIO_MEM_RESP_ERROR;
        }

        for region in self.get_regions(gpa, nb_blocks as u64) {
            let offset = region.offset().0;
            warn!("add region offset {}", offset);
            if mem_space.root().add_subregion(region, offset).is_err() {
                error!("failed to add subregion");
                return VIRTIO_MEM_RESP_BUSY;
            }
        }

        if self
            .plugged_regions
            .set_range(first_block, nb_blocks)
            .is_err()
        {
            error!("failed to set range");
            return VIRTIO_MEM_RESP_ERROR;
        }

        VIRTIO_MEM_RESP_ACK
    }

    fn unplug_range(&mut self, mem_space: Arc<AddressSpace>, gpa: u64, nb_blocks: usize) -> u16 {
        let first_block = ((gpa - self.base_gpa) / self.block_size) as usize;
        if self.valid_range(gpa, nb_blocks as u64) != VIRTIO_MEM_RESP_ACK {
            error!("unplug request region illegal");
            return VIRTIO_MEM_RESP_ERROR;
        }
        if self.check_range_plugged(gpa, nb_blocks as u64) != VIRTIO_MEM_RESP_ACK {
            warn!("unplug request region conflict");
            return VIRTIO_MEM_RESP_ERROR;
        }

        for region in self.get_regions(gpa, nb_blocks as u64) {
            warn!("del region offset {}", region.offset().0);
            if mem_space.root().delete_subregion(&region).is_err() {
                error!("failed to delete subregion");
                return VIRTIO_MEM_RESP_ERROR;
            }
        }

        if self
            .plugged_regions
            .clear_range(first_block, nb_blocks)
            .is_err()
        {
            error!("failed to delete subregion");
            return VIRTIO_MEM_RESP_ERROR;
        }

        VIRTIO_MEM_RESP_ACK
    }

    fn range_state(&self, gpa: u64, nb_blocks: u64) -> (u16, u16) {
        let first_block = ((gpa - self.base_gpa) / self.block_size) as usize;
        let last_block = first_block + nb_blocks as usize;
        if self.valid_range(gpa, nb_blocks) != VIRTIO_MEM_RESP_ACK {
            error!("plug request region illegal");
            return (VIRTIO_MEM_RESP_ERROR, 0);
        }

        let bit = match self.plugged_regions.contain(first_block) {
            Ok(bit) => bit,
            Err(_) => return (VIRTIO_MEM_RESP_ERROR, 0),
        };

        if bit {
            match self.plugged_regions.find_next_zero(first_block + 1) {
                Ok(found_block) => {
                    if found_block >= last_block {
                        (VIRTIO_MEM_RESP_ACK, VIRTIO_MEM_STATE_PLUGGED)
                    } else {
                        (VIRTIO_MEM_RESP_ACK, VIRTIO_MEM_STATE_MIXED)
                    }
                }
                Err(_) => (VIRTIO_MEM_RESP_ERROR, 0),
            }
        } else {
            match self.plugged_regions.find_next_bit(first_block + 1) {
                Ok(found_block) => {
                    if found_block >= last_block {
                        (VIRTIO_MEM_RESP_ACK, VIRTIO_MEM_STATE_UNPLUGGED)
                    } else {
                        (VIRTIO_MEM_RESP_ACK, VIRTIO_MEM_STATE_MIXED)
                    }
                }
                Err(_) => (VIRTIO_MEM_RESP_ERROR, 0),
            }
        }
    }
}

struct MemoryHandler {
    /// The guest request queue
    pub(crate) queue: Arc<Mutex<Queue>>,
    /// The eventfd used to notify the guest request queue event
    pub(crate) queue_evt: Arc<EventFd>,
    /// The function for interrupt triggering
    pub(crate) interrupt_cb: Arc<VirtioInterrupt>,
    /// Configuration space of virtio mem device.
    config: Arc<Mutex<VirtioMemConfig>>,
    /// System address space.
    pub(crate) mem_space: Arc<AddressSpace>,
    /// Bit mask of features negotiated by the backend and the frontend
    pub(crate) driver_features: u64,
    /// Virtio mem device is broken or not.
    pub(crate) device_broken: Arc<AtomicBool>,
    /// Virtio mem Region list
    pub(crate) regions: Arc<Mutex<MemRegionState>>,
}

impl MemoryHandler {
    fn handle_plug_request(&self, req: &VirtioMemReqPlug) -> u16 {
        info!("handle_plug_request: {:?}", req);
        let gpa = req.addr;
        let nb_blocks = req.nb_blocks as u64;
        let mut locked_regions = self.regions.lock().unwrap();
        let mut config = self.config.lock().unwrap();
        let plug_size = nb_blocks * config.block_size;
        if (plug_size + config.plugged_size) > config.requested_size || plug_size == 0 {
            return VIRTIO_MEM_RESP_NACK;
        }
        let ack = locked_regions.plug_range(self.mem_space.clone(), gpa, nb_blocks as usize);
        if ack != VIRTIO_MEM_RESP_ACK {
            return ack;
        }
        config.plugged_size += plug_size;

        locked_regions.plugged_size += nb_blocks * locked_regions.block_size;

        VIRTIO_MEM_RESP_ACK
    }

    fn handle_unplug_request(&self, req: &VirtioMemReqUnplug) -> u16 {
        info!("handle_unplug_request: {:?}", req);
        let gpa = req.addr;
        let nb_blocks = req.nb_blocks as u64;
        let mut config = self.config.lock().unwrap();
        let unplug_size = config.block_size * nb_blocks;
        if (unplug_size + config.requested_size) > config.plugged_size || unplug_size == 0 {
            return VIRTIO_MEM_RESP_NACK;
        }
        let mut locked_regions = self.regions.lock().unwrap();
        let ack = locked_regions.unplug_range(self.mem_space.clone(), gpa, nb_blocks as usize);
        if ack != VIRTIO_MEM_RESP_ACK {
            return ack;
        }
        config.plugged_size -= unplug_size;
        locked_regions.plugged_size += nb_blocks * locked_regions.block_size;

        VIRTIO_MEM_RESP_ACK
    }

    fn handle_state_request(&self, req: &VirtioMemReqState) -> (u16, u16) {
        info!("handle_state_request: {:?}", req);
        let gpa = req.addr;
        let nb_blocks = req.nb_blocks as u64;
        let locked_regions = self.regions.lock().unwrap();
        locked_regions.range_state(gpa, nb_blocks)
    }

    fn handle_unplug_all_request(&self) -> u16 {
        loop {
            let (addr, nb_blocks) = self.regions.lock().unwrap().top_plugged_range();
            info!("find plugged memory region: ({}, {})", addr, nb_blocks);
            if nb_blocks == 0 {
                break;
            }
            let req = &VirtioMemReqUnplug {
                addr,
                nb_blocks,
                ..Default::default()
            };
            let ack = self.handle_unplug_request(req);
            if ack != VIRTIO_MEM_RESP_ACK {
                return ack;
            }
        }
        VIRTIO_MEM_RESP_ACK
    }

    pub fn process_queue(&self) -> Result<()> {
        loop {
            let mut locked_queue = self.queue.lock().unwrap();
            let elem = locked_queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
                .with_context(|| {
                    "Failed to pop avail ring element for process guest request queue"
                })?;
            if elem.desc_num == 0 {
                break;
            }

            let mut req = iov_read_object::<VirtioMemReq>(
                &self.mem_space.clone(),
                &elem.out_iovec,
                locked_queue.vring.get_cache(),
            )?;

            let mut send_response = |resp: VirtioMemResp| -> Result<()> {
                iov_write_object(
                    &self.mem_space,
                    &elem.in_iovec,
                    locked_queue.vring.get_cache(),
                    resp,
                )?;

                locked_queue
                    .vring
                    .add_used(elem.index, resp.as_bytes().len() as u32)
                    .with_context(|| {
                        format!(
                            "Failed to add used ring(guest request queue), index {}, len {}",
                            elem.index,
                            resp.as_bytes().len(),
                        )
                    })?;

                if locked_queue.vring.should_notify(self.driver_features) {
                    (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&locked_queue), false)
                        .with_context(|| {
                            VirtioError::InterruptTrigger(
                                "mem guest request queue",
                                VirtioInterruptType::Vring,
                            )
                        })?;
                }

                Ok(())
            };

            match req.req_type {
                VIRTIO_MEM_REQ_PLUG => {
                    let resp_type = self.handle_plug_request(
                        VirtioMemReqPlug::from_bytes(req.req_union.as_mut_slice()).unwrap(),
                    );
                    let resp = VirtioMemResp {
                        resp_type,
                        ..Default::default()
                    };
                    send_response(resp)?;
                }
                VIRTIO_MEM_REQ_UNPLUG => {
                    let resp = VirtioMemResp {
                        resp_type: self.handle_unplug_request(
                            VirtioMemReqUnplug::from_bytes(req.req_union.as_mut_slice()).unwrap(),
                        ),
                        ..Default::default()
                    };
                    send_response(resp)?;
                }
                VIRTIO_MEM_REQ_UNPLUG_ALL => {
                    let resp = VirtioMemResp {
                        resp_type: self.handle_unplug_all_request(),
                        ..Default::default()
                    };
                    send_response(resp)?;
                }
                VIRTIO_MEM_REQ_STATE => {
                    let (resp_type, state_type) = self.handle_state_request(
                        VirtioMemReqState::from_bytes(req.req_union.as_mut_slice()).unwrap(),
                    );
                    let mut resp = VirtioMemResp {
                        resp_type,
                        ..Default::default()
                    };
                    resp.state.state_type = state_type;
                    send_response(resp)?;
                }
                _ => {
                    bail!("virtio-mem: unknown request type {}", req.req_type);
                }
            }
        }
        Ok(())
    }
}

impl EventNotifierHelper for MemoryHandler {
    fn internal_notifiers(mh: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();
        let closure_mh = mh.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let locked_closure_mh = closure_mh.lock().unwrap();
            if let Err(e) = locked_closure_mh.process_queue() {
                error!("Failed to plug/unplug mem: {:?}", e);
                report_virtio_error(
                    locked_closure_mh.interrupt_cb.clone(),
                    locked_closure_mh.driver_features,
                    &locked_closure_mh.device_broken,
                );
            }

            None
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            mh.lock().unwrap().queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![handler],
        ));
        notifiers
    }
}

#[derive(Default)]
pub struct Memory {
    /// Virtio device base property.
    base: VirtioBase,
    /// Virtio mem device id
    id: String,
    /// Configuration space of virtio mem device.
    config: Arc<Mutex<VirtioMemConfig>>,
    /// Memory
    backend: Arc<Mutex<MemoryBackend>>,
    /// unplugged-inaccessible
    unplugged_inaccessible: bool,
    /// Interrupt callback function.
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
}

impl Memory {
    fn new_internal(option: MemoryConfig, memobj: MemBackendObjConfig, max_size: u64) -> Self {
        info!("virtio-mem: new MemoryConfig {:?}", option);
        let mut mem = Self {
            base: VirtioBase::new(VIRTIO_TYPE_MEM, QUEUE_NUM_MEM, DEFAULT_VIRTQUEUE_SIZE),
            id: option.id.clone(),
            backend: Arc::new(Mutex::new(MemoryBackend::new(memobj))),
            ..Default::default()
        };

        let mut config: std::sync::MutexGuard<'_, VirtioMemConfig> = mem.config.lock().unwrap();
        config.block_size = match option.block_size {
            Some(block_size) => {
                if block_size % DEFAULT_MEM_BLOCK_ALIGN_SIZE != 0 {
                    DEFAULT_MEM_BLOCK_SIZE
                } else {
                    block_size
                }
            }
            None => DEFAULT_MEM_BLOCK_SIZE,
        };
        config.region_size = mem.backend.lock().unwrap().size;
        config.addr = alloc_base_addr(
            max_size,
            option.memaddr,
            config.region_size,
            config.block_size,
        );
        config.usable_region_size = config.region_size;
        config.node_id = match option.node {
            Some(node) => {
                info!(
                    "virtio-mem not support ACPI NUMA, ignore node option(node={})",
                    node
                );
                NUMA_NONE
            }
            None => NUMA_NONE,
        };

        config.plugged_size = 0;
        config.requested_size = option.requested_size.unwrap_or(0);
        drop(config);

        mem.unplugged_inaccessible = option.unplugged_inaccessible;
        mem
    }

    pub fn new_arc(
        option: MemoryConfig,
        memobj: MemBackendObjConfig,
        max_size: u64,
    ) -> Result<Arc<Mutex<Self>>> {
        let mem = Self::new_internal(option, memobj, max_size);
        let id = mem.id.clone();
        let mem_arc = Arc::new(Mutex::new(mem));
        register_viomem_device(id, mem_arc.clone())?;

        Ok(mem_arc)
    }

    pub fn get_region_size(&self) -> u64 {
        self.config.lock().unwrap().region_size
    }

    fn update_request(&mut self, request_size: u64) -> Result<()> {
        info!("qmp request size {}", request_size);
        if request_size > self.config.lock().unwrap().region_size {
            bail!("request size out of the device region size")
        }
        if request_size % self.config.lock().unwrap().block_size != 0 {
            bail!("requested_size not aligned with device block size")
        }
        let old_requested_size = self.config.lock().unwrap().requested_size;
        self.config.lock().unwrap().requested_size = request_size;
        self.signal_config_change().with_context(|| {
            self.config.lock().unwrap().requested_size = old_requested_size;
            "Failed to notify about configuration change after setting request memory size"
        })?;

        Ok(())
    }

    /// Notify configuration changes to VM.
    fn signal_config_change(&self) -> Result<()> {
        if let Some(interrupt_cb) = &self.interrupt_cb {
            interrupt_cb(&VirtioInterruptType::Config, None, false).with_context(|| {
                VirtioError::InterruptTrigger("viomem", VirtioInterruptType::Config)
            })
        } else {
            Err(anyhow!(VirtioError::DeviceNotActivated(
                "viomem".to_string()
            )))
        }
    }
}

impl VirtioDevice for Memory {
    gen_base_func!(virtio_base, virtio_base_mut, VirtioBase, base);

    fn realize(&mut self) -> Result<()> {
        if self.config.lock().unwrap().addr == INVALID_ADDR {
            bail!("inconsistent maddr configuration options");
        }

        self.backend.lock().unwrap().realize()?;
        self.init_config_features()?;
        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        self.base.device_features = 1u64 << VIRTIO_F_VERSION_1 | 1u64 << VIRTIO_F_RING_EVENT_IDX;

        if self.config.lock().unwrap().node_id != NUMA_NONE {
            self.base.device_features |= 1u64 << VIRTIO_MEM_F_ACPI_PXM;
        }
        if self.unplugged_inaccessible {
            self.base.device_features |= 1u64 << VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE;
        }

        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        let new_config = *self.config.lock().unwrap();
        let config_len = size_of::<VirtioMemConfig>();
        let config = &new_config.as_bytes()[..config_len];
        read_config_default(config, offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        warn!(
            "virtio-mem write config: offset = {}, data = {:?}",
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
        info!("virtio-mem@{} activate", self.id);
        let queues = &self.base.queues;
        if queues.len() != self.queue_num() {
            return Err(anyhow!(VirtioError::IncorrectQueueNum(
                self.queue_num(),
                queues.len()
            )));
        }
        self.interrupt_cb = Some(interrupt_cb.clone());

        let config = self.config.lock().unwrap();
        let backend = self.backend.lock().unwrap();
        let host_addr = match &backend.backend {
            Some(file) => do_mmap(
                &Some(file.as_ref()),
                config.region_size,
                0,
                false,
                backend.share,
                false,
            )?,
            None => do_mmap(&None, config.region_size, 0, false, backend.share, false)?,
        };
        drop(backend);

        let handler = MemoryHandler {
            queue: queues[0].clone(),
            queue_evt: queue_evts[0].clone(),
            interrupt_cb: interrupt_cb.clone(),
            driver_features: self.base.driver_features,
            config: self.config.clone(),
            mem_space,
            regions: Arc::new(Mutex::new(MemRegionState::new(
                config.addr,
                config.region_size,
                config.block_size,
                host_addr,
            ))),
            device_broken: self.base.broken.clone(),
        };

        let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler)));
        register_event_helper(notifiers, None, &mut self.base.deactivate_evts)
            .with_context(|| "Failed to register mem guest request event notifier to MainLoop")?;

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        info!("virtio-mem@{} deactivate", self.id);
        unregister_event_helper(None, &mut self.base.deactivate_evts)
    }

    fn reset(&mut self) -> Result<()> {
        Ok(())
    }
}

fn register_viomem_device(id: String, mem: Arc<Mutex<Memory>>) -> Result<()> {
    VIOMEM_DEV_LIST
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .lock()
        .unwrap()
        .insert(id, mem);
    Ok(())
}

pub fn qmp_set_viomem(id: &String, request_size: u64) -> Result<()> {
    if let Some(devlist) = VIOMEM_DEV_LIST.get() {
        match devlist.lock().unwrap().get(id) {
            Some(mem) => mem.lock().unwrap().update_request(request_size),
            None => {
                bail!("not found virtio-mem@{} device", id)
            }
        }
    } else {
        bail!("no virtio-mem device context")
    }
}

pub fn qmp_get_viomem(id: &String) -> Result<Value> {
    if let Some(devlist) = VIOMEM_DEV_LIST.get() {
        match devlist.lock().unwrap().get(id) {
            Some(mem) => Ok(mem.lock().unwrap().config.lock().unwrap().qmp_query()),
            None => {
                bail!("not found virtio-mem@{} device", id)
            }
        }
    } else {
        bail!("no virtio-mem device context")
    }
}
