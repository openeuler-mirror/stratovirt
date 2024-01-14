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

//! # Virtio
//!
//! This mod is used for virtio device.
//!
//! ## Design
//!
//! This module offers support for:
//! 1. Some Spec specified const variable used by virtio device.
//! 2. Virtio Device trait
//!
//! ## Platform Support
//!
//! - `x86_64`
//! - `aarch64`

pub mod device;
pub mod error;
pub mod vhost;

mod queue;
mod transport;

pub use device::balloon::*;
pub use device::block::{Block, BlockState, VirtioBlkConfig};
#[cfg(feature = "virtio_gpu")]
pub use device::gpu::*;
pub use device::net::*;
pub use device::rng::{Rng, RngState};
pub use device::scsi_cntlr as ScsiCntlr;
pub use device::serial::{find_port_by_nr, get_max_nr, Serial, SerialPort, VirtioSerialState};
pub use error::VirtioError;
pub use queue::*;
pub use transport::virtio_mmio::{VirtioMmioDevice, VirtioMmioState};
pub use transport::virtio_pci::VirtioPciDevice;
pub use vhost::kernel as VhostKern;
pub use vhost::user as VhostUser;

use std::cmp;
use std::io::Write;
use std::os::unix::prelude::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use log::{error, warn};
use vmm_sys_util::eventfd::EventFd;

use address_space::AddressSpace;
use machine_manager::config::ConfigCheck;
use migration_derive::ByteCode;
use util::aio::{mem_to_buf, Iovec};
use util::num_ops::{read_u32, write_u32};
use util::AsAny;

/// Check if the bit of features is configured.
pub fn virtio_has_feature(feature: u64, fbit: u32) -> bool {
    feature & (1 << fbit) != 0
}

/// Identifier of different virtio device, refer to Virtio Spec.
pub const VIRTIO_TYPE_NET: u32 = 1;
pub const VIRTIO_TYPE_BLOCK: u32 = 2;
pub const VIRTIO_TYPE_CONSOLE: u32 = 3;
pub const VIRTIO_TYPE_RNG: u32 = 4;
pub const VIRTIO_TYPE_BALLOON: u32 = 5;
pub const VIRTIO_TYPE_SCSI: u32 = 8;
pub const VIRTIO_TYPE_GPU: u32 = 16;
pub const VIRTIO_TYPE_VSOCK: u32 = 19;
pub const VIRTIO_TYPE_FS: u32 = 26;

// The Status of Virtio Device.
const CONFIG_STATUS_ACKNOWLEDGE: u32 = 0x01;
const CONFIG_STATUS_DRIVER: u32 = 0x02;
const CONFIG_STATUS_DRIVER_OK: u32 = 0x04;
const CONFIG_STATUS_FEATURES_OK: u32 = 0x08;
const CONFIG_STATUS_NEEDS_RESET: u32 = 0x40;
const CONFIG_STATUS_FAILED: u32 = 0x80;

/// Feature Bits, refer to Virtio Spec.
/// Negotiating this feature indicates that the driver can use descriptors
/// with the VIRTQ_DESC_F_INDIRECT flag set.
pub const VIRTIO_F_RING_INDIRECT_DESC: u32 = 28;
/// This feature enables the used_event and the avail_event fields.
pub const VIRTIO_F_RING_EVENT_IDX: u32 = 29;
/// Indicates compliance with Virtio Spec.
pub const VIRTIO_F_VERSION_1: u32 = 32;
/// This feature indicates that the device can be used on a platform
/// where device access to data in memory is limited and/or translated.
pub const VIRTIO_F_ACCESS_PLATFORM: u32 = 33;
/// This feature indicates support for the packed virtqueue layout.
pub const VIRTIO_F_RING_PACKED: u32 = 34;

/// Device handles packets with partial checksum.
pub const VIRTIO_NET_F_CSUM: u32 = 0;
/// Driver handles packets with partial checksum.
pub const VIRTIO_NET_F_GUEST_CSUM: u32 = 1;
/// Device has given MAC address.
pub const VIRTIO_NET_F_MAC: u32 = 5;
/// Driver can receive TSOv4.
pub const VIRTIO_NET_F_GUEST_TSO4: u32 = 7;
/// Driver can receive TSOv6.
pub const VIRTIO_NET_F_GUEST_TSO6: u32 = 8;
/// Driver can receive TSO with ECN.
pub const VIRTIO_NET_F_GUEST_ECN: u32 = 9;
/// Driver can receive UFO.
pub const VIRTIO_NET_F_GUEST_UFO: u32 = 10;
/// Device can receive TSOv4.
pub const VIRTIO_NET_F_HOST_TSO4: u32 = 11;
/// Device can receive TSOv6.
pub const VIRTIO_NET_F_HOST_TSO6: u32 = 12;
/// Device can receive UFO.
pub const VIRTIO_NET_F_HOST_UFO: u32 = 14;
/// Device can merge receive buffers.
pub const VIRTIO_NET_F_MRG_RXBUF: u32 = 15;
/// Control channel is available.
pub const VIRTIO_NET_F_CTRL_VQ: u32 = 17;
/// Control channel RX mode support.
pub const VIRTIO_NET_F_CTRL_RX: u32 = 18;
/// Control channel VLAN filtering.
pub const VIRTIO_NET_F_CTRL_VLAN: u32 = 19;
/// Extra RX mode control support.
pub const VIRTIO_NET_F_CTRL_RX_EXTRA: u32 = 20;
/// Device supports multi queue with automatic receive steering.
pub const VIRTIO_NET_F_MQ: u32 = 22;
/// Set Mac Address through control channel.
pub const VIRTIO_NET_F_CTRL_MAC_ADDR: u32 = 23;
/// Configuration cols and rows are valid.
pub const VIRTIO_CONSOLE_F_SIZE: u64 = 0;
/// Device has support for multiple ports.
/// max_nr_ports is valid and control virtqueues will be used.
pub const VIRTIO_CONSOLE_F_MULTIPORT: u64 = 1;
/// Device has support for emergency write.
/// Configuration field emerg_wr is valid.
pub const VIRTIO_CONSOLE_F_EMERG_WRITE: u64 = 2;
/// Maximum size of any single segment is in size_max.
pub const VIRTIO_BLK_F_SIZE_MAX: u32 = 1;
/// Maximum number of segments in a request is in seg_max.
pub const VIRTIO_BLK_F_SEG_MAX: u32 = 2;
/// Legacy geometry available.
pub const VIRTIO_BLK_F_GEOMETRY: u32 = 4;
/// Device is read-only.
pub const VIRTIO_BLK_F_RO: u32 = 5;
/// Block size of disk is available.
pub const VIRTIO_BLK_F_BLK_SIZE: u32 = 6;
/// Cache flush command support.
pub const VIRTIO_BLK_F_FLUSH: u32 = 9;
/// Topology information is available.
pub const VIRTIO_BLK_F_TOPOLOGY: u32 = 10;
/// DISCARD is supported.
pub const VIRTIO_BLK_F_DISCARD: u32 = 13;
/// WRITE ZEROES is supported.
pub const VIRTIO_BLK_F_WRITE_ZEROES: u32 = 14;
/// Unmap flags for write zeroes command.
pub const VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP: u32 = 1;
/// GPU EDID feature is supported.
pub const VIRTIO_GPU_F_EDID: u32 = 1;
/// TODO: need to change to 5 or bigger
pub const VIRTIO_GPU_F_MONOCHROME: u32 = 4;

/// The device sets control ok status to driver.
pub const VIRTIO_NET_OK: u8 = 0;
/// The device sets control err status to driver.
pub const VIRTIO_NET_ERR: u8 = 1;

/// Driver can send control commands.
pub const VIRTIO_NET_CTRL_RX: u8 = 0;
/// Control commands for promiscuous mode.
pub const VIRTIO_NET_CTRL_RX_PROMISC: u8 = 0;
/// Control commands for all-multicast receive.
pub const VIRTIO_NET_CTRL_RX_ALLMULTI: u8 = 1;
/// Control commands for all-unicast receive.
pub const VIRTIO_NET_CTRL_RX_ALLUNI: u8 = 2;
/// Control commands for suppressing multicast receive.
pub const VIRTIO_NET_CTRL_RX_NOMULTI: u8 = 3;
/// Control commands for suppressing unicast receive.
pub const VIRTIO_NET_CTRL_RX_NOUNI: u8 = 4;
/// Control commands for suppressing broadcast receive.
pub const VIRTIO_NET_CTRL_RX_NOBCAST: u8 = 5;

/// The driver can send control commands for MAC address filtering.
pub const VIRTIO_NET_CTRL_MAC: u8 = 1;
/// The driver sets the unicast/multicast address table.
pub const VIRTIO_NET_CTRL_MAC_TABLE_SET: u8 = 0;
/// The driver sets the default MAC address which rx filtering accepts.
pub const VIRTIO_NET_CTRL_MAC_ADDR_SET: u8 = 1;

/// The driver can send control commands for vlan filtering.
pub const VIRTIO_NET_CTRL_VLAN: u8 = 2;
/// The driver adds a vlan id to the vlan filtering table.
pub const VIRTIO_NET_CTRL_VLAN_ADD: u8 = 0;
/// The driver adds a vlan id from the vlan filtering table.
pub const VIRTIO_NET_CTRL_VLAN_DEL: u8 = 1;

/// Driver configure the class before enabling virtqueue.
pub const VIRTIO_NET_CTRL_MQ: u8 = 4;
/// Driver configure the command before enabling virtqueue.
pub const VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET: u16 = 0;
/// The minimum pairs of multiple queue.
pub const VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN: u16 = 1;
/// The maximum pairs of multiple queue.
pub const VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX: u16 = 0x8000;
/// Support more than one virtqueue.
pub const VIRTIO_BLK_F_MQ: u32 = 12;

/// A single request can include both device-readable and device-writable data buffers.
pub const VIRTIO_SCSI_F_INOUT: u32 = 0;
/// The host SHOULD enable reporting of hot-plug and hot-unplug events for LUNs and targets on the
/// SCSI bus. The guest SHOULD handle hot-plug and hot-unplug events.
pub const VIRTIO_SCSI_F_HOTPLUG: u32 = 1;
/// The host will report changes to LUN parameters via a VIRTIO_SCSI_T_PARAM_CHANGE event.
/// The guest SHOULD handle them.
pub const VIRTIO_SCSI_F_CHANGE: u32 = 2;
/// The extended fields for T10 protection information (DIF/DIX) are included in the SCSI request
/// header.
pub const VIRTIO_SCSI_F_T10_PI: u32 = 3;

/// The IO type of virtio block, refer to Virtio Spec.
/// Read.
pub const VIRTIO_BLK_T_IN: u32 = 0;
/// Write.
pub const VIRTIO_BLK_T_OUT: u32 = 1;
/// Flush.
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
/// Device id
pub const VIRTIO_BLK_T_GET_ID: u32 = 8;
/// Discard command.
pub const VIRTIO_BLK_T_DISCARD: u32 = 11;
/// Write zeroes command.
pub const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;
/// Device id length
pub const VIRTIO_BLK_ID_BYTES: u32 = 20;
/// Success
pub const VIRTIO_BLK_S_OK: u8 = 0;
/// IO Error.
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
/// Unsupported.
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// The Type of virtio gpu, refer to Virtio Spec.
/// 2D commands:
/// Retrieve the current output configuration.
pub const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;
/// Create a 2D resource on the host.
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
/// Destroy a resource on the host.
pub const VIRTIO_GPU_CMD_RESOURCE_UNREF: u32 = 0x0102;
/// Set the scanout parameters for a single output.
pub const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0103;
/// Flush a scanout resource.
pub const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x0104;
/// Transfer from guest memory to host resource.
pub const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
/// Assign backing pages to a resource.
pub const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
/// Detach backing pages from a resource.
pub const VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
/// Retrieve the EDID data for a given scanout.
pub const VIRTIO_GPU_CMD_GET_EDID: u32 = 0x010a;
/// update cursor
pub const VIRTIO_GPU_CMD_UPDATE_CURSOR: u32 = 0x0300;
/// move cursor
pub const VIRTIO_GPU_CMD_MOVE_CURSOR: u32 = 0x0301;
/// Success for cmd without data back.
pub const VIRTIO_GPU_RESP_OK_NODATA: u32 = 0x1100;
/// Success for VIRTIO_GPU_CMD_GET_DISPLAY_INFO.
pub const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;
/// Success for VIRTIO_GPU_CMD_GET_EDID.
pub const VIRTIO_GPU_RESP_OK_EDID: u32 = 0x1104;
/// unspecificated
pub const VIRTIO_GPU_RESP_ERR_UNSPEC: u32 = 0x1200;
/// out of host memory
pub const VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
/// invalid id of scanout
pub const VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
/// invalid id of 2D resource
pub const VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
/// invalid parameter
pub const VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;
/// Flags in virtio gpu cmd which means need a fence.
pub const VIRTIO_GPU_FLAG_FENCE: u32 = 1 << 0;

/// Interrupt status: Used Buffer Notification
pub const VIRTIO_MMIO_INT_VRING: u32 = 0x01;
/// Interrupt status: Configuration Change Notification
pub const VIRTIO_MMIO_INT_CONFIG: u32 = 0x02;

/// The offset between notify reg's address and base MMIO address
/// Guest OS uses notify reg to notify the VMM.
pub const NOTIFY_REG_OFFSET: u32 = 0x50;

/// Packet header, refer to Virtio Spec.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

#[derive(Debug)]
pub enum VirtioInterruptType {
    Config,
    Vring,
}

pub type VirtioInterrupt =
    Box<dyn Fn(&VirtioInterruptType, Option<&Queue>, bool) -> Result<()> + Send + Sync>;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum VirtioDeviceQuirk {
    VirtioGpuEnableBar0,
    VirtioDeviceQuirkMax,
}

#[derive(Default)]
pub struct VirtioBase {
    /// Device type
    device_type: u32,
    /// Bit mask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Device (host) feature-setting selector.
    hfeatures_sel: u32,
    /// Driver (guest) feature-setting selector.
    gfeatures_sel: u32,
    /// Interrupt status.
    interrupt_status: Arc<AtomicU32>,
    /// Device status.
    device_status: Arc<AtomicU32>,
    /// If this device is activated or not.
    device_activated: Arc<AtomicBool>,
    /// Configuration atomicity value.
    config_generation: Arc<AtomicU8>,
    /// The MSI-X vector for config change notification.
    config_vector: Arc<AtomicU16>,
    /// The type of queue, split-vring or packed-vring.
    queue_type: u16,
    /// The number of device queues.
    queue_num: usize,
    /// The max size of each queue.
    queue_size_max: u16,
    /// Queue selector.
    queue_select: u16,
    /// The configuration of queues.
    queues_config: Vec<QueueConfig>,
    /// Virtio queues.
    queues: Vec<Arc<Mutex<Queue>>>,
    /// Eventfd for device deactivate.
    deactivate_evts: Vec<RawFd>,
    /// Device is broken or not.
    broken: Arc<AtomicBool>,
}

#[derive(Copy, Clone, ByteCode)]
struct VirtioBaseState {
    device_activated: bool,
    hfeatures_sel: u32,
    gfeatures_sel: u32,
    interrupt_status: u32,
    device_status: u32,
    config_generation: u8,
    queue_select: u16,
    config_vector: u16,
    queues_config: [QueueConfig; 32],
    /// The number of activated queues.
    queue_num: usize,
    queue_type: u16,
}

impl VirtioBase {
    fn new(device_type: u32, queue_num: usize, queue_size_max: u16) -> Self {
        Self {
            device_type,
            config_vector: Arc::new(AtomicU16::new(INVALID_VECTOR_NUM)),
            queue_num,
            queue_size_max,
            queue_type: QUEUE_TYPE_SPLIT_VRING,
            queues_config: vec![QueueConfig::new(queue_size_max); queue_num],
            ..Default::default()
        }
    }

    fn reset(&mut self) {
        // device_type, device_features, queue_num and queue_size_max
        // is not mutable, thus no need to reset.
        self.driver_features = 0;
        self.hfeatures_sel = 0;
        self.gfeatures_sel = 0;
        self.interrupt_status.store(0, Ordering::SeqCst);
        self.device_status.store(0, Ordering::SeqCst);
        self.device_activated.store(false, Ordering::SeqCst);
        self.config_generation.store(0, Ordering::SeqCst);
        self.config_vector
            .store(INVALID_VECTOR_NUM, Ordering::SeqCst);
        self.queue_type = QUEUE_TYPE_SPLIT_VRING;
        self.queue_select = 0;
        self.queues_config.iter_mut().for_each(|q| q.reset());
        self.queues.clear();
        self.broken.store(false, Ordering::SeqCst);
    }

    fn get_state(&self) -> VirtioBaseState {
        let mut state = VirtioBaseState {
            device_activated: self.device_activated.load(Ordering::Acquire),
            hfeatures_sel: self.hfeatures_sel,
            gfeatures_sel: self.gfeatures_sel,
            interrupt_status: self.interrupt_status.load(Ordering::Acquire),
            device_status: self.device_status.load(Ordering::Acquire),
            config_generation: self.config_generation.load(Ordering::Acquire),
            queue_select: self.queue_select,
            config_vector: self.config_vector.load(Ordering::Acquire),
            queues_config: [QueueConfig::default(); 32],
            queue_num: 0,
            queue_type: self.queue_type,
        };

        for (index, queue) in self.queues_config.iter().enumerate() {
            state.queues_config[index] = *queue;
        }
        for (index, queue) in self.queues.iter().enumerate() {
            state.queues_config[index] = queue.lock().unwrap().vring.get_queue_config();
            state.queue_num += 1;
        }

        state
    }

    fn set_state(
        &mut self,
        state: &VirtioBaseState,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
    ) {
        self.device_activated
            .store(state.device_activated, Ordering::SeqCst);
        self.hfeatures_sel = state.hfeatures_sel;
        self.gfeatures_sel = state.gfeatures_sel;
        self.interrupt_status
            .store(state.interrupt_status, Ordering::SeqCst);
        self.device_status
            .store(state.device_status, Ordering::SeqCst);
        self.config_generation
            .store(state.config_generation, Ordering::SeqCst);
        self.queue_select = state.queue_select;
        self.config_vector
            .store(state.config_vector, Ordering::SeqCst);
        self.queues_config = state.queues_config[..self.queue_num].to_vec();
        self.queue_type = state.queue_type;

        if state.queue_num == 0 {
            return;
        }

        let mut queues = Vec::with_capacity(self.queue_num);
        for queue_config in self.queues_config.iter_mut().take(state.queue_num) {
            if queue_config.ready {
                queue_config.set_addr_cache(
                    mem_space.clone(),
                    interrupt_cb.clone(),
                    self.driver_features,
                    &self.broken,
                );
            }
            queues.push(Arc::new(Mutex::new(
                Queue::new(*queue_config, self.queue_type).unwrap(),
            )));
        }
        self.queues = queues;
    }
}

/// The trait for virtio device operations.
pub trait VirtioDevice: Send + AsAny {
    /// Get base property of virtio device.
    fn virtio_base(&self) -> &VirtioBase;

    /// Get mutable base property virtio device.
    fn virtio_base_mut(&mut self) -> &mut VirtioBase;

    /// Realize low level device.
    fn realize(&mut self) -> Result<()>;

    /// Unrealize low level device.
    fn unrealize(&mut self) -> Result<()> {
        bail!("Unrealize of the virtio device is not implemented");
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        self.virtio_base().device_type
    }

    /// Get the virtio device customized modification.
    fn device_quirk(&self) -> Option<VirtioDeviceQuirk> {
        None
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        self.virtio_base().queue_num
    }

    /// Get the queue size of virtio device.
    fn queue_size_max(&self) -> u16 {
        self.virtio_base().queue_size_max
    }

    /// Init device configure space and features.
    fn init_config_features(&mut self) -> Result<()>;

    /// Get device features from host.
    fn device_features(&self, features_select: u32) -> u32 {
        read_u32(self.virtio_base().device_features, features_select)
    }

    /// Set driver features by guest.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        let mut v = value;
        let unsupported_features = value & !self.device_features(page);
        if unsupported_features != 0 {
            warn!(
                "Receive acknowledge request with unknown feature: {:x}",
                write_u32(value, page)
            );
            v &= !unsupported_features;
        }

        let features = if page == 0 {
            (self.driver_features(1) as u64) << 32 | (v as u64)
        } else {
            (v as u64) << 32 | (self.driver_features(0) as u64)
        };
        self.virtio_base_mut().driver_features = features;
    }

    /// Get driver features by guest.
    fn driver_features(&self, features_select: u32) -> u32 {
        read_u32(self.virtio_base().driver_features, features_select)
    }

    /// Get host feature selector.
    fn hfeatures_sel(&self) -> u32 {
        self.virtio_base().hfeatures_sel
    }

    /// Set host feature selector.
    fn set_hfeatures_sel(&mut self, val: u32) {
        self.virtio_base_mut().hfeatures_sel = val;
    }

    /// Get guest feature selector.
    fn gfeatures_sel(&self) -> u32 {
        self.virtio_base().gfeatures_sel
    }

    /// Set guest feature selector.
    fn set_gfeatures_sel(&mut self, val: u32) {
        self.virtio_base_mut().gfeatures_sel = val;
    }

    /// Check whether virtio device status is as expected.
    fn check_device_status(&self, set: u32, clr: u32) -> bool {
        self.device_status() & (set | clr) == set
    }

    /// Get the status of virtio device.
    fn device_status(&self) -> u32 {
        self.virtio_base().device_status.load(Ordering::Acquire)
    }

    /// Set the status of virtio device.
    fn set_device_status(&mut self, val: u32) {
        self.virtio_base_mut()
            .device_status
            .store(val, Ordering::SeqCst)
    }

    /// Check device is activated or not.
    fn device_activated(&self) -> bool {
        self.virtio_base().device_activated.load(Ordering::Acquire)
    }

    /// Set device activate status.
    fn set_device_activated(&mut self, val: bool) {
        self.virtio_base_mut()
            .device_activated
            .store(val, Ordering::SeqCst)
    }

    /// Get config generation.
    fn config_generation(&self) -> u8 {
        self.virtio_base().config_generation.load(Ordering::Acquire)
    }

    /// Set config generation.
    fn set_config_generation(&mut self, val: u8) {
        self.virtio_base_mut()
            .config_generation
            .store(val, Ordering::SeqCst);
    }

    /// Get msix vector of config change interrupt.
    fn config_vector(&self) -> u16 {
        self.virtio_base().config_vector.load(Ordering::Acquire)
    }

    /// Set msix vector of config change interrupt.
    fn set_config_vector(&mut self, val: u16) {
        self.virtio_base_mut()
            .config_vector
            .store(val, Ordering::SeqCst);
    }

    /// Get virtqueue type.
    fn queue_type(&self) -> u16 {
        self.virtio_base().queue_type
    }

    /// Set virtqueue type.
    fn set_queue_type(&mut self, val: u16) {
        self.virtio_base_mut().queue_type = val;
    }

    /// Get virtqueue selector.
    fn queue_select(&self) -> u16 {
        self.virtio_base().queue_select
    }

    /// Set virtqueue selector.
    fn set_queue_select(&mut self, val: u16) {
        self.virtio_base_mut().queue_select = val;
    }

    /// Get virtqueue config.
    fn queue_config(&self) -> Result<&QueueConfig> {
        let queues_config = &self.virtio_base().queues_config;
        let queue_select = self.virtio_base().queue_select;
        queues_config
            .get(queue_select as usize)
            .with_context(|| "queue_select overflows")
    }

    /// Get mutable virtqueue config.
    fn queue_config_mut(&mut self, need_check: bool) -> Result<&mut QueueConfig> {
        if need_check
            && !self.check_device_status(
                CONFIG_STATUS_FEATURES_OK,
                CONFIG_STATUS_DRIVER_OK | CONFIG_STATUS_FAILED,
            )
        {
            return Err(anyhow!(VirtioError::DevStatErr(self.device_status())));
        }

        let queue_select = self.virtio_base().queue_select;
        let queues_config = &mut self.virtio_base_mut().queues_config;
        return queues_config
            .get_mut(queue_select as usize)
            .with_context(|| "queue_select overflows");
    }

    /// Get ISR register.
    fn interrupt_status(&self) -> u32 {
        self.virtio_base().interrupt_status.load(Ordering::Acquire)
    }

    /// Set ISR register.
    fn set_interrupt_status(&mut self, val: u32) {
        self.virtio_base_mut()
            .interrupt_status
            .store(val, Ordering::SeqCst)
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()>;

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()>;

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    ///
    /// # Arguments
    ///
    /// * `mem_space` - System mem.
    /// * `interrupt_cb` - The callback used to send interrupt to guest.
    /// * `queues` - The virtio queues.
    /// * `queue_evts` - The notifier events from guest.
    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()>;

    /// Deactivate virtio device, this function remove event fd
    /// of device out of the event loop.
    fn deactivate(&mut self) -> Result<()> {
        bail!(
            "Reset this device is not supported, virtio dev type is {}",
            self.device_type()
        );
    }

    /// Reset virtio device, used to do some special reset action for
    /// different device.
    fn reset(&mut self) -> Result<()> {
        Ok(())
    }

    /// Update the low level config of MMIO device,
    /// for example: update the images file fd of virtio block device.
    ///
    /// # Arguments
    ///
    /// * `_file_path` - The related backend file path.
    fn update_config(&mut self, _dev_config: Option<Arc<dyn ConfigCheck>>) -> Result<()> {
        bail!("Unsupported to update configuration")
    }

    /// Set guest notifiers for notifying the guest.
    ///
    /// # Arguments
    ///
    /// * `_queue_evts` - The notifier events from host.
    fn set_guest_notifiers(&mut self, _queue_evts: &[Arc<EventFd>]) -> Result<()> {
        Ok(())
    }

    /// Get whether the virtio device has a control queue,
    /// devices with a control queue should override this function.
    fn has_control_queue(&self) -> bool {
        false
    }
}

/// Check boundary for config space rw.
fn check_config_space_rw(config: &[u8], offset: u64, data: &[u8]) -> Result<()> {
    let config_len = config.len() as u64;
    let data_len = data.len() as u64;
    offset
        .checked_add(data_len)
        .filter(|&end| end <= config_len)
        .with_context(|| VirtioError::DevConfigOverflow(offset, data_len, config_len))?;
    Ok(())
}

/// Default implementation for config space read.
fn read_config_default(config: &[u8], offset: u64, mut data: &mut [u8]) -> Result<()> {
    check_config_space_rw(config, offset, data)?;
    let read_end = offset as usize + data.len();
    data.write_all(&config[offset as usize..read_end])?;
    Ok(())
}

/// The function used to inject interrupt to guest when encounter an virtio error.
pub fn report_virtio_error(
    interrupt_cb: Arc<VirtioInterrupt>,
    features: u64,
    broken: &Arc<AtomicBool>,
) {
    if virtio_has_feature(features, VIRTIO_F_VERSION_1) {
        interrupt_cb(&VirtioInterruptType::Config, None, true).unwrap_or_else(|e| {
            error!(
                "Failed to trigger interrupt for virtio error, error is {:?}",
                e
            )
        });
    }
    // The device should not work when meeting virtio error.
    broken.store(true, Ordering::SeqCst);
}

/// Read iovec to buf and return the read number of bytes.
pub fn iov_to_buf(mem_space: &AddressSpace, iovec: &[ElemIovec], buf: &mut [u8]) -> Result<usize> {
    let mut start: usize = 0;
    let mut end: usize = 0;

    for iov in iovec {
        let addr_map = mem_space.get_address_map(iov.addr, iov.len as u64)?;
        for addr in addr_map.into_iter() {
            end = cmp::min(start + addr.iov_len as usize, buf.len());
            mem_to_buf(&mut buf[start..end], addr.iov_base)?;
            if end >= buf.len() {
                return Ok(end);
            }
            start = end;
        }
    }
    Ok(end)
}

/// Discard "size" bytes of the front of iovec.
pub fn iov_discard_front(iovec: &mut [ElemIovec], mut size: u64) -> Option<&mut [ElemIovec]> {
    for (index, iov) in iovec.iter_mut().enumerate() {
        if iov.len as u64 > size {
            iov.addr.0 += size;
            iov.len -= size as u32;
            return Some(&mut iovec[index..]);
        }
        size -= iov.len as u64;
    }
    None
}

/// Discard "size" bytes of the back of iovec.
pub fn iov_discard_back(iovec: &mut [ElemIovec], mut size: u64) -> Option<&mut [ElemIovec]> {
    let len = iovec.len();
    for (index, iov) in iovec.iter_mut().rev().enumerate() {
        if iov.len as u64 > size {
            iov.len -= size as u32;
            return Some(&mut iovec[..(len - index)]);
        }
        size -= iov.len as u64;
    }
    None
}

/// Convert GPA buffer iovec to HVA buffer iovec.
/// If don't need the entire iovec, use iov_discard_front/iov_discard_back firstly.
fn gpa_hva_iovec_map(
    gpa_elemiovec: &[ElemIovec],
    mem_space: &AddressSpace,
) -> Result<(u64, Vec<Iovec>)> {
    let mut iov_size = 0;
    let mut hva_iovec = Vec::new();

    for elem in gpa_elemiovec.iter() {
        let mut hva_vec = mem_space.get_address_map(elem.addr, elem.len as u64)?;
        hva_iovec.append(&mut hva_vec);
        iov_size += elem.len as u64;
    }

    Ok((iov_size, hva_iovec))
}
