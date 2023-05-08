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

use std::cmp::{max, min};
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, Weak};

use address_space::{AddressRange, AddressSpace, GuestAddress, Region, RegionIoEventFd, RegionOps};
use anyhow::{anyhow, bail, Context};
use byteorder::{ByteOrder, LittleEndian};
use log::{error, warn};
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::{ByteCode, Desc};
use pci::config::{
    RegionType, BAR_SPACE_UNMAPPED, DEVICE_ID, MINMUM_BAR_SIZE_FOR_MMIO, PCIE_CONFIG_SPACE_SIZE,
    PCI_VENDOR_ID_REDHAT_QUMRANET, REG_SIZE, REVISION_ID, STATUS, STATUS_INTERRUPT, SUBSYSTEM_ID,
    SUBSYSTEM_VENDOR_ID, SUB_CLASS_CODE, VENDOR_ID,
};

use pci::msix::{update_dev_id, MsixState, MSIX_TABLE_ENTRY_SIZE};
use pci::Result as PciResult;
use pci::{
    config::PciConfig, init_intx, init_msix, init_multifunction, le_write_u16, le_write_u32,
    ranges_overlap, PciBus, PciDevOps, PciError,
};
use util::byte_code::ByteCode;
use util::num_ops::{read_data_u32, write_data_u32};
use util::offset_of;
use vmm_sys_util::eventfd::EventFd;

use crate::{
    virtio_has_feature, NotifyEventFds, Queue, QueueConfig, VirtioDevice, VirtioInterrupt,
    VirtioInterruptType,
};
use crate::{
    CONFIG_STATUS_ACKNOWLEDGE, CONFIG_STATUS_DRIVER, CONFIG_STATUS_DRIVER_OK, CONFIG_STATUS_FAILED,
    CONFIG_STATUS_FEATURES_OK, CONFIG_STATUS_NEEDS_RESET, INVALID_VECTOR_NUM,
    QUEUE_TYPE_PACKED_VRING, QUEUE_TYPE_SPLIT_VRING, VIRTIO_F_RING_PACKED, VIRTIO_F_VERSION_1,
    VIRTIO_MMIO_INT_CONFIG, VIRTIO_MMIO_INT_VRING, VIRTIO_TYPE_BLOCK, VIRTIO_TYPE_CONSOLE,
    VIRTIO_TYPE_FS, VIRTIO_TYPE_GPU, VIRTIO_TYPE_NET, VIRTIO_TYPE_SCSI,
};

const VIRTIO_QUEUE_MAX: u32 = 1024;

const VIRTIO_PCI_VENDOR_ID: u16 = PCI_VENDOR_ID_REDHAT_QUMRANET;
const VIRTIO_PCI_DEVICE_ID_BASE: u16 = 0x1040;
const VIRTIO_PCI_ABI_VERSION: u8 = 1;
const VIRTIO_PCI_CLASS_ID_NET: u16 = 0x0280;
const VIRTIO_PCI_CLASS_ID_BLOCK: u16 = 0x0100;
const VIRTIO_PCI_CLASS_ID_STORAGE_OTHER: u16 = 0x0180;
const VIRTIO_PCI_CLASS_ID_COMMUNICATION_OTHER: u16 = 0x0780;
#[cfg(target_arch = "aarch64")]
const VIRTIO_PCI_CLASS_ID_DISPLAY_OTHER: u16 = 0x0380;
#[cfg(target_arch = "x86_64")]
const VIRTIO_PCI_CLASS_ID_DISPLAY_VGA: u16 = 0x0300;
const VIRTIO_PCI_CLASS_ID_OTHERS: u16 = 0x00ff;

const VIRTIO_PCI_CAP_COMMON_OFFSET: u32 = 0x0;
const VIRTIO_PCI_CAP_COMMON_LENGTH: u32 = 0x1000;
const VIRTIO_PCI_CAP_ISR_OFFSET: u32 = 0x1000;
const VIRTIO_PCI_CAP_ISR_LENGTH: u32 = 0x1000;
const VIRTIO_PCI_CAP_DEVICE_OFFSET: u32 = 0x2000;
const VIRTIO_PCI_CAP_DEVICE_LENGTH: u32 = 0x1000;
const VIRTIO_PCI_CAP_NOTIFY_OFFSET: u32 = 0x3000;
const VIRTIO_PCI_CAP_NOTIFY_LENGTH: u32 = 0x1000;
const VIRTIO_PCI_CAP_NOTIFY_OFF_MULTIPLIER: u32 = 4;

const VIRTIO_PCI_BAR_MAX: u8 = 3;
const VIRTIO_PCI_MSIX_BAR_IDX: u8 = 1;
const VIRTIO_PCI_MEM_BAR_IDX: u8 = 2;

const PCI_CAP_VNDR_AND_NEXT_SIZE: u8 = 2;
const PCI_CAP_ID_VNDR: u8 = 0x9;

/// Device (host) features set selector - Read Write.
const COMMON_DFSELECT_REG: u64 = 0x0;
/// Bitmask of the features supported by the device(host) (32 bits per set) - Read Only.
const COMMON_DF_REG: u64 = 0x4;
/// Driver (guest) features set selector - Read Write.
const COMMON_GFSELECT_REG: u64 = 0x8;
/// Bitmask of features activated by the driver (guest) (32 bits per set) - Write Only.
const COMMON_GF_REG: u64 = 0xc;
/// The configuration vector for MSI-X - Read Write.
const COMMON_MSIX_REG: u64 = 0x10;
/// The maximum number of virtqueues supported - Read Only.
const COMMON_NUMQ_REG: u64 = 0x12;
/// Device status - Read Write.
const COMMON_STATUS_REG: u64 = 0x14;
/// Configuration atomicity value - Read Only.
const COMMON_CFGGENERATION_REG: u64 = 0x15;
/// Queue selector - Read Write.
const COMMON_Q_SELECT_REG: u64 = 0x16;
/// The size for the currently selected queue - Read Write.
const COMMON_Q_SIZE_REG: u64 = 0x18;
/// The queue vector for MSI-X - Read Write.
const COMMON_Q_MSIX_REG: u64 = 0x1a;
/// Ready bit for the currently selected queue - Read Write.
const COMMON_Q_ENABLE_REG: u64 = 0x1c;
/// The offset from start of Notification structure at which this virtqueue is located - Read only
const COMMON_Q_NOFF_REG: u64 = 0x1e;
/// The low 32bit of queue's Descriptor Table address - Read Write.
const COMMON_Q_DESCLO_REG: u64 = 0x20;
/// The high 32bit of queue's Descriptor Table address - Read Write.
const COMMON_Q_DESCHI_REG: u64 = 0x24;
/// The low 32 bit of queue's Available Ring address - Read Write.
const COMMON_Q_AVAILLO_REG: u64 = 0x28;
/// The high 32 bit of queue's Available Ring address - Read Write.
const COMMON_Q_AVAILHI_REG: u64 = 0x2c;
/// The low 32bit of queue's Used Ring address - Read Write.
const COMMON_Q_USEDLO_REG: u64 = 0x30;
/// The high 32bit of queue's Used Ring address - Read Write.
const COMMON_Q_USEDHI_REG: u64 = 0x34;

/// The max features select num, only 0 or 1 is valid:
///   0: select feature bits 0 to 31.
///   1: select feature bits 32 to 63.
const MAX_FEATURES_SELECT_NUM: u32 = 2;

/// Get class id according to device type.
///
/// # Arguments
///
/// * `device_type` - Device type set by the host.
fn get_virtio_class_id(device_type: u32) -> u16 {
    match device_type {
        VIRTIO_TYPE_BLOCK => VIRTIO_PCI_CLASS_ID_BLOCK,
        VIRTIO_TYPE_SCSI => VIRTIO_PCI_CLASS_ID_BLOCK,
        VIRTIO_TYPE_FS => VIRTIO_PCI_CLASS_ID_STORAGE_OTHER,
        VIRTIO_TYPE_NET => VIRTIO_PCI_CLASS_ID_NET,
        VIRTIO_TYPE_CONSOLE => VIRTIO_PCI_CLASS_ID_COMMUNICATION_OTHER,
        #[cfg(target_arch = "x86_64")]
        VIRTIO_TYPE_GPU => VIRTIO_PCI_CLASS_ID_DISPLAY_VGA,
        #[cfg(target_arch = "aarch64")]
        VIRTIO_TYPE_GPU => VIRTIO_PCI_CLASS_ID_DISPLAY_OTHER,
        _ => {
            warn!("Unknown device type, please make sure it is supported.");
            VIRTIO_PCI_CLASS_ID_OTHERS
        }
    }
}

/// The configuration of virtio-pci device, the fields refer to Virtio Spec.
#[derive(Clone)]
struct VirtioPciCommonConfig {
    /// Bitmask of the features supported by the device (host)(32 bits per set)
    features_select: u32,
    /// Device (host) feature-setting selector.
    acked_features_select: u32,
    /// Interrupt status.
    interrupt_status: u32,
    /// Device status.
    device_status: u32,
    /// Configuration atomicity value.
    config_generation: u8,
    /// Queue selector.
    queue_select: u16,
    /// The MSI-X vector for config change notification.
    msix_config: u16,
    /// The configuration of queues.
    queues_config: Vec<QueueConfig>,
    /// The type of queue, split-vring or packed-vring.
    queue_type: u16,
}

impl VirtioPciCommonConfig {
    fn new(queue_size: u16, queue_num: usize) -> Self {
        VirtioPciCommonConfig {
            features_select: 0,
            acked_features_select: 0,
            interrupt_status: 0,
            device_status: 0,
            config_generation: 0,
            queue_select: 0,
            msix_config: INVALID_VECTOR_NUM,
            queues_config: vec![QueueConfig::new(queue_size); queue_num],
            queue_type: QUEUE_TYPE_SPLIT_VRING,
        }
    }

    fn reset(&mut self) {
        self.features_select = 0;
        self.acked_features_select = 0;
        self.interrupt_status = 0;
        self.device_status = 0;
        self.config_generation = 0;
        self.queue_select = 0;
        self.msix_config = INVALID_VECTOR_NUM;
        self.queue_type = QUEUE_TYPE_SPLIT_VRING;
        self.queues_config.iter_mut().for_each(|q| q.reset());
    }

    fn check_device_status(&self, set: u32, clr: u32) -> bool {
        self.device_status & (set | clr) == set
    }

    fn get_mut_queue_config(&mut self, need_check: bool) -> PciResult<&mut QueueConfig> {
        if !need_check {
            return self
                .queues_config
                .get_mut(self.queue_select as usize)
                .with_context(|| "pci-reg queue_select overflows");
        }
        if self.check_device_status(
            CONFIG_STATUS_FEATURES_OK,
            CONFIG_STATUS_DRIVER_OK | CONFIG_STATUS_FAILED,
        ) {
            self.queues_config
                .get_mut(self.queue_select as usize)
                .with_context(|| "pci-reg queue_select overflows")
        } else {
            Err(anyhow!(PciError::DeviceStatus(self.device_status)))
        }
    }

    fn get_queue_config(&self) -> PciResult<&QueueConfig> {
        self.queues_config
            .get(self.queue_select as usize)
            .with_context(|| "pci-reg queue_select overflows")
    }

    fn revise_queue_vector(&self, vector_nr: u32, virtio_pci_dev: &VirtioPciDevice) -> u32 {
        let msix = &virtio_pci_dev.config.msix;
        if msix.is_none() {
            return INVALID_VECTOR_NUM as u32;
        }
        let max_vector =
            msix.as_ref().unwrap().lock().unwrap().table.len() / MSIX_TABLE_ENTRY_SIZE as usize;
        if vector_nr >= max_vector as u32 {
            INVALID_VECTOR_NUM as u32
        } else {
            vector_nr
        }
    }

    /// Read data from the common config of virtio device.
    /// Return the config value in u32.
    ///
    /// # Arguments
    ///
    /// * `device` - Virtio device entity.
    /// * `offset` - The offset of common config.
    fn read_common_config(
        &self,
        device: &Arc<Mutex<dyn VirtioDevice>>,
        offset: u64,
    ) -> PciResult<u32> {
        let value = match offset {
            COMMON_DFSELECT_REG => self.features_select,
            COMMON_DF_REG => {
                if self.features_select < MAX_FEATURES_SELECT_NUM {
                    device
                        .lock()
                        .unwrap()
                        .get_device_features(self.features_select)
                } else {
                    0
                }
            }
            COMMON_GFSELECT_REG => self.acked_features_select,
            COMMON_GF_REG => {
                if self.acked_features_select < MAX_FEATURES_SELECT_NUM {
                    device
                        .lock()
                        .unwrap()
                        .get_driver_features(self.acked_features_select)
                } else {
                    0
                }
            }
            COMMON_MSIX_REG => self.msix_config as u32,
            COMMON_NUMQ_REG => self.queues_config.len() as u32,
            COMMON_STATUS_REG => self.device_status,
            COMMON_CFGGENERATION_REG => self.config_generation as u32,
            COMMON_Q_SELECT_REG => self.queue_select as u32,
            COMMON_Q_SIZE_REG => self
                .get_queue_config()
                .map(|config| u32::from(config.size))?,
            COMMON_Q_MSIX_REG => self
                .get_queue_config()
                .map(|config| u32::from(config.vector))?,
            COMMON_Q_ENABLE_REG => self
                .get_queue_config()
                .map(|config| u32::from(config.ready))?,
            COMMON_Q_NOFF_REG => self.queue_select as u32,
            COMMON_Q_DESCLO_REG => self
                .get_queue_config()
                .map(|config| config.desc_table.0 as u32)?,
            COMMON_Q_DESCHI_REG => self
                .get_queue_config()
                .map(|config| (config.desc_table.0 >> 32) as u32)?,
            COMMON_Q_AVAILLO_REG => self
                .get_queue_config()
                .map(|config| config.avail_ring.0 as u32)?,
            COMMON_Q_AVAILHI_REG => self
                .get_queue_config()
                .map(|config| (config.avail_ring.0 >> 32) as u32)?,
            COMMON_Q_USEDLO_REG => self
                .get_queue_config()
                .map(|config| config.used_ring.0 as u32)?,
            COMMON_Q_USEDHI_REG => self
                .get_queue_config()
                .map(|config| (config.used_ring.0 >> 32) as u32)?,
            _ => 0,
        };

        Ok(value)
    }

    /// Write data to the common config of virtio device.
    ///
    /// # Arguments
    ///
    /// * `device` - Virtio device entity.
    /// * `offset` - The offset of common config.
    /// * `value` - The value to write.
    ///
    /// # Errors
    ///
    /// Returns Error if the offset is out of bound.
    fn write_common_config(
        &mut self,
        virtio_pci_dev: &VirtioPciDevice,
        offset: u64,
        value: u32,
    ) -> PciResult<()> {
        let device = virtio_pci_dev.device.clone();
        match offset {
            COMMON_DFSELECT_REG => {
                self.features_select = value;
            }
            COMMON_GFSELECT_REG => {
                self.acked_features_select = value;
            }
            COMMON_GF_REG => {
                if self.device_status & CONFIG_STATUS_FEATURES_OK != 0 {
                    error!("it's not allowed to set features after having been negoiated");
                    return Ok(());
                }
                if self.acked_features_select >= MAX_FEATURES_SELECT_NUM {
                    return Err(anyhow!(PciError::FeaturesSelect(
                        self.acked_features_select
                    )));
                }
                device
                    .lock()
                    .unwrap()
                    .set_driver_features(self.acked_features_select, value);

                if self.acked_features_select == 1 {
                    let features = (device.lock().unwrap().get_driver_features(1) as u64) << 32;
                    if virtio_has_feature(features, VIRTIO_F_RING_PACKED) {
                        self.queue_type = QUEUE_TYPE_PACKED_VRING;
                    } else {
                        self.queue_type = QUEUE_TYPE_SPLIT_VRING;
                    }
                }
            }
            COMMON_MSIX_REG => {
                let val = self.revise_queue_vector(value, virtio_pci_dev);
                self.msix_config = val as u16;
                self.interrupt_status = 0;
            }
            COMMON_STATUS_REG => {
                if value & CONFIG_STATUS_FEATURES_OK != 0 && value & CONFIG_STATUS_DRIVER_OK == 0 {
                    let features = (device.lock().unwrap().get_driver_features(1) as u64) << 32;
                    if !virtio_has_feature(features, VIRTIO_F_VERSION_1) {
                        error!(
                            "Device is modern only, but the driver not support VIRTIO_F_VERSION_1"
                        );
                        return Ok(());
                    }
                }
                if value != 0 && (self.device_status & !value) != 0 {
                    error!("Driver must not clear a device status bit");
                    return Ok(());
                }

                let old_status = self.device_status;
                self.device_status = value;
                if self.check_device_status(
                    CONFIG_STATUS_ACKNOWLEDGE
                        | CONFIG_STATUS_DRIVER
                        | CONFIG_STATUS_DRIVER_OK
                        | CONFIG_STATUS_FEATURES_OK,
                    CONFIG_STATUS_FAILED,
                ) {
                    virtio_pci_dev.activate_device(self);
                } else if old_status != 0 && self.device_status == 0 {
                    self.reset();
                    virtio_pci_dev.deactivate_device();
                }
            }
            COMMON_Q_SELECT_REG => {
                if value < VIRTIO_QUEUE_MAX {
                    self.queue_select = value as u16;
                }
            }
            COMMON_Q_SIZE_REG => self
                .get_mut_queue_config(true)
                .map(|config| config.size = value as u16)?,
            COMMON_Q_ENABLE_REG => {
                if value != 1 {
                    error!("Driver set illegal value for queue_enable {}", value);
                    return Err(anyhow!(PciError::QueueEnable(value)));
                }
                self.get_mut_queue_config(true)
                    .map(|config| config.ready = true)?;
            }
            COMMON_Q_MSIX_REG => {
                let val = self.revise_queue_vector(value, virtio_pci_dev);
                // It should not check device status when detaching device which
                // will set vector to INVALID_VECTOR_NUM.
                let mut need_check = true;
                if self.device_status == 0 {
                    need_check = false;
                }
                self.get_mut_queue_config(need_check)
                    .map(|config| config.vector = val as u16)?;
            }
            COMMON_Q_DESCLO_REG => self.get_mut_queue_config(true).map(|config| {
                config.desc_table = GuestAddress(config.desc_table.0 | u64::from(value));
            })?,
            COMMON_Q_DESCHI_REG => self.get_mut_queue_config(true).map(|config| {
                config.desc_table = GuestAddress(config.desc_table.0 | (u64::from(value) << 32));
            })?,
            COMMON_Q_AVAILLO_REG => self.get_mut_queue_config(true).map(|config| {
                config.avail_ring = GuestAddress(config.avail_ring.0 | u64::from(value));
            })?,
            COMMON_Q_AVAILHI_REG => self.get_mut_queue_config(true).map(|config| {
                config.avail_ring = GuestAddress(config.avail_ring.0 | (u64::from(value) << 32));
            })?,
            COMMON_Q_USEDLO_REG => self.get_mut_queue_config(true).map(|config| {
                config.used_ring = GuestAddress(config.used_ring.0 | u64::from(value));
            })?,
            COMMON_Q_USEDHI_REG => self.get_mut_queue_config(true).map(|config| {
                config.used_ring = GuestAddress(config.used_ring.0 | (u64::from(value) << 32));
            })?,
            _ => {
                return Err(anyhow!(PciError::PciRegister(offset)));
            }
        };

        Ok(())
    }
}

#[allow(clippy::upper_case_acronyms)]
#[repr(u8)]
enum VirtioPciCapType {
    Common = 1,
    Notify = 2,
    ISR = 3,
    Device = 4,
    CfgAccess = 5,
}

/// Virtio PCI Capability
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
struct VirtioPciCap {
    /// Capability length
    cap_len: u8,
    /// The type identifies the structure
    cfg_type: u8,
    /// The bar id where to find it
    bar_id: u8,
    /// Padding data
    padding: [u8; 3],
    /// Offset within bar
    offset: u32,
    /// Length of this structure, in bytes.
    length: u32,
}

impl ByteCode for VirtioPciCap {}

impl VirtioPciCap {
    fn new(cap_len: u8, cfg_type: u8, bar_id: u8, offset: u32, length: u32) -> Self {
        VirtioPciCap {
            cap_len,
            cfg_type,
            bar_id,
            padding: [0u8; 3],
            offset,
            length,
        }
    }
}

/// The struct of virtio pci capability for accessing BAR regions.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
struct VirtioPciCfgAccessCap {
    /// The struct of virtio pci capability.
    cap: VirtioPciCap,
    /// Data for BAR regions access.
    pci_cfg_data: [u8; 4],
}

impl ByteCode for VirtioPciCfgAccessCap {}

impl VirtioPciCfgAccessCap {
    fn new(cap_len: u8, cfg_type: u8) -> Self {
        VirtioPciCfgAccessCap {
            cap: VirtioPciCap::new(cap_len, cfg_type, 0, 0, 0),
            pci_cfg_data: [0; 4],
        }
    }
}

/// The struct of virtio pci capability for notifying the host
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
struct VirtioPciNotifyCap {
    /// The struct of virtio pci capability
    cap: VirtioPciCap,
    /// Multiplier for queue_notify_off
    notify_off_multiplier: u32,
}

impl ByteCode for VirtioPciNotifyCap {}

impl VirtioPciNotifyCap {
    fn new(
        cap_len: u8,
        cfg_type: u8,
        bar_id: u8,
        offset: u32,
        length: u32,
        notify_off_multiplier: u32,
    ) -> Self {
        VirtioPciNotifyCap {
            cap: VirtioPciCap::new(cap_len, cfg_type, bar_id, offset, length),
            notify_off_multiplier,
        }
    }
}

/// The state of virtio-pci device.
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct VirtioPciState {
    activated: bool,
    dev_id: u16,
    /// Max length of config_space is 4096.
    config_space: [u8; 4096],
    write_mask: [u8; 4096],
    write_clear_mask: [u8; 4096],
    last_cap_end: u16,
    last_ext_cap_offset: u16,
    last_ext_cap_end: u16,
    features_select: u32,
    acked_features_select: u32,
    interrupt_status: u32,
    device_status: u32,
    config_generation: u8,
    queue_select: u16,
    msix_config: u16,
    /// The configuration of queues. Max number of queues is 32(equals to MAX_VIRTIO_QUEUE).
    queues_config: [QueueConfig; 32],
    /// The number of queues.
    queue_num: usize,
}

/// Virtio-PCI device structure
#[derive(Clone)]
pub struct VirtioPciDevice {
    /// Name of this device
    name: String,
    /// The entity of virtio device
    device: Arc<Mutex<dyn VirtioDevice>>,
    /// Device id
    dev_id: Arc<AtomicU16>,
    /// Devfn
    devfn: u8,
    /// If this device is activated or not.
    device_activated: Arc<AtomicBool>,
    /// Memory AddressSpace
    sys_mem: Arc<AddressSpace>,
    /// Pci config space.
    config: PciConfig,
    /// Offset of VirtioPciCfgAccessCap in Pci config space.
    cfg_cap_offset: usize,
    /// Virtio common config refer to Virtio Spec.
    common_config: Arc<Mutex<VirtioPciCommonConfig>>,
    /// Primary Bus
    parent_bus: Weak<Mutex<PciBus>>,
    /// Eventfds used for guest notify the Device.
    notify_eventfds: Arc<NotifyEventFds>,
    /// The function for interrupt triggering
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    /// Virtio queues. The vector and Queue will be shared acrossing thread, so all with Arc<Mutex<..>> wrapper.
    queues: Arc<Mutex<Vec<Arc<Mutex<Queue>>>>>,
    /// Multi-Function flag.
    multi_func: bool,
    /// If the device need to register irqfd to kvm.
    need_irqfd: bool,
}

impl VirtioPciDevice {
    pub fn new(
        name: String,
        devfn: u8,
        sys_mem: Arc<AddressSpace>,
        device: Arc<Mutex<dyn VirtioDevice>>,
        parent_bus: Weak<Mutex<PciBus>>,
        multi_func: bool,
    ) -> Self {
        let queue_num = device.lock().unwrap().queue_num();
        let queue_size = device.lock().unwrap().queue_size();

        VirtioPciDevice {
            name,
            device,
            dev_id: Arc::new(AtomicU16::new(0)),
            devfn,
            device_activated: Arc::new(AtomicBool::new(false)),
            sys_mem,
            config: PciConfig::new(PCIE_CONFIG_SPACE_SIZE, VIRTIO_PCI_BAR_MAX),
            cfg_cap_offset: 0,
            common_config: Arc::new(Mutex::new(VirtioPciCommonConfig::new(
                queue_size, queue_num,
            ))),
            parent_bus,
            notify_eventfds: Arc::new(NotifyEventFds::new(queue_num)),
            interrupt_cb: None,
            queues: Arc::new(Mutex::new(Vec::with_capacity(queue_num))),
            multi_func,
            need_irqfd: false,
        }
    }

    pub fn enable_need_irqfd(&mut self) {
        self.need_irqfd = true;
    }

    fn assign_interrupt_cb(&mut self) {
        let cloned_common_cfg = self.common_config.clone();
        let cloned_msix = self.config.msix.as_ref().unwrap().clone();
        let cloned_intx = self.config.intx.as_ref().unwrap().clone();
        let dev_id = self.dev_id.clone();
        let cb = Arc::new(Box::new(
            move |int_type: &VirtioInterruptType, queue: Option<&Queue>, needs_reset: bool| {
                let vector = match int_type {
                    VirtioInterruptType::Config => {
                        let mut locked_common_cfg = cloned_common_cfg.lock().unwrap();
                        if needs_reset {
                            locked_common_cfg.device_status |= CONFIG_STATUS_NEEDS_RESET;
                            if locked_common_cfg.device_status & CONFIG_STATUS_DRIVER_OK == 0 {
                                return Ok(());
                            }
                        }
                        // Use (CONFIG | VRING) instead of CONFIG, it can be used to solve the
                        // IO stuck problem by change the device configure.
                        locked_common_cfg.interrupt_status |=
                            VIRTIO_MMIO_INT_CONFIG | VIRTIO_MMIO_INT_VRING;
                        locked_common_cfg.config_generation += 1;
                        locked_common_cfg.msix_config
                    }
                    VirtioInterruptType::Vring => {
                        let mut locked_common_cfg = cloned_common_cfg.lock().unwrap();
                        locked_common_cfg.interrupt_status |= VIRTIO_MMIO_INT_VRING;
                        queue.map_or(0, |q| q.vring.get_queue_config().vector)
                    }
                };

                let mut locked_msix = cloned_msix.lock().unwrap();
                if locked_msix.enabled {
                    locked_msix.notify(vector, dev_id.load(Ordering::Acquire));
                } else {
                    cloned_intx.lock().unwrap().notify(1);
                }

                Ok(())
            },
        ) as VirtioInterrupt);

        self.interrupt_cb = Some(cb);
    }

    fn ioeventfds(&self) -> Vec<RegionIoEventFd> {
        let mut ret = Vec::new();
        let eventfds = (*self.notify_eventfds).clone();
        for (index, eventfd) in eventfds.events.into_iter().enumerate() {
            let addr = index as u64 * u64::from(VIRTIO_PCI_CAP_NOTIFY_OFF_MULTIPLIER);
            ret.push(RegionIoEventFd {
                fd: eventfd.clone(),
                addr_range: AddressRange::from((addr, 2u64)),
                data_match: false,
                data: index as u64,
            })
        }

        ret
    }

    fn modern_mem_region_map<T: ByteCode>(&mut self, data: T) -> PciResult<usize> {
        let cap_offset = self.config.add_pci_cap(
            PCI_CAP_ID_VNDR,
            size_of::<T>() + PCI_CAP_VNDR_AND_NEXT_SIZE as usize,
        )?;

        let write_start = cap_offset + PCI_CAP_VNDR_AND_NEXT_SIZE as usize;
        self.config.config[write_start..(write_start + size_of::<T>())]
            .copy_from_slice(data.as_bytes());

        Ok(write_start)
    }

    fn activate_device(&self, common_cfg_lock: &mut VirtioPciCommonConfig) -> bool {
        if self.device_activated.load(Ordering::Acquire) {
            return true;
        }

        let queue_type = common_cfg_lock.queue_type;
        let queues_config = &mut common_cfg_lock.queues_config;
        let mut locked_queues = self.queues.lock().unwrap();
        for q_config in queues_config.iter_mut() {
            if !q_config.ready {
                warn!("queue is not ready, please check your init process");
            } else {
                q_config.addr_cache.desc_table_host = self
                    .sys_mem
                    .get_host_address(q_config.desc_table)
                    .unwrap_or(0);
                q_config.addr_cache.avail_ring_host = self
                    .sys_mem
                    .get_host_address(q_config.avail_ring)
                    .unwrap_or(0);
                q_config.addr_cache.used_ring_host = self
                    .sys_mem
                    .get_host_address(q_config.used_ring)
                    .unwrap_or(0);
            }
            let queue = Queue::new(*q_config, queue_type).unwrap();
            if q_config.ready && !queue.is_valid(&self.sys_mem) {
                error!("Failed to activate device: Invalid queue");
                return false;
            }
            let arc_queue = Arc::new(Mutex::new(queue));
            locked_queues.push(arc_queue.clone());
        }
        drop(locked_queues);

        update_dev_id(&self.parent_bus, self.devfn, &self.dev_id);
        if self.need_irqfd {
            let mut queue_num = self.device.lock().unwrap().queue_num();
            // No need to create call event for control queue.
            // It will be polled in StratoVirt when activating the device.
            if self.device.lock().unwrap().has_control_queue() && queue_num % 2 != 0 {
                queue_num -= 1;
            }
            let call_evts = NotifyEventFds::new(queue_num);
            if let Err(e) = self
                .device
                .lock()
                .unwrap()
                .set_guest_notifiers(&call_evts.events)
            {
                error!("Failed to set guest notifiers, error is {:?}", e);
                return false;
            }
            if !self.queues_register_irqfd(&call_evts.events) {
                error!("Failed to register queues irqfd.");
                return false;
            }
        }

        let queue_evts = (*self.notify_eventfds).clone().events;
        if let Err(e) = self.device.lock().unwrap().activate(
            self.sys_mem.clone(),
            self.interrupt_cb.clone().unwrap(),
            &self.queues.lock().unwrap(),
            queue_evts,
        ) {
            error!("Failed to activate device, error is {:?}", e);
            return false;
        }

        self.device_activated.store(true, Ordering::Release);
        true
    }

    fn deactivate_device(&self) -> bool {
        if self.need_irqfd && self.config.msix.is_some() {
            let msix = self.config.msix.as_ref().unwrap();
            if msix.lock().unwrap().unregister_irqfd().is_err() {
                return false;
            }
        }

        self.queues.lock().unwrap().clear();
        if self.device_activated.load(Ordering::Acquire) {
            self.device_activated.store(false, Ordering::Release);
            if let Err(e) = self.device.lock().unwrap().deactivate() {
                error!("Failed to deactivate virtio device, error is {:?}", e);
                return false;
            }
        }
        true
    }

    fn build_common_cfg_ops(&mut self) -> RegionOps {
        let cloned_virtio_dev = self.device.clone();
        let cloned_common_cfg = self.common_config.clone();
        let common_read = move |data: &mut [u8], _addr: GuestAddress, offset: u64| -> bool {
            let value = match cloned_common_cfg
                .lock()
                .unwrap()
                .read_common_config(&cloned_virtio_dev, offset)
            {
                Ok(v) => v,
                Err(e) => {
                    error!(
                        "Failed to read common config of virtio-pci device, error is {:?}",
                        e,
                    );
                    return false;
                }
            };

            write_data_u32(data, value)
        };

        let cloned_pci_device = self.clone();
        let common_write = move |data: &[u8], _addr: GuestAddress, offset: u64| -> bool {
            let mut value = 0;
            if !read_data_u32(data, &mut value) {
                return false;
            }

            if let Err(e) = cloned_pci_device
                .common_config
                .lock()
                .unwrap()
                .write_common_config(&cloned_pci_device, offset, value)
            {
                error!(
                    "Failed to write common config of virtio-pci device, error is {:?}",
                    e,
                );
                return false;
            }
            true
        };

        RegionOps {
            read: Arc::new(common_read),
            write: Arc::new(common_write),
        }
    }

    fn modern_mem_region_init(&mut self, modern_mem_region: &Region) -> PciResult<()> {
        // 1. PCI common cap sub-region.
        let common_region_ops = self.build_common_cfg_ops();
        let common_region =
            Region::init_io_region(u64::from(VIRTIO_PCI_CAP_COMMON_LENGTH), common_region_ops);
        modern_mem_region
            .add_subregion(common_region, u64::from(VIRTIO_PCI_CAP_COMMON_OFFSET))
            .with_context(|| "Failed to register pci-common-cap region.")?;

        // 2. PCI ISR cap sub-region.
        let cloned_common_cfg = self.common_config.clone();
        let cloned_intx = self.config.intx.as_ref().unwrap().clone();
        let isr_read = move |data: &mut [u8], _: GuestAddress, _: u64| -> bool {
            if let Some(val) = data.get_mut(0) {
                let mut common_cfg_lock = cloned_common_cfg.lock().unwrap();
                *val = common_cfg_lock.interrupt_status as u8;
                common_cfg_lock.interrupt_status = 0;
                cloned_intx.lock().unwrap().notify(0);
            }
            true
        };
        let isr_write = move |_: &[u8], _: GuestAddress, _: u64| -> bool { true };
        let isr_region_ops = RegionOps {
            read: Arc::new(isr_read),
            write: Arc::new(isr_write),
        };
        let isr_region =
            Region::init_io_region(u64::from(VIRTIO_PCI_CAP_ISR_LENGTH), isr_region_ops);
        modern_mem_region
            .add_subregion(isr_region, u64::from(VIRTIO_PCI_CAP_ISR_OFFSET))
            .with_context(|| "Failed to register pci-isr-cap region.")?;

        // 3. PCI dev cap sub-region.
        let cloned_virtio_dev = self.device.clone();
        let device_read = move |data: &mut [u8], _addr: GuestAddress, offset: u64| -> bool {
            if let Err(e) = cloned_virtio_dev.lock().unwrap().read_config(offset, data) {
                error!("Failed to read virtio-dev config space, error is {:?}", e);
                return false;
            }
            true
        };

        let cloned_virtio_dev = self.device.clone();
        let device_write = move |data: &[u8], _addr: GuestAddress, offset: u64| -> bool {
            if let Err(e) = cloned_virtio_dev.lock().unwrap().write_config(offset, data) {
                error!("Failed to write virtio-dev config space, error is {:?}", e);
                return false;
            }
            true
        };
        let device_region_ops = RegionOps {
            read: Arc::new(device_read),
            write: Arc::new(device_write),
        };
        let device_region =
            Region::init_io_region(u64::from(VIRTIO_PCI_CAP_DEVICE_LENGTH), device_region_ops);
        modern_mem_region
            .add_subregion(device_region, u64::from(VIRTIO_PCI_CAP_DEVICE_OFFSET))
            .with_context(|| "Failed to register pci-dev-cap region.")?;

        // 4. PCI notify cap sub-region.
        let notify_read = move |_: &mut [u8], _: GuestAddress, _: u64| -> bool { true };
        let notify_write = move |_: &[u8], _: GuestAddress, _: u64| -> bool { true };
        let notify_region_ops = RegionOps {
            read: Arc::new(notify_read),
            write: Arc::new(notify_write),
        };
        let notify_region =
            Region::init_io_region(u64::from(VIRTIO_PCI_CAP_NOTIFY_LENGTH), notify_region_ops);
        notify_region.set_ioeventfds(&self.ioeventfds());
        modern_mem_region
            .add_subregion(notify_region, u64::from(VIRTIO_PCI_CAP_NOTIFY_OFFSET))
            .with_context(|| "Failed to register pci-notify-cap region.")?;

        Ok(())
    }

    // Access virtio configuration through VirtioPciCfgAccessCap.
    fn do_cfg_access(&mut self, start: usize, end: usize, is_write: bool) {
        let pci_cfg_data_offset =
            self.cfg_cap_offset + offset_of!(VirtioPciCfgAccessCap, pci_cfg_data);
        let cap_size = size_of::<VirtioPciCfgAccessCap>();
        if !ranges_overlap(start, end - start, pci_cfg_data_offset, cap_size) {
            return;
        }

        let config = &self.config.config[self.cfg_cap_offset..];
        let bar = config[offset_of!(VirtioPciCap, bar_id)];
        let off = LittleEndian::read_u32(&config[offset_of!(VirtioPciCap, offset)..]);
        let len = LittleEndian::read_u32(&config[offset_of!(VirtioPciCap, length)..]);
        if bar >= VIRTIO_PCI_BAR_MAX {
            warn!("The bar_id {} of VirtioPciCfgAccessCap exceeds max", bar);
            return;
        }
        let bar_base = self.config.get_bar_address(bar as usize);
        if bar_base == BAR_SPACE_UNMAPPED {
            warn!("The bar {} of VirtioPciCfgAccessCap is not mapped", bar);
            return;
        }
        if ![1, 2, 4].contains(&len) {
            warn!("The length {} of VirtioPciCfgAccessCap is illegal", len);
            return;
        }
        if off & (len - 1) != 0 {
            warn!("The offset {} of VirtioPciCfgAccessCap is not aligned", off);
            return;
        }
        if (off as u64)
            .checked_add(len as u64)
            .filter(|&end| end <= self.config.bars[bar as usize].size)
            .is_none()
        {
            warn!("The access range of VirtioPciCfgAccessCap exceeds bar size");
            return;
        }

        let result = if is_write {
            let mut data = self.config.config[pci_cfg_data_offset..].as_ref();
            self.sys_mem
                .write(&mut data, GuestAddress(bar_base + off as u64), len as u64)
        } else {
            let mut data = self.config.config[pci_cfg_data_offset..].as_mut();
            self.sys_mem
                .read(&mut data, GuestAddress(bar_base + off as u64), len as u64)
        };
        if let Err(e) = result {
            error!(
                "Failed to access virtio configuration through VirtioPciCfgAccessCap. {:?}",
                e
            );
        }
    }

    pub fn virtio_pci_auto_queues_num(queues_fixed: u16, nr_cpus: u8, queues_max: usize) -> u16 {
        // Give each vcpu a vq, allow the vCPU that submit request can handle
        // its own request completion. i.e, If the vq is not enough, vcpu A will
        // receive completion of request that submitted by vcpu B, then A needs
        // to IPI B.
        min(queues_max as u16 - queues_fixed, nr_cpus as u16)
    }

    fn queues_register_irqfd(&self, call_fds: &[Arc<EventFd>]) -> bool {
        let mut locked_msix = if let Some(msix) = &self.config.msix {
            msix.lock().unwrap()
        } else {
            error!("Failed to get msix in virtio pci device configure");
            return false;
        };

        let locked_queues = self.queues.lock().unwrap();
        for (queue_index, queue_mutex) in locked_queues.iter().enumerate() {
            if self.device.lock().unwrap().has_control_queue()
                && queue_index + 1 == locked_queues.len()
                && locked_queues.len() % 2 != 0
            {
                break;
            }

            let vector = queue_mutex.lock().unwrap().vring.get_queue_config().vector;
            if vector == INVALID_VECTOR_NUM {
                continue;
            }

            if locked_msix
                .register_irqfd(vector, call_fds[queue_index].clone())
                .is_err()
            {
                return false;
            }
        }

        true
    }

    pub fn get_virtio_device(&self) -> &Arc<Mutex<dyn VirtioDevice>> {
        &self.device
    }
}

impl PciDevOps for VirtioPciDevice {
    fn init_write_mask(&mut self) -> PciResult<()> {
        self.config.init_common_write_mask()
    }

    fn init_write_clear_mask(&mut self) -> PciResult<()> {
        self.config.init_common_write_clear_mask()
    }

    fn realize(mut self) -> PciResult<()> {
        self.init_write_mask()?;
        self.init_write_clear_mask()?;

        let device_type = self.device.lock().unwrap().device_type();
        le_write_u16(
            &mut self.config.config,
            VENDOR_ID as usize,
            VIRTIO_PCI_VENDOR_ID,
        )?;
        le_write_u16(
            &mut self.config.config,
            DEVICE_ID as usize,
            VIRTIO_PCI_DEVICE_ID_BASE + device_type as u16,
        )?;
        self.config.config[REVISION_ID] = VIRTIO_PCI_ABI_VERSION;
        let class_id = get_virtio_class_id(device_type);
        le_write_u16(&mut self.config.config, SUB_CLASS_CODE as usize, class_id)?;
        le_write_u16(
            &mut self.config.config,
            SUBSYSTEM_VENDOR_ID,
            VIRTIO_PCI_VENDOR_ID,
        )?;
        le_write_u16(
            &mut self.config.config,
            SUBSYSTEM_ID,
            0x40 + device_type as u16,
        )?;
        init_multifunction(
            self.multi_func,
            &mut self.config.config,
            self.devfn,
            self.parent_bus.clone(),
        )?;
        #[cfg(target_arch = "aarch64")]
        self.config.set_interrupt_pin();

        let common_cap = VirtioPciCap::new(
            size_of::<VirtioPciCap>() as u8 + PCI_CAP_VNDR_AND_NEXT_SIZE,
            VirtioPciCapType::Common as u8,
            VIRTIO_PCI_MEM_BAR_IDX,
            VIRTIO_PCI_CAP_COMMON_OFFSET,
            VIRTIO_PCI_CAP_COMMON_LENGTH,
        );
        self.modern_mem_region_map(common_cap)?;

        let isr_cap = VirtioPciCap::new(
            size_of::<VirtioPciCap>() as u8 + PCI_CAP_VNDR_AND_NEXT_SIZE,
            VirtioPciCapType::ISR as u8,
            VIRTIO_PCI_MEM_BAR_IDX,
            VIRTIO_PCI_CAP_ISR_OFFSET,
            VIRTIO_PCI_CAP_ISR_LENGTH,
        );
        self.modern_mem_region_map(isr_cap)?;

        let device_cap = VirtioPciCap::new(
            size_of::<VirtioPciCap>() as u8 + PCI_CAP_VNDR_AND_NEXT_SIZE,
            VirtioPciCapType::Device as u8,
            VIRTIO_PCI_MEM_BAR_IDX,
            VIRTIO_PCI_CAP_DEVICE_OFFSET,
            VIRTIO_PCI_CAP_DEVICE_LENGTH,
        );
        self.modern_mem_region_map(device_cap)?;

        let notify_cap = VirtioPciNotifyCap::new(
            size_of::<VirtioPciNotifyCap>() as u8 + PCI_CAP_VNDR_AND_NEXT_SIZE,
            VirtioPciCapType::Notify as u8,
            VIRTIO_PCI_MEM_BAR_IDX,
            VIRTIO_PCI_CAP_NOTIFY_OFFSET,
            VIRTIO_PCI_CAP_NOTIFY_LENGTH,
            VIRTIO_PCI_CAP_NOTIFY_OFF_MULTIPLIER,
        );
        self.modern_mem_region_map(notify_cap)?;

        let cfg_cap = VirtioPciCfgAccessCap::new(
            size_of::<VirtioPciCfgAccessCap>() as u8 + PCI_CAP_VNDR_AND_NEXT_SIZE,
            VirtioPciCapType::CfgAccess as u8,
        );
        self.cfg_cap_offset = self.modern_mem_region_map(cfg_cap)?;

        // Make related fields of PCI config writable for VirtioPciCfgAccessCap.
        let write_mask = &mut self.config.write_mask[self.cfg_cap_offset..];
        write_mask[offset_of!(VirtioPciCap, bar_id)] = !0;
        le_write_u32(write_mask, offset_of!(VirtioPciCap, offset), !0)?;
        le_write_u32(write_mask, offset_of!(VirtioPciCap, length), !0)?;
        le_write_u32(
            write_mask,
            offset_of!(VirtioPciCfgAccessCap, pci_cfg_data),
            !0,
        )?;

        let nvectors = self.device.lock().unwrap().queue_num() + 1;

        init_msix(
            VIRTIO_PCI_MSIX_BAR_IDX as usize,
            nvectors as u32,
            &mut self.config,
            self.dev_id.clone(),
            &self.name,
            None,
            None,
        )?;

        init_intx(
            self.name.clone(),
            &mut self.config,
            self.parent_bus.clone(),
            self.devfn,
        )?;

        self.assign_interrupt_cb();

        let mut mem_region_size = ((VIRTIO_PCI_CAP_NOTIFY_OFFSET + VIRTIO_PCI_CAP_NOTIFY_LENGTH)
            as u64)
            .next_power_of_two();
        mem_region_size = max(mem_region_size, MINMUM_BAR_SIZE_FOR_MMIO as u64);
        let modern_mem_region = Region::init_container_region(mem_region_size);
        self.modern_mem_region_init(&modern_mem_region)?;

        self.config.register_bar(
            VIRTIO_PCI_MEM_BAR_IDX as usize,
            modern_mem_region,
            RegionType::Mem64Bit,
            false,
            mem_region_size,
        )?;

        self.device
            .lock()
            .unwrap()
            .realize()
            .with_context(|| "Failed to realize virtio device")?;

        let name = self.name.clone();
        let devfn = self.devfn;
        let dev = Arc::new(Mutex::new(self));
        let pci_bus = dev.lock().unwrap().parent_bus.upgrade().unwrap();
        let mut locked_pci_bus = pci_bus.lock().unwrap();
        let pci_device = locked_pci_bus.devices.get(&devfn);
        if pci_device.is_none() {
            locked_pci_bus.devices.insert(devfn, dev.clone());
        } else {
            bail!(
                "Devfn {:?} has been used by {:?}",
                &devfn,
                pci_device.unwrap().lock().unwrap().name()
            );
        }
        MigrationManager::register_transport_instance(VirtioPciState::descriptor(), dev, &name);

        Ok(())
    }

    fn unrealize(&mut self) -> PciResult<()> {
        self.device
            .lock()
            .unwrap()
            .unrealize()
            .with_context(|| "Failed to unrealize the virtio device")?;

        let bus = self.parent_bus.upgrade().unwrap();
        self.config.unregister_bars(&bus)?;

        MigrationManager::unregister_device_instance(MsixState::descriptor(), &self.name);
        MigrationManager::unregister_transport_instance(VirtioPciState::descriptor(), &self.name);

        Ok(())
    }

    fn read_config(&mut self, offset: usize, data: &mut [u8]) {
        self.do_cfg_access(offset, offset + data.len(), false);
        self.config.read(offset, data);
    }

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let data_size = data.len();
        let end = offset + data_size;
        if end > PCIE_CONFIG_SPACE_SIZE || data_size > REG_SIZE {
            error!(
                "Failed to write pcie config space at offset 0x{:x} with data size {}",
                offset, data_size
            );
            return;
        }

        let parent_bus = self.parent_bus.upgrade().unwrap();
        let locked_parent_bus = parent_bus.lock().unwrap();
        self.config.write(
            offset,
            data,
            self.dev_id.clone().load(Ordering::Acquire),
            #[cfg(target_arch = "x86_64")]
            Some(&locked_parent_bus.io_region),
            Some(&locked_parent_bus.mem_region),
        );
        self.do_cfg_access(offset, end, true);
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn devfn(&self) -> Option<u8> {
        Some(self.devfn)
    }

    fn reset(&mut self, _reset_child_device: bool) -> PciResult<()> {
        self.deactivate_device();
        self.device
            .lock()
            .unwrap()
            .reset()
            .with_context(|| "Failed to reset virtio device")?;
        self.common_config.lock().unwrap().reset();

        self.config.reset()?;

        Ok(())
    }

    fn get_dev_path(&self) -> Option<String> {
        let parent_bus = self.parent_bus.upgrade().unwrap();
        match self.device.lock().unwrap().device_type() {
            VIRTIO_TYPE_BLOCK => {
                // The virtio blk device is identified as a single-channel SCSI device,
                // so add scsi controller identification without channel, scsi-id and lun.
                let parent_dev_path = self.get_parent_dev_path(parent_bus);
                let mut dev_path = self.populate_dev_path(parent_dev_path, self.devfn, "/scsi@");
                dev_path.push_str("/disk@0,0");
                Some(dev_path)
            }
            VIRTIO_TYPE_SCSI => {
                // The virtio scsi controller can not set boot order, which is set for scsi device.
                // All the scsi devices in the same scsi controller have the same boot path prefix
                // (eg: /pci@XXXXX/scsi@$slot_id[,function_id]). And every scsi device has it's
                // own boot path("/channel@0/disk@$target_id,$lun_id");
                let parent_dev_path = self.get_parent_dev_path(parent_bus);
                let dev_path = self.populate_dev_path(parent_dev_path, self.devfn, "/scsi@");
                Some(dev_path)
            }
            _ => None,
        }
    }
}

impl StateTransfer for VirtioPciDevice {
    fn get_state_vec(&self) -> migration::Result<Vec<u8>> {
        let mut state = VirtioPciState::default();

        // Save virtio pci config state.
        for idx in 0..self.config.config.len() {
            // Clean interrupt status bit.
            if (idx as u8) == STATUS {
                state.config_space[idx] = self.config.config[idx] & (!STATUS_INTERRUPT);
            } else {
                state.config_space[idx] = self.config.config[idx];
            }
            state.write_mask[idx] = self.config.write_mask[idx];
            state.write_clear_mask[idx] = self.config.write_clear_mask[idx];
        }
        state.last_cap_end = self.config.last_cap_end;
        state.last_ext_cap_offset = self.config.last_ext_cap_offset;
        state.last_ext_cap_end = self.config.last_ext_cap_end;

        // Save virtio pci common config state.
        {
            let common_config = self.common_config.lock().unwrap();
            state.interrupt_status = common_config.interrupt_status;
            state.msix_config = common_config.msix_config;
            state.features_select = common_config.features_select;
            state.acked_features_select = common_config.acked_features_select;
            state.device_status = common_config.device_status;
            state.config_generation = common_config.config_generation;
            state.queue_select = common_config.queue_select;
        }

        // Save virtio pci state.
        state.activated = self.device_activated.load(Ordering::Relaxed);
        state.dev_id = self.dev_id.load(Ordering::Acquire);
        {
            let locked_queues = self.queues.lock().unwrap();
            for (index, queue) in locked_queues.iter().enumerate() {
                state.queues_config[index] = queue.lock().unwrap().vring.get_queue_config();
                state.queue_num += 1;
            }
        }

        Ok(state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> migration::Result<()> {
        let mut pci_state = *VirtioPciState::from_bytes(state)
            .with_context(|| migration::error::MigrationError::FromBytesError("PCI_DEVICE"))?;

        // Set virtio pci config state.
        let config_length = self.config.config.len();
        self.config.config = pci_state.config_space[..config_length].to_vec();
        self.config.write_mask = pci_state.write_mask[..config_length].to_vec();
        self.config.write_clear_mask = pci_state.write_clear_mask[..config_length].to_vec();
        self.config.last_cap_end = pci_state.last_cap_end;
        self.config.last_ext_cap_end = pci_state.last_ext_cap_end;
        self.config.last_ext_cap_offset = pci_state.last_ext_cap_offset;

        // Set virtio pci common config state.
        {
            let mut common_config = self.common_config.lock().unwrap();
            common_config.interrupt_status = pci_state.interrupt_status;
            common_config.msix_config = pci_state.msix_config;
            common_config.features_select = pci_state.features_select;
            common_config.acked_features_select = pci_state.acked_features_select;
            common_config.device_status = pci_state.device_status;
            common_config.config_generation = pci_state.config_generation;
            common_config.queue_select = pci_state.queue_select;
        }

        // Set virtio pci state.
        self.device_activated
            .store(pci_state.activated, Ordering::Relaxed);
        self.dev_id.store(pci_state.dev_id, Ordering::Release);
        {
            let queue_type = self.common_config.lock().unwrap().queue_type;
            let mut locked_queues = self.queues.lock().unwrap();
            let cloned_mem_space = self.sys_mem.clone();
            for queue_state in pci_state.queues_config[0..pci_state.queue_num].iter_mut() {
                queue_state.addr_cache.desc_table_host = cloned_mem_space
                    .get_host_address(queue_state.desc_table)
                    .unwrap_or(0);
                queue_state.addr_cache.avail_ring_host = cloned_mem_space
                    .get_host_address(queue_state.avail_ring)
                    .unwrap_or(0);
                queue_state.addr_cache.used_ring_host = cloned_mem_space
                    .get_host_address(queue_state.used_ring)
                    .unwrap_or(0);
                locked_queues.push(Arc::new(Mutex::new(
                    Queue::new(*queue_state, queue_type).unwrap(),
                )))
            }
        }

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&VirtioPciState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for VirtioPciDevice {
    fn resume(&mut self) -> migration::Result<()> {
        if self.device_activated.load(Ordering::Relaxed) {
            // Reregister ioevents for notifies.
            let parent_bus = self.parent_bus.upgrade().unwrap();
            let locked_parent_bus = parent_bus.lock().unwrap();
            if let Err(e) = self.config.update_bar_mapping(
                #[cfg(target_arch = "x86_64")]
                Some(&locked_parent_bus.io_region),
                Some(&locked_parent_bus.mem_region),
            ) {
                bail!("Failed to update bar, error is {:?}", e);
            }

            let queue_evts = (*self.notify_eventfds).clone().events;
            if let Some(cb) = self.interrupt_cb.clone() {
                if let Err(e) = self.device.lock().unwrap().activate(
                    self.sys_mem.clone(),
                    cb,
                    &self.queues.lock().unwrap(),
                    queue_evts,
                ) {
                    error!("Failed to resume device, error is {:?}", e);
                }
            } else {
                error!("Failed to resume device: No interrupt callback");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use address_space::{AddressSpace, GuestAddress, HostMemMapping};
    use pci::{
        config::{HEADER_TYPE, HEADER_TYPE_MULTIFUNC},
        le_read_u16,
    };
    use util::num_ops::read_u32;
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::Result as VirtioResult;

    const VIRTIO_DEVICE_TEST_TYPE: u32 = 1;
    const VIRTIO_DEVICE_QUEUE_NUM: usize = 2;
    const VIRTIO_DEVICE_QUEUE_SIZE: u16 = 256;

    pub struct VirtioDeviceTest {
        pub device_features: u64,
        pub driver_features: u64,
        pub is_activated: bool,
    }

    impl VirtioDeviceTest {
        pub fn new() -> Self {
            VirtioDeviceTest {
                device_features: 0xFFFF_FFF0,
                driver_features: 0,
                is_activated: false,
            }
        }
    }

    impl VirtioDevice for VirtioDeviceTest {
        fn realize(&mut self) -> VirtioResult<()> {
            Ok(())
        }

        fn device_type(&self) -> u32 {
            VIRTIO_DEVICE_TEST_TYPE
        }

        fn queue_num(&self) -> usize {
            VIRTIO_DEVICE_QUEUE_NUM
        }

        fn queue_size(&self) -> u16 {
            VIRTIO_DEVICE_QUEUE_SIZE
        }

        fn get_device_features(&self, features_select: u32) -> u32 {
            read_u32(self.device_features, features_select)
        }

        fn set_driver_features(&mut self, page: u32, value: u32) {
            self.driver_features = self.checked_driver_features(page, value);
        }

        fn get_driver_features(&self, features_select: u32) -> u32 {
            read_u32(self.driver_features, features_select)
        }

        fn read_config(&self, _offset: u64, mut _data: &mut [u8]) -> VirtioResult<()> {
            Ok(())
        }

        fn write_config(&mut self, _offset: u64, _data: &[u8]) -> VirtioResult<()> {
            Ok(())
        }

        fn activate(
            &mut self,
            _mem_space: Arc<AddressSpace>,
            _interrupt_cb: Arc<VirtioInterrupt>,
            _queues: &[Arc<Mutex<Queue>>],
            _queue_evts: Vec<Arc<EventFd>>,
        ) -> VirtioResult<()> {
            self.is_activated = true;
            Ok(())
        }
    }

    macro_rules! com_cfg_read_test {
        ($cfg: ident, $dev: ident, $reg: ident, $expect: expr) => {
            assert_eq!($cfg.read_common_config(&$dev, $reg).unwrap(), $expect)
        };
    }
    macro_rules! com_cfg_write_test {
        ($cfg: ident, $dev: ident, $reg: ident, $val: expr) => {
            assert!($cfg.write_common_config(&$dev, $reg, $val).is_ok())
        };
    }

    #[test]
    fn test_common_config_dev_feature() {
        let dev = Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let virtio_dev = dev.clone() as Arc<Mutex<dyn VirtioDevice>>;
        let sys_mem = AddressSpace::new(Region::init_container_region(u64::max_value())).unwrap();
        let parent_bus = Arc::new(Mutex::new(PciBus::new(
            String::from("test bus"),
            #[cfg(target_arch = "x86_64")]
            Region::init_container_region(1 << 16),
            sys_mem.root().clone(),
        )));
        let cloned_virtio_dev = virtio_dev.clone();
        let virtio_pci = VirtioPciDevice::new(
            String::from("test device"),
            0,
            sys_mem,
            cloned_virtio_dev,
            Arc::downgrade(&parent_bus),
            false,
        );

        let queue_size = dev.lock().unwrap().queue_size();
        let queue_num = dev.lock().unwrap().queue_num();

        let mut cmn_cfg = VirtioPciCommonConfig::new(queue_size, queue_num);

        // Read virtio device features
        cmn_cfg.features_select = 0_u32;
        com_cfg_read_test!(cmn_cfg, virtio_dev, COMMON_DF_REG, 0xFFFF_FFF0_u32);
        cmn_cfg.features_select = 1_u32;
        com_cfg_read_test!(cmn_cfg, virtio_dev, COMMON_DF_REG, 0_u32);

        // Write virtio device features
        cmn_cfg.acked_features_select = 1_u32;
        com_cfg_write_test!(cmn_cfg, virtio_pci, COMMON_GF_REG, 0xFF);
        // The feature is not supported by this virtio device, and is masked
        assert_eq!(dev.lock().unwrap().driver_features, 0_u64);

        cmn_cfg.acked_features_select = 0_u32;
        com_cfg_write_test!(cmn_cfg, virtio_pci, COMMON_GF_REG, 0xCF);
        // The feature is partially supported by this virtio device, and is partially masked
        assert_eq!(dev.lock().unwrap().driver_features, 0xC0_u64);

        // Set the feature of the Queue type
        cmn_cfg.acked_features_select = 1_u32;
        dev.lock().unwrap().driver_features = 0_u64;
        dev.lock().unwrap().device_features = 0xFFFF_FFFF_0000_0000_u64;
        let driver_features = 1_u32 << (VIRTIO_F_RING_PACKED - 32);
        com_cfg_write_test!(cmn_cfg, virtio_pci, COMMON_GF_REG, driver_features);
        assert_eq!(cmn_cfg.queue_type, QUEUE_TYPE_PACKED_VRING);
        assert_eq!(
            dev.lock().unwrap().driver_features,
            1_u64 << VIRTIO_F_RING_PACKED
        );
    }

    #[test]
    fn test_common_config_queue() {
        let virtio_dev: Arc<Mutex<dyn VirtioDevice>> =
            Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let queue_size = virtio_dev.lock().unwrap().queue_size();
        let queue_num = virtio_dev.lock().unwrap().queue_num();
        let mut cmn_cfg = VirtioPciCommonConfig::new(queue_size, queue_num);

        // Read Queue's Descriptor Table address
        cmn_cfg.queue_select = VIRTIO_DEVICE_QUEUE_NUM as u16 - 1;
        cmn_cfg.queues_config[cmn_cfg.queue_select as usize].desc_table =
            GuestAddress(0xAABBCCDD_FFEEDDAA);
        com_cfg_read_test!(cmn_cfg, virtio_dev, COMMON_Q_DESCLO_REG, 0xFFEEDDAA_u32);
        com_cfg_read_test!(cmn_cfg, virtio_dev, COMMON_Q_DESCHI_REG, 0xAABBCCDD_u32);

        // Read Queue's Available Ring address
        cmn_cfg.queue_select = 0;
        cmn_cfg.queues_config[0].avail_ring = GuestAddress(0x11223344_55667788);
        com_cfg_read_test!(cmn_cfg, virtio_dev, COMMON_Q_AVAILLO_REG, 0x55667788_u32);
        com_cfg_read_test!(cmn_cfg, virtio_dev, COMMON_Q_AVAILHI_REG, 0x11223344_u32);

        // Read Queue's Used Ring address
        cmn_cfg.queue_select = 0;
        cmn_cfg.queues_config[0].used_ring = GuestAddress(0x55667788_99AABBCC);
        com_cfg_read_test!(cmn_cfg, virtio_dev, COMMON_Q_USEDLO_REG, 0x99AABBCC_u32);
        com_cfg_read_test!(cmn_cfg, virtio_dev, COMMON_Q_USEDHI_REG, 0x55667788_u32);
    }

    #[test]
    fn test_common_config_queue_error() {
        let virtio_dev: Arc<Mutex<dyn VirtioDevice>> =
            Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let queue_size = virtio_dev.lock().unwrap().queue_size();
        let queue_num = virtio_dev.lock().unwrap().queue_num();
        let mut cmn_cfg = VirtioPciCommonConfig::new(queue_size, queue_num);
        let sys_mem = AddressSpace::new(Region::init_container_region(u64::max_value())).unwrap();
        let parent_bus = Arc::new(Mutex::new(PciBus::new(
            String::from("test bus"),
            #[cfg(target_arch = "x86_64")]
            Region::init_container_region(1 << 16),
            sys_mem.root().clone(),
        )));
        let cloned_virtio_dev = virtio_dev.clone();
        let mut virtio_pci = VirtioPciDevice::new(
            String::from("test device"),
            0,
            sys_mem,
            cloned_virtio_dev,
            Arc::downgrade(&parent_bus),
            false,
        );

        assert!(init_msix(
            VIRTIO_PCI_MSIX_BAR_IDX as usize,
            (queue_num + 1) as u32,
            &mut virtio_pci.config,
            virtio_pci.dev_id.clone(),
            &virtio_pci.name,
            None,
            None,
        )
        .is_ok());

        // Error occurs when queue selector exceeds queue num
        cmn_cfg.queue_select = VIRTIO_DEVICE_QUEUE_NUM as u16;
        assert!(cmn_cfg
            .read_common_config(&virtio_dev, COMMON_Q_SIZE_REG)
            .is_err());
        assert!(cmn_cfg
            .write_common_config(&virtio_pci, COMMON_Q_SIZE_REG, 128)
            .is_err());

        // Test Queue ready register
        cmn_cfg.device_status = CONFIG_STATUS_FEATURES_OK | CONFIG_STATUS_DRIVER;
        cmn_cfg.queue_select = 0;
        com_cfg_write_test!(cmn_cfg, virtio_pci, COMMON_Q_ENABLE_REG, 0x1_u32);
        assert!(cmn_cfg.queues_config.get(0).unwrap().ready);

        // Failed to set Queue relevant register if device is no ready
        cmn_cfg.device_status = CONFIG_STATUS_FEATURES_OK | CONFIG_STATUS_DRIVER_OK;
        cmn_cfg.queue_select = 1;
        assert!(cmn_cfg
            .write_common_config(&virtio_pci, COMMON_Q_MSIX_REG, 0x4_u32)
            .is_err());
    }

    #[test]
    fn test_virtio_pci_config_access() {
        let virtio_dev: Arc<Mutex<dyn VirtioDevice>> =
            Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let sys_mem = AddressSpace::new(Region::init_container_region(u64::max_value())).unwrap();
        let parent_bus = Arc::new(Mutex::new(PciBus::new(
            String::from("test bus"),
            #[cfg(target_arch = "x86_64")]
            Region::init_container_region(1 << 16),
            sys_mem.root().clone(),
        )));
        let mut virtio_pci = VirtioPciDevice::new(
            String::from("test device"),
            0,
            sys_mem,
            virtio_dev,
            Arc::downgrade(&parent_bus),
            false,
        );
        virtio_pci.init_write_mask().unwrap();
        virtio_pci.init_write_clear_mask().unwrap();

        // Overflows, exceeds size of pcie config space
        let mut data = vec![0_u8; 4];
        virtio_pci.write_config(PCIE_CONFIG_SPACE_SIZE, data.as_slice());
        virtio_pci.read_config(PCIE_CONFIG_SPACE_SIZE, data.as_mut_slice());
        assert_eq!(data, vec![0_u8; 4]);

        let data = vec![1_u8; 4];
        virtio_pci.write_config(PCIE_CONFIG_SPACE_SIZE - 4, data.as_slice());
        let mut data_ret = vec![0_u8; 4];
        virtio_pci.read_config(PCIE_CONFIG_SPACE_SIZE - 4, data_ret.as_mut_slice());
        assert_eq!(data_ret, data);
    }

    #[test]
    fn test_virtio_pci_realize() {
        let virtio_dev: Arc<Mutex<dyn VirtioDevice>> =
            Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let sys_mem = AddressSpace::new(Region::init_container_region(u64::max_value())).unwrap();
        let parent_bus = Arc::new(Mutex::new(PciBus::new(
            String::from("test bus"),
            #[cfg(target_arch = "x86_64")]
            Region::init_container_region(1 << 16),
            sys_mem.root().clone(),
        )));
        let virtio_pci = VirtioPciDevice::new(
            String::from("test device"),
            0,
            sys_mem,
            virtio_dev,
            Arc::downgrade(&parent_bus),
            false,
        );
        assert!(virtio_pci.realize().is_ok());
    }

    #[test]
    fn test_device_activate() {
        let sys_mem = AddressSpace::new(Region::init_container_region(u64::max_value())).unwrap();
        let mem_size: u64 = 1024 * 1024;
        let host_mmap = Arc::new(
            HostMemMapping::new(GuestAddress(0), None, mem_size, None, false, false, false)
                .unwrap(),
        );
        sys_mem
            .root()
            .add_subregion(
                Region::init_ram_region(host_mmap.clone()),
                host_mmap.start_address().raw_value(),
            )
            .unwrap();

        let virtio_dev: Arc<Mutex<dyn VirtioDevice>> =
            Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let parent_bus = Arc::new(Mutex::new(PciBus::new(
            String::from("test bus"),
            #[cfg(target_arch = "x86_64")]
            Region::init_container_region(1 << 16),
            sys_mem.root().clone(),
        )));
        let mut virtio_pci = VirtioPciDevice::new(
            String::from("test device"),
            0,
            sys_mem,
            virtio_dev,
            Arc::downgrade(&parent_bus),
            false,
        );
        #[cfg(target_arch = "aarch64")]
        virtio_pci.config.set_interrupt_pin();

        init_msix(
            VIRTIO_PCI_MSIX_BAR_IDX as usize,
            virtio_pci.device.lock().unwrap().queue_num() as u32 + 1,
            &mut virtio_pci.config,
            virtio_pci.dev_id.clone(),
            &virtio_pci.name,
            None,
            None,
        )
        .unwrap();

        init_intx(
            virtio_pci.name.clone(),
            &mut virtio_pci.config,
            virtio_pci.parent_bus.clone(),
            virtio_pci.devfn,
        )
        .unwrap();
        // Prepare msix and interrupt callback
        virtio_pci.assign_interrupt_cb();

        // Prepare valid queue config
        for queue_cfg in virtio_pci
            .common_config
            .lock()
            .unwrap()
            .queues_config
            .iter_mut()
        {
            queue_cfg.desc_table = GuestAddress(0);
            queue_cfg.avail_ring = GuestAddress((VIRTIO_DEVICE_QUEUE_SIZE as u64) * 16);
            queue_cfg.used_ring = GuestAddress(2 * 4096);
            queue_cfg.ready = true;
            queue_cfg.size = VIRTIO_DEVICE_QUEUE_SIZE;
        }
        let common_cfg_ops = virtio_pci.build_common_cfg_ops();

        // Device status is not ok, failed to activate virtio device
        let status = (CONFIG_STATUS_ACKNOWLEDGE | CONFIG_STATUS_DRIVER | CONFIG_STATUS_FEATURES_OK)
            .as_bytes();
        (common_cfg_ops.write)(status, GuestAddress(0), COMMON_STATUS_REG);
        assert_eq!(virtio_pci.device_activated.load(Ordering::Relaxed), false);
        // Device status is not ok, failed to activate virtio device
        let status = (CONFIG_STATUS_ACKNOWLEDGE
            | CONFIG_STATUS_DRIVER
            | CONFIG_STATUS_FAILED
            | CONFIG_STATUS_FEATURES_OK)
            .as_bytes();
        (common_cfg_ops.write)(status, GuestAddress(0), COMMON_STATUS_REG);
        assert_eq!(virtio_pci.device_activated.load(Ordering::Relaxed), false);
        // Status is ok, virtio device is activated.
        let status = (CONFIG_STATUS_ACKNOWLEDGE
            | CONFIG_STATUS_DRIVER
            | CONFIG_STATUS_DRIVER_OK
            | CONFIG_STATUS_FEATURES_OK)
            .as_bytes();
        (common_cfg_ops.write)(status, GuestAddress(0), COMMON_STATUS_REG);
        assert_eq!(virtio_pci.device_activated.load(Ordering::Relaxed), true);

        // If device status(not zero) is set to zero, reset the device
        (common_cfg_ops.write)(0_u32.as_bytes(), GuestAddress(0), COMMON_STATUS_REG);
        assert_eq!(virtio_pci.device_activated.load(Ordering::Relaxed), false);
    }

    #[test]
    fn test_multifunction() {
        let virtio_dev: Arc<Mutex<dyn VirtioDevice>> =
            Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let sys_mem = AddressSpace::new(Region::init_container_region(u64::max_value())).unwrap();
        let parent_bus = Arc::new(Mutex::new(PciBus::new(
            String::from("test bus"),
            #[cfg(target_arch = "x86_64")]
            Region::init_container_region(1 << 16),
            sys_mem.root().clone(),
        )));
        let mut virtio_pci = VirtioPciDevice::new(
            String::from("test device"),
            24,
            sys_mem,
            virtio_dev,
            Arc::downgrade(&parent_bus),
            true,
        );

        assert!(init_multifunction(
            virtio_pci.multi_func,
            &mut virtio_pci.config.config,
            virtio_pci.devfn,
            virtio_pci.parent_bus.clone()
        )
        .is_ok());
        let header_type = le_read_u16(&virtio_pci.config.config, HEADER_TYPE as usize).unwrap();
        assert_eq!(header_type, HEADER_TYPE_MULTIFUNC as u16);
    }
}
