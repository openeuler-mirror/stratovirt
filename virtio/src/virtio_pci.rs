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

use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};

use address_space::{AddressRange, AddressSpace, GuestAddress, Region, RegionIoEventFd, RegionOps};
use byteorder::{ByteOrder, LittleEndian};
use error_chain::ChainedError;
use hypervisor::kvm::{MsiVector, KVM_FDS};
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use pci::config::{
    RegionType, BAR_0, COMMAND, DEVICE_ID, PCIE_CONFIG_SPACE_SIZE, REG_SIZE, REVISION_ID,
    ROM_ADDRESS, STATUS, STATUS_INTERRUPT, SUBSYSTEM_ID, SUBSYSTEM_VENDOR_ID, SUB_CLASS_CODE,
    VENDOR_ID,
};
use pci::errors::{ErrorKind, Result as PciResult, ResultExt};
use pci::msix::{update_dev_id, MsixState};
use pci::{
    config::PciConfig, init_msix, init_multifunction, le_write_u16, ranges_overlap, PciBus,
    PciDevOps,
};
use util::{byte_code::ByteCode, num_ops::round_up, unix::host_page_size};
use vmm_sys_util::eventfd::EventFd;

use crate::{
    virtio_has_feature, Queue, QueueConfig, VirtioDevice, VirtioInterrupt, VirtioInterruptType,
};
use crate::{
    CONFIG_STATUS_ACKNOWLEDGE, CONFIG_STATUS_DRIVER, CONFIG_STATUS_DRIVER_OK, CONFIG_STATUS_FAILED,
    CONFIG_STATUS_FEATURES_OK, QUEUE_TYPE_PACKED_VRING, QUEUE_TYPE_SPLIT_VRING,
    VIRTIO_F_RING_PACKED, VIRTIO_TYPE_BLOCK, VIRTIO_TYPE_NET,
};

const VIRTIO_QUEUE_MAX: u32 = 1024;

const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_PCI_DEVICE_ID_BASE: u16 = 0x1040;
const VIRTIO_PCI_ABI_VERSION: u8 = 1;
const VIRTIO_PCI_CLASS_ID_NET: u16 = 0x0280;
const VIRTIO_PCI_CLASS_ID_BLOCK: u16 = 0x0100;
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

/// Get class id according to device type.
///
/// # Arguments
///
/// * `device_type` - Device type set by the host.
fn get_virtio_class_id(device_type: u32) -> u16 {
    match device_type {
        VIRTIO_TYPE_BLOCK => VIRTIO_PCI_CLASS_ID_BLOCK,
        VIRTIO_TYPE_NET => VIRTIO_PCI_CLASS_ID_NET,
        _ => VIRTIO_PCI_CLASS_ID_OTHERS,
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
    interrupt_status: Arc<AtomicU32>,
    /// Device status.
    device_status: u32,
    /// Configuration atomicity value.
    config_generation: u32,
    /// Queue selector.
    queue_select: u16,
    /// The configuration vector for MSI-X.
    msix_config: Arc<AtomicU16>,
    /// The configuration of queues.
    queues_config: Vec<QueueConfig>,
    /// The type of queue, split-vring or packed-vring.
    queue_type: u16,
}

impl VirtioPciCommonConfig {
    fn new(queue_size: u16, queue_num: usize) -> Self {
        let mut queues_config = Vec::new();
        for _ in 0..queue_num {
            queues_config.push(QueueConfig::new(queue_size))
        }

        VirtioPciCommonConfig {
            features_select: 0,
            acked_features_select: 0,
            interrupt_status: Arc::new(AtomicU32::new(0)),
            device_status: 0,
            config_generation: 0,
            queue_select: 0,
            msix_config: Arc::new(AtomicU16::new(0)),
            queues_config,
            queue_type: QUEUE_TYPE_SPLIT_VRING,
        }
    }

    fn check_device_status(&self, set: u32, clr: u32) -> bool {
        self.device_status & (set | clr) == set
    }

    fn get_mut_queue_config(&mut self) -> PciResult<&mut QueueConfig> {
        if self.check_device_status(
            CONFIG_STATUS_FEATURES_OK,
            CONFIG_STATUS_DRIVER_OK | CONFIG_STATUS_FAILED,
        ) {
            self.queues_config
                .get_mut(self.queue_select as usize)
                .ok_or_else(|| "pci-reg queue_select overflows".into())
        } else {
            Err(ErrorKind::DeviceStatus(self.device_status).into())
        }
    }

    fn get_queue_config(&self) -> PciResult<&QueueConfig> {
        self.queues_config
            .get(self.queue_select as usize)
            .ok_or_else(|| "pci-reg queue_select overflows".into())
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
            COMMON_DF_REG => device
                .lock()
                .unwrap()
                .get_device_features(self.features_select),
            COMMON_GFSELECT_REG => self.acked_features_select,
            COMMON_MSIX_REG => self.msix_config.load(Ordering::SeqCst) as u32,
            COMMON_NUMQ_REG => self.queues_config.len() as u32,
            COMMON_STATUS_REG => self.device_status,
            COMMON_CFGGENERATION_REG => self.config_generation,
            COMMON_Q_SELECT_REG => self.queue_select as u32,
            COMMON_Q_SIZE_REG => self
                .get_queue_config()
                .map(|config| u32::from(config.max_size))?,
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
            _ => {
                return Err(ErrorKind::PciRegister(offset).into());
            }
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
        device: &Arc<Mutex<dyn VirtioDevice>>,
        offset: u64,
        value: u32,
    ) -> PciResult<()> {
        match offset {
            COMMON_DFSELECT_REG => {
                self.features_select = value;
            }
            COMMON_GFSELECT_REG => {
                self.acked_features_select = value;
            }
            COMMON_GF_REG => {
                device
                    .lock()
                    .unwrap()
                    .set_driver_features(self.acked_features_select, value);

                if self.acked_features_select == 1
                    && virtio_has_feature(u64::from(value) << 32, VIRTIO_F_RING_PACKED)
                {
                    error!("Set packed virtqueue, which is not supported");
                    self.queue_type = QUEUE_TYPE_PACKED_VRING;
                }
            }
            COMMON_MSIX_REG => {
                self.msix_config.store(value as u16, Ordering::SeqCst);
                self.interrupt_status.store(0_u32, Ordering::SeqCst);
            }
            COMMON_STATUS_REG => {
                self.device_status = value;
                if self.device_status == 0 {
                    self.queues_config.iter_mut().for_each(|q| {
                        q.ready = false;
                        q.vector = 0;
                        q.avail_ring = GuestAddress(0);
                        q.desc_table = GuestAddress(0);
                        q.used_ring = GuestAddress(0);
                    });
                    self.msix_config.store(0_u16, Ordering::SeqCst)
                }
            }
            COMMON_Q_SELECT_REG => {
                if value < VIRTIO_QUEUE_MAX {
                    self.queue_select = value as u16;
                }
            }
            COMMON_Q_SIZE_REG => self
                .get_mut_queue_config()
                .map(|config| config.size = value as u16)?,
            COMMON_Q_ENABLE_REG => self
                .get_mut_queue_config()
                .map(|config| config.ready = value == 1)?,
            COMMON_Q_MSIX_REG => self
                .get_mut_queue_config()
                .map(|config| config.vector = value as u16)?,
            COMMON_Q_DESCLO_REG => self.get_mut_queue_config().map(|config| {
                config.desc_table = GuestAddress(config.desc_table.0 | u64::from(value));
            })?,
            COMMON_Q_DESCHI_REG => self.get_mut_queue_config().map(|config| {
                config.desc_table = GuestAddress(config.desc_table.0 | (u64::from(value) << 32));
            })?,
            COMMON_Q_AVAILLO_REG => self.get_mut_queue_config().map(|config| {
                config.avail_ring = GuestAddress(config.avail_ring.0 | u64::from(value));
            })?,
            COMMON_Q_AVAILHI_REG => self.get_mut_queue_config().map(|config| {
                config.avail_ring = GuestAddress(config.avail_ring.0 | (u64::from(value) << 32));
            })?,
            COMMON_Q_USEDLO_REG => self.get_mut_queue_config().map(|config| {
                config.used_ring = GuestAddress(config.used_ring.0 | u64::from(value));
            })?,
            COMMON_Q_USEDHI_REG => self.get_mut_queue_config().map(|config| {
                config.used_ring = GuestAddress(config.used_ring.0 | (u64::from(value) << 32));
            })?,
            _ => {
                return Err(ErrorKind::PciRegister(offset).into());
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

struct NotifyEventFds {
    events: Vec<EventFd>,
}

impl NotifyEventFds {
    fn new(queue_num: usize) -> Self {
        let mut events = Vec::new();
        for _i in 0..queue_num {
            events.push(EventFd::new(libc::EFD_NONBLOCK).unwrap());
        }

        NotifyEventFds { events }
    }
}

impl Clone for NotifyEventFds {
    fn clone(&self) -> NotifyEventFds {
        let mut queue_evts = Vec::<EventFd>::new();
        for fd in self.events.iter() {
            let cloned_evt_fd = fd.try_clone().unwrap();
            queue_evts.push(cloned_evt_fd);
        }
        NotifyEventFds { events: queue_evts }
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
    config_generation: u32,
    queue_select: u16,
    msix_config: u16,
    /// The configuration of queues. Max number of queues is 8.
    queues_config: [QueueConfig; 8],
    /// The number of queues.
    queue_num: usize,
}

struct GsiMsiRoute {
    irq_fd: Option<EventFd>,
    gsi: i32,
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
    /// Virtio common config refer to Virtio Spec.
    common_config: Arc<Mutex<VirtioPciCommonConfig>>,
    /// Primary Bus
    parent_bus: Weak<Mutex<PciBus>>,
    /// Eventfds used for notifying the guest.
    notify_eventfds: NotifyEventFds,
    /// The function for interrupt triggering
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    /// Virtio queues. The vector and Queue will be shared acrossing thread, so all with Arc<Mutex<..>> wrapper.
    queues: Arc<Mutex<Vec<Arc<Mutex<Queue>>>>>,
    /// Multi-Function flag.
    multi_func: bool,
    /// If the device need to register irqfd to kvm.
    need_irqfd: bool,
    /// Maintains a list of GSI with irqfds that are registered to kvm.
    gsi_msi_routes: Arc<Mutex<Vec<GsiMsiRoute>>>,
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
            common_config: Arc::new(Mutex::new(VirtioPciCommonConfig::new(
                queue_size, queue_num,
            ))),
            parent_bus,
            notify_eventfds: NotifyEventFds::new(queue_num),
            interrupt_cb: None,
            queues: Arc::new(Mutex::new(Vec::with_capacity(queue_num))),
            multi_func,
            need_irqfd: false,
            gsi_msi_routes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn enable_need_irqfd(&mut self) {
        self.need_irqfd = true;
    }

    fn assign_interrupt_cb(&mut self) {
        let cloned_common_cfg = self.common_config.clone();
        let cloned_msix = self.config.msix.clone();
        let dev_id = self.dev_id.clone();
        let cb = Arc::new(Box::new(
            move |int_type: &VirtioInterruptType, queue: Option<&Queue>| {
                let vector = match int_type {
                    VirtioInterruptType::Config => cloned_common_cfg
                        .lock()
                        .unwrap()
                        .msix_config
                        .load(Ordering::SeqCst),
                    VirtioInterruptType::Vring => {
                        queue.map_or(0, |q| q.vring.get_queue_config().vector)
                    }
                };

                if let Some(msix) = &cloned_msix {
                    msix.lock()
                        .unwrap()
                        .notify(vector, dev_id.load(Ordering::Acquire));
                } else {
                    bail!("Failed to send interrupt, msix does not exist");
                }
                Ok(())
            },
        ) as VirtioInterrupt);

        self.interrupt_cb = Some(cb);
    }

    fn ioeventfds(&self) -> Vec<RegionIoEventFd> {
        let mut ret = Vec::new();
        for (index, eventfd) in self.notify_eventfds.events.iter().enumerate() {
            let addr = index as u64 * u64::from(VIRTIO_PCI_CAP_NOTIFY_OFF_MULTIPLIER);
            let eventfd_clone = match eventfd.try_clone() {
                Err(e) => {
                    error!("Failed to clone ioeventfd, error is {}", e);
                    continue;
                }
                Ok(fd) => fd,
            };
            ret.push(RegionIoEventFd {
                fd: eventfd_clone,
                addr_range: AddressRange::from((addr, 2u64)),
                data_match: false,
                data: index as u64,
            })
        }

        ret
    }

    fn modern_mem_region_map<T: ByteCode>(&mut self, data: T) -> PciResult<()> {
        let cap_offset = self.config.add_pci_cap(
            PCI_CAP_ID_VNDR,
            size_of::<T>() + PCI_CAP_VNDR_AND_NEXT_SIZE as usize,
        )?;

        let write_start = cap_offset + PCI_CAP_VNDR_AND_NEXT_SIZE as usize;
        self.config.config[write_start..(write_start + size_of::<T>())]
            .copy_from_slice(data.as_bytes());

        Ok(())
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
                        "Failed to read common config of virtio-pci device, error is {}",
                        e.display_chain(),
                    );
                    return false;
                }
            };

            match data.len() {
                1 => data[0] = value as u8,
                2 => {
                    LittleEndian::write_u16(data, value as u16);
                }
                4 => {
                    LittleEndian::write_u32(data, value);
                }
                _ => {
                    error!(
                        "invalid data length for reading pci common config: offset 0x{:x}, data len {}",
                        offset, data.len()
                    );
                    return false;
                }
            };

            true
        };

        let cloned_pci_device = self.clone();
        let cloned_mem_space = self.sys_mem.clone();
        let cloned_gsi_routes = self.gsi_msi_routes.clone();
        let common_write = move |data: &[u8], _addr: GuestAddress, offset: u64| -> bool {
            let value = match data.len() {
                1 => data[0] as u32,
                2 => LittleEndian::read_u16(data) as u32,
                4 => LittleEndian::read_u32(data),
                _ => {
                    error!(
                        "Invalid data length for writing pci common config: offset 0x{:x}, data len {}",
                        offset, data.len()
                    );
                    return false;
                }
            };
            let old_dev_status = cloned_pci_device
                .common_config
                .lock()
                .unwrap()
                .device_status;

            if let Err(e) = cloned_pci_device
                .common_config
                .lock()
                .unwrap()
                .write_common_config(&cloned_pci_device.device.clone(), offset, value)
            {
                error!(
                    "Failed to read common config of virtio-pci device, error is {}",
                    e.display_chain(),
                );
                return false;
            }

            if !cloned_pci_device.device_activated.load(Ordering::Acquire)
                && cloned_pci_device
                    .common_config
                    .lock()
                    .unwrap()
                    .check_device_status(
                        CONFIG_STATUS_ACKNOWLEDGE
                            | CONFIG_STATUS_DRIVER
                            | CONFIG_STATUS_DRIVER_OK
                            | CONFIG_STATUS_FEATURES_OK,
                        CONFIG_STATUS_FAILED,
                    )
            {
                let queue_type = cloned_pci_device.common_config.lock().unwrap().queue_type;
                let queues_config = &mut cloned_pci_device
                    .common_config
                    .lock()
                    .unwrap()
                    .queues_config;
                let mut locked_queues = cloned_pci_device.queues.lock().unwrap();
                for q_config in queues_config.iter_mut() {
                    q_config.addr_cache.desc_table_host = cloned_mem_space
                        .get_host_address(q_config.desc_table)
                        .unwrap_or(0);
                    q_config.addr_cache.avail_ring_host = cloned_mem_space
                        .get_host_address(q_config.avail_ring)
                        .unwrap_or(0);
                    q_config.addr_cache.used_ring_host = cloned_mem_space
                        .get_host_address(q_config.used_ring)
                        .unwrap_or(0);
                    let queue = Queue::new(*q_config, queue_type).unwrap();
                    if !queue.is_valid(&cloned_pci_device.sys_mem) {
                        error!("Failed to activate device: Invalid queue");
                        return false;
                    }
                    let arc_queue = Arc::new(Mutex::new(queue));
                    locked_queues.push(arc_queue.clone());
                }

                let queue_num = cloned_pci_device.device.lock().unwrap().queue_num();
                let call_evts = NotifyEventFds::new(queue_num);
                let queue_evts = cloned_pci_device.notify_eventfds.clone().events;
                if let Some(cb) = cloned_pci_device.interrupt_cb.clone() {
                    if cloned_pci_device.need_irqfd {
                        if let Err(e) = cloned_pci_device
                            .device
                            .lock()
                            .unwrap()
                            .set_guest_notifiers(&call_evts.events)
                        {
                            error!(
                                "Failed to set guest notifiers, error is {}",
                                e.display_chain()
                            );
                        }
                    }
                    if let Err(e) = cloned_pci_device.device.lock().unwrap().activate(
                        cloned_pci_device.sys_mem.clone(),
                        cb,
                        &locked_queues,
                        queue_evts,
                    ) {
                        error!("Failed to activate device, error is {}", e.display_chain());
                    }
                } else {
                    error!("Failed to activate device: No interrupt callback");
                    return false;
                }
                cloned_pci_device
                    .device_activated
                    .store(true, Ordering::Release);

                update_dev_id(
                    &cloned_pci_device.parent_bus,
                    cloned_pci_device.devfn,
                    &cloned_pci_device.dev_id,
                );

                drop(locked_queues);
                if cloned_pci_device.need_irqfd
                    && !virtio_pci_register_irqfd(
                        &cloned_pci_device,
                        &cloned_gsi_routes,
                        &call_evts.events,
                    )
                {
                    return false;
                }
            }

            if old_dev_status != 0
                && cloned_pci_device
                    .common_config
                    .lock()
                    .unwrap()
                    .device_status
                    == 0
            {
                if cloned_pci_device.need_irqfd {
                    virtio_pci_unregister_irqfd(cloned_gsi_routes.clone());
                }

                let mut locked_queues = cloned_pci_device.queues.lock().unwrap();
                locked_queues.clear();
                if cloned_pci_device.device_activated.load(Ordering::Acquire) {
                    cloned_pci_device
                        .device_activated
                        .store(false, Ordering::Release);
                    let cloned_msix = cloned_pci_device.config.msix.as_ref().unwrap().clone();
                    cloned_msix.lock().unwrap().reset();
                    if let Err(e) = cloned_pci_device.device.lock().unwrap().deactivate() {
                        error!(
                            "Failed to deactivate virtio device, error is {}",
                            e.display_chain()
                        );
                    }
                }
                update_dev_id(
                    &cloned_pci_device.parent_bus,
                    cloned_pci_device.devfn,
                    &cloned_pci_device.dev_id,
                );
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
            .chain_err(|| "Failed to register pci-common-cap region.")?;

        // 2. PCI ISR cap sub-region.
        let cloned_common_cfg = self.common_config.clone();
        let isr_read = move |data: &mut [u8], _: GuestAddress, _: u64| -> bool {
            if let Some(val) = data.get_mut(0) {
                *val = cloned_common_cfg
                    .lock()
                    .unwrap()
                    .interrupt_status
                    .swap(0, Ordering::SeqCst) as u8;
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
            .chain_err(|| "Failed to register pci-isr-cap region.")?;

        // 3. PCI dev cap sub-region.
        let cloned_virtio_dev = self.device.clone();
        let device_read = move |data: &mut [u8], _addr: GuestAddress, offset: u64| -> bool {
            if let Err(e) = cloned_virtio_dev.lock().unwrap().read_config(offset, data) {
                error!(
                    "Failed to read virtio-dev config space, error is {}",
                    e.display_chain()
                );
                return false;
            }
            true
        };

        let cloned_virtio_dev = self.device.clone();
        let device_write = move |data: &[u8], _addr: GuestAddress, offset: u64| -> bool {
            if let Err(e) = cloned_virtio_dev.lock().unwrap().write_config(offset, data) {
                error!(
                    "Failed to write virtio-dev config space, error is {}",
                    e.display_chain()
                );
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
            .chain_err(|| "Failed to register pci-dev-cap region.")?;

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
            .chain_err(|| "Failed to register pci-notify-cap region.")?;

        Ok(())
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

        let nvectors = self.device.lock().unwrap().queue_num() + 1;

        init_msix(
            VIRTIO_PCI_MSIX_BAR_IDX as usize,
            nvectors as u32,
            &mut self.config,
            self.dev_id.clone(),
            &self.name,
        )?;

        self.assign_interrupt_cb();

        let mut mem_region_size = ((VIRTIO_PCI_CAP_NOTIFY_OFFSET + VIRTIO_PCI_CAP_NOTIFY_LENGTH)
            as u64)
            .next_power_of_two();
        mem_region_size = round_up(mem_region_size, host_page_size()).unwrap();
        let modern_mem_region = Region::init_container_region(mem_region_size);
        self.modern_mem_region_init(&modern_mem_region)?;

        self.config.register_bar(
            VIRTIO_PCI_MEM_BAR_IDX as usize,
            modern_mem_region,
            RegionType::Mem32Bit,
            false,
            mem_region_size,
        );

        self.device
            .lock()
            .unwrap()
            .realize()
            .chain_err(|| "Failed to realize virtio device")?;

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
        MigrationManager::register_device_instance_mutex_with_id(
            VirtioPciState::descriptor(),
            dev,
            &name,
        );

        Ok(())
    }

    fn unrealize(&mut self) -> PciResult<()> {
        self.device
            .lock()
            .unwrap()
            .unrealize()
            .chain_err(|| "Failed to unrealize the virtio device")?;

        let bus = self.parent_bus.upgrade().unwrap();
        self.config.unregister_bars(&bus)?;

        MigrationManager::unregister_device_instance_mutex_by_id(
            MsixState::descriptor(),
            &self.name,
        );
        MigrationManager::unregister_device_instance_mutex_by_id(
            VirtioPciState::descriptor(),
            &self.name,
        );
        Ok(())
    }

    fn read_config(&self, offset: usize, data: &mut [u8]) {
        let data_size = data.len();
        if offset + data_size > PCIE_CONFIG_SPACE_SIZE || data_size > REG_SIZE {
            error!(
                "Failed to read pcie config space at offset 0x{:x} with data size {}",
                offset, data_size
            );
            return;
        }

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

        self.config
            .write(offset, data, self.dev_id.clone().load(Ordering::Acquire));
        if ranges_overlap(
            offset,
            end,
            BAR_0 as usize,
            BAR_0 as usize + REG_SIZE as usize * VIRTIO_PCI_BAR_MAX as usize,
        ) || ranges_overlap(offset, end, ROM_ADDRESS, ROM_ADDRESS + 4)
            || ranges_overlap(offset, end, COMMAND as usize, COMMAND as usize + 1)
        {
            let parent_bus = self.parent_bus.upgrade().unwrap();
            let locked_parent_bus = parent_bus.lock().unwrap();
            if let Err(e) = self.config.update_bar_mapping(
                #[cfg(target_arch = "x86_64")]
                &locked_parent_bus.io_region,
                &locked_parent_bus.mem_region,
            ) {
                error!("Failed to update bar, error is {}", e.display_chain());
            }
        }
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn devfn(&self) -> Option<u8> {
        Some(self.devfn)
    }

    fn reset(&mut self, _reset_child_device: bool) -> PciResult<()> {
        self.device
            .lock()
            .unwrap()
            .reset()
            .chain_err(|| "Fail to reset virtio device")
    }
}

impl StateTransfer for VirtioPciDevice {
    fn get_state_vec(&self) -> migration::errors::Result<Vec<u8>> {
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
            state.interrupt_status = common_config.interrupt_status.load(Ordering::SeqCst);
            state.msix_config = common_config.msix_config.load(Ordering::SeqCst);
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

    fn set_state_mut(&mut self, state: &[u8]) -> migration::errors::Result<()> {
        let mut pci_state = *VirtioPciState::from_bytes(state)
            .ok_or(migration::errors::ErrorKind::FromBytesError("PCI_DEVICE"))?;

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
            common_config
                .interrupt_status
                .store(pci_state.interrupt_status, Ordering::SeqCst);
            common_config
                .msix_config
                .store(pci_state.msix_config, Ordering::SeqCst);
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
        if let Some(alias) = MigrationManager::get_desc_alias(&VirtioPciState::descriptor().name) {
            alias
        } else {
            !0
        }
    }
}

impl MigrationHook for VirtioPciDevice {
    fn resume(&mut self) -> migration::errors::Result<()> {
        if self.device_activated.load(Ordering::Relaxed) {
            // Reregister ioevents for notifies.
            let parent_bus = self.parent_bus.upgrade().unwrap();
            let locked_parent_bus = parent_bus.lock().unwrap();
            if let Err(e) = self.config.update_bar_mapping(
                #[cfg(target_arch = "x86_64")]
                &locked_parent_bus.io_region,
                &locked_parent_bus.mem_region,
            ) {
                bail!("Failed to update bar, error is {}", e.display_chain());
            }

            let queue_evts = self.notify_eventfds.clone().events;
            if let Some(cb) = self.interrupt_cb.clone() {
                if let Err(e) = self.device.lock().unwrap().activate(
                    self.sys_mem.clone(),
                    cb,
                    &self.queues.lock().unwrap(),
                    queue_evts,
                ) {
                    error!("Failed to resume device, error is {}", e.display_chain());
                }
            } else {
                error!("Failed to resume device: No interrupt callback");
            }
        }

        Ok(())
    }
}

fn virtio_pci_register_irqfd(
    pci_device: &VirtioPciDevice,
    gsi_routes: &Arc<Mutex<Vec<GsiMsiRoute>>>,
    call_fds: &[EventFd],
) -> bool {
    let locked_msix = if let Some(msix) = &pci_device.config.msix {
        msix.lock().unwrap()
    } else {
        error!("Failed to get msix in virtio pci device configure");
        return false;
    };

    let locked_queues = pci_device.queues.lock().unwrap();
    let mut locked_gsi_routes = gsi_routes.lock().unwrap();
    for (queue_index, queue_mutex) in locked_queues.iter().enumerate() {
        let vector = queue_mutex.lock().unwrap().vring.get_queue_config().vector;
        let entry = locked_msix.get_message(vector as u16);
        let msix_vector = MsiVector {
            msg_addr_lo: entry.address_lo,
            msg_addr_hi: entry.address_hi,
            msg_data: entry.data,
            masked: false,
            #[cfg(target_arch = "aarch64")]
            dev_id: pci_device.dev_id.load(Ordering::Acquire) as u32,
        };

        let gsi = match KVM_FDS
            .load()
            .irq_route_table
            .lock()
            .unwrap()
            .allocate_gsi()
        {
            Ok(g) => g as i32,
            Err(e) => {
                error!("Failed to allocate gsi, error is {}", e);
                return false;
            }
        };

        KVM_FDS
            .load()
            .irq_route_table
            .lock()
            .unwrap()
            .add_msi_route(gsi as u32, msix_vector)
            .unwrap_or_else(|e| error!("Failed to add MSI-X route, error is {}", e));

        KVM_FDS
            .load()
            .commit_irq_routing()
            .unwrap_or_else(|e| error!("Failed to commit irq routing, error is {}", e));

        KVM_FDS
            .load()
            .vm_fd
            .as_ref()
            .unwrap()
            .register_irqfd(&call_fds[queue_index], gsi as u32)
            .unwrap_or_else(|e| error!("Failed to register irq, error is {}", e));

        let gsi_route = GsiMsiRoute {
            irq_fd: Some(call_fds[queue_index].try_clone().unwrap()),
            gsi,
        };
        locked_gsi_routes.push(gsi_route);
    }

    true
}

fn virtio_pci_unregister_irqfd(gsi_routes: Arc<Mutex<Vec<GsiMsiRoute>>>) {
    let mut locked_gsi_routes = gsi_routes.lock().unwrap();
    for route in locked_gsi_routes.iter() {
        if let Some(fd) = &route.irq_fd.as_ref() {
            KVM_FDS
                .load()
                .unregister_irqfd(fd, route.gsi as u32)
                .unwrap_or_else(|e| error!("Failed to unregister irq, error is {}", e));

            KVM_FDS
                .load()
                .irq_route_table
                .lock()
                .unwrap()
                .release_gsi(route.gsi as u32)
                .unwrap_or_else(|e| error!("Failed to release gsi, error is {}", e));
        }
    }
    locked_gsi_routes.clear();
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use address_space::{AddressSpace, GuestAddress, HostMemMapping};
    use pci::{
        config::{HEADER_TYPE, HEADER_TYPE_MULTIFUNC},
        le_read_u16,
    };
    use util::num_ops::{read_u32, write_u32};
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
            let mut v = write_u32(value, page);
            let unrequested_features = v & !self.device_features;
            if unrequested_features != 0 {
                v &= !unrequested_features;
            }
            self.driver_features |= v;
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
            _queue_evts: Vec<EventFd>,
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
        let queue_size = virtio_dev.lock().unwrap().queue_size();
        let queue_num = virtio_dev.lock().unwrap().queue_num();

        let mut cmn_cfg = VirtioPciCommonConfig::new(queue_size, queue_num);

        // Read virtio device features
        cmn_cfg.features_select = 0_u32;
        com_cfg_read_test!(cmn_cfg, virtio_dev, COMMON_DF_REG, 0xFFFF_FFF0_u32);
        cmn_cfg.features_select = 1_u32;
        com_cfg_read_test!(cmn_cfg, virtio_dev, COMMON_DF_REG, 0_u32);

        // Write virtio device features
        cmn_cfg.acked_features_select = 1_u32;
        com_cfg_write_test!(cmn_cfg, virtio_dev, COMMON_GF_REG, 0xFF);
        // The feature is not supported by this virtio device, and is masked
        assert_eq!(dev.lock().unwrap().driver_features, 0_u64);
        cmn_cfg.acked_features_select = 0_u32;
        com_cfg_write_test!(cmn_cfg, virtio_dev, COMMON_GF_REG, 0xCF);
        // The feature is partially supported by this virtio device, and is partially masked
        assert_eq!(dev.lock().unwrap().driver_features, 0xC0_u64);

        // Set the feature of the Queue type
        cmn_cfg.acked_features_select = 1_u32;
        dev.lock().unwrap().driver_features = 0_u64;
        dev.lock().unwrap().device_features = 0xFFFF_FFFF_0000_0000_u64;
        let driver_features = 1_u32 << (VIRTIO_F_RING_PACKED - 32);
        com_cfg_write_test!(cmn_cfg, virtio_dev, COMMON_GF_REG, driver_features);
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

        // Error occurs when queue selector exceeds queue num
        cmn_cfg.queue_select = VIRTIO_DEVICE_QUEUE_NUM as u16;
        assert!(cmn_cfg
            .read_common_config(&virtio_dev, COMMON_Q_SIZE_REG)
            .is_err());
        assert!(cmn_cfg
            .write_common_config(&virtio_dev, COMMON_Q_SIZE_REG, 128)
            .is_err());

        // Test Queue ready register
        cmn_cfg.device_status = CONFIG_STATUS_FEATURES_OK | CONFIG_STATUS_DRIVER;
        cmn_cfg.queue_select = 0;
        com_cfg_write_test!(cmn_cfg, virtio_dev, COMMON_Q_ENABLE_REG, 0x1_u32);
        assert!(cmn_cfg.queues_config.get(0).unwrap().ready);

        // Failed to set Queue relevant register if device is no ready
        cmn_cfg.device_status = CONFIG_STATUS_FEATURES_OK | CONFIG_STATUS_DRIVER_OK;
        cmn_cfg.queue_select = 1;
        assert!(cmn_cfg
            .write_common_config(&virtio_dev, COMMON_Q_MSIX_REG, 0x4_u32)
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

        // Prepare msix and interrupt callback
        virtio_pci.assign_interrupt_cb();
        init_msix(
            VIRTIO_PCI_MSIX_BAR_IDX as usize,
            virtio_pci.device.lock().unwrap().queue_num() as u32 + 1,
            &mut virtio_pci.config,
            virtio_pci.dev_id.clone(),
            &virtio_pci.name,
        )
        .unwrap();
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
