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

use address_space::{AddressSpace, GuestAddress, Region};
use error_chain::ChainedError;
use kvm_ioctls::VmFd;
use pci::config::{
    RegionType, BAR_0, COMMAND, DEVICE_ID, PCIE_CONFIG_SPACE_SIZE, REG_SIZE, REVISION_ID,
    ROM_ADDRESS, SUBSYSTEM_ID, SUBSYSTEM_VENDOR_ID, SUB_CLASS_CODE, VENDOR_ID,
};
use pci::errors::{ErrorKind, Result as PciResult, ResultExt};
use pci::{init_msix, le_write_u16, ranges_overlap, PciBus, PciConfig, PciDevOps};
use util::byte_code::ByteCode;
use vmm_sys_util::eventfd::EventFd;

use crate::{virtio_has_feature, QueueConfig, VirtioDevice, VirtioInterrupt};
use crate::{
    CONFIG_STATUS_DRIVER_OK, CONFIG_STATUS_FAILED, CONFIG_STATUS_FEATURES_OK,
    QUEUE_TYPE_PACKED_VRING, QUEUE_TYPE_SPLIT_VRING, VIRTIO_F_RING_PACKED, VIRTIO_TYPE_BLOCK,
    VIRTIO_TYPE_NET,
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
            }
            COMMON_STATUS_REG => {
                self.device_status = value;
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

/// Virtio-PCI device structure
pub struct VirtioPciDevice {
    /// Name of this device
    name: String,
    /// The entity of virtio device
    device: Arc<Mutex<dyn VirtioDevice>>,
    /// Device id
    dev_id: u16,
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
    /// The function for interrupt triggerring
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    vm_fd: Arc<VmFd>,
}

impl VirtioPciDevice {
    pub fn new(
        name: String,
        devfn: u8,
        sys_mem: Arc<AddressSpace>,
        device: Arc<Mutex<dyn VirtioDevice>>,
        parent_bus: Weak<Mutex<PciBus>>,
        vm_fd: Arc<VmFd>,
    ) -> Self {
        let queue_num = device.lock().unwrap().queue_num();
        let queue_size = device.lock().unwrap().queue_size();

        VirtioPciDevice {
            name,
            device,
            dev_id: 0_u16,
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
            vm_fd,
        }
    }

    fn assign_interrupt_cb(&mut self) {}

    fn modern_mem_region_init(&mut self, _modern_mem_region: &Region) -> PciResult<()> {
        Ok(())
    }

    fn modern_mem_region_map<T: ByteCode>(&mut self, _data: T) -> PciResult<()> {
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

    fn realize(mut self, vm_fd: &Arc<VmFd>) -> PciResult<()> {
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
        #[cfg(target_arch = "aarch64")]
        {
            self.dev_id = self.set_dev_id(0, self.devfn);
        }
        init_msix(
            vm_fd,
            VIRTIO_PCI_MSIX_BAR_IDX as usize,
            nvectors as u32,
            &mut self.config,
            self.dev_id,
        )?;

        self.assign_interrupt_cb();

        let mem_region_size = ((VIRTIO_PCI_CAP_NOTIFY_OFFSET + VIRTIO_PCI_CAP_NOTIFY_LENGTH)
            as u64)
            .next_power_of_two();
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

        let devfn = self.devfn;
        let dev = Arc::new(Mutex::new(self));
        dev.lock()
            .unwrap()
            .parent_bus
            .upgrade()
            .unwrap()
            .lock()
            .unwrap()
            .devices
            .insert(devfn, dev.clone());

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

        self.config.write(offset, data, &self.vm_fd, self.dev_id);

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
}
