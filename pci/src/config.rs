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

use address_space::Region;

use crate::errors::{ErrorKind, Result, ResultExt};
use crate::{
    le_read_u16, le_read_u32, le_read_u64, le_write_u16, le_write_u32, le_write_u64, BDF_FUNC_SHIFT,
};

/// Size in bytes of the configuration space of legacy PCI device.
pub const PCI_CONFIG_SPACE_SIZE: usize = 256;
/// Size in bytes of the configuration space of PCIe device.
pub const PCIE_CONFIG_SPACE_SIZE: usize = 4096;
/// Size in bytes of dword.
pub const REG_SIZE: usize = 4;

/// Command register.
pub const COMMAND: u8 = 0x04;
/// Base address register 0.
pub const BAR_0: u8 = 0x10;
/// Secondary bus number register.
pub const SECONDARY_BUS_NUM: u8 = 0x19;
/// Subordinate bus number register.
pub const SUBORDINATE_BUS_NUM: u8 = 0x1a;
/// I/O base register.
pub const IO_BASE: u8 = 0x1c;
/// Memory base register.
pub const MEMORY_BASE: u8 = 0x20;
/// Prefetchable memory base register.
pub const PREF_MEMORY_BASE: u8 = 0x24;

/// I/O space enable.
pub const COMMAND_IO_SPACE: u16 = 0x0001;
/// Memory space enable.
pub const COMMAND_MEMORY_SPACE: u16 = 0x0002;

const PCI_CONFIG_HEAD_END: u8 = 64;
const NEXT_CAP_OFFSET: u8 = 0x01;
const STATUS_CAP_LIST: u16 = 0x0010;
const PCIE_CAP_VERSION_SHIFT: u8 = 16;
const PCIE_CAP_NEXT_OFFSET_SHIFT: u8 = 20;
const PCIE_CAP_SIZE: u8 = 0x3c;
const PCIE_CAP_VERSION_2: u16 = 0x0002;
const PCIE_CAP_SLOT_IMPLEMENTED: u16 = 0x0100;

const STATUS: u8 = 0x06;
const CACHE_LINE_SIZE: u8 = 0x0c;
const PRIMARY_BUS_NUM: u8 = 0x18;
const IO_LIMIT: u8 = 0x1d;
const PREF_MEM_BASE_UPPER: u8 = 0x28;
const CAP_LIST: u8 = 0x34;
const INTERRUPT_LINE: u8 = 0x3c;
const BRIDGE_CONTROL: u8 = 0x3e;

const BRIDGE_CTL_PARITY_ENABLE: u16 = 0x0001;
const BRIDGE_CTL_SERR_ENABLE: u16 = 0x0002;
const BRIDGE_CTL_ISA_ENABLE: u16 = 0x0004;
const BRIDGE_CTL_VGA_ENABLE: u16 = 0x0008;
const BRIDGE_CTL_VGA_16BIT_DEC: u16 = 0x0010;
const BRIDGE_CTL_SEC_BUS_RESET: u16 = 0x0040;
const BRIDGE_CTL_DISCARD_TIMER_STATUS: u16 = 0x0400;

const COMMAND_BUS_MASTER: u16 = 0x0004;
const COMMAND_SERR_ENABLE: u16 = 0x0100;
const COMMAND_INTERRUPT_DISABLE: u16 = 0x0400;

const STATUS_PARITY_ERROR: u16 = 0x0100;
const STATUS_SIG_TARGET_ABORT: u16 = 0x0800;
const STATUS_RECV_TARGET_ABORT: u16 = 0x1000;
const STATUS_RECV_MASTER_ABORT: u16 = 0x2000;
const STATUS_SIG_SYS_ERROR: u16 = 0x4000;
const STATUS_DETECT_PARITY_ERROR: u16 = 0x8000;

const BAR_IO_SPACE: u8 = 0x01;
const IO_BASE_ADDR_MASK: u32 = 0xffff_fffc;
const MEM_BASE_ADDR_MASK: u32 = 0xffff_fff0;
const BAR_MEM_64BIT: u8 = 0x04;
const BAR_PREFETCH: u8 = 0x08;
const BAR_SPACE_UNMAPPED: u64 = 0xffff_ffff_ffff_ffff;

// Role-Based error reporting.
const PCIE_CAP_RBER: u32 = 0x8000;
// Correctable error reporting.
const PCIE_CAP_DEV_CER: u16 = 0x01;
// Non-Fatal error reporting.
const PCIE_CAP_DEV_NFER: u16 = 0x02;
// Fatal error reporting.
const PCIE_CAP_DEV_FER: u16 = 0x04;
// Unsupported request reporting.
const PCIE_CAP_DEV_URR: u16 = 0x08;
// Max link speed.
const PCIE_CAP_MLS_16GT: u32 = 0x0000_0004;
// Maximum link width.
const PCIE_CAP_MLW_X32: u32 = 0x0000_0200;
// Active state power management support.
const PCIE_CAP_ASPM_L0S: u32 = 0x0000_0400;
// Link bandwidth notification capability
const PCIE_CAP_LINK_LBNC: u32 = 0x0020_0000;
// Data link layer link active reporting capable
const PCIE_CAP_LINK_DLLLARC: u32 = 0x0010_0000;
const PCIE_CAP_PORT_NUM_SHIFT: u8 = 24;
// Current link speed.
const PCIE_CAP_CLS_X1: u16 = 0x0001;
// Negotiated link width.
const PCIE_CAP_NLW_2_5GT: u16 = 0x0010;
// Data link layer link active
const PCIE_CAP_LINK_DLLLA: u16 = 0x2000;
// Attention button present.
const PCIE_CAP_SLOTCAP_ABP: u32 = 0x0000_0001;
// Power controller present.
const PCIE_CAP_SLOTCAP_PCP: u32 = 0x0000_0002;
// Attention indicator present.
const PCIE_CAP_SLOTCAP_AIP: u32 = 0x0000_0008;
// Power indicator present.
const PCIE_CAP_SLOTCAP_PIP: u32 = 0x0000_0010;
// Hot-Plug surprise.
const PCIE_CAP_SLOTCAP_HPS: u32 = 0x0000_0020;
// Hot-Plug capable.
const PCIE_CAP_SLOTCAP_HPC: u32 = 0x0000_0040;
// Electromechanical interlock present.
const PCIE_CAP_SLOTCAP_EIP: u32 = 0x0002_0000;
const PCIE_CAP_SLOT_NUM_SHIFT: u32 = 19;
// Attention Indicator Control.
const PCIE_CAP_SLOT_AIC_MASK: u16 = 0x00c0;
const PCIE_CAP_SLOT_AIC_OFF: u16 = 0x00c0;
// Power Indicator Control.
const PCIE_CAP_SLOT_PIC_MASK: u16 = 0x0300;
const PCIE_CAP_SLOT_PIC_OFF: u16 = 0x0300;
// Attention button pressed enable.
const PCIE_CAP_SLOT_ABP: u16 = 0x0001;
// Presence detect changed enable.
const PCIE_CAP_SLOT_PDC: u16 = 0x0008;
// Command completed interrupt enable.
const PCIE_CAP_SLOT_CCI: u16 = 0x0010;
// Hot-Plug interrupt enable.
const PCIE_CAP_SLOT_HPI: u16 = 0x0020;
// Power controller control.
const PCIE_CAP_SLOT_PCC: u16 = 0x0400;
// Electromechanical interlock control.
const PCIE_CAP_SLOT_EIC: u16 = 0x0800;
// System error on correctable error enable.
const PCIE_CAP_ROOT_SECEE: u16 = 0x01;
// System error on non-fatal error enable.
const PCIE_CAP_ROOT_SENFEE: u16 = 0x02;
// System error on fatal error enable.
const PCIE_CAP_ROOT_SEFEE: u16 = 0x04;
const PCIE_CAP_ARI: u32 = 0x0000_0020;
// Extended Fmt Field Supported.
const PCIE_CAP_DEV_EFFS: u32 = 0x0010_0000;
// End-End TLP Prefix Supported.
const PCIE_CAP_DEV_EETPS: u32 = 0x0020_0000;
const PCIE_CAP_ARI_ENABLE: u16 = 0x0020;
// End-End TLP Prefix Blocking
const PCIE_CAP_DEV_EETPB: u16 = 0x8000;
// Supported Link Speeds Vector.
const PCIE_CAP_LINK_SLSV_2_5GT: u32 = 0x02;
const PCIE_CAP_LINK_SLSV_5GT: u32 = 0x04;
const PCIE_CAP_LINK_SLSV_8GT: u32 = 0x08;
const PCIE_CAP_LINK_SLSV_16GT: u32 = 0x10;
// Target Link Speed.
const PCIE_CAP_LINK_TLS_16GT: u16 = 0x0004;

#[derive(PartialEq, Debug)]
pub enum RegionType {
    Io,
    Mem32Bit,
    Mem64Bit,
}

pub struct Bar {
    region_type: RegionType,
    address: u64,
    size: u64,
    pub region: Option<Region>,
}

pub enum CapId {
    Pcie = 0x10,
    Msix,
}

/// Offset of registers in PCIe capability register.
enum PcieCap {
    CapReg = 0x02,
    DevCap = 0x04,
    DevCtl = 0x08,
    DevStat = 0x0a,
    LinkCap = 0x0c,
    LinkStat = 0x12,
    SlotCap = 0x14,
    SlotCtl = 0x18,
    SlotStat = 0x1a,
    RootCtl = 0x1c,
    DevCap2 = 0x24,
    DevCtl2 = 0x28,
    LinkCap2 = 0x2c,
    LinkCtl2 = 0x30,
}

/// Device/Port Type in PCIe capability register.
pub enum PcieDevType {
    PcieEp,
    LegacyPcieEp,
    RootPort = 0x04,
    UpPort,
    DownPort,
    PciePciBridge,
    PciPcieBridge,
    Rciep,
    RcEventCol,
}

/// Configuration space of PCI/PCIe device.
pub struct PciConfig {
    /// Configuration space data.
    pub config: Vec<u8>,
    /// Mask of writable bits.
    pub write_mask: Vec<u8>,
    /// Mask of bits which are cleared when written.
    pub write_clear_mask: Vec<u8>,
    /// BARs.
    pub bars: Vec<Bar>,
    /// Base offset of the last PCI standard capability.
    pub last_cap_end: u16,
    /// Base offset of the last PCIe extended capability.
    pub last_ext_cap_offset: u16,
    /// End offset of the last PCIe extended capability.
    pub last_ext_cap_end: u16,
}

impl PciConfig {
    /// Construct new PciConfig entity.
    ///
    /// # Arguments
    ///
    /// * `config_size` - Configuration size in bytes.
    /// * `nr_bar` - Number of BARs.
    pub fn new(config_size: usize, nr_bar: u8) -> Self {
        let mut bars = Vec::new();
        for _ in 0..nr_bar as usize {
            bars.push(Bar {
                region_type: RegionType::Mem32Bit,
                address: 0,
                size: 0,
                region: None,
            });
        }

        PciConfig {
            config: vec![0; config_size],
            write_mask: vec![0; config_size],
            write_clear_mask: vec![0; config_size],
            bars,
            last_cap_end: PCI_CONFIG_HEAD_END as u16,
            last_ext_cap_offset: 0,
            last_ext_cap_end: PCI_CONFIG_SPACE_SIZE as u16,
        }
    }

    /// Init write_mask for all kinds of PCI/PCIe devices, including bridges.
    pub fn init_common_write_mask(&mut self) -> Result<()> {
        self.write_mask[CACHE_LINE_SIZE as usize] = 0xff;
        self.write_mask[INTERRUPT_LINE as usize] = 0xff;
        le_write_u16(
            &mut self.write_mask,
            COMMAND as usize,
            COMMAND_IO_SPACE
                | COMMAND_MEMORY_SPACE
                | COMMAND_BUS_MASTER
                | COMMAND_INTERRUPT_DISABLE
                | COMMAND_SERR_ENABLE,
        )?;

        let mut offset = PCI_CONFIG_HEAD_END as usize;
        while offset < self.config.len() {
            le_write_u32(&mut self.write_mask, offset, 0xffff_ffff)?;
            offset += 4;
        }

        Ok(())
    }

    /// Init write_mask especially for bridge devices.
    pub fn init_bridge_write_mask(&mut self) -> Result<()> {
        self.write_mask[IO_BASE as usize] = 0xf0;
        self.write_mask[IO_LIMIT as usize] = 0xf0;
        le_write_u32(&mut self.write_mask, PRIMARY_BUS_NUM as usize, 0xffff_ffff)?;
        le_write_u32(&mut self.write_mask, MEMORY_BASE as usize, 0xfff0_fff0)?;
        le_write_u32(&mut self.write_mask, PREF_MEMORY_BASE as usize, 0xfff0_fff0)?;
        le_write_u64(
            &mut self.write_mask,
            PREF_MEM_BASE_UPPER as usize,
            0xffff_ffff_ffff_ffff,
        )?;
        le_write_u16(
            &mut self.write_mask,
            BRIDGE_CONTROL as usize,
            BRIDGE_CTL_PARITY_ENABLE
                | BRIDGE_CTL_SERR_ENABLE
                | BRIDGE_CTL_ISA_ENABLE
                | BRIDGE_CTL_VGA_ENABLE
                | BRIDGE_CTL_VGA_16BIT_DEC
                | BRIDGE_CTL_SEC_BUS_RESET,
        )?;
        Ok(())
    }

    /// Init write_clear_mask especially for bridge devices.
    pub fn init_bridge_write_clear_mask(&mut self) -> Result<()> {
        le_write_u16(
            &mut self.write_clear_mask,
            BRIDGE_CONTROL as usize,
            BRIDGE_CTL_DISCARD_TIMER_STATUS,
        )
    }

    /// Init write_clear_mask for all kind of PCI/PCIe devices, including bridges.
    pub fn init_common_write_clear_mask(&mut self) -> Result<()> {
        le_write_u16(
            &mut self.write_clear_mask,
            STATUS as usize,
            STATUS_PARITY_ERROR
                | STATUS_SIG_TARGET_ABORT
                | STATUS_RECV_TARGET_ABORT
                | STATUS_RECV_MASTER_ABORT
                | STATUS_SIG_SYS_ERROR
                | STATUS_DETECT_PARITY_ERROR,
        )
    }

    /// Common reading from configuration space.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset in the configuration space from which to read.
    /// * `data` - Buffer to put read data.
    pub fn read(&self, offset: usize, buf: &mut [u8]) {
        let size = buf.len();
        buf[..].copy_from_slice(&self.config[offset..(offset + size)]);
    }

    /// Common writing to configuration space.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset in the configuration space from which to write.
    /// * `data` - Data to write.
    /// * `vm_fd` - The file descriptor of VM.
    /// * `dev_id` - Device id to send MSI/MSI-X.
    pub fn write(&mut self, mut offset: usize, data: &mut [u8]) {
        for i in 0..data.len() {
            data[i] &= self.write_mask[offset];
            self.config[offset] = (self.config[offset] & (!self.write_mask[offset])) | data[i];
            self.config[offset] &= !self.write_clear_mask[offset];
            offset += 1;
        }
    }

    /// Get base address of BAR.
    ///
    /// # Arguments
    ///
    /// * `id` - Index of the BAR.
    pub fn get_bar_address(&self, id: usize) -> u64 {
        let command = le_read_u16(&self.config, COMMAND as usize).unwrap();
        let offset: usize = BAR_0 as usize + id * REG_SIZE;
        if self.config[offset] & BAR_IO_SPACE > 0 {
            if command & COMMAND_IO_SPACE == 0 {
                return BAR_SPACE_UNMAPPED;
            }
            let bar_val = le_read_u32(&self.config, offset).unwrap();
            let address: u64 = (bar_val & IO_BASE_ADDR_MASK) as u64;
            address
        } else {
            if command & COMMAND_MEMORY_SPACE == 0 {
                return BAR_SPACE_UNMAPPED;
            }
            let address: u64;
            match self.bars[id].region_type {
                RegionType::Io | RegionType::Mem32Bit => {
                    let bar_val = le_read_u32(&self.config, offset).unwrap();
                    address = (bar_val & MEM_BASE_ADDR_MASK) as u64;
                }
                RegionType::Mem64Bit => {
                    let bar_val = le_read_u64(&self.config, offset).unwrap();
                    address = bar_val & MEM_BASE_ADDR_MASK as u64;
                }
            }
            address
        }
    }

    /// Register a bar in PciConfig::bars.
    ///
    /// # Arguments
    ///
    /// * `id` - Index of the BAR.
    /// * `region` - Region mapped for the BAR.
    /// * `region_type` - Region type of the BAR.
    /// * `prefetchable` - Indicate whether the BAR is prefetchable or not.
    /// * `size` - Size of the BAR.
    pub fn register_bar(
        &mut self,
        id: usize,
        region: Region,
        region_type: RegionType,
        prefetchable: bool,
        size: u64,
    ) {
        let offset: usize = BAR_0 as usize + id * REG_SIZE;
        match region_type {
            RegionType::Io => {
                let write_mask = (!(size - 1) as u32) & 0xffff_fffc;
                le_write_u32(&mut self.write_mask, offset, write_mask).unwrap();
                self.config[offset] = BAR_IO_SPACE;
            }
            RegionType::Mem32Bit => {
                let write_mask = (!(size - 1) as u32) & 0xffff_fff0;
                le_write_u32(&mut self.write_mask, offset, write_mask).unwrap();
            }
            RegionType::Mem64Bit => {
                let write_mask = !(size - 1) & 0xffff_ffff_ffff_fff0;
                le_write_u64(&mut self.write_mask, offset, write_mask).unwrap();
                self.config[offset] = BAR_MEM_64BIT;
            }
        }
        if prefetchable {
            self.config[offset] |= BAR_PREFETCH;
        }

        self.bars[id].region_type = region_type;
        self.bars[id].address = BAR_SPACE_UNMAPPED;
        self.bars[id].size = size;
        self.bars[id].region = Some(region);
    }

    /// Update bar space mapping once the base address is updated by the guest.
    ///
    /// # Arguments
    ///
    /// * `io_region`: IO space region which the parent bridge manages.
    /// * `mem_region`: Memory space region which the parent bridge manages.
    pub fn update_bar_mapping(
        &mut self,
        #[cfg(target_arch = "x86_64")] io_region: &Region,
        mem_region: &Region,
    ) -> Result<()> {
        for id in 0..self.bars.len() {
            if self.bars[id].size == 0 {
                continue;
            }

            let new_addr: u64 = self.get_bar_address(id);
            if self.bars[id].address == new_addr {
                continue;
            }
            if self.bars[id].address != BAR_SPACE_UNMAPPED {
                match self.bars[id].region_type {
                    RegionType::Io => {
                        #[cfg(target_arch = "x86_64")]
                        io_region
                            .delete_subregion(self.bars[id].region.as_ref().unwrap())
                            .chain_err(|| format!("Failed to unmap BAR{} in I/O space.", id))?;
                    }
                    _ => mem_region
                        .delete_subregion(self.bars[id].region.as_ref().unwrap())
                        .chain_err(|| ErrorKind::UnregMemBar(id))?,
                }
            }
            if new_addr != BAR_SPACE_UNMAPPED {
                match self.bars[id].region_type {
                    RegionType::Io => {
                        #[cfg(target_arch = "x86_64")]
                        io_region
                            .add_subregion(self.bars[id].region.clone().unwrap(), new_addr)
                            .chain_err(|| format!("Failed to map BAR{} in I/O space.", id))?;
                    }
                    _ => mem_region
                        .add_subregion(self.bars[id].region.clone().unwrap(), new_addr)
                        .chain_err(|| ErrorKind::UnregMemBar(id))?,
                }
            }
        }
        Ok(())
    }

    /// Add a pci standard capability in the configuration space.
    ///
    /// # Arguments
    ///
    /// * `id` - Capability ID.
    /// * `size` - Size of the capability.
    pub fn add_pci_cap(&mut self, id: u8, size: usize) -> Result<usize> {
        let offset = self.last_cap_end as usize;
        if offset + size > PCI_CONFIG_SPACE_SIZE {
            return Err(ErrorKind::AddPciCap(id, size).into());
        }

        self.config[offset] = id;
        self.config[offset + NEXT_CAP_OFFSET as usize] = self.config[CAP_LIST as usize];
        self.config[CAP_LIST as usize] = offset as u8;
        self.config[STATUS as usize] |= STATUS_CAP_LIST as u8;

        let regs_num = if size % REG_SIZE == 0 {
            size / REG_SIZE
        } else {
            size / REG_SIZE + 1
        };
        for _ in 0..regs_num {
            le_write_u32(&mut self.write_mask, self.last_cap_end as usize, 0)?;
            self.last_cap_end += REG_SIZE as u16;
        }

        Ok(offset)
    }

    /// Add a pcie extended capability in the configuration space.
    ///
    /// # Arguments
    ///
    /// * `id` - Capability ID.
    /// * `size` - Size of the capability.
    /// * `version` - Capability version.
    pub fn add_pcie_ext_cap(&mut self, id: u8, size: usize, version: u32) -> Result<usize> {
        let offset = self.last_ext_cap_end as usize;
        if offset + size > PCIE_CONFIG_SPACE_SIZE {
            return Err(ErrorKind::AddPcieExtCap(id, size).into());
        }

        let regs_num = if size % REG_SIZE == 0 {
            size / REG_SIZE
        } else {
            size / REG_SIZE + 1
        };

        for _ in 0..regs_num {
            le_write_u32(&mut self.write_mask, self.last_ext_cap_end as usize, 0)?;
            self.last_ext_cap_end += REG_SIZE as u16;
        }
        le_write_u32(
            &mut self.config,
            offset,
            id as u32 | (version << PCIE_CAP_VERSION_SHIFT),
        )?;
        if self.last_ext_cap_offset != 0 {
            let old_value = le_read_u32(&self.config, self.last_ext_cap_offset as usize)?;
            le_write_u32(
                &mut self.config,
                self.last_ext_cap_offset as usize,
                old_value | ((offset as u32) << PCIE_CAP_NEXT_OFFSET_SHIFT),
            )?;
        }
        self.last_ext_cap_offset = offset as u16;

        Ok(offset)
    }

    /// Add PCIe capability.
    ///
    /// # Arguments
    ///
    /// * `devfn` - Slot number << 3 | function number.
    /// * `port_num` - Port number.
    /// * `dev_type` - Device type.
    pub fn add_pcie_cap(&mut self, devfn: u8, port_num: u8, dev_type: u8) -> Result<usize> {
        let cap_offset: usize = self.add_pci_cap(CapId::Pcie as u8, PCIE_CAP_SIZE as usize)?;
        let mut offset: usize = cap_offset + PcieCap::CapReg as usize;
        le_write_u16(
            &mut self.config,
            offset,
            dev_type as u16 | PCIE_CAP_VERSION_2 | PCIE_CAP_SLOT_IMPLEMENTED,
        )?;

        offset = cap_offset + PcieCap::DevCap as usize;
        le_write_u32(&mut self.config, offset, PCIE_CAP_RBER)?;
        offset = cap_offset + PcieCap::DevCtl as usize;
        let mask = PCIE_CAP_DEV_CER | PCIE_CAP_DEV_NFER | PCIE_CAP_DEV_FER | PCIE_CAP_DEV_URR;
        le_write_u16(&mut self.write_mask, offset, mask)?;
        offset = cap_offset + PcieCap::DevStat as usize;
        le_write_u16(&mut self.write_clear_mask, offset, mask)?;

        offset = cap_offset + PcieCap::LinkCap as usize;
        le_write_u32(
            &mut self.config,
            offset,
            PCIE_CAP_MLS_16GT
                | PCIE_CAP_MLW_X32
                | PCIE_CAP_ASPM_L0S
                | PCIE_CAP_LINK_LBNC
                | PCIE_CAP_LINK_DLLLARC
                | ((port_num as u32) << PCIE_CAP_PORT_NUM_SHIFT),
        )?;
        offset = cap_offset + PcieCap::LinkStat as usize;
        le_write_u16(
            &mut self.config,
            offset,
            PCIE_CAP_CLS_X1 | PCIE_CAP_NLW_2_5GT | PCIE_CAP_LINK_DLLLA,
        )?;

        let slot: u8 = devfn >> BDF_FUNC_SHIFT;
        offset = cap_offset + PcieCap::SlotCap as usize;
        le_write_u32(
            &mut self.config,
            offset,
            PCIE_CAP_SLOTCAP_ABP
                | PCIE_CAP_SLOTCAP_PCP
                | PCIE_CAP_SLOTCAP_AIP
                | PCIE_CAP_SLOTCAP_PIP
                | PCIE_CAP_SLOTCAP_HPS
                | PCIE_CAP_SLOTCAP_HPC
                | PCIE_CAP_SLOTCAP_EIP
                | ((slot as u32) << PCIE_CAP_SLOT_NUM_SHIFT),
        )?;
        offset = cap_offset + PcieCap::SlotCtl as usize;
        le_write_u16(
            &mut self.config,
            offset,
            PCIE_CAP_SLOT_AIC_OFF | PCIE_CAP_SLOT_PIC_OFF | PCIE_CAP_SLOT_PCC,
        )?;
        le_write_u16(
            &mut self.write_mask,
            offset,
            PCIE_CAP_SLOT_ABP
                | PCIE_CAP_SLOT_PDC
                | PCIE_CAP_SLOT_CCI
                | PCIE_CAP_SLOT_HPI
                | PCIE_CAP_SLOT_AIC_MASK
                | PCIE_CAP_SLOT_PIC_MASK
                | PCIE_CAP_SLOT_PCC
                | PCIE_CAP_SLOT_EIC,
        )?;
        offset = cap_offset + PcieCap::SlotStat as usize;
        le_write_u16(
            &mut self.write_clear_mask,
            offset,
            PCIE_CAP_SLOT_ABP | PCIE_CAP_SLOT_PDC | PCIE_CAP_SLOT_CCI,
        )?;

        offset = cap_offset + PcieCap::RootCtl as usize;
        le_write_u16(
            &mut self.write_mask,
            offset,
            PCIE_CAP_ROOT_SECEE | PCIE_CAP_ROOT_SENFEE | PCIE_CAP_ROOT_SEFEE,
        )?;

        offset = cap_offset + PcieCap::DevCap2 as usize;
        le_write_u32(
            &mut self.config,
            offset,
            PCIE_CAP_ARI | PCIE_CAP_DEV_EFFS | PCIE_CAP_DEV_EETPS,
        )?;
        offset = cap_offset + PcieCap::DevCtl2 as usize;
        le_write_u16(
            &mut self.write_mask,
            offset,
            PCIE_CAP_ARI_ENABLE | PCIE_CAP_DEV_EETPB,
        )?;

        offset = cap_offset + PcieCap::LinkCap2 as usize;
        le_write_u32(
            &mut self.write_mask,
            offset,
            PCIE_CAP_LINK_SLSV_2_5GT
                | PCIE_CAP_LINK_SLSV_5GT
                | PCIE_CAP_LINK_SLSV_8GT
                | PCIE_CAP_LINK_SLSV_16GT,
        )?;
        offset = cap_offset + PcieCap::LinkCtl2 as usize;
        le_write_u16(&mut self.write_mask, offset, PCIE_CAP_LINK_TLS_16GT)?;

        Ok(cap_offset)
    }
}
