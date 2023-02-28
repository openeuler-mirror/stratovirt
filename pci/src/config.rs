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

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use address_space::Region;
use log::{error, warn};

use crate::msix::Msix;
use crate::{
    le_read_u16, le_read_u32, le_read_u64, le_write_u16, le_write_u32, le_write_u64,
    pci_ext_cap_next, PciBus, BDF_FUNC_SHIFT,
};
use crate::{ranges_overlap, PciError};
use anyhow::{anyhow, Context, Result};

/// Size in bytes of the configuration space of legacy PCI device.
pub const PCI_CONFIG_SPACE_SIZE: usize = 256;
/// Size in bytes of the configuration space of PCIe device.
pub const PCIE_CONFIG_SPACE_SIZE: usize = 4096;
/// Size in bytes of dword.
pub const REG_SIZE: usize = 4;
/// Max number of function.
pub const MAX_FUNC: u8 = 8;

/// Vendor ID Register.
pub const VENDOR_ID: u8 = 0x0;
/// Device ID register.
pub const DEVICE_ID: u8 = 0x02;
/// Command register.
pub const COMMAND: u8 = 0x04;
pub const REVISION_ID: usize = 0x08;
/// Sub-Class Code Register.
pub const SUB_CLASS_CODE: u8 = 0x0a;
pub const SUBSYSTEM_VENDOR_ID: usize = 0x2c;
pub const SUBSYSTEM_ID: usize = 0x2e;
/// Header Type register.
pub const HEADER_TYPE: u8 = 0x0e;
/// Base address register 0.
pub const BAR_0: u8 = 0x10;
/// Base address register 5.
pub const BAR_5: u8 = 0x24;
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
/// Prefetchable memory limit register.
pub const PREF_MEMORY_LIMIT: u8 = 0x26;
pub const ROM_ADDRESS: usize = 0x30;
pub const ROM_ADDRESS1: usize = 0x38;

/// 64-bit prefetchable memory addresses.
pub const PREF_MEM_RANGE_64BIT: u8 = 0x01;

/// I/O space enable.
pub const COMMAND_IO_SPACE: u16 = 0x0001;
/// Memory space enable.
pub const COMMAND_MEMORY_SPACE: u16 = 0x0002;

/// Class code of host bridge.
pub const CLASS_CODE_HOST_BRIDGE: u16 = 0x0600;
/// Class code of ISA bridge.
pub const CLASS_CODE_ISA_BRIDGE: u16 = 0x0601;
/// Class code of PCI-to-PCI bridge.
pub const CLASS_CODE_PCI_BRIDGE: u16 = 0x0604;
/// Type 0 configuration Space Header Layout.
pub const HEADER_TYPE_ENDPOINT: u8 = 0x0;
/// Type 1 configuration Space Header Layout.
pub const HEADER_TYPE_BRIDGE: u8 = 0x01;
/// Multi-function device.
pub const HEADER_TYPE_MULTIFUNC: u8 = 0x80;
/// The vendor ID for PCI devices other than virtio.
pub const PCI_VENDOR_ID_REDHAT: u16 = 0x1b36;

const PCI_CONFIG_HEAD_END: u8 = 64;
const NEXT_CAP_OFFSET: u8 = 0x01;
const STATUS_CAP_LIST: u16 = 0x0010;

/// 16 bits PCI Status.
pub const STATUS: u8 = 0x06;
/// PCI Interrupt Status.
pub const STATUS_INTERRUPT: u8 = 0x08;
const CACHE_LINE_SIZE: u8 = 0x0c;
pub const PRIMARY_BUS_NUM: u8 = 0x18;
pub const IO_LIMIT: u8 = 0x1d;
pub const PREF_MEM_BASE_UPPER: u8 = 0x28;
const CAP_LIST: u8 = 0x34;
const INTERRUPT_LINE: u8 = 0x3c;
pub const BRIDGE_CONTROL: u8 = 0x3e;

const BRIDGE_CTL_PARITY_ENABLE: u16 = 0x0001;
const BRIDGE_CTL_SERR_ENABLE: u16 = 0x0002;
const BRIDGE_CTL_ISA_ENABLE: u16 = 0x0004;
const BRIDGE_CTL_VGA_ENABLE: u16 = 0x0008;
const BRIDGE_CTL_VGA_16BIT_DEC: u16 = 0x0010;
pub const BRIDGE_CTL_SEC_BUS_RESET: u16 = 0x0040;
const BRIDGE_CTL_FAST_BACK: u16 = 0x0080;
const BRIDGE_CTL_DISCARD_TIMER: u16 = 0x0100;
const BRIDGE_CTL_SEC_DISCARD_TIMER: u16 = 0x0200;
const BRIDGE_CTL_DISCARD_TIMER_STATUS: u16 = 0x0400;
const BRIDGE_CTL_DISCARD_TIMER_SERR_E: u16 = 0x0800;

pub const COMMAND_BUS_MASTER: u16 = 0x0004;
const COMMAND_SERR_ENABLE: u16 = 0x0100;
#[cfg(test)]
const COMMAND_FAST_BACK: u16 = 0x0200;
pub const COMMAND_INTERRUPT_DISABLE: u16 = 0x0400;

const STATUS_PARITY_ERROR: u16 = 0x0100;
const STATUS_SIG_TARGET_ABORT: u16 = 0x0800;
const STATUS_RECV_TARGET_ABORT: u16 = 0x1000;
const STATUS_RECV_MASTER_ABORT: u16 = 0x2000;
const STATUS_SIG_SYS_ERROR: u16 = 0x4000;
const STATUS_DETECT_PARITY_ERROR: u16 = 0x8000;

pub const BAR_IO_SPACE: u8 = 0x01;
pub const IO_BASE_ADDR_MASK: u32 = 0xffff_fffc;
pub const MEM_BASE_ADDR_MASK: u64 = 0xffff_ffff_ffff_fff0;
pub const BAR_MEM_64BIT: u8 = 0x04;
const BAR_PREFETCH: u8 = 0x08;
pub const BAR_SPACE_UNMAPPED: u64 = 0xffff_ffff_ffff_ffff;
/// The maximum Bar ID numbers of a Type 0 device
pub const BAR_NUM_MAX_FOR_ENDPOINT: u8 = 6;
/// The maximum Bar ID numbers of a Type 1 device
pub const BAR_NUM_MAX_FOR_BRIDGE: u8 = 2;
/// mmio bar's minimum size shall be 4KB
pub const MINMUM_BAR_SIZE_FOR_MMIO: usize = 0x1000;
/// pio bar's minimum size shall be 4B
pub const MINMUM_BAR_SIZE_FOR_PIO: usize = 0x4;

/// PCI Express capability registers, same as kernel defines

const PCI_EXT_CAP_VER_SHIFT: u8 = 16;
const PCI_EXT_CAP_NEXT_SHIFT: u8 = 20;
const PCI_EXP_VER2_SIZEOF: u8 = 0x3c;
const PCI_EXP_FLAGS_VER2: u16 = 0x0002;
const PCI_EXP_FLAGS_SLOT: u16 = 0x0100;
// PCIe type flag
const PCI_EXP_FLAGS_TYPE_SHIFT: u16 = 4;
const PCI_EXP_FLAGS_TYPE: u16 = 0x00f0;

// Role-Based error reporting.
const PCI_EXP_DEVCAP_RBER: u32 = 0x8000;

// Correctable error reporting enable.
const PCI_EXP_DEVCTL_CERE: u16 = 0x01;
// Non-Fatal error reporting enable.
const PCI_EXP_DEVCTL_NFERE: u16 = 0x02;
// Fatal error reporting enable.
const PCI_EXP_DEVCTL_FERE: u16 = 0x04;
// Unsupported request reporting enable.
const PCI_EXP_DEVCTL_URRE: u16 = 0x08;

// Supported max link speed, 16GT for default.
const PCI_EXP_LNKCAP_MLS_16GT: u32 = 0x0000_0004;
// Supported maximum link width, X32 for default.
const PCI_EXP_LNKCAP_MLW_X32: u32 = 0x0000_0200;
// Active state power management support.
const PCI_EXP_LNKCAP_ASPMS_0S: u32 = 0x0000_0400;
// Link bandwidth notification capability.
const PCI_EXP_LNKCAP_LBNC: u32 = 0x0020_0000;
// Data link layer link active reporting capable.
const PCI_EXP_LNKCAP_DLLLARC: u32 = 0x0010_0000;
// Port number reg's shift.
const PCI_EXP_LNKCAP_PN_SHIFT: u8 = 24;

/// Link Training
pub const PCI_EXP_LNKSTA: u16 = 18;
// Current link speed, 2.5GB for default.
pub const PCI_EXP_LNKSTA_CLS_2_5GB: u16 = 0x0001;
// Negotiated link width, X1 for default.
pub const PCI_EXP_LNKSTA_NLW_X1: u16 = 0x0010;
/// Data Link Layer Link Active
pub const PCI_EXP_LNKSTA_DLLLA: u16 = 0x2000;
/// Negotiated Link Width
pub const PCI_EXP_LNKSTA_NLW: u16 = 0x03f0;

// Attention button present.
const PCI_EXP_SLTCAP_ABP: u32 = 0x0000_0001;
// Power controller present.
const PCI_EXP_SLTCAP_PCP: u32 = 0x0000_0002;
// Attention indicator present.
const PCI_EXP_SLTCAP_AIP: u32 = 0x0000_0008;
// Power indicator present.
const PCI_EXP_SLTCAP_PIP: u32 = 0x0000_0010;
// Hot-Plug surprise.
const PCI_EXP_SLTCAP_HPS: u32 = 0x0000_0020;
// Hot-Plug capable.
const PCI_EXP_SLTCAP_HPC: u32 = 0x0000_0040;
// Physical slot number reg's shift.
const PCI_EXP_SLTCAP_PSN_SHIFT: u32 = 19;

/// Slot Control
pub const PCI_EXP_SLTCTL: u16 = 24;
/// Attention Button Pressed Enable
pub const PCI_EXP_SLTCTL_ABPE: u16 = 0x0001;
/// Presence Detect Changed Enable
pub const PCI_EXP_SLTCTL_PDCE: u16 = 0x0008;
/// Command Completed Interrupt Enable
pub const PCI_EXP_SLTCTL_CCIE: u16 = 0x0010;
/// Hot-Plug Interrupt Enable
pub const PCI_EXP_SLTCTL_HPIE: u16 = 0x0020;
// Attention Indicator Control.
const PCI_EXP_SLTCTL_AIC: u16 = 0x00c0;
// Attention Indicator off.
const PCI_EXP_SLTCTL_ATTN_IND_OFF: u16 = 0x00c0;
// Power Indicator Control.
pub(crate) const PCI_EXP_SLTCTL_PIC: u16 = 0x0300;
// Power Indicator blinking.
pub(crate) const PCI_EXP_SLTCTL_PWR_IND_BLINK: u16 = 0x200;
/// Power Indicator on
pub const PCI_EXP_SLTCTL_PWR_IND_ON: u16 = 0x0100;
// Power Indicator off.
pub const PCI_EXP_SLTCTL_PWR_IND_OFF: u16 = 0x0300;
/// Power Controller Control
pub const PCI_EXP_SLTCTL_PCC: u16 = 0x0400;
/// Power Off
pub const PCI_EXP_SLTCTL_PWR_OFF: u16 = 0x0400;
// Electromechanical interlock control.
const PCI_EXP_SLTCTL_EIC: u16 = 0x0800;

/// Slot Status
pub const PCI_EXP_SLTSTA: u16 = 26;
/// Attention Button Pressed
pub const PCI_EXP_SLTSTA_ABP: u16 = 0x0001;
/// Power Fault Detected
pub const PCI_EXP_SLTSTA_PFD: u16 = 0x0002;
/// MRL Sensor Changed
pub const PCI_EXP_SLTSTA_MRLSC: u16 = 0x0004;
/// Presence Detect Changed
pub const PCI_EXP_SLTSTA_PDC: u16 = 0x0008;
/// Command Completed
pub const PCI_EXP_SLTSTA_CC: u16 = 0x0010;
/// Presence Detect State
pub const PCI_EXP_SLTSTA_PDS: u16 = 0x0040;
pub const PCI_EXP_SLOTSTA_EVENTS: u16 = PCI_EXP_SLTSTA_ABP
    | PCI_EXP_SLTSTA_PFD
    | PCI_EXP_SLTSTA_MRLSC
    | PCI_EXP_SLTSTA_PDC
    | PCI_EXP_SLTSTA_CC;

// System error on correctable error enable.
const PCI_EXP_RTCTL_SECEE: u16 = 0x01;
// System error on non-fatal error enable.
const PCI_EXP_RTCTL_SENFEE: u16 = 0x02;
// System error on fatal error enable.
const PCI_EXP_RTCTL_SEFEE: u16 = 0x04;

// Alternative Routing-ID.
const PCI_EXP_DEVCAP2_ARI: u32 = 0x0000_0020;
// Extended Fmt Field Supported.
const PCI_EXP_DEVCAP2_EFF: u32 = 0x0010_0000;
// End-End TLP Prefix Supported.
const PCI_EXP_DEVCAP2_EETLPP: u32 = 0x0020_0000;
// Alternative Routing-ID.
const PCI_EXP_DEVCTL2_ARI: u16 = 0x0020;
// End-End TLP Prefix Blocking
const PCI_EXP_DEVCTL2_EETLPPB: u16 = 0x8000;

// Supported Link Speeds Vector.
const PCI_EXP_LNKCAP2_SLS_2_5GB: u32 = 0x02;
const PCI_EXP_LNKCAP2_SLS_5_0GB: u32 = 0x04;
const PCI_EXP_LNKCAP2_SLS_8_0GB: u32 = 0x08;
const PCI_EXP_LNKCAP2_SLS_16_0GB: u32 = 0x10;

// Target Link Speed, 16GT for default.
const PCI_EXP_LNKCTL2_TLS_16_0GT: u16 = 0x0004;

/// Hot plug event
/// Presence detect changed
pub const PCI_EXP_HP_EV_PDC: u16 = PCI_EXP_SLTCTL_PDCE;
/// Attention button pressed
pub const PCI_EXP_HP_EV_ABP: u16 = PCI_EXP_SLTCTL_ABPE;
/// Command completed
pub const PCI_EXP_HP_EV_CCI: u16 = PCI_EXP_SLTCTL_CCIE;

// XHCI device id
pub const PCI_DEVICE_ID_REDHAT_XHCI: u16 = 0x000d;
pub const PCI_CLASS_SERIAL_USB: u16 = 0x0c03;

/// Type of bar region.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum RegionType {
    Io,
    Mem32Bit,
    Mem64Bit,
}

impl std::fmt::Display for RegionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                RegionType::Io => "PIO",
                RegionType::Mem32Bit => "32 bits MMIO",
                RegionType::Mem64Bit => "64 bits MMIO",
            }
        )
    }
}

/// Registered bar.
#[derive(Clone)]
pub struct Bar {
    region_type: RegionType,
    address: u64,
    pub size: u64,
    pub region: Option<Region>,
    pub parent_io_region: Option<Arc<Mutex<Region>>>,
    pub parent_mem_region: Option<Arc<Mutex<Region>>>,
}

/// Capbility ID defined by PCIe/PCI spec.
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
#[derive(Clone)]
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
    /// MSI-X information.
    pub msix: Option<Arc<Mutex<Msix>>>,
    /// Offset of the PCI express capability.
    pub pci_express_cap_offset: u16,
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
                parent_io_region: None,
                parent_mem_region: None,
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
            msix: None,
            pci_express_cap_offset: PCI_CONFIG_HEAD_END as u16,
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
                | BRIDGE_CTL_SEC_BUS_RESET
                | BRIDGE_CTL_FAST_BACK
                | BRIDGE_CTL_DISCARD_TIMER
                | BRIDGE_CTL_SEC_DISCARD_TIMER
                | BRIDGE_CTL_DISCARD_TIMER_SERR_E,
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
        if let Err(err) = self.validate_config_boundary(offset, buf) {
            warn!("invalid read: {:?}", err);
            return;
        }
        let size = buf.len();
        buf[..].copy_from_slice(&self.config[offset..(offset + size)]);
    }

    fn validate_config_boundary(&self, offset: usize, data: &[u8]) -> Result<()> {
        if offset + data.len() > self.config.len() {
            return Err(anyhow!(PciError::InvalidConf(
                "config size".to_string(),
                format!("offset {} with len {}", offset, data.len())
            )));
        }

        // According to pcie specification 7.2.2.2 PCI Express Device Requirements:
        if data.len() > 4 {
            return Err(anyhow!(PciError::InvalidConf(
                "data size".to_string(),
                format!("{}", data.len())
            )));
        }

        Ok(())
    }

    /// Common writing to configuration space.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset in the configuration space from which to write.
    /// * `data` - Data to write.
    /// * `dev_id` - Device id to send MSI/MSI-X.
    pub fn write(
        &mut self,
        mut offset: usize,
        data: &[u8],
        dev_id: u16,
        #[cfg(target_arch = "x86_64")] io_region: Option<&Region>,
        mem_region: Option<&Region>,
    ) {
        if let Err(err) = self.validate_config_boundary(offset, data) {
            error!("invalid write: {:?}", err);
            return;
        }

        let cloned_data = data.to_vec();
        let old_offset = offset;
        let end = offset + data.len();
        for data in &cloned_data {
            self.config[offset] = (self.config[offset] & (!self.write_mask[offset]))
                | (data & self.write_mask[offset]);
            self.config[offset] &= !(data & self.write_clear_mask[offset]);
            offset += 1;
        }

        let mut bar_num = BAR_NUM_MAX_FOR_ENDPOINT;
        if self.config[HEADER_TYPE as usize] == HEADER_TYPE_BRIDGE {
            bar_num = BAR_NUM_MAX_FOR_ENDPOINT;
        }
        if ranges_overlap(old_offset, end, COMMAND as usize, (COMMAND + 1) as usize)
            || ranges_overlap(
                old_offset,
                end,
                BAR_0 as usize,
                BAR_0 as usize + REG_SIZE * bar_num as usize,
            )
            || ranges_overlap(old_offset, end, ROM_ADDRESS, ROM_ADDRESS + 4)
        {
            if let Err(e) = self.update_bar_mapping(
                #[cfg(target_arch = "x86_64")]
                io_region,
                mem_region,
            ) {
                error!("{:?}", e);
            }
        }

        if let Some(msix) = &mut self.msix {
            msix.lock()
                .unwrap()
                .write_config(&self.config, dev_id, old_offset, data);
        }
    }

    /// Reset type1 specific configuration space.
    pub fn reset_bridge_regs(&mut self) -> Result<()> {
        le_write_u32(&mut self.config, PRIMARY_BUS_NUM as usize, 0)?;

        self.config[IO_BASE as usize] = 0xff;
        self.config[IO_LIMIT as usize] = 0;
        // set memory/pref memory's base to 0xFFFF and limit to 0.
        le_write_u32(&mut self.config, MEMORY_BASE as usize, 0xffff)?;
        le_write_u32(&mut self.config, PREF_MEMORY_BASE as usize, 0xffff)?;
        le_write_u64(&mut self.config, PREF_MEM_BASE_UPPER as usize, 0)?;
        Ok(())
    }

    fn reset_single_writable_reg(&mut self, offset: usize) -> Result<()> {
        let writable_command = le_read_u16(&self.write_mask, offset).unwrap()
            | le_read_u16(&self.write_clear_mask, offset).unwrap();
        let old_command = le_read_u16(&self.config, offset).unwrap();

        le_write_u16(&mut self.config, offset, old_command & !writable_command)
    }

    /// Reset bits that's writable in the common configuration fields for both type0 and type1 devices.
    pub fn reset_common_regs(&mut self) -> Result<()> {
        self.reset_single_writable_reg(COMMAND as usize)?;
        self.reset_single_writable_reg(STATUS as usize)?;
        self.reset_single_writable_reg(INTERRUPT_LINE as usize)?;
        self.config[CACHE_LINE_SIZE as usize] = 0;

        Ok(())
    }

    /// General reset process for pci devices
    pub fn reset(&mut self) -> Result<()> {
        self.reset_common_regs()?;

        if let Err(e) = self.update_bar_mapping(
            #[cfg(target_arch = "x86_64")]
            None,
            None,
        ) {
            error!("{:?}", e);
        }

        if let Some(msix) = &self.msix {
            msix.lock().unwrap().reset();
        }

        Ok(())
    }

    /// Get base offset of the capability in PCIe/PCI configuration space.
    ///
    /// # Arguments
    ///
    /// * `cap_id` - Capability ID.
    pub fn find_pci_cap(&self, cap_id: u8) -> usize {
        let mut offset = self.config[CAP_LIST as usize];
        let mut cache_offsets = HashSet::new();
        cache_offsets.insert(offset);
        loop {
            let cap = self.config[offset as usize];
            if cap == cap_id {
                return offset as usize;
            }

            offset = self.config[offset as usize + NEXT_CAP_OFFSET as usize];
            if offset == 0 || cache_offsets.contains(&offset) {
                return 0xff;
            }
            cache_offsets.insert(offset);
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
            return (bar_val & IO_BASE_ADDR_MASK) as u64;
        }

        if command & COMMAND_MEMORY_SPACE == 0 {
            return BAR_SPACE_UNMAPPED;
        }
        match self.bars[id].region_type {
            RegionType::Io => BAR_SPACE_UNMAPPED,
            RegionType::Mem32Bit => {
                let bar_val = le_read_u32(&self.config, offset).unwrap();
                (bar_val & MEM_BASE_ADDR_MASK as u32) as u64
            }
            RegionType::Mem64Bit => {
                let bar_val = le_read_u64(&self.config, offset).unwrap();
                bar_val & MEM_BASE_ADDR_MASK
            }
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
    ) -> Result<()> {
        self.validate_bar_id(id)?;
        self.validate_bar_size(region_type, size)?;
        let offset: usize = BAR_0 as usize + id * REG_SIZE;
        match region_type {
            RegionType::Io => {
                let write_mask = !(size - 1) as u32;
                le_write_u32(&mut self.write_mask, offset, write_mask).unwrap();
                self.config[offset] = BAR_IO_SPACE;
            }
            RegionType::Mem32Bit => {
                let write_mask = !(size - 1) as u32;
                le_write_u32(&mut self.write_mask, offset, write_mask).unwrap();
            }
            RegionType::Mem64Bit => {
                let write_mask = !(size - 1);
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
        Ok(())
    }

    /// Unregister region in PciConfig::bars.
    ///
    /// # Arguments
    ///
    /// * `bus` - The bus which region registered.
    pub fn unregister_bars(&mut self, bus: &Arc<Mutex<PciBus>>) -> Result<()> {
        let locked_bus = bus.lock().unwrap();
        for bar in self.bars.iter_mut() {
            if bar.address == BAR_SPACE_UNMAPPED || bar.size == 0 {
                continue;
            }
            match bar.region_type {
                RegionType::Io =>
                {
                    #[cfg(target_arch = "x86_64")]
                    if let Some(region) = bar.region.as_ref() {
                        locked_bus
                            .io_region
                            .delete_subregion(region)
                            .with_context(|| "Failed to unregister io bar")?;
                    }
                }
                _ => {
                    if let Some(region) = bar.region.as_ref() {
                        locked_bus
                            .mem_region
                            .delete_subregion(region)
                            .with_context(|| "Failed to unregister mem bar")?;
                    }
                }
            }
            bar.region = None;
        }
        Ok(())
    }

    fn is_bar_region_empty(
        &mut self,
        id: usize,
        #[cfg(target_arch = "x86_64")] io_region: Option<&Region>,
        mem_region: Option<&Region>,
    ) -> bool {
        if self.bars[id].region_type == RegionType::Io {
            #[cfg(target_arch = "x86_64")]
            if io_region.is_none() {
                return true;
            }
        } else if mem_region.is_none() {
            return true;
        }
        false
    }

    /// Update bar space mapping once the base address is updated by the guest.
    ///
    /// # Arguments
    ///
    /// * `io_region`: IO space region which the parent bridge manages.
    /// * `mem_region`: Memory space region which the parent bridge manages.
    pub fn update_bar_mapping(
        &mut self,
        #[cfg(target_arch = "x86_64")] io_region: Option<&Region>,
        mem_region: Option<&Region>,
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
                    #[cfg(target_arch = "x86_64")]
                    RegionType::Io => {
                        if self.bars[id].parent_io_region.is_some() {
                            self.bars[id]
                                .parent_io_region
                                .as_ref()
                                .unwrap()
                                .lock()
                                .unwrap()
                                .delete_subregion(self.bars[id].region.as_ref().unwrap())
                                .with_context(|| {
                                    format!("Failed to unmap BAR{} in I/O space.", id)
                                })?;
                        }
                    }
                    _ => {
                        if self.bars[id].parent_mem_region.is_some() {
                            self.bars[id]
                                .parent_mem_region
                                .as_ref()
                                .unwrap()
                                .lock()
                                .unwrap()
                                .delete_subregion(self.bars[id].region.as_ref().unwrap())
                                .with_context(|| anyhow!(PciError::UnregMemBar(id)))?
                        }
                    }
                }
                self.bars[id].address = BAR_SPACE_UNMAPPED;
            }

            if self.is_bar_region_empty(
                id,
                #[cfg(target_arch = "x86_64")]
                io_region,
                mem_region,
            ) {
                return Ok(());
            }

            if new_addr != BAR_SPACE_UNMAPPED {
                match self.bars[id].region_type {
                    #[cfg(target_arch = "x86_64")]
                    RegionType::Io => {
                        io_region
                            .unwrap()
                            .add_subregion(self.bars[id].region.clone().unwrap(), new_addr)
                            .with_context(|| format!("Failed to map BAR{} in I/O space.", id))?;
                        self.bars[id].parent_io_region =
                            Some(Arc::new(Mutex::new(io_region.unwrap().clone())));
                    }
                    _ => {
                        mem_region
                            .unwrap()
                            .add_subregion(self.bars[id].region.clone().unwrap(), new_addr)
                            .with_context(|| anyhow!(PciError::UnregMemBar(id)))?;
                        self.bars[id].parent_mem_region =
                            Some(Arc::new(Mutex::new(mem_region.unwrap().clone())));
                    }
                }

                self.bars[id].address = new_addr;
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
            return Err(anyhow!(PciError::AddPciCap(id, size)));
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
    pub fn add_pcie_ext_cap(&mut self, id: u16, size: usize, version: u32) -> Result<usize> {
        let offset = self.last_ext_cap_end as usize;
        if offset + size > PCIE_CONFIG_SPACE_SIZE {
            return Err(anyhow!(PciError::AddPcieExtCap(id, size)));
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
            id as u32 | (version << PCI_EXT_CAP_VER_SHIFT),
        )?;
        if self.last_ext_cap_offset != 0 {
            let old_value = le_read_u32(&self.config, self.last_ext_cap_offset as usize)?;
            le_write_u32(
                &mut self.config,
                self.last_ext_cap_offset as usize,
                old_value | ((offset as u32) << PCI_EXT_CAP_NEXT_SHIFT),
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
        let cap_offset: usize =
            self.add_pci_cap(CapId::Pcie as u8, PCI_EXP_VER2_SIZEOF as usize)?;
        self.pci_express_cap_offset = cap_offset as u16;
        let mut offset: usize = cap_offset + PcieCap::CapReg as usize;
        let pci_type = (dev_type << PCI_EXP_FLAGS_TYPE_SHIFT) as u16 & PCI_EXP_FLAGS_TYPE;
        le_write_u16(
            &mut self.config,
            offset,
            pci_type | PCI_EXP_FLAGS_VER2 | PCI_EXP_FLAGS_SLOT,
        )?;

        offset = cap_offset + PcieCap::DevCap as usize;
        le_write_u32(&mut self.config, offset, PCI_EXP_DEVCAP_RBER)?;
        offset = cap_offset + PcieCap::DevCtl as usize;
        let mask =
            PCI_EXP_DEVCTL_CERE | PCI_EXP_DEVCTL_NFERE | PCI_EXP_DEVCTL_FERE | PCI_EXP_DEVCTL_URRE;
        le_write_u16(&mut self.write_mask, offset, mask)?;
        offset = cap_offset + PcieCap::DevStat as usize;
        le_write_u16(&mut self.write_clear_mask, offset, mask)?;

        offset = cap_offset + PcieCap::LinkCap as usize;
        le_write_u32(
            &mut self.config,
            offset,
            PCI_EXP_LNKCAP_MLS_16GT
                | PCI_EXP_LNKCAP_MLW_X32
                | PCI_EXP_LNKCAP_ASPMS_0S
                | PCI_EXP_LNKCAP_LBNC
                | PCI_EXP_LNKCAP_DLLLARC
                | ((port_num as u32) << PCI_EXP_LNKCAP_PN_SHIFT),
        )?;
        offset = cap_offset + PcieCap::LinkStat as usize;
        le_write_u16(
            &mut self.config,
            offset,
            PCI_EXP_LNKSTA_CLS_2_5GB | PCI_EXP_LNKSTA_NLW_X1,
        )?;

        let slot: u8 = devfn >> BDF_FUNC_SHIFT;
        offset = cap_offset + PcieCap::SlotCap as usize;
        le_write_u32(
            &mut self.config,
            offset,
            PCI_EXP_SLTCAP_ABP
                | PCI_EXP_SLTCAP_PCP
                | PCI_EXP_SLTCAP_AIP
                | PCI_EXP_SLTCAP_PIP
                | PCI_EXP_SLTCAP_HPS
                | PCI_EXP_SLTCAP_HPC
                | ((slot as u32) << PCI_EXP_SLTCAP_PSN_SHIFT),
        )?;
        offset = cap_offset + PcieCap::SlotCtl as usize;
        le_write_u16(
            &mut self.config,
            offset,
            PCI_EXP_SLTCTL_ATTN_IND_OFF | PCI_EXP_SLTCTL_PWR_IND_OFF | PCI_EXP_SLTCTL_PCC,
        )?;
        le_write_u16(
            &mut self.write_mask,
            offset,
            PCI_EXP_SLTCTL_ABPE
                | PCI_EXP_SLTCTL_PDCE
                | PCI_EXP_SLTCTL_CCIE
                | PCI_EXP_SLTCTL_HPIE
                | PCI_EXP_SLTCTL_AIC
                | PCI_EXP_SLTCTL_PIC
                | PCI_EXP_SLTCTL_PCC
                | PCI_EXP_SLTCTL_EIC,
        )?;
        offset = cap_offset + PcieCap::SlotStat as usize;
        le_write_u16(
            &mut self.write_clear_mask,
            offset,
            PCI_EXP_SLTSTA_ABP | PCI_EXP_SLTSTA_PDC | PCI_EXP_SLTSTA_CC,
        )?;

        offset = cap_offset + PcieCap::RootCtl as usize;
        le_write_u16(
            &mut self.write_mask,
            offset,
            PCI_EXP_RTCTL_SECEE | PCI_EXP_RTCTL_SENFEE | PCI_EXP_RTCTL_SEFEE,
        )?;

        offset = cap_offset + PcieCap::DevCap2 as usize;
        le_write_u32(
            &mut self.config,
            offset,
            PCI_EXP_DEVCAP2_ARI | PCI_EXP_DEVCAP2_EFF | PCI_EXP_DEVCAP2_EETLPP,
        )?;
        offset = cap_offset + PcieCap::DevCtl2 as usize;
        le_write_u16(
            &mut self.write_mask,
            offset,
            PCI_EXP_DEVCTL2_ARI | PCI_EXP_DEVCTL2_EETLPPB,
        )?;

        offset = cap_offset + PcieCap::LinkCap2 as usize;
        le_write_u32(
            &mut self.config,
            offset,
            PCI_EXP_LNKCAP2_SLS_2_5GB
                | PCI_EXP_LNKCAP2_SLS_5_0GB
                | PCI_EXP_LNKCAP2_SLS_8_0GB
                | PCI_EXP_LNKCAP2_SLS_16_0GB,
        )?;
        offset = cap_offset + PcieCap::LinkCtl2 as usize;
        le_write_u16(&mut self.config, offset, PCI_EXP_LNKCTL2_TLS_16_0GT)?;

        Ok(cap_offset)
    }

    /// Calculate the next extended cap size from pci config space.
    ///
    /// # Arguments
    ///
    /// * `pos` - next extended capability offset.
    pub fn get_ext_cap_size(&self, pos: usize) -> usize {
        let mut cap_offset = PCI_CONFIG_SPACE_SIZE;
        let mut end_pos = PCIE_CONFIG_SPACE_SIZE;

        while (PCI_CONFIG_SPACE_SIZE..PCIE_CONFIG_SPACE_SIZE).contains(&cap_offset) {
            let header = le_read_u32(&self.config, cap_offset).unwrap();
            cap_offset = pci_ext_cap_next(header);
            if cap_offset > pos && cap_offset < end_pos {
                end_pos = cap_offset;
            }
        }

        end_pos - pos
    }

    fn validate_bar_id(&self, id: usize) -> Result<()> {
        if (self.config[HEADER_TYPE as usize] == HEADER_TYPE_ENDPOINT
            && id >= BAR_NUM_MAX_FOR_ENDPOINT as usize)
            || (self.config[HEADER_TYPE as usize] == HEADER_TYPE_BRIDGE
                && id >= BAR_NUM_MAX_FOR_BRIDGE as usize)
        {
            return Err(anyhow!(PciError::InvalidConf(
                "Bar id".to_string(),
                id.to_string(),
            )));
        }
        Ok(())
    }

    fn validate_bar_size(&self, bar_type: RegionType, size: u64) -> Result<()> {
        if !size.is_power_of_two()
            || ((bar_type == RegionType::Mem32Bit || bar_type == RegionType::Mem64Bit)
                && size < MINMUM_BAR_SIZE_FOR_MMIO.try_into().unwrap())
            || (bar_type == RegionType::Io && size < MINMUM_BAR_SIZE_FOR_PIO.try_into().unwrap())
            || (bar_type == RegionType::Mem32Bit && size > u32::MAX as u64)
            || (bar_type == RegionType::Io && size > u16::MAX as u64)
        {
            return Err(anyhow!(PciError::InvalidConf(
                "Bar size of type ".to_string() + &bar_type.to_string(),
                size.to_string(),
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use address_space::{AddressSpace, GuestAddress, RegionOps};

    use super::*;

    const MSI_CAP_ID: u8 = 0x05;
    const MSIX_CAP_ID: u8 = 0x11;

    #[test]
    fn test_find_pci_cap() {
        let mut pci_config = PciConfig::new(PCI_CONFIG_SPACE_SIZE, 3);
        let offset = pci_config.find_pci_cap(MSIX_CAP_ID);
        assert_eq!(offset, 0xff);

        let msi_cap_offset = pci_config.add_pci_cap(MSI_CAP_ID, 12).unwrap();
        let offset = pci_config.find_pci_cap(MSI_CAP_ID);
        assert_eq!(offset, msi_cap_offset);

        let msix_cap_offset = pci_config.add_pci_cap(MSIX_CAP_ID, 12).unwrap();
        let offset = pci_config.find_pci_cap(MSIX_CAP_ID);
        assert_eq!(offset, msix_cap_offset);

        let offset = pci_config.find_pci_cap(MSI_CAP_ID);
        assert_eq!(offset, msi_cap_offset);

        let tmp_offset = pci_config.config[CAP_LIST as usize];
        pci_config.config[tmp_offset as usize + NEXT_CAP_OFFSET as usize] = tmp_offset;
        let offset = pci_config.find_pci_cap(MSI_CAP_ID);
        assert_eq!(offset, 0xff);
    }

    #[test]
    fn test_get_bar_address() {
        let read_ops = move |_data: &mut [u8], _addr: GuestAddress, _offset: u64| -> bool { true };
        let write_ops = move |_data: &[u8], _addr: GuestAddress, _offset: u64| -> bool { true };
        let region_ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };
        let region = Region::init_io_region(8192, region_ops.clone());
        let mut pci_config = PciConfig::new(PCI_CONFIG_SPACE_SIZE, 3);

        #[cfg(target_arch = "x86_64")]
        assert!(pci_config
            .register_bar(0, region.clone(), RegionType::Io, false, 8192)
            .is_ok());
        assert!(pci_config
            .register_bar(1, region.clone(), RegionType::Mem32Bit, false, 8192)
            .is_ok());
        assert!(pci_config
            .register_bar(2, region.clone(), RegionType::Mem64Bit, true, 8192)
            .is_ok());
        // test when bar id is not valid
        assert!(pci_config
            .register_bar(7, region, RegionType::Mem64Bit, true, 8192)
            .is_err());
        // test when bar size is incorrect(below 4KB, or not power of 2)
        let region_size_too_small = Region::init_io_region(2048, region_ops.clone());
        assert!(pci_config
            .register_bar(3, region_size_too_small, RegionType::Mem64Bit, true, 2048)
            .is_err());
        let region_size_not_pow_2 = Region::init_io_region(4238, region_ops);
        assert!(pci_config
            .register_bar(4, region_size_not_pow_2, RegionType::Mem64Bit, true, 4238)
            .is_err());

        #[cfg(target_arch = "x86_64")]
        le_write_u32(
            &mut pci_config.config,
            BAR_0 as usize,
            IO_BASE_ADDR_MASK | BAR_IO_SPACE as u32,
        )
        .unwrap();
        le_write_u32(
            &mut pci_config.config,
            BAR_0 as usize + REG_SIZE,
            MEM_BASE_ADDR_MASK as u32,
        )
        .unwrap();
        le_write_u64(
            &mut pci_config.config,
            BAR_0 as usize + 2 * REG_SIZE,
            MEM_BASE_ADDR_MASK | (BAR_MEM_64BIT | BAR_PREFETCH) as u64,
        )
        .unwrap();

        // Neither I/O space nor memory space is enabled in command register.
        assert_eq!(pci_config.get_bar_address(0), BAR_SPACE_UNMAPPED);
        #[cfg(target_arch = "x86_64")]
        {
            // I/O space access is enabled.
            le_write_u16(&mut pci_config.config, COMMAND as usize, COMMAND_IO_SPACE).unwrap();
            assert_eq!(pci_config.get_bar_address(0), IO_BASE_ADDR_MASK as u64);
        }
        assert_eq!(pci_config.get_bar_address(1), BAR_SPACE_UNMAPPED);
        assert_eq!(pci_config.get_bar_address(2), BAR_SPACE_UNMAPPED);
        // Memory space access is enabled.
        le_write_u16(
            &mut pci_config.config,
            COMMAND as usize,
            COMMAND_MEMORY_SPACE,
        )
        .unwrap();
        #[cfg(target_arch = "x86_64")]
        assert_eq!(pci_config.get_bar_address(0), BAR_SPACE_UNMAPPED);
        assert_eq!(
            pci_config.get_bar_address(1),
            (MEM_BASE_ADDR_MASK as u32) as u64
        );
        assert_eq!(pci_config.get_bar_address(2), MEM_BASE_ADDR_MASK);
    }

    #[test]
    fn test_update_bar_mapping() {
        let read_ops = move |_data: &mut [u8], _addr: GuestAddress, _offset: u64| -> bool { true };
        let write_ops = move |_data: &[u8], _addr: GuestAddress, _offset: u64| -> bool { true };
        let region_ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };
        let region = Region::init_io_region(8192, region_ops);
        let mut pci_config = PciConfig::new(PCI_CONFIG_SPACE_SIZE, 6);

        #[cfg(target_arch = "x86_64")]
        assert!(pci_config
            .register_bar(0, region.clone(), RegionType::Io, false, 8192)
            .is_ok());
        assert!(pci_config
            .register_bar(1, region.clone(), RegionType::Mem32Bit, false, 8192)
            .is_ok());
        assert!(pci_config
            .register_bar(2, region, RegionType::Mem64Bit, true, 8192)
            .is_ok());

        #[cfg(target_arch = "x86_64")]
        le_write_u32(
            &mut pci_config.config,
            BAR_0 as usize,
            2048_u32 | BAR_IO_SPACE as u32,
        )
        .unwrap();
        le_write_u32(&mut pci_config.config, BAR_0 as usize + REG_SIZE, 2048).unwrap();
        le_write_u32(
            &mut pci_config.config,
            BAR_0 as usize + 2 * REG_SIZE,
            2048_u32 | BAR_MEM_64BIT as u32 | BAR_PREFETCH as u32,
        )
        .unwrap();
        le_write_u16(
            &mut pci_config.config,
            COMMAND as usize,
            COMMAND_IO_SPACE | COMMAND_MEMORY_SPACE,
        )
        .unwrap();

        #[cfg(target_arch = "x86_64")]
        let sys_io = AddressSpace::new(Region::init_container_region(1 << 16)).unwrap();
        let sys_mem = AddressSpace::new(Region::init_container_region(u64::max_value())).unwrap();
        assert_eq!(pci_config.bars[1].address, BAR_SPACE_UNMAPPED);
        assert_eq!(pci_config.bars[2].address, BAR_SPACE_UNMAPPED);
        pci_config
            .update_bar_mapping(
                #[cfg(target_arch = "x86_64")]
                Some(sys_io.root()),
                Some(sys_mem.root()),
            )
            .unwrap();
        assert_eq!(pci_config.bars[1].address, 2048);
        assert_eq!(pci_config.bars[2].address, 2048);

        // Bar addresses not changed.
        pci_config
            .update_bar_mapping(
                #[cfg(target_arch = "x86_64")]
                Some(sys_io.root()),
                Some(sys_mem.root()),
            )
            .unwrap();
        assert_eq!(pci_config.bars[1].address, 2048);
        assert_eq!(pci_config.bars[2].address, 2048);

        // Bar addresses are changed.
        le_write_u32(
            &mut pci_config.config,
            BAR_0 as usize,
            4096_u32 | BAR_IO_SPACE as u32,
        )
        .unwrap();
        le_write_u32(&mut pci_config.config, BAR_0 as usize + REG_SIZE, 4096).unwrap();
        le_write_u32(
            &mut pci_config.config,
            BAR_0 as usize + 2 * REG_SIZE,
            4096_u32 | BAR_MEM_64BIT as u32 | BAR_PREFETCH as u32,
        )
        .unwrap();
        pci_config
            .update_bar_mapping(
                #[cfg(target_arch = "x86_64")]
                Some(sys_io.root()),
                Some(sys_mem.root()),
            )
            .unwrap();
        assert_eq!(pci_config.bars[1].address, pci_config.get_bar_address(1));
        assert_eq!(pci_config.bars[2].address, pci_config.get_bar_address(2));
    }

    #[test]
    fn test_add_pci_cap() {
        let mut pci_config = PciConfig::new(PCI_CONFIG_SPACE_SIZE, 2);

        // Overflow.
        assert!(pci_config
            .add_pci_cap(
                0x12,
                PCI_CONFIG_SPACE_SIZE - PCI_CONFIG_HEAD_END as usize + 1
            )
            .is_err());

        // Capbility size is not multiple of DWORD.
        pci_config.add_pci_cap(0x12, 10).unwrap();
        assert_eq!(pci_config.last_cap_end, PCI_CONFIG_HEAD_END as u16 + 12);
    }

    #[test]
    fn test_add_pcie_ext_cap() {
        let mut pci_config = PciConfig::new(PCIE_CONFIG_SPACE_SIZE, 2);

        // Overflow.
        assert!(pci_config
            .add_pcie_ext_cap(
                0x12,
                PCIE_CONFIG_SPACE_SIZE - PCI_CONFIG_SPACE_SIZE as usize + 1,
                1
            )
            .is_err());

        // Capbility size is not multiple of DWORD.
        pci_config.add_pcie_ext_cap(0x12, 10, 1).unwrap();
        assert_eq!(
            pci_config.last_ext_cap_end,
            PCI_CONFIG_SPACE_SIZE as u16 + 12
        );
    }

    #[test]
    fn test_get_ext_cap_size() {
        let mut pcie_config = PciConfig::new(PCIE_CONFIG_SPACE_SIZE, 3);
        let offset1 = pcie_config.add_pcie_ext_cap(1, 0x10, 1).unwrap();
        let offset2 = pcie_config.add_pcie_ext_cap(1, 0x40, 1).unwrap();
        pcie_config.add_pcie_ext_cap(1, 0x20, 1).unwrap();

        let size1 = pcie_config.get_ext_cap_size(offset1);
        let size2 = pcie_config.get_ext_cap_size(offset2);
        assert_eq!(size1, 0x10);
        assert_eq!(size2, 0x40);
    }

    #[test]
    fn test_reset_common_regs() {
        let mut pcie_config = PciConfig::new(PCIE_CONFIG_SPACE_SIZE, 3);
        pcie_config.init_common_write_mask().unwrap();
        pcie_config.init_common_write_clear_mask().unwrap();

        le_write_u16(
            &mut pcie_config.config,
            COMMAND as usize,
            COMMAND_MEMORY_SPACE | COMMAND_FAST_BACK,
        )
        .unwrap();
        assert!(pcie_config.reset_common_regs().is_ok());

        let res = le_read_u16(&mut pcie_config.config, COMMAND as usize).unwrap();
        assert_eq!(res, COMMAND_FAST_BACK);
    }

    #[test]
    fn test_unregister_bars() {
        let read_ops = move |_data: &mut [u8], _addr: GuestAddress, _offset: u64| -> bool { true };
        let write_ops = move |_data: &[u8], _addr: GuestAddress, _offset: u64| -> bool { true };
        let region_ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };
        let region = Region::init_io_region(4096, region_ops);
        let mut pci_config = PciConfig::new(PCI_CONFIG_SPACE_SIZE, 3);

        // bar is unmapped
        #[cfg(target_arch = "x86_64")]
        assert!(pci_config
            .register_bar(0, region.clone(), RegionType::Io, false, 4096)
            .is_ok());
        assert!(pci_config
            .register_bar(1, region.clone(), RegionType::Mem32Bit, false, 4096)
            .is_ok());
        assert!(pci_config
            .register_bar(2, region.clone(), RegionType::Mem64Bit, true, 4096)
            .is_ok());

        #[cfg(target_arch = "x86_64")]
        let io_region = Region::init_container_region(1 << 16);
        let mem_region = Region::init_container_region(u64::max_value());
        let bus = Arc::new(Mutex::new(PciBus::new(
            String::from("bus"),
            #[cfg(target_arch = "x86_64")]
            io_region.clone(),
            mem_region.clone(),
        )));

        assert!(pci_config.unregister_bars(&bus).is_ok());

        // bar is mapped
        #[cfg(target_arch = "x86_64")]
        assert!(pci_config
            .register_bar(0, region.clone(), RegionType::Io, false, 4096)
            .is_ok());
        assert!(pci_config
            .register_bar(1, region.clone(), RegionType::Mem32Bit, false, 4096)
            .is_ok());
        assert!(pci_config
            .register_bar(2, region.clone(), RegionType::Mem64Bit, true, 4096)
            .is_ok());

        #[cfg(target_arch = "x86_64")]
        le_write_u32(
            &mut pci_config.config,
            BAR_0 as usize,
            2048 | BAR_IO_SPACE as u32,
        )
        .unwrap();
        le_write_u32(&mut pci_config.config, BAR_0 as usize + REG_SIZE, 2048).unwrap();
        le_write_u32(
            &mut pci_config.config,
            BAR_0 as usize + 2 * REG_SIZE,
            2048 | BAR_MEM_64BIT as u32 | BAR_PREFETCH as u32,
        )
        .unwrap();
        le_write_u16(
            &mut pci_config.config,
            COMMAND as usize,
            COMMAND_IO_SPACE | COMMAND_MEMORY_SPACE,
        )
        .unwrap();
        pci_config
            .update_bar_mapping(
                #[cfg(target_arch = "x86_64")]
                Some(&io_region),
                Some(&mem_region),
            )
            .unwrap();

        assert!(pci_config.unregister_bars(&bus).is_ok());
    }
}
