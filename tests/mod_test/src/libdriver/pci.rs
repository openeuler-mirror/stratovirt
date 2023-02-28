// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use super::pci_bus::PciBusOps;
use super::pci_bus::TestPciBus;
use std::cell::RefCell;
use std::rc::Rc;

const BAR_MAP: [u8; 6] = [0x10, 0x14, 0x18, 0x1c, 0x20, 0x24];
pub const PCI_VENDOR_ID: u8 = 0x00;
pub const PCI_DEVICE_ID: u8 = 0x02;
pub const PCI_COMMAND: u8 = 0x04;

const PCI_COMMAND_IO: u8 = 0x1;
pub const PCI_COMMAND_MEMORY: u8 = 0x2;
const PCI_COMMAND_MASTER: u8 = 0x4;

pub const PCI_STATUS: u8 = 0x06;
pub const PCI_STATUS_INTERRUPT: u16 = 0x08;
pub const PCI_STATUS_CAP_LIST: u16 = 0x10;
pub const PCI_REVISION_ID: u8 = 0x08;
pub const PCI_SUB_CLASS_DEVICE: u8 = 0x0a;
pub const PCI_HEADER_TYPE: u8 = 0x0e;
pub const PCI_PRIMARY_BUS: u8 = 0x18;
pub const PCI_SECONDARY_BUS: u8 = 0x19;
pub const PCI_SUBORDINATE_BUS: u8 = 0x1a;
pub const PCI_SUBSYSTEM_VENDOR_ID: u8 = 0x2c;
pub const PCI_SUBSYSTEM_ID: u8 = 0x2e;

pub const PCI_CAPABILITY_LIST: u8 = 0x34;
pub const PCI_BRIDGE_CONTROL: u8 = 0x3e;
pub const BRIDGE_CTL_SEC_BUS_RESET: u8 = 0x40;

pub const PCI_CAP_LIST_NEXT: u8 = 1;
pub const PCI_CAP_ID_VNDR: u8 = 0x09;
pub const PCI_CAP_ID_EXP: u8 = 0x10;
pub const PCI_CAP_ID_MSIX: u8 = 0x11;

pub const PCI_MSIX_MSG_CTL: u8 = 2;
pub const PCI_MSIX_MSG_CTL_TSIZE: u16 = 0x07FF;
pub const PCI_MSIX_MSG_CTL_MASKALL: u16 = 0x4000;
pub const PCI_MSIX_MSG_CTL_ENABLE: u16 = 0x8000;
pub const PCI_MSIX_TABLE: u8 = 4;
pub const PCI_MSIX_TABLE_BIR: u32 = 0x00000007;
pub const PCI_MSIX_PBA: u8 = 8;
pub const PCI_MSIX_PBA_BIR: u32 = 0x00000007;

pub const PCI_MSIX_ENTRY_SIZE: u16 = 16;
pub const PCI_MSIX_ENTRY_LOWER_ADDR: u64 = 0x0;
pub const PCI_MSIX_ENTRY_UPPER_ADDR: u64 = 0x4;
pub const PCI_MSIX_ENTRY_DATA: u64 = 0x8;
pub const PCI_MSIX_ENTRY_VECTOR_CTRL: u64 = 0xc;
pub const PCI_MSIX_ENTRY_CTRL_MASKBIT: u32 = 0x00000001;

pub const PCI_EXP_LNKSTA: u8 = 0x12;
pub const PCI_EXP_LNKSTA_CLS: u16 = 0x000f;
pub const PCI_EXP_LNKSTA_NLW: u16 = 0x03f0;
pub const PCI_EXP_LNKSTA_DLLLA: u16 = 0x2000;

pub const PCI_EXP_SLTSTA: u8 = 0x1a;
pub const PCI_EXP_SLTSTA_ABP: u16 = 0x0001;
pub const PCI_EXP_SLTSTA_PDC: u16 = 0x0008;
pub const PCI_EXP_SLTSTA_CC: u16 = 0x0010;
pub const PCI_EXP_SLTSTA_PDS: u16 = 0x0040;

pub const PCI_EXP_SLTCTL: u8 = 0x18;
pub const PCI_EXP_SLTCTL_PIC: u16 = 0x0300;
pub const PCI_EXP_SLTCTL_PWR_IND_ON: u16 = 0x0100;
pub const PCI_EXP_SLTCTL_PWR_IND_BLINK: u16 = 0x0200;
pub const PCI_EXP_SLTCTL_PWR_IND_OFF: u16 = 0x0300;
pub const PCI_EXP_SLTCTL_PCC: u16 = 0x0400;
pub const PCI_EXP_SLTCTL_PWR_ON: u16 = 0x0000;
pub const PCI_EXP_SLTCTL_PWR_OFF: u16 = 0x0400;
pub type PCIBarAddr = u64;
pub const INVALID_BAR_ADDR: u64 = u64::MAX;

pub trait PciMsixOps {
    fn set_msix_vector(&self, msix_entry: u16, msix_addr: u64, msix_data: u32);
}

#[derive(Clone)]
pub struct TestPciDev {
    pub pci_bus: Rc<RefCell<TestPciBus>>,
    pub bus_num: u8,
    pub devfn: u8,
    pub msix_enabled: bool,
    pub msix_table_bar: PCIBarAddr,
    pub msix_pba_bar: PCIBarAddr,
    pub msix_table_off: u64,
    pub msix_pba_off: u64,
    pub msix_used_vectors: u32,
}

impl TestPciDev {
    pub fn new(pci_bus: Rc<RefCell<TestPciBus>>) -> Self {
        Self {
            pci_bus,
            bus_num: 0,
            devfn: 0,
            msix_enabled: false,
            msix_table_bar: 0,
            msix_pba_bar: 0,
            msix_table_off: 0,
            msix_pba_off: 0,
            msix_used_vectors: 0,
        }
    }

    pub fn set_bus_num(&mut self, bus_num: u8) {
        self.bus_num = bus_num;
    }

    pub fn enable(&self) {
        let mut cmd = self.config_readw(PCI_COMMAND);
        cmd |= (PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER) as u16;
        self.config_writew(PCI_COMMAND, cmd);

        cmd = self.config_readw(PCI_COMMAND);
        assert!(cmd & PCI_COMMAND_IO as u16 == PCI_COMMAND_IO as u16);
        assert!(cmd & PCI_COMMAND_MEMORY as u16 == PCI_COMMAND_MEMORY as u16);
        assert!(cmd & PCI_COMMAND_MASTER as u16 == PCI_COMMAND_MASTER as u16);
    }

    pub fn find_capability(&self, id: u8, start_addr: u8) -> u8 {
        let mut addr = if start_addr != 0 {
            self.config_readb(start_addr + PCI_CAP_LIST_NEXT)
        } else {
            self.config_readb(start_addr + PCI_CAPABILITY_LIST)
        };

        loop {
            let cap = self.config_readb(addr);
            if cap != id {
                addr = self.config_readb(addr + PCI_CAP_LIST_NEXT);
            }
            if cap == id || addr == 0 {
                break;
            }
        }
        addr
    }

    /// Enable MSI-X.
    ///
    /// # Arguments
    ///
    /// `bar_addr` - Address of the bar where the MSI-X is located. Address allocated by Default.
    pub fn enable_msix(&mut self, bar_addr: Option<u64>) {
        let addr = self.find_capability(PCI_CAP_ID_MSIX, 0);
        assert!(addr != 0);
        let value = self.config_readw(addr + PCI_MSIX_MSG_CTL);
        self.config_writew(addr + PCI_MSIX_MSG_CTL, value | PCI_MSIX_MSG_CTL_ENABLE);

        let table = self.config_readl(addr + PCI_MSIX_TABLE);
        let bar_table = table & PCI_MSIX_TABLE_BIR;
        self.msix_table_bar = if let Some(addr) = bar_addr {
            addr
        } else {
            self.io_map(bar_table.try_into().unwrap())
        };
        self.msix_table_off = (table & !PCI_MSIX_TABLE_BIR).try_into().unwrap();

        let table = self.config_readl(addr + PCI_MSIX_PBA);
        let bar_pba = table & PCI_MSIX_TABLE_BIR;
        if bar_pba != bar_table {
            self.msix_pba_bar = self.io_map(bar_pba.try_into().unwrap());
        } else {
            self.msix_pba_bar = self.msix_table_bar;
        }
        self.msix_pba_off = (table & !PCI_MSIX_TABLE_BIR).try_into().unwrap();
        self.msix_enabled = true;
    }

    pub fn disable_msix(&mut self) {
        let addr = self.find_capability(PCI_CAP_ID_MSIX, 0);
        assert!(addr != 0);
        let value = self.config_readw(addr + PCI_MSIX_MSG_CTL);
        self.config_writew(addr + PCI_MSIX_MSG_CTL, value & !PCI_MSIX_MSG_CTL_ENABLE);

        self.msix_enabled = false;
        self.msix_table_off = 0;
        self.msix_pba_off = 0;
    }

    pub fn has_msix(&self, msix_addr: u64, msix_data: u32) -> bool {
        self.pci_bus
            .borrow()
            .test_state
            .borrow()
            .query_msix(msix_addr, msix_data)
    }

    pub fn get_msix_table_size(&self) -> u16 {
        let addr = self.find_capability(PCI_CAP_ID_MSIX, 0);
        assert!(addr != 0);

        let value = self.config_readw(addr + PCI_MSIX_MSG_CTL);
        (value & PCI_MSIX_MSG_CTL_TSIZE) + 1
    }

    pub fn io_readb(&self, bar_addr: PCIBarAddr, offset: u64) -> u8 {
        let pci_bus = self.pci_bus.borrow_mut();
        let value_bytes = pci_bus.memread((bar_addr + offset) as u32, 1);
        assert!(!value_bytes.is_empty());
        u8::from_le_bytes(value_bytes[0..1].try_into().unwrap())
    }

    pub fn io_readw(&self, bar_addr: PCIBarAddr, offset: u64) -> u16 {
        let pci_bus = self.pci_bus.borrow_mut();
        let value_bytes = pci_bus.memread((bar_addr + offset) as u32, 2);
        assert!(value_bytes.len() >= 2);
        u16::from_le_bytes(value_bytes[0..2].try_into().unwrap())
    }

    pub fn io_readl(&self, bar_addr: PCIBarAddr, offset: u64) -> u32 {
        let pci_bus = self.pci_bus.borrow_mut();
        let value_bytes = pci_bus.memread((bar_addr + offset) as u32, 4);
        assert!(value_bytes.len() >= 4);
        u32::from_le_bytes(value_bytes[0..4].try_into().unwrap())
    }

    pub fn io_readq(&self, bar_addr: PCIBarAddr, offset: u64) -> u64 {
        let pci_bus = self.pci_bus.borrow_mut();
        let value_bytes = pci_bus.memread((bar_addr + offset) as u32, 8);
        assert!(value_bytes.len() >= 8);
        u64::from_le_bytes(value_bytes[0..8].try_into().unwrap())
    }

    pub fn io_writeb(&self, bar_addr: PCIBarAddr, offset: u64, value: u8) {
        let value_buf = value.to_le_bytes().to_vec();
        let pci_bus = self.pci_bus.borrow_mut();
        pci_bus.memwrite((bar_addr + offset) as u32, &value_buf);
    }

    pub fn io_writew(&self, bar_addr: PCIBarAddr, offset: u64, value: u16) {
        let value_buf = value.to_le_bytes().to_vec();
        let pci_bus = self.pci_bus.borrow_mut();
        pci_bus.memwrite((bar_addr + offset) as u32, &value_buf);
    }

    pub fn io_writel(&self, bar_addr: PCIBarAddr, offset: u64, value: u32) {
        let value_buf = value.to_le_bytes().to_vec();
        let pci_bus = self.pci_bus.borrow_mut();
        pci_bus.memwrite((bar_addr + offset) as u32, &value_buf);
    }

    #[allow(unused)]
    pub fn io_writeq(&self, bar_addr: PCIBarAddr, offset: u64, value: u64) {
        let value_buf = value.to_le_bytes().to_vec();
        let pci_bus = self.pci_bus.borrow_mut();
        pci_bus.memwrite((bar_addr + offset) as u32, &value_buf);
    }

    pub fn io_map(&self, barnum: u8) -> u64 {
        let addr: u32;
        let size: u64;
        let location: u64;
        let bar_addr: PCIBarAddr;

        assert!(barnum <= 5);
        let bar_offset: u8 = BAR_MAP[barnum as usize];

        self.config_writel(bar_offset, 0xFFFFFFFF);
        addr = self.config_readl(bar_offset) & !(0x0F_u32);
        assert!(addr != 0);

        let mut pci_bus = self.pci_bus.borrow_mut();
        size = 1 << addr.trailing_zeros();
        location = (pci_bus.mmio_alloc_ptr + size - 1) / size * size;
        if location < pci_bus.mmio_alloc_ptr || location + size > pci_bus.mmio_limit {
            return INVALID_BAR_ADDR;
        }

        pci_bus.mmio_alloc_ptr = location + size;
        drop(pci_bus);
        self.config_writel(bar_offset, location as u32);
        bar_addr = location;
        bar_addr
    }

    pub fn config_readb(&self, offset: u8) -> u8 {
        self.pci_bus
            .borrow()
            .config_readb(self.bus_num, self.devfn, offset)
    }

    pub fn config_readw(&self, offset: u8) -> u16 {
        self.pci_bus
            .borrow()
            .config_readw(self.bus_num, self.devfn, offset)
    }

    pub fn config_readl(&self, offset: u8) -> u32 {
        self.pci_bus
            .borrow()
            .config_readl(self.bus_num, self.devfn, offset)
    }

    pub fn config_readq(&self, offset: u8) -> u64 {
        self.pci_bus
            .borrow()
            .config_readq(self.bus_num, self.devfn, offset)
    }

    #[allow(unused)]
    pub fn config_writeb(&self, offset: u8, value: u8) {
        self.pci_bus
            .borrow()
            .config_writeb(self.bus_num, self.devfn, offset, value);
    }

    pub fn config_writew(&self, offset: u8, value: u16) {
        self.pci_bus
            .borrow()
            .config_writew(self.bus_num, self.devfn, offset, value);
    }

    pub fn config_writel(&self, offset: u8, value: u32) {
        self.pci_bus
            .borrow()
            .config_writel(self.bus_num, self.devfn, offset, value);
    }

    pub fn config_writeq(&self, offset: u8, value: u64) {
        self.pci_bus
            .borrow()
            .config_writeq(self.bus_num, self.devfn, offset, value);
    }
}

impl PciMsixOps for TestPciDev {
    fn set_msix_vector(&self, msix_entry: u16, msix_addr: u64, msix_data: u32) {
        assert!(self.msix_enabled);
        let offset = self.msix_table_off + (msix_entry * 16) as u64;

        let msix_table_bar = self.msix_table_bar;
        self.io_writel(
            msix_table_bar,
            offset + PCI_MSIX_ENTRY_LOWER_ADDR,
            msix_addr.try_into().unwrap(),
        );
        self.io_writel(
            msix_table_bar,
            offset + PCI_MSIX_ENTRY_UPPER_ADDR,
            (msix_addr >> 32).try_into().unwrap(),
        );
        self.io_writel(msix_table_bar, offset + PCI_MSIX_ENTRY_DATA, msix_data);

        let ctl = self.io_readl(msix_table_bar, offset + PCI_MSIX_ENTRY_VECTOR_CTRL);
        self.io_writel(
            msix_table_bar,
            offset + PCI_MSIX_ENTRY_VECTOR_CTRL,
            ctl & !PCI_MSIX_ENTRY_CTRL_MASKBIT,
        );
    }
}
