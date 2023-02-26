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
const PCI_COMMAND: u8 = 0x04;
const PCI_COMMAND_IO: u8 = 0x1;
const PCI_COMMAND_MEMORY: u8 = 0x2;
const PCI_COMMAND_MASTER: u8 = 0x4;

pub const PCI_SUBSYSTEM_ID: u8 = 0x2e;
const PCI_CAPABILITY_LIST: u8 = 0x34;

const PCI_CAP_LIST_NEXT: u8 = 1;
pub const PCI_CAP_ID_VNDR: u8 = 0x09;
const PCI_CAP_ID_MSIX: u8 = 0x11;

const PCI_MSIX_FLAGS: u8 = 2;
const PCI_MSIX_FLAGS_QSIZE: u16 = 0x07FF;
const PCI_MSIX_TABLE: u8 = 4;
const PCI_MSIX_PBA: u8 = 8;
const PCI_MSIX_FLAGS_MASKALL: u16 = 0x4000;
const PCI_MSIX_FLAGS_ENABLE: u16 = 0x8000;
const PCI_MSIX_TABLE_BIR: u32 = 0x00000007;

const PCI_MSIX_ENTRY_SIZE: u16 = 16;
pub const PCI_MSIX_ENTRY_LOWER_ADDR: u64 = 0x0;
pub const PCI_MSIX_ENTRY_UPPER_ADDR: u64 = 0x4;
pub const PCI_MSIX_ENTRY_DATA: u64 = 0x8;
pub const PCI_MSIX_ENTRY_VECTOR_CTRL: u64 = 0xc;
pub const PCI_MSIX_ENTRY_CTRL_MASKBIT: u32 = 0x00000001;
pub type PCIBarAddr = u64;

pub trait PciMsixOps {
    fn set_msix_vector(&self, msix_entry: u16, msix_addr: u64, msix_data: u32);
}

pub struct TestPciDev {
    pub pci_bus: Rc<RefCell<TestPciBus>>,
    pub devfn: u32,
    pub msix_enabled: bool,
    pub msix_table_bar: PCIBarAddr,
    msix_pba_bar: PCIBarAddr,
    pub msix_table_off: u64,
    msix_pba_off: u64,
    pub msix_used_vectors: u32,
}

impl TestPciDev {
    pub fn new(pci_bus: Rc<RefCell<TestPciBus>>) -> Self {
        Self {
            pci_bus,
            devfn: 0,
            msix_enabled: false,
            msix_table_bar: 0,
            msix_pba_bar: 0,
            msix_table_off: 0,
            msix_pba_off: 0,
            msix_used_vectors: 0,
        }
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

    pub fn enable_msix(&mut self) {
        let addr = self.find_capability(PCI_CAP_ID_MSIX, 0);
        assert!(addr != 0);
        let value = self.config_readw(addr + PCI_MSIX_FLAGS);
        self.config_writew(addr + PCI_MSIX_FLAGS, value | PCI_MSIX_FLAGS_ENABLE);

        let table = self.config_readl(addr + PCI_MSIX_TABLE);
        let bar_table = table & PCI_MSIX_TABLE_BIR;
        self.msix_table_bar = self.io_map(bar_table.try_into().unwrap());
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
        let value = self.config_readw(addr + PCI_MSIX_FLAGS);
        self.config_writew(addr + PCI_MSIX_FLAGS, value & !PCI_MSIX_FLAGS_ENABLE);

        self.msix_enabled = false;
        self.msix_table_off = 0;
        self.msix_pba_off = 0;
    }

    pub fn msix_is_pending(&self, entry: u16) -> bool {
        assert!(self.msix_enabled);
        let bit = entry % 32;
        let offset = (entry / 32) * 4;

        let pba_entry = self.io_readl(self.msix_pba_bar, self.msix_pba_off + offset as u64);
        self.io_writel(
            self.msix_pba_bar,
            self.msix_pba_off + offset as u64,
            pba_entry & !(1 << bit),
        );
        (pba_entry & (1 << bit)) != 0
    }

    pub fn msix_is_masked(&self, entry: u16) -> bool {
        assert!(self.msix_enabled);
        let offset: u64 = self.msix_table_off + (entry * PCI_MSIX_ENTRY_SIZE) as u64;

        let addr = self.find_capability(PCI_CAP_ID_MSIX, 0);
        assert!(addr != 0);
        let value = self.config_readw(addr + PCI_MSIX_FLAGS);

        if (value & PCI_MSIX_FLAGS_MASKALL) != 0 {
            true
        } else {
            self.io_readl(
                self.msix_table_bar,
                offset + PCI_MSIX_ENTRY_VECTOR_CTRL as u64,
            ) != 0
        }
    }

    pub fn get_msix_table_size(&self) -> u16 {
        let addr = self.find_capability(PCI_CAP_ID_MSIX, 0);
        assert!(addr != 0);

        let value = self.config_readw(addr + PCI_MSIX_FLAGS);
        (value & PCI_MSIX_FLAGS_QSIZE) + 1
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
        pci_bus.memwrite((bar_addr + offset) as u32, &value_buf, value_buf.len());
    }

    pub fn io_writew(&self, bar_addr: PCIBarAddr, offset: u64, value: u16) {
        let value_buf = value.to_le_bytes().to_vec();
        let pci_bus = self.pci_bus.borrow_mut();
        pci_bus.memwrite((bar_addr + offset) as u32, &value_buf, value_buf.len());
    }

    pub fn io_writel(&self, bar_addr: PCIBarAddr, offset: u64, value: u32) {
        let value_buf = value.to_le_bytes().to_vec();
        let pci_bus = self.pci_bus.borrow_mut();
        pci_bus.memwrite((bar_addr + offset) as u32, &value_buf, value_buf.len());
    }

    #[allow(unused)]
    pub fn io_writeq(&self, bar_addr: PCIBarAddr, offset: u64, value: u64) {
        let value_buf = value.to_le_bytes().to_vec();
        let pci_bus = self.pci_bus.borrow_mut();
        pci_bus.memwrite((bar_addr + offset) as u32, &value_buf, value_buf.len());
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

        size = 1 << addr.trailing_zeros();
        location = (self.pci_bus.borrow().mmio_alloc_ptr + size - 1) / size * size;
        assert!(location >= self.pci_bus.borrow().mmio_alloc_ptr);
        assert!(location + size <= self.pci_bus.borrow().mmio_limit);
        self.pci_bus.borrow_mut().mmio_alloc_ptr = location + size;
        self.config_writel(bar_offset, location as u32);
        bar_addr = location;
        bar_addr
    }

    pub fn config_readb(&self, offset: u8) -> u8 {
        self.pci_bus.borrow().config_readb(self.devfn, offset)
    }

    pub fn config_readw(&self, offset: u8) -> u16 {
        self.pci_bus.borrow().config_readw(self.devfn, offset)
    }

    pub fn config_readl(&self, offset: u8) -> u32 {
        self.pci_bus.borrow().config_readl(self.devfn, offset)
    }

    #[allow(unused)]
    pub fn config_writeb(&self, offset: u8, value: u8) {
        self.pci_bus
            .borrow()
            .config_writeb(self.devfn, offset, value);
    }

    pub fn config_writew(&self, offset: u8, value: u16) {
        self.pci_bus
            .borrow()
            .config_writew(self.devfn, offset, value);
    }

    pub fn config_writel(&self, offset: u8, value: u32) {
        self.pci_bus
            .borrow()
            .config_writel(self.devfn, offset, value);
    }
}

impl PciMsixOps for TestPciDev {
    fn set_msix_vector(&self, msix_entry: u16, msix_addr: u64, msix_data: u32) {
        assert!(self.msix_enabled);
        assert!(msix_entry <= self.get_msix_table_size());
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
