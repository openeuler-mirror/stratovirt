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

use crate::libdriver::pci::*;
use crate::libtest::TestState;
use crate::utils::{read_le_u16, read_le_u32, read_le_u64};
use machine::standard_vm::aarch64::{LayoutEntryType, MEM_LAYOUT};
use std::cell::RefCell;
use std::rc::Rc;

const PCIE_MMIO_BASE: u64 = MEM_LAYOUT[LayoutEntryType::PcieMmio as usize].0;
const PCIE_MMIO_SIZE: u64 = MEM_LAYOUT[LayoutEntryType::PcieMmio as usize].1;
const PCIE_ECAM_BASE: u64 = MEM_LAYOUT[LayoutEntryType::HighPcieEcam as usize].0;

pub trait PciBusOps {
    fn memread(&self, addr: u32, len: usize) -> Vec<u8>;
    fn memwrite(&self, addr: u32, buf: &[u8]);

    fn config_readb(&self, bus_num: u8, devfn: u8, offset: u8) -> u8;
    fn config_readw(&self, bus_num: u8, devfn: u8, offset: u8) -> u16;
    fn config_readl(&self, bus_num: u8, devfn: u8, offset: u8) -> u32;
    fn config_readq(&self, bus_num: u8, devfn: u8, offset: u8) -> u64;

    fn config_writeb(&self, bus_num: u8, devfn: u8, offset: u8, value: u8);
    fn config_writew(&self, bus_num: u8, devfn: u8, offset: u8, value: u16);
    fn config_writel(&self, bus_num: u8, devfn: u8, offset: u8, value: u32);
    fn config_writeq(&self, bus_num: u8, devfn: u8, offset: u8, value: u64);
}

#[allow(unused)]
pub struct TestPciBus {
    pub mmio_alloc_ptr: u64,
    pub mmio_limit: u64,
    pub ecam_alloc_ptr: u64,
    not_hotpluggable: bool,
    pub test_state: Rc<RefCell<TestState>>,
}

impl TestPciBus {
    pub fn new(test_state: Rc<RefCell<TestState>>) -> Self {
        Self {
            mmio_alloc_ptr: PCIE_MMIO_BASE,
            mmio_limit: PCIE_MMIO_SIZE,
            ecam_alloc_ptr: PCIE_ECAM_BASE,
            not_hotpluggable: false,
            test_state,
        }
    }

    fn get_addr(&self, bus_num: u8, devfn: u8, offset: u8) -> u64 {
        self.ecam_alloc_ptr + ((bus_num as u32) << 20 | (devfn as u32) << 12 | offset as u32) as u64
    }

    pub fn pci_auto_bus_scan(&self, root_port_num: u8) {
        let current_bus = 0;
        let mut sub_bus = 0;

        for addr in 0..=root_port_num {
            let devfn = addr << 3;
            if current_bus == 0 && devfn == 0 {
                continue;
            }

            if devfn & 0x7 != 0 {
                continue;
            }

            if self.config_readb(current_bus, devfn, PCI_HEADER_TYPE) == 0 {
                continue;
            }

            let vendor_id = self.config_readw(current_bus, devfn, PCI_VENDOR_ID);
            if vendor_id == 0xffff || vendor_id == 0x0000 {
                continue;
            }

            if self.config_readw(current_bus, devfn, PCI_SUB_CLASS_DEVICE) == 0x0604 {
                self.pciauto_scan_setup_bridge(current_bus, devfn, sub_bus);
                sub_bus += 1
            }
        }
    }

    fn pciauto_scan_setup_bridge(&self, current_bus: u8, devfn: u8, sub_bus: u8) {
        self.config_writeb(current_bus, devfn, PCI_PRIMARY_BUS, 0);
        self.config_writeb(current_bus, devfn, PCI_SECONDARY_BUS, sub_bus + 1);
        self.config_writeb(current_bus, devfn, PCI_SUBORDINATE_BUS, sub_bus + 1);
    }
}

impl PciBusOps for TestPciBus {
    fn memread(&self, addr: u32, len: usize) -> Vec<u8> {
        self.test_state.borrow().memread(addr as u64, len as u64)
    }

    fn memwrite(&self, addr: u32, buf: &[u8]) {
        self.test_state.borrow().memwrite(addr as u64, buf);
    }

    fn config_readb(&self, bus_num: u8, devfn: u8, offset: u8) -> u8 {
        let addr = self.get_addr(bus_num, devfn, offset);
        self.test_state.borrow().memread(addr, 1)[0]
    }

    fn config_readw(&self, bus_num: u8, devfn: u8, offset: u8) -> u16 {
        let addr = self.get_addr(bus_num, devfn, offset);
        let mut buf: &[u8] = &self.test_state.borrow().memread(addr, 2)[0..2];
        read_le_u16(&mut buf)
    }

    fn config_readl(&self, bus_num: u8, devfn: u8, offset: u8) -> u32 {
        let addr = self.get_addr(bus_num, devfn, offset);
        let mut buf: &[u8] = &self.test_state.borrow().memread(addr, 4)[0..4];
        read_le_u32(&mut buf)
    }

    fn config_readq(&self, bus_num: u8, devfn: u8, offset: u8) -> u64 {
        let addr = self.get_addr(bus_num, devfn, offset);
        let mut buf: &[u8] = &self.test_state.borrow().memread(addr, 8)[0..8];
        read_le_u64(&mut buf)
    }

    fn config_writeb(&self, bus_num: u8, devfn: u8, offset: u8, value: u8) {
        let addr = self.get_addr(bus_num, devfn, offset);
        let buf = value.to_le_bytes();
        self.test_state.borrow().memwrite(addr, &buf);
    }

    fn config_writew(&self, bus_num: u8, devfn: u8, offset: u8, value: u16) {
        let addr = self.get_addr(bus_num, devfn, offset);
        let buf = value.to_le_bytes();
        self.test_state.borrow().memwrite(addr, &buf);
    }

    fn config_writel(&self, bus_num: u8, devfn: u8, offset: u8, value: u32) {
        let addr = self.get_addr(bus_num, devfn, offset);
        let buf = value.to_le_bytes();
        self.test_state.borrow().memwrite(addr, &buf);
    }

    fn config_writeq(&self, bus_num: u8, devfn: u8, offset: u8, value: u64) {
        let addr = self.get_addr(bus_num, devfn, offset);
        let buf = value.to_le_bytes();
        self.test_state.borrow().memwrite(addr, &buf);
    }
}
