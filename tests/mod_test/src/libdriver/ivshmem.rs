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

use std::{cell::RefCell, rc::Rc};

use super::{
    pci::{PCIBarAddr, TestPciDev},
    pci_bus::TestPciBus,
};

pub struct TestIvshmemDev {
    pub pci_dev: TestPciDev,
    bar0_addr: PCIBarAddr,
    bar1_addr: PCIBarAddr,
    pub bar2_addr: PCIBarAddr,
}

impl TestIvshmemDev {
    pub fn new(pci_bus: Rc<RefCell<TestPciBus>>) -> Self {
        Self {
            pci_dev: TestPciDev::new(pci_bus),
            bar0_addr: 0,
            bar1_addr: 0,
            bar2_addr: 0,
        }
    }

    pub fn init(&mut self, pci_slot: u8) {
        let devfn = pci_slot << 3;
        assert!(self.pci_dev.find_pci_device(devfn));

        self.pci_dev.enable();
        self.bar0_addr = self.pci_dev.io_map(0);
        self.bar1_addr = self.pci_dev.io_map(1);
        self.bar2_addr = self.pci_dev.io_map(2);
    }

    pub fn writeb(&mut self, offset: u64, value: u8) {
        self.pci_dev.io_writeb(self.bar2_addr, offset, value);
    }

    pub fn writew(&mut self, offset: u64, value: u16) {
        self.pci_dev.io_writew(self.bar2_addr, offset, value);
    }

    pub fn writel(&mut self, offset: u64, value: u32) {
        self.pci_dev.io_writel(self.bar2_addr, offset, value);
    }

    pub fn writeq(&mut self, offset: u64, value: u64) {
        self.pci_dev.io_writeq(self.bar2_addr, offset, value);
    }

    pub fn readw(&self, offset: u64) -> u16 {
        self.pci_dev.io_readw(self.bar2_addr, offset)
    }

    pub fn readl(&self, offset: u64) -> u32 {
        self.pci_dev.io_readl(self.bar2_addr, offset)
    }

    pub fn writel_reg(&self, offset: u64, value: u32) {
        self.pci_dev.io_writel(self.bar0_addr, offset, value);
    }

    pub fn readl_reg(&self, offset: u64) -> u32 {
        self.pci_dev.io_readl(self.bar0_addr, offset)
    }
}
