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

use crate::libtest::TestState;
use crate::utils::{read_le_u16, read_le_u32};
use std::cell::RefCell;
use std::rc::Rc;

const PCIE_MMIO_BASE: u64 = 0x1000_0000;
const PCIE_MMIO_SIZE: u64 = 0x2EFF_0000;
const PCIE_ECAM_BASE: u64 = 511 << 30;

pub trait PciBusOps {
    fn memread(&self, addr: u32, len: usize) -> Vec<u8>;
    fn memwrite(&self, addr: u32, buf: &[u8], len: usize);

    fn config_readb(&self, devfn: u32, offset: u8) -> u8;
    fn config_readw(&self, devfn: u32, offset: u8) -> u16;
    fn config_readl(&self, devfn: u32, offset: u8) -> u32;

    fn config_writeb(&self, devfn: u32, offset: u8, value: u8);
    fn config_writew(&self, devfn: u32, offset: u8, value: u16);
    fn config_writel(&self, devfn: u32, offset: u8, value: u32);
}

#[allow(unused)]
pub struct TestPciBus {
    pub mmio_alloc_ptr: u64,
    pub mmio_limit: u64,
    ecam_alloc_ptr: u64,
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

    fn get_addr(&self, devfn: u32, offset: u8) -> u64 {
        self.ecam_alloc_ptr + (devfn << 12 | offset as u32) as u64
    }
}

impl PciBusOps for TestPciBus {
    fn memread(&self, addr: u32, len: usize) -> Vec<u8> {
        self.test_state.borrow().memread(addr as u64, len as u64)
    }

    fn memwrite(&self, addr: u32, buf: &[u8], len: usize) {
        self.test_state
            .borrow()
            .memwrite(addr as u64, buf, len as u64);
    }

    fn config_readb(&self, devfn: u32, offset: u8) -> u8 {
        let addr = self.get_addr(devfn, offset);
        self.test_state.borrow().memread(addr, 1)[0]
    }

    fn config_readw(&self, devfn: u32, offset: u8) -> u16 {
        let addr = self.get_addr(devfn, offset);
        let mut buf: &[u8] = &self.test_state.borrow().memread(addr, 2)[0..2];
        read_le_u16(&mut buf)
    }

    fn config_readl(&self, devfn: u32, offset: u8) -> u32 {
        let addr = self.get_addr(devfn, offset);
        let mut buf: &[u8] = &self.test_state.borrow().memread(addr, 4)[0..4];
        read_le_u32(&mut buf)
    }

    fn config_writeb(&self, devfn: u32, offset: u8, value: u8) {
        let addr = self.get_addr(devfn, offset);
        let buf = value.to_le_bytes();
        self.test_state.borrow().memwrite(addr, &buf, 1);
    }

    fn config_writew(&self, devfn: u32, offset: u8, value: u16) {
        let addr = self.get_addr(devfn, offset);
        let buf = value.to_le_bytes();
        self.test_state.borrow().memwrite(addr, &buf, 2);
    }

    fn config_writel(&self, devfn: u32, offset: u8, value: u32) {
        let addr = self.get_addr(devfn, offset);
        let buf = value.to_le_bytes();
        self.test_state.borrow().memwrite(addr, &buf, 4);
    }
}
