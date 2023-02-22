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

use super::malloc::GuestAllocator;
use super::pci_bus::TestPciBus;
use crate::libtest::TestState;
use std::cell::RefCell;
use std::rc::Rc;

const ARM_VIRT_RAM_ADDR: u64 = 0x40000000;
const ARM_VIRT_RAM_SIZE: u64 = 0x20000000;
const ARM_PAGE_SIZE: u64 = 4096;

pub struct TestStdMachine {
    pub pci_bus: Rc<RefCell<TestPciBus>>,
    pub allocator: Rc<RefCell<GuestAllocator>>,
}

impl TestStdMachine {
    pub fn new(test_state: Rc<RefCell<TestState>>) -> Self {
        Self {
            pci_bus: Rc::new(RefCell::new(TestPciBus::new(test_state))),
            allocator: Rc::new(RefCell::new(GuestAllocator::new(
                ARM_VIRT_RAM_ADDR,
                ARM_VIRT_RAM_SIZE,
                ARM_PAGE_SIZE,
            ))),
        }
    }

    pub fn new_bymem(test_state: Rc<RefCell<TestState>>, memsize: u64, page_size: u64) -> Self {
        Self {
            pci_bus: Rc::new(RefCell::new(TestPciBus::new(test_state))),
            allocator: Rc::new(RefCell::new(GuestAllocator::new(
                ARM_VIRT_RAM_ADDR,
                memsize,
                page_size,
            ))),
        }
    }
}
