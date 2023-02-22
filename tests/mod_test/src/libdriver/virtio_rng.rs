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

use super::machine::TestStdMachine;
use super::malloc::GuestAllocator;
use super::virtio_pci_modern::TestVirtioPciDev;
use crate::libtest::{test_init, TestState};

use std::cell::RefCell;
use std::rc::Rc;

pub fn create_rng(
    random_file: String,
    max_bytes: u64,
    period: u64,
) -> (
    Rc<RefCell<TestVirtioPciDev>>,
    Rc<RefCell<TestState>>,
    Rc<RefCell<GuestAllocator>>,
) {
    let pci_slot: u8 = 0x4;
    let pci_fn: u8 = 0x0;
    let mut extra_args: Vec<&str> = Vec::new();

    let mut args: Vec<&str> = "-machine virt".split(' ').collect();
    extra_args.append(&mut args);

    let rng_pci_args = format!(
        "-device {},rng=objrng0,max-bytes={},period={},bus=pcie.0,addr={}.0x0,id=rng-id",
        "virtio-rng-pci", max_bytes, period, pci_slot
    );
    args = rng_pci_args[..].split(' ').collect();
    extra_args.append(&mut args);

    let rng_args = format!("-object rng-random,id=objrng0,filename={}", random_file);
    args = rng_args.split(' ').collect();
    extra_args.append(&mut args);

    let test_state = Rc::new(RefCell::new(test_init(extra_args)));
    let machine = TestStdMachine::new(test_state.clone());
    let allocator = machine.allocator.clone();

    let rng = Rc::new(RefCell::new(TestVirtioPciDev::new(machine.pci_bus.clone())));

    rng.borrow_mut().init(pci_slot, pci_fn);

    (rng, test_state, allocator)
}
