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
use super::virtio::{
    TestVirtQueue, VirtioDeviceOps, VIRTIO_F_BAD_FEATURE, VIRTIO_RING_F_EVENT_IDX,
    VIRTIO_RING_F_INDIRECT_DESC,
};
use super::virtio_pci_modern::TestVirtioPciDev;
use crate::libtest::{test_init, TestState};
use std::cell::RefCell;
use std::rc::Rc;

const VIRTIO_NET_F_MQ: u64 = 22;

#[allow(unused)]
pub fn virtio_net_setup(
    net: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
) -> Vec<Rc<RefCell<TestVirtQueue>>> {
    let mut queue_num: u16;
    let mut features = net.borrow().get_device_features();
    features &=
        !(VIRTIO_F_BAD_FEATURE | 1 << VIRTIO_RING_F_INDIRECT_DESC | 1 << VIRTIO_RING_F_EVENT_IDX);
    net.borrow_mut().negotiate_features(features);
    net.borrow_mut().set_features_ok();

    if features & (1 << VIRTIO_NET_F_MQ) != 0 {
        queue_num = net.borrow().config_readw(8) * 2;
    } else {
        queue_num = 2;
    }
    queue_num += 1;

    let queues = net.borrow_mut().init_virtqueue(test_state, alloc, 1);
    net.borrow().set_driver_ok();
    queues
}

#[allow(unused)]
pub fn create_net() -> (
    Rc<RefCell<TestVirtioPciDev>>,
    Rc<RefCell<TestState>>,
    Rc<RefCell<GuestAllocator>>,
    Vec<Rc<RefCell<TestVirtQueue>>>,
) {
    let pci_slot: u8 = 0x4;
    let pci_fn: u8 = 0x0;
    let mut extra_args: Vec<&str> = Vec::new();

    let mut args: Vec<&str> = "-machine virt".split(' ').collect();
    extra_args.append(&mut args);

    let blk_pci_args = format!(
        "-device {},id=net0,netdev=netdev0,bus=pcie.0,addr={}.0,mq=on",
        "virtio-net-pci", pci_slot
    );
    args = blk_pci_args[..].split(' ').collect();
    extra_args.append(&mut args);
    let blk_args = String::from("-netdev tap,id=netdev0,ifname=tap_mq,queues=4");
    args = blk_args.split(' ').collect();
    extra_args.append(&mut args);
    println!("start args is {:?}", extra_args);
    let test_state = Rc::new(RefCell::new(test_init(extra_args)));
    let machine = TestStdMachine::new(test_state.clone());
    let allocator = machine.allocator.clone();

    let virtio_net = Rc::new(RefCell::new(TestVirtioPciDev::new(machine.pci_bus)));

    virtio_net.borrow_mut().init(pci_slot, pci_fn);
    let virtio_net_queues =
        virtio_net_setup(virtio_net.clone(), test_state.clone(), allocator.clone());

    (virtio_net, test_state, allocator, virtio_net_queues)
}
