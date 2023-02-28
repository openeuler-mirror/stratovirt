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

pub enum ChardevType {
    Stdio,
    Pty,
    Socket {
        path: String,
        server: bool,
        nowait: bool,
    },
    File {
        path: String,
    },
}

pub fn create_console(
    chardev_type: ChardevType,
    pci_slot: u8,
    pci_fn: u8,
) -> (
    Rc<RefCell<TestVirtioPciDev>>,
    Rc<RefCell<TestState>>,
    Rc<RefCell<GuestAllocator>>,
) {
    let mut extra_args: Vec<&str> = Vec::new();

    let mut args: Vec<&str> = "-machine virt".split(' ').collect();
    extra_args.append(&mut args);

    let serial_pci_args = format!(
        "-device {},id=serial0,bus=pcie.0,addr={}.0",
        "virtio-serial-pci", pci_slot
    );
    extra_args.append(&mut serial_pci_args[..].split(' ').collect());

    let chardev_args = match chardev_type {
        ChardevType::Stdio => String::from("-chardev stdio,id=charconsole0"),
        ChardevType::Pty => String::from("-chardev pty,id=charconsole0"),
        ChardevType::Socket {
            path,
            server,
            nowait,
        } => {
            let mut args = format!("-chardev socket,id=charconsole0,path={}", path);
            if server {
                args.push_str(",server")
            }
            if nowait {
                args.push_str(",nowait")
            }
            args
        }
        ChardevType::File { path } => {
            let args = format!("-chardev file,id=charconsole0,path={}", path);
            args
        }
    };
    extra_args.append(&mut chardev_args.split(' ').collect());

    let console_args = String::from("-device virtconsole,chardev=charconsole0,id=console0");
    extra_args.append(&mut console_args.split(' ').collect());

    let test_state = Rc::new(RefCell::new(test_init(extra_args)));
    let machine = TestStdMachine::new(test_state.clone());
    let allocator = machine.allocator.clone();

    let virtio_console = Rc::new(RefCell::new(TestVirtioPciDev::new(machine.pci_bus)));

    virtio_console.borrow_mut().init(pci_slot, pci_fn);

    (virtio_console, test_state, allocator)
}
