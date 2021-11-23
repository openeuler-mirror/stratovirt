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

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
#[macro_use]
extern crate vmm_sys_util;
#[macro_use]
extern crate lazy_static;

pub mod errors {
    error_chain! {
        links {
            PciErr(pci::errors::Error, pci::errors::ErrorKind);
            AddressSpace(address_space::errors::Error, address_space::errors::ErrorKind);
            Hypervisor(hypervisor::errors::Error, hypervisor::errors::ErrorKind);
        }
        errors {
            AddRegBar(id: usize) {
                display("Failed to add sub region at the BAR {} in memory space.", id)
            }
            VfioIoctl(ioctl: String, error: std::io::Error) {
                display("Vfio ioctl failed: {}, error is: {:?}", ioctl, error)
            }
        }
    }
}

mod vfio_dev;
mod vfio_pci;

pub use vfio_dev::{VfioContainer, VfioDevice};
pub use vfio_pci::VfioPciDevice;

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

use hypervisor::KVM_FDS;
use kvm_bindings::{kvm_create_device, kvm_device_type_KVM_DEV_TYPE_VFIO};
use kvm_ioctls::DeviceFd;
use vfio_dev::VfioGroup;

lazy_static! {
    static ref KVM_DEVICE_FD: Option<DeviceFd> = create_kvm_vfio_device();
    static ref CONTAINERS: Mutex<HashMap<RawFd, Arc<VfioContainer>>> = Mutex::new(HashMap::new());
    static ref GROUPS: Mutex<HashMap<u32, Arc<VfioGroup>>> = Mutex::new(HashMap::new());
}

fn create_kvm_vfio_device() -> Option<DeviceFd> {
    let mut device = kvm_create_device {
        type_: kvm_device_type_KVM_DEV_TYPE_VFIO,
        fd: 0,
        flags: 0,
    };
    match KVM_FDS
        .load()
        .vm_fd
        .as_ref()
        .unwrap()
        .create_device(&mut device)
    {
        Ok(fd) => Some(fd),
        Err(e) => {
            error!("{}", e);
            None
        }
    }
}
