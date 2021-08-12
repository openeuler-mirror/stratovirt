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

pub mod errors {
    error_chain! {
        links {
            PciErr(pci::errors::Error, pci::errors::ErrorKind);
        }
        errors {
            UnregMemBar(id: usize) {
                display("Failed to unmap BAR {} in memory space.", id)
            }
            VfioIoctl(ioctl: String, result: i32) {
                display("Vfio ioctl failed: {}, result is: {}", ioctl, result)
            }
        }
    }
}

mod vfio_dev;
pub mod vfio_pci;

pub use vfio_dev::VfioContainer;
pub use vfio_pci::VfioPciDevice;
