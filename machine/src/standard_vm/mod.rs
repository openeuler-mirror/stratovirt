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

pub mod errors {
    error_chain! {
        links {
            AddressSpace(address_space::errors::Error, address_space::errors::ErrorKind);
            Cpu(cpu::errors::Error, cpu::errors::ErrorKind);
            Legacy(devices::LegacyErrs::Error, devices::LegacyErrs::ErrorKind);
            PciErr(pci::errors::Error, pci::errors::ErrorKind);
        }
        foreign_links{
            Io(std::io::Error);
        }
        errors {
            InitPCIeHostErr {
                display("Failed to init PCIe host.")
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod x86_64;

use std::sync::{Arc, Mutex};

use devices::legacy::FwCfgOps;
use errors::Result;
use kvm_ioctls::VmFd;
use machine_manager::config::PFlashConfig;

#[allow(dead_code)]
#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::StdMachine;

trait StdMachineOps {
    fn init_pci_host(&self, vm_fd: &Arc<VmFd>) -> Result<()>;

    fn add_fwcfg_device(&mut self, _vm_fd: &VmFd) -> Result<Arc<Mutex<dyn FwCfgOps>>> {
        bail!("Not implemented");
    }

    fn add_pflash_device(&mut self, _config: &PFlashConfig, _vm_fd: &VmFd) -> Result<()> {
        Ok(())
    }
}
