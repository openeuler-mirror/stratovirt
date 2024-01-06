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

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

use std::sync::Arc;

use anyhow::{bail, Result};
use kvm_ioctls::{Kvm, VmFd};

use super::HypervisorOps;

#[allow(clippy::upper_case_acronyms)]
#[derive(Default)]
pub struct KvmHypervisor {
    pub fd: Option<Kvm>,
    pub vm_fd: Option<Arc<VmFd>>,
}

impl KvmHypervisor {
    pub fn new(kvm_vm_fd: Option<Arc<VmFd>>) -> Result<Self> {
        match Kvm::new() {
            Ok(kvm_fd) => {
                let vm_fd: Option<Arc<VmFd>> = if kvm_vm_fd.is_some() {
                    kvm_vm_fd
                } else {
                    Some(Arc::new(match kvm_fd.create_vm() {
                        Ok(fd) => fd,
                        Err(e) => {
                            bail!("Failed to create VM in KVM: {:?}", e);
                        }
                    }))
                };
                Ok(KvmHypervisor {
                    fd: Some(kvm_fd),
                    vm_fd,
                })
            }
            Err(e) => {
                bail!("Failed to open /dev/kvm: {:?}", e)
            }
        }
    }
}

impl HypervisorOps for KvmHypervisor {
    fn init_machine(&self) -> Result<()> {
        self.arch_init()?;
        Ok(())
    }
}
