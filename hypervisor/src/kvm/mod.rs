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

use std::sync::Arc;

use arc_swap::ArcSwap;
use kvm_ioctls::{Kvm, VmFd};
use log::error;
use once_cell::sync::Lazy;

#[allow(clippy::upper_case_acronyms)]
#[derive(Default)]
pub struct KVMFds {
    pub fd: Option<Kvm>,
    pub vm_fd: Option<Arc<VmFd>>,
}

impl KVMFds {
    pub fn new() -> Self {
        match Kvm::new() {
            Ok(fd) => {
                let vm_fd = match fd.create_vm() {
                    Ok(vm_fd) => vm_fd,
                    Err(e) => {
                        error!("Failed to create VM in KVM: {:?}", e);
                        return KVMFds::default();
                    }
                };
                KVMFds {
                    fd: Some(fd),
                    vm_fd: Some(Arc::new(vm_fd)),
                }
            }
            Err(e) => {
                error!("Failed to open /dev/kvm: {:?}", e);
                KVMFds::default()
            }
        }
    }
}

pub static KVM_FDS: Lazy<ArcSwap<KVMFds>> = Lazy::new(|| ArcSwap::from(Arc::new(KVMFds::new())));
