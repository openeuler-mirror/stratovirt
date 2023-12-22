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

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use kvm_bindings::*;

use crate::kvm::listener::KvmIoListener;
use crate::kvm::KvmHypervisor;
use crate::HypervisorError;
use address_space::Listener;

impl KvmHypervisor {
    pub fn arch_init(&self) -> Result<()> {
        // The identity_addr is set in the memory layout of x86 machine.
        let identity_addr: u64 = 0xFEF0_C000;
        let vm_fd = self.vm_fd.as_ref().unwrap();

        vm_fd
            .set_identity_map_address(identity_addr)
            .with_context(|| HypervisorError::SetIdentityMapAddr)?;

        // Page table takes 1 page, TSS takes the following 3 pages.
        vm_fd
            .set_tss_address((identity_addr + 0x1000) as usize)
            .with_context(|| HypervisorError::SetTssErr)?;

        let pit_config = kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            pad: Default::default(),
        };
        vm_fd
            .create_pit2(pit_config)
            .with_context(|| HypervisorError::CrtPitErr)
    }

    pub fn create_io_listener(&self) -> Arc<Mutex<dyn Listener>> {
        Arc::new(Mutex::new(KvmIoListener::new(self.vm_fd.clone())))
    }
}
