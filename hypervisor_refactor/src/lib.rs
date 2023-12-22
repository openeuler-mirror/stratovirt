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

//! This crate offers interfaces for different kinds of hypervisors, such as KVM.

pub mod error;
pub mod kvm;

use std::any::Any;
use std::sync::Arc;

pub use error::HypervisorError;

use anyhow::Result;

use address_space::AddressSpace;
use machine_manager::machine::HypervisorType;

pub trait HypervisorOps: Send + Sync + Any {
    fn get_hypervisor_type(&self) -> HypervisorType {
        HypervisorType::Kvm
    }

    fn init_machine(
        &self,
        #[cfg(target_arch = "x86_64")] sys_io: &Arc<AddressSpace>,
        sys_mem: &Arc<AddressSpace>,
    ) -> Result<()>;
}
