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

pub use error::HypervisorError;

use std::any::Any;
use std::sync::Arc;

use anyhow::Result;
use kvm_ioctls::DeviceFd;

use address_space::AddressSpace;
use cpu::CPUHypervisorOps;
use devices::IrqManager;
#[cfg(target_arch = "aarch64")]
use devices::{ICGICConfig, InterruptController};
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

    #[cfg(target_arch = "aarch64")]
    fn create_interrupt_controller(
        &mut self,
        gic_conf: &ICGICConfig,
    ) -> Result<Arc<InterruptController>>;

    #[cfg(target_arch = "x86_64")]
    fn create_interrupt_controller(&mut self) -> Result<()>;

    fn create_hypervisor_cpu(&self, vcpu_id: u8)
        -> Result<Arc<dyn CPUHypervisorOps + Send + Sync>>;

    fn create_irq_manager(&mut self) -> Result<IrqManager>;

    fn create_vfio_device(&self) -> Option<DeviceFd>;
}
