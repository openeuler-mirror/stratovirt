// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use kvm_ioctls::Cap;
use kvm_ioctls::Kvm;

use anyhow::{bail, Result};

/// KVM capabilities the aarch64 machine cannot run without.
const REQUIRED_CAPS: [Cap; 8] = [
    Cap::ArmPsci02,     // KVM_ARM_VCPU_PSCI_0_2 set in arch_vcpu_init.
    Cap::ImmediateExit, // KVM_RUN immediate exit for vCPU pause.
    Cap::Ioeventfd,     // ioeventfd offload for virtio notifications.
    Cap::Irqchip,       // In-kernel GIC.
    Cap::Irqfd,         // irqfd for interrupt injection.
    Cap::IrqRouting,    // GSI routing table for irqfd/MSI.
    Cap::OneReg,        // KVM_GET/SET_ONE_REG for all vCPU register access.
    Cap::UserMemory,    // KVM_SET_USER_MEMORY_REGION for guest memory.
];

// Capabilities for ARM cpu.
#[derive(Debug, Clone)]
pub struct ArmCPUCaps {
    pub irq_chip: bool,
    pub ioevent_fd: bool,
    pub irq_fd: bool,
    pub user_mem: bool,
    pub psci02: bool,
    pub mp_state: bool,
    pub vcpu_events: bool,
    pub pmuv3: bool,
    pub sve: bool,
}

impl ArmCPUCaps {
    /// Preflight the KVM capabilities required by the aarch64 machine.
    pub fn check_required_extensions(kvm: &Kvm) -> Result<()> {
        for cap in REQUIRED_CAPS {
            if !kvm.check_extension(cap) {
                bail!("KVM capability {cap:?} is required for aarch64");
            }
        }
        Ok(())
    }

    /// Initialize ArmCPUCaps instance.
    pub fn init_capabilities(kvm: &Kvm) -> Result<Self> {
        Ok(ArmCPUCaps {
            irq_chip: kvm.check_extension(Cap::Irqchip),
            ioevent_fd: kvm.check_extension(Cap::Ioeventfd),
            irq_fd: kvm.check_extension(Cap::Irqfd),
            user_mem: kvm.check_extension(Cap::UserMemory),
            psci02: kvm.check_extension(Cap::ArmPsci02),
            mp_state: kvm.check_extension(Cap::MpState),
            vcpu_events: kvm.check_extension(Cap::VcpuEvents),
            pmuv3: kvm.check_extension(Cap::ArmPmuV3),
            sve: kvm.check_extension(Cap::ArmSve),
        })
    }
}
