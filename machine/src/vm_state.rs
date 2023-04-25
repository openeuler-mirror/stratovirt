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

use anyhow::Context;
use kvm_bindings::{kvm_clock_data, kvm_irqchip, kvm_pit_state2, KVM_IRQCHIP_IOAPIC};

use hypervisor::kvm::KVM_FDS;
use migration::{
    DeviceStateDesc, FieldDesc, MigrationError, MigrationHook, MigrationManager, StateTransfer,
};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;

/// Structure to wrapper kvm_device related function.
pub struct KvmDevice {}

/// Status of kvm device.
/// Kvm device include pit, kvm_clock, irq on x86_64 platform.
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct KvmDeviceState {
    pit_state: kvm_pit_state2,
    kvm_clock: kvm_clock_data,
    ioapic: kvm_irqchip,
}

impl StateTransfer for KvmDevice {
    fn get_state_vec(&self) -> migration::Result<Vec<u8>> {
        let kvm_fds = KVM_FDS.load();
        let vm_fd = kvm_fds.vm_fd.as_ref().unwrap();

        // save pit
        let pit_state = vm_fd.get_pit2()?;

        // save kvm_clock
        let mut kvm_clock = vm_fd.get_clock()?;
        // Reset kvm clock flag.
        kvm_clock.flags = 0;

        // save ioapic
        let mut ioapic = kvm_irqchip {
            chip_id: KVM_IRQCHIP_IOAPIC,
            ..Default::default()
        };
        vm_fd.get_irqchip(&mut ioapic)?;

        Ok(KvmDeviceState {
            pit_state,
            kvm_clock,
            ioapic,
        }
        .as_bytes()
        .to_vec())
    }

    fn set_state(&self, state: &[u8]) -> migration::Result<()> {
        let kvm_fds = KVM_FDS.load();
        let vm_fd = kvm_fds.vm_fd.as_ref().unwrap();

        let kvm_state = KvmDeviceState::from_bytes(state)
            .with_context(|| MigrationError::FromBytesError("KVM_DEVICE"))?;

        vm_fd.set_pit2(&kvm_state.pit_state)?;
        vm_fd.set_clock(&kvm_state.kvm_clock)?;
        vm_fd.set_irqchip(&kvm_state.ioapic)?;

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&KvmDeviceState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for KvmDevice {}
