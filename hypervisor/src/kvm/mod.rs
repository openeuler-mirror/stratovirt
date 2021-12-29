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

mod interrupt;
#[cfg(target_arch = "x86_64")]
mod state;

pub use interrupt::MsiVector;

use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use interrupt::{refact_vec_with_field, IrqRoute, IrqRouteEntry, IrqRouteTable};
use kvm_bindings::*;
use kvm_ioctls::{Kvm, VmFd};
use vmm_sys_util::eventfd::EventFd;

use crate::errors::{Result, ResultExt};

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/asm-generic/kvm.h
pub const KVM_SET_DEVICE_ATTR: u32 = 0x4018_aee1;
pub const KVM_SET_USER_MEMORY_REGION: u32 = 0x4020_ae46;
pub const KVM_IOEVENTFD: u32 = 0x4040_ae79;
pub const KVM_SIGNAL_MSI: u32 = 0x4020_aea5;

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/kvm.h
ioctl_iow_nr!(KVM_SET_GSI_ROUTING, KVMIO, 0x6a, kvm_irq_routing);
ioctl_iow_nr!(KVM_IRQFD, KVMIO, 0x76, kvm_irqfd);
ioctl_io_nr!(KVM_GET_API_VERSION, KVMIO, 0x00);
ioctl_ior_nr!(KVM_GET_MP_STATE, KVMIO, 0x98, kvm_mp_state);
ioctl_ior_nr!(KVM_GET_VCPU_EVENTS, KVMIO, 0x9f, kvm_vcpu_events);
#[cfg(target_arch = "x86_64")]
ioctl_ior_nr!(KVM_GET_PIT2, KVMIO, 0x9f, kvm_pit_state2);
ioctl_ior_nr!(KVM_GET_CLOCK, KVMIO, 0x7c, kvm_clock_data);
ioctl_iowr_nr!(KVM_GET_IRQCHIP, KVMIO, 0x62, kvm_irqchip);
ioctl_ior_nr!(KVM_GET_REGS, KVMIO, 0x81, kvm_regs);
ioctl_ior_nr!(KVM_GET_SREGS, KVMIO, 0x83, kvm_sregs);
#[cfg(target_arch = "x86_64")]
ioctl_ior_nr!(KVM_GET_XSAVE, KVMIO, 0xa4, kvm_xsave);
ioctl_ior_nr!(KVM_GET_FPU, KVMIO, 0x8c, kvm_fpu);
#[cfg(target_arch = "x86_64")]
ioctl_ior_nr!(KVM_GET_XCRS, KVMIO, 0xa6, kvm_xcrs);
#[cfg(target_arch = "x86_64")]
ioctl_ior_nr!(KVM_GET_DEBUGREGS, KVMIO, 0xa1, kvm_debugregs);
#[cfg(target_arch = "x86_64")]
ioctl_ior_nr!(KVM_GET_LAPIC, KVMIO, 0x8e, kvm_lapic_state);
#[cfg(target_arch = "x86_64")]
ioctl_iowr_nr!(KVM_GET_MSRS, KVMIO, 0x88, kvm_msrs);
ioctl_iowr_nr!(KVM_CREATE_DEVICE, KVMIO, 0xe0, kvm_create_device);
#[cfg(target_arch = "aarch64")]
ioctl_iow_nr!(KVM_GET_ONE_REG, KVMIO, 0xab, kvm_one_reg);
#[cfg(target_arch = "aarch64")]
ioctl_iow_nr!(KVM_SET_ONE_REG, KVMIO, 0xac, kvm_one_reg);
#[cfg(target_arch = "aarch64")]
ioctl_iow_nr!(KVM_GET_DEVICE_ATTR, KVMIO, 0xe2, kvm_device_attr);
#[cfg(target_arch = "aarch64")]
ioctl_iowr_nr!(KVM_GET_REG_LIST, KVMIO, 0xb0, kvm_reg_list);

#[allow(clippy::upper_case_acronyms)]
#[derive(Default)]
pub struct KVMFds {
    pub fd: Option<Kvm>,
    pub vm_fd: Option<VmFd>,
    pub irq_route_table: Mutex<IrqRouteTable>,
}

impl KVMFds {
    pub fn new() -> Self {
        let kvm_fds = match Kvm::new() {
            Ok(fd) => {
                let vm_fd = match fd.create_vm() {
                    Ok(vm_fd) => vm_fd,
                    Err(e) => {
                        error!("Failed to create VM in KVM: {}", e);
                        return KVMFds::default();
                    }
                };
                let irq_route_table = Mutex::new(IrqRouteTable::new(&fd));
                KVMFds {
                    fd: Some(fd),
                    vm_fd: Some(vm_fd),
                    irq_route_table,
                }
            }
            Err(e) => {
                error!("Failed to open /dev/kvm: {}", e);
                KVMFds::default()
            }
        };

        #[cfg(target_arch = "x86_64")]
        migration::MigrationManager::register_device_instance(
            state::KvmDeviceState::descriptor(),
            Arc::new(state::KvmDevice {}),
            false,
        );

        kvm_fds
    }

    /// Sets the gsi routing table entries. It will overwrite previously set entries.
    pub fn commit_irq_routing(&self) -> Result<()> {
        let routes = self.irq_route_table.lock().unwrap().irq_routes.clone();

        // Safe because data in `routes` is reliable.
        unsafe {
            let mut irq_routing = refact_vec_with_field::<IrqRoute, IrqRouteEntry>(routes.len());
            (*irq_routing).nr = routes.len() as u32;
            (*irq_routing).flags = 0;
            let entries: &mut [IrqRouteEntry] = (*irq_routing).entries.as_mut_slice(routes.len());
            entries.copy_from_slice(&routes);

            self.vm_fd
                .as_ref()
                .unwrap()
                .set_gsi_routing(&*irq_routing)
                .chain_err(|| "Failed to set gsi routing")
        }
    }

    pub fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()> {
        self.vm_fd
            .as_ref()
            .unwrap()
            .register_irqfd(fd, gsi)
            .chain_err(|| format!("Failed to register irqfd: gsi {}.", gsi))
    }

    pub fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()> {
        self.vm_fd
            .as_ref()
            .unwrap()
            .unregister_irqfd(fd, gsi)
            .chain_err(|| format!("Failed to unregister irqfd: gsi {}.", gsi))
    }
}

lazy_static! {
    pub static ref KVM_FDS: ArcSwap<KVMFds> = ArcSwap::from(Arc::new(KVMFds::new()));
}
