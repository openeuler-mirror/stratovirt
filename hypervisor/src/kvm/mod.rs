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

pub use interrupt::MsiVector;

use std::mem::{align_of, size_of};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use kvm_bindings::*;
use kvm_ioctls::{Kvm, VmFd};
use log::error;
use once_cell::sync::Lazy;
use vmm_sys_util::{
    eventfd::EventFd, ioctl_io_nr, ioctl_ioc_nr, ioctl_ior_nr, ioctl_iow_nr, ioctl_iowr_nr,
};

use interrupt::{IrqRoute, IrqRouteEntry, IrqRouteTable};

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/asm-generic/kvm.h
pub const KVM_SET_DEVICE_ATTR: u32 = 0x4018_aee1;
pub const KVM_SIGNAL_MSI: u32 = 0x4020_aea5;

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/kvm.h
ioctl_iow_nr!(KVM_SET_GSI_ROUTING, KVMIO, 0x6a, kvm_irq_routing);
ioctl_iow_nr!(KVM_IRQFD, KVMIO, 0x76, kvm_irqfd);
ioctl_io_nr!(KVM_GET_API_VERSION, KVMIO, 0x00);
ioctl_ior_nr!(KVM_GET_MP_STATE, KVMIO, 0x98, kvm_mp_state);
ioctl_ior_nr!(KVM_GET_VCPU_EVENTS, KVMIO, 0x9f, kvm_vcpu_events);
#[cfg(target_arch = "x86_64")]
ioctl_iowr_nr!(KVM_GET_SUPPORTED_CPUID, KVMIO, 0x05, kvm_cpuid2);
#[cfg(target_arch = "x86_64")]
ioctl_iow_nr!(KVM_SET_CPUID2, KVMIO, 0x90, kvm_cpuid2);
#[cfg(target_arch = "x86_64")]
ioctl_iow_nr!(KVM_SET_MP_STATE, KVMIO, 0x99, kvm_mp_state);
#[cfg(target_arch = "x86_64")]
ioctl_iow_nr!(KVM_SET_SREGS, KVMIO, 0x84, kvm_sregs);
#[cfg(target_arch = "x86_64")]
ioctl_iow_nr!(KVM_SET_REGS, KVMIO, 0x82, kvm_regs);
#[cfg(target_arch = "x86_64")]
ioctl_iow_nr!(KVM_SET_XSAVE, KVMIO, 0xa5, kvm_xsave);
#[cfg(target_arch = "x86_64")]
ioctl_iow_nr!(KVM_SET_XCRS, KVMIO, 0xa7, kvm_xcrs);
#[cfg(target_arch = "x86_64")]
ioctl_iow_nr!(KVM_SET_DEBUGREGS, KVMIO, 0xa2, kvm_debugregs);
#[cfg(target_arch = "x86_64")]
ioctl_iow_nr!(KVM_SET_LAPIC, KVMIO, 0x8f, kvm_lapic_state);
#[cfg(target_arch = "x86_64")]
ioctl_iow_nr!(KVM_SET_MSRS, KVMIO, 0x89, kvm_msrs);
#[cfg(target_arch = "x86_64")]
ioctl_iow_nr!(KVM_SET_VCPU_EVENTS, KVMIO, 0xa0, kvm_vcpu_events);
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
#[cfg(target_arch = "aarch64")]
ioctl_iow_nr!(KVM_ARM_VCPU_INIT, KVMIO, 0xae, kvm_vcpu_init);
ioctl_iow_nr!(KVM_IRQ_LINE, KVMIO, 0x61, kvm_irq_level);

#[allow(clippy::upper_case_acronyms)]
#[derive(Default)]
pub struct KVMFds {
    pub fd: Option<Kvm>,
    pub vm_fd: Option<Arc<VmFd>>,
    pub irq_route_table: Mutex<IrqRouteTable>,
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
                let irq_route_table = Mutex::new(IrqRouteTable::new(&fd));
                KVMFds {
                    fd: Some(fd),
                    vm_fd: Some(Arc::new(vm_fd)),
                    irq_route_table,
                }
            }
            Err(e) => {
                error!("Failed to open /dev/kvm: {:?}", e);
                KVMFds::default()
            }
        }
    }

    /// Sets the gsi routing table entries. It will overwrite previously set entries.
    pub fn commit_irq_routing(&self) -> Result<()> {
        let routes = self.irq_route_table.lock().unwrap().irq_routes.clone();

        let layout = std::alloc::Layout::from_size_align(
            size_of::<IrqRoute>() + routes.len() * size_of::<IrqRouteEntry>(),
            std::cmp::max(align_of::<IrqRoute>(), align_of::<IrqRouteEntry>()),
        )?;

        // SAFETY: data in `routes` is reliable.
        unsafe {
            let irq_routing = std::alloc::alloc(layout) as *mut IrqRoute;
            if irq_routing.is_null() {
                bail!("Failed to alloc irq routing");
            }
            (*irq_routing).nr = routes.len() as u32;
            (*irq_routing).flags = 0;
            let entries: &mut [IrqRouteEntry] = (*irq_routing).entries.as_mut_slice(routes.len());
            entries.copy_from_slice(&routes);

            let ret = self
                .vm_fd
                .as_ref()
                .unwrap()
                .set_gsi_routing(&*irq_routing)
                .with_context(|| "Failed to set gsi routing");

            std::alloc::dealloc(irq_routing as *mut u8, layout);
            ret
        }
    }

    pub fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()> {
        self.vm_fd
            .as_ref()
            .unwrap()
            .register_irqfd(fd, gsi)
            .with_context(|| format!("Failed to register irqfd: gsi {}.", gsi))
    }

    pub fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()> {
        self.vm_fd
            .as_ref()
            .unwrap()
            .unregister_irqfd(fd, gsi)
            .with_context(|| format!("Failed to unregister irqfd: gsi {}.", gsi))
    }

    pub fn set_irq_line(&self, irq: u32, level: bool) -> Result<()> {
        self.vm_fd
            .as_ref()
            .unwrap()
            .set_irq_line(irq, level)
            .with_context(|| format!("Failed to set irq {} level {:?}.", irq, level))
    }
}

pub static KVM_FDS: Lazy<ArcSwap<KVMFds>> = Lazy::new(|| ArcSwap::from(Arc::new(KVMFds::new())));
