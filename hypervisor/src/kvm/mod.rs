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
use vmm_sys_util::{eventfd::EventFd, ioctl_ioc_nr, ioctl_iow_nr, ioctl_iowr_nr};

use interrupt::{IrqRoute, IrqRouteEntry, IrqRouteTable};

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/asm-generic/kvm.h
pub const KVM_SIGNAL_MSI: u32 = 0x4020_aea5;

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/kvm.h
ioctl_iow_nr!(KVM_SET_GSI_ROUTING, KVMIO, 0x6a, kvm_irq_routing);
ioctl_iow_nr!(KVM_IRQFD, KVMIO, 0x76, kvm_irqfd);
ioctl_iowr_nr!(KVM_GET_IRQCHIP, KVMIO, 0x62, kvm_irqchip);
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
