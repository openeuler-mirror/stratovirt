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

use std::mem::{align_of, size_of};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use kvm_bindings::{KVMIO, KVM_IRQ_ROUTING_IRQCHIP};
use kvm_ioctls::{Cap, Kvm, VmFd};
use vmm_sys_util::{ioctl_io_nr, ioctl_ioc_nr};

use util::bitmap::Bitmap;

pub(crate) type IrqRoute = kvm_bindings::kvm_irq_routing;
pub(crate) type IrqRouteEntry = kvm_bindings::kvm_irq_routing_entry;
type IrqRouteChip = kvm_bindings::kvm_irq_routing_irqchip;
type IrqChip = kvm_bindings::kvm_irq_routing_entry__bindgen_ty_1;

ioctl_io_nr!(KVM_CHECK_EXTENSION, KVMIO, 0x03);

#[cfg(target_arch = "x86_64")]
const IOAPIC_NUM_PINS: u32 = 24;
#[cfg(target_arch = "x86_64")]
const PIC_MASTER_PINS: u32 = 8;
#[cfg(target_arch = "x86_64")]
const PIC_SLACE_PINS: u32 = 8;
#[cfg(target_arch = "aarch64")]
const IOCHIP_NUM_PINS: u32 = 192;
#[cfg(target_arch = "aarch64")]
const KVM_IRQCHIP: u32 = 0;

/// Return the max number kvm supports.
fn get_maximum_gsi_cnt(kvmfd: &Kvm) -> u32 {
    let mut gsi_count = kvmfd.check_extension_int(Cap::IrqRouting);
    if gsi_count < 0 {
        gsi_count = 0;
    }

    gsi_count as u32
}

/// Return `IrqRouteEntry` according to gsi, irqchip kind and pin.
fn create_irq_route_entry(gsi: u32, irqchip: u32, pin: u32) -> IrqRouteEntry {
    let irq_route_chip = IrqRouteChip { irqchip, pin };
    let irq_chip = IrqChip {
        irqchip: irq_route_chip,
    };
    IrqRouteEntry {
        gsi,
        type_: KVM_IRQ_ROUTING_IRQCHIP,
        flags: 0,
        pad: 0,
        u: irq_chip,
    }
}

/// Offer the irq gsi table for a current kvm vm instance.
pub struct IrqRouteTable {
    pub irq_routes: Vec<IrqRouteEntry>,
    gsi_bitmap: Bitmap<u64>,
}

impl Default for IrqRouteTable {
    fn default() -> Self {
        IrqRouteTable {
            irq_routes: Vec::<IrqRouteEntry>::new(),
            gsi_bitmap: Bitmap::<u64>::new(0),
        }
    }
}

impl IrqRouteTable {
    /// Allocate a new irq route table.
    pub fn new(kvmfd: &Kvm) -> Self {
        let gsi_count = get_maximum_gsi_cnt(kvmfd);

        IrqRouteTable {
            irq_routes: Vec::<IrqRouteEntry>::new(),
            gsi_bitmap: Bitmap::<u64>::new(gsi_count as usize),
        }
    }

    /// Init irq route table in arch x86_64.
    #[cfg(target_arch = "x86_64")]
    pub fn init_irq_route_table(&mut self) {
        // On x86, use `kvm_create_irqchip` to create an interrupt
        // controller module in the kernel. It creates a virtual PIC, a virtual ioapic,
        // and sets up future vcpus to have a local APIC. IRQ routing for GSIs 0-15 is set
        // to both PIC and IOAPIC. GSI 16-23 only go to the IOAPIC.
        for i in 0..IOAPIC_NUM_PINS {
            if i < PIC_MASTER_PINS {
                self.irq_routes.push(create_irq_route_entry(
                    i,
                    kvm_bindings::KVM_IRQCHIP_PIC_MASTER,
                    i,
                ));
            } else if i < PIC_MASTER_PINS + PIC_SLACE_PINS {
                self.irq_routes.push(create_irq_route_entry(
                    i,
                    kvm_bindings::KVM_IRQCHIP_PIC_SLAVE,
                    i - PIC_MASTER_PINS,
                ));
            }
            self.irq_routes.push(create_irq_route_entry(
                i,
                kvm_bindings::KVM_IRQCHIP_IOAPIC,
                i,
            ));
            // This unwrap() will never fail, it is safe.
            self.gsi_bitmap.set(i as usize).unwrap();
        }
    }

    /// Init irq route table in arch aarch64.
    #[cfg(target_arch = "aarch64")]
    pub fn init_irq_route_table(&mut self) {
        for i in 0..IOCHIP_NUM_PINS {
            self.irq_routes
                .push(create_irq_route_entry(i, KVM_IRQCHIP, i));
            // This unwrap() will never fail, it is safe.
            self.gsi_bitmap.set(i as usize).unwrap();
        }
    }

    /// Get `IrqRouteEntry` by given gsi number.
    /// A gsi number may have several entries. If no gsi number in table, is will
    /// return an empty vector.
    pub fn get_irq_route_entry(&self, gsi: u32) -> Vec<IrqRouteEntry> {
        let mut entries = Vec::new();
        for entry in self.irq_routes.iter() {
            if gsi == entry.gsi {
                entries.push(*entry);
            }
        }

        entries
    }

    /// Sets the gsi routing table entries. It will overwrite previously set entries.
    pub fn commit_irq_routing(&self, vm_fd: &Arc<VmFd>) -> Result<()> {
        let routes = self.irq_routes.clone();

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

            let ret = vm_fd
                .set_gsi_routing(&*irq_routing)
                .with_context(|| "Failed to set gsi routing");

            std::alloc::dealloc(irq_routing as *mut u8, layout);
            ret
        }
    }
}

#[cfg(test)]
mod tests {
    use super::get_maximum_gsi_cnt;
    use crate::kvm::KvmHypervisor;

    #[test]
    fn test_get_maximum_gsi_cnt() {
        let kvm_hyp = KvmHypervisor::new(None).unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }
        assert!(get_maximum_gsi_cnt(kvm_hyp.fd.as_ref().unwrap()) > 0);
    }
}
