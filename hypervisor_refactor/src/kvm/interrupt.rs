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
use kvm_bindings::{KVMIO, KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI};
use kvm_ioctls::{Cap, Kvm, VmFd};
use vmm_sys_util::{ioctl_io_nr, ioctl_ioc_nr};

use devices::pci::MsiVector;
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

    /// Add msi irq route to irq routing table.
    pub fn add_msi_route(&mut self, gsi: u32, msi_vector: MsiVector) -> Result<()> {
        let mut kroute = IrqRouteEntry {
            gsi,
            type_: KVM_IRQ_ROUTING_MSI,
            flags: 0,
            ..Default::default()
        };
        kroute.u.msi.address_lo = msi_vector.msg_addr_lo;
        kroute.u.msi.address_hi = msi_vector.msg_addr_hi;
        kroute.u.msi.data = msi_vector.msg_data;
        #[cfg(target_arch = "aarch64")]
        {
            kroute.flags = kvm_bindings::KVM_MSI_VALID_DEVID;
            kroute.u.msi.__bindgen_anon_1.devid = msi_vector.dev_id;
        }
        self.irq_routes.push(kroute);

        Ok(())
    }

    fn remove_irq_route(&mut self, gsi: u32) {
        while let Some((index, _)) = self
            .irq_routes
            .iter()
            .enumerate()
            .find(|(_, e)| e.gsi == gsi)
        {
            self.irq_routes.remove(index);
        }
    }

    /// Update msi irq route to irq routing table.
    pub fn update_msi_route(&mut self, gsi: u32, msi_vector: MsiVector) -> Result<()> {
        self.remove_irq_route(gsi);
        self.add_msi_route(gsi, msi_vector)
            .with_context(|| "Failed to add msi route")?;

        Ok(())
    }

    /// Allocate free gsi number.
    pub fn allocate_gsi(&mut self) -> Result<u32> {
        let free_gsi = self
            .gsi_bitmap
            .find_next_zero(0)
            .with_context(|| "Failed to get new free gsi")?;
        self.gsi_bitmap.set(free_gsi)?;
        Ok(free_gsi as u32)
    }

    /// Release gsi number to free.
    ///
    /// # Notions
    ///
    /// If registered irqfd with this gsi, it's necessary to unregister irqfd first.
    pub fn release_gsi(&mut self, gsi: u32) -> Result<()> {
        self.gsi_bitmap
            .clear(gsi as usize)
            .with_context(|| "Failed to release gsi")?;
        self.remove_irq_route(gsi);
        Ok(())
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
    use std::sync::{Arc, Mutex};

    use super::{get_maximum_gsi_cnt, IrqRouteTable};
    use crate::kvm::{KVMInterruptManager, KvmHypervisor};

    #[test]
    fn test_get_maximum_gsi_cnt() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }
        assert!(get_maximum_gsi_cnt(kvm_hyp.fd.as_ref().unwrap()) > 0);
    }

    #[test]
    fn test_alloc_and_release_gsi() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }
        let irq_route_table = Mutex::new(IrqRouteTable::new(&kvm_hyp.fd.as_ref().unwrap()));
        let irq_manager = Arc::new(KVMInterruptManager::new(
            true,
            kvm_hyp.vm_fd.clone().unwrap(),
            irq_route_table,
        ));
        let mut irq_route_table = irq_manager.irq_route_table.lock().unwrap();
        irq_route_table.init_irq_route_table();

        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(irq_route_table.allocate_gsi().unwrap(), 24);
            assert_eq!(irq_route_table.allocate_gsi().unwrap(), 25);
            assert_eq!(irq_route_table.allocate_gsi().unwrap(), 26);
            assert_eq!(irq_route_table.allocate_gsi().unwrap(), 27);
            assert_eq!(irq_route_table.allocate_gsi().unwrap(), 28);
            assert!(irq_route_table.release_gsi(26).is_ok());
            assert_eq!(irq_route_table.allocate_gsi().unwrap(), 26);
        }
        #[cfg(target_arch = "aarch64")]
        {
            assert_eq!(irq_route_table.allocate_gsi().unwrap(), 192);
            assert_eq!(irq_route_table.allocate_gsi().unwrap(), 193);
            assert_eq!(irq_route_table.allocate_gsi().unwrap(), 194);
            assert_eq!(irq_route_table.allocate_gsi().unwrap(), 195);
            assert_eq!(irq_route_table.allocate_gsi().unwrap(), 196);
            assert!(irq_route_table.release_gsi(195).is_ok());
            assert_eq!(irq_route_table.allocate_gsi().unwrap(), 195);
        }
    }
}
