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

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

mod interrupt;
mod listener;

#[cfg(target_arch = "aarch64")]
pub use aarch64::gicv2::KvmGICv2;
#[cfg(target_arch = "aarch64")]
pub use aarch64::gicv3::{KvmGICv3, KvmGICv3Its};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use kvm_bindings::kvm_userspace_memory_region as KvmMemSlot;
use kvm_bindings::*;
use kvm_ioctls::{Cap, Kvm, VmFd};
use vmm_sys_util::{ioctl_ioc_nr, ioctl_iow_nr, ioctl_iowr_nr};

use self::listener::KvmMemoryListener;
use super::HypervisorOps;
#[cfg(target_arch = "x86_64")]
use crate::HypervisorError;
use address_space::{AddressSpace, Listener};
use cpu::CPUHypervisorOps;
#[cfg(target_arch = "aarch64")]
use devices::{
    GICVersion, GICv2, GICv3, GICv3ItsState, GICv3State, ICGICConfig, InterruptController,
};
use interrupt::IrqRouteTable;
use machine_manager::{
    config::{MachineType, VmConfig},
    machine::HypervisorType,
};
#[cfg(target_arch = "aarch64")]
use migration::{
    snapshot::{GICV3_ITS_SNAPSHOT_ID, GICV3_SNAPSHOT_ID},
    MigrationManager,
};
use migration::{MigrateMemSlot, MigrateOps};

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/asm-generic/kvm.h
pub const KVM_SET_DEVICE_ATTR: u32 = 0x4018_aee1;
pub const KVM_SET_USER_MEMORY_REGION: u32 = 0x4020_ae46;
pub const KVM_IOEVENTFD: u32 = 0x4040_ae79;

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/kvm.h
ioctl_iow_nr!(KVM_GET_DIRTY_LOG, KVMIO, 0x42, kvm_dirty_log);
ioctl_iowr_nr!(KVM_CREATE_DEVICE, KVMIO, 0xe0, kvm_create_device);

#[allow(clippy::upper_case_acronyms)]
#[derive(Default)]
pub struct KvmHypervisor {
    pub fd: Option<Kvm>,
    pub vm_fd: Option<Arc<VmFd>>,
    pub mem_slots: Arc<Mutex<HashMap<u32, KvmMemSlot>>>,
    #[cfg(target_arch = "aarch64")]
    pub irq_chip: Option<Arc<InterruptController>>,
    pub irq_route_table: Option<Mutex<IrqRouteTable>>,
}

impl KvmHypervisor {
    pub fn new(kvm_vm_fd: Option<Arc<VmFd>>) -> Result<Self> {
        match Kvm::new() {
            Ok(kvm_fd) => {
                let vm_fd: Option<Arc<VmFd>> = if kvm_vm_fd.is_some() {
                    kvm_vm_fd
                } else {
                    Some(Arc::new(match kvm_fd.create_vm() {
                        Ok(fd) => fd,
                        Err(e) => {
                            bail!("Failed to create VM in KVM: {:?}", e);
                        }
                    }))
                };
                let irq_route_table = Mutex::new(IrqRouteTable::new(&kvm_fd));
                Ok(KvmHypervisor {
                    fd: Some(kvm_fd),
                    vm_fd,
                    mem_slots: Arc::new(Mutex::new(HashMap::new())),
                    #[cfg(target_arch = "aarch64")]
                    irq_chip: None,
                    irq_route_table: Some(irq_route_table),
                })
            }
            Err(e) => {
                bail!("Failed to open /dev/kvm: {:?}", e)
            }
        }
    }

    fn create_memory_listener(&self) -> Arc<Mutex<dyn Listener>> {
        Arc::new(Mutex::new(KvmMemoryListener::new(
            self.fd.as_ref().unwrap().get_nr_memslots() as u32,
            self.vm_fd.clone(),
            self.mem_slots.clone(),
        )))
    }

    fn init_irq_route_table(&self) -> Result<()> {
        let irq_route_table = self.irq_route_table.as_ref().unwrap();
        let mut locked_irq_route_table = irq_route_table.lock().unwrap();
        locked_irq_route_table.init_irq_route_table();
        locked_irq_route_table.commit_irq_routing(self.vm_fd.as_ref().unwrap())
    }
}

impl HypervisorOps for KvmHypervisor {
    fn init_machine(
        &self,
        #[cfg(target_arch = "x86_64")] sys_io: &Arc<AddressSpace>,
        sys_mem: &Arc<AddressSpace>,
    ) -> Result<()> {
        self.arch_init()?;

        sys_mem
            .register_listener(self.create_memory_listener())
            .with_context(|| "Failed to register hypervisor listener for memory space.")?;
        #[cfg(target_arch = "x86_64")]
        sys_io
            .register_listener(self.create_io_listener())
            .with_context(|| "Failed to register hypervisor listener for I/O address space.")?;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn create_interrupt_controller(
        &mut self,
        gic_conf: &ICGICConfig,
        vm_config: &VmConfig,
    ) -> Result<Arc<InterruptController>> {
        gic_conf.check_sanity()?;

        let create_gicv3 = || {
            let hypervisor_gic = KvmGICv3::new(self.vm_fd.clone().unwrap(), gic_conf.vcpu_count)?;
            let its_handler = KvmGICv3Its::new(self.vm_fd.clone().unwrap())?;
            let gicv3 = Arc::new(GICv3::new(
                Arc::new(hypervisor_gic),
                Arc::new(its_handler),
                gic_conf,
            )?);
            if let Some(its_dev) = gicv3.its_dev.clone() {
                MigrationManager::register_gic_instance(
                    GICv3ItsState::descriptor(),
                    its_dev,
                    GICV3_ITS_SNAPSHOT_ID,
                );
            }

            MigrationManager::register_gic_instance(
                GICv3State::descriptor(),
                gicv3.clone(),
                GICV3_SNAPSHOT_ID,
            );

            Ok(Arc::new(InterruptController::new(gicv3)))
        };

        let create_gicv2 = || {
            let hypervisor_gic = KvmGICv2::new(self.vm_fd.clone().unwrap())?;
            let gicv2 = Arc::new(GICv2::new(Arc::new(hypervisor_gic), gic_conf)?);
            Ok(Arc::new(InterruptController::new(gicv2)))
        };

        let interrupt_controller = match &gic_conf.version {
            Some(GICVersion::GICv3) => create_gicv3(),
            Some(GICVersion::GICv2) => create_gicv2(),
            // Try v3 by default if no version specified.
            None => create_gicv3().or_else(|_| create_gicv2()),
        };

        if vm_config.machine_config.mach_type == MachineType::StandardVm {
            self.init_irq_route_table()?;
        }

        interrupt_controller
    }

    #[cfg(target_arch = "x86_64")]
    fn create_interrupt_controller(&mut self, vm_config: &VmConfig) -> Result<()> {
        self.vm_fd
            .as_ref()
            .unwrap()
            .create_irq_chip()
            .with_context(|| HypervisorError::CrtIrqchipErr)?;

        if vm_config.machine_config.mach_type == MachineType::StandardVm {
            self.init_irq_route_table()?;
        }

        Ok(())
    }

    fn create_hypervisor_cpu(
        &self,
        _vcpu_id: u8,
    ) -> Result<Arc<dyn CPUHypervisorOps + Send + Sync>> {
        Ok(Arc::new(KvmCpu::new()))
    }
}

impl MigrateOps for KvmHypervisor {
    /// Get ram memory region from `KvmHypervisor` structure.
    fn get_mem_slots(&self) -> Arc<Mutex<HashMap<u32, MigrateMemSlot>>> {
        let mut mgt_mem_slots = HashMap::new();
        for (_, slot) in self.mem_slots.lock().unwrap().iter() {
            let mem_slot = MigrateMemSlot {
                slot: slot.slot,
                guest_phys_addr: slot.guest_phys_addr,
                userspace_addr: slot.userspace_addr,
                memory_size: slot.memory_size,
            };
            mgt_mem_slots.insert(slot.slot, mem_slot);
        }
        Arc::new(Mutex::new(mgt_mem_slots))
    }

    /// Get dirty page bitmap in kvm.
    fn get_dirty_log(&self, slot: u32, mem_size: u64) -> Result<Vec<u64>> {
        self.vm_fd
            .as_ref()
            .unwrap()
            .get_dirty_log(slot, mem_size as usize)
            .with_context(|| {
                format!(
                    "Failed to get dirty log, error is {}",
                    std::io::Error::last_os_error()
                )
            })
    }

    /// Start dirty page tracking in kvm.
    fn start_dirty_log(&self) -> Result<()> {
        for (_, region) in self.mem_slots.lock().unwrap().iter_mut() {
            region.flags = KVM_MEM_LOG_DIRTY_PAGES;
            // SAFETY: region from `KvmHypervisor` is reliable.
            unsafe {
                self.vm_fd
                    .as_ref()
                    .unwrap()
                    .set_user_memory_region(*region)
                    .with_context(|| {
                        format!(
                            "Failed to start dirty log, error is {}",
                            std::io::Error::last_os_error()
                        )
                    })?;
            }
        }

        Ok(())
    }

    /// Stop dirty page tracking in kvm.
    fn stop_dirty_log(&self) -> Result<()> {
        for (_, region) in self.mem_slots.lock().unwrap().iter_mut() {
            region.flags = 0;
            // SAFETY: region from `KvmHypervisor` is reliable.
            unsafe {
                self.vm_fd
                    .as_ref()
                    .unwrap()
                    .set_user_memory_region(*region)
                    .with_context(|| {
                        format!(
                            "Failed to stop dirty log, error is {}",
                            std::io::Error::last_os_error()
                        )
                    })?;
            }
        }

        Ok(())
    }
}

pub struct KvmCpu {}

impl KvmCpu {
    pub fn new() -> Self {
        Self {}
    }
}

impl CPUHypervisorOps for KvmCpu {
    fn get_hypervisor_type(&self) -> HypervisorType {
        HypervisorType::Kvm
    }

    fn check_extension(&self, cap: Cap) -> bool {
        let kvm = Kvm::new().unwrap();
        kvm.check_extension(cap)
    }

    fn get_msr_index_list(&self) -> Vec<u32> {
        self.arch_get_msr_index_list()
    }
}
