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

use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};

use crate::{
    micro_common::syscall::syscall_whitelist, LightMachine, MachineBase, MachineError, MachineOps,
};
use address_space::{AddressSpace, Region};
use cpu::{CPUBootConfig, CPUTopology};
use devices::legacy::FwCfgOps;
use hypervisor::kvm::x86_64::*;
use hypervisor::kvm::*;
use machine_manager::config::{SerialConfig, VmConfig};
use migration::{MigrationManager, MigrationStatus};
use util::seccomp::{BpfRule, SeccompCmpOpt};
use virtio::VirtioMmioDevice;

#[repr(usize)]
pub enum LayoutEntryType {
    MemBelow4g = 0_usize,
    Mmio,
    IoApic,
    LocalApic,
    IdentTss,
    MemAbove4g,
}

pub const MEM_LAYOUT: &[(u64, u64)] = &[
    (0, 0xC000_0000),                // MemBelow4g
    (0xF010_0000, 0x200),            // Mmio
    (0xFEC0_0000, 0x10_0000),        // IoApic
    (0xFEE0_0000, 0x10_0000),        // LocalApic
    (0xFEF0_C000, 0x4000),           // Identity map address and TSS
    (0x1_0000_0000, 0x80_0000_0000), // MemAbove4g
];

impl MachineOps for LightMachine {
    fn machine_base(&self) -> &MachineBase {
        &self.base
    }

    fn machine_base_mut(&mut self) -> &mut MachineBase {
        &mut self.base
    }

    fn init_machine_ram(&self, sys_mem: &Arc<AddressSpace>, mem_size: u64) -> Result<()> {
        let vm_ram = self.get_vm_ram();
        let below4g_size = MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].1;
        let below4g_ram = Region::init_alias_region(
            vm_ram.clone(),
            0,
            std::cmp::min(below4g_size, mem_size),
            "below4g_ram",
        );
        sys_mem.root().add_subregion(
            below4g_ram,
            MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].0,
        )?;

        if mem_size > below4g_size {
            let above4g_ram = Region::init_alias_region(
                vm_ram.clone(),
                below4g_size,
                mem_size - below4g_size,
                "above4g_ram",
            );
            let above4g_start = MEM_LAYOUT[LayoutEntryType::MemAbove4g as usize].0;
            sys_mem.root().add_subregion(above4g_ram, above4g_start)?;
        }

        Ok(())
    }

    fn init_interrupt_controller(&mut self, _vcpu_count: u64) -> Result<()> {
        let hypervisor = self.get_hypervisor();
        let mut locked_hypervisor = hypervisor.lock().unwrap();
        locked_hypervisor.create_interrupt_controller()?;

        let irq_manager = locked_hypervisor.create_irq_manager()?;
        self.base.sysbus.irq_manager = irq_manager.line_irq_manager;

        Ok(())
    }

    fn load_boot_source(&self, fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>) -> Result<CPUBootConfig> {
        use boot_loader::{load_linux, BootLoaderConfig};

        let boot_source = self.base.boot_source.lock().unwrap();
        let initrd = boot_source.initrd.as_ref().map(|b| b.initrd_file.clone());

        let gap_start = MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].0
            + MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].1;
        let gap_end = MEM_LAYOUT[LayoutEntryType::MemAbove4g as usize].0;
        let bootloader_config = BootLoaderConfig {
            kernel: boot_source.kernel_file.clone(),
            initrd,
            kernel_cmdline: boot_source.kernel_cmdline.to_string(),
            cpu_count: self.base.cpu_topo.nrcpus,
            gap_range: (gap_start, gap_end - gap_start),
            ioapic_addr: MEM_LAYOUT[LayoutEntryType::IoApic as usize].0 as u32,
            lapic_addr: MEM_LAYOUT[LayoutEntryType::LocalApic as usize].0 as u32,
            ident_tss_range: None,
            prot64_mode: true,
        };
        let layout = load_linux(&bootloader_config, &self.base.sys_mem, fwcfg)
            .with_context(|| MachineError::LoadKernErr)?;

        Ok(CPUBootConfig {
            prot64_mode: true,
            boot_ip: layout.boot_ip,
            boot_sp: layout.boot_sp,
            boot_selector: layout.boot_selector,
            zero_page: layout.zero_page_addr,
            code_segment: layout.segments.code_segment,
            data_segment: layout.segments.data_segment,
            gdt_base: layout.segments.gdt_base,
            gdt_size: layout.segments.gdt_limit,
            idt_base: layout.segments.idt_base,
            idt_size: layout.segments.idt_limit,
            pml4_start: layout.boot_pml4_addr,
        })
    }

    fn add_serial_device(&mut self, config: &SerialConfig) -> Result<()> {
        use devices::legacy::{Serial, SERIAL_ADDR};

        let region_base: u64 = SERIAL_ADDR;
        let region_size: u64 = 8;
        let serial = Serial::new(config.clone());
        serial
            .realize(&mut self.base.sysbus, region_base, region_size)
            .with_context(|| "Failed to realize serial device.")
    }

    fn realize(vm: &Arc<Mutex<Self>>, vm_config: &mut VmConfig) -> Result<()> {
        let mut locked_vm = vm.lock().unwrap();

        trace::sysbus(&locked_vm.base.sysbus);
        trace::vm_state(&locked_vm.base.vm_state);

        let topology = CPUTopology::new().set_topology((
            vm_config.machine_config.nr_threads,
            vm_config.machine_config.nr_cores,
            vm_config.machine_config.nr_dies,
        ));
        trace::cpu_topo(&topology);
        locked_vm.base.numa_nodes = locked_vm.add_numa_nodes(vm_config)?;
        let locked_hypervisor = locked_vm.base.hypervisor.lock().unwrap();
        locked_hypervisor.init_machine(&locked_vm.base.sys_io, &locked_vm.base.sys_mem)?;
        drop(locked_hypervisor);
        locked_vm.init_memory(
            &vm_config.machine_config.mem_config,
            &locked_vm.base.sys_mem,
            vm_config.machine_config.nr_cpus,
        )?;

        locked_vm.init_interrupt_controller(u64::from(vm_config.machine_config.nr_cpus))?;

        // Add mmio devices
        locked_vm
            .create_replaceable_devices()
            .with_context(|| "Failed to create replaceable devices.")?;
        locked_vm.add_devices(vm_config)?;
        trace::replaceable_info(&locked_vm.replaceable_info);

        let boot_config = locked_vm.load_boot_source(None)?;
        let hypervisor = locked_vm.base.hypervisor.clone();
        locked_vm.base.cpus.extend(<Self as MachineOps>::init_vcpu(
            vm.clone(),
            hypervisor,
            vm_config.machine_config.nr_cpus,
            vm_config.machine_config.max_cpus,
            &topology,
            &boot_config,
        )?);

        MigrationManager::register_vm_instance(vm.clone());
        let migration_hyp = locked_vm.base.migration_hypervisor.clone();
        migration_hyp.lock().unwrap().register_instance()?;
        MigrationManager::register_migration_instance(migration_hyp);
        if let Err(e) = MigrationManager::set_status(MigrationStatus::Setup) {
            bail!("Failed to set migration status {}", e);
        }

        Ok(())
    }

    fn add_virtio_mmio_net(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        self.add_virtio_mmio_net(vm_config, cfg_args)
    }

    fn add_virtio_mmio_block(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        self.add_virtio_mmio_block(vm_config, cfg_args)
    }

    fn realize_virtio_mmio_device(
        &mut self,
        dev: VirtioMmioDevice,
    ) -> Result<Arc<Mutex<VirtioMmioDevice>>> {
        self.realize_virtio_mmio_device(dev)
    }

    fn syscall_whitelist(&self) -> Vec<BpfRule> {
        syscall_whitelist()
    }
}

pub(crate) fn arch_ioctl_allow_list(bpf_rule: BpfRule) -> BpfRule {
    bpf_rule
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_PIT2() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_CLOCK() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_IRQCHIP() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_REGS() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_SREGS() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_XSAVE() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_SREGS() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_DEBUGREGS() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_XCRS() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_LAPIC() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_MSRS() as u32)
}

pub(crate) fn arch_syscall_whitelist() -> Vec<BpfRule> {
    vec![
        #[cfg(not(target_env = "gnu"))]
        BpfRule::new(libc::SYS_epoll_pwait),
        #[cfg(target_env = "gnu")]
        BpfRule::new(libc::SYS_epoll_wait),
        BpfRule::new(libc::SYS_open),
        #[cfg(target_env = "musl")]
        BpfRule::new(libc::SYS_stat),
        #[cfg(target_env = "gnu")]
        BpfRule::new(libc::SYS_newfstatat),
        BpfRule::new(libc::SYS_unlink),
        BpfRule::new(libc::SYS_mkdir),
        #[cfg(target_env = "gnu")]
        BpfRule::new(libc::SYS_readlink),
    ]
}
