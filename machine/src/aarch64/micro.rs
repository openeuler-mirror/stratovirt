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

use crate::{micro_common::syscall::syscall_whitelist, MachineBase, MachineError};
use crate::{LightMachine, MachineOps};
use address_space::{AddressSpace, GuestAddress, Region};
use cpu::CPUTopology;
use devices::{legacy::PL031, ICGICConfig, ICGICv2Config, ICGICv3Config, GIC_IRQ_MAX};
use hypervisor::kvm::aarch64::*;
use machine_manager::config::{SerialConfig, VmConfig};
use migration::{MigrationManager, MigrationStatus};
use util::{
    device_tree::{self, CompileFDT, FdtBuilder},
    seccomp::{BpfRule, SeccompCmpOpt},
};
use virtio::VirtioMmioDevice;

#[repr(usize)]
pub enum LayoutEntryType {
    GicDist,
    GicCpu,
    GicIts,
    GicRedist,
    Uart,
    Rtc,
    Mmio,
    Mem,
    HighGicRedist,
}

pub const MEM_LAYOUT: &[(u64, u64)] = &[
    (0x0800_0000, 0x0001_0000),    // GicDist
    (0x0801_0000, 0x0001_0000),    // GicCpu
    (0x0808_0000, 0x0002_0000),    // GicIts
    (0x080A_0000, 0x00F6_0000),    // GicRedist (max 123 redistributors)
    (0x0900_0000, 0x0000_1000),    // Uart
    (0x0901_0000, 0x0000_1000),    // Rtc
    (0x0A00_0000, 0x0000_0200),    // Mmio
    (0x4000_0000, 0x80_0000_0000), // Mem
    (256 << 30, 0x200_0000),       // HighGicRedist, (where remaining redistributors locates)
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
        let layout_size = MEM_LAYOUT[LayoutEntryType::Mem as usize].1;
        let ram = Region::init_alias_region(
            vm_ram.clone(),
            0,
            std::cmp::min(layout_size, mem_size),
            "pc_ram",
        );
        sys_mem
            .root()
            .add_subregion(ram, MEM_LAYOUT[LayoutEntryType::Mem as usize].0)
    }

    fn init_interrupt_controller(&mut self, vcpu_count: u64) -> Result<()> {
        let v3 = ICGICv3Config {
            msi: true,
            dist_range: MEM_LAYOUT[LayoutEntryType::GicDist as usize],
            redist_region_ranges: vec![
                MEM_LAYOUT[LayoutEntryType::GicRedist as usize],
                MEM_LAYOUT[LayoutEntryType::HighGicRedist as usize],
            ],
            its_range: Some(MEM_LAYOUT[LayoutEntryType::GicIts as usize]),
        };
        let v2 = ICGICv2Config {
            dist_range: MEM_LAYOUT[LayoutEntryType::GicDist as usize],
            cpu_range: MEM_LAYOUT[LayoutEntryType::GicCpu as usize],
            v2m_range: None,
            sys_mem: None,
        };
        // Passing both v2 and v3, leave GIC self to decide which one to use.
        let intc_conf = ICGICConfig {
            version: None,
            vcpu_count,
            max_irq: GIC_IRQ_MAX,
            v3: Some(v3),
            v2: Some(v2),
        };

        let hypervisor = self.get_hypervisor();
        let mut locked_hypervisor = hypervisor.lock().unwrap();
        self.base.irq_chip = Some(locked_hypervisor.create_interrupt_controller(&intc_conf)?);
        self.base.irq_chip.as_ref().unwrap().realize()?;

        let irq_manager = locked_hypervisor.create_irq_manager()?;
        self.base.sysbus.irq_manager = irq_manager.line_irq_manager;
        Ok(())
    }

    fn add_rtc_device(&mut self) -> Result<()> {
        PL031::realize(
            PL031::default(),
            &mut self.base.sysbus,
            MEM_LAYOUT[LayoutEntryType::Rtc as usize].0,
            MEM_LAYOUT[LayoutEntryType::Rtc as usize].1,
        )
        .with_context(|| "Failed to realize pl031.")
    }

    fn add_serial_device(&mut self, config: &SerialConfig) -> Result<()> {
        use devices::legacy::PL011;

        let region_base: u64 = MEM_LAYOUT[LayoutEntryType::Uart as usize].0;
        let region_size: u64 = MEM_LAYOUT[LayoutEntryType::Uart as usize].1;

        let pl011 = PL011::new(config.clone()).with_context(|| "Failed to create PL011")?;
        pl011
            .realize(
                &mut self.base.sysbus,
                region_base,
                region_size,
                &self.base.boot_source,
            )
            .with_context(|| "Failed to realize PL011")
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
        locked_hypervisor.init_machine(&locked_vm.base.sys_mem)?;
        drop(locked_hypervisor);
        locked_vm.init_memory(
            &vm_config.machine_config.mem_config,
            &locked_vm.base.sys_mem,
            vm_config.machine_config.nr_cpus,
        )?;

        let boot_config =
            locked_vm.load_boot_source(None, MEM_LAYOUT[LayoutEntryType::Mem as usize].0)?;
        let cpu_config = locked_vm.load_cpu_features(vm_config)?;

        let hypervisor = locked_vm.base.hypervisor.clone();
        // vCPUs init,and apply CPU features (for aarch64)
        locked_vm.base.cpus.extend(<Self as MachineOps>::init_vcpu(
            vm.clone(),
            hypervisor,
            vm_config.machine_config.nr_cpus,
            &topology,
            &boot_config,
            &cpu_config,
        )?);

        locked_vm.init_interrupt_controller(u64::from(vm_config.machine_config.nr_cpus))?;

        locked_vm.cpu_post_init(&cpu_config)?;

        // Add mmio devices
        locked_vm
            .create_replaceable_devices()
            .with_context(|| "Failed to create replaceable devices.")?;
        locked_vm.add_devices(vm_config)?;
        trace::replaceable_info(&locked_vm.replaceable_info);

        let mut fdt_helper = FdtBuilder::new();
        locked_vm
            .generate_fdt_node(&mut fdt_helper)
            .with_context(|| MachineError::GenFdtErr)?;
        let fdt_vec = fdt_helper.finish()?;
        locked_vm
            .base
            .sys_mem
            .write(
                &mut fdt_vec.as_slice(),
                GuestAddress(boot_config.fdt_addr),
                fdt_vec.len() as u64,
            )
            .with_context(|| MachineError::WrtFdtErr(boot_config.fdt_addr, fdt_vec.len()))?;

        MigrationManager::register_vm_instance(vm.clone());
        MigrationManager::register_migration_instance(locked_vm.base.migration_hypervisor.clone());
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
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_ONE_REG() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_DEVICE_ATTR() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_REG_LIST() as u32)
}

pub(crate) fn arch_syscall_whitelist() -> Vec<BpfRule> {
    vec![
        BpfRule::new(libc::SYS_epoll_pwait),
        BpfRule::new(libc::SYS_newfstatat),
        BpfRule::new(libc::SYS_unlinkat),
        BpfRule::new(libc::SYS_mkdirat),
    ]
}

/// Trait that helps to generate all nodes in device-tree.
#[allow(clippy::upper_case_acronyms)]
trait CompileFDTHelper {
    /// Function that helps to generate memory nodes.
    fn generate_memory_node(&self, fdt: &mut FdtBuilder) -> Result<()>;
    /// Function that helps to generate the chosen node.
    fn generate_chosen_node(&self, fdt: &mut FdtBuilder) -> Result<()>;
}

impl CompileFDTHelper for LightMachine {
    fn generate_memory_node(&self, fdt: &mut FdtBuilder) -> Result<()> {
        let mem_base = MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
        let mem_size = self.base.sys_mem.memory_end_address().raw_value()
            - MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
        let node = "memory";
        let memory_node_dep = fdt.begin_node(node)?;
        fdt.set_property_string("device_type", "memory")?;
        fdt.set_property_array_u64("reg", &[mem_base, mem_size])?;
        fdt.end_node(memory_node_dep)
    }

    fn generate_chosen_node(&self, fdt: &mut FdtBuilder) -> Result<()> {
        let node = "chosen";
        let boot_source = self.base.boot_source.lock().unwrap();

        let chosen_node_dep = fdt.begin_node(node)?;
        let cmdline = &boot_source.kernel_cmdline.to_string();
        fdt.set_property_string("bootargs", cmdline.as_str())?;

        let pl011_property_string =
            format!("/pl011@{:x}", MEM_LAYOUT[LayoutEntryType::Uart as usize].0);
        fdt.set_property_string("stdout-path", &pl011_property_string)?;

        match &boot_source.initrd {
            Some(initrd) => {
                fdt.set_property_u64("linux,initrd-start", initrd.initrd_addr)?;
                fdt.set_property_u64("linux,initrd-end", initrd.initrd_addr + initrd.initrd_size)?;
            }
            None => {}
        }
        fdt.end_node(chosen_node_dep)
    }
}

impl device_tree::CompileFDT for LightMachine {
    fn generate_fdt_node(&self, fdt: &mut FdtBuilder) -> Result<()> {
        let node_dep = fdt.begin_node("")?;
        self.base.generate_fdt_node(fdt)?;
        self.generate_memory_node(fdt)?;
        self.generate_chosen_node(fdt)?;
        fdt.end_node(node_dep)
    }
}
