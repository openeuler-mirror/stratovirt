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

//! # Micro VM
//!
//! Micro VM is a extremely light machine type.
//! It has a very simple machine model, which benefits to a very short
//! boot-time and tiny memory usage.
//!
//! ## Design
//!
//! This module offers support for:
//! 1. Create and manage lifecycle for `Micro VM`.
//! 2. Set cmdline arguments parameters for `Micro VM`.
//! 3. Manage mainloop to handle events for `Micro VM` and its devices.
//!
//! ## Platform Support
//!
//! - `x86_64`
//! - `aarch64`

pub mod error;
pub use error::MicroVmError;
use machine_manager::config::DiskFormat;
use machine_manager::event_loop::EventLoop;
use machine_manager::qmp::qmp_schema::UpdateRegionArgument;
use util::aio::{AioEngine, WriteZeroesState};

mod mem_layout;
mod syscall;

use super::Result as MachineResult;
use log::{error, info};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Condvar, Mutex};
use std::vec::Vec;

use address_space::{AddressSpace, GuestAddress, Region};
use boot_loader::{load_linux, BootLoaderConfig};
#[cfg(target_arch = "aarch64")]
use cpu::CPUFeatures;
#[cfg(target_arch = "aarch64")]
use cpu::PMU_INTR;
use cpu::{CPUBootConfig, CPUTopology, CpuLifecycleState, CpuTopology, CPU};
#[cfg(target_arch = "aarch64")]
use devices::legacy::PL031;
#[cfg(target_arch = "x86_64")]
use devices::legacy::SERIAL_ADDR;
use devices::legacy::{FwCfgOps, Serial};
use devices::sysbus::{SysBus, IRQ_BASE, IRQ_MAX};
#[cfg(target_arch = "aarch64")]
use devices::sysbus::{SysBusDevType, SysRes};
#[cfg(target_arch = "aarch64")]
use devices::{ICGICConfig, ICGICv2Config, ICGICv3Config, InterruptController, GIC_IRQ_MAX};
#[cfg(target_arch = "x86_64")]
use hypervisor::kvm::KVM_FDS;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{kvm_pit_config, KVM_PIT_SPEAKER_DUMMY};
use machine_manager::{
    config::{
        parse_blk, parse_incoming_uri, parse_net, BlkDevConfig, BootSource, ConfigCheck, DriveFile,
        Incoming, MigrateMode, NetworkInterfaceConfig, NumaNodes, SerialConfig, VmConfig,
        DEFAULT_VIRTQUEUE_SIZE,
    },
    event,
    machine::{
        DeviceInterface, KvmVmState, MachineAddressInterface, MachineExternalInterface,
        MachineInterface, MachineLifecycle, MigrateInterface,
    },
    qmp::{qmp_schema, QmpChannel, Response},
};
use mem_layout::{LayoutEntryType, MEM_LAYOUT};
use migration::{MigrationManager, MigrationStatus};
use syscall::syscall_whitelist;
#[cfg(target_arch = "aarch64")]
use util::device_tree::{self, CompileFDT, FdtBuilder};
use util::{
    loop_context::EventLoopManager, num_ops::str_to_usize, seccomp::BpfRule, set_termi_canon_mode,
};
use virtio::{
    create_tap, qmp_balloon, qmp_query_balloon, Block, BlockState, Net, VhostKern, VirtioDevice,
    VirtioMmioDevice, VirtioMmioState, VirtioNetState,
};

use super::{error::MachineError, MachineOps};
#[cfg(target_arch = "x86_64")]
use crate::vm_state;
use anyhow::{anyhow, bail, Context, Result};

// The replaceable block device maximum count.
const MMIO_REPLACEABLE_BLK_NR: usize = 4;
// The replaceable network device maximum count.
const MMIO_REPLACEABLE_NET_NR: usize = 2;

// The config of replaceable device.
#[derive(Debug)]
struct MmioReplaceableConfig {
    // Device id.
    id: String,
    // The dev_config of the related backend device.
    dev_config: Arc<dyn ConfigCheck>,
}

// The device information of replaceable device.
struct MmioReplaceableDevInfo {
    // The related MMIO device.
    device: Arc<Mutex<dyn VirtioDevice>>,
    // Device id.
    id: String,
    // Identify if this device is be used.
    used: bool,
}

impl fmt::Debug for MmioReplaceableDevInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmioReplaceableDevInfo")
            .field("device_type", &self.device.lock().unwrap().device_type())
            .field("id", &self.id)
            .field("used", &self.used)
            .finish()
    }
}

// The gather of config, info and count of all replaceable devices.
#[derive(Debug)]
struct MmioReplaceableInfo {
    // The arrays of all replaceable configs.
    configs: Arc<Mutex<Vec<MmioReplaceableConfig>>>,
    // The arrays of all replaceable device information.
    devices: Arc<Mutex<Vec<MmioReplaceableDevInfo>>>,
    // The count of block device which is plugin.
    block_count: usize,
    // The count of network device which is plugin.
    net_count: usize,
}

impl MmioReplaceableInfo {
    fn new() -> Self {
        MmioReplaceableInfo {
            configs: Arc::new(Mutex::new(Vec::new())),
            devices: Arc::new(Mutex::new(Vec::new())),
            block_count: 0_usize,
            net_count: 0_usize,
        }
    }
}

/// A wrapper around creating and using a kvm-based micro VM.
pub struct LightMachine {
    // `vCPU` topology, support sockets, cores, threads.
    cpu_topo: CpuTopology,
    // `vCPU` family and feature configuration. Only supports aarch64 currently.
    #[cfg(target_arch = "aarch64")]
    cpu_feature: CPUFeatures,
    // `vCPU` devices.
    cpus: Vec<Arc<CPU>>,
    // Interrupt controller device.
    #[cfg(target_arch = "aarch64")]
    irq_chip: Option<Arc<InterruptController>>,
    // Memory address space.
    sys_mem: Arc<AddressSpace>,
    // IO address space.
    #[cfg(target_arch = "x86_64")]
    sys_io: Arc<AddressSpace>,
    // System bus.
    sysbus: SysBus,
    // All replaceable device information.
    replaceable_info: MmioReplaceableInfo,
    // VM running state.
    vm_state: Arc<(Mutex<KvmVmState>, Condvar)>,
    // Vm boot_source config.
    boot_source: Arc<Mutex<BootSource>>,
    // All configuration information of virtual machine.
    vm_config: Arc<Mutex<VmConfig>>,
    // List of guest NUMA nodes information.
    numa_nodes: Option<NumaNodes>,
    // Drive backend files.
    drive_files: Arc<Mutex<HashMap<String, DriveFile>>>,
    // All backend memory region tree.
    machine_ram: Arc<Region>,
}

impl LightMachine {
    /// Constructs a new `LightMachine`.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - Represents the configuration for VM.
    pub fn new(vm_config: &VmConfig) -> MachineResult<Self> {
        let sys_mem = AddressSpace::new(
            Region::init_container_region(u64::max_value(), "SysMem"),
            "sys_mem",
        )
        .with_context(|| MachineError::CrtMemSpaceErr)?;
        #[cfg(target_arch = "x86_64")]
        let sys_io = AddressSpace::new(Region::init_container_region(1 << 16, "SysIo"), "SysIo")
            .with_context(|| MachineError::CrtIoSpaceErr)?;
        let free_irqs: (i32, i32) = (IRQ_BASE, IRQ_MAX);
        let mmio_region: (u64, u64) = (
            MEM_LAYOUT[LayoutEntryType::Mmio as usize].0,
            MEM_LAYOUT[LayoutEntryType::Mmio as usize + 1].0,
        );
        let sysbus = SysBus::new(
            #[cfg(target_arch = "x86_64")]
            &sys_io,
            &sys_mem,
            free_irqs,
            mmio_region,
        );

        // Machine state init
        let vm_state = Arc::new((Mutex::new(KvmVmState::Created), Condvar::new()));

        Ok(LightMachine {
            cpu_topo: CpuTopology::new(
                vm_config.machine_config.nr_cpus,
                vm_config.machine_config.nr_sockets,
                vm_config.machine_config.nr_dies,
                vm_config.machine_config.nr_clusters,
                vm_config.machine_config.nr_cores,
                vm_config.machine_config.nr_threads,
                vm_config.machine_config.max_cpus,
            ),
            cpus: Vec::new(),
            #[cfg(target_arch = "aarch64")]
            cpu_feature: (&vm_config.machine_config.cpu_config).into(),
            #[cfg(target_arch = "aarch64")]
            irq_chip: None,
            sys_mem,
            #[cfg(target_arch = "x86_64")]
            sys_io,
            sysbus,
            replaceable_info: MmioReplaceableInfo::new(),
            boot_source: Arc::new(Mutex::new(vm_config.clone().boot_source)),
            vm_state,
            vm_config: Arc::new(Mutex::new(vm_config.clone())),
            numa_nodes: None,
            drive_files: Arc::new(Mutex::new(vm_config.init_drive_files()?)),
            machine_ram: Arc::new(Region::init_container_region(u64::max_value(), "pc.ram")),
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn arch_init() -> MachineResult<()> {
        let kvm_fds = KVM_FDS.load();
        let vm_fd = kvm_fds.vm_fd.as_ref().unwrap();
        vm_fd
            .set_tss_address(0xfffb_d000_usize)
            .with_context(|| MachineError::SetTssErr)?;

        let pit_config = kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            pad: Default::default(),
        };
        vm_fd
            .create_pit2(pit_config)
            .with_context(|| MachineError::CrtPitErr)?;

        Ok(())
    }

    pub fn mem_show(&self) {
        self.sys_mem.memspace_show();
        #[cfg(target_arch = "x86_64")]
        self.sys_io.memspace_show();

        let machine_ram = self.get_vm_ram();
        machine_ram.mtree(0_u32);
    }

    fn create_replaceable_devices(&mut self) -> Result<()> {
        let mut rpl_devs: Vec<VirtioMmioDevice> = Vec::new();
        for id in 0..MMIO_REPLACEABLE_BLK_NR {
            let block = Arc::new(Mutex::new(Block::new(
                BlkDevConfig::default(),
                self.get_drive_files(),
            )));
            let virtio_mmio = VirtioMmioDevice::new(&self.sys_mem, block.clone());
            rpl_devs.push(virtio_mmio);

            MigrationManager::register_device_instance(
                BlockState::descriptor(),
                block,
                &id.to_string(),
            );
        }
        for id in 0..MMIO_REPLACEABLE_NET_NR {
            let net = Arc::new(Mutex::new(Net::new(NetworkInterfaceConfig::default())));
            let virtio_mmio = VirtioMmioDevice::new(&self.sys_mem, net.clone());
            rpl_devs.push(virtio_mmio);

            MigrationManager::register_device_instance(
                VirtioNetState::descriptor(),
                net,
                &id.to_string(),
            );
        }

        let mut region_base = self.sysbus.min_free_base;
        let region_size = MEM_LAYOUT[LayoutEntryType::Mmio as usize].1;
        for (id, dev) in rpl_devs.into_iter().enumerate() {
            self.replaceable_info
                .devices
                .lock()
                .unwrap()
                .push(MmioReplaceableDevInfo {
                    device: dev.device.clone(),
                    id: id.to_string(),
                    used: false,
                });

            MigrationManager::register_transport_instance(
                VirtioMmioState::descriptor(),
                VirtioMmioDevice::realize(
                    dev,
                    &mut self.sysbus,
                    region_base,
                    MEM_LAYOUT[LayoutEntryType::Mmio as usize].1,
                    #[cfg(target_arch = "x86_64")]
                    &self.boot_source,
                )
                .with_context(|| MicroVmError::RlzVirtioMmioErr)?,
                &id.to_string(),
            );
            region_base += region_size;
        }
        self.sysbus.min_free_base = region_base;
        Ok(())
    }

    fn fill_replaceable_device(
        &mut self,
        id: &str,
        dev_config: Arc<dyn ConfigCheck>,
        index: usize,
    ) -> Result<()> {
        let mut replaceable_devices = self.replaceable_info.devices.lock().unwrap();
        if let Some(device_info) = replaceable_devices.get_mut(index) {
            if device_info.used {
                bail!("{}: index {} is already used.", id, index);
            }

            device_info.id = id.to_string();
            device_info.used = true;
            device_info
                .device
                .lock()
                .unwrap()
                .update_config(Some(dev_config.clone()))
                .with_context(|| MicroVmError::UpdCfgErr(id.to_string()))?;
        }

        self.add_replaceable_config(id, dev_config)?;
        Ok(())
    }

    fn add_replaceable_config(&self, id: &str, dev_config: Arc<dyn ConfigCheck>) -> Result<()> {
        let mut configs_lock = self.replaceable_info.configs.lock().unwrap();
        let limit = MMIO_REPLACEABLE_BLK_NR + MMIO_REPLACEABLE_NET_NR;
        if configs_lock.len() >= limit {
            return Err(anyhow!(MicroVmError::RplDevLmtErr("".to_string(), limit)));
        }

        for config in configs_lock.iter() {
            if config.id == id {
                bail!("{} is already registered.", id);
            }
        }

        let config = MmioReplaceableConfig {
            id: id.to_string(),
            dev_config,
        };

        trace_mmio_replaceable_config(&config);
        configs_lock.push(config);
        Ok(())
    }

    fn add_replaceable_device(&self, id: &str, driver: &str, slot: usize) -> Result<()> {
        // Find the configuration by id.
        let configs_lock = self.replaceable_info.configs.lock().unwrap();
        let mut dev_config = None;
        for config in configs_lock.iter() {
            if config.id == id {
                dev_config = Some(config.dev_config.clone());
            }
        }
        if dev_config.is_none() {
            bail!("Failed to find device configuration.");
        }

        // Sanity check for config, driver and slot.
        let cfg_any = dev_config.as_ref().unwrap().as_any();
        let index = if driver.contains("net") {
            if slot >= MMIO_REPLACEABLE_NET_NR {
                return Err(anyhow!(MicroVmError::RplDevLmtErr(
                    "net".to_string(),
                    MMIO_REPLACEABLE_NET_NR
                )));
            }
            if cfg_any.downcast_ref::<NetworkInterfaceConfig>().is_none() {
                return Err(anyhow!(MicroVmError::DevTypeErr("net".to_string())));
            }
            slot + MMIO_REPLACEABLE_BLK_NR
        } else if driver.contains("blk") {
            if slot >= MMIO_REPLACEABLE_BLK_NR {
                return Err(anyhow!(MicroVmError::RplDevLmtErr(
                    "block".to_string(),
                    MMIO_REPLACEABLE_BLK_NR
                )));
            }
            if cfg_any.downcast_ref::<BlkDevConfig>().is_none() {
                return Err(anyhow!(MicroVmError::DevTypeErr("blk".to_string())));
            }
            slot
        } else {
            bail!("Unsupported replaceable device type.");
        };

        // Find the replaceable device and replace it.
        let mut replaceable_devices = self.replaceable_info.devices.lock().unwrap();
        if let Some(device_info) = replaceable_devices.get_mut(index) {
            if device_info.used {
                bail!("The slot {} is occupied already.", slot);
            }

            device_info.id = id.to_string();
            device_info.used = true;
            device_info
                .device
                .lock()
                .unwrap()
                .update_config(dev_config)
                .with_context(|| MicroVmError::UpdCfgErr(id.to_string()))?;
        }
        Ok(())
    }

    fn del_replaceable_device(&self, id: &str) -> Result<String> {
        // find the index of configuration by name and remove it
        let mut is_exist = false;
        let mut configs_lock = self.replaceable_info.configs.lock().unwrap();
        for (index, config) in configs_lock.iter().enumerate() {
            if config.id == id {
                if let Some(blkconf) = config.dev_config.as_any().downcast_ref::<BlkDevConfig>() {
                    self.unregister_drive_file(&blkconf.path_on_host)?;
                }
                configs_lock.remove(index);
                is_exist = true;
                break;
            }
        }

        // set the status of the device to 'unused'
        let mut replaceable_devices = self.replaceable_info.devices.lock().unwrap();
        for device_info in replaceable_devices.iter_mut() {
            if device_info.id == id {
                device_info.id = "".to_string();
                device_info.used = false;
                device_info
                    .device
                    .lock()
                    .unwrap()
                    .update_config(None)
                    .with_context(|| MicroVmError::UpdCfgErr(id.to_string()))?;
            }
        }

        if !is_exist {
            bail!("Device {} not found", id);
        }
        Ok(id.to_string())
    }

    /// Must be called after the CPUs have been realized and GIC has been created.
    #[cfg(target_arch = "aarch64")]
    fn cpu_post_init(&self, vcpu_cfg: &Option<CPUFeatures>) -> Result<()> {
        let features = vcpu_cfg.unwrap_or_default();
        if features.pmu {
            for cpu in self.cpus.iter() {
                cpu.init_pmu()?;
            }
        }
        Ok(())
    }
}

impl MachineOps for LightMachine {
    fn init_machine_ram(&self, sys_mem: &Arc<AddressSpace>, mem_size: u64) -> Result<()> {
        let vm_ram = self.get_vm_ram();

        #[cfg(target_arch = "aarch64")]
        {
            let layout_size = MEM_LAYOUT[LayoutEntryType::Mem as usize].1;
            let ram = Region::init_alias_region(
                vm_ram.clone(),
                0,
                std::cmp::min(layout_size, mem_size),
                "pc_ram",
            );
            sys_mem
                .root()
                .add_subregion(ram, MEM_LAYOUT[LayoutEntryType::Mem as usize].0)?;
        }
        #[cfg(target_arch = "x86_64")]
        {
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
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn init_interrupt_controller(&mut self, _vcpu_count: u64) -> MachineResult<()> {
        KVM_FDS
            .load()
            .vm_fd
            .as_ref()
            .unwrap()
            .create_irq_chip()
            .with_context(|| MachineError::CrtIrqchipErr)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn init_interrupt_controller(&mut self, vcpu_count: u64) -> MachineResult<()> {
        // Interrupt Controller Chip init
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
        let irq_chip = InterruptController::new(&intc_conf)?;
        self.irq_chip = Some(Arc::new(irq_chip));
        self.irq_chip.as_ref().unwrap().realize()?;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn load_boot_source(
        &self,
        fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>,
    ) -> MachineResult<CPUBootConfig> {
        let boot_source = self.boot_source.lock().unwrap();
        let initrd = boot_source.initrd.as_ref().map(|b| b.initrd_file.clone());

        let gap_start = MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].0
            + MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].1;
        let gap_end = MEM_LAYOUT[LayoutEntryType::MemAbove4g as usize].0;
        let bootloader_config = BootLoaderConfig {
            kernel: boot_source.kernel_file.clone(),
            initrd,
            kernel_cmdline: boot_source.kernel_cmdline.to_string(),
            cpu_count: self.cpu_topo.nrcpus,
            gap_range: (gap_start, gap_end - gap_start),
            ioapic_addr: MEM_LAYOUT[LayoutEntryType::IoApic as usize].0 as u32,
            lapic_addr: MEM_LAYOUT[LayoutEntryType::LocalApic as usize].0 as u32,
            ident_tss_range: None,
            prot64_mode: true,
        };
        let layout = load_linux(&bootloader_config, &self.sys_mem, fwcfg)
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

    #[cfg(target_arch = "aarch64")]
    fn load_boot_source(
        &self,
        fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>,
    ) -> MachineResult<CPUBootConfig> {
        let mut boot_source = self.boot_source.lock().unwrap();
        let initrd = boot_source.initrd.as_ref().map(|b| b.initrd_file.clone());

        let bootloader_config = BootLoaderConfig {
            kernel: boot_source.kernel_file.clone(),
            initrd,
            mem_start: MEM_LAYOUT[LayoutEntryType::Mem as usize].0,
        };
        let layout = load_linux(&bootloader_config, &self.sys_mem, fwcfg)
            .with_context(|| MachineError::LoadKernErr)?;
        if let Some(rd) = &mut boot_source.initrd {
            rd.initrd_addr = layout.initrd_start;
            rd.initrd_size = layout.initrd_size;
        }

        Ok(CPUBootConfig {
            fdt_addr: layout.dtb_start,
            boot_pc: layout.boot_pc,
        })
    }

    fn realize_virtio_mmio_device(
        &mut self,
        dev: VirtioMmioDevice,
    ) -> MachineResult<Arc<Mutex<VirtioMmioDevice>>> {
        let region_base = self.sysbus.min_free_base;
        let region_size = MEM_LAYOUT[LayoutEntryType::Mmio as usize].1;
        let realized_virtio_mmio_device = VirtioMmioDevice::realize(
            dev,
            &mut self.sysbus,
            region_base,
            region_size,
            #[cfg(target_arch = "x86_64")]
            &self.boot_source,
        )
        .with_context(|| MicroVmError::RlzVirtioMmioErr)?;
        self.sysbus.min_free_base += region_size;
        Ok(realized_virtio_mmio_device)
    }

    fn get_sys_mem(&mut self) -> &Arc<AddressSpace> {
        &self.sys_mem
    }

    fn get_vm_config(&self) -> Arc<Mutex<VmConfig>> {
        self.vm_config.clone()
    }

    fn get_vm_state(&self) -> &Arc<(Mutex<KvmVmState>, Condvar)> {
        &self.vm_state
    }

    fn get_migrate_info(&self) -> Incoming {
        if let Some((mode, path)) = self.get_vm_config().lock().unwrap().incoming.as_ref() {
            return (*mode, path.to_string());
        }

        (MigrateMode::Unknown, String::new())
    }

    fn get_sys_bus(&mut self) -> &SysBus {
        &self.sysbus
    }

    fn get_vm_ram(&self) -> &Arc<Region> {
        &self.machine_ram
    }

    fn get_numa_nodes(&self) -> &Option<NumaNodes> {
        &self.numa_nodes
    }

    #[cfg(target_arch = "aarch64")]
    fn add_rtc_device(&mut self) -> MachineResult<()> {
        PL031::realize(
            PL031::default(),
            &mut self.sysbus,
            MEM_LAYOUT[LayoutEntryType::Rtc as usize].0,
            MEM_LAYOUT[LayoutEntryType::Rtc as usize].1,
        )
        .with_context(|| "Failed to realize pl031.")?;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn add_rtc_device(&mut self, _mem_size: u64) -> MachineResult<()> {
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn add_ged_device(&mut self) -> MachineResult<()> {
        Ok(())
    }

    fn add_serial_device(&mut self, config: &SerialConfig) -> MachineResult<()> {
        #[cfg(target_arch = "x86_64")]
        let region_base: u64 = SERIAL_ADDR;
        #[cfg(target_arch = "aarch64")]
        let region_base: u64 = MEM_LAYOUT[LayoutEntryType::Uart as usize].0;
        #[cfg(target_arch = "x86_64")]
        let region_size: u64 = 8;
        #[cfg(target_arch = "aarch64")]
        let region_size: u64 = MEM_LAYOUT[LayoutEntryType::Uart as usize].1;

        let serial = Serial::new(config.clone());
        serial
            .realize(
                &mut self.sysbus,
                region_base,
                region_size,
                #[cfg(target_arch = "aarch64")]
                &self.boot_source,
            )
            .with_context(|| "Failed to realize serial device.")?;
        Ok(())
    }

    fn add_virtio_mmio_net(
        &mut self,
        vm_config: &mut VmConfig,
        cfg_args: &str,
    ) -> MachineResult<()> {
        let device_cfg = parse_net(vm_config, cfg_args)?;
        if device_cfg.vhost_type.is_some() {
            let net = Arc::new(Mutex::new(VhostKern::Net::new(&device_cfg, &self.sys_mem)));
            net.lock().unwrap().disable_irqfd = true;
            let device = VirtioMmioDevice::new(&self.sys_mem, net);
            self.realize_virtio_mmio_device(device)?;
        } else {
            let index = MMIO_REPLACEABLE_BLK_NR + self.replaceable_info.net_count;
            if index >= MMIO_REPLACEABLE_BLK_NR + MMIO_REPLACEABLE_NET_NR {
                bail!(
                    "A maximum of {} net replaceable devices are supported.",
                    MMIO_REPLACEABLE_NET_NR
                );
            }
            self.fill_replaceable_device(&device_cfg.id, Arc::new(device_cfg.clone()), index)?;
            self.replaceable_info.net_count += 1;
        }
        Ok(())
    }

    fn add_virtio_mmio_block(
        &mut self,
        vm_config: &mut VmConfig,
        cfg_args: &str,
    ) -> MachineResult<()> {
        let device_cfg = parse_blk(vm_config, cfg_args, None)?;
        if self.replaceable_info.block_count >= MMIO_REPLACEABLE_BLK_NR {
            bail!(
                "A maximum of {} block replaceable devices are supported.",
                MMIO_REPLACEABLE_BLK_NR
            );
        }
        let index = self.replaceable_info.block_count;
        self.fill_replaceable_device(&device_cfg.id, Arc::new(device_cfg.clone()), index)?;
        self.replaceable_info.block_count += 1;
        Ok(())
    }

    fn syscall_whitelist(&self) -> Vec<BpfRule> {
        syscall_whitelist()
    }

    fn get_drive_files(&self) -> Arc<Mutex<HashMap<String, DriveFile>>> {
        self.drive_files.clone()
    }

    fn realize(vm: &Arc<Mutex<Self>>, vm_config: &mut VmConfig) -> MachineResult<()> {
        let mut locked_vm = vm.lock().unwrap();

        //trace for lightmachine
        trace_sysbus(&locked_vm.sysbus);
        trace_vm_state(&locked_vm.vm_state);

        let topology = CPUTopology::new().set_topology((
            vm_config.machine_config.nr_threads,
            vm_config.machine_config.nr_cores,
            vm_config.machine_config.nr_dies,
        ));
        trace_cpu_topo(&topology);
        locked_vm.numa_nodes = locked_vm.add_numa_nodes(vm_config)?;
        locked_vm.init_memory(
            &vm_config.machine_config.mem_config,
            #[cfg(target_arch = "x86_64")]
            &locked_vm.sys_io,
            &locked_vm.sys_mem,
            vm_config.machine_config.nr_cpus,
        )?;

        let migrate_info = locked_vm.get_migrate_info();

        #[cfg(target_arch = "x86_64")]
        {
            locked_vm.init_interrupt_controller(u64::from(vm_config.machine_config.nr_cpus))?;
            LightMachine::arch_init()?;

            // Add mmio devices
            locked_vm
                .create_replaceable_devices()
                .with_context(|| "Failed to create replaceable devices.")?;
            locked_vm.add_devices(vm_config)?;
            trace_replaceable_info(&locked_vm.replaceable_info);

            let boot_config = if migrate_info.0 == MigrateMode::Unknown {
                Some(locked_vm.load_boot_source(None)?)
            } else {
                None
            };

            // vCPUs init
            locked_vm.cpus.extend(<Self as MachineOps>::init_vcpu(
                vm.clone(),
                vm_config.machine_config.nr_cpus,
                &topology,
                &boot_config,
            )?);
        }

        #[cfg(target_arch = "aarch64")]
        {
            let (boot_config, cpu_config) = if migrate_info.0 == MigrateMode::Unknown {
                (
                    Some(locked_vm.load_boot_source(None)?),
                    Some(locked_vm.load_cpu_features(vm_config)?),
                )
            } else {
                (None, None)
            };

            // vCPUs init,and apply CPU features (for aarch64)
            locked_vm.cpus.extend(<Self as MachineOps>::init_vcpu(
                vm.clone(),
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
            trace_replaceable_info(&locked_vm.replaceable_info);

            if let Some(boot_cfg) = boot_config {
                let mut fdt_helper = FdtBuilder::new();
                locked_vm
                    .generate_fdt_node(&mut fdt_helper)
                    .with_context(|| MachineError::GenFdtErr)?;
                let fdt_vec = fdt_helper.finish()?;
                locked_vm
                    .sys_mem
                    .write(
                        &mut fdt_vec.as_slice(),
                        GuestAddress(boot_cfg.fdt_addr),
                        fdt_vec.len() as u64,
                    )
                    .with_context(|| MachineError::WrtFdtErr(boot_cfg.fdt_addr, fdt_vec.len()))?;
            }
        }

        MigrationManager::register_vm_instance(vm.clone());
        #[cfg(target_arch = "x86_64")]
        MigrationManager::register_kvm_instance(
            vm_state::KvmDeviceState::descriptor(),
            Arc::new(vm_state::KvmDevice {}),
        );
        if let Err(e) = MigrationManager::set_status(MigrationStatus::Setup) {
            bail!("Failed to set migration status {}", e);
        }

        Ok(())
    }

    fn run(&self, paused: bool) -> MachineResult<()> {
        self.vm_start(paused, &self.cpus, &mut self.vm_state.0.lock().unwrap())
    }
}

impl MachineLifecycle for LightMachine {
    fn pause(&self) -> bool {
        if self.notify_lifecycle(KvmVmState::Running, KvmVmState::Paused) {
            event!(Stop);
            true
        } else {
            false
        }
    }

    fn resume(&self) -> bool {
        if !self.notify_lifecycle(KvmVmState::Paused, KvmVmState::Running) {
            return false;
        }

        event!(Resume);
        true
    }

    fn destroy(&self) -> bool {
        let vmstate = {
            let state = self.vm_state.deref().0.lock().unwrap();
            *state
        };

        if !self.notify_lifecycle(vmstate, KvmVmState::Shutdown) {
            return false;
        }

        info!("vm destroy");
        EventLoop::get_ctx(None).unwrap().kick();

        true
    }

    fn reset(&mut self) -> bool {
        // For micro vm, the reboot command is equivalent to the shutdown command.
        for cpu in self.cpus.iter() {
            let (cpu_state, _) = cpu.state();
            *cpu_state.lock().unwrap() = CpuLifecycleState::Stopped;
        }

        self.destroy()
    }

    fn notify_lifecycle(&self, old: KvmVmState, new: KvmVmState) -> bool {
        if let Err(e) = self.vm_state_transfer(
            &self.cpus,
            #[cfg(target_arch = "aarch64")]
            &self.irq_chip,
            &mut self.vm_state.0.lock().unwrap(),
            old,
            new,
        ) {
            error!("VM state transfer failed: {:?}", e);
            return false;
        }
        true
    }
}

impl MachineAddressInterface for LightMachine {
    #[cfg(target_arch = "x86_64")]
    fn pio_in(&self, addr: u64, mut data: &mut [u8]) -> bool {
        // The function pit_calibrate_tsc() in kernel gets stuck if data read from
        // io-port 0x61 is not 0x20.
        // This problem only happens before Linux version 4.18 (fixed by 368a540e0)
        if addr == 0x61 {
            data[0] = 0x20;
            return true;
        }
        let length = data.len() as u64;
        self.sys_io
            .read(&mut data, GuestAddress(addr), length)
            .is_ok()
    }

    #[cfg(target_arch = "x86_64")]
    fn pio_out(&self, addr: u64, mut data: &[u8]) -> bool {
        let count = data.len() as u64;
        self.sys_io
            .write(&mut data, GuestAddress(addr), count)
            .is_ok()
    }

    fn mmio_read(&self, addr: u64, mut data: &mut [u8]) -> bool {
        let length = data.len() as u64;
        self.sys_mem
            .read(&mut data, GuestAddress(addr), length)
            .is_ok()
    }

    fn mmio_write(&self, addr: u64, mut data: &[u8]) -> bool {
        let count = data.len() as u64;
        self.sys_mem
            .write(&mut data, GuestAddress(addr), count)
            .is_ok()
    }
}

impl DeviceInterface for LightMachine {
    fn query_status(&self) -> Response {
        let vmstate = self.get_vm_state().deref().0.lock().unwrap();
        let qmp_state = match *vmstate {
            KvmVmState::Running => qmp_schema::StatusInfo {
                singlestep: false,
                running: true,
                status: qmp_schema::RunState::running,
            },
            KvmVmState::Paused => qmp_schema::StatusInfo {
                singlestep: false,
                running: false,
                status: qmp_schema::RunState::paused,
            },
            _ => Default::default(),
        };

        Response::create_response(serde_json::to_value(&qmp_state).unwrap(), None)
    }

    fn query_cpus(&self) -> Response {
        let mut cpu_vec: Vec<serde_json::Value> = Vec::new();
        for cpu_index in 0..self.cpu_topo.max_cpus {
            if self.cpu_topo.get_mask(cpu_index as usize) == 1 {
                let thread_id = self.cpus[cpu_index as usize].tid();
                let cpu_instance = self.cpu_topo.get_topo_instance_for_qmp(cpu_index as usize);
                let cpu_common = qmp_schema::CpuInfoCommon {
                    current: true,
                    qom_path: String::from("/machine/unattached/device[")
                        + &cpu_index.to_string()
                        + "]",
                    halted: false,
                    props: Some(cpu_instance),
                    CPU: cpu_index as isize,
                    thread_id: thread_id as isize,
                };
                #[cfg(target_arch = "x86_64")]
                {
                    let cpu_info = qmp_schema::CpuInfo::x86 {
                        common: cpu_common,
                        x86: qmp_schema::CpuInfoX86 {},
                    };
                    cpu_vec.push(serde_json::to_value(cpu_info).unwrap());
                }
                #[cfg(target_arch = "aarch64")]
                {
                    let cpu_info = qmp_schema::CpuInfo::Arm {
                        common: cpu_common,
                        arm: qmp_schema::CpuInfoArm {},
                    };
                    cpu_vec.push(serde_json::to_value(cpu_info).unwrap());
                }
            }
        }
        Response::create_response(cpu_vec.into(), None)
    }

    fn query_hotpluggable_cpus(&self) -> Response {
        let mut hotplug_vec: Vec<serde_json::Value> = Vec::new();
        #[cfg(target_arch = "x86_64")]
        let cpu_type = String::from("host-x86-cpu");
        #[cfg(target_arch = "aarch64")]
        let cpu_type = String::from("host-aarch64-cpu");

        for cpu_index in 0..self.cpu_topo.max_cpus {
            if self.cpu_topo.get_mask(cpu_index as usize) == 0 {
                let cpu_instance = self.cpu_topo.get_topo_instance_for_qmp(cpu_index as usize);
                let hotpluggable_cpu = qmp_schema::HotpluggableCPU {
                    type_: cpu_type.clone(),
                    vcpus_count: 1,
                    props: cpu_instance,
                    qom_path: None,
                };
                hotplug_vec.push(serde_json::to_value(hotpluggable_cpu).unwrap());
            } else {
                let cpu_instance = self.cpu_topo.get_topo_instance_for_qmp(cpu_index as usize);
                let hotpluggable_cpu = qmp_schema::HotpluggableCPU {
                    type_: cpu_type.clone(),
                    vcpus_count: 1,
                    props: cpu_instance,
                    qom_path: Some(
                        String::from("/machine/unattached/device[") + &cpu_index.to_string() + "]",
                    ),
                };
                hotplug_vec.push(serde_json::to_value(hotpluggable_cpu).unwrap());
            }
        }
        Response::create_response(hotplug_vec.into(), None)
    }

    fn balloon(&self, value: u64) -> Response {
        if qmp_balloon(value) {
            return Response::create_empty_response();
        }
        Response::create_error_response(
            qmp_schema::QmpErrorClass::DeviceNotActive(
                "No balloon device has been activated".to_string(),
            ),
            None,
        )
    }

    fn query_balloon(&self) -> Response {
        if let Some(actual) = qmp_query_balloon() {
            let ret = qmp_schema::BalloonInfo { actual };
            return Response::create_response(serde_json::to_value(&ret).unwrap(), None);
        }
        Response::create_error_response(
            qmp_schema::QmpErrorClass::DeviceNotActive(
                "No balloon device has been activated".to_string(),
            ),
            None,
        )
    }

    fn query_mem(&self) -> Response {
        self.mem_show();
        Response::create_empty_response()
    }

    /// VNC is not supported by light machine currently.
    fn query_vnc(&self) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(
                "The service of VNC is not supported".to_string(),
            ),
            None,
        )
    }

    fn device_add(&mut self, args: Box<qmp_schema::DeviceAddArgument>) -> Response {
        // get slot of bus by addr or lun
        let mut slot = 0;
        if let Some(addr) = args.addr {
            if let Ok(num) = str_to_usize(addr) {
                slot = num;
            } else {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(format!(
                        "Invalid addr for device {}",
                        args.id
                    )),
                    None,
                );
            }
        } else if let Some(lun) = args.lun {
            slot = lun + 1;
        }

        match self.add_replaceable_device(&args.id, &args.driver, slot) {
            Ok(()) => Response::create_empty_response(),
            Err(ref e) => {
                error!("{:?}", e);
                error!("Failed to add device: id {}, type {}", args.id, args.driver);
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        }
    }

    fn device_del(&mut self, device_id: String) -> Response {
        match self.del_replaceable_device(&device_id) {
            Ok(path) => {
                let block_del_event = qmp_schema::DeviceDeleted {
                    device: Some(device_id),
                    path,
                };
                event!(DeviceDeleted; block_del_event);

                Response::create_empty_response()
            }
            Err(ref e) => {
                error!("Failed to delete device: {:?}", e);
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        }
    }

    fn blockdev_add(&self, args: Box<qmp_schema::BlockDevAddArgument>) -> Response {
        let read_only = args.read_only.unwrap_or(false);
        let mut direct = true;
        if args.cache.is_some() && !args.cache.unwrap().direct.unwrap_or(true) {
            direct = false;
        }

        let config = BlkDevConfig {
            id: args.node_name.clone(),
            path_on_host: args.file.filename.clone(),
            read_only,
            direct,
            serial_num: None,
            iothread: None,
            iops: None,
            queues: 1,
            boot_index: None,
            chardev: None,
            socket_path: None,
            // TODO Add aio option by qmp, now we set it based on "direct".
            aio: if direct {
                AioEngine::Native
            } else {
                AioEngine::Off
            },
            queue_size: DEFAULT_VIRTQUEUE_SIZE,
            discard: false,
            write_zeroes: WriteZeroesState::Off,
            format: DiskFormat::Raw,
            l2_cache_size: None,
            refcount_cache_size: None,
        };
        if let Err(e) = config.check() {
            error!("{:?}", e);
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            );
        }
        // Register drive backend file for hotplugged drive.
        if let Err(e) = self.register_drive_file(&config.id, &args.file.filename, read_only, direct)
        {
            error!("{:?}", e);
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            );
        }
        match self.add_replaceable_config(&args.node_name, Arc::new(config)) {
            Ok(()) => Response::create_empty_response(),
            Err(ref e) => {
                error!("{:?}", e);
                // It's safe to unwrap as the path has been registered.
                self.unregister_drive_file(&args.file.filename).unwrap();
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        }
    }

    fn blockdev_del(&self, _node_name: String) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError("blockdev_del not support yet".to_string()),
            None,
        )
    }

    fn netdev_add(&mut self, args: Box<qmp_schema::NetDevAddArgument>) -> Response {
        let mut config = NetworkInterfaceConfig {
            id: args.id.clone(),
            host_dev_name: "".to_string(),
            mac: None,
            tap_fds: None,
            vhost_type: None,
            vhost_fds: None,
            iothread: None,
            queues: 2,
            mq: false,
            socket_path: None,
            queue_size: DEFAULT_VIRTQUEUE_SIZE,
        };

        if let Some(fds) = args.fds {
            let netdev_fd = if fds.contains(':') {
                let col: Vec<_> = fds.split(':').collect();
                String::from(col[col.len() - 1])
            } else {
                String::from(&fds)
            };

            if let Some(fd_num) = QmpChannel::get_fd(&netdev_fd) {
                config.tap_fds = Some(vec![fd_num]);
            } else {
                // try to convert string to RawFd
                let fd_num = match netdev_fd.parse::<i32>() {
                    Ok(fd) => fd,
                    _ => {
                        error!(
                            "Add netdev error: failed to convert {} to RawFd.",
                            netdev_fd
                        );
                        return Response::create_error_response(
                            qmp_schema::QmpErrorClass::GenericError(
                                "Add netdev error: failed to convert {} to RawFd.".to_string(),
                            ),
                            None,
                        );
                    }
                };
                config.tap_fds = Some(vec![fd_num]);
            }
        } else if let Some(if_name) = args.if_name {
            config.host_dev_name = if_name.clone();
            if create_tap(None, Some(&if_name), 1).is_err() {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(
                        "Tap device already in use".to_string(),
                    ),
                    None,
                );
            }
        }

        match self.add_replaceable_config(&args.id, Arc::new(config)) {
            Ok(()) => Response::create_empty_response(),
            Err(ref e) => {
                error!("{:?}", e);
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        }
    }

    fn netdev_del(&mut self, _node_name: String) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError("netdev_del not support yet".to_string()),
            None,
        )
    }

    fn chardev_add(&mut self, _args: qmp_schema::CharDevAddArgument) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(
                "chardev_add not supported yet for microVM".to_string(),
            ),
            None,
        )
    }

    fn chardev_remove(&mut self, _id: String) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(
                "chardev_remove not supported yet for microVM".to_string(),
            ),
            None,
        )
    }

    fn cameradev_add(&mut self, _args: qmp_schema::CameraDevAddArgument) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(
                "cameradev_add not supported for MicroVM".to_string(),
            ),
            None,
        )
    }

    fn cameradev_del(&mut self, _id: String) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(
                "cameradev_del not supported for MicroVM".to_string(),
            ),
            None,
        )
    }

    fn getfd(&self, fd_name: String, if_fd: Option<RawFd>) -> Response {
        if let Some(fd) = if_fd {
            QmpChannel::set_fd(fd_name, fd);
            Response::create_empty_response()
        } else {
            let err_resp =
                qmp_schema::QmpErrorClass::GenericError("Invalid SCM message".to_string());
            Response::create_error_response(err_resp, None)
        }
    }

    fn update_region(&mut self, _args: UpdateRegionArgument) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError("The micro vm is not supported".to_string()),
            None,
        )
    }
}

impl MigrateInterface for LightMachine {
    fn migrate(&self, uri: String) -> Response {
        match parse_incoming_uri(&uri) {
            Ok((MigrateMode::File, path)) => migration::snapshot(path),
            Ok((MigrateMode::Unix, _)) | Ok((MigrateMode::Tcp, _)) => {
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(
                        "MicroVM does not support migration".to_string(),
                    ),
                    None,
                )
            }
            _ => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(format!("Invalid uri: {}", uri)),
                None,
            ),
        }
    }

    fn query_migrate(&self) -> Response {
        migration::query_migrate()
    }
}

impl MachineInterface for LightMachine {}
impl MachineExternalInterface for LightMachine {}

impl EventLoopManager for LightMachine {
    fn loop_should_exit(&self) -> bool {
        let vmstate = self.vm_state.deref().0.lock().unwrap();
        *vmstate == KvmVmState::Shutdown
    }

    fn loop_cleanup(&self) -> util::Result<()> {
        set_termi_canon_mode().with_context(|| "Failed to set terminal to canonical mode")?;
        Ok(())
    }
}

// Function that helps to generate serial node in device-tree.
//
// # Arguments
//
// * `dev_info` - Device resource info of serial device.
// * `fdt` - Flatted device-tree blob where serial node will be filled into.
#[cfg(target_arch = "aarch64")]
fn generate_serial_device_node(fdt: &mut FdtBuilder, res: &SysRes) -> util::Result<()> {
    let node = format!("uart@{:x}", res.region_base);
    let serial_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "ns16550a")?;
    fdt.set_property_string("clock-names", "apb_pclk")?;
    fdt.set_property_u32("clocks", device_tree::CLK_PHANDLE)?;
    fdt.set_property_array_u64("reg", &[res.region_base, res.region_size])?;
    fdt.set_property_array_u32(
        "interrupts",
        &[
            device_tree::GIC_FDT_IRQ_TYPE_SPI,
            res.irq as u32,
            device_tree::IRQ_TYPE_EDGE_RISING,
        ],
    )?;
    fdt.end_node(serial_node_dep)?;

    Ok(())
}

// Function that helps to generate RTC node in device-tree.
//
// # Arguments
//
// * `dev_info` - Device resource info of RTC device.
// * `fdt` - Flatted device-tree blob where RTC node will be filled into.
#[cfg(target_arch = "aarch64")]
fn generate_rtc_device_node(fdt: &mut FdtBuilder, res: &SysRes) -> util::Result<()> {
    let node = format!("pl031@{:x}", res.region_base);
    let rtc_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "arm,pl031\0arm,primecell\0")?;
    fdt.set_property_string("clock-names", "apb_pclk")?;
    fdt.set_property_u32("clocks", device_tree::CLK_PHANDLE)?;
    fdt.set_property_array_u64("reg", &[res.region_base, res.region_size])?;
    fdt.set_property_array_u32(
        "interrupts",
        &[
            device_tree::GIC_FDT_IRQ_TYPE_SPI,
            res.irq as u32,
            device_tree::IRQ_TYPE_LEVEL_HIGH,
        ],
    )?;
    fdt.end_node(rtc_node_dep)?;

    Ok(())
}

// Function that helps to generate Virtio-Mmio device's node in device-tree.
//
// # Arguments
//
// * `dev_info` - Device resource info of Virtio-Mmio device.
// * `fdt` - Flatted device-tree blob where node will be filled into.
#[cfg(target_arch = "aarch64")]
fn generate_virtio_devices_node(fdt: &mut FdtBuilder, res: &SysRes) -> util::Result<()> {
    let node = format!("virtio_mmio@{:x}", res.region_base);
    let virtio_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "virtio,mmio")?;
    fdt.set_property_u32("interrupt-parent", device_tree::GIC_PHANDLE)?;
    fdt.set_property_array_u64("reg", &[res.region_base, res.region_size])?;
    fdt.set_property_array_u32(
        "interrupts",
        &[
            device_tree::GIC_FDT_IRQ_TYPE_SPI,
            res.irq as u32,
            device_tree::IRQ_TYPE_EDGE_RISING,
        ],
    )?;
    fdt.end_node(virtio_node_dep)?;
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn generate_pmu_node(fdt: &mut FdtBuilder) -> util::Result<()> {
    let node = "pmu";
    let pmu_node_dep = fdt.begin_node(node)?;
    fdt.set_property_string("compatible", "arm,armv8-pmuv3")?;
    fdt.set_property_u32("interrupt-parent", device_tree::GIC_PHANDLE)?;
    fdt.set_property_array_u32(
        "interrupts",
        &[
            device_tree::GIC_FDT_IRQ_TYPE_PPI,
            PMU_INTR,
            device_tree::IRQ_TYPE_LEVEL_HIGH,
        ],
    )?;

    fdt.end_node(pmu_node_dep)?;
    Ok(())
}

/// Trait that helps to generate all nodes in device-tree.
#[allow(clippy::upper_case_acronyms)]
#[cfg(target_arch = "aarch64")]
trait CompileFDTHelper {
    /// Function that helps to generate cpu nodes.
    fn generate_cpu_nodes(&self, fdt: &mut FdtBuilder) -> util::Result<()>;
    /// Function that helps to generate memory nodes.
    fn generate_memory_node(&self, fdt: &mut FdtBuilder) -> util::Result<()>;
    /// Function that helps to generate Virtio-mmio devices' nodes.
    fn generate_devices_node(&self, fdt: &mut FdtBuilder) -> util::Result<()>;
    /// Function that helps to generate the chosen node.
    fn generate_chosen_node(&self, fdt: &mut FdtBuilder) -> util::Result<()>;
}

#[cfg(target_arch = "aarch64")]
impl CompileFDTHelper for LightMachine {
    fn generate_cpu_nodes(&self, fdt: &mut FdtBuilder) -> util::Result<()> {
        let node = "cpus";

        let cpus_node_dep = fdt.begin_node(node)?;
        fdt.set_property_u32("#address-cells", 0x02)?;
        fdt.set_property_u32("#size-cells", 0x0)?;

        // Generate CPU topology
        let cpu_map_node_dep = fdt.begin_node("cpu-map")?;
        for socket in 0..self.cpu_topo.sockets {
            let sock_name = format!("cluster{}", socket);
            let sock_node_dep = fdt.begin_node(&sock_name)?;
            for cluster in 0..self.cpu_topo.clusters {
                let clster = format!("cluster{}", cluster);
                let cluster_node_dep = fdt.begin_node(&clster)?;

                for core in 0..self.cpu_topo.cores {
                    let core_name = format!("core{}", core);
                    let core_node_dep = fdt.begin_node(&core_name)?;

                    for thread in 0..self.cpu_topo.threads {
                        let thread_name = format!("thread{}", thread);
                        let thread_node_dep = fdt.begin_node(&thread_name)?;
                        let vcpuid = self.cpu_topo.threads
                            * self.cpu_topo.cores
                            * self.cpu_topo.clusters
                            * socket
                            + self.cpu_topo.threads * self.cpu_topo.cores * cluster
                            + self.cpu_topo.threads * core
                            + thread;
                        fdt.set_property_u32(
                            "cpu",
                            u32::from(vcpuid) + device_tree::CPU_PHANDLE_START,
                        )?;
                        fdt.end_node(thread_node_dep)?;
                    }
                    fdt.end_node(core_node_dep)?;
                }
                fdt.end_node(cluster_node_dep)?;
            }
            fdt.end_node(sock_node_dep)?;
        }
        fdt.end_node(cpu_map_node_dep)?;

        for cpu_index in 0..self.cpu_topo.nrcpus {
            let mpidr = self.cpus[cpu_index as usize].arch().lock().unwrap().mpidr();

            let node = format!("cpu@{:x}", mpidr);
            let mpidr_node_dep = fdt.begin_node(&node)?;
            fdt.set_property_u32(
                "phandle",
                u32::from(cpu_index) + device_tree::CPU_PHANDLE_START,
            )?;
            fdt.set_property_string("device_type", "cpu")?;
            fdt.set_property_string("compatible", "arm,arm-v8")?;
            if self.cpu_topo.max_cpus > 1 {
                fdt.set_property_string("enable-method", "psci")?;
            }
            fdt.set_property_u64("reg", mpidr & 0x007F_FFFF)?;
            fdt.end_node(mpidr_node_dep)?;
        }

        fdt.end_node(cpus_node_dep)?;

        // CPU Features : PMU
        if self.cpu_feature.pmu {
            generate_pmu_node(fdt)?;
        }

        Ok(())
    }

    fn generate_memory_node(&self, fdt: &mut FdtBuilder) -> util::Result<()> {
        let mem_base = MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
        let mem_size = self.sys_mem.memory_end_address().raw_value()
            - MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
        let node = "memory";
        let memory_node_dep = fdt.begin_node(node)?;
        fdt.set_property_string("device_type", "memory")?;
        fdt.set_property_array_u64("reg", &[mem_base, mem_size])?;
        fdt.end_node(memory_node_dep)?;

        Ok(())
    }

    fn generate_devices_node(&self, fdt: &mut FdtBuilder) -> util::Result<()> {
        // timer
        let mut cells: Vec<u32> = Vec::new();
        for &irq in [13, 14, 11, 10].iter() {
            cells.push(device_tree::GIC_FDT_IRQ_TYPE_PPI);
            cells.push(irq);
            cells.push(device_tree::IRQ_TYPE_LEVEL_HIGH);
        }
        let node = "timer";
        let timer_node_dep = fdt.begin_node(node)?;
        fdt.set_property_string("compatible", "arm,armv8-timer")?;
        fdt.set_property("always-on", &Vec::new())?;
        fdt.set_property_array_u32("interrupts", &cells)?;
        fdt.end_node(timer_node_dep)?;

        // clock
        let node = "apb-pclk";
        let clock_node_dep = fdt.begin_node(node)?;
        fdt.set_property_string("compatible", "fixed-clock")?;
        fdt.set_property_string("clock-output-names", "clk24mhz")?;
        fdt.set_property_u32("#clock-cells", 0x0)?;
        fdt.set_property_u32("clock-frequency", 24_000_000)?;
        fdt.set_property_u32("phandle", device_tree::CLK_PHANDLE)?;
        fdt.end_node(clock_node_dep)?;

        // psci
        let node = "psci";
        let psci_node_dep = fdt.begin_node(node)?;
        fdt.set_property_string("compatible", "arm,psci-0.2")?;
        fdt.set_property_string("method", "hvc")?;
        fdt.end_node(psci_node_dep)?;

        for dev in self.sysbus.devices.iter() {
            let locked_dev = dev.lock().unwrap();
            let dev_type = locked_dev.sysbusdev_base().dev_type;
            let sys_res = locked_dev.sysbusdev_base().res;
            match dev_type {
                SysBusDevType::Serial => generate_serial_device_node(fdt, &sys_res)?,
                SysBusDevType::Rtc => generate_rtc_device_node(fdt, &sys_res)?,
                SysBusDevType::VirtioMmio => generate_virtio_devices_node(fdt, &sys_res)?,
                _ => (),
            }
        }

        Ok(())
    }

    fn generate_chosen_node(&self, fdt: &mut FdtBuilder) -> util::Result<()> {
        let node = "chosen";
        let boot_source = self.boot_source.lock().unwrap();

        let chosen_node_dep = fdt.begin_node(node)?;
        let cmdline = &boot_source.kernel_cmdline.to_string();
        fdt.set_property_string("bootargs", cmdline.as_str())?;

        match &boot_source.initrd {
            Some(initrd) => {
                fdt.set_property_u64("linux,initrd-start", initrd.initrd_addr)?;
                fdt.set_property_u64("linux,initrd-end", initrd.initrd_addr + initrd.initrd_size)?;
            }
            None => {}
        }
        fdt.end_node(chosen_node_dep)?;

        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
impl device_tree::CompileFDT for LightMachine {
    fn generate_fdt_node(&self, fdt: &mut FdtBuilder) -> util::Result<()> {
        let node_dep = fdt.begin_node("")?;

        fdt.set_property_string("compatible", "linux,dummy-virt")?;
        fdt.set_property_u32("#address-cells", 0x2)?;
        fdt.set_property_u32("#size-cells", 0x2)?;
        fdt.set_property_u32("interrupt-parent", device_tree::GIC_PHANDLE)?;

        self.generate_cpu_nodes(fdt)?;
        self.generate_memory_node(fdt)?;
        self.generate_devices_node(fdt)?;
        self.generate_chosen_node(fdt)?;
        // SAFETY: ARM architecture must have interrupt controllers in user mode.
        self.irq_chip.as_ref().unwrap().generate_fdt_node(fdt)?;

        fdt.end_node(node_dep)?;

        Ok(())
    }
}

/// Trace descriptions for some devices at stratovirt startup.
fn trace_cpu_topo(cpu_topo: &CPUTopology) {
    util::ftrace!(trace_cpu_topo, "{:#?}", cpu_topo);
}

fn trace_sysbus(sysbus: &SysBus) {
    util::ftrace!(trace_sysbus, "{:?}", sysbus);
}

fn trace_replaceable_info(replaceable_info: &MmioReplaceableInfo) {
    util::ftrace!(trace_replaceable_info, "{:?}", replaceable_info);
}

fn trace_vm_state(vm_state: &Arc<(Mutex<KvmVmState>, Condvar)>) {
    util::ftrace!(trace_vm_state, "{:#?}", vm_state);
}

fn trace_mmio_replaceable_config(config: &MmioReplaceableConfig) {
    util::ftrace!(trace_mmio_replaceable_config, "{:#?}", config);
}
