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

mod pci_host_root;
mod syscall;

pub use crate::error::MachineError;

use std::collections::HashMap;
use std::mem::size_of;
use std::ops::Deref;
use std::sync::{Arc, Condvar, Mutex};

use anyhow::{bail, Context, Result};
use kvm_bindings::{KVM_ARM_IRQ_TYPE_SHIFT, KVM_ARM_IRQ_TYPE_SPI};
use log::{error, info, warn};
use vmm_sys_util::eventfd::EventFd;

use super::{AcpiBuilder, Result as StdResult, StdMachineOps};
use crate::MachineOps;
use acpi::{
    processor_append_priv_res, AcpiGicCpu, AcpiGicDistributor, AcpiGicIts, AcpiGicRedistributor,
    AcpiSratGiccAffinity, AcpiSratMemoryAffinity, AcpiTable, AmlBuilder, AmlDevice, AmlInteger,
    AmlNameDecl, AmlScope, AmlScopeBuilder, AmlString, CacheHierarchyNode, CacheType,
    ProcessorHierarchyNode, TableLoader, ACPI_GTDT_ARCH_TIMER_NS_EL1_IRQ,
    ACPI_GTDT_ARCH_TIMER_NS_EL2_IRQ, ACPI_GTDT_ARCH_TIMER_S_EL1_IRQ, ACPI_GTDT_ARCH_TIMER_VIRT_IRQ,
    ACPI_GTDT_CAP_ALWAYS_ON, ACPI_GTDT_INTERRUPT_MODE_LEVEL, ACPI_IORT_NODE_ITS_GROUP,
    ACPI_IORT_NODE_PCI_ROOT_COMPLEX, ACPI_MADT_GENERIC_CPU_INTERFACE,
    ACPI_MADT_GENERIC_DISTRIBUTOR, ACPI_MADT_GENERIC_REDISTRIBUTOR, ACPI_MADT_GENERIC_TRANSLATOR,
    ARCH_GIC_MAINT_IRQ, ID_MAPPING_ENTRY_SIZE, INTERRUPT_PPIS_COUNT, INTERRUPT_SGIS_COUNT,
    ROOT_COMPLEX_ENTRY_SIZE,
};
use address_space::{AddressSpace, GuestAddress, Region};
use boot_loader::{load_linux, BootLoaderConfig};
use cpu::{
    CPUBootConfig, CPUFeatures, CPUInterface, CPUTopology, CpuTopology, CPU, PMU_INTR, PPI_BASE,
};
use devices::acpi::ged::{acpi_dsdt_add_power_button, Ged};
use devices::acpi::power::PowerDev;
#[cfg(feature = "ramfb")]
use devices::legacy::Ramfb;
use devices::legacy::{
    FwCfgEntryType, FwCfgMem, FwCfgOps, LegacyError as DevErrorKind, PFlash, PL011, PL031,
};
use devices::pci::{InterruptHandler, PciDevOps, PciHost, PciIntxState};
use devices::sysbus::{SysBus, SysBusDevType, SysRes};
use devices::{ICGICConfig, ICGICv3Config, InterruptController, GIC_IRQ_INTERNAL, GIC_IRQ_MAX};
use hypervisor::kvm::KVM_FDS;
#[cfg(feature = "ramfb")]
use machine_manager::config::parse_ramfb;
use machine_manager::config::ShutdownAction;
#[cfg(feature = "gtk")]
use machine_manager::config::UiContext;
use machine_manager::config::{
    parse_incoming_uri, BootIndexInfo, BootSource, DriveFile, Incoming, MigrateMode, NumaNode,
    NumaNodes, PFlashConfig, SerialConfig, VmConfig,
};
use machine_manager::event;
use machine_manager::event_loop::EventLoop;
use machine_manager::machine::{
    KvmVmState, MachineAddressInterface, MachineExternalInterface, MachineInterface,
    MachineLifecycle, MachineTestInterface, MigrateInterface,
};
use machine_manager::qmp::{qmp_channel::QmpChannel, qmp_response::Response, qmp_schema};
use migration::{MigrationManager, MigrationStatus};
use pci_host_root::PciHostRoot;
use syscall::syscall_whitelist;
#[cfg(feature = "gtk")]
use ui::gtk::gtk_display_init;
#[cfg(feature = "vnc")]
use ui::vnc::vnc_init;
use util::byte_code::ByteCode;
use util::device_tree::{self, CompileFDT, FdtBuilder};
use util::loop_context::EventLoopManager;
use util::seccomp::BpfRule;
use util::set_termi_canon_mode;

/// The type of memory layout entry on aarch64
pub enum LayoutEntryType {
    Flash = 0,
    GicDist,
    GicIts,
    GicRedist,
    Uart,
    Rtc,
    FwCfg,
    Ged,
    PowerDev,
    Mmio,
    PcieMmio,
    PciePio,
    Mem,
    HighGicRedist,
    HighPcieEcam,
    HighPcieMmio,
}

/// Layout of aarch64
pub const MEM_LAYOUT: &[(u64, u64)] = &[
    (0, 0x0800_0000),              // Flash
    (0x0800_0000, 0x0001_0000),    // GicDist
    (0x0808_0000, 0x0002_0000),    // GicIts
    (0x080A_0000, 0x00F6_0000),    // GicRedist (max 123 redistributors)
    (0x0900_0000, 0x0000_1000),    // Uart
    (0x0901_0000, 0x0000_1000),    // Rtc
    (0x0902_0000, 0x0000_0018),    // FwCfg
    (0x0908_0000, 0x0000_0004),    // Ged
    (0x0909_0000, 0x0000_1000),    // PowerDev
    (0x0A00_0000, 0x0000_0200),    // Mmio
    (0x1000_0000, 0x2EFF_0000),    // PcieMmio
    (0x3EFF_0000, 0x0001_0000),    // PciePio
    (0x4000_0000, 0x7F_4000_0000), // Mem
    (510 << 30, 0x200_0000),       // HighGicRedist, (where remaining redistributors locates)
    (511 << 30, 0x1000_0000),      // HighPcieEcam
    (512 << 30, 512 << 30),        // HighPcieMmio
];

/// The type of Irq entry on aarch64
enum IrqEntryType {
    Sysbus,
    Pcie,
}

/// IRQ MAP of aarch64
const IRQ_MAP: &[(i32, i32)] = &[
    (5, 15),  // Sysbus
    (16, 19), // Pcie
];

/// Standard machine structure.
pub struct StdMachine {
    /// `vCPU` topology, support sockets, cores, threads.
    cpu_topo: CpuTopology,
    /// `vCPU` devices.
    cpus: Vec<Arc<CPU>>,
    cpu_features: CPUFeatures,
    // Interrupt controller device.
    irq_chip: Option<Arc<InterruptController>>,
    /// Memory address space.
    pub sys_mem: Arc<AddressSpace>,
    /// System bus.
    sysbus: SysBus,
    /// PCI/PCIe host bridge.
    pci_host: Arc<Mutex<PciHost>>,
    /// VM running state.
    vm_state: Arc<(Mutex<KvmVmState>, Condvar)>,
    /// Vm boot_source config.
    boot_source: Arc<Mutex<BootSource>>,
    /// VM power button, handle VM `Shutdown` event.
    pub power_button: Arc<EventFd>,
    /// All configuration information of virtual machine.
    vm_config: Arc<Mutex<VmConfig>>,
    /// Shutdown request, handle VM `shutdown` event.
    shutdown_req: Arc<EventFd>,
    /// Reset request, handle VM `Reset` event.
    reset_req: Arc<EventFd>,
    /// Pause request, handle VM `Pause` event.
    pause_req: Arc<EventFd>,
    /// Resume request, handle VM `Resume` event.
    resume_req: Arc<EventFd>,
    /// Device Tree Blob.
    dtb_vec: Vec<u8>,
    /// List of guest NUMA nodes information.
    numa_nodes: Option<NumaNodes>,
    /// List contains the boot order of boot devices.
    boot_order_list: Arc<Mutex<Vec<BootIndexInfo>>>,
    /// FwCfg device.
    fwcfg_dev: Option<Arc<Mutex<FwCfgMem>>>,
    /// Drive backend files.
    drive_files: Arc<Mutex<HashMap<String, DriveFile>>>,
    /// machine all backend memory region tree
    machine_ram: Arc<Region>,
}

impl StdMachine {
    pub fn new(vm_config: &VmConfig) -> Result<Self> {
        let cpu_topo = CpuTopology::new(
            vm_config.machine_config.nr_cpus,
            vm_config.machine_config.nr_sockets,
            vm_config.machine_config.nr_dies,
            vm_config.machine_config.nr_clusters,
            vm_config.machine_config.nr_cores,
            vm_config.machine_config.nr_threads,
            vm_config.machine_config.max_cpus,
        );
        let sys_mem = AddressSpace::new(
            Region::init_container_region(u64::max_value(), "SysMem"),
            "sys_mem",
        )
        .with_context(|| MachineError::CrtIoSpaceErr)?;
        let sysbus = SysBus::new(
            &sys_mem,
            (
                IRQ_MAP[IrqEntryType::Sysbus as usize].0,
                IRQ_MAP[IrqEntryType::Sysbus as usize].1,
            ),
            (
                MEM_LAYOUT[LayoutEntryType::Mmio as usize].0,
                MEM_LAYOUT[LayoutEntryType::Mmio as usize + 1].0,
            ),
        );

        Ok(StdMachine {
            cpu_topo,
            cpus: Vec::new(),
            cpu_features: (&vm_config.machine_config.cpu_config).into(),
            irq_chip: None,
            sys_mem: sys_mem.clone(),
            sysbus,
            pci_host: Arc::new(Mutex::new(PciHost::new(
                &sys_mem,
                MEM_LAYOUT[LayoutEntryType::HighPcieEcam as usize],
                MEM_LAYOUT[LayoutEntryType::PcieMmio as usize],
                MEM_LAYOUT[LayoutEntryType::PciePio as usize],
                MEM_LAYOUT[LayoutEntryType::HighPcieMmio as usize],
                IRQ_MAP[IrqEntryType::Pcie as usize].0,
            ))),
            boot_source: Arc::new(Mutex::new(vm_config.clone().boot_source)),
            vm_state: Arc::new((Mutex::new(KvmVmState::Created), Condvar::new())),
            power_button: Arc::new(
                EventFd::new(libc::EFD_NONBLOCK)
                    .with_context(|| MachineError::InitEventFdErr("power_button".to_string()))?,
            ),
            vm_config: Arc::new(Mutex::new(vm_config.clone())),
            shutdown_req: Arc::new(
                EventFd::new(libc::EFD_NONBLOCK)
                    .with_context(|| MachineError::InitEventFdErr("shutdown_req".to_string()))?,
            ),
            reset_req: Arc::new(
                EventFd::new(libc::EFD_NONBLOCK)
                    .with_context(|| MachineError::InitEventFdErr("reset_req".to_string()))?,
            ),
            pause_req: Arc::new(
                EventFd::new(libc::EFD_NONBLOCK)
                    .with_context(|| MachineError::InitEventFdErr("pause_req".to_string()))?,
            ),
            resume_req: Arc::new(
                EventFd::new(libc::EFD_NONBLOCK)
                    .with_context(|| MachineError::InitEventFdErr("resume_req".to_string()))?,
            ),
            dtb_vec: Vec::new(),
            numa_nodes: None,
            boot_order_list: Arc::new(Mutex::new(Vec::new())),
            fwcfg_dev: None,
            drive_files: Arc::new(Mutex::new(vm_config.init_drive_files()?)),
            machine_ram: Arc::new(Region::init_container_region(
                u64::max_value(),
                "MachineRam",
            )),
        })
    }

    pub fn handle_reset_request(vm: &Arc<Mutex<Self>>) -> Result<()> {
        let mut locked_vm = vm.lock().unwrap();
        let mut fdt_addr: u64 = 0;

        for (cpu_index, cpu) in locked_vm.cpus.iter().enumerate() {
            cpu.pause()
                .with_context(|| format!("Failed to pause vcpu{}", cpu_index))?;

            cpu.set_to_boot_state();
            if cpu_index == 0 {
                fdt_addr = cpu.arch().lock().unwrap().core_regs().regs.regs[0];
            }
            cpu.fd()
                .vcpu_init(&cpu.arch().lock().unwrap().kvi())
                .with_context(|| "Failed to init vcpu fd")?;
        }

        locked_vm
            .sys_mem
            .write(
                &mut locked_vm.dtb_vec.as_slice(),
                GuestAddress(fdt_addr),
                locked_vm.dtb_vec.len() as u64,
            )
            .with_context(|| "Fail to write dtb into sysmem")?;

        locked_vm
            .reset_all_devices()
            .with_context(|| "Fail to reset all devices")?;
        locked_vm
            .reset_fwcfg_boot_order()
            .with_context(|| "Fail to update boot order imformation to FwCfg device")?;

        if QmpChannel::is_connected() {
            let reset_msg = qmp_schema::Reset { guest: true };
            event!(Reset; reset_msg);
        }

        locked_vm.irq_chip.as_ref().unwrap().reset()?;

        for (cpu_index, cpu) in locked_vm.cpus.iter().enumerate() {
            cpu.resume()
                .with_context(|| format!("Failed to resume vcpu{}", cpu_index))?;
        }

        Ok(())
    }

    fn build_pptt_cores(&self, pptt: &mut AcpiTable, cluster_offset: u32, uid: &mut u32) {
        for core in 0..self.cpu_topo.cores {
            let mut priv_resources = vec![0; 3];
            priv_resources[0] = pptt.table_len() as u32;
            let mut cache_hierarchy_node = CacheHierarchyNode::new(0, CacheType::L2);
            pptt.append_child(&cache_hierarchy_node.aml_bytes());
            priv_resources[1] = pptt.table_len() as u32;
            cache_hierarchy_node = CacheHierarchyNode::new(priv_resources[0], CacheType::L1D);
            pptt.append_child(&cache_hierarchy_node.aml_bytes());
            priv_resources[2] = pptt.table_len() as u32;
            cache_hierarchy_node = CacheHierarchyNode::new(priv_resources[0], CacheType::L1I);
            pptt.append_child(&cache_hierarchy_node.aml_bytes());

            if self.cpu_topo.threads > 1 {
                let core_offset = pptt.table_len();
                let core_hierarchy_node =
                    ProcessorHierarchyNode::new(0x0, cluster_offset, core as u32, 3);
                pptt.append_child(&core_hierarchy_node.aml_bytes());
                processor_append_priv_res(pptt, priv_resources);
                for _thread in 0..self.cpu_topo.threads {
                    let thread_hierarchy_node =
                        ProcessorHierarchyNode::new(0xE, core_offset as u32, *uid, 0);
                    pptt.append_child(&thread_hierarchy_node.aml_bytes());
                    (*uid) += 1;
                }
            } else {
                let core_hierarchy_node = ProcessorHierarchyNode::new(0xA, cluster_offset, *uid, 3);
                pptt.append_child(&core_hierarchy_node.aml_bytes());
                (*uid) += 1;
                processor_append_priv_res(pptt, priv_resources);
            }
        }
    }

    fn build_pptt_clusters(&self, pptt: &mut AcpiTable, socket_offset: u32, uid: &mut u32) {
        for cluster in 0..self.cpu_topo.clusters {
            let cluster_offset = pptt.table_len();
            let cluster_hierarchy_node =
                ProcessorHierarchyNode::new(0x0, socket_offset, cluster as u32, 0);
            pptt.append_child(&cluster_hierarchy_node.aml_bytes());
            self.build_pptt_cores(pptt, cluster_offset as u32, uid);
        }
    }

    fn build_pptt_sockets(&self, pptt: &mut AcpiTable, uid: &mut u32) {
        for socket in 0..self.cpu_topo.sockets {
            let priv_resources = vec![pptt.table_len() as u32];
            let cache_hierarchy_node = CacheHierarchyNode::new(0, CacheType::L3);
            pptt.append_child(&cache_hierarchy_node.aml_bytes());

            let socket_offset = pptt.table_len();
            let socket_hierarchy_node = ProcessorHierarchyNode::new(0x1, 0, socket as u32, 1);
            pptt.append_child(&socket_hierarchy_node.aml_bytes());
            processor_append_priv_res(pptt, priv_resources);

            self.build_pptt_clusters(pptt, socket_offset as u32, uid);
        }
    }

    /// Must be called after the CPUs have been realized and GIC has been created.
    fn cpu_post_init(&self, vcpu_cfg: &Option<CPUFeatures>) -> Result<()> {
        let features = vcpu_cfg.unwrap_or_default();
        if features.pmu {
            for cpu in self.cpus.iter() {
                cpu.init_pmu()?;
            }
        }
        Ok(())
    }

    pub fn mem_show(&self) {
        self.sys_mem.memspace_show();
        let machine_ram = self.get_vm_ram();
        machine_ram.mtree(0_u32);
    }
}

impl StdMachineOps for StdMachine {
    fn init_pci_host(&self) -> StdResult<()> {
        let root_bus = Arc::downgrade(&self.pci_host.lock().unwrap().root_bus);
        let mmconfig_region_ops = PciHost::build_mmconfig_ops(self.pci_host.clone());
        let mmconfig_region = Region::init_io_region(
            MEM_LAYOUT[LayoutEntryType::HighPcieEcam as usize].1,
            mmconfig_region_ops,
            "PcieEcamIo",
        );
        self.sys_mem
            .root()
            .add_subregion(
                mmconfig_region,
                MEM_LAYOUT[LayoutEntryType::HighPcieEcam as usize].0,
            )
            .with_context(|| "Failed to register ECAM in memory space.")?;

        let pcihost_root = PciHostRoot::new(root_bus);
        pcihost_root
            .realize()
            .with_context(|| "Failed to realize pcihost root device.")?;

        Ok(())
    }

    fn add_fwcfg_device(&mut self, nr_cpus: u8) -> StdResult<Option<Arc<Mutex<dyn FwCfgOps>>>> {
        if self.vm_config.lock().unwrap().pflashs.is_none() {
            return Ok(None);
        }

        let mut fwcfg = FwCfgMem::new(self.sys_mem.clone());
        fwcfg
            .add_data_entry(FwCfgEntryType::NbCpus, nr_cpus.as_bytes().to_vec())
            .with_context(|| DevErrorKind::AddEntryErr("NbCpus".to_string()))?;

        let cmdline = self.boot_source.lock().unwrap().kernel_cmdline.to_string();
        fwcfg
            .add_data_entry(
                FwCfgEntryType::CmdlineSize,
                (cmdline.len() + 1).as_bytes().to_vec(),
            )
            .with_context(|| DevErrorKind::AddEntryErr("CmdlineSize".to_string()))?;
        fwcfg
            .add_string_entry(FwCfgEntryType::CmdlineData, cmdline.as_str())
            .with_context(|| DevErrorKind::AddEntryErr("CmdlineData".to_string()))?;

        let boot_order = Vec::<u8>::new();
        fwcfg
            .add_file_entry("bootorder", boot_order)
            .with_context(|| DevErrorKind::AddEntryErr("bootorder".to_string()))?;

        let bios_geometry = Vec::<u8>::new();
        fwcfg
            .add_file_entry("bios-geometry", bios_geometry)
            .with_context(|| DevErrorKind::AddEntryErr("bios-geometry".to_string()))?;

        let fwcfg_dev = FwCfgMem::realize(
            fwcfg,
            &mut self.sysbus,
            MEM_LAYOUT[LayoutEntryType::FwCfg as usize].0,
            MEM_LAYOUT[LayoutEntryType::FwCfg as usize].1,
        )
        .with_context(|| "Failed to realize fwcfg device")?;
        self.fwcfg_dev = Some(fwcfg_dev.clone());

        Ok(Some(fwcfg_dev))
    }

    fn get_cpu_topo(&self) -> &CpuTopology {
        &self.cpu_topo
    }

    fn get_cpus(&self) -> &Vec<Arc<CPU>> {
        &self.cpus
    }

    fn get_guest_numa(&self) -> &Option<NumaNodes> {
        &self.numa_nodes
    }
}

impl MachineOps for StdMachine {
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
            .add_subregion(ram, MEM_LAYOUT[LayoutEntryType::Mem as usize].0)?;
        Ok(())
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
        let intc_conf = ICGICConfig {
            version: None,
            vcpu_count,
            max_irq: GIC_IRQ_MAX,
            v2: None,
            v3: Some(v3),
        };
        let irq_chip = InterruptController::new(&intc_conf)?;
        self.irq_chip = Some(Arc::new(irq_chip));
        self.irq_chip.as_ref().unwrap().realize()?;
        KVM_FDS
            .load()
            .irq_route_table
            .lock()
            .unwrap()
            .init_irq_route_table();
        KVM_FDS.load().commit_irq_routing()?;

        let root_bus = &self.pci_host.lock().unwrap().root_bus;
        let irq_handler = Box::new(move |gsi: u32, level: bool| -> Result<()> {
            // The handler is only used to send PCI INTx interrupt.
            // PCI INTx interrupt is belong to SPI interrupt type.
            let irq = gsi + GIC_IRQ_INTERNAL;
            let irqtype = KVM_ARM_IRQ_TYPE_SPI;
            let kvm_irq = irqtype << KVM_ARM_IRQ_TYPE_SHIFT | irq;

            KVM_FDS.load().set_irq_line(kvm_irq, level)
        }) as InterruptHandler;

        let irq_state = Some(Arc::new(Mutex::new(PciIntxState::new(
            IRQ_MAP[IrqEntryType::Pcie as usize].0 as u32,
            irq_handler,
        ))));
        root_bus.lock().unwrap().intx_state = irq_state;

        Ok(())
    }

    fn load_boot_source(&self, fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>) -> Result<CPUBootConfig> {
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

    fn add_rtc_device(&mut self) -> Result<()> {
        let rtc = PL031::default();
        PL031::realize(
            rtc,
            &mut self.sysbus,
            MEM_LAYOUT[LayoutEntryType::Rtc as usize].0,
            MEM_LAYOUT[LayoutEntryType::Rtc as usize].1,
        )
        .with_context(|| "Failed to realize PL031")?;
        Ok(())
    }

    fn add_ged_device(&mut self) -> Result<()> {
        let battery_present = self.vm_config.lock().unwrap().machine_config.battery;
        let ged = Ged::default();
        let ged_dev = ged
            .realize(
                &mut self.sysbus,
                self.power_button.clone(),
                battery_present,
                MEM_LAYOUT[LayoutEntryType::Ged as usize].0,
                MEM_LAYOUT[LayoutEntryType::Ged as usize].1,
            )
            .with_context(|| "Failed to realize Ged")?;
        if battery_present {
            let pdev = PowerDev::new(ged_dev);
            pdev.realize(
                &mut self.sysbus,
                MEM_LAYOUT[LayoutEntryType::PowerDev as usize].0,
                MEM_LAYOUT[LayoutEntryType::PowerDev as usize].1,
            )
            .with_context(|| "Failed to realize PowerDev")?;
        }
        Ok(())
    }

    fn add_serial_device(&mut self, config: &SerialConfig) -> Result<()> {
        let region_base: u64 = MEM_LAYOUT[LayoutEntryType::Uart as usize].0;
        let region_size: u64 = MEM_LAYOUT[LayoutEntryType::Uart as usize].1;

        let pl011 = PL011::new(config.clone()).with_context(|| "Failed to create PL011")?;
        pl011
            .realize(
                &mut self.sysbus,
                region_base,
                region_size,
                &self.boot_source,
            )
            .with_context(|| "Failed to realize PL011")?;
        Ok(())
    }

    fn syscall_whitelist(&self) -> Vec<BpfRule> {
        syscall_whitelist()
    }

    fn get_drive_files(&self) -> Arc<Mutex<HashMap<String, DriveFile>>> {
        self.drive_files.clone()
    }

    fn realize(vm: &Arc<Mutex<Self>>, vm_config: &mut VmConfig) -> Result<()> {
        use super::error::StandardVmError as StdErrorKind;

        let nr_cpus = vm_config.machine_config.nr_cpus;
        let mut locked_vm = vm.lock().unwrap();
        locked_vm.init_global_config(vm_config)?;
        locked_vm
            .register_shutdown_event(locked_vm.shutdown_req.clone(), vm.clone())
            .with_context(|| "Fail to register shutdown event")?;
        locked_vm
            .register_reset_event(locked_vm.reset_req.clone(), vm.clone())
            .with_context(|| "Fail to register reset event")?;
        locked_vm
            .register_pause_event(locked_vm.pause_req.clone(), vm.clone())
            .with_context(|| "Fail to register pause event")?;
        locked_vm
            .register_resume_event(locked_vm.resume_req.clone(), vm.clone())
            .with_context(|| "Fail to register resume event")?;

        locked_vm.numa_nodes = locked_vm.add_numa_nodes(vm_config)?;
        locked_vm.init_memory(
            &vm_config.machine_config.mem_config,
            &locked_vm.sys_mem,
            nr_cpus,
        )?;

        locked_vm
            .init_pci_host()
            .with_context(|| StdErrorKind::InitPCIeHostErr)?;
        let fwcfg = locked_vm.add_fwcfg_device(nr_cpus)?;

        let migrate = locked_vm.get_migrate_info();
        let boot_config = if migrate.0 == MigrateMode::Unknown {
            Some(locked_vm.load_boot_source(fwcfg.as_ref())?)
        } else {
            None
        };
        let cpu_config = if migrate.0 == MigrateMode::Unknown {
            Some(locked_vm.load_cpu_features(vm_config)?)
        } else {
            None
        };

        locked_vm.cpus.extend(<Self as MachineOps>::init_vcpu(
            vm.clone(),
            nr_cpus,
            &CPUTopology::new(),
            &boot_config,
            &cpu_config,
        )?);

        // Interrupt Controller Chip init
        locked_vm.init_interrupt_controller(u64::from(nr_cpus))?;

        locked_vm.cpu_post_init(&cpu_config)?;

        locked_vm
            .add_devices(vm_config)
            .with_context(|| "Failed to add devices")?;

        if let Some(boot_cfg) = boot_config {
            let mut fdt_helper = FdtBuilder::new();
            locked_vm
                .generate_fdt_node(&mut fdt_helper)
                .with_context(|| MachineError::GenFdtErr)?;
            let fdt_vec = fdt_helper.finish()?;
            locked_vm.dtb_vec = fdt_vec.clone();
            locked_vm
                .sys_mem
                .write(
                    &mut fdt_vec.as_slice(),
                    GuestAddress(boot_cfg.fdt_addr),
                    fdt_vec.len() as u64,
                )
                .with_context(|| MachineError::WrtFdtErr(boot_cfg.fdt_addr, fdt_vec.len()))?;
        }

        // If it is direct kernel boot mode, the ACPI can not be enabled.
        if migrate.0 == MigrateMode::Unknown {
            if let Some(fw_cfg) = fwcfg {
                locked_vm
                    .build_acpi_tables(&fw_cfg)
                    .with_context(|| "Failed to create ACPI tables")?;
                locked_vm
                    .build_smbios(&fw_cfg, Vec::new())
                    .with_context(|| "Failed to create smbios tables")?;
            }
        }

        locked_vm
            .reset_fwcfg_boot_order()
            .with_context(|| "Fail to update boot order imformation to FwCfg device")?;

        locked_vm
            .display_init(vm_config)
            .with_context(|| "Fail to init display")?;

        #[cfg(feature = "windows_emu_pid")]
        locked_vm.watch_windows_emu_pid(
            vm_config,
            locked_vm.power_button.clone(),
            locked_vm.shutdown_req.clone(),
        );

        MigrationManager::register_vm_config(locked_vm.get_vm_config());
        MigrationManager::register_vm_instance(vm.clone());
        if let Err(e) = MigrationManager::set_status(MigrationStatus::Setup) {
            bail!("Failed to set migration status {}", e);
        }
        Ok(())
    }

    fn add_pflash_device(&mut self, configs: &[PFlashConfig]) -> Result<()> {
        use super::error::StandardVmError as StdErrorKind;
        let mut configs_vec = configs.to_vec();
        configs_vec.sort_by_key(|c| c.unit);
        let sector_len: u32 = 1024 * 256;
        let mut flash_base: u64 = MEM_LAYOUT[LayoutEntryType::Flash as usize].0;
        let flash_size: u64 = MEM_LAYOUT[LayoutEntryType::Flash as usize].1 / 2;
        for i in 0..=1 {
            let (fd, read_only) = if i < configs_vec.len() {
                let path = &configs_vec[i].path_on_host;
                let read_only = configs_vec[i].read_only;
                let fd = self.fetch_drive_file(path)?;
                (Some(fd), read_only)
            } else {
                (None, false)
            };

            let pflash = PFlash::new(flash_size, &fd, sector_len, 4, 2, read_only)
                .with_context(|| StdErrorKind::InitPflashErr)?;
            PFlash::realize(pflash, &mut self.sysbus, flash_base, flash_size, fd)
                .with_context(|| StdErrorKind::RlzPflashErr)?;
            flash_base += flash_size;
        }

        Ok(())
    }

    /// Create display.
    #[allow(unused_variables)]
    fn display_init(&mut self, vm_config: &mut VmConfig) -> Result<()> {
        // GTK display init.
        #[cfg(feature = "gtk")]
        match vm_config.display {
            Some(ref ds_cfg) if ds_cfg.gtk => {
                let ui_context = UiContext {
                    vm_name: vm_config.guest_name.clone(),
                    power_button: Some(self.power_button.clone()),
                    shutdown_req: Some(self.shutdown_req.clone()),
                    pause_req: Some(self.pause_req.clone()),
                    resume_req: Some(self.resume_req.clone()),
                };
                gtk_display_init(ds_cfg, ui_context)
                    .with_context(|| "Failed to init GTK display!")?;
            }
            _ => {}
        };

        // VNC display init.
        #[cfg(feature = "vnc")]
        vnc_init(&vm_config.vnc, &vm_config.object)
            .with_context(|| "Failed to init VNC server!")?;
        Ok(())
    }

    #[cfg(feature = "ramfb")]
    fn add_ramfb(&mut self, cfg_args: &str) -> Result<()> {
        let install = parse_ramfb(cfg_args)?;
        let fwcfg_dev = self
            .get_fwcfg_dev()
            .with_context(|| "Ramfb device must be used UEFI to boot, please add pflash devices")?;
        let sys_mem = self.get_sys_mem();
        let mut ramfb = Ramfb::new(sys_mem.clone(), install);

        ramfb.ramfb_state.setup(&fwcfg_dev)?;
        ramfb.realize(&mut self.sysbus)?;
        Ok(())
    }

    fn run(&self, paused: bool) -> Result<()> {
        self.vm_start(paused, &self.cpus, &mut self.vm_state.0.lock().unwrap())
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

    fn get_pci_host(&mut self) -> StdResult<&Arc<Mutex<PciHost>>> {
        Ok(&self.pci_host)
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

    fn get_fwcfg_dev(&mut self) -> Option<Arc<Mutex<dyn FwCfgOps>>> {
        if let Some(fwcfg_dev) = &self.fwcfg_dev {
            return Some(fwcfg_dev.clone());
        }
        None
    }

    fn get_boot_order_list(&self) -> Option<Arc<Mutex<Vec<BootIndexInfo>>>> {
        Some(self.boot_order_list.clone())
    }
}

impl AcpiBuilder for StdMachine {
    fn build_gtdt_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::Result<u64> {
        let mut gtdt = AcpiTable::new(*b"GTDT", 2, *b"STRATO", *b"VIRTGTDT", 1);
        gtdt.set_table_len(96);

        // Secure EL1 interrupt
        gtdt.set_field(48, ACPI_GTDT_ARCH_TIMER_S_EL1_IRQ + INTERRUPT_PPIS_COUNT);
        // Secure EL1 flags
        gtdt.set_field(52, ACPI_GTDT_INTERRUPT_MODE_LEVEL);

        // Non secure EL1 interrupt
        gtdt.set_field(56, ACPI_GTDT_ARCH_TIMER_NS_EL1_IRQ + INTERRUPT_PPIS_COUNT);
        // Non secure EL1 flags
        gtdt.set_field(60, ACPI_GTDT_INTERRUPT_MODE_LEVEL | ACPI_GTDT_CAP_ALWAYS_ON);

        // Virtual timer interrupt
        gtdt.set_field(64, ACPI_GTDT_ARCH_TIMER_VIRT_IRQ + INTERRUPT_PPIS_COUNT);
        // Virtual timer flags
        gtdt.set_field(68, ACPI_GTDT_INTERRUPT_MODE_LEVEL);

        // Non secure EL2 interrupt
        gtdt.set_field(72, ACPI_GTDT_ARCH_TIMER_NS_EL2_IRQ + INTERRUPT_PPIS_COUNT);
        // Non secure EL2 flags
        gtdt.set_field(76, ACPI_GTDT_INTERRUPT_MODE_LEVEL);

        let gtdt_begin = StdMachine::add_table_to_loader(acpi_data, loader, &gtdt)
            .with_context(|| "Fail to add GTDT table to loader")?;
        Ok(gtdt_begin)
    }

    fn build_dbg2_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::Result<u64> {
        // Table format described at:
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/acpi-debug-port-table

        let dev_name = "COM0";
        let dev_name_length = dev_name.len() + 1;

        let dbg2_table_size = 82 // Fixed size part of table
            + dev_name_length;

        let dbg2_info_size = 22 // BaseAddressRegister offset
            + 12 // BaseAddressRegister
            + 4 // AddressSize
            + dev_name_length;

        let mut dbg2 = AcpiTable::new(*b"DBG2", 0, *b"STRATO", *b"VIRTDBG2", 1);
        dbg2.set_table_len(dbg2_table_size);

        // Table 1. Debug Port Table 2 format
        // OffsetDbgDeviceInfo
        dbg2.set_field(36, 44_u32);
        // NumberDbgDeviceInfo
        dbg2.set_field(40, 1_u32);

        // Table 2. Debug Device Information structure format
        let offset = 44;
        // Revision
        dbg2.set_field(offset, 0_u8);
        // Length
        dbg2.set_field(offset + 1, dbg2_info_size as u16);
        // NumberofGenericAddressRegisters
        dbg2.set_field(offset + 3, 1_u8);
        // NamespaceStringLength
        dbg2.set_field(offset + 4, dev_name_length as u16);
        // NamespaceStringOffset
        dbg2.set_field(offset + 6, 38_u16);
        // OemDataLength
        dbg2.set_field(offset + 8, 0_u16);
        // OemDataOffset
        dbg2.set_field(offset + 10, 0_u16);
        // Port Type: 0x8000 is serial
        dbg2.set_field(offset + 12, 0x8000_u16);
        // Port Subtype: 0x3 is ARM PL011 UART
        dbg2.set_field(offset + 14, 0x3_u16);

        // BaseAddressRegisterOffset
        dbg2.set_field(offset + 18, 22_u16);
        // AddressSizeOffset
        dbg2.set_field(offset + 20, 34_u16);

        let uart_memory_address = MEM_LAYOUT[LayoutEntryType::Uart as usize].0;
        let uart_memory_size = MEM_LAYOUT[LayoutEntryType::Uart as usize].1;

        // BaseAddressRegister: aml address space
        dbg2.set_field(offset + 22, 0_u8);
        // BaseAddressRegister: bit width
        dbg2.set_field(offset + 23, 8_u8);
        // BaseAddressRegister: bit offset
        dbg2.set_field(offset + 24, 0_u8);
        // BaseAddressRegister: access width
        dbg2.set_field(offset + 25, 1_u8);
        // BaseAddressRegister: address
        dbg2.set_field(offset + 26, uart_memory_address as u64);
        // AddressSize
        dbg2.set_field(offset + 34, uart_memory_size as u32);

        // NamespaceString
        let mut offset = offset + 38;
        for ch in dev_name.chars() {
            dbg2.set_field(offset, ch as u8);
            offset += 1;
        }
        dbg2.set_field(offset, 0_u8);

        let dbg2_begin = StdMachine::add_table_to_loader(acpi_data, loader, &dbg2)
            .with_context(|| "Fail to add DBG2 table to loader")?;
        Ok(dbg2_begin)
    }

    fn build_iort_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::Result<u64> {
        let mut iort = AcpiTable::new(*b"IORT", 2, *b"STRATO", *b"VIRTIORT", 1);
        iort.set_table_len(128);

        // Number of IORT nodes is 2: ITS group node and Root Complex Node.
        iort.set_field(36, 2_u32);
        // Node offset
        iort.set_field(40, 48_u32);

        // ITS group node
        iort.set_field(48, ACPI_IORT_NODE_ITS_GROUP);
        // ITS node length
        iort.set_field(49, 24_u16);
        // ITS count
        iort.set_field(64, 1_u32);

        // Root Complex Node
        iort.set_field(72, ACPI_IORT_NODE_PCI_ROOT_COMPLEX);
        // Length of Root Complex node
        let len = ROOT_COMPLEX_ENTRY_SIZE + ID_MAPPING_ENTRY_SIZE;
        iort.set_field(73, len);
        // Mapping counts of Root Complex Node
        iort.set_field(80, 1_u32);
        // Mapping offset of Root Complex Node
        iort.set_field(84, ROOT_COMPLEX_ENTRY_SIZE as u32);
        // Cache of coherent device
        iort.set_field(88, 1_u32);
        // Memory flags of coherent device
        iort.set_field(95, 3_u8);
        // Identity RID mapping
        iort.set_field(112, 0xffff_u32);
        // Without SMMU, id mapping is the first node in ITS group node
        iort.set_field(120, 48_u32);

        let iort_begin = StdMachine::add_table_to_loader(acpi_data, loader, &iort)
            .with_context(|| "Fail to add IORT table to loader")?;
        Ok(iort_begin)
    }

    fn build_spcr_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::Result<u64> {
        let mut spcr = AcpiTable::new(*b"SPCR", 2, *b"STRATO", *b"VIRTSPCR", 1);
        spcr.set_table_len(80);

        // Interface type: ARM PL011 UART
        spcr.set_field(36, 3_u8);
        // Bit width of AcpiGenericAddress
        spcr.set_field(41, 8_u8);
        // Access width of AcpiGenericAddress
        spcr.set_field(43, 1_u8);
        // Base addr of AcpiGenericAddress
        spcr.set_field(44, MEM_LAYOUT[LayoutEntryType::Uart as usize].0);
        // Interrupt Type: Arm GIC Interrupt
        spcr.set_field(52, 1_u8 << 3);
        // Irq number used by the UART
        let mut uart_irq: u32 = 0;
        for dev in self.sysbus.devices.iter() {
            let locked_dev = dev.lock().unwrap();
            if locked_dev.sysbusdev_base().dev_type == SysBusDevType::PL011 {
                uart_irq = locked_dev.sysbusdev_base().res.irq as u32;
                break;
            }
        }
        spcr.set_field(54, uart_irq + INTERRUPT_SGIS_COUNT + INTERRUPT_PPIS_COUNT);
        // Set baud rate: 3 = 9600
        spcr.set_field(58, 3_u8);
        // Stop bit
        spcr.set_field(60, 1_u8);
        // Hardware flow control
        spcr.set_field(61, 2_u8);
        // PCI Device ID: it is not a PCI device
        spcr.set_field(64, 0xffff_u16);
        // PCI Vendor ID: it is not a PCI device
        spcr.set_field(66, 0xffff_u16);

        let spcr_begin = StdMachine::add_table_to_loader(acpi_data, loader, &spcr)
            .with_context(|| "Fail to add SPCR table to loader")?;
        Ok(spcr_begin)
    }

    fn build_dsdt_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::Result<u64> {
        let mut dsdt = AcpiTable::new(*b"DSDT", 2, *b"STRATO", *b"VIRTDSDT", 1);

        // 1. CPU info.
        let cpus_count = self.cpus.len() as u64;
        let mut sb_scope = AmlScope::new("\\_SB");
        for cpu_id in 0..cpus_count {
            let mut dev = AmlDevice::new(format!("C{:03}", cpu_id).as_str());
            dev.append_child(AmlNameDecl::new("_HID", AmlString("ACPI0007".to_string())));
            dev.append_child(AmlNameDecl::new("_UID", AmlInteger(cpu_id)));
            sb_scope.append_child(dev);
        }

        // 2. Create pci host bridge node.
        sb_scope.append_child(self.pci_host.lock().unwrap().clone());

        sb_scope.append_child(acpi_dsdt_add_power_button());

        dsdt.append_child(sb_scope.aml_bytes().as_slice());

        // 3. Info of devices attached to system bus.
        dsdt.append_child(self.sysbus.aml_bytes().as_slice());

        let dsdt_begin = StdMachine::add_table_to_loader(acpi_data, loader, &dsdt)
            .with_context(|| "Fail to add DSDT table to loader")?;
        Ok(dsdt_begin)
    }

    fn build_madt_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::Result<u64> {
        let mut madt = AcpiTable::new(*b"APIC", 5, *b"STRATO", *b"VIRTAPIC", 1);
        madt.set_table_len(44);

        // 1. GIC Distributor.
        let mut gic_dist = AcpiGicDistributor::default();
        gic_dist.type_id = ACPI_MADT_GENERIC_DISTRIBUTOR;
        gic_dist.length = 24;
        gic_dist.base_addr = MEM_LAYOUT[LayoutEntryType::GicDist as usize].0;
        gic_dist.gic_version = 3;
        madt.append_child(&gic_dist.aml_bytes());

        // 2. GIC CPU.
        let cpus_count = self.cpus.len() as u64;
        for cpu_index in 0..cpus_count {
            let mpidr = self.cpus[cpu_index as usize].arch().lock().unwrap().mpidr();
            let mpidr_mask: u64 = 0x007f_ffff;
            let mut gic_cpu = AcpiGicCpu::default();
            gic_cpu.type_id = ACPI_MADT_GENERIC_CPU_INTERFACE;
            gic_cpu.length = 80;
            gic_cpu.cpu_interface_num = cpu_index as u32;
            gic_cpu.processor_uid = cpu_index as u32;
            gic_cpu.flags = 5;
            gic_cpu.mpidr = mpidr & mpidr_mask;
            gic_cpu.vgic_interrupt = ARCH_GIC_MAINT_IRQ + INTERRUPT_PPIS_COUNT;
            gic_cpu.perf_interrupt = PMU_INTR + PPI_BASE;
            madt.append_child(&gic_cpu.aml_bytes());
        }

        // 3. GIC Redistributor.
        let mut gic_redist = AcpiGicRedistributor::default();
        gic_redist.type_id = ACPI_MADT_GENERIC_REDISTRIBUTOR;
        gic_redist.range_length = MEM_LAYOUT[LayoutEntryType::GicRedist as usize].1 as u32;
        gic_redist.base_addr = MEM_LAYOUT[LayoutEntryType::GicRedist as usize].0;
        gic_redist.length = 16;
        madt.append_child(&gic_redist.aml_bytes());
        // SAFETY: ARM architecture must have interrupt controllers in user mode.
        if self.irq_chip.as_ref().unwrap().get_redist_count() > 1 {
            gic_redist.range_length = MEM_LAYOUT[LayoutEntryType::HighGicRedist as usize].1 as u32;
            gic_redist.base_addr = MEM_LAYOUT[LayoutEntryType::HighGicRedist as usize].0;
            madt.append_child(&gic_redist.aml_bytes());
        }

        // 4. GIC Its.
        let mut gic_its = AcpiGicIts::default();
        gic_its.type_id = ACPI_MADT_GENERIC_TRANSLATOR;
        gic_its.length = 20;
        gic_its.base_addr = MEM_LAYOUT[LayoutEntryType::GicIts as usize].0;
        madt.append_child(&gic_its.aml_bytes());

        let madt_begin = StdMachine::add_table_to_loader(acpi_data, loader, &madt)
            .with_context(|| "Fail to add MADT table to loader")?;
        Ok(madt_begin)
    }

    fn build_srat_cpu(&self, proximity_domain: u32, node: &NumaNode, srat: &mut AcpiTable) {
        for cpu in node.cpus.iter() {
            srat.append_child(
                &AcpiSratGiccAffinity {
                    type_id: 3_u8,
                    length: size_of::<AcpiSratGiccAffinity>() as u8,
                    proximity_domain,
                    process_uid: *cpu as u32,
                    flags: 1,
                    clock_domain: 0_u32,
                }
                .aml_bytes(),
            );
        }
    }

    fn build_srat_mem(
        &self,
        base_addr: u64,
        proximity_domain: u32,
        node: &NumaNode,
        srat: &mut AcpiTable,
    ) -> u64 {
        srat.append_child(
            &AcpiSratMemoryAffinity {
                type_id: 1,
                length: size_of::<AcpiSratMemoryAffinity>() as u8,
                proximity_domain,
                base_addr,
                range_length: node.size,
                flags: 1,
                ..Default::default()
            }
            .aml_bytes(),
        );
        base_addr + node.size
    }

    fn build_srat_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::Result<u64> {
        let mut srat = AcpiTable::new(*b"SRAT", 1, *b"STRATO", *b"VIRTSRAT", 1);
        // Reserved
        srat.append_child(&[1_u8; 4_usize]);
        // Reserved
        srat.append_child(&[0_u8; 8_usize]);

        let mut next_base = MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
        // SAFETY: the SRAT table is created only when numa node configured.
        for (id, node) in self.numa_nodes.as_ref().unwrap().iter() {
            self.build_srat_cpu(*id, node, &mut srat);
            next_base = self.build_srat_mem(next_base, *id, node, &mut srat);
        }

        let srat_begin = StdMachine::add_table_to_loader(acpi_data, loader, &srat)
            .with_context(|| "Fail to add SRAT table to loader")?;
        Ok(srat_begin)
    }

    fn build_pptt_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::Result<u64> {
        let mut pptt = AcpiTable::new(*b"PPTT", 2, *b"STRATO", *b"VIRTPPTT", 1);
        let mut uid = 0;
        self.build_pptt_sockets(&mut pptt, &mut uid);
        let pptt_begin = StdMachine::add_table_to_loader(acpi_data, loader, &pptt)
            .with_context(|| "Fail to add PPTT table to loader")?;
        Ok(pptt_begin)
    }
}

impl MachineLifecycle for StdMachine {
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
            warn!("Failed to destroy guest, destroy continue.");
            if self.shutdown_req.write(1).is_err() {
                error!("Failed to send shutdown request.")
            }
            return false;
        }

        info!("vm destroy");
        EventLoop::get_ctx(None).unwrap().kick();

        true
    }

    fn powerdown(&self) -> bool {
        if self.power_button.write(1).is_err() {
            error!("ARM standard vm write power button failed");
            return false;
        }
        true
    }

    fn get_shutdown_action(&self) -> ShutdownAction {
        self.vm_config
            .lock()
            .unwrap()
            .machine_config
            .shutdown_action
    }

    fn reset(&mut self) -> bool {
        if self.reset_req.write(1).is_err() {
            error!("ARM standard vm write reset req failed");
            return false;
        }
        true
    }

    fn notify_lifecycle(&self, old: KvmVmState, new: KvmVmState) -> bool {
        if let Err(e) = self.vm_state_transfer(
            &self.cpus,
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

impl MachineAddressInterface for StdMachine {
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

impl MigrateInterface for StdMachine {
    fn migrate(&self, uri: String) -> Response {
        match parse_incoming_uri(&uri) {
            Ok((MigrateMode::File, path)) => migration::snapshot(path),
            Ok((MigrateMode::Unix, path)) => migration::migration_unix_mode(path),
            Ok((MigrateMode::Tcp, path)) => migration::migration_tcp_mode(path),
            _ => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(format!("Invalid uri: {}", uri)),
                None,
            ),
        }
    }

    fn query_migrate(&self) -> Response {
        migration::query_migrate()
    }

    fn cancel_migrate(&self) -> Response {
        migration::cancel_migrate()
    }
}

impl MachineInterface for StdMachine {}
impl MachineExternalInterface for StdMachine {}
impl MachineTestInterface for StdMachine {}

impl EventLoopManager for StdMachine {
    fn loop_should_exit(&self) -> bool {
        let vmstate = self.vm_state.deref().0.lock().unwrap();
        *vmstate == KvmVmState::Shutdown
    }

    fn loop_cleanup(&self) -> util::Result<()> {
        set_termi_canon_mode().with_context(|| "Failed to set terminal to canonical mode")?;
        Ok(())
    }
}

// Function that helps to generate pci node in device-tree.
//
// # Arguments
//
// * `fdt` - Flatted device-tree blob where node will be filled into.
fn generate_pci_host_node(fdt: &mut FdtBuilder) -> util::Result<()> {
    let pcie_ecam_base = MEM_LAYOUT[LayoutEntryType::HighPcieEcam as usize].0;
    let pcie_ecam_size = MEM_LAYOUT[LayoutEntryType::HighPcieEcam as usize].1;
    let pcie_buses_num = MEM_LAYOUT[LayoutEntryType::HighPcieEcam as usize].1 >> 20;
    let node = format!("pcie@{:x}", pcie_ecam_base);
    let pci_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "pci-host-ecam-generic")?;
    fdt.set_property_string("device_type", "pci")?;
    fdt.set_property_array_u64("reg", &[pcie_ecam_base, pcie_ecam_size])?;
    fdt.set_property_array_u32("bus-range", &[0, (pcie_buses_num - 1) as u32])?;
    fdt.set_property_u32("linux,pci-domain", 0)?;
    fdt.set_property_u32("#address-cells", 3)?;
    fdt.set_property_u32("#size-cells", 2)?;

    let high_pcie_mmio_base = MEM_LAYOUT[LayoutEntryType::HighPcieMmio as usize].0;
    let high_pcie_mmio_size = MEM_LAYOUT[LayoutEntryType::HighPcieMmio as usize].1;
    let fdt_pci_mmio_type_64bit: u32 = device_tree::FDT_PCI_RANGE_MMIO_64BIT;
    let high_mmio_base_hi: u32 = (high_pcie_mmio_base >> 32) as u32;
    let high_mmio_base_lo: u32 = (high_pcie_mmio_base & 0xffff_ffff) as u32;
    let high_mmio_size_hi: u32 = (high_pcie_mmio_size >> 32) as u32;
    let high_mmio_size_lo: u32 = (high_pcie_mmio_size & 0xffff_ffff) as u32;

    let pcie_mmio_base = MEM_LAYOUT[LayoutEntryType::PcieMmio as usize].0;
    let pcie_mmio_size = MEM_LAYOUT[LayoutEntryType::PcieMmio as usize].1;
    let fdt_pci_mmio_type: u32 = device_tree::FDT_PCI_RANGE_MMIO;
    let mmio_base_hi: u32 = (pcie_mmio_base >> 32) as u32;
    let mmio_base_lo: u32 = (pcie_mmio_base & 0xffff_ffff) as u32;
    let mmio_size_hi: u32 = (pcie_mmio_size >> 32) as u32;
    let mmio_size_lo: u32 = (pcie_mmio_size & 0xffff_ffff) as u32;

    let pcie_pio_base = MEM_LAYOUT[LayoutEntryType::PciePio as usize].0;
    let pcie_pio_size = MEM_LAYOUT[LayoutEntryType::PciePio as usize].1;
    let fdt_pci_pio_type: u32 = device_tree::FDT_PCI_RANGE_IOPORT;
    let pio_base_hi: u32 = (pcie_pio_base >> 32) as u32;
    let pio_base_lo: u32 = (pcie_pio_base & 0xffff_ffff) as u32;
    let pio_size_hi: u32 = (pcie_pio_size >> 32) as u32;
    let pio_size_lo: u32 = (pcie_pio_size & 0xffff_ffff) as u32;

    fdt.set_property_array_u32(
        "ranges",
        &[
            fdt_pci_pio_type,
            0,
            0,
            pio_base_hi,
            pio_base_lo,
            pio_size_hi,
            pio_size_lo,
            fdt_pci_mmio_type,
            mmio_base_hi,
            mmio_base_lo,
            mmio_base_hi,
            mmio_base_lo,
            mmio_size_hi,
            mmio_size_lo,
            fdt_pci_mmio_type_64bit,
            high_mmio_base_hi,
            high_mmio_base_lo,
            high_mmio_base_hi,
            high_mmio_base_lo,
            high_mmio_size_hi,
            high_mmio_size_lo,
        ],
    )?;

    fdt.set_property_u32("msi-parent", device_tree::GIC_ITS_PHANDLE)?;
    fdt.end_node(pci_node_dep)?;
    Ok(())
}

// Function that helps to generate Virtio-Mmio device's node in device-tree.
//
// # Arguments
//
// * `dev_info` - Device resource info of Virtio-Mmio device.
// * `fdt` - Flatted device-tree blob where node will be filled into.
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

/// Function that helps to generate flash node in device-tree.
///
/// # Arguments
///
/// * `dev_info` - Device resource info of fw-cfg device.
/// * `flash` - Flatted device-tree blob where fw-cfg node will be filled into.
fn generate_flash_device_node(fdt: &mut FdtBuilder) -> util::Result<()> {
    let flash_base = MEM_LAYOUT[LayoutEntryType::Flash as usize].0;
    let flash_size = MEM_LAYOUT[LayoutEntryType::Flash as usize].1 / 2;
    let node = format!("flash@{:x}", flash_base);
    let flash_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "cfi-flash")?;
    fdt.set_property_array_u64(
        "reg",
        &[flash_base, flash_size, flash_base + flash_size, flash_size],
    )?;
    fdt.set_property_u32("bank-width", 4)?;
    fdt.end_node(flash_node_dep)?;
    Ok(())
}

/// Function that helps to generate fw-cfg node in device-tree.
///
/// # Arguments
///
/// * `dev_info` - Device resource info of fw-cfg device.
/// * `fdt` - Flatted device-tree blob where fw-cfg node will be filled into.
fn generate_fwcfg_device_node(fdt: &mut FdtBuilder, res: &SysRes) -> util::Result<()> {
    let node = format!("fw-cfg@{:x}", res.region_base);
    let fwcfg_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "qemu,fw-cfg-mmio")?;
    fdt.set_property_array_u64("reg", &[res.region_base, res.region_size])?;
    fdt.end_node(fwcfg_node_dep)?;

    Ok(())
}

// Function that helps to generate serial node in device-tree.
//
// # Arguments
//
// * `dev_info` - Device resource info of serial device.
// * `fdt` - Flatted device-tree blob where serial node will be filled into.
fn generate_serial_device_node(fdt: &mut FdtBuilder, res: &SysRes) -> util::Result<()> {
    let node = format!("pl011@{:x}", res.region_base);
    let serial_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "arm,pl011\0arm,primecell")?;
    fdt.set_property_string("clock-names", "uartclk\0apb_pclk")?;
    fdt.set_property_array_u32(
        "clocks",
        &[device_tree::CLK_PHANDLE, device_tree::CLK_PHANDLE],
    )?;
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
trait CompileFDTHelper {
    /// Function that helps to generate cpu nodes.
    fn generate_cpu_nodes(&self, fdt: &mut FdtBuilder) -> util::Result<()>;
    /// Function that helps to generate memory nodes.
    fn generate_memory_node(&self, fdt: &mut FdtBuilder) -> util::Result<()>;
    /// Function that helps to generate Virtio-mmio devices' nodes.
    fn generate_devices_node(&self, fdt: &mut FdtBuilder) -> util::Result<()>;
    /// Function that helps to generate the chosen node.
    fn generate_chosen_node(&self, fdt: &mut FdtBuilder) -> util::Result<()>;
    /// Function that helps to generate numa node distances.
    fn generate_distance_node(&self, fdt: &mut FdtBuilder) -> util::Result<()>;
}

impl CompileFDTHelper for StdMachine {
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
                        let vcpuid = self.cpu_topo.threads * self.cpu_topo.cores * cluster
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
            fdt.set_property_u32("phandle", device_tree::FIRST_VCPU_PHANDLE)?;

            if let Some(numa_nodes) = &self.numa_nodes {
                for numa_index in 0..numa_nodes.len() {
                    let numa_node = numa_nodes.get(&(numa_index as u32));
                    if numa_node.unwrap().cpus.contains(&(cpu_index)) {
                        fdt.set_property_u32("numa-node-id", numa_index as u32)?;
                    }
                }
            }

            fdt.end_node(mpidr_node_dep)?;
        }

        fdt.end_node(cpus_node_dep)?;

        if self.cpu_features.pmu {
            generate_pmu_node(fdt)?;
        }

        Ok(())
    }

    fn generate_memory_node(&self, fdt: &mut FdtBuilder) -> util::Result<()> {
        if self.numa_nodes.is_none() {
            let mem_base = MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
            let mem_size = self.sys_mem.memory_end_address().raw_value()
                - MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
            let node = "memory";
            let memory_node_dep = fdt.begin_node(node)?;
            fdt.set_property_string("device_type", "memory")?;
            fdt.set_property_array_u64("reg", &[mem_base, mem_size])?;
            fdt.end_node(memory_node_dep)?;

            return Ok(());
        }

        // Set NUMA node information.
        let mut mem_base = MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
        for (id, node) in self.numa_nodes.as_ref().unwrap().iter().enumerate() {
            let mem_size = node.1.size;
            let node = format!("memory@{:x}", mem_base);
            let memory_node_dep = fdt.begin_node(&node)?;
            fdt.set_property_string("device_type", "memory")?;
            fdt.set_property_array_u64("reg", &[mem_base, mem_size])?;
            fdt.set_property_u32("numa-node-id", id as u32)?;
            fdt.end_node(memory_node_dep)?;
            mem_base += mem_size;
        }

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
            match locked_dev.sysbusdev_base().dev_type {
                SysBusDevType::PL011 => {
                    // SAFETY: Legacy devices guarantee is not empty.
                    generate_serial_device_node(fdt, &locked_dev.sysbusdev_base().res)?
                }
                SysBusDevType::Rtc => {
                    // SAFETY: Legacy devices guarantee is not empty.
                    generate_rtc_device_node(fdt, &locked_dev.sysbusdev_base().res)?
                }
                SysBusDevType::VirtioMmio => {
                    // SAFETY: Legacy devices guarantee is not empty.
                    generate_virtio_devices_node(fdt, &locked_dev.sysbusdev_base().res)?
                }
                SysBusDevType::FwCfg => {
                    // SAFETY: Legacy devices guarantee is not empty.
                    generate_fwcfg_device_node(fdt, &locked_dev.sysbusdev_base().res)?;
                }
                _ => (),
            }
        }
        generate_flash_device_node(fdt)?;

        generate_pci_host_node(fdt)?;

        Ok(())
    }

    fn generate_chosen_node(&self, fdt: &mut FdtBuilder) -> util::Result<()> {
        let node = "chosen";

        let boot_source = self.boot_source.lock().unwrap();

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
        fdt.end_node(chosen_node_dep)?;

        Ok(())
    }

    fn generate_distance_node(&self, fdt: &mut FdtBuilder) -> util::Result<()> {
        if self.numa_nodes.is_none() {
            return Ok(());
        }

        let distance_node_dep = fdt.begin_node("distance-map")?;
        fdt.set_property_string("compatible", "numa-distance-map-v1")?;

        let mut matrix = Vec::new();
        let numa_nodes = self.numa_nodes.as_ref().unwrap();
        let existing_nodes: Vec<u32> = numa_nodes.keys().cloned().collect();
        for (id, node) in numa_nodes.iter().enumerate() {
            let distances = &node.1.distances;
            for i in existing_nodes.iter() {
                matrix.push(id as u32);
                matrix.push(*i);
                let dist: u32 = if id as u32 == *i {
                    10
                } else if let Some(distance) = distances.get(i) {
                    *distance as u32
                } else {
                    20
                };
                matrix.push(dist);
            }
        }

        fdt.set_property_array_u32("distance-matrix", matrix.as_ref())?;
        fdt.end_node(distance_node_dep)?;

        Ok(())
    }
}

impl device_tree::CompileFDT for StdMachine {
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
        self.irq_chip.as_ref().unwrap().generate_fdt_node(fdt)?;
        self.generate_distance_node(fdt)?;
        fdt.end_node(node_dep)?;

        Ok(())
    }
}
