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

pub use crate::error::MachineError;

use std::mem::size_of;
use std::ops::Deref;
#[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
use std::sync::RwLock;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use log::{error, info, warn};
use vmm_sys_util::eventfd::EventFd;

use crate::standard_common::{AcpiBuilder, StdMachineOps};
use crate::{MachineBase, MachineOps};
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
#[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
use address_space::FileBackend;
use address_space::{AddressSpace, GuestAddress, Region};
use cpu::{CPUInterface, CPUTopology, CpuLifecycleState, PMU_INTR, PPI_BASE};

use super::pci_host_root::PciHostRoot;
use crate::standard_common::syscall::syscall_whitelist;
use devices::acpi::ged::{acpi_dsdt_add_power_button, Ged, GedEvent};
use devices::acpi::power::PowerDev;
#[cfg(feature = "ramfb")]
use devices::legacy::Ramfb;
use devices::legacy::{
    FwCfgEntryType, FwCfgMem, FwCfgOps, LegacyError as DevErrorKind, PFlash, PL011, PL031,
};
use devices::pci::{PciDevOps, PciHost, PciIntxState};
use devices::sysbus::SysBusDevType;
use devices::{ICGICConfig, ICGICv3Config, GIC_IRQ_MAX};
use hypervisor::kvm::aarch64::*;
use hypervisor::kvm::*;
#[cfg(feature = "ramfb")]
use machine_manager::config::parse_ramfb;
use machine_manager::config::ShutdownAction;
#[cfg(feature = "gtk")]
use machine_manager::config::UiContext;
use machine_manager::config::{
    parse_incoming_uri, BootIndexInfo, MigrateMode, NumaNode, PFlashConfig, SerialConfig, VmConfig,
};
use machine_manager::event;
use machine_manager::machine::{
    MachineExternalInterface, MachineInterface, MachineLifecycle, MachineTestInterface,
    MigrateInterface, VmState,
};
use machine_manager::qmp::{qmp_channel::QmpChannel, qmp_response::Response, qmp_schema};
use migration::{MigrationManager, MigrationStatus};
#[cfg(feature = "gtk")]
use ui::gtk::gtk_display_init;
#[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
use ui::ohui_srv::{ohui_init, OhUiServer};
#[cfg(feature = "vnc")]
use ui::vnc::vnc_init;
use util::byte_code::ByteCode;
use util::device_tree::{self, CompileFDT, FdtBuilder};
use util::loop_context::EventLoopManager;
use util::seccomp::{BpfRule, SeccompCmpOpt};
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
    /// Machine base members.
    base: MachineBase,
    /// PCI/PCIe host bridge.
    pci_host: Arc<Mutex<PciHost>>,
    /// VM power button, handle VM `Shutdown` event.
    pub power_button: Arc<EventFd>,
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
    /// List contains the boot order of boot devices.
    boot_order_list: Arc<Mutex<Vec<BootIndexInfo>>>,
    /// OHUI server
    #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
    ohui_server: Option<Arc<OhUiServer>>,
}

impl StdMachine {
    pub fn new(vm_config: &VmConfig) -> Result<Self> {
        let free_irqs = (
            IRQ_MAP[IrqEntryType::Sysbus as usize].0,
            IRQ_MAP[IrqEntryType::Sysbus as usize].1,
        );
        let mmio_region: (u64, u64) = (
            MEM_LAYOUT[LayoutEntryType::Mmio as usize].0,
            MEM_LAYOUT[LayoutEntryType::Mmio as usize + 1].0,
        );
        let base = MachineBase::new(vm_config, free_irqs, mmio_region)?;
        let sys_mem = base.sys_mem.clone();

        Ok(StdMachine {
            base,
            pci_host: Arc::new(Mutex::new(PciHost::new(
                &sys_mem,
                MEM_LAYOUT[LayoutEntryType::HighPcieEcam as usize],
                MEM_LAYOUT[LayoutEntryType::PcieMmio as usize],
                MEM_LAYOUT[LayoutEntryType::PciePio as usize],
                MEM_LAYOUT[LayoutEntryType::HighPcieMmio as usize],
                IRQ_MAP[IrqEntryType::Pcie as usize].0,
            ))),
            power_button: Arc::new(
                EventFd::new(libc::EFD_NONBLOCK)
                    .with_context(|| MachineError::InitEventFdErr("power_button".to_string()))?,
            ),
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
            boot_order_list: Arc::new(Mutex::new(Vec::new())),
            #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
            ohui_server: None,
        })
    }

    pub fn handle_reset_request(vm: &Arc<Mutex<Self>>) -> Result<()> {
        let mut locked_vm = vm.lock().unwrap();
        let mut fdt_addr: u64 = 0;

        for (cpu_index, cpu) in locked_vm.base.cpus.iter().enumerate() {
            cpu.pause()
                .with_context(|| format!("Failed to pause vcpu{}", cpu_index))?;

            cpu.hypervisor_cpu.reset_vcpu(cpu.clone())?;
            if cpu_index == 0 {
                fdt_addr = cpu.arch().lock().unwrap().core_regs().regs.regs[0];
            }
        }

        locked_vm
            .base
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

        locked_vm.base.irq_chip.as_ref().unwrap().reset()?;

        for (cpu_index, cpu) in locked_vm.base.cpus.iter().enumerate() {
            cpu.resume()
                .with_context(|| format!("Failed to resume vcpu{}", cpu_index))?;
        }

        Ok(())
    }

    pub fn handle_destroy_request(vm: &Arc<Mutex<Self>>) -> Result<()> {
        let locked_vm = vm.lock().unwrap();
        let vmstate = {
            let state = locked_vm.base.vm_state.deref().0.lock().unwrap();
            *state
        };

        if !locked_vm.notify_lifecycle(vmstate, VmState::Shutdown) {
            warn!("Failed to destroy guest, destroy continue.");
            if locked_vm.shutdown_req.write(1).is_err() {
                error!("Failed to send shutdown request.")
            }
        }

        info!("vm destroy");

        Ok(())
    }

    fn build_pptt_cores(&self, pptt: &mut AcpiTable, cluster_offset: u32, uid: &mut u32) {
        for core in 0..self.base.cpu_topo.cores {
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

            if self.base.cpu_topo.threads > 1 {
                let core_offset = pptt.table_len();
                let core_hierarchy_node =
                    ProcessorHierarchyNode::new(0x0, cluster_offset, core as u32, 3);
                pptt.append_child(&core_hierarchy_node.aml_bytes());
                processor_append_priv_res(pptt, priv_resources);
                for _thread in 0..self.base.cpu_topo.threads {
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
        for cluster in 0..self.base.cpu_topo.clusters {
            let cluster_offset = pptt.table_len();
            let cluster_hierarchy_node =
                ProcessorHierarchyNode::new(0x0, socket_offset, cluster as u32, 0);
            pptt.append_child(&cluster_hierarchy_node.aml_bytes());
            self.build_pptt_cores(pptt, cluster_offset as u32, uid);
        }
    }

    fn build_pptt_sockets(&self, pptt: &mut AcpiTable, uid: &mut u32) {
        for socket in 0..self.base.cpu_topo.sockets {
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

    pub fn get_vcpu_reg_val(&self, addr: u64, vcpu_index: usize) -> Option<u128> {
        if let Some(vcpu) = self.get_cpus().get(vcpu_index) {
            let (cpu_state, _) = vcpu.state();
            let cpu_state = *cpu_state.lock().unwrap();
            if cpu_state != CpuLifecycleState::Paused {
                self.pause();
            }

            let value = match vcpu.hypervisor_cpu.get_one_reg(addr) {
                Ok(value) => Some(value),
                _ => None,
            };

            if cpu_state != CpuLifecycleState::Paused {
                self.resume();
            }
            return value;
        }
        None
    }

    #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
    fn add_ohui_server(&mut self, vm_config: &VmConfig) -> Result<()> {
        if let Some(dpy) = vm_config.display.as_ref() {
            if !dpy.ohui_config.ohui {
                return Ok(());
            }
            self.ohui_server = Some(Arc::new(OhUiServer::new(dpy.get_ui_path())?));
        }
        Ok(())
    }
}

impl StdMachineOps for StdMachine {
    fn init_pci_host(&self) -> Result<()> {
        let root_bus = Arc::downgrade(&self.pci_host.lock().unwrap().root_bus);
        let mmconfig_region_ops = PciHost::build_mmconfig_ops(self.pci_host.clone());
        let mmconfig_region = Region::init_io_region(
            MEM_LAYOUT[LayoutEntryType::HighPcieEcam as usize].1,
            mmconfig_region_ops,
            "PcieEcamIo",
        );
        self.base
            .sys_mem
            .root()
            .add_subregion(
                mmconfig_region,
                MEM_LAYOUT[LayoutEntryType::HighPcieEcam as usize].0,
            )
            .with_context(|| "Failed to register ECAM in memory space.")?;

        let pcihost_root = PciHostRoot::new(root_bus);
        pcihost_root
            .realize()
            .with_context(|| "Failed to realize pcihost root device.")
    }

    fn add_fwcfg_device(&mut self, nr_cpus: u8) -> Result<Option<Arc<Mutex<dyn FwCfgOps>>>> {
        if self.base.vm_config.lock().unwrap().pflashs.is_none() {
            return Ok(None);
        }

        let mut fwcfg = FwCfgMem::new(self.base.sys_mem.clone());
        fwcfg
            .add_data_entry(FwCfgEntryType::NbCpus, nr_cpus.as_bytes().to_vec())
            .with_context(|| DevErrorKind::AddEntryErr("NbCpus".to_string()))?;

        let cmdline = self
            .base
            .boot_source
            .lock()
            .unwrap()
            .kernel_cmdline
            .to_string();
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
            &mut self.base.sysbus,
            MEM_LAYOUT[LayoutEntryType::FwCfg as usize].0,
            MEM_LAYOUT[LayoutEntryType::FwCfg as usize].1,
        )
        .with_context(|| "Failed to realize fwcfg device")?;
        self.base.fwcfg_dev = Some(fwcfg_dev.clone());

        Ok(Some(fwcfg_dev))
    }
}

impl MachineOps for StdMachine {
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
        let intc_conf = ICGICConfig {
            version: None,
            vcpu_count,
            max_irq: GIC_IRQ_MAX,
            v2: None,
            v3: Some(v3),
        };

        let hypervisor = self.get_hypervisor();
        let mut locked_hypervisor = hypervisor.lock().unwrap();
        self.base.irq_chip = Some(locked_hypervisor.create_interrupt_controller(&intc_conf)?);
        self.base.irq_chip.as_ref().unwrap().realize()?;

        let root_bus = &self.pci_host.lock().unwrap().root_bus;
        let irq_manager = locked_hypervisor.create_irq_manager()?;
        root_bus.lock().unwrap().msi_irq_manager = irq_manager.msi_irq_manager;
        let line_irq_manager = irq_manager.line_irq_manager;
        if let Some(line_irq_manager) = line_irq_manager.clone() {
            let irq_state = Some(Arc::new(Mutex::new(PciIntxState::new(
                IRQ_MAP[IrqEntryType::Pcie as usize].0 as u32,
                line_irq_manager.clone(),
            ))));
            root_bus.lock().unwrap().intx_state = irq_state;
        } else {
            return Err(anyhow!(
                "Failed to create intx state: legacy irq manager is none."
            ));
        }
        self.base.sysbus.irq_manager = line_irq_manager;

        Ok(())
    }

    fn add_rtc_device(&mut self) -> Result<()> {
        let rtc = PL031::default();
        PL031::realize(
            rtc,
            &mut self.base.sysbus,
            MEM_LAYOUT[LayoutEntryType::Rtc as usize].0,
            MEM_LAYOUT[LayoutEntryType::Rtc as usize].1,
        )
        .with_context(|| "Failed to realize PL031")
    }

    fn add_ged_device(&mut self) -> Result<()> {
        let battery_present = self.base.vm_config.lock().unwrap().machine_config.battery;
        let ged = Ged::default();
        let ged_dev = ged
            .realize(
                &mut self.base.sysbus,
                GedEvent::new(self.power_button.clone()),
                battery_present,
                MEM_LAYOUT[LayoutEntryType::Ged as usize].0,
                MEM_LAYOUT[LayoutEntryType::Ged as usize].1,
            )
            .with_context(|| "Failed to realize Ged")?;
        if battery_present {
            let pdev = PowerDev::new(ged_dev);
            pdev.realize(
                &mut self.base.sysbus,
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
                &mut self.base.sysbus,
                region_base,
                region_size,
                &self.base.boot_source,
            )
            .with_context(|| "Failed to realize PL011")
    }

    fn syscall_whitelist(&self) -> Vec<BpfRule> {
        syscall_whitelist()
    }

    #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
    fn update_ohui_srv(&mut self, passthru: bool) {
        self.ohui_server.as_ref().unwrap().set_passthru(passthru);
    }

    #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
    fn get_ohui_fb(&self) -> Option<FileBackend> {
        match &self.ohui_server {
            Some(server) => server.get_ohui_fb(),
            None => None,
        }
    }

    fn realize(vm: &Arc<Mutex<Self>>, vm_config: &mut VmConfig) -> Result<()> {
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

        locked_vm.base.numa_nodes = locked_vm.add_numa_nodes(vm_config)?;
        let locked_hypervisor = locked_vm.base.hypervisor.lock().unwrap();
        locked_hypervisor.init_machine(&locked_vm.base.sys_mem)?;
        drop(locked_hypervisor);
        locked_vm.init_memory(
            &vm_config.machine_config.mem_config,
            &locked_vm.base.sys_mem,
            nr_cpus,
        )?;

        locked_vm
            .init_pci_host()
            .with_context(|| MachineError::InitPCIeHostErr)?;
        let fwcfg = locked_vm.add_fwcfg_device(nr_cpus)?;

        let boot_config = locked_vm
            .load_boot_source(fwcfg.as_ref(), MEM_LAYOUT[LayoutEntryType::Mem as usize].0)?;
        let cpu_config = locked_vm.load_cpu_features(vm_config)?;

        let hypervisor = locked_vm.base.hypervisor.clone();
        locked_vm.base.cpus.extend(<Self as MachineOps>::init_vcpu(
            vm.clone(),
            hypervisor,
            nr_cpus,
            &CPUTopology::new(),
            &boot_config,
            &cpu_config,
        )?);

        // Interrupt Controller Chip init
        locked_vm.init_interrupt_controller(u64::from(nr_cpus))?;

        locked_vm.cpu_post_init(&cpu_config)?;

        #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
        locked_vm.add_ohui_server(vm_config)?;

        locked_vm
            .add_devices(vm_config)
            .with_context(|| "Failed to add devices")?;

        let mut fdt_helper = FdtBuilder::new();
        locked_vm
            .generate_fdt_node(&mut fdt_helper)
            .with_context(|| MachineError::GenFdtErr)?;
        let fdt_vec = fdt_helper.finish()?;
        locked_vm.dtb_vec = fdt_vec.clone();
        locked_vm
            .base
            .sys_mem
            .write(
                &mut fdt_vec.as_slice(),
                GuestAddress(boot_config.fdt_addr),
                fdt_vec.len() as u64,
            )
            .with_context(|| MachineError::WrtFdtErr(boot_config.fdt_addr, fdt_vec.len()))?;

        // If it is direct kernel boot mode, the ACPI can not be enabled.
        if let Some(fw_cfg) = fwcfg {
            let mut mem_array = Vec::new();
            let mem_size = vm_config.machine_config.mem_config.mem_size;
            mem_array.push((MEM_LAYOUT[LayoutEntryType::Mem as usize].0, mem_size));
            locked_vm
                .build_acpi_tables(&fw_cfg)
                .with_context(|| "Failed to create ACPI tables")?;
            locked_vm
                .build_smbios(&fw_cfg, mem_array)
                .with_context(|| "Failed to create smbios tables")?;
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
        MigrationManager::register_migration_instance(locked_vm.base.migration_hypervisor.clone());
        if let Err(e) = MigrationManager::set_status(MigrationStatus::Setup) {
            bail!("Failed to set migration status {}", e);
        }
        Ok(())
    }

    fn add_pflash_device(&mut self, configs: &[PFlashConfig]) -> Result<()> {
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
                .with_context(|| MachineError::InitPflashErr)?;
            PFlash::realize(pflash, &mut self.base.sysbus, flash_base, flash_size, fd)
                .with_context(|| MachineError::RlzPflashErr)?;
            flash_base += flash_size;
        }

        Ok(())
    }

    /// Create display.
    #[allow(unused_variables)]
    fn display_init(&mut self, vm_config: &mut VmConfig) -> Result<()> {
        // GTK display init.
        #[cfg(any(feature = "gtk", all(target_env = "ohos", feature = "ohui_srv")))]
        match vm_config.display {
            #[cfg(feature = "gtk")]
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
            // OHUI server init.
            #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
            Some(ref ds_cfg) if ds_cfg.ohui_config.ohui => {
                ohui_init(self.ohui_server.as_ref().unwrap().clone(), ds_cfg)
                    .with_context(|| "Failed to init OH UI server!")?;
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
        ramfb.realize(&mut self.base.sysbus)
    }

    fn get_pci_host(&mut self) -> Result<&Arc<Mutex<PciHost>>> {
        Ok(&self.pci_host)
    }

    fn get_boot_order_list(&self) -> Option<Arc<Mutex<Vec<BootIndexInfo>>>> {
        Some(self.boot_order_list.clone())
    }

    #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
    fn get_token_id(&self) -> Option<Arc<RwLock<u64>>> {
        self.ohui_server.as_ref().map(|srv| srv.token_id.clone())
    }
}

pub(crate) fn arch_ioctl_allow_list(bpf_rule: BpfRule) -> BpfRule {
    bpf_rule
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_ONE_REG() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_DEVICE_ATTR() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_REG_LIST() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_ARM_VCPU_INIT() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_IRQ_LINE() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_SET_ONE_REG() as u32)
}

pub(crate) fn arch_syscall_whitelist() -> Vec<BpfRule> {
    vec![
        BpfRule::new(libc::SYS_epoll_pwait),
        BpfRule::new(libc::SYS_mkdirat),
        BpfRule::new(libc::SYS_unlinkat),
        BpfRule::new(libc::SYS_clone),
        BpfRule::new(libc::SYS_rt_sigaction),
        #[cfg(target_env = "gnu")]
        BpfRule::new(libc::SYS_rseq),
        #[cfg(target_env = "gnu")]
        BpfRule::new(223),
        #[cfg(target_env = "gnu")]
        BpfRule::new(libc::SYS_listen),
        #[cfg(target_env = "gnu")]
        BpfRule::new(libc::SYS_fchmodat),
        #[cfg(target_env = "gnu")]
        BpfRule::new(libc::SYS_shmctl),
        #[cfg(target_env = "gnu")]
        BpfRule::new(libc::SYS_shmat),
        #[cfg(target_env = "gnu")]
        BpfRule::new(libc::SYS_shmdt),
        #[cfg(target_env = "gnu")]
        BpfRule::new(libc::SYS_lremovexattr),
    ]
}

impl AcpiBuilder for StdMachine {
    fn build_gtdt_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> Result<u64> {
        let mut gtdt = AcpiTable::new(*b"GTDT", 2, *b"STRATO", *b"VIRTGTDT", 1);
        gtdt.set_table_len(96);

        // Counter control block physical address
        gtdt.set_field(36, 0xFFFF_FFFF_FFFF_FFFF_u64);
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
        // Counter read block physical address
        gtdt.set_field(80, 0xFFFF_FFFF_FFFF_FFFF_u64);

        let gtdt_begin = StdMachine::add_table_to_loader(acpi_data, loader, &gtdt)
            .with_context(|| "Fail to add GTDT table to loader")?;
        Ok(gtdt_begin)
    }

    fn build_dbg2_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> Result<u64> {
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
        dbg2.set_field(offset + 26, uart_memory_address);
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
    ) -> Result<u64> {
        let mut iort = AcpiTable::new(*b"IORT", 3, *b"STRATO", *b"VIRTIORT", 1);
        iort.set_table_len(128);

        // Number of IORT nodes is 2: ITS group node and Root Complex Node.
        iort.set_field(36, 2_u32);
        // Node offset
        iort.set_field(40, 48_u32);

        // ITS group node
        iort.set_field(48, ACPI_IORT_NODE_ITS_GROUP);
        // ITS node length
        iort.set_field(49, 24_u16);
        // ITS node revision
        iort.set_field(51, 1_u8);
        // ITS count
        iort.set_field(64, 1_u32);

        // Root Complex Node
        iort.set_field(72, ACPI_IORT_NODE_PCI_ROOT_COMPLEX);
        // Length of Root Complex node
        let len = ROOT_COMPLEX_ENTRY_SIZE + ID_MAPPING_ENTRY_SIZE;
        iort.set_field(73, len);
        // Revision of Root Complex node
        iort.set_field(75, 3_u8);
        // Identifier of Root Complex node
        iort.set_field(76, 1_u32);
        // Mapping counts of Root Complex Node
        iort.set_field(80, 1_u32);
        // Mapping offset of Root Complex Node
        iort.set_field(84, ROOT_COMPLEX_ENTRY_SIZE as u32);
        // Cache of coherent device
        iort.set_field(88, 1_u32);
        // Memory flags of coherent device
        iort.set_field(95, 3_u8);
        // Memory address size limit
        iort.set_field(104, 0x40_u8);
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
    ) -> Result<u64> {
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
        for dev in self.base.sysbus.devices.iter() {
            let locked_dev = dev.lock().unwrap();
            if locked_dev.sysbusdev_base().dev_type == SysBusDevType::PL011 {
                uart_irq = locked_dev.sysbusdev_base().irq_state.irq as _;
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
    ) -> Result<u64> {
        let mut dsdt = AcpiTable::new(*b"DSDT", 2, *b"STRATO", *b"VIRTDSDT", 1);

        // 1. CPU info.
        let cpus_count = self.base.cpus.len() as u64;
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
        dsdt.append_child(self.base.sysbus.aml_bytes().as_slice());

        let dsdt_begin = StdMachine::add_table_to_loader(acpi_data, loader, &dsdt)
            .with_context(|| "Fail to add DSDT table to loader")?;
        Ok(dsdt_begin)
    }

    fn build_madt_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> Result<u64> {
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
        let cpus_count = self.base.cpus.len() as u64;
        for cpu_index in 0..cpus_count {
            let mpidr = self.base.cpus[cpu_index as usize]
                .arch()
                .lock()
                .unwrap()
                .mpidr();
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
        if self.base.irq_chip.as_ref().unwrap().get_redist_count() > 1 {
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
    ) -> Result<u64> {
        let mut srat = AcpiTable::new(*b"SRAT", 1, *b"STRATO", *b"VIRTSRAT", 1);
        // Reserved
        srat.append_child(&[1_u8; 4_usize]);
        // Reserved
        srat.append_child(&[0_u8; 8_usize]);

        let mut next_base = MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
        // SAFETY: the SRAT table is created only when numa node configured.
        for (id, node) in self.base.numa_nodes.as_ref().unwrap().iter() {
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
    ) -> Result<u64> {
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
        if self.notify_lifecycle(VmState::Running, VmState::Paused) {
            event!(Stop);
            true
        } else {
            false
        }
    }

    fn resume(&self) -> bool {
        if !self.notify_lifecycle(VmState::Paused, VmState::Running) {
            return false;
        }
        event!(Resume);
        true
    }

    fn destroy(&self) -> bool {
        if self.shutdown_req.write(1).is_err() {
            error!("Failed to send shutdown request.");
            return false;
        }

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
        self.base
            .vm_config
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

    fn notify_lifecycle(&self, old: VmState, new: VmState) -> bool {
        if let Err(e) = self.vm_state_transfer(
            &self.base.cpus,
            &self.base.irq_chip,
            &mut self.base.vm_state.0.lock().unwrap(),
            old,
            new,
        ) {
            error!("VM state transfer failed: {:?}", e);
            return false;
        }
        true
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
        let vmstate = self.base.vm_state.deref().0.lock().unwrap();
        *vmstate == VmState::Shutdown
    }

    fn loop_cleanup(&self) -> Result<()> {
        set_termi_canon_mode().with_context(|| "Failed to set terminal to canonical mode")?;
        Ok(())
    }
}

/// Function that helps to generate flash node in device-tree.
///

/// Trait that helps to generate all nodes in device-tree.
#[allow(clippy::upper_case_acronyms)]
trait CompileFDTHelper {
    /// Function that helps to generate memory nodes.
    fn generate_memory_node(&self, fdt: &mut FdtBuilder) -> Result<()>;
    /// Function that helps to generate pci node in device-tree.
    fn generate_pci_host_node(&self, fdt: &mut FdtBuilder) -> Result<()>;
    /// Function that helps to generate the chosen node.
    fn generate_chosen_node(&self, fdt: &mut FdtBuilder) -> Result<()>;
}

impl CompileFDTHelper for StdMachine {
    fn generate_pci_host_node(&self, fdt: &mut FdtBuilder) -> Result<()> {
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
        fdt.end_node(pci_node_dep)
    }

    fn generate_memory_node(&self, fdt: &mut FdtBuilder) -> Result<()> {
        if self.base.numa_nodes.is_none() {
            let mem_base = MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
            let mem_size = self.base.sys_mem.memory_end_address().raw_value()
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
        for (id, node) in self.base.numa_nodes.as_ref().unwrap().iter().enumerate() {
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

impl device_tree::CompileFDT for StdMachine {
    fn generate_fdt_node(&self, fdt: &mut FdtBuilder) -> Result<()> {
        let node_dep = fdt.begin_node("")?;
        self.base.generate_fdt_node(fdt)?;
        self.generate_memory_node(fdt)?;
        self.generate_chosen_node(fdt)?;
        self.generate_pci_host_node(fdt)?;
        fdt.end_node(node_dep)
    }
}
