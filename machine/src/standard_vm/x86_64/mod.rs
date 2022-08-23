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

pub(crate) mod ich9_lpc;
mod mch;
mod syscall;

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom};
use std::mem::size_of;
use std::ops::Deref;
use std::sync::{Arc, Condvar, Mutex};

use error_chain::{bail, ChainedError};
use log::error;
use vmm_sys_util::{eventfd::EventFd, ioctl_ioc_nr, ioctl_iow_nr};

use acpi::{
    AcpiIoApic, AcpiLocalApic, AcpiSratMemoryAffinity, AcpiSratProcessorAffinity, AcpiTable,
    AmlBuilder, AmlDevice, AmlInteger, AmlNameDecl, AmlPackage, AmlScope, AmlScopeBuilder,
    AmlString, TableLoader, IOAPIC_BASE_ADDR, LAPIC_BASE_ADDR,
};
use address_space::{AddressSpace, GuestAddress, HostMemMapping, Region};
use boot_loader::{load_linux, BootLoaderConfig};
use cpu::{CPUBootConfig, CPUInterface, CPUTopology, CpuTopology, CPU};
use devices::legacy::{
    errors::ErrorKind as DevErrorKind, FwCfgEntryType, FwCfgIO, FwCfgOps, PFlash, Serial, RTC,
    SERIAL_ADDR,
};
use hypervisor::kvm::KVM_FDS;
use kvm_bindings::{kvm_pit_config, KVM_PIT_SPEAKER_DUMMY};
use machine_manager::config::{
    parse_incoming_uri, BootIndexInfo, BootSource, Incoming, MigrateMode, NumaNode, NumaNodes,
    PFlashConfig, SerialConfig, VmConfig,
};
use machine_manager::event;
use machine_manager::machine::{
    KvmVmState, MachineAddressInterface, MachineExternalInterface, MachineInterface,
    MachineLifecycle, MigrateInterface,
};
use machine_manager::qmp::{qmp_schema, QmpChannel, Response};
use mch::Mch;
use migration::{MigrationManager, MigrationStatus};
use pci::{PciDevOps, PciHost};
use sysbus::SysBus;
use syscall::syscall_whitelist;
use usb::bus::BusDeviceMap;
use util::{
    byte_code::ByteCode, loop_context::EventLoopManager, seccomp::BpfRule, set_termi_canon_mode,
};

use self::ich9_lpc::SLEEP_CTRL_OFFSET;
use super::errors::{ErrorKind, Result};
use super::{AcpiBuilder, StdMachineOps};
use crate::errors::{ErrorKind as MachineErrorKind, Result as MachineResult};
use crate::{vm_state, MachineOps};
use vnc::vnc;

const VENDOR_ID_INTEL: u16 = 0x8086;
const HOLE_640K_START: u64 = 0x000A_0000;
const HOLE_640K_END: u64 = 0x0010_0000;

/// The type of memory layout entry on x86_64
#[repr(usize)]
pub enum LayoutEntryType {
    MemBelow4g = 0_usize,
    PcieEcam,
    PcieMmio,
    Mmio,
    IoApic,
    LocalApic,
    IdentTss,
    MemAbove4g,
}

/// Layout of x86_64
pub const MEM_LAYOUT: &[(u64, u64)] = &[
    (0, 0x8000_0000),                // MemBelow4g
    (0xB000_0000, 0x1000_0000),      // PcieEcam
    (0xC000_0000, 0x3000_0000),      // PcieMmio
    (0xF010_0000, 0x200),            // Mmio
    (0xFEC0_0000, 0x10_0000),        // IoApic
    (0xFEE0_0000, 0x10_0000),        // LocalApic
    (0xFEF0_C000, 0x4000),           // Identity map address and TSS
    (0x1_0000_0000, 0x80_0000_0000), // MemAbove4g
];

/// Standard machine structure.
pub struct StdMachine {
    /// `vCPU` topology, support sockets, cores, threads.
    cpu_topo: CpuTopology,
    /// `vCPU` devices.
    cpus: Vec<Arc<CPU>>,
    /// IO address space.
    sys_io: Arc<AddressSpace>,
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
    power_button: EventFd,
    /// All configuration information of virtual machine.
    vm_config: Mutex<VmConfig>,
    /// List of guest NUMA nodes information.
    numa_nodes: Option<NumaNodes>,
    /// List contains the boot order of boot devices.
    boot_order_list: Arc<Mutex<Vec<BootIndexInfo>>>,
    /// FwCfg device.
    fwcfg_dev: Option<Arc<Mutex<FwCfgIO>>>,
    /// Bus device used to attach other devices. Only USB controller used now.
    bus_device: BusDeviceMap,
}

impl StdMachine {
    pub fn new(vm_config: &VmConfig) -> MachineResult<Self> {
        use crate::errors::ResultExt;

        let cpu_topo = CpuTopology::new(
            vm_config.machine_config.nr_cpus,
            vm_config.machine_config.nr_threads,
            vm_config.machine_config.nr_cores,
            vm_config.machine_config.nr_dies,
            vm_config.machine_config.nr_clusters,
            vm_config.machine_config.nr_sockets,
            vm_config.machine_config.max_cpus,
        );
        let sys_io = AddressSpace::new(Region::init_container_region(1 << 16))
            .chain_err(|| MachineErrorKind::CrtMemSpaceErr)?;
        let sys_mem = AddressSpace::new(Region::init_container_region(u64::max_value()))
            .chain_err(|| MachineErrorKind::CrtIoSpaceErr)?;
        let sysbus = SysBus::new(
            &sys_io,
            &sys_mem,
            (5, 15),
            (
                MEM_LAYOUT[LayoutEntryType::Mmio as usize].0,
                MEM_LAYOUT[LayoutEntryType::Mmio as usize + 1].0,
            ),
        );
        // Machine state init
        let vm_state = Arc::new((Mutex::new(KvmVmState::Created), Condvar::new()));

        Ok(StdMachine {
            cpu_topo,
            cpus: Vec::new(),
            sys_io: sys_io.clone(),
            sys_mem: sys_mem.clone(),
            sysbus,
            pci_host: Arc::new(Mutex::new(PciHost::new(
                &sys_io,
                &sys_mem,
                MEM_LAYOUT[LayoutEntryType::PcieEcam as usize],
                MEM_LAYOUT[LayoutEntryType::PcieMmio as usize],
            ))),
            boot_source: Arc::new(Mutex::new(vm_config.clone().boot_source)),
            vm_state,
            power_button: EventFd::new(libc::EFD_NONBLOCK)
                .chain_err(|| MachineErrorKind::InitEventFdErr("power_button".to_string()))?,
            vm_config: Mutex::new(vm_config.clone()),
            numa_nodes: None,
            boot_order_list: Arc::new(Mutex::new(Vec::new())),
            fwcfg_dev: None,
            bus_device: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn handle_reset_request(vm: &Arc<Mutex<Self>>) -> MachineResult<()> {
        use crate::errors::ResultExt as MachineResultExt;

        let mut locked_vm = vm.lock().unwrap();

        for (cpu_index, cpu) in locked_vm.cpus.iter().enumerate() {
            MachineResultExt::chain_err(cpu.kick(), || {
                format!("Failed to kick vcpu{}", cpu_index)
            })?;

            cpu.set_to_boot_state();
        }

        MachineResultExt::chain_err(locked_vm.reset_all_devices(), || {
            "Fail to reset all devices"
        })?;
        MachineResultExt::chain_err(locked_vm.reset_fwcfg_boot_order(), || {
            "Fail to update boot order information to FwCfg device"
        })?;

        for (cpu_index, cpu) in locked_vm.cpus.iter().enumerate() {
            MachineResultExt::chain_err(cpu.reset(), || {
                format!("Failed to reset vcpu{}", cpu_index)
            })?;
        }

        Ok(())
    }

    pub fn handle_shutdown_request(vm: &Arc<Mutex<Self>>) -> bool {
        let locked_vm = vm.lock().unwrap();
        for (cpu_index, cpu) in locked_vm.cpus.iter().enumerate() {
            if let Err(e) = cpu.destroy() {
                error!(
                    "Failed to destroy vcpu{}, error is {}",
                    cpu_index,
                    e.display_chain()
                );
            }
        }

        let mut vmstate = locked_vm.vm_state.0.lock().unwrap();
        *vmstate = KvmVmState::Shutdown;
        true
    }

    fn arch_init() -> MachineResult<()> {
        use crate::errors::ResultExt;

        let kvm_fds = KVM_FDS.load();
        let vm_fd = kvm_fds.vm_fd.as_ref().unwrap();
        let identity_addr: u64 = MEM_LAYOUT[LayoutEntryType::IdentTss as usize].0;

        ioctl_iow_nr!(
            KVM_SET_IDENTITY_MAP_ADDR,
            kvm_bindings::KVMIO,
            0x48,
            std::os::raw::c_ulong
        );
        // Safe because the following ioctl only sets identity map address to KVM.
        unsafe {
            vmm_sys_util::ioctl::ioctl_with_ref(vm_fd, KVM_SET_IDENTITY_MAP_ADDR(), &identity_addr);
        }
        // Page table takes 1 page, TSS takes the following 3 pages.
        vm_fd
            .set_tss_address((identity_addr + 0x1000) as usize)
            .chain_err(|| MachineErrorKind::SetTssErr)?;

        let pit_config = kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            pad: Default::default(),
        };
        vm_fd
            .create_pit2(pit_config)
            .chain_err(|| MachineErrorKind::CrtPitErr)?;
        Ok(())
    }

    fn init_ich9_lpc(&self, vm: Arc<Mutex<StdMachine>>) -> Result<()> {
        use super::errors::ResultExt;

        let clone_vm = vm.clone();
        let root_bus = Arc::downgrade(&self.pci_host.lock().unwrap().root_bus);
        let ich = ich9_lpc::LPCBridge::new(root_bus, self.sys_io.clone());
        self.register_reset_event(&ich.reset_req, vm)
            .chain_err(|| "Fail to register reset event in LPC")?;
        self.register_acpi_shutdown_event(&ich.shutdown_req, clone_vm)
            .chain_err(|| "Fail to register shutdown event in LPC")?;
        PciDevOps::realize(ich)?;
        Ok(())
    }
}

impl StdMachineOps for StdMachine {
    fn init_pci_host(&self) -> Result<()> {
        use super::errors::ResultExt;

        let root_bus = Arc::downgrade(&self.pci_host.lock().unwrap().root_bus);
        let mmconfig_region_ops = PciHost::build_mmconfig_ops(self.pci_host.clone());
        let mmconfig_region = Region::init_io_region(
            MEM_LAYOUT[LayoutEntryType::PcieEcam as usize].1,
            mmconfig_region_ops.clone(),
        );
        self.sys_mem
            .root()
            .add_subregion(
                mmconfig_region.clone(),
                MEM_LAYOUT[LayoutEntryType::PcieEcam as usize].0,
            )
            .chain_err(|| "Failed to register ECAM in memory space.")?;

        let pio_addr_ops = PciHost::build_pio_addr_ops(self.pci_host.clone());
        let pio_addr_region = Region::init_io_region(4, pio_addr_ops);
        self.sys_io
            .root()
            .add_subregion(pio_addr_region, 0xcf8)
            .chain_err(|| "Failed to register CONFIG_ADDR port in I/O space.")?;
        let pio_data_ops = PciHost::build_pio_data_ops(self.pci_host.clone());
        let pio_data_region = Region::init_io_region(4, pio_data_ops);
        self.sys_io
            .root()
            .add_subregion(pio_data_region, 0xcfc)
            .chain_err(|| "Failed to register CONFIG_DATA port in I/O space.")?;

        let mch = Mch::new(root_bus, mmconfig_region, mmconfig_region_ops);
        PciDevOps::realize(mch)?;
        Ok(())
    }

    fn add_fwcfg_device(&mut self) -> super::errors::Result<Arc<Mutex<dyn FwCfgOps>>> {
        use super::errors::ResultExt;

        let mut fwcfg = FwCfgIO::new(self.sys_mem.clone());
        let ncpus = self.cpus.len();
        fwcfg.add_data_entry(FwCfgEntryType::NbCpus, ncpus.as_bytes().to_vec())?;
        fwcfg.add_data_entry(FwCfgEntryType::MaxCpus, ncpus.as_bytes().to_vec())?;
        fwcfg.add_data_entry(FwCfgEntryType::Irq0Override, 1_u32.as_bytes().to_vec())?;

        let boot_order = Vec::<u8>::new();
        fwcfg
            .add_file_entry("bootorder", boot_order)
            .chain_err(|| DevErrorKind::AddEntryErr("bootorder".to_string()))?;

        let fwcfg_dev = FwCfgIO::realize(fwcfg, &mut self.sysbus)
            .chain_err(|| "Failed to realize fwcfg device")?;
        self.fwcfg_dev = Some(fwcfg_dev.clone());

        Ok(fwcfg_dev)
    }

    fn get_vm_state(&self) -> &Arc<(Mutex<KvmVmState>, Condvar)> {
        &self.vm_state
    }

    fn get_cpu_topo(&self) -> &CpuTopology {
        &self.cpu_topo
    }

    fn get_cpus(&self) -> &Vec<Arc<CPU>> {
        &self.cpus
    }

    fn get_numa_nodes(&self) -> &Option<NumaNodes> {
        &self.numa_nodes
    }
}

impl MachineOps for StdMachine {
    fn arch_ram_ranges(&self, mem_size: u64) -> Vec<(u64, u64)> {
        let gap_start = MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].0
            + MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].1;

        let mut ranges = vec![(0, std::cmp::min(gap_start, mem_size))];
        if mem_size > gap_start {
            let gap_end = MEM_LAYOUT[LayoutEntryType::MemAbove4g as usize].0;
            ranges.push((gap_end, mem_size - gap_start));
        }
        ranges
    }

    fn init_interrupt_controller(&mut self, _vcpu_count: u64) -> MachineResult<()> {
        use crate::errors::ResultExt;

        KVM_FDS
            .load()
            .vm_fd
            .as_ref()
            .unwrap()
            .create_irq_chip()
            .chain_err(|| MachineErrorKind::CrtIrqchipErr)?;
        KVM_FDS
            .load()
            .irq_route_table
            .lock()
            .unwrap()
            .init_irq_route_table();
        KVM_FDS.load().commit_irq_routing()?;
        Ok(())
    }

    fn load_boot_source(
        &self,
        fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>,
    ) -> MachineResult<CPUBootConfig> {
        use crate::errors::ResultExt;

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
            ident_tss_range: Some(MEM_LAYOUT[LayoutEntryType::IdentTss as usize]),
            prot64_mode: false,
        };
        let layout = load_linux(&bootloader_config, &self.sys_mem, fwcfg)
            .chain_err(|| MachineErrorKind::LoadKernErr)?;

        Ok(CPUBootConfig {
            prot64_mode: false,
            boot_ip: layout.boot_ip,
            boot_sp: layout.boot_sp,
            boot_selector: layout.boot_selector,
            ..Default::default()
        })
    }

    fn add_rtc_device(&mut self, mem_size: u64) -> MachineResult<()> {
        use crate::errors::ResultExt;

        let mut rtc = RTC::new().chain_err(|| "Failed to create RTC device")?;
        rtc.set_memory(
            mem_size,
            MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].0
                + MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].1,
        );
        RTC::realize(rtc, &mut self.sysbus).chain_err(|| "Failed to realize RTC device")?;

        Ok(())
    }

    fn add_serial_device(&mut self, config: &SerialConfig) -> MachineResult<()> {
        use crate::errors::ResultExt;
        let region_base: u64 = SERIAL_ADDR;
        let region_size: u64 = 8;
        let serial = Serial::new(config.clone());
        serial
            .realize(&mut self.sysbus, region_base, region_size)
            .chain_err(|| "Failed to realize serial device.")?;
        Ok(())
    }

    fn syscall_whitelist(&self) -> Vec<BpfRule> {
        syscall_whitelist()
    }

    fn realize(vm: &Arc<Mutex<Self>>, vm_config: &mut VmConfig) -> MachineResult<()> {
        use crate::errors::ResultExt;

        let clone_vm = vm.clone();
        let mut locked_vm = vm.lock().unwrap();
        locked_vm.init_global_config(vm_config)?;
        locked_vm.numa_nodes = locked_vm.add_numa_nodes(vm_config)?;
        locked_vm.init_memory(
            &vm_config.machine_config.mem_config,
            &locked_vm.sys_io,
            &locked_vm.sys_mem,
            vm_config.machine_config.nr_cpus,
        )?;

        locked_vm.init_interrupt_controller(u64::from(vm_config.machine_config.nr_cpus))?;
        let kvm_fds = KVM_FDS.load();
        let vm_fd = kvm_fds.vm_fd.as_ref().unwrap();
        let nr_cpus = vm_config.machine_config.nr_cpus;
        let mut vcpu_fds = vec![];
        for cpu_id in 0..nr_cpus {
            vcpu_fds.push(Arc::new(vm_fd.create_vcpu(cpu_id as u64)?));
        }

        locked_vm
            .init_pci_host()
            .chain_err(|| ErrorKind::InitPCIeHostErr)?;
        locked_vm
            .init_ich9_lpc(clone_vm)
            .chain_err(|| "Fail to init LPC bridge")?;
        locked_vm.add_devices(vm_config)?;
        vnc::vnc_init(&vm_config.vnc, &vm_config.object)
            .chain_err(|| "Failed to init VNC server!")?;
        let fwcfg = locked_vm.add_fwcfg_device()?;

        let migrate = locked_vm.get_migrate_info();
        let boot_config = if migrate.0 == MigrateMode::Unknown {
            Some(locked_vm.load_boot_source(Some(&fwcfg))?)
        } else {
            None
        };
        let topology = CPUTopology::new().set_topology((
            vm_config.machine_config.nr_threads,
            vm_config.machine_config.nr_cores,
            vm_config.machine_config.nr_dies,
        ));
        locked_vm.cpus.extend(<Self as MachineOps>::init_vcpu(
            vm.clone(),
            vm_config.machine_config.nr_cpus,
            &topology,
            &vcpu_fds,
            &boot_config,
        )?);

        if migrate.0 == MigrateMode::Unknown {
            locked_vm
                .build_acpi_tables(&fwcfg)
                .chain_err(|| "Failed to create ACPI tables")?;
        }

        StdMachine::arch_init()?;
        locked_vm.register_power_event(&locked_vm.power_button)?;

        locked_vm
            .reset_fwcfg_boot_order()
            .chain_err(|| "Fail to update boot order imformation to FwCfg device")?;

        MigrationManager::register_vm_config(vm_config);
        MigrationManager::register_vm_instance(vm.clone());
        MigrationManager::register_kvm_instance(
            vm_state::KvmDeviceState::descriptor(),
            Arc::new(vm_state::KvmDevice {}),
        );
        if let Err(e) = MigrationManager::set_status(MigrationStatus::Setup) {
            bail!("Failed to set migration status {}", e);
        }

        Ok(())
    }

    fn add_pflash_device(&mut self, configs: &[PFlashConfig]) -> MachineResult<()> {
        use super::errors::ResultExt;

        let mut configs_vec = configs.to_vec();
        configs_vec.sort_by_key(|c| c.unit);
        // The two PFlash devices locates below 4GB, this variable represents the end address
        // of current PFlash device.
        let mut flash_end: u64 = MEM_LAYOUT[LayoutEntryType::MemAbove4g as usize].0;
        for config in configs_vec {
            let mut fd = OpenOptions::new()
                .read(true)
                .write(!config.read_only)
                .open(&config.path_on_host)
                .chain_err(|| ErrorKind::OpenFileErr(config.path_on_host.clone()))?;
            let pfl_size = fd.metadata().unwrap().len();

            if config.unit == 0 {
                // According to the Linux/x86 boot protocol, the memory region of
                // 0x000000 - 0x100000 (1 MiB) is for BIOS usage. And the top 128
                // KiB is for BIOS code which is stored in the first PFlash.
                let rom_base = 0xe0000;
                let rom_size = 0x20000;
                fd.seek(SeekFrom::Start(pfl_size - rom_size))?;

                let ram1 = Arc::new(HostMemMapping::new(
                    GuestAddress(rom_base),
                    None,
                    rom_size,
                    None,
                    false,
                    false,
                    false,
                )?);
                let rom_region = Region::init_ram_region(ram1);
                rom_region.write(&mut fd, GuestAddress(rom_base), 0, rom_size)?;
                rom_region.set_priority(10);
                self.sys_mem.root().add_subregion(rom_region, rom_base)?;

                fd.seek(SeekFrom::Start(0))?;
            }

            let sector_len: u32 = 1024 * 4;
            let backend = Some(fd);
            let pflash = PFlash::new(
                pfl_size,
                &backend,
                sector_len,
                4_u32,
                1_u32,
                config.read_only,
            )
            .chain_err(|| ErrorKind::InitPflashErr)?;
            PFlash::realize(
                pflash,
                &mut self.sysbus,
                flash_end - pfl_size,
                pfl_size,
                backend,
            )
            .chain_err(|| ErrorKind::RlzPflashErr)?;
            flash_end -= pfl_size;
        }

        Ok(())
    }

    fn run(&self, paused: bool) -> MachineResult<()> {
        <Self as MachineOps>::vm_start(paused, &self.cpus, &mut self.vm_state.0.lock().unwrap())
    }

    fn get_sys_mem(&mut self) -> &Arc<AddressSpace> {
        &self.sys_mem
    }

    fn get_vm_config(&self) -> &Mutex<VmConfig> {
        &self.vm_config
    }

    fn get_migrate_info(&self) -> Incoming {
        if let Some((mode, path)) = self.get_vm_config().lock().unwrap().incoming.as_ref() {
            return (*mode, path.to_string());
        }

        (MigrateMode::Unknown, String::new())
    }

    fn get_pci_host(&mut self) -> Result<&Arc<Mutex<PciHost>>> {
        Ok(&self.pci_host)
    }

    fn get_sys_bus(&mut self) -> &SysBus {
        &self.sysbus
    }

    fn get_fwcfg_dev(&mut self) -> MachineResult<Arc<Mutex<dyn FwCfgOps>>> {
        // Unwrap is safe. Because after standard machine realize, this will not be None.F
        Ok(self.fwcfg_dev.clone().unwrap())
    }

    fn get_boot_order_list(&self) -> Option<Arc<Mutex<Vec<BootIndexInfo>>>> {
        Some(self.boot_order_list.clone())
    }

    fn get_bus_device(&mut self) -> Option<&BusDeviceMap> {
        Some(&self.bus_device)
    }
}

impl AcpiBuilder for StdMachine {
    fn build_dsdt_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::errors::Result<u64> {
        use super::errors::ResultExt;
        let mut dsdt = AcpiTable::new(*b"DSDT", 2, *b"STRATO", *b"VIRTDSDT", 1);

        // 1. CPU info.
        let cpus_count = self.cpus.len() as u64;
        let mut sb_scope = AmlScope::new("\\_SB");
        for cpu_id in 0..cpus_count {
            let mut dev = AmlDevice::new(format!("C{:03}", cpu_id).as_str());
            dev.append_child(AmlNameDecl::new("_HID", AmlString("ACPI0007".to_string())));
            dev.append_child(AmlNameDecl::new("_UID", AmlInteger(cpu_id)));
            dev.append_child(AmlNameDecl::new("_PXM", AmlInteger(0)));
            sb_scope.append_child(dev);
        }

        // 2. Create pci host bridge node.
        sb_scope.append_child(self.pci_host.lock().unwrap().clone());
        dsdt.append_child(sb_scope.aml_bytes().as_slice());

        // 3. Info of devices attached to system bus.
        dsdt.append_child(self.sysbus.aml_bytes().as_slice());

        // 4. Add _S5 sleep state.
        let mut package = AmlPackage::new(4);
        package.append_child(AmlInteger(5));
        package.append_child(AmlInteger(0));
        package.append_child(AmlInteger(0));
        package.append_child(AmlInteger(0));
        dsdt.append_child(AmlNameDecl::new("_S5", package).aml_bytes().as_slice());

        let dsdt_begin = StdMachine::add_table_to_loader(acpi_data, loader, &dsdt)
            .chain_err(|| "Fail to add DSTD table to loader")?;
        Ok(dsdt_begin as u64)
    }

    fn build_madt_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::errors::Result<u64> {
        use super::errors::ResultExt;
        let mut madt = AcpiTable::new(*b"APIC", 5, *b"STRATO", *b"VIRTAPIC", 1);

        madt.append_child(LAPIC_BASE_ADDR.as_bytes());
        // Flags: PC-AT-compatible dual-8259 setup
        madt.append_child(1_u32.as_bytes());

        let ioapic = AcpiIoApic {
            type_id: 1_u8,
            length: size_of::<AcpiIoApic>() as u8,
            io_apic_id: 0,
            reserved: 0,
            io_apic_addr: IOAPIC_BASE_ADDR,
            gsi_base: 0,
        };
        madt.append_child(ioapic.aml_bytes().as_ref());

        self.cpus.iter().for_each(|cpu| {
            let lapic = AcpiLocalApic {
                type_id: 0,
                length: size_of::<AcpiLocalApic>() as u8,
                processor_uid: cpu.id(),
                apic_id: cpu.id(),
                flags: 1, // Flags: enabled.
            };
            madt.append_child(&lapic.aml_bytes());
        });

        let madt_begin = StdMachine::add_table_to_loader(acpi_data, loader, &madt)
            .chain_err(|| "Fail to add DSTD table to loader")?;
        Ok(madt_begin as u64)
    }

    fn build_srat_cpu(&self, proximity_domain: u32, node: &NumaNode, srat: &mut AcpiTable) {
        for cpu in node.cpus.iter() {
            srat.append_child(
                &AcpiSratProcessorAffinity {
                    length: size_of::<AcpiSratProcessorAffinity>() as u8,
                    proximity_lo: proximity_domain as u8,
                    local_apic_id: *cpu,
                    flags: 1,
                    ..Default::default()
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
        let mem_below_4g = MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].0
            + MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].1;
        let mem_above_4g = MEM_LAYOUT[LayoutEntryType::MemAbove4g as usize].0;

        let mut mem_base = base_addr;
        let mut mem_len = node.size;
        let mut next_base = mem_base + mem_len;
        // It contains the hole from 604Kb to 1Mb
        if mem_base <= HOLE_640K_START && next_base > HOLE_640K_START {
            mem_len -= next_base - HOLE_640K_START;
            if mem_len > 0 {
                srat.append_child(
                    &AcpiSratMemoryAffinity {
                        type_id: 1,
                        length: size_of::<AcpiSratMemoryAffinity>() as u8,
                        proximity_domain,
                        base_addr: mem_base,
                        range_length: mem_len,
                        flags: 1,
                        ..Default::default()
                    }
                    .aml_bytes(),
                );
            }

            if next_base <= HOLE_640K_END {
                next_base = HOLE_640K_END;
                return next_base;
            }
            mem_base = HOLE_640K_END;
            mem_len = next_base - HOLE_640K_END;
        }

        // It contains the hole possibly from mem_below_4g(2G) to mem_below_4g(4G).
        if mem_base <= mem_below_4g && next_base > mem_below_4g {
            mem_len -= next_base - mem_below_4g;
            if mem_len > 0 {
                srat.append_child(
                    &AcpiSratMemoryAffinity {
                        type_id: 1,
                        length: size_of::<AcpiSratMemoryAffinity>() as u8,
                        proximity_domain,
                        base_addr: mem_base,
                        range_length: mem_len,
                        flags: 1,
                        ..Default::default()
                    }
                    .aml_bytes(),
                );
            }
            mem_base = mem_above_4g;
            mem_len = next_base - mem_below_4g;
            next_base = mem_base + mem_len;
        }

        if mem_len > 0 {
            srat.append_child(
                &AcpiSratMemoryAffinity {
                    type_id: 1,
                    length: size_of::<AcpiSratMemoryAffinity>() as u8,
                    proximity_domain,
                    base_addr: mem_base,
                    range_length: mem_len,
                    flags: 1,
                    ..Default::default()
                }
                .aml_bytes(),
            );
        }

        next_base
    }

    fn build_srat_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::errors::Result<u64> {
        use super::errors::ResultExt;
        if self.numa_nodes.is_none() {
            return Ok(0);
        }

        let mut srat = AcpiTable::new(*b"SRAT", 1, *b"STRATO", *b"VIRTSRAT", 1);
        srat.append_child(&[1_u8; 4_usize]);
        srat.append_child(&[0_u8; 8_usize]);

        let mut next_base = 0_u64;
        for (id, node) in self.numa_nodes.as_ref().unwrap().iter() {
            self.build_srat_cpu(*id, node, &mut srat);
            next_base = self.build_srat_mem(next_base, *id, node, &mut srat);
        }

        let srat_begin = StdMachine::add_table_to_loader(acpi_data, loader, &srat)
            .chain_err(|| "Fail to add SRAT table to loader")?;
        Ok(srat_begin as u64)
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
            return false;
        }

        self.power_button.write(1).unwrap();
        true
    }

    fn notify_lifecycle(&self, old: KvmVmState, new: KvmVmState) -> bool {
        <Self as MachineOps>::vm_state_transfer(
            &self.cpus,
            &mut self.vm_state.0.lock().unwrap(),
            old,
            new,
        )
        .is_ok()
    }
}

impl MachineAddressInterface for StdMachine {
    fn pio_in(&self, addr: u64, mut data: &mut [u8]) -> bool {
        if (0x60..=0x64).contains(&addr) {
            // The function pit_calibrate_tsc() in kernel gets stuck if data read from
            // io-port 0x61 is not 0x20.
            // This problem only happens before Linux version 4.18 (fixed by 368a540e0)
            if addr == 0x61 {
                data[0] = 0x20;
                return true;
            }
            if addr == 0x64 {
                // UEFI will read PS2 Keyboard's Status register 0x64 to detect if
                // this device is present.
                data[0] = 0xFF;
            }
        }

        let length = data.len() as u64;
        self.sys_io
            .read(&mut data, GuestAddress(addr), length)
            .is_ok()
    }

    fn pio_out(&self, addr: u64, mut data: &[u8]) -> bool {
        let count = data.len() as u64;
        if addr == SLEEP_CTRL_OFFSET as u64 {
            if let Err(e) = self.cpus[0].pause() {
                error!("Fail to pause bsp, {}", e.display_chain());
            }
        }
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

impl EventLoopManager for StdMachine {
    fn loop_should_exit(&self) -> bool {
        let vmstate = self.vm_state.deref().0.lock().unwrap();
        *vmstate == KvmVmState::Shutdown
    }

    fn loop_cleanup(&self) -> util::errors::Result<()> {
        use util::errors::ResultExt;

        set_termi_canon_mode().chain_err(|| "Failed to set terminal to canonical mode")?;
        Ok(())
    }
}
