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

use std::io::{Seek, SeekFrom};
use std::mem::size_of;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use log::{error, info};
use vmm_sys_util::eventfd::EventFd;

use super::error::StandardVmError;
use super::{AcpiBuilder, StdMachineOps};
use crate::error::MachineError;
use crate::{vm_state, MachineBase, MachineOps};
use acpi::{
    AcpiIoApic, AcpiLocalApic, AcpiSratMemoryAffinity, AcpiSratProcessorAffinity, AcpiTable,
    AmlBuilder, AmlDevice, AmlInteger, AmlNameDecl, AmlPackage, AmlScope, AmlScopeBuilder,
    AmlString, TableLoader, IOAPIC_BASE_ADDR, LAPIC_BASE_ADDR,
};
use address_space::{AddressSpace, GuestAddress, HostMemMapping, Region};
use boot_loader::{load_linux, BootLoaderConfig};
use cpu::{CPUBootConfig, CPUInterface, CPUTopology};
use devices::acpi::ged::{Ged, GedEvent};
use devices::legacy::{
    error::LegacyError as DevErrorKind, FwCfgEntryType, FwCfgIO, FwCfgOps, PFlash, Serial, RTC,
    SERIAL_ADDR,
};
use devices::pci::{PciDevOps, PciHost};
use hypervisor::kvm::KVM_FDS;
#[cfg(feature = "gtk")]
use machine_manager::config::UiContext;
use machine_manager::config::{
    parse_incoming_uri, BootIndexInfo, MigrateMode, NumaNode, PFlashConfig, SerialConfig, VmConfig,
};
use machine_manager::event;
use machine_manager::event_loop::EventLoop;
use machine_manager::machine::{
    KvmVmState, MachineAddressInterface, MachineExternalInterface, MachineInterface,
    MachineLifecycle, MachineTestInterface, MigrateInterface,
};
use machine_manager::qmp::{qmp_channel::QmpChannel, qmp_response::Response, qmp_schema};
use mch::Mch;
use migration::{MigrationManager, MigrationStatus};
use syscall::syscall_whitelist;
#[cfg(feature = "gtk")]
use ui::gtk::gtk_display_init;
#[cfg(feature = "vnc")]
use ui::vnc::vnc_init;
use util::{
    byte_code::ByteCode, loop_context::EventLoopManager, seccomp::BpfRule, set_termi_canon_mode,
};

const VENDOR_ID_INTEL: u16 = 0x8086;
const HOLE_640K_START: u64 = 0x000A_0000;
const HOLE_640K_END: u64 = 0x0010_0000;

/// The type of memory layout entry on x86_64
#[repr(usize)]
pub enum LayoutEntryType {
    MemBelow4g = 0_usize,
    PcieEcam,
    PcieMmio,
    GedMmio,
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
    (0xF000_0000, 0x04),             // GedMmio
    (0xF010_0000, 0x200),            // Mmio
    (0xFEC0_0000, 0x10_0000),        // IoApic
    (0xFEE0_0000, 0x10_0000),        // LocalApic
    (0xFEF0_C000, 0x4000),           // Identity map address and TSS
    (0x1_0000_0000, 0x80_0000_0000), // MemAbove4g
];

/// The type of Irq entry on aarch64
enum IrqEntryType {
    #[allow(unused)]
    Uart,
    Sysbus,
    Pcie,
}

/// IRQ MAP of x86_64
const IRQ_MAP: &[(i32, i32)] = &[
    (4, 4),   // Uart
    (5, 15),  // Sysbus
    (16, 19), // Pcie
];

/// Standard machine structure.
pub struct StdMachine {
    // Machine base members.
    base: MachineBase,
    /// PCI/PCIe host bridge.
    pci_host: Arc<Mutex<PciHost>>,
    /// Reset request, handle VM `Reset` event.
    reset_req: Arc<EventFd>,
    /// Shutdown_req, handle VM 'ShutDown' event.
    shutdown_req: Arc<EventFd>,
    /// VM power button, handle VM `Powerdown` event.
    power_button: Arc<EventFd>,
    /// CPU Resize request, handle vm cpu hot(un)plug event.
    cpu_resize_req: Arc<EventFd>,
    /// List contains the boot order of boot devices.
    boot_order_list: Arc<Mutex<Vec<BootIndexInfo>>>,
}

impl StdMachine {
    pub fn new(vm_config: &VmConfig) -> Result<Self> {
        let free_irqs = (
            IRQ_MAP[IrqEntryType::Sysbus as usize].0,
            IRQ_MAP[IrqEntryType::Sysbus as usize].1,
        );
        let mmio_region = (
            MEM_LAYOUT[LayoutEntryType::Mmio as usize].0,
            MEM_LAYOUT[LayoutEntryType::Mmio as usize + 1].0,
        );
        let base = MachineBase::new(vm_config, free_irqs, mmio_region)?;
        let sys_mem = base.sys_mem.clone();
        let sys_io = base.sys_io.clone();

        Ok(StdMachine {
            base,
            pci_host: Arc::new(Mutex::new(PciHost::new(
                &sys_io,
                &sys_mem,
                MEM_LAYOUT[LayoutEntryType::PcieEcam as usize],
                MEM_LAYOUT[LayoutEntryType::PcieMmio as usize],
                IRQ_MAP[IrqEntryType::Pcie as usize].0,
            ))),
            reset_req: Arc::new(
                EventFd::new(libc::EFD_NONBLOCK)
                    .with_context(|| MachineError::InitEventFdErr("reset request".to_string()))?,
            ),
            shutdown_req: Arc::new(
                EventFd::new(libc::EFD_NONBLOCK).with_context(|| {
                    MachineError::InitEventFdErr("shutdown request".to_string())
                })?,
            ),
            power_button: Arc::new(
                EventFd::new(libc::EFD_NONBLOCK)
                    .with_context(|| MachineError::InitEventFdErr("power button".to_string()))?,
            ),
            cpu_resize_req: Arc::new(
                EventFd::new(libc::EFD_NONBLOCK)
                    .with_context(|| MachineError::InitEventFdErr("cpu resize".to_string()))?,
            ),
            boot_order_list: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub fn handle_reset_request(vm: &Arc<Mutex<Self>>) -> Result<()> {
        let mut locked_vm = vm.lock().unwrap();

        for (cpu_index, cpu) in locked_vm.base.cpus.iter().enumerate() {
            cpu.pause()
                .with_context(|| format!("Failed to pause vcpu{}", cpu_index))?;

            cpu.set_to_boot_state();
        }

        locked_vm
            .reset_all_devices()
            .with_context(|| "Fail to reset all devices")?;
        locked_vm
            .reset_fwcfg_boot_order()
            .with_context(|| "Fail to update boot order information to FwCfg device")?;

        if QmpChannel::is_connected() {
            let reset_msg = qmp_schema::Reset { guest: true };
            event!(Reset; reset_msg);
        }

        for (cpu_index, cpu) in locked_vm.base.cpus.iter().enumerate() {
            cpu.reset()
                .with_context(|| format!("Failed to reset vcpu{}", cpu_index))?;
            cpu.resume()
                .with_context(|| format!("Failed to resume vcpu{}", cpu_index))?;
        }

        Ok(())
    }

    fn init_ich9_lpc(&self, vm: Arc<Mutex<StdMachine>>) -> Result<()> {
        let clone_vm = vm.clone();
        let root_bus = Arc::downgrade(&self.pci_host.lock().unwrap().root_bus);
        let ich = ich9_lpc::LPCBridge::new(
            root_bus,
            self.base.sys_io.clone(),
            self.reset_req.clone(),
            self.shutdown_req.clone(),
        )?;
        self.register_reset_event(self.reset_req.clone(), vm)
            .with_context(|| "Fail to register reset event in LPC")?;
        self.register_shutdown_event(ich.shutdown_req.clone(), clone_vm)
            .with_context(|| "Fail to register shutdown event in LPC")?;
        ich.realize()?;
        Ok(())
    }

    pub fn get_vcpu_reg_val(&self, _addr: u64, _vcpu: usize) -> Option<u128> {
        None
    }
}

impl StdMachineOps for StdMachine {
    fn init_pci_host(&self) -> Result<()> {
        let root_bus = Arc::downgrade(&self.pci_host.lock().unwrap().root_bus);
        let mmconfig_region_ops = PciHost::build_mmconfig_ops(self.pci_host.clone());
        let mmconfig_region = Region::init_io_region(
            MEM_LAYOUT[LayoutEntryType::PcieEcam as usize].1,
            mmconfig_region_ops.clone(),
            "PcieEcamSpace",
        );
        self.base
            .sys_mem
            .root()
            .add_subregion(
                mmconfig_region.clone(),
                MEM_LAYOUT[LayoutEntryType::PcieEcam as usize].0,
            )
            .with_context(|| "Failed to register ECAM in memory space.")?;

        let pio_addr_ops = PciHost::build_pio_addr_ops(self.pci_host.clone());
        let pio_addr_region = Region::init_io_region(4, pio_addr_ops, "PioAddr");
        self.base
            .sys_io
            .root()
            .add_subregion(pio_addr_region, 0xcf8)
            .with_context(|| "Failed to register CONFIG_ADDR port in I/O space.")?;
        let pio_data_ops = PciHost::build_pio_data_ops(self.pci_host.clone());
        let pio_data_region = Region::init_io_region(4, pio_data_ops, "PioData");
        self.base
            .sys_io
            .root()
            .add_subregion(pio_data_region, 0xcfc)
            .with_context(|| "Failed to register CONFIG_DATA port in I/O space.")?;

        let mch = Mch::new(root_bus, mmconfig_region, mmconfig_region_ops);
        mch.realize()?;
        Ok(())
    }

    fn add_fwcfg_device(
        &mut self,
        nr_cpus: u8,
        max_cpus: u8,
    ) -> super::Result<Option<Arc<Mutex<dyn FwCfgOps>>>> {
        let mut fwcfg = FwCfgIO::new(self.base.sys_mem.clone());
        fwcfg.add_data_entry(FwCfgEntryType::NbCpus, nr_cpus.as_bytes().to_vec())?;
        fwcfg.add_data_entry(FwCfgEntryType::MaxCpus, max_cpus.as_bytes().to_vec())?;
        fwcfg.add_data_entry(FwCfgEntryType::Irq0Override, 1_u32.as_bytes().to_vec())?;

        let boot_order = Vec::<u8>::new();
        fwcfg
            .add_file_entry("bootorder", boot_order)
            .with_context(|| DevErrorKind::AddEntryErr("bootorder".to_string()))?;

        let fwcfg_dev = FwCfgIO::realize(fwcfg, &mut self.base.sysbus)
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
        let ram = self.get_vm_ram();
        let below4g_size = MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].1;

        let below4g_ram = Region::init_alias_region(
            ram.clone(),
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
                ram.clone(),
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
        KVM_FDS
            .load()
            .vm_fd
            .as_ref()
            .unwrap()
            .create_irq_chip()
            .with_context(|| MachineError::CrtIrqchipErr)?;
        KVM_FDS
            .load()
            .irq_route_table
            .lock()
            .unwrap()
            .init_irq_route_table();
        KVM_FDS.load().commit_irq_routing()?;
        Ok(())
    }

    fn load_boot_source(&self, fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>) -> Result<CPUBootConfig> {
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
            ident_tss_range: Some(MEM_LAYOUT[LayoutEntryType::IdentTss as usize]),
            prot64_mode: false,
        };
        let layout = load_linux(&bootloader_config, &self.base.sys_mem, fwcfg)
            .with_context(|| MachineError::LoadKernErr)?;

        Ok(CPUBootConfig {
            prot64_mode: false,
            boot_ip: layout.boot_ip,
            boot_sp: layout.boot_sp,
            boot_selector: layout.boot_selector,
            ..Default::default()
        })
    }

    fn add_rtc_device(&mut self, mem_size: u64) -> Result<()> {
        let mut rtc = RTC::new().with_context(|| "Failed to create RTC device")?;
        rtc.set_memory(
            mem_size,
            MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].0
                + MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].1,
        );
        RTC::realize(rtc, &mut self.base.sysbus).with_context(|| "Failed to realize RTC device")?;

        Ok(())
    }

    fn add_ged_device(&mut self) -> Result<()> {
        let ged = Ged::default();
        let region_base: u64 = MEM_LAYOUT[LayoutEntryType::GedMmio as usize].0;
        let region_size: u64 = MEM_LAYOUT[LayoutEntryType::GedMmio as usize].1;

        let ged_event = GedEvent::new(self.power_button.clone(), self.cpu_resize_req.clone());
        ged.realize(
            &mut self.base.sysbus,
            ged_event,
            false,
            region_base,
            region_size,
        )
        .with_context(|| "Failed to realize Ged")?;
        Ok(())
    }

    fn add_serial_device(&mut self, config: &SerialConfig) -> Result<()> {
        let region_base: u64 = SERIAL_ADDR;
        let region_size: u64 = 8;
        let serial = Serial::new(config.clone());
        serial
            .realize(&mut self.base.sysbus, region_base, region_size)
            .with_context(|| "Failed to realize serial device.")?;
        Ok(())
    }

    fn syscall_whitelist(&self) -> Vec<BpfRule> {
        syscall_whitelist()
    }

    fn realize(vm: &Arc<Mutex<Self>>, vm_config: &mut VmConfig) -> Result<()> {
        let nr_cpus = vm_config.machine_config.nr_cpus;
        let max_cpus = vm_config.machine_config.max_cpus;
        let clone_vm = vm.clone();
        let mut locked_vm = vm.lock().unwrap();
        locked_vm.init_global_config(vm_config)?;
        locked_vm.base.numa_nodes = locked_vm.add_numa_nodes(vm_config)?;
        locked_vm.init_memory(
            &vm_config.machine_config.mem_config,
            &locked_vm.base.sys_io,
            &locked_vm.base.sys_mem,
            nr_cpus,
        )?;

        locked_vm.init_interrupt_controller(u64::from(nr_cpus))?;
        locked_vm.arch_init(MEM_LAYOUT[LayoutEntryType::IdentTss as usize].0)?;

        locked_vm
            .init_pci_host()
            .with_context(|| StandardVmError::InitPCIeHostErr)?;
        locked_vm
            .init_ich9_lpc(clone_vm)
            .with_context(|| "Fail to init LPC bridge")?;
        locked_vm.add_devices(vm_config)?;

        let fwcfg = locked_vm.add_fwcfg_device(nr_cpus, max_cpus)?;

        let migrate = locked_vm.get_migrate_info();
        let boot_config = if migrate.0 == MigrateMode::Unknown {
            Some(locked_vm.load_boot_source(fwcfg.as_ref())?)
        } else {
            None
        };
        let topology = CPUTopology::new().set_topology((
            vm_config.machine_config.nr_threads,
            vm_config.machine_config.nr_cores,
            vm_config.machine_config.nr_dies,
        ));
        locked_vm.base.cpus.extend(<Self as MachineOps>::init_vcpu(
            vm.clone(),
            nr_cpus,
            max_cpus,
            &topology,
            &boot_config,
        )?);

        if migrate.0 == MigrateMode::Unknown {
            if let Some(fw_cfg) = fwcfg {
                locked_vm
                    .build_acpi_tables(&fw_cfg)
                    .with_context(|| "Failed to create ACPI tables")?;
                let mut mem_array = Vec::new();
                let mem_size = vm_config.machine_config.mem_config.mem_size;
                let below_size =
                    std::cmp::min(MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].1, mem_size);
                mem_array.push((
                    MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].0,
                    below_size,
                ));
                if mem_size > below_size {
                    mem_array.push((
                        MEM_LAYOUT[LayoutEntryType::MemAbove4g as usize].0,
                        mem_size - below_size,
                    ));
                }

                locked_vm
                    .build_smbios(&fw_cfg, mem_array)
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
            locked_vm.shutdown_req.clone(),
            locked_vm.shutdown_req.clone(),
        );

        MigrationManager::register_vm_config(locked_vm.get_vm_config());
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

    fn add_pflash_device(&mut self, configs: &[PFlashConfig]) -> Result<()> {
        let mut configs_vec = configs.to_vec();
        configs_vec.sort_by_key(|c| c.unit);
        // The two PFlash devices locates below 4GB, this variable represents the end address
        // of current PFlash device.
        let mut flash_end: u64 = MEM_LAYOUT[LayoutEntryType::MemAbove4g as usize].0;
        for config in configs_vec {
            let mut fd = self.fetch_drive_file(&config.path_on_host)?;
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
                let rom_region = Region::init_ram_region(ram1, "PflashRam");
                rom_region.write(&mut fd, GuestAddress(rom_base), 0, rom_size)?;
                rom_region.set_priority(10);
                self.base
                    .sys_mem
                    .root()
                    .add_subregion(rom_region, rom_base)?;

                fd.rewind()?
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
            .with_context(|| StandardVmError::InitPflashErr)?;
            PFlash::realize(
                pflash,
                &mut self.base.sysbus,
                flash_end - pfl_size,
                pfl_size,
                backend,
            )
            .with_context(|| StandardVmError::RlzPflashErr)?;
            flash_end -= pfl_size;
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
                    power_button: None,
                    shutdown_req: Some(self.shutdown_req.clone()),
                    pause_req: None,
                    resume_req: None,
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

    fn get_pci_host(&mut self) -> Result<&Arc<Mutex<PciHost>>> {
        Ok(&self.pci_host)
    }

    fn get_boot_order_list(&self) -> Option<Arc<Mutex<Vec<BootIndexInfo>>>> {
        Some(self.boot_order_list.clone())
    }
}

impl AcpiBuilder for StdMachine {
    fn build_dsdt_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::Result<u64> {
        let mut dsdt = AcpiTable::new(*b"DSDT", 2, *b"STRATO", *b"VIRTDSDT", 1);

        // 1. CPU info.
        let cpus_count = self.base.cpus.len() as u64;
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
        dsdt.append_child(self.base.sysbus.aml_bytes().as_slice());

        // 4. Add _S5 sleep state.
        let mut package = AmlPackage::new(4);
        package.append_child(AmlInteger(5));
        package.append_child(AmlInteger(0));
        package.append_child(AmlInteger(0));
        package.append_child(AmlInteger(0));
        dsdt.append_child(AmlNameDecl::new("_S5", package).aml_bytes().as_slice());

        let dsdt_begin = StdMachine::add_table_to_loader(acpi_data, loader, &dsdt)
            .with_context(|| "Fail to add DSTD table to loader")?;
        Ok(dsdt_begin)
    }

    fn build_madt_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::Result<u64> {
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

        self.base.cpus.iter().for_each(|cpu| {
            let lapic = AcpiLocalApic {
                type_id: 0,
                length: size_of::<AcpiLocalApic>() as u8,
                processor_uid: cpu.id(),
                apic_id: cpu.id(),
                flags: 1, // Flags: enabled.
            };
            madt.append_child(&lapic.aml_bytes());
        });

        // Add non boot cpu lapic.
        for cpuid in self.base.cpu_topo.nrcpus as u8..self.base.cpu_topo.max_cpus {
            let lapic = AcpiLocalApic {
                type_id: 0,
                length: size_of::<AcpiLocalApic>() as u8,
                processor_uid: cpuid,
                apic_id: cpuid,
                flags: 2, // Flags: hotplug enabled.
            };
            madt.append_child(&lapic.aml_bytes());
        }

        let madt_begin = StdMachine::add_table_to_loader(acpi_data, loader, &madt)
            .with_context(|| "Fail to add MADT table to loader")?;
        Ok(madt_begin)
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
    ) -> super::Result<u64> {
        let mut srat = AcpiTable::new(*b"SRAT", 1, *b"STRATO", *b"VIRTSRAT", 1);
        srat.append_child(&[1_u8; 4_usize]);
        srat.append_child(&[0_u8; 8_usize]);

        let mut next_base = 0_u64;
        for (id, node) in self.base.numa_nodes.as_ref().unwrap().iter() {
            self.build_srat_cpu(*id, node, &mut srat);
            next_base = self.build_srat_mem(next_base, *id, node, &mut srat);
        }

        let srat_begin = StdMachine::add_table_to_loader(acpi_data, loader, &srat)
            .with_context(|| "Fail to add SRAT table to loader")?;
        Ok(srat_begin)
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
            let state = self.base.vm_state.deref().0.lock().unwrap();
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
        if self.reset_req.write(1).is_err() {
            error!("X86 standard vm write reset request failed");
            return false;
        }
        true
    }

    fn notify_lifecycle(&self, old: KvmVmState, new: KvmVmState) -> bool {
        if let Err(e) = self.vm_state_transfer(
            &self.base.cpus,
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

impl MachineAddressInterface for StdMachine {
    fn pio_in(&self, addr: u64, data: &mut [u8]) -> bool {
        self.machine_base().pio_in(addr, data)
    }

    fn pio_out(&self, addr: u64, data: &[u8]) -> bool {
        self.machine_base().pio_out(addr, data)
    }

    fn mmio_read(&self, addr: u64, data: &mut [u8]) -> bool {
        self.machine_base().mmio_read(addr, data)
    }

    fn mmio_write(&self, addr: u64, data: &[u8]) -> bool {
        self.machine_base().mmio_write(addr, data)
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
        *vmstate == KvmVmState::Shutdown
    }

    fn loop_cleanup(&self) -> util::Result<()> {
        set_termi_canon_mode().with_context(|| "Failed to set terminal to canonical mode")?;
        Ok(())
    }
}
