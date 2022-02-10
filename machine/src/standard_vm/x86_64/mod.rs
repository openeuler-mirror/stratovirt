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

mod ich9_lpc;
mod mch;
mod syscall;

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom};
use std::mem::size_of;
use std::ops::Deref;
use std::sync::{Arc, Condvar, Mutex};

use acpi::{
    AcpiIoApic, AcpiLocalApic, AcpiTable, AmlBuilder, AmlDevice, AmlInteger, AmlNameDecl, AmlScope,
    AmlScopeBuilder, AmlString, TableLoader, ACPI_TABLE_FILE, IOAPIC_BASE_ADDR, LAPIC_BASE_ADDR,
    TABLE_CHECKSUM_OFFSET,
};
use address_space::{AddressSpace, GuestAddress, HostMemMapping, Region};
use boot_loader::{load_linux, BootLoaderConfig};
use cpu::{CPUBootConfig, CpuTopology, CPU};
use devices::legacy::{FwCfgEntryType, FwCfgIO, FwCfgOps, PFlash, Serial, RTC, SERIAL_ADDR};
use hypervisor::kvm::KVM_FDS;
use kvm_bindings::{kvm_pit_config, KVM_PIT_SPEAKER_DUMMY};
use machine_manager::config::{BootSource, PFlashConfig, SerialConfig, VmConfig};
use machine_manager::machine::{
    KvmVmState, MachineAddressInterface, MachineExternalInterface, MachineInterface,
    MachineLifecycle, MigrateInterface,
};
use machine_manager::qmp::{qmp_schema, QmpChannel, Response};
use migration::{MigrationManager, MigrationStatus};
use pci::{PciDevOps, PciHost};
use sysbus::SysBus;
use util::loop_context::EventLoopManager;
use util::seccomp::BpfRule;
use util::set_termi_canon_mode;
use vmm_sys_util::eventfd::EventFd;

use super::errors::{ErrorKind, Result};
use super::{AcpiBuilder, StdMachineOps};
use crate::errors::{ErrorKind as MachineErrorKind, Result as MachineResult};
use crate::MachineOps;
use mch::Mch;
use syscall::syscall_whitelist;
use util::byte_code::ByteCode;

const VENDOR_ID_INTEL: u16 = 0x8086;

/// The type of memory layout entry on x86_64
#[repr(usize)]
#[allow(dead_code)]
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
    vm_config: Mutex<VmConfig>,
}

impl StdMachine {
    pub fn new(vm_config: &VmConfig) -> MachineResult<Self> {
        use crate::errors::ResultExt;

        let cpu_topo = CpuTopology::new(vm_config.machine_config.nr_cpus);
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
                .chain_err(|| MachineErrorKind::InitPwrBtnErr)?,
            vm_config: Mutex::new(vm_config.clone()),
        })
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

        let mch = Mch::new(root_bus.clone(), mmconfig_region, mmconfig_region_ops);
        PciDevOps::realize(mch)?;

        let ich = ich9_lpc::LPCBridge::new(root_bus, self.sys_io.clone());
        PciDevOps::realize(ich)?;
        Ok(())
    }

    fn add_fwcfg_device(&mut self) -> super::errors::Result<Arc<Mutex<dyn FwCfgOps>>> {
        use super::errors::ResultExt;

        let mut fwcfg = FwCfgIO::new(self.sys_mem.clone());
        let ncpus = self.cpus.len();
        fwcfg.add_data_entry(FwCfgEntryType::NbCpus, ncpus.as_bytes().to_vec())?;
        fwcfg.add_data_entry(FwCfgEntryType::MaxCpus, ncpus.as_bytes().to_vec())?;
        fwcfg.add_data_entry(FwCfgEntryType::Irq0Override, 1_u32.as_bytes().to_vec())?;

        let fwcfg_dev = FwCfgIO::realize(fwcfg, &mut self.sysbus)
            .chain_err(|| "Failed to realize fwcfg device")?;

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

    fn get_vm_config(&self) -> &Mutex<VmConfig> {
        &self.vm_config
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

    fn realize(
        vm: &Arc<Mutex<Self>>,
        vm_config: &mut VmConfig,
        is_migrate: bool,
    ) -> MachineResult<()> {
        use crate::errors::ResultExt;

        let mut locked_vm = vm.lock().unwrap();
        locked_vm.init_memory(
            &vm_config.machine_config.mem_config,
            &locked_vm.sys_io,
            &locked_vm.sys_mem,
            is_migrate,
            vm_config.machine_config.nr_cpus,
        )?;

        locked_vm.init_interrupt_controller(u64::from(vm_config.machine_config.nr_cpus))?;
        let kvm_fds = KVM_FDS.load();
        let vm_fd = kvm_fds.vm_fd.as_ref().unwrap();
        let nr_cpus = vm_config.machine_config.nr_cpus;
        let mut vcpu_fds = vec![];
        for cpu_id in 0..nr_cpus {
            vcpu_fds.push(Arc::new(vm_fd.create_vcpu(cpu_id)?));
        }

        locked_vm
            .init_pci_host()
            .chain_err(|| ErrorKind::InitPCIeHostErr)?;
        locked_vm.add_devices(vm_config)?;

        let (boot_config, fwcfg) = if !is_migrate {
            let fwcfg = locked_vm.add_fwcfg_device()?;
            (Some(locked_vm.load_boot_source(Some(&fwcfg))?), Some(fwcfg))
        } else {
            (None, None)
        };
        locked_vm.cpus.extend(<Self as MachineOps>::init_vcpu(
            vm.clone(),
            vm_config.machine_config.nr_cpus,
            &vcpu_fds,
            &boot_config,
        )?);

        if let Some(fwcfg) = fwcfg {
            locked_vm
                .build_acpi_tables(&fwcfg)
                .chain_err(|| "Failed to create ACPI tables")?;
        }
        StdMachine::arch_init()?;
        locked_vm.register_power_event(&locked_vm.power_button)?;

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

    fn get_pci_host(&mut self) -> Result<&Arc<Mutex<PciHost>>> {
        Ok(&self.pci_host)
    }
}

impl AcpiBuilder for StdMachine {
    fn build_dsdt_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::errors::Result<u64> {
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
        dsdt.append_child(sb_scope.aml_bytes().as_slice());

        // 3. Info of devices attached to system bus.
        dsdt.append_child(self.sysbus.aml_bytes().as_slice());

        let mut locked_acpi_data = acpi_data.lock().unwrap();
        let dsdt_begin = locked_acpi_data.len() as u32;
        locked_acpi_data.extend(dsdt.aml_bytes());
        let dsdt_end = locked_acpi_data.len() as u32;
        // Drop the lock of acpi_data to avoid dead-lock when adding entry to
        // TableLoader, because TableLoader also needs to acquire this lock.
        drop(locked_acpi_data);

        loader.add_cksum_entry(
            ACPI_TABLE_FILE,
            dsdt_begin + TABLE_CHECKSUM_OFFSET,
            dsdt_begin,
            dsdt_end - dsdt_begin,
        )?;

        Ok(dsdt_begin as u64)
    }

    fn build_madt_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> super::errors::Result<u64> {
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

        let mut locked_acpi_data = acpi_data.lock().unwrap();
        let madt_begin = locked_acpi_data.len() as u32;
        locked_acpi_data.extend(madt.aml_bytes());
        let madt_end = locked_acpi_data.len() as u32;
        // Drop the lock of acpi_data to avoid dead-lock when adding entry to
        // TableLoader, because TableLoader also needs to acquire this lock.
        drop(locked_acpi_data);

        loader.add_cksum_entry(
            ACPI_TABLE_FILE,
            madt_begin + TABLE_CHECKSUM_OFFSET,
            madt_begin,
            madt_end - madt_begin,
        )?;

        Ok(madt_begin as u64)
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
        use crate::error_chain::ChainedError;
        use util::unix::{parse_uri, UnixPath};

        match parse_uri(&uri) {
            Ok((UnixPath::File, path)) => {
                if let Err(e) = MigrationManager::save_snapshot(&path) {
                    error!(
                        "Failed to migrate to path \'{:?}\': {}",
                        path,
                        e.display_chain()
                    );
                    let _ = MigrationManager::set_status(MigrationStatus::Failed)
                        .map_err(|e| error!("{}", e));
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                        None,
                    );
                }
            }
            _ => {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(format!("Invalid uri: {}", uri)),
                    None,
                );
            }
        }

        Response::create_empty_response()
    }

    fn query_migrate(&self) -> Response {
        let status_str = MigrationManager::migration_get_status().to_string();
        let migration_info = qmp_schema::MigrationInfo {
            status: Some(status_str),
        };

        Response::create_response(serde_json::to_value(migration_info).unwrap(), None)
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
