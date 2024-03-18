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

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
pub mod error;
pub mod standard_common;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

mod micro_common;

pub use crate::error::MachineError;
pub use micro_common::LightMachine;
pub use standard_common::StdMachine;

use std::collections::{BTreeMap, HashMap};
use std::fs::{remove_file, File};
use std::net::TcpListener;
use std::ops::Deref;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{Arc, Barrier, Condvar, Mutex, RwLock, Weak};
#[cfg(feature = "windows_emu_pid")]
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use log::warn;
#[cfg(feature = "windows_emu_pid")]
use vmm_sys_util::eventfd::EventFd;

#[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
use address_space::FileBackend;
use address_space::{create_backend_mem, create_default_mem, AddressSpace, GuestAddress, Region};
#[cfg(target_arch = "aarch64")]
use cpu::CPUFeatures;
use cpu::{ArchCPU, CPUBootConfig, CPUHypervisorOps, CPUInterface, CPUTopology, CpuTopology, CPU};
use devices::legacy::FwCfgOps;
#[cfg(feature = "pvpanic")]
use devices::misc::pvpanic::PvPanicPci;
#[cfg(feature = "scream")]
use devices::misc::scream::{Scream, ScreamConfig};
#[cfg(feature = "demo_device")]
use devices::pci::demo_device::DemoDev;
use devices::pci::{PciBus, PciDevOps, PciHost, RootPort};
use devices::smbios::smbios_table::{build_smbios_ep30, SmbiosTable};
use devices::smbios::{SMBIOS_ANCHOR_FILE, SMBIOS_TABLE_FILE};
use devices::sysbus::{SysBus, SysBusDevOps, SysBusDevType};
#[cfg(feature = "usb_camera")]
use devices::usb::camera::{UsbCamera, UsbCameraConfig};
use devices::usb::keyboard::{UsbKeyboard, UsbKeyboardConfig};
use devices::usb::tablet::{UsbTablet, UsbTabletConfig};
#[cfg(feature = "usb_host")]
use devices::usb::usbhost::{UsbHost, UsbHostConfig};
use devices::usb::xhci::xhci_pci::{XhciConfig, XhciPciDevice};
use devices::usb::{storage::UsbStorage, UsbDevice};
#[cfg(target_arch = "aarch64")]
use devices::InterruptController;
use devices::ScsiDisk::{ScsiDevice, SCSI_TYPE_DISK, SCSI_TYPE_ROM};
use hypervisor::{kvm::KvmHypervisor, HypervisorOps};
#[cfg(feature = "usb_camera")]
use machine_manager::config::get_cameradev_by_id;
#[cfg(feature = "demo_device")]
use machine_manager::config::parse_demo_dev;
#[cfg(feature = "virtio_gpu")]
use machine_manager::config::parse_gpu;
#[cfg(feature = "pvpanic")]
use machine_manager::config::parse_pvpanic;
use machine_manager::config::parse_usb_storage;
use machine_manager::config::{
    complete_numa_node, get_multi_function, get_pci_bdf, parse_blk, parse_device_id,
    parse_device_type, parse_fs, parse_net, parse_numa_distance, parse_numa_mem, parse_rng_dev,
    parse_root_port, parse_scsi_controller, parse_scsi_device, parse_vfio, parse_vhost_user_blk,
    parse_virtio_serial, parse_virtserialport, parse_vsock, str_slip_to_clap, BootIndexInfo,
    BootSource, DriveFile, Incoming, MachineMemConfig, MigrateMode, NumaConfig, NumaDistance,
    NumaNode, NumaNodes, PFlashConfig, PciBdf, SerialConfig, VfioConfig, VmConfig, FAST_UNPLUG_ON,
    MAX_VIRTIO_QUEUE,
};
use machine_manager::event_loop::EventLoop;
use machine_manager::machine::{MachineInterface, VmState};
use migration::{MigrateOps, MigrationManager};
#[cfg(feature = "windows_emu_pid")]
use ui::console::{get_run_stage, VmRunningStage};
use util::file::{clear_file, lock_file, unlock_file};
use util::{
    arg_parser,
    seccomp::{BpfRule, SeccompOpt, SyscallFilter},
};
use vfio::{VfioDevice, VfioPciDevice, KVM_DEVICE_FD};
#[cfg(feature = "virtio_gpu")]
use virtio::Gpu;
#[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
use virtio::VirtioDeviceQuirk;
use virtio::{
    balloon_allow_list, find_port_by_nr, get_max_nr, vhost, Balloon, BalloonConfig, Block,
    BlockState, Rng, RngState,
    ScsiCntlr::{scsi_cntlr_create_scsi_bus, ScsiCntlr},
    Serial, SerialPort, VhostKern, VhostUser, VirtioDevice, VirtioMmioDevice, VirtioMmioState,
    VirtioNetState, VirtioPciDevice, VirtioSerialState, VIRTIO_TYPE_CONSOLE,
};

/// Machine structure include base members.
pub struct MachineBase {
    /// `vCPU` topology, support sockets, cores, threads.
    cpu_topo: CpuTopology,
    /// `vCPU` devices.
    cpus: Vec<Arc<CPU>>,
    /// Interrupt controller device.
    #[cfg(target_arch = "aarch64")]
    irq_chip: Option<Arc<InterruptController>>,
    /// Memory address space.
    sys_mem: Arc<AddressSpace>,
    // IO address space.
    #[cfg(target_arch = "x86_64")]
    sys_io: Arc<AddressSpace>,
    /// System bus.
    sysbus: SysBus,
    /// VM running state.
    vm_state: Arc<(Mutex<VmState>, Condvar)>,
    /// Vm boot_source config.
    boot_source: Arc<Mutex<BootSource>>,
    /// All configuration information of virtual machine.
    vm_config: Arc<Mutex<VmConfig>>,
    /// List of guest NUMA nodes information.
    numa_nodes: Option<NumaNodes>,
    /// Drive backend files.
    drive_files: Arc<Mutex<HashMap<String, DriveFile>>>,
    /// FwCfg device.
    fwcfg_dev: Option<Arc<Mutex<dyn FwCfgOps>>>,
    /// machine all backend memory region tree
    machine_ram: Arc<Region>,
    /// machine hypervisor.
    hypervisor: Arc<Mutex<dyn HypervisorOps>>,
    /// migrate hypervisor.
    migration_hypervisor: Arc<Mutex<dyn MigrateOps>>,
}

impl MachineBase {
    pub fn new(
        vm_config: &VmConfig,
        free_irqs: (i32, i32),
        mmio_region: (u64, u64),
    ) -> Result<Self> {
        let cpu_topo = CpuTopology::new(
            vm_config.machine_config.nr_cpus,
            vm_config.machine_config.nr_sockets,
            vm_config.machine_config.nr_dies,
            vm_config.machine_config.nr_clusters,
            vm_config.machine_config.nr_cores,
            vm_config.machine_config.nr_threads,
            vm_config.machine_config.max_cpus,
        );
        let machine_ram = Arc::new(Region::init_container_region(
            u64::max_value(),
            "MachineRam",
        ));
        let sys_mem = AddressSpace::new(
            Region::init_container_region(u64::max_value(), "SysMem"),
            "sys_mem",
            Some(machine_ram.clone()),
        )
        .with_context(|| MachineError::CrtIoSpaceErr)?;

        #[cfg(target_arch = "x86_64")]
        let sys_io = AddressSpace::new(
            Region::init_container_region(1 << 16, "SysIo"),
            "SysIo",
            None,
        )
        .with_context(|| MachineError::CrtIoSpaceErr)?;
        let sysbus = SysBus::new(
            #[cfg(target_arch = "x86_64")]
            &sys_io,
            &sys_mem,
            free_irqs,
            mmio_region,
        );

        let hypervisor = Arc::new(Mutex::new(KvmHypervisor::new()?));

        Ok(MachineBase {
            cpu_topo,
            cpus: Vec::new(),
            #[cfg(target_arch = "aarch64")]
            irq_chip: None,
            sys_mem,
            #[cfg(target_arch = "x86_64")]
            sys_io,
            sysbus,
            vm_state: Arc::new((Mutex::new(VmState::Created), Condvar::new())),
            boot_source: Arc::new(Mutex::new(vm_config.clone().boot_source)),
            vm_config: Arc::new(Mutex::new(vm_config.clone())),
            numa_nodes: None,
            drive_files: Arc::new(Mutex::new(vm_config.init_drive_files()?)),
            fwcfg_dev: None,
            machine_ram,
            hypervisor: hypervisor.clone(),
            migration_hypervisor: hypervisor,
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn pio_in(&self, addr: u64, mut data: &mut [u8]) -> bool {
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

        let length = data.len() as u64;
        self.sys_io
            .read(&mut data, GuestAddress(addr), length)
            .is_ok()
    }

    #[cfg(target_arch = "x86_64")]
    fn pio_out(&self, addr: u64, mut data: &[u8]) -> bool {
        use crate::x86_64::ich9_lpc::SLEEP_CTRL_OFFSET;

        let count = data.len() as u64;
        if addr == SLEEP_CTRL_OFFSET as u64 {
            if let Err(e) = self.cpus[0].pause() {
                log::error!("Fail to pause bsp, {:?}", e);
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

macro_rules! create_device_add_matches {
    ( $command:expr; $controller: expr;
        $(($($driver_name:tt)|+, $function_name:tt, $($arg:tt),*)),*;
        $(#[cfg($($features: tt)*)]
        ($driver_name1:tt, $function_name1:tt, $($arg1:tt),*)),*
    ) => {
        match $command {
            $(
                $($driver_name)|+ => {
                    $controller.$function_name($($arg),*)?;
                },
            )*
            $(
                #[cfg($($features)*)]
                $driver_name1 => {
                    $controller.$function_name1($($arg1),*)?;
                },
            )*
            _ => bail!("Unsupported device: {:?}", $command),
        }
    };
}

pub trait MachineOps {
    fn machine_base(&self) -> &MachineBase;

    fn machine_base_mut(&mut self) -> &mut MachineBase;

    fn build_smbios(
        &self,
        fw_cfg: &Arc<Mutex<dyn FwCfgOps>>,
        mem_array: Vec<(u64, u64)>,
    ) -> Result<()> {
        let vm_config = self.get_vm_config();
        let vmcfg_lock = vm_config.lock().unwrap();

        let mut smbios = SmbiosTable::new();
        let table = smbios.build_smbios_tables(
            vmcfg_lock.smbios.clone(),
            &vmcfg_lock.machine_config,
            mem_array,
        );
        let ep = build_smbios_ep30(table.len() as u32);

        let mut locked_fw_cfg = fw_cfg.lock().unwrap();
        locked_fw_cfg
            .add_file_entry(SMBIOS_TABLE_FILE, table)
            .with_context(|| "Failed to add smbios table file entry")?;
        locked_fw_cfg
            .add_file_entry(SMBIOS_ANCHOR_FILE, ep)
            .with_context(|| "Failed to add smbios anchor file entry")?;

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn load_boot_source(&self, fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>) -> Result<CPUBootConfig>;

    #[cfg(target_arch = "aarch64")]
    fn load_boot_source(
        &self,
        fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>,
        mem_start: u64,
    ) -> Result<CPUBootConfig> {
        use boot_loader::{load_linux, BootLoaderConfig};

        let mut boot_source = self.machine_base().boot_source.lock().unwrap();
        let initrd = boot_source.initrd.as_ref().map(|b| b.initrd_file.clone());

        let bootloader_config = BootLoaderConfig {
            kernel: boot_source.kernel_file.clone(),
            initrd,
            mem_start,
        };
        let layout = load_linux(&bootloader_config, &self.machine_base().sys_mem, fwcfg)
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

    #[cfg(target_arch = "aarch64")]
    fn load_cpu_features(&self, vmcfg: &VmConfig) -> Result<CPUFeatures> {
        Ok((&vmcfg.machine_config.cpu_config).into())
    }

    /// Init memory of vm to architecture.
    ///
    /// # Arguments
    ///
    /// * `mem_size` - memory size of VM.
    fn init_machine_ram(&self, sys_mem: &Arc<AddressSpace>, mem_size: u64) -> Result<()>;

    fn create_machine_ram(&self, mem_config: &MachineMemConfig, thread_num: u8) -> Result<()> {
        let root = self.get_vm_ram();
        let numa_nodes = self.get_numa_nodes();

        if numa_nodes.is_none() || mem_config.mem_zones.is_none() {
            let default_mem = create_default_mem(mem_config, thread_num)?;
            root.add_subregion_not_update(default_mem, 0_u64)?;
            return Ok(());
        }
        let zones = mem_config.mem_zones.as_ref().unwrap();
        let mut offset = 0_u64;
        for (_, node) in numa_nodes.as_ref().unwrap().iter().enumerate() {
            for zone in zones.iter() {
                if zone.id.eq(&node.1.mem_dev) {
                    let ram = create_backend_mem(zone, thread_num)?;
                    root.add_subregion_not_update(ram, offset)?;
                    offset += zone.size;
                    break;
                }
            }
        }
        Ok(())
    }

    /// Init I/O & memory address space and mmap guest memory.
    ///
    /// # Arguments
    ///
    /// * `mem_config` - Memory setting.
    /// * `sys_io` - IO address space required for x86_64.
    /// * `sys_mem` - Memory address space.
    fn init_memory(
        &self,
        mem_config: &MachineMemConfig,
        sys_mem: &Arc<AddressSpace>,
        nr_cpus: u8,
    ) -> Result<()> {
        let migrate_info = self.get_migrate_info();
        if migrate_info.0 != MigrateMode::File {
            self.create_machine_ram(mem_config, nr_cpus)?;
        }

        if migrate_info.0 != MigrateMode::File {
            self.init_machine_ram(sys_mem, mem_config.mem_size)?;
        }

        MigrationManager::register_memory_instance(sys_mem.clone());

        Ok(())
    }

    fn mem_show(&self) {
        self.machine_base().sys_mem.memspace_show();
        #[cfg(target_arch = "x86_64")]
        self.machine_base().sys_io.memspace_show();
        self.get_vm_ram().mtree(0_u32);
    }

    /// Create vcpu for virtual machine.
    ///
    /// # Arguments
    ///
    /// * `vcpu_id` - The id number of vcpu.
    /// * `vm` - `MachineInterface` to obtain functions cpu can use.
    /// * `max_cpus` - max cpu number of virtual machine.
    fn create_vcpu(
        vcpu_id: u8,
        vm: Arc<Mutex<dyn MachineInterface + Send + Sync>>,
        hypervisor: Arc<Mutex<dyn HypervisorOps>>,
        #[cfg(target_arch = "x86_64")] max_cpus: u8,
    ) -> Result<Arc<CPU>>
    where
        Self: Sized,
    {
        let locked_hypervisor = hypervisor.lock().unwrap();
        let hypervisor_cpu: Arc<dyn CPUHypervisorOps> =
            locked_hypervisor.create_hypervisor_cpu(vcpu_id)?;

        #[cfg(target_arch = "aarch64")]
        let arch_cpu = ArchCPU::new(u32::from(vcpu_id));
        #[cfg(target_arch = "x86_64")]
        let arch_cpu = ArchCPU::new(u32::from(vcpu_id), u32::from(max_cpus));

        let cpu = Arc::new(CPU::new(
            hypervisor_cpu,
            vcpu_id,
            Arc::new(Mutex::new(arch_cpu)),
            vm.clone(),
        ));
        Ok(cpu)
    }

    /// Init vcpu register with boot message.
    ///
    /// # Arguments
    ///
    /// * `vm` - `MachineInterface` to obtain functions cpu can use.
    /// * `nr_cpus` - The number of vcpus.
    /// * `max_cpus` - The max number of vcpus.
    /// * `boot_cfg` - Boot message generated by reading boot source to guest memory.
    fn init_vcpu(
        vm: Arc<Mutex<dyn MachineInterface + Send + Sync>>,
        hypervisor: Arc<Mutex<dyn HypervisorOps>>,
        nr_cpus: u8,
        #[cfg(target_arch = "x86_64")] max_cpus: u8,
        topology: &CPUTopology,
        boot_cfg: &CPUBootConfig,
        #[cfg(target_arch = "aarch64")] vcpu_cfg: &CPUFeatures,
    ) -> Result<Vec<Arc<CPU>>>
    where
        Self: Sized,
    {
        let mut cpus = Vec::<Arc<CPU>>::new();

        for vcpu_id in 0..nr_cpus {
            let cpu = Self::create_vcpu(
                vcpu_id,
                vm.clone(),
                hypervisor.clone(),
                #[cfg(target_arch = "x86_64")]
                max_cpus,
            )?;
            cpus.push(cpu.clone());

            MigrationManager::register_cpu_instance(cpu::ArchCPU::descriptor(), cpu, vcpu_id);
        }

        for (cpu_index, cpu) in cpus.iter().enumerate() {
            cpu.realize(
                boot_cfg,
                topology,
                #[cfg(target_arch = "aarch64")]
                vcpu_cfg,
            )
            .with_context(|| {
                format!(
                    "Failed to realize arch cpu register/features for CPU {}",
                    cpu_index
                )
            })?;
        }

        Ok(cpus)
    }

    /// Must be called after the CPUs have been realized and GIC has been created.
    ///
    /// # Arguments
    ///
    /// * `CPUFeatures` - The features of vcpu.
    #[cfg(target_arch = "aarch64")]
    fn cpu_post_init(&self, vcpu_cfg: &CPUFeatures) -> Result<()> {
        if vcpu_cfg.pmu {
            for cpu in self.machine_base().cpus.iter() {
                cpu.hypervisor_cpu.init_pmu()?;
            }
        }
        Ok(())
    }

    /// Add interrupt controller.
    ///
    /// # Arguments
    ///
    /// * `vcpu_count` - The number of vcpu.
    fn init_interrupt_controller(&mut self, vcpu_count: u64) -> Result<()>;

    /// Add RTC device.
    fn add_rtc_device(&mut self, #[cfg(target_arch = "x86_64")] _mem_size: u64) -> Result<()> {
        Ok(())
    }

    /// Add Generic event device.
    fn add_ged_device(&mut self) -> Result<()> {
        Ok(())
    }

    /// Add serial device.
    ///
    /// # Arguments
    ///
    /// * `config` - Device configuration.
    fn add_serial_device(&mut self, config: &SerialConfig) -> Result<()>;

    /// Add block device.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM configuration.
    /// * `cfg_args` - Device configuration args.
    fn add_virtio_mmio_block(&mut self, _vm_config: &mut VmConfig, _cfg_args: &str) -> Result<()> {
        bail!("Virtio mmio devices Not supported!");
    }

    /// Add virtio mmio vsock device.
    ///
    /// # Arguments
    ///
    /// * `cfg_args` - Device configuration.
    fn add_virtio_vsock(&mut self, cfg_args: &str) -> Result<()> {
        let device_cfg = parse_vsock(cfg_args)?;
        let sys_mem = self.get_sys_mem().clone();
        let vsock = Arc::new(Mutex::new(VhostKern::Vsock::new(&device_cfg, &sys_mem)));
        match parse_device_type(cfg_args)?.as_str() {
            "vhost-vsock-device" => {
                let device = VirtioMmioDevice::new(&sys_mem, vsock.clone());
                MigrationManager::register_device_instance(
                    VirtioMmioState::descriptor(),
                    self.realize_virtio_mmio_device(device)
                        .with_context(|| MachineError::RlzVirtioMmioErr)?,
                    &device_cfg.id,
                );
            }
            _ => {
                let bdf = get_pci_bdf(cfg_args)?;
                let multi_func = get_multi_function(cfg_args)?;
                let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;
                let mut virtio_pci_device = VirtioPciDevice::new(
                    device_cfg.id.clone(),
                    devfn,
                    sys_mem,
                    vsock.clone(),
                    parent_bus,
                    multi_func,
                );
                virtio_pci_device.enable_need_irqfd();
                virtio_pci_device
                    .realize()
                    .with_context(|| "Failed to add virtio pci vsock device")?;
            }
        }

        MigrationManager::register_device_instance(
            VhostKern::VsockState::descriptor(),
            vsock,
            &device_cfg.id,
        );

        Ok(())
    }

    fn realize_virtio_mmio_device(
        &mut self,
        _dev: VirtioMmioDevice,
    ) -> Result<Arc<Mutex<VirtioMmioDevice>>> {
        bail!("Virtio mmio devices not supported");
    }

    fn get_cpu_topo(&self) -> &CpuTopology {
        &self.machine_base().cpu_topo
    }

    fn get_cpus(&self) -> &Vec<Arc<CPU>> {
        &self.machine_base().cpus
    }

    fn get_sys_mem(&mut self) -> &Arc<AddressSpace> {
        &self.machine_base().sys_mem
    }

    fn get_vm_config(&self) -> Arc<Mutex<VmConfig>> {
        self.machine_base().vm_config.clone()
    }

    fn get_vm_state(&self) -> &Arc<(Mutex<VmState>, Condvar)> {
        &self.machine_base().vm_state
    }

    fn get_vm_ram(&self) -> &Arc<Region> {
        &self.machine_base().machine_ram
    }

    fn get_numa_nodes(&self) -> &Option<NumaNodes> {
        &self.machine_base().numa_nodes
    }

    fn get_hypervisor(&self) -> Arc<Mutex<dyn HypervisorOps>> {
        self.machine_base().hypervisor.clone()
    }

    /// Get migration mode and path from VM config. There are four modes in total:
    /// Tcp, Unix, File and Unknown.
    fn get_migrate_info(&self) -> Incoming {
        if let Some((mode, path)) = self.get_vm_config().lock().unwrap().incoming.as_ref() {
            return (*mode, path.to_string());
        }

        (MigrateMode::Unknown, String::new())
    }

    /// Add net device.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM configuration.
    /// * `cfg_args` - Device configuration args.
    fn add_virtio_mmio_net(&mut self, _vm_config: &mut VmConfig, _cfg_args: &str) -> Result<()> {
        bail!("Virtio mmio device Not supported!");
    }

    fn add_virtio_balloon(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        if vm_config.dev_name.get("balloon").is_some() {
            bail!("Only one balloon device is supported for each vm.");
        }
        let config = BalloonConfig::try_parse_from(str_slip_to_clap(cfg_args))?;
        vm_config.dev_name.insert("balloon".to_string(), 1);

        let sys_mem = self.get_sys_mem();
        let balloon = Arc::new(Mutex::new(Balloon::new(config.clone(), sys_mem.clone())));
        Balloon::object_init(balloon.clone());
        match parse_device_type(cfg_args)?.as_str() {
            "virtio-balloon-device" => {
                if config.addr.is_some() || config.bus.is_some() || config.multifunction.is_some() {
                    bail!("virtio balloon device config is error!");
                }
                let device = VirtioMmioDevice::new(sys_mem, balloon);
                self.realize_virtio_mmio_device(device)?;
            }
            _ => {
                if config.addr.is_none() || config.bus.is_none() {
                    bail!("virtio balloon pci config is error!");
                }
                let bdf = PciBdf {
                    bus: config.bus.unwrap(),
                    addr: config.addr.unwrap(),
                };
                let multi_func = config.multifunction.unwrap_or_default();
                let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;
                let sys_mem = self.get_sys_mem().clone();
                let virtio_pci_device = VirtioPciDevice::new(
                    config.id, devfn, sys_mem, balloon, parent_bus, multi_func,
                );
                virtio_pci_device
                    .realize()
                    .with_context(|| "Failed to add virtio pci balloon device")?;
            }
        }

        Ok(())
    }

    /// Add virtio serial device.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM configuration.
    /// * `cfg_args` - Device configuration args.
    fn add_virtio_serial(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        let serial_cfg = parse_virtio_serial(vm_config, cfg_args)?;
        let sys_mem = self.get_sys_mem().clone();
        let serial = Arc::new(Mutex::new(Serial::new(serial_cfg.clone())));

        match parse_device_type(cfg_args)?.as_str() {
            "virtio-serial-device" => {
                let device = VirtioMmioDevice::new(&sys_mem, serial.clone());
                MigrationManager::register_device_instance(
                    VirtioMmioState::descriptor(),
                    self.realize_virtio_mmio_device(device)
                        .with_context(|| MachineError::RlzVirtioMmioErr)?,
                    &serial_cfg.id,
                );
            }
            _ => {
                let bdf = serial_cfg.pci_bdf.unwrap();
                let multi_func = serial_cfg.multifunction;
                let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;
                let virtio_pci_device = VirtioPciDevice::new(
                    serial_cfg.id.clone(),
                    devfn,
                    sys_mem,
                    serial.clone(),
                    parent_bus,
                    multi_func,
                );
                virtio_pci_device
                    .realize()
                    .with_context(|| "Failed to add virtio pci serial device")?;
            }
        }

        MigrationManager::register_device_instance(
            VirtioSerialState::descriptor(),
            serial,
            &serial_cfg.id,
        );

        Ok(())
    }

    /// Add virtio serial port.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM configuration.
    /// * `cfg_args` - Device configuration args.
    fn add_virtio_serial_port(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        let serial_cfg = vm_config
            .virtio_serial
            .as_ref()
            .with_context(|| "No virtio serial device specified")?;

        let mut virtio_device = None;
        if serial_cfg.pci_bdf.is_none() {
            // Micro_vm.
            for dev in self.get_sys_bus().devices.iter() {
                let locked_busdev = dev.lock().unwrap();
                if locked_busdev.sysbusdev_base().dev_type == SysBusDevType::VirtioMmio {
                    let virtio_mmio_dev = locked_busdev
                        .as_any()
                        .downcast_ref::<VirtioMmioDevice>()
                        .unwrap();
                    if virtio_mmio_dev.device.lock().unwrap().device_type() == VIRTIO_TYPE_CONSOLE {
                        virtio_device = Some(virtio_mmio_dev.device.clone());
                        break;
                    }
                }
            }
        } else {
            // Standard_vm.
            let pci_dev = self
                .get_pci_dev_by_id_and_type(vm_config, Some(&serial_cfg.id), "virtio-serial-pci")
                .with_context(|| {
                    format!(
                        "Can not find virtio serial pci device {} from pci bus",
                        serial_cfg.id
                    )
                })?;
            let locked_pcidev = pci_dev.lock().unwrap();
            let virtio_pcidev = locked_pcidev
                .as_any()
                .downcast_ref::<VirtioPciDevice>()
                .unwrap();
            virtio_device = Some(virtio_pcidev.get_virtio_device().clone());
        }

        let virtio_dev = virtio_device.with_context(|| "No virtio serial device found")?;
        let mut virtio_dev_h = virtio_dev.lock().unwrap();
        let serial = virtio_dev_h.as_any_mut().downcast_mut::<Serial>().unwrap();

        let is_console = matches!(parse_device_type(cfg_args)?.as_str(), "virtconsole");
        let free_port0 = find_port_by_nr(&serial.ports, 0).is_none();
        // Note: port 0 is reserved for a virtconsole.
        let free_nr = get_max_nr(&serial.ports) + 1;
        let serialport_cfg =
            parse_virtserialport(vm_config, cfg_args, is_console, free_nr, free_port0)?;
        if serialport_cfg.nr >= serial.max_nr_ports {
            bail!(
                "virtio serial port nr {} should be less than virtio serial's max_nr_ports {}",
                serialport_cfg.nr,
                serial.max_nr_ports
            );
        }
        if find_port_by_nr(&serial.ports, serialport_cfg.nr).is_some() {
            bail!("Repetitive virtio serial port nr {}.", serialport_cfg.nr,);
        }

        let mut serial_port = SerialPort::new(serialport_cfg);
        let port = Arc::new(Mutex::new(serial_port.clone()));
        serial_port.realize()?;
        if !is_console {
            serial_port.chardev.lock().unwrap().set_device(port.clone());
        }
        serial.ports.lock().unwrap().push(port);

        Ok(())
    }

    /// Add virtio-rng device.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM configuration.
    /// * `cfg_args` - Device configuration arguments.
    fn add_virtio_rng(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        let device_cfg = parse_rng_dev(vm_config, cfg_args)?;
        let sys_mem = self.get_sys_mem();
        let rng_dev = Arc::new(Mutex::new(Rng::new(device_cfg.clone())));

        match parse_device_type(cfg_args)?.as_str() {
            "virtio-rng-device" => {
                let device = VirtioMmioDevice::new(sys_mem, rng_dev.clone());
                self.realize_virtio_mmio_device(device)
                    .with_context(|| "Failed to add virtio mmio rng device")?;
            }
            _ => {
                let bdf = get_pci_bdf(cfg_args)?;
                let multi_func = get_multi_function(cfg_args)?;
                let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;
                let sys_mem = self.get_sys_mem().clone();
                let vitio_pci_device = VirtioPciDevice::new(
                    device_cfg.id.clone(),
                    devfn,
                    sys_mem,
                    rng_dev.clone(),
                    parent_bus,
                    multi_func,
                );
                vitio_pci_device
                    .realize()
                    .with_context(|| "Failed to add pci rng device")?;
            }
        }

        MigrationManager::register_device_instance(RngState::descriptor(), rng_dev, &device_cfg.id);
        Ok(())
    }

    fn get_pci_host(&mut self) -> Result<&Arc<Mutex<PciHost>>> {
        bail!("No pci host found");
    }

    /// Add virtioFs device.
    ///
    /// # Arguments
    ///
    /// * 'vm_config' - VM configuration.
    /// * 'cfg_args' - Device configuration arguments.
    fn add_virtio_fs(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        let dev_cfg = parse_fs(vm_config, cfg_args)?;
        let id_clone = dev_cfg.id.clone();
        let sys_mem = self.get_sys_mem().clone();

        if !vm_config.machine_config.mem_config.mem_share {
            bail!("When configuring the vhost-user-fs-device or vhost-user-fs-pci device, the memory must be shared.");
        }

        match parse_device_type(cfg_args)?.as_str() {
            "vhost-user-fs-device" => {
                let device = Arc::new(Mutex::new(vhost::user::Fs::new(dev_cfg, sys_mem.clone())));
                let virtio_mmio_device = VirtioMmioDevice::new(&sys_mem, device);
                self.realize_virtio_mmio_device(virtio_mmio_device)
                    .with_context(|| "Failed to add vhost user fs device")?;
            }
            _ => {
                let device = Arc::new(Mutex::new(vhost::user::Fs::new(dev_cfg, sys_mem.clone())));
                let bdf = get_pci_bdf(cfg_args)?;
                let multi_func = get_multi_function(cfg_args)?;
                let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;

                let mut vitio_pci_device =
                    VirtioPciDevice::new(id_clone, devfn, sys_mem, device, parent_bus, multi_func);
                vitio_pci_device.enable_need_irqfd();
                vitio_pci_device
                    .realize()
                    .with_context(|| "Failed to add pci fs device")?;
            }
        }

        Ok(())
    }

    fn get_sys_bus(&mut self) -> &SysBus {
        &self.machine_base().sysbus
    }

    fn get_fwcfg_dev(&mut self) -> Option<Arc<Mutex<dyn FwCfgOps>>> {
        self.machine_base().fwcfg_dev.clone()
    }

    fn get_boot_order_list(&self) -> Option<Arc<Mutex<Vec<BootIndexInfo>>>> {
        None
    }

    fn reset_all_devices(&mut self) -> Result<()> {
        let sysbus = self.get_sys_bus();
        for dev in sysbus.devices.iter() {
            dev.lock()
                .unwrap()
                .reset()
                .with_context(|| "Fail to reset sysbus device")?;
        }

        if let Ok(pci_host) = self.get_pci_host() {
            pci_host
                .lock()
                .unwrap()
                .reset()
                .with_context(|| "Fail to reset pci host")?;
        }

        Ok(())
    }

    fn check_id_existed_in_xhci(&mut self, id: &str) -> Result<bool> {
        let vm_config = self.get_vm_config();
        let locked_vmconfig = vm_config.lock().unwrap();
        let parent_dev = self
            .get_pci_dev_by_id_and_type(&locked_vmconfig, None, "nec-usb-xhci")
            .with_context(|| "Can not find parent device from pci bus")?;
        let locked_parent_dev = parent_dev.lock().unwrap();
        let xhci_pci = locked_parent_dev
            .as_any()
            .downcast_ref::<XhciPciDevice>()
            .with_context(|| "PciDevOps can not downcast to XhciPciDevice")?;
        let mut locked_xhci = xhci_pci.xhci.lock().unwrap();
        let port = locked_xhci.find_usb_port_by_id(id);
        Ok(port.is_some())
    }

    fn check_device_id_existed(&mut self, name: &str) -> Result<()> {
        // If there is no pci bus, skip the id check, such as micro vm.
        if let Ok(pci_host) = self.get_pci_host() {
            // Because device_del needs an id when removing a device, it's necessary to ensure that
            // the id is unique.
            if name.is_empty() {
                bail!("Device id is empty");
            }
            if PciBus::find_attached_bus(&pci_host.lock().unwrap().root_bus, name).is_some() {
                bail!("Device id {} existed", name);
            }
            if self.check_id_existed_in_xhci(name).unwrap_or_default() {
                bail!("Device id {} existed in xhci", name);
            }
        }
        Ok(())
    }

    fn reset_fwcfg_boot_order(&mut self) -> Result<()> {
        // SAFETY: unwrap is safe because stand machine always make sure it not return null.
        let boot_order_vec = self.get_boot_order_list().unwrap();
        let mut locked_boot_order_vec = boot_order_vec.lock().unwrap().clone();
        if locked_boot_order_vec.is_empty() {
            return Ok(());
        }
        locked_boot_order_vec.sort_by(|x, y| x.boot_index.cmp(&y.boot_index));
        let mut fwcfg_boot_order_string = String::new();
        for item in &locked_boot_order_vec {
            fwcfg_boot_order_string.push_str(&item.dev_path);
            fwcfg_boot_order_string.push('\n');
        }
        fwcfg_boot_order_string.push('\0');

        let fwcfg = self.get_fwcfg_dev();
        if fwcfg.is_none() {
            warn!("Direct kernel boot mode don't support set boot order");
            return Ok(());
        }
        fwcfg
            .unwrap()
            .lock()
            .unwrap()
            .modify_file_entry("bootorder", fwcfg_boot_order_string.as_bytes().to_vec())
            .with_context(|| "Fail to add bootorder entry for standard VM.")?;
        Ok(())
    }

    /// Check the boot index of device is duplicated or not.
    ///
    /// # Arguments
    ///
    /// * `bootindex` - The boot index of the device.
    fn check_bootindex(&mut self, boot_index: u8) -> Result<()> {
        // SAFETY: Unwrap is safe because StdMachine will overwrite this function,
        // which ensure boot_order_list is not None.
        let boot_order_list = self.get_boot_order_list().unwrap();
        if boot_order_list
            .lock()
            .unwrap()
            .iter()
            .any(|item| item.boot_index == boot_index)
        {
            bail!("Failed to add duplicated bootindex {}.", boot_index);
        }

        Ok(())
    }

    /// Add boot index of device.
    ///
    /// # Arguments
    ///
    /// * `bootindex` - The boot index of the device.
    /// * `dev_path` - The firmware device path of the device.
    /// * `dev_id` - The id of the device.
    fn add_bootindex_devices(&mut self, boot_index: u8, dev_path: &str, dev_id: &str) {
        // SAFETY: Unwrap is safe because StdMachine will overwrite this function,
        // which ensure boot_order_list is not None.
        let boot_order_list = self.get_boot_order_list().unwrap();
        boot_order_list.lock().unwrap().push(BootIndexInfo {
            boot_index,
            id: dev_id.to_string(),
            dev_path: dev_path.to_string(),
        });
    }

    /// Delete boot index of device.
    ///
    /// # Arguments
    ///
    /// * `dev_id` - The id of the device.
    fn del_bootindex_devices(&self, dev_id: &str) {
        // Unwrap is safe because StdMachine will overwrite this function,
        // which ensure boot_order_list is not None.
        let boot_order_list = self.get_boot_order_list().unwrap();
        let mut locked_boot_order_list = boot_order_list.lock().unwrap();
        locked_boot_order_list.retain(|item| item.id != dev_id);
    }

    #[cfg(feature = "pvpanic")]
    fn add_pvpanic(&mut self, cfg_args: &str) -> Result<()> {
        let bdf = get_pci_bdf(cfg_args)?;
        let device_cfg = parse_pvpanic(cfg_args)?;

        let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;
        let pcidev = PvPanicPci::new(&device_cfg, devfn, parent_bus);
        pcidev
            .realize()
            .with_context(|| "Failed to realize pvpanic device")?;

        Ok(())
    }

    fn add_virtio_pci_blk(
        &mut self,
        vm_config: &mut VmConfig,
        cfg_args: &str,
        hotplug: bool,
    ) -> Result<()> {
        let bdf = get_pci_bdf(cfg_args)?;
        let multi_func = get_multi_function(cfg_args)?;
        let queues_auto = Some(VirtioPciDevice::virtio_pci_auto_queues_num(
            0,
            vm_config.machine_config.nr_cpus,
            MAX_VIRTIO_QUEUE,
        ));
        let device_cfg = parse_blk(vm_config, cfg_args, queues_auto)?;
        if let Some(bootindex) = device_cfg.boot_index {
            self.check_bootindex(bootindex)
                .with_context(|| "Fail to add virtio pci blk device for invalid bootindex")?;
        }
        let device = Arc::new(Mutex::new(Block::new(
            device_cfg.clone(),
            self.get_drive_files(),
        )));
        let pci_dev = self
            .add_virtio_pci_device(&device_cfg.id, &bdf, device.clone(), multi_func, false)
            .with_context(|| "Failed to add virtio pci device")?;
        if let Some(bootindex) = device_cfg.boot_index {
            // Eg: OpenFirmware device path(virtio-blk disk):
            // /pci@i0cf8/scsi@6[,3]/disk@0,0
            //   |             |  |       | |
            //   |             |  |       | |
            //   |             |  |     fixed 0.
            //   |         PCI slot,[function] holding disk.
            //  PCI root as system bus port.
            if let Some(dev_path) = pci_dev.lock().unwrap().get_dev_path() {
                self.add_bootindex_devices(bootindex, &dev_path, &device_cfg.id);
            }
        }
        MigrationManager::register_device_instance(
            BlockState::descriptor(),
            device,
            &device_cfg.id,
        );
        if !hotplug {
            self.reset_bus(&device_cfg.id)?;
        }
        Ok(())
    }

    fn add_virtio_pci_scsi(
        &mut self,
        vm_config: &mut VmConfig,
        cfg_args: &str,
        hotplug: bool,
    ) -> Result<()> {
        let bdf = get_pci_bdf(cfg_args)?;
        let multi_func = get_multi_function(cfg_args)?;
        let queues_auto = Some(VirtioPciDevice::virtio_pci_auto_queues_num(
            0,
            vm_config.machine_config.nr_cpus,
            MAX_VIRTIO_QUEUE,
        ));
        let device_cfg = parse_scsi_controller(cfg_args, queues_auto)?;
        let device = Arc::new(Mutex::new(ScsiCntlr::new(device_cfg.clone())));

        let bus_name = format!("{}.0", device_cfg.id);
        scsi_cntlr_create_scsi_bus(&bus_name, &device)?;

        let pci_dev = self
            .add_virtio_pci_device(&device_cfg.id, &bdf, device.clone(), multi_func, false)
            .with_context(|| "Failed to add virtio scsi controller")?;
        if !hotplug {
            self.reset_bus(&device_cfg.id)?;
        }
        device.lock().unwrap().config.boot_prefix = pci_dev.lock().unwrap().get_dev_path();
        Ok(())
    }

    fn add_scsi_device(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        let device_cfg = parse_scsi_device(vm_config, cfg_args)?;
        let scsi_type = match parse_device_type(cfg_args)?.as_str() {
            "scsi-hd" => SCSI_TYPE_DISK,
            _ => SCSI_TYPE_ROM,
        };
        if let Some(bootindex) = device_cfg.boot_index {
            self.check_bootindex(bootindex)
                .with_context(|| "Failed to add scsi device for invalid bootindex")?;
        }
        let device = Arc::new(Mutex::new(ScsiDevice::new(
            device_cfg.clone(),
            scsi_type,
            self.get_drive_files(),
        )));

        let pci_dev = self
            .get_pci_dev_by_id_and_type(vm_config, Some(&device_cfg.cntlr), "virtio-scsi-pci")
            .with_context(|| {
                format!(
                    "Can not find scsi controller from pci bus {}",
                    device_cfg.cntlr
                )
            })?;
        let locked_pcidev = pci_dev.lock().unwrap();
        let virtio_pcidev = locked_pcidev
            .as_any()
            .downcast_ref::<VirtioPciDevice>()
            .unwrap();
        let virtio_device = virtio_pcidev.get_virtio_device().lock().unwrap();
        let cntlr = virtio_device.as_any().downcast_ref::<ScsiCntlr>().unwrap();

        let bus = cntlr.bus.as_ref().unwrap();
        if bus
            .lock()
            .unwrap()
            .devices
            .contains_key(&(device_cfg.target, device_cfg.lun))
        {
            bail!("Wrong! Two scsi devices have the same scsi-id and lun");
        }
        let iothread = cntlr.config.iothread.clone();
        device.lock().unwrap().realize(iothread)?;
        bus.lock()
            .unwrap()
            .devices
            .insert((device_cfg.target, device_cfg.lun), device.clone());
        device.lock().unwrap().parent_bus = Arc::downgrade(bus);

        if let Some(bootindex) = device_cfg.boot_index {
            // Eg: OpenFirmware device path(virtio-scsi disk):
            // /pci@i0cf8/scsi@7[,3]/channel@0/disk@2,3
            //   |             |  |      |          | |
            //   |             |  |      |     target,lun.
            //   |             |  |   channel(unused, fixed 0).
            //   |         PCI slot,[function] holding SCSI controller.
            //  PCI root as system bus port.
            let prefix = cntlr.config.boot_prefix.as_ref().unwrap();
            let dev_path =
                format! {"{}/channel@0/disk@{:x},{:x}", prefix, device_cfg.target, device_cfg.lun};
            self.add_bootindex_devices(bootindex, &dev_path, &device_cfg.id);
        }
        Ok(())
    }

    fn add_virtio_pci_net(
        &mut self,
        vm_config: &mut VmConfig,
        cfg_args: &str,
        hotplug: bool,
    ) -> Result<()> {
        let bdf = get_pci_bdf(cfg_args)?;
        let multi_func = get_multi_function(cfg_args)?;
        let device_cfg = parse_net(vm_config, cfg_args)?;
        let mut need_irqfd = false;
        let device: Arc<Mutex<dyn VirtioDevice>> = if device_cfg.vhost_type.is_some() {
            need_irqfd = true;
            if device_cfg.vhost_type == Some(String::from("vhost-kernel")) {
                Arc::new(Mutex::new(VhostKern::Net::new(
                    &device_cfg,
                    self.get_sys_mem(),
                )))
            } else {
                Arc::new(Mutex::new(VhostUser::Net::new(
                    &device_cfg,
                    self.get_sys_mem(),
                )))
            }
        } else {
            let device = Arc::new(Mutex::new(virtio::Net::new(device_cfg.clone())));
            MigrationManager::register_device_instance(
                VirtioNetState::descriptor(),
                device.clone(),
                &device_cfg.id,
            );
            device
        };
        self.add_virtio_pci_device(&device_cfg.id, &bdf, device, multi_func, need_irqfd)?;
        if !hotplug {
            self.reset_bus(&device_cfg.id)?;
        }
        Ok(())
    }

    fn add_vhost_user_blk_pci(
        &mut self,
        vm_config: &mut VmConfig,
        cfg_args: &str,
        hotplug: bool,
    ) -> Result<()> {
        let bdf = get_pci_bdf(cfg_args)?;
        let multi_func = get_multi_function(cfg_args)?;
        let queues_auto = Some(VirtioPciDevice::virtio_pci_auto_queues_num(
            0,
            vm_config.machine_config.nr_cpus,
            MAX_VIRTIO_QUEUE,
        ));
        let device_cfg = parse_vhost_user_blk(vm_config, cfg_args, queues_auto)?;
        let device: Arc<Mutex<dyn VirtioDevice>> = Arc::new(Mutex::new(VhostUser::Block::new(
            &device_cfg,
            self.get_sys_mem(),
        )));
        let pci_dev = self
            .add_virtio_pci_device(&device_cfg.id, &bdf, device.clone(), multi_func, true)
            .with_context(|| {
                format!(
                    "Failed to add virtio pci device, device id: {}",
                    &device_cfg.id
                )
            })?;
        if let Some(bootindex) = device_cfg.boot_index {
            if let Some(dev_path) = pci_dev.lock().unwrap().get_dev_path() {
                self.add_bootindex_devices(bootindex, &dev_path, &device_cfg.id);
            }
        }
        if !hotplug {
            self.reset_bus(&device_cfg.id)?;
        }
        Ok(())
    }

    fn add_vhost_user_blk_device(
        &mut self,
        vm_config: &mut VmConfig,
        cfg_args: &str,
    ) -> Result<()> {
        let device_cfg = parse_vhost_user_blk(vm_config, cfg_args, None)?;
        let device: Arc<Mutex<dyn VirtioDevice>> = Arc::new(Mutex::new(VhostUser::Block::new(
            &device_cfg,
            self.get_sys_mem(),
        )));
        let virtio_mmio_device = VirtioMmioDevice::new(self.get_sys_mem(), device);
        self.realize_virtio_mmio_device(virtio_mmio_device)
            .with_context(|| "Failed to add vhost user block device")?;
        Ok(())
    }

    fn create_vfio_pci_device(
        &mut self,
        id: &str,
        bdf: &PciBdf,
        host: &str,
        sysfsdev: &str,
        multifunc: bool,
    ) -> Result<()> {
        let (devfn, parent_bus) = self.get_devfn_and_parent_bus(bdf)?;
        let path = if !host.is_empty() {
            format!("/sys/bus/pci/devices/{}", host)
        } else {
            sysfsdev.to_string()
        };
        let device = VfioDevice::new(Path::new(&path), self.get_sys_mem())
            .with_context(|| "Failed to create vfio device.")?;
        let vfio_pci = VfioPciDevice::new(
            device,
            devfn,
            id.to_string(),
            parent_bus,
            multifunc,
            self.get_sys_mem().clone(),
        );
        VfioPciDevice::realize(vfio_pci).with_context(|| "Failed to realize vfio-pci device.")?;
        Ok(())
    }

    fn add_vfio_device(&mut self, cfg_args: &str, hotplug: bool) -> Result<()> {
        let hypervisor = self.get_hypervisor();
        let locked_hypervisor = hypervisor.lock().unwrap();
        *KVM_DEVICE_FD.lock().unwrap() = locked_hypervisor.create_vfio_device();

        let device_cfg: VfioConfig = parse_vfio(cfg_args)?;
        let bdf = get_pci_bdf(cfg_args)?;
        let multifunc = get_multi_function(cfg_args)?;
        self.create_vfio_pci_device(
            &device_cfg.id,
            &bdf,
            &device_cfg.host,
            &device_cfg.sysfsdev,
            multifunc,
        )?;
        if !hotplug {
            self.reset_bus(&device_cfg.id)?;
        }
        Ok(())
    }

    #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
    fn update_ohui_srv(&mut self, _passthru: bool) {}

    #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
    fn get_ohui_fb(&self) -> Option<FileBackend> {
        None
    }

    #[cfg(feature = "virtio_gpu")]
    fn add_virtio_pci_gpu(&mut self, cfg_args: &str) -> Result<()> {
        let bdf = get_pci_bdf(cfg_args)?;
        let multi_func = get_multi_function(cfg_args)?;
        let device_cfg = parse_gpu(cfg_args)?;
        let device = Arc::new(Mutex::new(Gpu::new(device_cfg.clone())));

        #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
        if device.lock().unwrap().device_quirk() == Some(VirtioDeviceQuirk::VirtioGpuEnableBar0)
            && self.get_ohui_fb().is_some()
        {
            self.update_ohui_srv(true);
            device.lock().unwrap().set_bar0_fb(self.get_ohui_fb());
        }

        self.add_virtio_pci_device(&device_cfg.id, &bdf, device, multi_func, false)?;
        Ok(())
    }

    fn get_devfn_and_parent_bus(&mut self, bdf: &PciBdf) -> Result<(u8, Weak<Mutex<PciBus>>)> {
        let pci_host = self.get_pci_host()?;
        let bus = pci_host.lock().unwrap().root_bus.clone();
        let pci_bus = PciBus::find_bus_by_name(&bus, &bdf.bus);
        if pci_bus.is_none() {
            bail!("Parent bus :{} not found", &bdf.bus);
        }
        let parent_bus = Arc::downgrade(&pci_bus.unwrap());
        let devfn = (bdf.addr.0 << 3) + bdf.addr.1;
        Ok((devfn, parent_bus))
    }

    fn add_pci_root_port(&mut self, cfg_args: &str) -> Result<()> {
        let bdf = get_pci_bdf(cfg_args)?;
        let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;
        let device_cfg = parse_root_port(cfg_args)?;
        let pci_host = self.get_pci_host()?;
        let bus = pci_host.lock().unwrap().root_bus.clone();
        if PciBus::find_bus_by_name(&bus, &device_cfg.id).is_some() {
            bail!("ID {} already exists.", &device_cfg.id);
        }
        let rootport = RootPort::new(
            device_cfg.id,
            devfn,
            device_cfg.port,
            parent_bus,
            device_cfg.multifunction,
        );
        rootport
            .realize()
            .with_context(|| "Failed to add pci root port")?;
        Ok(())
    }

    fn add_virtio_pci_device(
        &mut self,
        id: &str,
        bdf: &PciBdf,
        device: Arc<Mutex<dyn VirtioDevice>>,
        multi_func: bool,
        need_irqfd: bool,
    ) -> Result<Arc<Mutex<dyn PciDevOps>>> {
        let (devfn, parent_bus) = self.get_devfn_and_parent_bus(bdf)?;
        let sys_mem = self.get_sys_mem();
        let mut pcidev = VirtioPciDevice::new(
            id.to_string(),
            devfn,
            sys_mem.clone(),
            device,
            parent_bus,
            multi_func,
        );
        if need_irqfd {
            pcidev.enable_need_irqfd();
        }
        let clone_pcidev = Arc::new(Mutex::new(pcidev.clone()));
        pcidev
            .realize()
            .with_context(|| "Failed to add virtio pci device")?;
        Ok(clone_pcidev)
    }

    /// Set the parent bus slot on when device attached
    fn reset_bus(&mut self, dev_id: &str) -> Result<()> {
        let pci_host = self.get_pci_host()?;
        let locked_pci_host = pci_host.lock().unwrap();
        let bus = PciBus::find_attached_bus(&locked_pci_host.root_bus, dev_id)
            .with_context(|| format!("Bus not found, dev id {}", dev_id))?
            .0;
        let locked_bus = bus.lock().unwrap();
        if locked_bus.name == "pcie.0" {
            // No need to reset root bus
            return Ok(());
        }
        let parent_bridge = locked_bus
            .parent_bridge
            .as_ref()
            .with_context(|| format!("Parent bridge does not exist, dev id {}", dev_id))?;
        let dev = parent_bridge.upgrade().unwrap();
        let locked_dev = dev.lock().unwrap();
        let name = locked_dev.name();
        drop(locked_dev);
        let mut devfn = None;
        let locked_bus = locked_pci_host.root_bus.lock().unwrap();
        for (id, dev) in &locked_bus.devices {
            if dev.lock().unwrap().name() == name {
                devfn = Some(*id);
                break;
            }
        }
        drop(locked_bus);
        // It's safe to call devfn.unwrap(), because the bus exists.
        match locked_pci_host.find_device(0, devfn.unwrap()) {
            Some(dev) => dev
                .lock()
                .unwrap()
                .reset(false)
                .with_context(|| "Failed to reset bus"),
            None => bail!("Failed to found device"),
        }
    }

    /// Init vm global config.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM Configuration.
    fn init_global_config(&mut self, vm_config: &mut VmConfig) -> Result<()> {
        let fast_unplug = vm_config
            .global_config
            .get("pcie-root-port.fast-unplug")
            .map_or(false, |val| val == FAST_UNPLUG_ON);

        RootPort::set_fast_unplug_feature(fast_unplug);
        Ok(())
    }

    /// Add numa nodes information to standard machine.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM Configuration.
    fn add_numa_nodes(&mut self, vm_config: &mut VmConfig) -> Result<Option<NumaNodes>> {
        if vm_config.numa_nodes.is_empty() {
            return Ok(None);
        }

        let mut numa_nodes: NumaNodes = BTreeMap::new();
        vm_config.numa_nodes.sort_by(|p, n| n.0.cmp(&p.0));
        for numa in vm_config.numa_nodes.iter() {
            match numa.0.as_str() {
                "node" => {
                    let numa_config: NumaConfig = parse_numa_mem(numa.1.as_str())?;
                    if numa_nodes.contains_key(&numa_config.numa_id) {
                        bail!("Numa node id is repeated {}", numa_config.numa_id);
                    }
                    let mut numa_node = NumaNode {
                        cpus: numa_config.cpus,
                        mem_dev: numa_config.mem_dev.clone(),
                        ..Default::default()
                    };

                    numa_node.size = vm_config
                        .object
                        .mem_object
                        .remove(&numa_config.mem_dev)
                        .map(|mem_conf| mem_conf.size)
                        .with_context(|| {
                            format!(
                                "Object for memory-backend {} config not found",
                                numa_config.mem_dev
                            )
                        })?;
                    numa_nodes.insert(numa_config.numa_id, numa_node);
                }
                "dist" => {
                    let dist: (u32, NumaDistance) = parse_numa_distance(numa.1.as_str())?;
                    if !numa_nodes.contains_key(&dist.0) {
                        bail!("Numa node id is not found {}", dist.0);
                    }
                    if !numa_nodes.contains_key(&dist.1.destination) {
                        bail!("Numa node id is not found {}", dist.1.destination);
                    }

                    if let Some(n) = numa_nodes.get_mut(&dist.0) {
                        if n.distances.contains_key(&dist.1.destination) {
                            bail!(
                                "Numa destination info {} repeat settings",
                                dist.1.destination
                            );
                        }
                        n.distances.insert(dist.1.destination, dist.1.distance);
                    }
                }
                _ => {
                    bail!("Unsupported args for NUMA node: {}", numa.0.as_str());
                }
            }
        }

        // Complete user parameters if necessary.
        complete_numa_node(
            &mut numa_nodes,
            vm_config.machine_config.nr_cpus,
            vm_config.machine_config.mem_config.mem_size,
        )?;

        Ok(Some(numa_nodes))
    }

    /// Add usb xhci controller.
    ///
    /// # Arguments
    ///
    /// * `cfg_args` - XHCI Configuration.
    fn add_usb_xhci(&mut self, cfg_args: &str) -> Result<()> {
        let device_cfg = XhciConfig::try_parse_from(str_slip_to_clap(cfg_args))?;
        let bdf = PciBdf::new(device_cfg.bus.clone(), device_cfg.addr);
        let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;

        let pcidev = XhciPciDevice::new(&device_cfg, devfn, parent_bus, self.get_sys_mem());

        pcidev
            .realize()
            .with_context(|| "Failed to realize usb xhci device")?;
        Ok(())
    }

    /// Add scream sound based on ivshmem.
    ///
    /// # Arguments
    ///
    /// * `cfg_args` - scream configuration.
    #[cfg(feature = "scream")]
    fn add_ivshmem_scream(
        &mut self,
        vm_config: &mut VmConfig,
        cfg_args: &str,
        token_id: Option<Arc<RwLock<u64>>>,
    ) -> Result<()> {
        let config = ScreamConfig::try_parse_from(str_slip_to_clap(cfg_args))?;
        let bdf = PciBdf {
            bus: config.bus.clone(),
            addr: config.addr,
        };
        let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;

        let mem_cfg = vm_config
            .object
            .mem_object
            .remove(&config.memdev)
            .with_context(|| {
                format!(
                    "Object for memory-backend-ram {} config not found",
                    config.memdev
                )
            })?;

        if !mem_cfg.share {
            bail!("Object for share config is not on");
        }

        let scream = Scream::new(mem_cfg.size, config, token_id);
        scream
            .realize(devfn, parent_bus)
            .with_context(|| "Failed to realize scream device")
    }

    /// Get the corresponding device from the PCI bus based on the device id and device type name.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM configuration.
    /// * `id` - Device id.
    /// * `dev_type` - Device type name.
    fn get_pci_dev_by_id_and_type(
        &mut self,
        vm_config: &VmConfig,
        id: Option<&str>,
        dev_type: &str,
    ) -> Option<Arc<Mutex<dyn PciDevOps>>> {
        let (id_check, id_str) = if id.is_some() {
            (true, format! {"id={}", id.unwrap()})
        } else {
            (false, "".to_string())
        };

        for dev in &vm_config.devices {
            if dev.0.as_str() != dev_type || id_check && !dev.1.contains(&id_str) {
                continue;
            }

            let cfg_args = dev.1.as_str();
            let bdf = get_pci_bdf(cfg_args).ok()?;
            let devfn = (bdf.addr.0 << 3) + bdf.addr.1;
            let pci_host = self.get_pci_host().ok()?;
            let root_bus = pci_host.lock().unwrap().root_bus.clone();
            if let Some(pci_bus) = PciBus::find_bus_by_name(&root_bus, &bdf.bus) {
                return pci_bus.lock().unwrap().get_device(0, devfn);
            } else {
                return None;
            }
        }
        None
    }

    /// Attach usb device to xhci controller.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM configuration.
    /// * `usb_dev` - Usb device.
    fn attach_usb_to_xhci_controller(
        &mut self,
        vm_config: &mut VmConfig,
        usb_dev: Arc<Mutex<dyn UsbDevice>>,
    ) -> Result<()> {
        let parent_dev = self
            .get_pci_dev_by_id_and_type(vm_config, None, "nec-usb-xhci")
            .with_context(|| "Can not find parent device from pci bus")?;
        let locked_parent_dev = parent_dev.lock().unwrap();
        let xhci_pci = locked_parent_dev
            .as_any()
            .downcast_ref::<XhciPciDevice>()
            .with_context(|| "PciDevOps can not downcast to XhciPciDevice")?;
        xhci_pci.attach_device(&(usb_dev))?;

        Ok(())
    }

    /// Detach usb device from xhci controller.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM configuration.
    /// * `id` - id of the usb device.
    fn detach_usb_from_xhci_controller(
        &mut self,
        vm_config: &mut VmConfig,
        id: String,
    ) -> Result<()> {
        let parent_dev = self
            .get_pci_dev_by_id_and_type(vm_config, None, "nec-usb-xhci")
            .with_context(|| "Can not find parent device from pci bus")?;
        let locked_parent_dev = parent_dev.lock().unwrap();
        let xhci_pci = locked_parent_dev
            .as_any()
            .downcast_ref::<XhciPciDevice>()
            .with_context(|| "PciDevOps can not downcast to XhciPciDevice")?;
        xhci_pci.detach_device(id)?;

        Ok(())
    }

    /// Add usb device.
    ///
    /// # Arguments
    ///
    /// * `driver` - USB device class.
    /// * `cfg_args` - USB device Configuration.
    fn add_usb_device(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        let usb_device = match parse_device_type(cfg_args)?.as_str() {
            "usb-kbd" => {
                let config = UsbKeyboardConfig::try_parse_from(str_slip_to_clap(cfg_args))?;
                let keyboard = UsbKeyboard::new(config);
                keyboard
                    .realize()
                    .with_context(|| "Failed to realize usb keyboard device")?
            }
            "usb-tablet" => {
                let config = UsbTabletConfig::try_parse_from(str_slip_to_clap(cfg_args))?;
                let tablet = UsbTablet::new(config);
                tablet
                    .realize()
                    .with_context(|| "Failed to realize usb tablet device")?
            }
            #[cfg(feature = "usb_camera")]
            "usb-camera" => {
                let config = UsbCameraConfig::try_parse_from(str_slip_to_clap(cfg_args))?;
                let cameradev = get_cameradev_by_id(vm_config, config.cameradev.clone())
                    .with_context(|| {
                        format!(
                            "no cameradev found with id {:?} for usb-camera",
                            config.cameradev
                        )
                    })?;

                let camera = UsbCamera::new(config, cameradev)?;
                camera
                    .realize()
                    .with_context(|| "Failed to realize usb camera device")?
            }
            "usb-storage" => {
                let device_cfg = parse_usb_storage(vm_config, cfg_args)?;
                let storage = UsbStorage::new(device_cfg, self.get_drive_files());
                storage
                    .realize()
                    .with_context(|| "Failed to realize usb storage device")?
            }
            #[cfg(feature = "usb_host")]
            "usb-host" => {
                let config = UsbHostConfig::try_parse_from(str_slip_to_clap(cfg_args))?;
                let usbhost = UsbHost::new(config)?;
                usbhost
                    .realize()
                    .with_context(|| "Failed to realize usb host device")?
            }
            _ => bail!("Unknown usb device classes."),
        };

        self.attach_usb_to_xhci_controller(vm_config, usb_device)?;
        Ok(())
    }

    /// Add peripheral devices.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM Configuration.
    fn add_devices(&mut self, vm_config: &mut VmConfig) -> Result<()> {
        self.add_rtc_device(
            #[cfg(target_arch = "x86_64")]
            vm_config.machine_config.mem_config.mem_size,
        )
        .with_context(|| MachineError::AddDevErr("RTC".to_string()))?;

        self.add_ged_device()
            .with_context(|| MachineError::AddDevErr("Ged".to_string()))?;

        let cloned_vm_config = vm_config.clone();
        if let Some(serial) = cloned_vm_config.serial.as_ref() {
            self.add_serial_device(serial)
                .with_context(|| MachineError::AddDevErr("serial".to_string()))?;
        }

        if let Some(pflashs) = cloned_vm_config.pflashs.as_ref() {
            self.add_pflash_device(pflashs)
                .with_context(|| MachineError::AddDevErr("pflash".to_string()))?;
        }

        for dev in &cloned_vm_config.devices {
            let cfg_args = dev.1.as_str();
            // Check whether the device id exists to ensure device uniqueness.
            let id = parse_device_id(cfg_args)?;
            self.check_device_id_existed(&id)
                .with_context(|| format!("Failed to check device id: config {}", cfg_args))?;
            #[cfg(feature = "scream")]
            let token_id = self.get_token_id();

            create_device_add_matches!(
                dev.0.as_str(); self;
                ("virtio-blk-device", add_virtio_mmio_block, vm_config, cfg_args),
                ("virtio-blk-pci", add_virtio_pci_blk, vm_config, cfg_args, false),
                ("virtio-scsi-pci", add_virtio_pci_scsi, vm_config, cfg_args, false),
                ("scsi-hd" | "scsi-cd", add_scsi_device, vm_config, cfg_args),
                ("virtio-net-device", add_virtio_mmio_net, vm_config, cfg_args),
                ("virtio-net-pci", add_virtio_pci_net, vm_config, cfg_args, false),
                ("pcie-root-port", add_pci_root_port, cfg_args),
                ("vhost-vsock-pci" | "vhost-vsock-device", add_virtio_vsock, cfg_args),
                ("virtio-balloon-device" | "virtio-balloon-pci", add_virtio_balloon, vm_config, cfg_args),
                ("virtio-serial-device" | "virtio-serial-pci", add_virtio_serial, vm_config, cfg_args),
                ("virtconsole" | "virtserialport", add_virtio_serial_port, vm_config, cfg_args),
                ("virtio-rng-device" | "virtio-rng-pci", add_virtio_rng, vm_config, cfg_args),
                ("vfio-pci", add_vfio_device, cfg_args, false),
                ("vhost-user-blk-device",add_vhost_user_blk_device, vm_config, cfg_args),
                ("vhost-user-blk-pci",add_vhost_user_blk_pci, vm_config, cfg_args, false),
                ("vhost-user-fs-pci" | "vhost-user-fs-device", add_virtio_fs, vm_config, cfg_args),
                ("nec-usb-xhci", add_usb_xhci, cfg_args),
                ("usb-kbd" | "usb-storage" | "usb-tablet" | "usb-camera" | "usb-host", add_usb_device,  vm_config, cfg_args);
                #[cfg(feature = "virtio_gpu")]
                ("virtio-gpu-pci", add_virtio_pci_gpu, cfg_args),
                #[cfg(feature = "ramfb")]
                ("ramfb", add_ramfb, cfg_args),
                #[cfg(feature = "demo_device")]
                ("pcie-demo-dev", add_demo_dev, vm_config, cfg_args),
                #[cfg(feature = "scream")]
                ("ivshmem-scream", add_ivshmem_scream, vm_config, cfg_args, token_id),
                #[cfg(feature = "pvpanic")]
                ("pvpanic", add_pvpanic, cfg_args)
            );
        }

        Ok(())
    }

    fn get_token_id(&self) -> Option<Arc<RwLock<u64>>> {
        None
    }

    fn add_pflash_device(&mut self, _configs: &[PFlashConfig]) -> Result<()> {
        bail!("Pflash device is not supported!");
    }

    fn add_ramfb(&mut self, _cfg_args: &str) -> Result<()> {
        bail!("ramfb device is not supported!");
    }

    fn display_init(&mut self, _vm_config: &mut VmConfig) -> Result<()> {
        bail!("Display is not supported.");
    }

    #[cfg(feature = "demo_device")]
    fn add_demo_dev(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        let bdf = get_pci_bdf(cfg_args)?;
        let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;

        let demo_cfg = parse_demo_dev(vm_config, cfg_args.to_string())
            .with_context(|| "failed to parse cmdline for demo dev.")?;

        let sys_mem = self.get_sys_mem().clone();
        let demo_dev = DemoDev::new(demo_cfg, devfn, sys_mem, parent_bus);

        demo_dev.realize()
    }

    /// Return the syscall whitelist for seccomp.
    fn syscall_whitelist(&self) -> Vec<BpfRule>;

    /// Register seccomp rules in syscall whitelist to seccomp.
    fn register_seccomp(&self, balloon_enable: bool) -> Result<()> {
        let mut seccomp_filter = SyscallFilter::new(SeccompOpt::Trap);
        let mut bpf_rules = self.syscall_whitelist();
        if balloon_enable {
            balloon_allow_list(&mut bpf_rules);
        }

        if let Ok(cov_enable) = std::env::var("STRATOVIRT_COV") {
            if cov_enable.eq("on") {
                coverage_allow_list(&mut bpf_rules);
            }
        }

        for bpf_rule in &mut bpf_rules {
            seccomp_filter.push(bpf_rule);
        }
        seccomp_filter
            .realize()
            .with_context(|| "Failed to init seccomp filter.")?;
        Ok(())
    }

    /// Get the drive backend files.
    fn get_drive_files(&self) -> Arc<Mutex<HashMap<String, DriveFile>>> {
        self.machine_base().drive_files.clone()
    }

    /// Fetch a cloned file from drive backend files.
    fn fetch_drive_file(&self, path: &str) -> Result<File> {
        let files = self.get_drive_files();
        let drive_files = files.lock().unwrap();
        VmConfig::fetch_drive_file(&drive_files, path)
    }

    /// Register a new drive backend file.
    fn register_drive_file(
        &self,
        id: &str,
        path: &str,
        read_only: bool,
        direct: bool,
    ) -> Result<()> {
        let files = self.get_drive_files();
        let mut drive_files = files.lock().unwrap();
        VmConfig::add_drive_file(&mut drive_files, id, path, read_only, direct)?;

        // Lock the added file if VM is running.
        let drive_file = drive_files.get_mut(path).unwrap();
        let vm_state = self.get_vm_state().deref().0.lock().unwrap();
        if *vm_state == VmState::Running && !drive_file.locked {
            if let Err(e) = lock_file(&drive_file.file, path, read_only) {
                VmConfig::remove_drive_file(&mut drive_files, path)?;
                return Err(e);
            }
            drive_file.locked = true;
        }
        Ok(())
    }

    /// Unregister a drive backend file.
    fn unregister_drive_file(&self, path: &str) -> Result<()> {
        let files = self.get_drive_files();
        let mut drive_files = files.lock().unwrap();
        VmConfig::remove_drive_file(&mut drive_files, path)
    }

    /// Active drive backend files. i.e., Apply lock.
    fn active_drive_files(&self) -> Result<()> {
        for drive_file in self.get_drive_files().lock().unwrap().values_mut() {
            if drive_file.locked {
                continue;
            }
            lock_file(&drive_file.file, &drive_file.path, drive_file.read_only)?;
            drive_file.locked = true;
        }
        Ok(())
    }

    /// Deactive drive backend files. i.e., Release lock.
    fn deactive_drive_files(&self) -> Result<()> {
        for drive_file in self.get_drive_files().lock().unwrap().values_mut() {
            if !drive_file.locked {
                continue;
            }
            unlock_file(&drive_file.file, &drive_file.path)?;
            drive_file.locked = false;
        }
        Ok(())
    }

    /// Realize the machine.
    ///
    /// # Arguments
    ///
    /// * `vm` - The machine structure.
    /// * `vm_config` - VM configuration.
    fn realize(vm: &Arc<Mutex<Self>>, vm_config: &mut VmConfig) -> Result<()>
    where
        Self: Sized;

    /// Run `LightMachine` with `paused` flag.
    ///
    /// # Arguments
    ///
    /// * `paused` - Flag for `paused` when `LightMachine` starts to run.
    fn run(&self, paused: bool) -> Result<()> {
        self.vm_start(
            paused,
            &self.machine_base().cpus,
            &mut self.machine_base().vm_state.0.lock().unwrap(),
        )
    }

    /// Start machine as `Running` or `Paused` state.
    ///
    /// # Arguments
    ///
    /// * `paused` - After started, paused all vcpu or not.
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm state.
    fn vm_start(&self, paused: bool, cpus: &[Arc<CPU>], vm_state: &mut VmState) -> Result<()> {
        if !paused {
            EventLoop::get_ctx(None).unwrap().enable_clock();
            self.active_drive_files()?;
        }

        let nr_vcpus = cpus.len();
        let cpus_thread_barrier = Arc::new(Barrier::new(nr_vcpus + 1));
        for (cpu_index, cpu) in cpus.iter().enumerate() {
            let cpu_thread_barrier = cpus_thread_barrier.clone();
            if let Err(e) = CPU::start(cpu.clone(), cpu_thread_barrier, paused) {
                self.deactive_drive_files()?;
                return Err(anyhow!("Failed to run vcpu{}, {:?}", cpu_index, e));
            }
        }

        if paused {
            *vm_state = VmState::Paused;
        } else {
            *vm_state = VmState::Running;
        }
        cpus_thread_barrier.wait();

        Ok(())
    }

    /// Pause VM as `Paused` state, sleepy all vcpu thread.
    ///
    /// # Arguments
    ///
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm state.
    fn vm_pause(
        &self,
        cpus: &[Arc<CPU>],
        #[cfg(target_arch = "aarch64")] irq_chip: &Option<Arc<InterruptController>>,
        vm_state: &mut VmState,
    ) -> Result<()> {
        EventLoop::get_ctx(None).unwrap().disable_clock();

        self.deactive_drive_files()?;

        for (cpu_index, cpu) in cpus.iter().enumerate() {
            if let Err(e) = cpu.pause() {
                self.active_drive_files()?;
                return Err(anyhow!("Failed to pause vcpu{}, {:?}", cpu_index, e));
            }
        }

        #[cfg(target_arch = "aarch64")]
        // SAFETY: ARM architecture must have interrupt controllers in user mode.
        irq_chip.as_ref().unwrap().stop();

        *vm_state = VmState::Paused;

        Ok(())
    }

    /// Resume VM as `Running` state, awaken all vcpu thread.
    ///
    /// # Arguments
    ///
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm state.
    fn vm_resume(&self, cpus: &[Arc<CPU>], vm_state: &mut VmState) -> Result<()> {
        EventLoop::get_ctx(None).unwrap().enable_clock();

        self.active_drive_files()?;

        for (cpu_index, cpu) in cpus.iter().enumerate() {
            if let Err(e) = cpu.resume() {
                self.deactive_drive_files()?;
                return Err(anyhow!("Failed to resume vcpu{}, {:?}", cpu_index, e));
            }
        }

        *vm_state = VmState::Running;

        Ok(())
    }

    /// Destroy VM as `Shutdown` state, destroy vcpu thread.
    ///
    /// # Arguments
    ///
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm state.
    fn vm_destroy(&self, cpus: &[Arc<CPU>], vm_state: &mut VmState) -> Result<()> {
        for (cpu_index, cpu) in cpus.iter().enumerate() {
            cpu.destroy()
                .with_context(|| format!("Failed to destroy vcpu{}", cpu_index))?;
        }

        *vm_state = VmState::Shutdown;

        Ok(())
    }

    /// Transfer VM state from `old` to `new`.
    ///
    /// # Arguments
    ///
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm state.
    /// * `old_state` - Old vm state want to leave.
    /// * `new_state` - New vm state want to transfer to.
    fn vm_state_transfer(
        &self,
        cpus: &[Arc<CPU>],
        #[cfg(target_arch = "aarch64")] irq_chip: &Option<Arc<InterruptController>>,
        vm_state: &mut VmState,
        old_state: VmState,
        new_state: VmState,
    ) -> Result<()> {
        use VmState::*;

        if *vm_state != old_state {
            bail!("Vm lifecycle error: state check failed.");
        }

        match (old_state, new_state) {
            (Created, Running) => self
                .vm_start(false, cpus, vm_state)
                .with_context(|| "Failed to start vm.")?,
            (Running, Paused) => self
                .vm_pause(
                    cpus,
                    #[cfg(target_arch = "aarch64")]
                    irq_chip,
                    vm_state,
                )
                .with_context(|| "Failed to pause vm.")?,
            (Paused, Running) => self
                .vm_resume(cpus, vm_state)
                .with_context(|| "Failed to resume vm.")?,
            (_, Shutdown) => self
                .vm_destroy(cpus, vm_state)
                .with_context(|| "Failed to destroy vm.")?,
            (_, _) => {
                bail!("Vm lifecycle error: this transform is illegal.");
            }
        }

        if *vm_state != new_state {
            bail!(
                "Vm lifecycle error: state '{:?} -> {:?}' transform failed.",
                old_state,
                new_state
            );
        }

        Ok(())
    }
}

/// Normal run or resume virtual machine from migration/snapshot.
///
/// # Arguments
///
/// * `vm` - virtual machine that implement `MachineOps`.
/// * `cmd_args` - Command arguments from user.
pub fn vm_run(
    vm: &Arc<Mutex<dyn MachineOps + Send + Sync>>,
    cmd_args: &arg_parser::ArgMatches,
) -> Result<()> {
    let migrate = vm.lock().unwrap().get_migrate_info();
    if migrate.0 == MigrateMode::Unknown {
        vm.lock()
            .unwrap()
            .run(cmd_args.is_present("freeze_cpu"))
            .with_context(|| "Failed to start VM.")?;
    } else {
        start_incoming_migration(vm).with_context(|| "Failed to start migration.")?;
    }

    Ok(())
}

/// Start incoming migration from destination.
fn start_incoming_migration(vm: &Arc<Mutex<dyn MachineOps + Send + Sync>>) -> Result<()> {
    let (mode, path) = vm.lock().unwrap().get_migrate_info();
    match mode {
        MigrateMode::File => {
            MigrationManager::restore_snapshot(&path)
                .with_context(|| "Failed to restore snapshot")?;
            vm.lock()
                .unwrap()
                .run(false)
                .with_context(|| "Failed to start VM.")?;
        }
        MigrateMode::Unix => {
            clear_file(path.clone())?;
            let listener = UnixListener::bind(&path)?;
            let (mut sock, _) = listener.accept()?;
            remove_file(&path)?;

            MigrationManager::recv_migration(&mut sock)
                .with_context(|| "Failed to receive migration with unix mode")?;
            vm.lock()
                .unwrap()
                .run(false)
                .with_context(|| "Failed to start VM.")?;
            MigrationManager::finish_migration(&mut sock)
                .with_context(|| "Failed to finish migraton.")?;
        }
        MigrateMode::Tcp => {
            let listener = TcpListener::bind(&path)?;
            let mut sock = listener.accept().map(|(stream, _)| stream)?;

            MigrationManager::recv_migration(&mut sock)
                .with_context(|| "Failed to receive migration with tcp mode")?;
            vm.lock()
                .unwrap()
                .run(false)
                .with_context(|| "Failed to start VM.")?;
            MigrationManager::finish_migration(&mut sock)
                .with_context(|| "Failed to finish migraton.")?;
        }
        MigrateMode::Unknown => {
            bail!("Unknown migration mode");
        }
    }

    // End the migration and reset the mode.
    let locked_vm = vm.lock().unwrap();
    let vm_config = locked_vm.get_vm_config();
    if let Some((mode, _)) = vm_config.lock().unwrap().incoming.as_mut() {
        *mode = MigrateMode::Unknown;
    }

    Ok(())
}

fn coverage_allow_list(syscall_allow_list: &mut Vec<BpfRule>) {
    syscall_allow_list.extend(vec![
        BpfRule::new(libc::SYS_fcntl),
        BpfRule::new(libc::SYS_ftruncate),
    ])
}

#[cfg(feature = "windows_emu_pid")]
fn check_windows_emu_pid(
    pid_path: String,
    powerdown_req: Arc<EventFd>,
    shutdown_req: Arc<EventFd>,
) {
    let mut check_delay = Duration::from_millis(4000);
    if !Path::new(&pid_path).exists() {
        log::info!("Detect windows emu exited, let VM exits now");
        if get_run_stage() == VmRunningStage::Os {
            if let Err(e) = powerdown_req.write(1) {
                log::error!("Failed to send powerdown request after emu exits: {:?}", e);
            }
        } else if let Err(e) = shutdown_req.write(1) {
            log::error!("Failed to send shutdown request after emu exits: {:?}", e);
        }
        // Continue checking to prevent exit failed.
        check_delay = Duration::from_millis(1000);
    }

    let check_emu_alive = Box::new(move || {
        check_windows_emu_pid(
            pid_path.clone(),
            powerdown_req.clone(),
            shutdown_req.clone(),
        );
    });
    EventLoop::get_ctx(None)
        .unwrap()
        .timer_add(check_emu_alive, check_delay);
}
