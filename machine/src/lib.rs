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

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
#[macro_use]
extern crate machine_manager;
#[cfg(target_arch = "x86_64")]
#[macro_use]
extern crate vmm_sys_util;

pub mod errors {
    error_chain! {
        links {
            AddressSpace(address_space::errors::Error, address_space::errors::ErrorKind);
            IntCtrl(devices::IntCtrlErrs::Error, devices::IntCtrlErrs::ErrorKind) #[cfg(target_arch = "aarch64")];
            Legacy(devices::LegacyErrs::Error, devices::LegacyErrs::ErrorKind);
            MicroVm(super::micro_vm::errors::Error, super::micro_vm::errors::ErrorKind);
            StdVm(super::standard_vm::errors::Error, super::standard_vm::errors::ErrorKind);
            Util(util::errors::Error, util::errors::ErrorKind);
            Virtio(virtio::errors::Error, virtio::errors::ErrorKind);
            MachineManager(machine_manager::config::errors::Error, machine_manager::config::errors::ErrorKind);
            Hypervisor(hypervisor::errors::Error, hypervisor::errors::ErrorKind);
        }

        foreign_links {
            KvmIoctl(kvm_ioctls::Error);
            Io(std::io::Error);
        }

        errors {
            AddDevErr(dev: String) {
                display("Failed to add {} device.", dev)
            }
            LoadKernErr {
                display("Failed to load kernel.")
            }
            CrtMemSpaceErr {
                display("Failed to create memory address space")
            }
            CrtIoSpaceErr {
                display("Failed to create I/O address space")
            }
            RegMemRegionErr(base: u64, size: u64) {
                display("Failed to register region in memory space: base={},size={}", base, size)
            }
            InitEventFdErr(fd: String) {
                display("Failed to init eventfd {}.", fd)
            }
            RlzVirtioMmioErr {
                display("Failed to realize virtio mmio.")
            }
            #[cfg(target_arch = "x86_64")]
            CrtIrqchipErr {
                display("Failed to create irq chip.")
            }
            #[cfg(target_arch = "x86_64")]
            SetTssErr {
                display("Failed to set tss address.")
            }
            #[cfg(target_arch = "x86_64")]
            CrtPitErr {
                display("Failed to create PIT.")
            }
            #[cfg(target_arch = "aarch64")]
            GenFdtErr {
                display("Failed to generate FDT.")
            }
            #[cfg(target_arch = "aarch64")]
            WrtFdtErr(addr: u64, size: usize) {
                display("Failed to write FDT: addr={}, size={}", addr, size)
            }
            RegNotifierErr {
                display("Failed to register event notifier.")
            }
            StartVcpuErr(id: u8) {
                display("Failed to run vcpu{}.", id)
            }
            PauseVcpuErr(id: u8) {
                display("Failed to pause vcpu{}.", id)
            }
            ResumeVcpuErr(id: u8) {
                display("Failed to resume vcpu{}.", id)
            }
            DestroyVcpuErr(id: u8) {
                display("Failed to destroy vcpu{}.", id)
            }
        }
    }
}

mod micro_vm;
mod standard_vm;

pub use micro_vm::LightMachine;
use pci::{PciBus, PciDevOps, PciHost, RootPort};
pub use standard_vm::StdMachine;
use virtio::{
    BlockState, RngState, VhostKern, VirtioConsoleState, VirtioDevice, VirtioMmioState,
    VirtioNetState,
};

use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::{Arc, Barrier, Mutex, Weak};

#[cfg(target_arch = "x86_64")]
use address_space::KvmIoListener;
use address_space::{create_host_mmaps, AddressSpace, KvmMemoryListener, Region};
use cpu::{ArchCPU, CPUBootConfig, CPUInterface, CPU};
use devices::legacy::FwCfgOps;
#[cfg(target_arch = "aarch64")]
use devices::InterruptController;
use hypervisor::kvm::KVM_FDS;
use kvm_ioctls::VcpuFd;
use machine_manager::config::{
    get_multi_function, get_pci_bdf, parse_balloon, parse_blk, parse_device_id, parse_net,
    parse_rng_dev, parse_root_port, parse_vfio, parse_virtconsole, parse_virtio_serial,
    parse_vsock, MachineMemConfig, PFlashConfig, PciBdf, SerialConfig, VfioConfig, VmConfig,
    FAST_UNPLUG_ON,
};
use machine_manager::event_loop::EventLoop;
use machine_manager::machine::{KvmVmState, MachineInterface};
use migration::MigrationManager;
use util::loop_context::{EventNotifier, NotifierCallback, NotifierOperation};
use util::seccomp::{BpfRule, SeccompOpt, SyscallFilter};
use vfio::{VfioDevice, VfioPciDevice};
use virtio::{balloon_allow_list, Balloon, Block, Console, Rng, VirtioMmioDevice, VirtioPciDevice};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use errors::{ErrorKind, Result, ResultExt};
use standard_vm::errors::Result as StdResult;

pub trait MachineOps {
    /// Calculate the ranges of memory according to architecture.
    ///
    /// # Arguments
    ///
    /// * `mem_size` - memory size of VM.
    ///
    /// # Returns
    ///
    /// A array of ranges, it's element represents (start_addr, size).
    /// On x86_64, there is a gap ranged from (4G - 768M) to 4G, which will be skipped.
    fn arch_ram_ranges(&self, mem_size: u64) -> Vec<(u64, u64)>;

    fn load_boot_source(&self, fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>) -> Result<CPUBootConfig>;

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
        #[cfg(target_arch = "x86_64")] sys_io: &Arc<AddressSpace>,
        sys_mem: &Arc<AddressSpace>,
        is_migrate: bool,
        nr_cpus: u8,
    ) -> Result<()> {
        // KVM_CREATE_VM system call is invoked when KVM_FDS is used for the first time. The system
        // call registers some notifier functions in the KVM, which are frequently triggered when
        // doing memory prealloc.To avoid affecting memory prealloc performance, create_host_mmaps
        // needs to be invoked first.
        let mut mem_mappings = Vec::new();
        if !is_migrate {
            let ram_ranges = self.arch_ram_ranges(mem_config.mem_size);
            mem_mappings = create_host_mmaps(&ram_ranges, &mem_config, nr_cpus)
                .chain_err(|| "Failed to mmap guest ram.")?;
        }

        sys_mem
            .register_listener(Arc::new(Mutex::new(KvmMemoryListener::new(
                KVM_FDS.load().fd.as_ref().unwrap().get_nr_memslots() as u32,
            ))))
            .chain_err(|| "Failed to register KVM listener for memory space.")?;
        #[cfg(target_arch = "x86_64")]
        sys_io
            .register_listener(Arc::new(Mutex::new(KvmIoListener::default())))
            .chain_err(|| "Failed to register KVM listener for I/O address space.")?;

        if !is_migrate {
            for mmap in mem_mappings.iter() {
                let base = mmap.start_address().raw_value();
                let size = mmap.size();
                sys_mem
                    .root()
                    .add_subregion(Region::init_ram_region(mmap.clone()), base)
                    .chain_err(|| ErrorKind::RegMemRegionErr(base, size))?;
            }
        }

        MigrationManager::register_memory_instance(sys_mem.clone());

        Ok(())
    }

    /// Init vcpu register with boot message.
    ///
    /// # Arguments
    ///
    /// * `vm` - `MachineInterface` to obtain functions cpu can use.
    /// * `nr_cpus` - The number of vcpus.
    /// * `fds` - File descriptors obtained by creating new Vcpu in KVM.
    /// * `boot_cfg` - Boot message generated by reading boot source to guest memory.
    fn init_vcpu(
        vm: Arc<Mutex<dyn MachineInterface + Send + Sync>>,
        nr_cpus: u8,
        fds: &[Arc<VcpuFd>],
        boot_cfg: &Option<CPUBootConfig>,
    ) -> Result<Vec<Arc<CPU>>>
    where
        Self: Sized,
    {
        let mut cpus = Vec::<Arc<CPU>>::new();

        for vcpu_id in 0..nr_cpus {
            #[cfg(target_arch = "aarch64")]
            let arch_cpu = ArchCPU::new(u32::from(vcpu_id));
            #[cfg(target_arch = "x86_64")]
            let arch_cpu = ArchCPU::new(u32::from(vcpu_id), u32::from(nr_cpus));

            let cpu = Arc::new(CPU::new(
                fds[vcpu_id as usize].clone(),
                vcpu_id,
                Arc::new(Mutex::new(arch_cpu)),
                vm.clone(),
            ));
            cpus.push(cpu.clone());

            MigrationManager::register_device_instance(cpu::ArchCPU::descriptor(), cpu, false);
        }

        if let Some(boot_config) = boot_cfg {
            for cpu_index in 0..nr_cpus as usize {
                cpus[cpu_index as usize]
                    .realize(&boot_config)
                    .chain_err(|| {
                        format!(
                            "Failed to realize arch cpu register for CPU {}/KVM",
                            cpu_index
                        )
                    })?;
            }
        }

        Ok(cpus)
    }

    /// Add interrupt controller.
    ///
    /// # Arguments
    ///
    /// * `vcpu_count` - The number of vcpu.
    fn init_interrupt_controller(&mut self, vcpu_count: u64) -> Result<()>;

    /// Add RTC device.
    fn add_rtc_device(&mut self, #[cfg(target_arch = "x86_64")] mem_size: u64) -> Result<()>;

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
        if cfg_args.contains("vhost-vsock-device") {
            let device = VirtioMmioDevice::new(&sys_mem, vsock.clone());
            MigrationManager::register_device_instance_mutex(
                VirtioMmioState::descriptor(),
                self.realize_virtio_mmio_device(device)
                    .chain_err(|| ErrorKind::RlzVirtioMmioErr)?,
            );
        } else {
            let bdf = get_pci_bdf(cfg_args)?;
            let multi_func = get_multi_function(cfg_args)?;
            let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;
            let virtio_pci_device = VirtioPciDevice::new(
                device_cfg.id,
                devfn,
                sys_mem,
                vsock.clone(),
                parent_bus,
                multi_func,
            );
            virtio_pci_device
                .realize()
                .chain_err(|| "Failed to add virtio pci vsock device")?;
        }
        MigrationManager::register_device_instance_mutex(
            VhostKern::VsockState::descriptor(),
            vsock,
        );

        Ok(())
    }

    fn realize_virtio_mmio_device(
        &mut self,
        _dev: VirtioMmioDevice,
    ) -> Result<Arc<Mutex<VirtioMmioDevice>>> {
        bail!("Virtio mmio devices not supported");
    }

    fn get_sys_mem(&mut self) -> &Arc<AddressSpace>;

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
        let device_cfg = parse_balloon(vm_config, cfg_args)?;
        let sys_mem = self.get_sys_mem();
        let balloon = Arc::new(Mutex::new(Balloon::new(&device_cfg, sys_mem.clone())));
        Balloon::object_init(balloon.clone());
        if cfg_args.contains("virtio-balloon-device") {
            let device = VirtioMmioDevice::new(sys_mem, balloon);
            self.realize_virtio_mmio_device(device)?;
        } else {
            let name = device_cfg.id;
            let bdf = get_pci_bdf(cfg_args)?;
            let multi_func = get_multi_function(cfg_args)?;
            let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;
            let sys_mem = self.get_sys_mem().clone();
            let virtio_pci_device =
                VirtioPciDevice::new(name, devfn, sys_mem, balloon, parent_bus, multi_func);
            virtio_pci_device
                .realize()
                .chain_err(|| "Failed to add virtio pci balloon device")?;
        }

        Ok(())
    }

    /// Add console device.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM configuration.
    /// * `cfg_args` - Device configuration args.
    fn add_virtio_console(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        let device_cfg = parse_virtconsole(vm_config, cfg_args)?;
        let sys_mem = self.get_sys_mem();
        let console = Arc::new(Mutex::new(Console::new(device_cfg.clone())));
        if let Some(serial) = &vm_config.virtio_serial {
            if serial.pci_bdf.is_none() {
                let device = VirtioMmioDevice::new(sys_mem, console.clone());
                MigrationManager::register_device_instance_mutex(
                    VirtioMmioState::descriptor(),
                    self.realize_virtio_mmio_device(device)
                        .chain_err(|| ErrorKind::RlzVirtioMmioErr)?,
                );
            } else {
                let name = device_cfg.id;
                let virtio_serial_info = if let Some(serial_info) = &vm_config.virtio_serial {
                    serial_info
                } else {
                    bail!("No virtio-serial-pci device configured for virtconsole");
                };
                // Reasonable, because for virtio-serial-pci device, the bdf has been checked.
                let bdf = virtio_serial_info.pci_bdf.clone().unwrap();
                let multi_func = virtio_serial_info.multifunction;
                let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;
                let sys_mem = self.get_sys_mem().clone();
                let virtio_pci_device = VirtioPciDevice::new(
                    name,
                    devfn,
                    sys_mem,
                    console.clone(),
                    parent_bus,
                    multi_func,
                );
                virtio_pci_device
                    .realize()
                    .chain_err(|| "Failed  to add virtio pci console device")?;
            }
        } else {
            bail!("No virtio-serial-bus specified");
        }
        MigrationManager::register_device_instance_mutex(VirtioConsoleState::descriptor(), console);

        Ok(())
    }

    fn add_virtio_serial(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        parse_virtio_serial(vm_config, cfg_args)?;
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
        if cfg_args.contains("virtio-rng-device") {
            let device = VirtioMmioDevice::new(sys_mem, rng_dev.clone());
            self.realize_virtio_mmio_device(device)
                .chain_err(|| "Failed to add virtio mmio rng device")?;
        } else {
            let bdf = get_pci_bdf(cfg_args)?;
            let multi_func = get_multi_function(cfg_args)?;
            let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;
            let sys_mem = self.get_sys_mem().clone();
            let vitio_pci_device = VirtioPciDevice::new(
                device_cfg.id,
                devfn,
                sys_mem,
                rng_dev.clone(),
                parent_bus,
                multi_func,
            );
            vitio_pci_device
                .realize()
                .chain_err(|| "Failed to add pci rng device")?;
        }
        MigrationManager::register_device_instance_mutex(RngState::descriptor(), rng_dev);
        Ok(())
    }

    fn get_pci_host(&mut self) -> StdResult<&Arc<Mutex<PciHost>>> {
        bail!("No pci host found");
    }

    fn check_device_id_existed(&mut self, name: &str) -> Result<()> {
        // If there is no pci bus, skip the id check, such as micro vm.
        if let Ok(pci_host) = self.get_pci_host() {
            // Because device_del needs an id when removing a device, it's necessary to ensure that the id is unique.
            if name.is_empty() {
                bail!("Device id is empty");
            }
            if PciBus::find_attached_bus(&pci_host.lock().unwrap().root_bus, name).is_some() {
                bail!("Device id {} existed", name);
            }
        }
        Ok(())
    }

    fn add_virtio_pci_blk(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        let bdf = get_pci_bdf(cfg_args)?;
        let multi_func = get_multi_function(cfg_args)?;
        let device_cfg = parse_blk(vm_config, cfg_args)?;
        let device = Arc::new(Mutex::new(Block::new(device_cfg.clone())));
        self.add_virtio_pci_device(&device_cfg.id, &bdf, device.clone(), multi_func)?;
        MigrationManager::register_device_instance_mutex(BlockState::descriptor(), device);
        self.reset_bus(&device_cfg.id)?;
        Ok(())
    }

    fn add_virtio_pci_net(&mut self, vm_config: &mut VmConfig, cfg_args: &str) -> Result<()> {
        let bdf = get_pci_bdf(cfg_args)?;
        let multi_func = get_multi_function(cfg_args)?;
        let device_cfg = parse_net(vm_config, cfg_args)?;
        let device: Arc<Mutex<dyn VirtioDevice>> = if device_cfg.vhost_type.is_some() {
            Arc::new(Mutex::new(VhostKern::Net::new(
                &device_cfg,
                self.get_sys_mem(),
            )))
        } else {
            let device = Arc::new(Mutex::new(virtio::Net::new(device_cfg.clone())));
            MigrationManager::register_device_instance_mutex(
                VirtioNetState::descriptor(),
                device.clone(),
            );
            device
        };
        self.add_virtio_pci_device(&device_cfg.id, &bdf, device, multi_func)?;
        self.reset_bus(&device_cfg.id)?;
        Ok(())
    }

    fn create_vfio_pci_device(
        &mut self,
        id: &str,
        bdf: &PciBdf,
        host: &str,
        multifunc: bool,
    ) -> Result<()> {
        let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;
        let path = format!("/sys/bus/pci/devices/{}", host);
        let device = VfioDevice::new(Path::new(&path), self.get_sys_mem())
            .chain_err(|| "Failed to create vfio device.")?;
        let vfio_pci = VfioPciDevice::new(
            device,
            devfn,
            id.to_string(),
            parent_bus,
            multifunc,
            self.get_sys_mem().clone(),
        );
        VfioPciDevice::realize(vfio_pci).chain_err(|| "Failed to realize vfio-pci device.")?;
        Ok(())
    }

    fn add_vfio_device(&mut self, cfg_args: &str) -> Result<()> {
        let device_cfg: VfioConfig = parse_vfio(cfg_args)?;
        let bdf = get_pci_bdf(cfg_args)?;
        let multifunc = get_multi_function(cfg_args)?;
        self.create_vfio_pci_device(&device_cfg.id, &bdf, &device_cfg.host, multifunc)?;
        self.reset_bus(&device_cfg.id)?;
        Ok(())
    }

    fn get_devfn_and_parent_bus(&mut self, bdf: &PciBdf) -> StdResult<(u8, Weak<Mutex<PciBus>>)> {
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
            bail!("ID {} already exists.");
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
            .chain_err(|| "Failed to add pci root port")?;
        Ok(())
    }

    fn add_virtio_pci_device(
        &mut self,
        id: &str,
        bdf: &PciBdf,
        device: Arc<Mutex<dyn VirtioDevice>>,
        multi_func: bool,
    ) -> Result<()> {
        let (devfn, parent_bus) = self.get_devfn_and_parent_bus(&bdf)?;
        let sys_mem = self.get_sys_mem();
        let pcidev = VirtioPciDevice::new(
            id.to_string(),
            devfn,
            sys_mem.clone(),
            device,
            parent_bus,
            multi_func,
        );
        pcidev
            .realize()
            .chain_err(|| "Failed to add virtio pci device")?;
        Ok(())
    }

    /// Set the parent bus slot on when device attached
    fn reset_bus(&mut self, dev_id: &str) -> Result<()> {
        let pci_host = self.get_pci_host()?;
        let locked_pci_host = pci_host.lock().unwrap();
        let bus =
            if let Some((bus, _)) = PciBus::find_attached_bus(&locked_pci_host.root_bus, &dev_id) {
                bus
            } else {
                bail!("Bus not found, dev id {}", dev_id);
            };
        let locked_bus = bus.lock().unwrap();
        if locked_bus.name == "pcie.0" {
            // No need to reset root bus
            return Ok(());
        }
        let parent_bridge = if let Some(bridge) = locked_bus.parent_bridge.as_ref() {
            bridge
        } else {
            bail!("Parent bridge does not exist, dev id {}", dev_id);
        };
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
                .chain_err(|| "Failed to reset bus"),
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
        .chain_err(|| ErrorKind::AddDevErr("RTC".to_string()))?;

        let cloned_vm_config = vm_config.clone();
        if let Some(serial) = cloned_vm_config.serial.as_ref() {
            self.add_serial_device(serial)
                .chain_err(|| ErrorKind::AddDevErr("serial".to_string()))?;
        }

        if let Some(pflashs) = cloned_vm_config.pflashs.as_ref() {
            self.add_pflash_device(pflashs)
                .chain_err(|| ErrorKind::AddDevErr("pflash".to_string()))?;
        }

        for dev in &cloned_vm_config.devices {
            let cfg_args = dev.1.as_str();
            // Check whether the device id exists to ensure device uniqueness.
            let id = parse_device_id(cfg_args)?;
            self.check_device_id_existed(&id)
                .chain_err(|| format!("Failed to check device id: config {}", cfg_args))?;
            match dev.0.as_str() {
                "virtio-blk-device" => {
                    self.add_virtio_mmio_block(vm_config, cfg_args)?;
                }
                "virtio-blk-pci" => {
                    self.add_virtio_pci_blk(vm_config, cfg_args)?;
                }
                "virtio-net-device" => {
                    self.add_virtio_mmio_net(vm_config, cfg_args)?;
                }
                "virtio-net-pci" => {
                    self.add_virtio_pci_net(vm_config, cfg_args)?;
                }
                "pcie-root-port" => {
                    self.add_pci_root_port(cfg_args)?;
                }
                "vhost-vsock-pci" | "vhost-vsock-device" => {
                    self.add_virtio_vsock(cfg_args)?;
                }
                "virtio-balloon-device" | "virtio-balloon-pci" => {
                    self.add_virtio_balloon(vm_config, cfg_args)?;
                }
                "virtio-serial-device" | "virtio-serial-pci" => {
                    self.add_virtio_serial(vm_config, cfg_args)?;
                }
                "virtconsole" => {
                    self.add_virtio_console(vm_config, cfg_args)?;
                }
                "virtio-rng-device" | "virtio-rng-pci" => {
                    self.add_virtio_rng(vm_config, cfg_args)?;
                }
                "vfio-pci" => {
                    self.add_vfio_device(cfg_args)?;
                }
                _ => {
                    bail!("Unsupported device: {:?}", dev.0.as_str());
                }
            }
        }

        Ok(())
    }

    fn add_pflash_device(&mut self, _configs: &[PFlashConfig]) -> Result<()> {
        bail!("Pflash device is not supported!");
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

        for bpf_rule in &mut bpf_rules {
            seccomp_filter.push(bpf_rule);
        }
        seccomp_filter
            .realize()
            .chain_err(|| "Failed to init seccomp filter.")?;
        Ok(())
    }

    /// Register event notifier for power button of mainboard.
    ///
    /// # Arguments
    ///
    /// * `power_button` - Eventfd of the power button.
    fn register_power_event(&self, power_button: &EventFd) -> Result<()> {
        let power_button = power_button.try_clone().unwrap();
        let button_fd = power_button.as_raw_fd();
        let power_button_handler: Arc<Mutex<Box<NotifierCallback>>> =
            Arc::new(Mutex::new(Box::new(move |_, _| {
                let _ret = power_button.read().unwrap();
                None
            })));
        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            button_fd,
            None,
            EventSet::IN,
            vec![power_button_handler],
        );

        EventLoop::update_event(vec![notifier], None).chain_err(|| ErrorKind::RegNotifierErr)?;
        Ok(())
    }

    /// Realize the machine.
    ///
    /// # Arguments
    ///
    /// * `vm` - The machine structure.
    /// * `vm_config` - VM configuration.
    fn realize(vm: &Arc<Mutex<Self>>, vm_config: &mut VmConfig, is_migrate: bool) -> Result<()>
    where
        Self: Sized;

    /// Run `LightMachine` with `paused` flag.
    ///
    /// # Arguments
    ///
    /// * `paused` - Flag for `paused` when `LightMachine` starts to run.
    fn run(&self, paused: bool) -> Result<()>;

    /// Start machine as `Running` or `Paused` state.
    ///
    /// # Arguments
    ///
    /// * `paused` - After started, paused all vcpu or not.
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm kvm vm state.
    fn vm_start(paused: bool, cpus: &[Arc<CPU>], vm_state: &mut KvmVmState) -> Result<()>
    where
        Self: Sized,
    {
        let nr_vcpus = cpus.len();
        let cpus_thread_barrier = Arc::new(Barrier::new((nr_vcpus + 1) as usize));
        for cpu_index in 0..nr_vcpus {
            let cpu_thread_barrier = cpus_thread_barrier.clone();
            let cpu = cpus[cpu_index as usize].clone();
            CPU::start(cpu, cpu_thread_barrier, paused)
                .chain_err(|| format!("Failed to run vcpu{}", cpu_index))?;
        }

        if paused {
            *vm_state = KvmVmState::Paused;
        } else {
            *vm_state = KvmVmState::Running;
        }
        cpus_thread_barrier.wait();

        Ok(())
    }

    /// Pause VM as `Paused` state, sleepy all vcpu thread.
    ///
    /// # Arguments
    ///
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm kvm vm state.
    fn vm_pause(
        cpus: &[Arc<CPU>],
        #[cfg(target_arch = "aarch64")] irq_chip: &Option<Arc<InterruptController>>,
        vm_state: &mut KvmVmState,
    ) -> Result<()>
    where
        Self: Sized,
    {
        for (cpu_index, cpu) in cpus.iter().enumerate() {
            cpu.pause()
                .chain_err(|| format!("Failed to pause vcpu{}", cpu_index))?;
        }

        #[cfg(target_arch = "aarch64")]
        irq_chip.as_ref().unwrap().stop();

        *vm_state = KvmVmState::Paused;

        Ok(())
    }

    /// Resume VM as `Running` state, awaken all vcpu thread.
    ///
    /// # Arguments
    ///
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm kvm vm state.
    fn vm_resume(cpus: &[Arc<CPU>], vm_state: &mut KvmVmState) -> Result<()>
    where
        Self: Sized,
    {
        for (cpu_index, cpu) in cpus.iter().enumerate() {
            cpu.resume()
                .chain_err(|| format!("Failed to resume vcpu{}", cpu_index))?;
        }

        *vm_state = KvmVmState::Running;

        Ok(())
    }

    /// Destroy VM as `Shutdown` state, destroy vcpu thread.
    ///
    /// # Arguments
    ///
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm kvm vm state.
    fn vm_destroy(cpus: &[Arc<CPU>], vm_state: &mut KvmVmState) -> Result<()>
    where
        Self: Sized,
    {
        for (cpu_index, cpu) in cpus.iter().enumerate() {
            cpu.destroy()
                .chain_err(|| format!("Failed to destroy vcpu{}", cpu_index))?;
        }

        *vm_state = KvmVmState::Shutdown;

        Ok(())
    }

    /// Transfer VM state from `old` to `new`.
    ///
    /// # Arguments
    ///
    /// * `cpus` - Cpus vector restore cpu structure.
    /// * `vm_state` - Vm kvm vm state.
    /// * `old_state` - Old vm state want to leave.
    /// * `new_state` - New vm state want to transfer to.
    fn vm_state_transfer(
        cpus: &[Arc<CPU>],
        #[cfg(target_arch = "aarch64")] irq_chip: &Option<Arc<InterruptController>>,
        vm_state: &mut KvmVmState,
        old_state: KvmVmState,
        new_state: KvmVmState,
    ) -> Result<()>
    where
        Self: Sized,
    {
        use KvmVmState::*;

        if *vm_state != old_state {
            bail!("Vm lifecycle error: state check failed.");
        }

        match (old_state, new_state) {
            (Created, Running) => <Self as MachineOps>::vm_start(false, cpus, vm_state)
                .chain_err(|| "Failed to start vm.")?,
            (Running, Paused) => <Self as MachineOps>::vm_pause(
                cpus,
                #[cfg(target_arch = "aarch64")]
                irq_chip,
                vm_state,
            )
            .chain_err(|| "Failed to pause vm.")?,
            (Paused, Running) => <Self as MachineOps>::vm_resume(cpus, vm_state)
                .chain_err(|| "Failed to resume vm.")?,
            (_, Shutdown) => {
                <Self as MachineOps>::vm_destroy(cpus, vm_state)
                    .chain_err(|| "Failed to destroy vm.")?;
            }
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
