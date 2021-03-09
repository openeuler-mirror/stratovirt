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

mod mch;
mod syscall;

use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Barrier, Condvar, Mutex};

use address_space::{AddressSpace, GuestAddress, Region};
use boot_loader::{load_kernel, BootLoaderConfig};
use cpu::{ArchCPU, CPUBootConfig, CPUInterface, CpuTopology, CPU};
use devices::{Serial, SERIAL_ADDR};
use error_chain::ChainedError;
use kvm_bindings::{kvm_pit_config, KVM_PIT_SPEAKER_DUMMY};
use kvm_ioctls::{Kvm, VmFd};
use machine_manager::config::{
    BalloonConfig, BootSource, ConsoleConfig, DriveConfig, NetworkInterfaceConfig, SerialConfig,
    VmConfig, VsockConfig,
};
use machine_manager::event_loop::EventLoop;
use machine_manager::machine::{
    DeviceInterface, KvmVmState, MachineAddressInterface, MachineExternalInterface,
    MachineInterface, MachineLifecycle,
};
use machine_manager::qmp::{qmp_schema, QmpChannel, Response};
use pci::{PciDevOps, PciHost};
use sysbus::SysBus;
use util::loop_context::{EventLoopManager, EventNotifierHelper};
use util::seccomp::BpfRule;
use virtio::{qmp_balloon, qmp_query_balloon};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::terminal::Terminal;

use super::errors::Result;
use super::{StdMachineOps, PCIE_MMCONFIG_REGION_SIZE};
use crate::errors::{ErrorKind as MachineErrorKind, Result as MachineResult};
use crate::MachineOps;
use mch::Mch;
use syscall::syscall_whitelist;

const VENDOR_ID_INTEL: u16 = 0x8086;

#[allow(dead_code)]
#[repr(usize)]
enum LayoutEntryType {
    MemBelow4g = 0_usize,
    Mmio,
    IoApic,
    LocalApic,
    MemAbove4g,
}

/// Memory Layout.
const MEM_LAYOUT: &[(u64, u64)] = &[
    (0, 0xC000_0000),                // MemBelow4g
    (0xF010_0000, 0x200),            // Mmio
    (0xFEC0_0000, 0x10_0000),        // IoApic
    (0xFEE0_0000, 0x10_0000),        // LocalApic
    (0x1_0000_0000, 0x80_0000_0000), // MemAbove4g
];

/// Standard machine structure.
pub struct StdMachine {
    /// `vCPU` topology, support sockets, cores, threads.
    cpu_topo: CpuTopology,
    /// `vCPU` devices.
    cpus: Arc<Mutex<Vec<Arc<CPU>>>>,
    /// IO address space.
    sys_io: Arc<AddressSpace>,
    /// Memory address space.
    sys_mem: Arc<AddressSpace>,
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
}

impl StdMachine {
    #[allow(dead_code)]
    pub fn new(vm_config: &VmConfig) -> Result<Self> {
        use super::errors::ResultExt;

        let cpu_topo = CpuTopology::new(vm_config.machine_config.nr_cpus);
        let sys_io = AddressSpace::new(Region::init_container_region(1 << 16))?;
        let sys_mem = AddressSpace::new(Region::init_container_region(u64::max_value()))?;
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
            cpus: Arc::new(Mutex::new(Vec::new())),
            sys_io: sys_io.clone(),
            sys_mem: sys_mem.clone(),
            sysbus,
            pci_host: Arc::new(Mutex::new(PciHost::new(&sys_io, &sys_mem))),
            boot_source: Arc::new(Mutex::new(vm_config.clone().boot_source)),
            vm_state,
            power_button: EventFd::new(libc::EFD_NONBLOCK)
                .chain_err(|| "Create EventFd for power-button failed.")?,
        })
    }

    /// Start VM, changed `StdMachine`'s `vmstate` to `Paused` or
    /// `Running`.
    ///
    /// # Arguments
    ///
    /// * `paused` - After started, paused all vcpu or not.
    pub fn vm_start(&self, paused: bool) -> Result<()> {
        use super::errors::ResultExt;

        let cpus_thread_barrier = Arc::new(Barrier::new((self.cpu_topo.max_cpus + 1) as usize));
        for cpu_index in 0..self.cpu_topo.max_cpus {
            let cpu_thread_barrier = cpus_thread_barrier.clone();
            let cpu = self.cpus.lock().unwrap()[cpu_index as usize].clone();
            CPU::start(cpu, cpu_thread_barrier, paused)
                .chain_err(|| format!("Failed to start vcpu{}", cpu_index))?;
        }

        let mut vmstate = self.vm_state.deref().0.lock().unwrap();
        if paused {
            *vmstate = KvmVmState::Paused;
        } else {
            *vmstate = KvmVmState::Running;
        }
        cpus_thread_barrier.wait();

        Ok(())
    }

    /// Pause VM, sleepy all vcpu thread. Changed `StdMachine`'s `vmstate`
    /// from `Running` to `Paused`.
    fn vm_pause(&self) -> Result<()> {
        use super::errors::ResultExt;

        for cpu_index in 0..self.cpu_topo.max_cpus {
            self.cpus.lock().unwrap()[cpu_index as usize]
                .pause()
                .chain_err(|| format!("Failed to pause vcpu{}", cpu_index))?;
        }

        #[cfg(target_arch = "aarch64")]
        self.irq_chip.as_ref().unwrap().stop();

        let mut vmstate = self.vm_state.deref().0.lock().unwrap();
        *vmstate = KvmVmState::Paused;

        Ok(())
    }

    /// Resume VM, awaken all vcpu thread. Changed `StdMachine`'s `vmstate`
    /// from `Paused` to `Running`.
    fn vm_resume(&self) -> Result<()> {
        use super::errors::ResultExt;

        for cpu_index in 0..self.cpu_topo.max_cpus {
            self.cpus.lock().unwrap()[cpu_index as usize]
                .resume()
                .chain_err(|| format!("Failed to resume vcpu{}", cpu_index))?;
        }

        let mut vmstate = self.vm_state.deref().0.lock().unwrap();
        *vmstate = KvmVmState::Running;

        Ok(())
    }

    /// Destroy VM, kill all vcpu thread. Changed `StdMachine`'s `vmstate`
    /// to `KVM_VMSTATE_DESTROY`.
    fn vm_destroy(&self) -> Result<()> {
        use super::errors::ResultExt;

        let mut vmstate = self.vm_state.deref().0.lock().unwrap();
        *vmstate = KvmVmState::Shutdown;

        let mut cpus = self.cpus.lock().unwrap();
        for cpu_index in 0..self.cpu_topo.max_cpus {
            cpus[cpu_index as usize]
                .destroy()
                .chain_err(|| format!("Failed to destroy vcpu{}", cpu_index))?;
        }
        cpus.clear();

        Ok(())
    }
}

impl StdMachineOps for StdMachine {
    fn init_pci_host(&self, vm_fd: &Arc<VmFd>) -> Result<()> {
        let root_bus = Arc::downgrade(&self.pci_host.lock().unwrap().root_bus);
        let mmconfig_region_ops = PciHost::build_mmconfig_ops(self.pci_host.clone());
        let mmconfig_region = Region::init_io_region(
            PCIE_MMCONFIG_REGION_SIZE as u64,
            mmconfig_region_ops.clone(),
        );
        let mch = Mch::new(
            vm_fd.clone(),
            root_bus,
            mmconfig_region,
            mmconfig_region_ops,
        );
        PciDevOps::realize(mch, &vm_fd)?;
        Ok(())
    }
}

impl MachineOps for StdMachine {
    fn arch_ram_ranges(&self, mem_size: u64) -> Vec<(u64, u64)> {
        // ranges is the vector of (start_addr, size)
        let mut ranges = Vec::<(u64, u64)>::new();
        let gap_start = MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].0
            + MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].1;
        ranges.push((0, std::cmp::min(gap_start, mem_size)));
        if mem_size > gap_start {
            let gap_end = MEM_LAYOUT[LayoutEntryType::MemAbove4g as usize].0;
            ranges.push((gap_end, mem_size - gap_start));
        }

        ranges
    }

    fn add_serial_device(&mut self, config: &SerialConfig, vm_fd: &Arc<VmFd>) -> MachineResult<()> {
        let err = Err(MachineErrorKind::AddDevErr("serial".to_string()).into());
        let region_base: u64 = SERIAL_ADDR;
        let region_size: u64 = 8;

        let serial = match Serial::realize(
            Serial::default(),
            &mut self.sysbus,
            region_base,
            region_size,
            vm_fd,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to realize serial: {}", e.display_chain());
                return err;
            }
        };
        if config.stdio {
            match EventLoop::update_event(EventNotifierHelper::internal_notifiers(serial), None) {
                Ok(_) => (),
                Err(e) => {
                    error!("Failed to register event notifer in the main thread: {}", e);
                    return err;
                }
            }
        }

        Ok(())
    }

    fn add_block_device(&mut self, _config: &DriveConfig) -> MachineResult<()> {
        Ok(())
    }

    fn add_vsock_device(&mut self, _config: &VsockConfig, _vm_fd: &Arc<VmFd>) -> MachineResult<()> {
        Ok(())
    }

    fn add_net_device(
        &mut self,
        _config: &NetworkInterfaceConfig,
        _vm_fd: &Arc<VmFd>,
    ) -> MachineResult<()> {
        Ok(())
    }

    fn add_console_device(
        &mut self,
        _config: &ConsoleConfig,
        _vm_fd: &Arc<VmFd>,
    ) -> MachineResult<()> {
        Ok(())
    }

    fn add_balloon_device(
        &mut self,
        _config: &BalloonConfig,
        _vm_fd: &Arc<VmFd>,
    ) -> MachineResult<()> {
        Ok(())
    }

    fn add_devices(&mut self, vm_config: &VmConfig, vm_fd: &Arc<VmFd>) -> MachineResult<()> {
        if let Some(serial) = vm_config.serial.as_ref() {
            self.add_serial_device(&serial, vm_fd)?;
        }

        if let Some(vsock) = vm_config.vsock.as_ref() {
            self.add_vsock_device(&vsock, vm_fd)?;
        }

        if let Some(drives) = vm_config.drives.as_ref() {
            for drive in drives {
                self.add_block_device(&drive)?;
            }
        }

        if let Some(nets) = vm_config.nets.as_ref() {
            for net in nets {
                self.add_net_device(&net, vm_fd)?;
            }
        }

        if let Some(consoles) = vm_config.consoles.as_ref() {
            for console in consoles {
                self.add_console_device(&console, vm_fd)?;
            }
        }

        if let Some(balloon) = vm_config.balloon.as_ref() {
            self.add_balloon_device(balloon, vm_fd)?;
        }

        Ok(())
    }

    fn syscall_whitelist(&self) -> Vec<BpfRule> {
        syscall_whitelist()
    }

    fn realize(mut self, vm_config: &VmConfig, fds: (Kvm, &Arc<VmFd>)) -> MachineResult<Arc<Self>> {
        use crate::errors::ResultExt;

        let vm_fd = fds.1;
        self.init_memory(
            fds,
            &vm_config.machine_config.mem_config,
            #[cfg(target_arch = "x86_64")]
            &self.sys_io,
            &self.sys_mem,
        )?;

        vm_fd.create_irq_chip()?;
        let nr_cpus = vm_config.machine_config.nr_cpus;
        let mut vcpu_fds = vec![];
        for cpu_id in 0..nr_cpus {
            vcpu_fds.push(Arc::new(vm_fd.create_vcpu(cpu_id)?));
        }

        self.init_pci_host(&vm_fd)
            .chain_err(|| "Failed to init PCIe host.")?;
        self.add_devices(vm_config, &vm_fd)
            .chain_err(|| "Failed to add peripheral devcies.")?;

        let vm = Arc::new(self);
        for vcpu_id in 0..nr_cpus {
            let arch_cpu = ArchCPU::new(u32::from(vcpu_id), u32::from(nr_cpus));
            let cpu = CPU::new(
                vcpu_fds[vcpu_id as usize].clone(),
                vcpu_id,
                Arc::new(Mutex::new(arch_cpu)),
                vm.clone(),
            );
            let mut vcpus = vm.cpus.lock().unwrap();
            let newcpu = Arc::new(cpu);
            vcpus.push(newcpu.clone());
        }

        let boot_source = vm.boot_source.lock().unwrap();
        let boot_config: CPUBootConfig;
        let (initrd, initrd_size) = match &boot_source.initrd {
            Some(rd) => (Some(rd.initrd_file.clone()), rd.initrd_size),
            None => (None, 0),
        };
        let gap_start = MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].0
            + MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].1;
        let gap_end = MEM_LAYOUT[LayoutEntryType::MemAbove4g as usize].0;
        let bootloader_config = BootLoaderConfig {
            kernel: boot_source.kernel_file.clone(),
            initrd,
            initrd_size: initrd_size as u32,
            kernel_cmdline: boot_source.kernel_cmdline.to_string(),
            cpu_count: vm.cpu_topo.nrcpus,
            gap_range: (gap_start, gap_end - gap_start),
            ioapic_addr: MEM_LAYOUT[LayoutEntryType::IoApic as usize].0 as u32,
            lapic_addr: MEM_LAYOUT[LayoutEntryType::LocalApic as usize].0 as u32,
        };

        let layout = match load_kernel(&bootloader_config, &vm.sys_mem) {
            Ok(l) => l,
            Err(e) => {
                error!("{}", e.display_chain());
                return Err(MachineErrorKind::LoadKernErr.into());
            }
        };
        boot_config = CPUBootConfig {
            boot_ip: layout.kernel_start,
            boot_sp: layout.kernel_sp,
            zero_page: layout.zero_page_addr,
            code_segment: layout.segments.code_segment,
            data_segment: layout.segments.data_segment,
            gdt_base: layout.segments.gdt_base,
            gdt_size: layout.segments.gdt_limit,
            idt_base: layout.segments.idt_base,
            idt_size: layout.segments.idt_limit,
            pml4_start: layout.boot_pml4_addr,
        };
        for cpu_index in 0..vm.cpu_topo.max_cpus {
            match vm.cpus.lock().unwrap()[cpu_index as usize].realize(vm_fd, &boot_config) {
                Ok(_) => (),
                Err(e) => {
                    error!("{}", e.display_chain());
                    bail!("Failed to realize vcpu{}.", cpu_index);
                }
            }
        }

        // Needed to release lock here because generate_fdt_node() will
        // acquire it later, and the ownership of vm will be passed out
        // of the function.
        drop(boot_source);

        let mut pit_config = kvm_pit_config::default();
        pit_config.flags = KVM_PIT_SPEAKER_DUMMY;
        vm_fd.create_pit2(pit_config)?;
        vm_fd.set_tss_address(0xfffb_d000 as usize)?;
        vm.register_power_event(&vm.power_button)?;
        Ok(vm)
    }
}

impl MachineLifecycle for StdMachine {
    fn pause(&self) -> bool {
        if self.notify_lifecycle(KvmVmState::Running, KvmVmState::Paused) {
            event!(STOP);
            true
        } else {
            false
        }
    }

    fn resume(&self) -> bool {
        if !self.notify_lifecycle(KvmVmState::Paused, KvmVmState::Running) {
            return false;
        }

        event!(RESUME);
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
        true
    }

    fn notify_lifecycle(&self, old: KvmVmState, new: KvmVmState) -> bool {
        use KvmVmState::*;

        let vmstate = self.vm_state.deref().0.lock().unwrap();
        if *vmstate != old {
            error!("Vm lifecycle error: state check failed.");
            return false;
        }
        drop(vmstate);

        match (old, new) {
            (Created, Running) => {
                if let Err(e) = self.vm_start(false) {
                    error!("Vm lifecycle error:{}", e);
                };
            }
            (Running, Paused) => {
                if let Err(e) = self.vm_pause() {
                    error!("Vm lifecycle error:{}", e);
                };
            }
            (Paused, Running) => {
                if let Err(e) = self.vm_resume() {
                    error!("Vm lifecycle error:{}", e);
                };
            }
            (_, Shutdown) => {
                if let Err(e) = self.vm_destroy() {
                    error!("Vm lifecycle error:{}", e);
                };
                self.power_button.write(1).unwrap();
            }
            (_, _) => {
                error!("Vm lifecycle error: this transform is illegal.");
                return false;
            }
        }

        let vmstate = self.vm_state.deref().0.lock().unwrap();
        if *vmstate != new {
            error!("Vm lifecycle error: state transform failed.");
            return false;
        }
        true
    }
}

impl MachineAddressInterface for StdMachine {
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

impl DeviceInterface for StdMachine {
    fn query_status(&self) -> Response {
        let vmstate = self.vm_state.deref().0.lock().unwrap();
        let qmp_state = match *vmstate {
            KvmVmState::Running => qmp_schema::StatusInfo {
                singlestep: false,
                running: true,
                status: qmp_schema::RunState::running,
            },
            KvmVmState::Paused => qmp_schema::StatusInfo {
                singlestep: false,
                running: true,
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
                let thread_id = self.cpus.lock().unwrap()[cpu_index as usize].tid();
                let (socketid, coreid, threadid) = self.cpu_topo.get_topo(cpu_index as usize);
                let cpu_instance = qmp_schema::CpuInstanceProperties {
                    node_id: None,
                    socket_id: Some(socketid as isize),
                    core_id: Some(coreid as isize),
                    thread_id: Some(threadid as isize),
                };
                #[cfg(target_arch = "x86_64")]
                {
                    let cpu_info = qmp_schema::CpuInfo::x86 {
                        current: true,
                        qom_path: String::from("/machine/unattached/device[")
                            + &cpu_index.to_string()
                            + &"]".to_string(),
                        halted: false,
                        props: Some(cpu_instance),
                        CPU: cpu_index as isize,
                        thread_id: thread_id as isize,
                        x86: qmp_schema::CpuInfoX86 {},
                    };
                    cpu_vec.push(serde_json::to_value(cpu_info).unwrap());
                }
                #[cfg(target_arch = "aarch64")]
                {
                    let cpu_info = qmp_schema::CpuInfo::Arm {
                        current: true,
                        qom_path: String::from("/machine/unattached/device[")
                            + &cpu_index.to_string()
                            + &"]".to_string(),
                        halted: false,
                        props: Some(cpu_instance),
                        CPU: cpu_index as isize,
                        thread_id: thread_id as isize,
                        arm: qmp_schema::CpuInfoArm {},
                    };
                    cpu_vec.push(serde_json::to_value(cpu_info).unwrap());
                }
            }
        }
        Response::create_response(cpu_vec.into(), None)
    }

    fn query_hotpluggable_cpus(&self) -> Response {
        Response::create_empty_response()
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

    fn device_add(
        &self,
        _id: String,
        _driver: String,
        _addr: Option<String>,
        _lun: Option<usize>,
    ) -> Response {
        Response::create_empty_response()
    }

    fn device_del(&self, _device_id: String) -> Response {
        Response::create_empty_response()
    }

    fn blockdev_add(
        &self,
        _node_name: String,
        _file: qmp_schema::FileOptions,
        _cache: Option<qmp_schema::CacheOptions>,
        _read_only: Option<bool>,
    ) -> Response {
        Response::create_empty_response()
    }

    fn netdev_add(&self, _id: String, _if_name: Option<String>, _fds: Option<String>) -> Response {
        Response::create_empty_response()
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
}

impl MachineInterface for StdMachine {}
impl MachineExternalInterface for StdMachine {}

impl EventLoopManager for StdMachine {
    fn loop_should_exit(&self) -> bool {
        let vmstate = self.vm_state.deref().0.lock().unwrap();
        *vmstate == KvmVmState::Shutdown
    }

    fn loop_cleanup(&self) -> util::errors::Result<()> {
        if let Err(e) = std::io::stdin().lock().set_canon_mode() {
            error!(
                "destroy virtual machine: reset stdin to canonical mode failed, {}",
                e
            );
        }

        Ok(())
    }
}
