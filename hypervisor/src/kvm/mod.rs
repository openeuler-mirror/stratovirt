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

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

mod interrupt;
mod listener;

#[cfg(target_arch = "x86_64")]
pub mod vm_state;

#[cfg(target_arch = "aarch64")]
pub use aarch64::gicv2::KvmGICv2;
#[cfg(target_arch = "aarch64")]
pub use aarch64::gicv3::{KvmGICv3, KvmGICv3Its};

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use kvm_bindings::kvm_userspace_memory_region as KvmMemSlot;
use kvm_bindings::*;
#[cfg(not(test))]
use kvm_ioctls::VcpuExit;
use kvm_ioctls::{Cap, DeviceFd, Kvm, VcpuFd, VmFd};
use libc::{c_int, c_void, siginfo_t};
use log::{error, info, warn};
use vmm_sys_util::{
    eventfd::EventFd,
    ioctl_io_nr, ioctl_ioc_nr, ioctl_ior_nr, ioctl_iow_nr, ioctl_iowr_nr,
    signal::{register_signal_handler, Killable},
};

use self::listener::KvmMemoryListener;
use super::HypervisorOps;
#[cfg(target_arch = "x86_64")]
use crate::HypervisorError;
#[cfg(target_arch = "aarch64")]
use aarch64::cpu_caps::ArmCPUCaps as CPUCaps;
use address_space::{AddressSpace, Listener};
#[cfg(feature = "boot_time")]
use cpu::capture_boot_signal;
#[cfg(target_arch = "aarch64")]
use cpu::CPUFeatures;
use cpu::{
    ArchCPU, CPUBootConfig, CPUHypervisorOps, CPUInterface, CPUThreadWorker, CpuError,
    CpuLifecycleState, RegsIndex, CPU, VCPU_TASK_SIGNAL,
};
use devices::{pci::MsiVector, IrqManager, LineIrqManager, MsiIrqManager, TriggerMode};
#[cfg(target_arch = "aarch64")]
use devices::{
    GICVersion, GICv2, GICv3, GICv3ItsState, GICv3State, ICGICConfig, InterruptController,
    GIC_IRQ_INTERNAL,
};
use interrupt::IrqRouteTable;
use machine_manager::machine::HypervisorType;
#[cfg(target_arch = "aarch64")]
use migration::snapshot::{GICV3_ITS_SNAPSHOT_ID, GICV3_SNAPSHOT_ID};
use migration::{MigrateMemSlot, MigrateOps, MigrationManager};
use util::test_helper::is_test_enabled;
#[cfg(target_arch = "x86_64")]
use x86_64::cpu_caps::X86CPUCaps as CPUCaps;

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/asm-generic/kvm.h
pub const KVM_SET_DEVICE_ATTR: u32 = 0x4018_aee1;
pub const KVM_SET_USER_MEMORY_REGION: u32 = 0x4020_ae46;
pub const KVM_IOEVENTFD: u32 = 0x4040_ae79;
pub const KVM_SIGNAL_MSI: u32 = 0x4020_aea5;

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/kvm.h
ioctl_iow_nr!(KVM_GET_DIRTY_LOG, KVMIO, 0x42, kvm_dirty_log);
ioctl_iowr_nr!(KVM_CREATE_DEVICE, KVMIO, 0xe0, kvm_create_device);
ioctl_io_nr!(KVM_GET_API_VERSION, KVMIO, 0x00);
ioctl_ior_nr!(KVM_GET_MP_STATE, KVMIO, 0x98, kvm_mp_state);
ioctl_ior_nr!(KVM_GET_VCPU_EVENTS, KVMIO, 0x9f, kvm_vcpu_events);
ioctl_ior_nr!(KVM_GET_CLOCK, KVMIO, 0x7c, kvm_clock_data);
ioctl_ior_nr!(KVM_GET_REGS, KVMIO, 0x81, kvm_regs);
ioctl_ior_nr!(KVM_GET_SREGS, KVMIO, 0x83, kvm_sregs);
ioctl_ior_nr!(KVM_GET_FPU, KVMIO, 0x8c, kvm_fpu);
ioctl_iow_nr!(KVM_SET_GSI_ROUTING, KVMIO, 0x6a, kvm_irq_routing);
ioctl_iow_nr!(KVM_IRQFD, KVMIO, 0x76, kvm_irqfd);
ioctl_iowr_nr!(KVM_GET_IRQCHIP, KVMIO, 0x62, kvm_irqchip);
ioctl_iow_nr!(KVM_IRQ_LINE, KVMIO, 0x61, kvm_irq_level);
ioctl_iow_nr!(KVM_SET_MP_STATE, KVMIO, 0x99, kvm_mp_state);
ioctl_iow_nr!(KVM_SET_VCPU_EVENTS, KVMIO, 0xa0, kvm_vcpu_events);

#[allow(clippy::upper_case_acronyms)]
#[derive(Default)]
pub struct KvmHypervisor {
    pub fd: Option<Kvm>,
    pub vm_fd: Option<Arc<VmFd>>,
    pub mem_slots: Arc<Mutex<HashMap<u32, KvmMemSlot>>>,
    #[cfg(target_arch = "aarch64")]
    pub irq_chip: Option<Arc<InterruptController>>,
}

impl KvmHypervisor {
    pub fn new() -> Result<Self> {
        match Kvm::new() {
            Ok(kvm_fd) => {
                let vm_fd: Option<Arc<VmFd>> = Some(Arc::new(match kvm_fd.create_vm() {
                    Ok(fd) => fd,
                    Err(e) => {
                        bail!("Failed to create VM in KVM: {:?}", e);
                    }
                }));

                Ok(KvmHypervisor {
                    fd: Some(kvm_fd),
                    vm_fd,
                    mem_slots: Arc::new(Mutex::new(HashMap::new())),
                    #[cfg(target_arch = "aarch64")]
                    irq_chip: None,
                })
            }
            Err(e) => {
                bail!("Failed to open /dev/kvm: {:?}", e)
            }
        }
    }

    fn create_memory_listener(&self) -> Arc<Mutex<dyn Listener>> {
        Arc::new(Mutex::new(KvmMemoryListener::new(
            self.fd.as_ref().unwrap().get_nr_memslots() as u32,
            self.vm_fd.clone(),
            self.mem_slots.clone(),
        )))
    }
}

impl HypervisorOps for KvmHypervisor {
    fn init_machine(
        &self,
        #[cfg(target_arch = "x86_64")] sys_io: &Arc<AddressSpace>,
        sys_mem: &Arc<AddressSpace>,
    ) -> Result<()> {
        self.arch_init()?;

        if !is_test_enabled() {
            sys_mem.set_ioevtfd_enabled(true);
        }

        sys_mem
            .register_listener(self.create_memory_listener())
            .with_context(|| "Failed to register hypervisor listener for memory space.")?;
        #[cfg(target_arch = "x86_64")]
        sys_io
            .register_listener(self.create_io_listener())
            .with_context(|| "Failed to register hypervisor listener for I/O address space.")?;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn create_interrupt_controller(
        &mut self,
        gic_conf: &ICGICConfig,
    ) -> Result<Arc<InterruptController>> {
        gic_conf.check_sanity()?;

        let create_gicv3 = || {
            let hypervisor_gic = KvmGICv3::new(self.vm_fd.clone().unwrap(), gic_conf.vcpu_count)?;
            let its_handler = KvmGICv3Its::new(self.vm_fd.clone().unwrap())?;
            let gicv3 = Arc::new(GICv3::new(
                Arc::new(hypervisor_gic),
                Arc::new(its_handler),
                gic_conf,
            )?);
            if let Some(its_dev) = gicv3.its_dev.clone() {
                MigrationManager::register_gic_instance(
                    GICv3ItsState::descriptor(),
                    its_dev,
                    GICV3_ITS_SNAPSHOT_ID,
                );
            }

            MigrationManager::register_gic_instance(
                GICv3State::descriptor(),
                gicv3.clone(),
                GICV3_SNAPSHOT_ID,
            );

            Ok(Arc::new(InterruptController::new(gicv3)))
        };

        let create_gicv2 = || {
            let hypervisor_gic = KvmGICv2::new(self.vm_fd.clone().unwrap())?;
            let gicv2 = Arc::new(GICv2::new(Arc::new(hypervisor_gic), gic_conf)?);
            Ok(Arc::new(InterruptController::new(gicv2)))
        };

        match &gic_conf.version {
            Some(GICVersion::GICv3) => create_gicv3(),
            Some(GICVersion::GICv2) => create_gicv2(),
            // Try v3 by default if no version specified.
            None => create_gicv3().or_else(|_| create_gicv2()),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn create_interrupt_controller(&mut self) -> Result<()> {
        self.vm_fd
            .as_ref()
            .unwrap()
            .create_irq_chip()
            .with_context(|| HypervisorError::CrtIrqchipErr)?;

        Ok(())
    }

    fn create_hypervisor_cpu(
        &self,
        vcpu_id: u8,
    ) -> Result<Arc<dyn CPUHypervisorOps + Send + Sync>> {
        let vcpu_fd = self
            .vm_fd
            .as_ref()
            .unwrap()
            .create_vcpu(vcpu_id as u64)
            .with_context(|| "Create vcpu failed")?;
        Ok(Arc::new(KvmCpu::new(
            vcpu_id,
            #[cfg(target_arch = "aarch64")]
            self.vm_fd.clone(),
            vcpu_fd,
        )))
    }

    fn create_irq_manager(&mut self) -> Result<IrqManager> {
        let kvm = Kvm::new().unwrap();
        let irqfd_enable = kvm.check_extension(Cap::Irqfd);
        let irq_route_table = Mutex::new(IrqRouteTable::new(self.fd.as_ref().unwrap()));
        let irq_manager = Arc::new(KVMInterruptManager::new(
            irqfd_enable,
            self.vm_fd.clone().unwrap(),
            irq_route_table,
        ));
        let mut locked_irq_route_table = irq_manager.irq_route_table.lock().unwrap();
        locked_irq_route_table.init_irq_route_table();
        locked_irq_route_table.commit_irq_routing(self.vm_fd.as_ref().unwrap())?;
        drop(locked_irq_route_table);

        Ok(IrqManager {
            line_irq_manager: Some(irq_manager.clone()),
            msi_irq_manager: Some(irq_manager),
        })
    }

    fn create_vfio_device(&self) -> Option<DeviceFd> {
        let mut device = kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_VFIO,
            fd: 0,
            flags: 0,
        };
        let vfio_device_fd = match self.vm_fd.as_ref().unwrap().create_device(&mut device) {
            Ok(fd) => Some(fd),
            Err(_) => {
                error!("Failed to create VFIO device.");
                None
            }
        };

        vfio_device_fd
    }
}

impl MigrateOps for KvmHypervisor {
    /// Get ram memory region from `KvmHypervisor` structure.
    fn get_mem_slots(&self) -> Arc<Mutex<HashMap<u32, MigrateMemSlot>>> {
        let mut mgt_mem_slots = HashMap::new();
        for (_, slot) in self.mem_slots.lock().unwrap().iter() {
            let mem_slot = MigrateMemSlot {
                slot: slot.slot,
                guest_phys_addr: slot.guest_phys_addr,
                userspace_addr: slot.userspace_addr,
                memory_size: slot.memory_size,
            };
            mgt_mem_slots.insert(slot.slot, mem_slot);
        }
        Arc::new(Mutex::new(mgt_mem_slots))
    }

    fn get_dirty_log(&self, slot: u32, mem_size: u64) -> Result<Vec<u64>> {
        self.vm_fd
            .as_ref()
            .unwrap()
            .get_dirty_log(slot, mem_size as usize)
            .with_context(|| {
                format!(
                    "Failed to get dirty log, error is {}",
                    std::io::Error::last_os_error()
                )
            })
    }

    /// Start dirty page tracking in kvm.
    fn start_dirty_log(&self) -> Result<()> {
        for (_, region) in self.mem_slots.lock().unwrap().iter_mut() {
            region.flags = KVM_MEM_LOG_DIRTY_PAGES;
            // SAFETY: region from `KvmHypervisor` is reliable.
            unsafe {
                self.vm_fd
                    .as_ref()
                    .unwrap()
                    .set_user_memory_region(*region)
                    .with_context(|| {
                        format!(
                            "Failed to start dirty log, error is {}",
                            std::io::Error::last_os_error()
                        )
                    })?;
            }
        }

        Ok(())
    }

    /// Stop dirty page tracking in kvm.
    fn stop_dirty_log(&self) -> Result<()> {
        for (_, region) in self.mem_slots.lock().unwrap().iter_mut() {
            region.flags = 0;
            // SAFETY: region from `KvmHypervisor` is reliable.
            unsafe {
                self.vm_fd
                    .as_ref()
                    .unwrap()
                    .set_user_memory_region(*region)
                    .with_context(|| {
                        format!(
                            "Failed to stop dirty log, error is {}",
                            std::io::Error::last_os_error()
                        )
                    })?;
            }
        }

        Ok(())
    }

    fn register_instance(&self) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        MigrationManager::register_kvm_instance(
            vm_state::KvmDeviceState::descriptor(),
            Arc::new(vm_state::KvmDevice::new(self.vm_fd.clone().unwrap())),
        );

        Ok(())
    }
}

pub struct KvmCpu {
    id: u8,
    #[cfg(target_arch = "aarch64")]
    vm_fd: Option<Arc<VmFd>>,
    fd: Arc<VcpuFd>,
    /// The capability of VCPU.
    caps: CPUCaps,
    #[cfg(target_arch = "aarch64")]
    /// Used to pass vcpu target and supported features to kvm.
    pub kvi: Mutex<kvm_vcpu_init>,
}

impl KvmCpu {
    pub fn new(
        id: u8,
        #[cfg(target_arch = "aarch64")] vm_fd: Option<Arc<VmFd>>,
        vcpu_fd: VcpuFd,
    ) -> Self {
        Self {
            id,
            #[cfg(target_arch = "aarch64")]
            vm_fd,
            fd: Arc::new(vcpu_fd),
            caps: CPUCaps::init_capabilities(),
            #[cfg(target_arch = "aarch64")]
            kvi: Mutex::new(kvm_vcpu_init::default()),
        }
    }

    /// Init signal for `CPU` event.
    fn init_signals(&self) -> Result<()> {
        extern "C" fn handle_signal(signum: c_int, _: *mut siginfo_t, _: *mut c_void) {
            if signum == VCPU_TASK_SIGNAL {
                let _ = CPUThreadWorker::run_on_local_thread_vcpu(|vcpu| {
                    vcpu.hypervisor_cpu().set_hypervisor_exit().unwrap()
                });
            }
        }

        register_signal_handler(VCPU_TASK_SIGNAL, handle_signal)
            .with_context(|| "Failed to register VCPU_TASK_SIGNAL signal.")?;

        Ok(())
    }

    #[cfg(not(test))]
    fn kvm_vcpu_exec(&self, cpu: Arc<CPU>) -> Result<bool> {
        let vm = cpu
            .vm()
            .upgrade()
            .with_context(|| CpuError::NoMachineInterface)?;

        match self.fd.run() {
            Ok(run) => match run {
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoIn(addr, data) => {
                    vm.lock().unwrap().pio_in(u64::from(addr), data);
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoOut(addr, data) => {
                    #[cfg(feature = "boot_time")]
                    capture_boot_signal(addr as u64, data);

                    vm.lock().unwrap().pio_out(u64::from(addr), data);
                }
                VcpuExit::MmioRead(addr, data) => {
                    vm.lock().unwrap().mmio_read(addr, data);
                }
                VcpuExit::MmioWrite(addr, data) => {
                    #[cfg(all(target_arch = "aarch64", feature = "boot_time"))]
                    capture_boot_signal(addr, data);

                    vm.lock().unwrap().mmio_write(addr, data);
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::Hlt => {
                    info!("Vcpu{} received KVM_EXIT_HLT signal", cpu.id);
                    return Err(anyhow!(CpuError::VcpuHltEvent(cpu.id)));
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::Shutdown => {
                    info!("Vcpu{} received an KVM_EXIT_SHUTDOWN signal", cpu.id);
                    cpu.guest_shutdown()?;

                    return Ok(false);
                }
                #[cfg(target_arch = "aarch64")]
                VcpuExit::SystemEvent(event, flags) => {
                    if event == kvm_bindings::KVM_SYSTEM_EVENT_SHUTDOWN {
                        info!(
                            "Vcpu{} received an KVM_SYSTEM_EVENT_SHUTDOWN signal",
                            cpu.id()
                        );
                        cpu.guest_shutdown()
                            .with_context(|| "Some error occurred in guest shutdown")?;
                        return Ok(true);
                    } else if event == kvm_bindings::KVM_SYSTEM_EVENT_RESET {
                        info!("Vcpu{} received an KVM_SYSTEM_EVENT_RESET signal", cpu.id());
                        cpu.guest_reset()
                            .with_context(|| "Some error occurred in guest reset")?;
                        return Ok(true);
                    } else {
                        error!(
                            "Vcpu{} received unexpected system event with type 0x{:x}, flags 0x{:x}",
                            cpu.id(),
                            event,
                            flags
                        );
                    }
                    return Ok(false);
                }
                VcpuExit::FailEntry(reason, cpuid) => {
                    info!(
                        "Vcpu{} received KVM_EXIT_FAIL_ENTRY signal. the vcpu could not be run due to unknown reasons({})",
                        cpuid, reason
                    );
                    return Ok(false);
                }
                VcpuExit::InternalError => {
                    info!("Vcpu{} received KVM_EXIT_INTERNAL_ERROR signal", cpu.id());
                    return Ok(false);
                }
                r => {
                    return Err(anyhow!(CpuError::VcpuExitReason(
                        cpu.id(),
                        format!("{:?}", r)
                    )));
                }
            },
            Err(ref e) => {
                match e.errno() {
                    libc::EAGAIN => {}
                    libc::EINTR => {
                        self.fd.set_kvm_immediate_exit(0);
                    }
                    _ => {
                        return Err(anyhow!(CpuError::UnhandledHypervisorExit(
                            cpu.id(),
                            e.errno()
                        )));
                    }
                };
            }
        }
        Ok(true)
    }

    fn kick_vcpu_thread(&self, task: Arc<Mutex<Option<thread::JoinHandle<()>>>>) -> Result<()> {
        let task = task.lock().unwrap();
        match task.as_ref() {
            Some(thread) => thread
                .kill(VCPU_TASK_SIGNAL)
                .with_context(|| CpuError::KickVcpu("Fail to kick vcpu".to_string())),
            None => {
                warn!("VCPU thread not started, no need to kick");
                Ok(())
            }
        }
    }
}

impl CPUHypervisorOps for KvmCpu {
    fn get_hypervisor_type(&self) -> HypervisorType {
        HypervisorType::Kvm
    }

    fn init_pmu(&self) -> Result<()> {
        self.arch_init_pmu()
    }

    fn vcpu_init(&self) -> Result<()> {
        self.arch_vcpu_init()
    }

    fn set_boot_config(
        &self,
        arch_cpu: Arc<Mutex<ArchCPU>>,
        boot_config: &CPUBootConfig,
        #[cfg(target_arch = "aarch64")] vcpu_config: &CPUFeatures,
    ) -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        return self.arch_set_boot_config(arch_cpu, boot_config, vcpu_config);
        #[cfg(target_arch = "x86_64")]
        return self.arch_set_boot_config(arch_cpu, boot_config);
    }

    fn get_one_reg(&self, reg_id: u64) -> Result<u128> {
        self.arch_get_one_reg(reg_id)
    }

    fn get_regs(&self, arch_cpu: Arc<Mutex<ArchCPU>>, regs_index: RegsIndex) -> Result<()> {
        self.arch_get_regs(arch_cpu, regs_index)
    }

    fn set_regs(&self, arch_cpu: Arc<Mutex<ArchCPU>>, regs_index: RegsIndex) -> Result<()> {
        self.arch_set_regs(arch_cpu, regs_index)
    }

    fn put_register(&self, cpu: Arc<CPU>) -> Result<()> {
        self.arch_put_register(cpu)?;

        Ok(())
    }

    fn reset_vcpu(&self, cpu: Arc<CPU>) -> Result<()> {
        self.arch_reset_vcpu(cpu)?;

        Ok(())
    }

    fn vcpu_exec(
        &self,
        cpu_thread_worker: CPUThreadWorker,
        thread_barrier: Arc<Barrier>,
    ) -> Result<()> {
        cpu_thread_worker.init_local_thread_vcpu();
        if let Err(e) = self.init_signals() {
            error!(
                "Failed to init cpu{} signal:{:?}",
                cpu_thread_worker.thread_cpu.id, e
            );
        }

        cpu_thread_worker.thread_cpu.set_tid(None);

        #[cfg(not(test))]
        self.put_register(cpu_thread_worker.thread_cpu.clone())?;

        // Wait for all vcpu to complete the running
        // environment initialization.
        thread_barrier.wait();

        info!("vcpu{} start running", cpu_thread_worker.thread_cpu.id);
        while let Ok(true) = cpu_thread_worker.ready_for_running() {
            #[cfg(not(test))]
            {
                if is_test_enabled() {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                if !self
                    .kvm_vcpu_exec(cpu_thread_worker.thread_cpu.clone())
                    .with_context(|| {
                        format!(
                            "VCPU {}/KVM emulate error!",
                            cpu_thread_worker.thread_cpu.id()
                        )
                    })?
                {
                    break;
                }
            }
            #[cfg(test)]
            {
                thread::sleep(Duration::from_millis(5));
            }
        }

        // The vcpu thread is about to exit, marking the state
        // of the CPU state as Stopped.
        let (cpu_state, cvar) = &*cpu_thread_worker.thread_cpu.state;
        *cpu_state.lock().unwrap() = CpuLifecycleState::Stopped;
        cvar.notify_one();

        Ok(())
    }

    fn set_hypervisor_exit(&self) -> Result<()> {
        self.fd.set_kvm_immediate_exit(1);
        Ok(())
    }

    fn pause(
        &self,
        task: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
        state: Arc<(Mutex<CpuLifecycleState>, Condvar)>,
        pause_signal: Arc<AtomicBool>,
    ) -> Result<()> {
        let task = task.lock().unwrap();
        let (cpu_state, cvar) = &*state;

        if *cpu_state.lock().unwrap() == CpuLifecycleState::Running {
            *cpu_state.lock().unwrap() = CpuLifecycleState::Paused;
            cvar.notify_one()
        } else if *cpu_state.lock().unwrap() == CpuLifecycleState::Paused {
            return Ok(());
        }

        match task.as_ref() {
            Some(thread) => {
                if let Err(e) = thread.kill(VCPU_TASK_SIGNAL) {
                    return Err(anyhow!(CpuError::StopVcpu(format!("{:?}", e))));
                }
            }
            None => {
                warn!("vCPU thread not started, no need to stop");
                return Ok(());
            }
        }

        // It shall wait for the vCPU pause state from hypervisor exits.
        loop {
            if pause_signal.load(Ordering::SeqCst) {
                break;
            }
        }

        Ok(())
    }

    fn resume(
        &self,
        state: Arc<(Mutex<CpuLifecycleState>, Condvar)>,
        pause_signal: Arc<AtomicBool>,
    ) -> Result<()> {
        let (cpu_state_locked, cvar) = &*state;
        let mut cpu_state = cpu_state_locked.lock().unwrap();
        if *cpu_state == CpuLifecycleState::Running {
            warn!("vcpu{} in running state, no need to resume", self.id);
            return Ok(());
        }

        *cpu_state = CpuLifecycleState::Running;
        pause_signal.store(false, Ordering::SeqCst);
        drop(cpu_state);
        cvar.notify_one();
        Ok(())
    }

    fn destroy(
        &self,
        task: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
        state: Arc<(Mutex<CpuLifecycleState>, Condvar)>,
    ) -> Result<()> {
        let (cpu_state, cvar) = &*state;
        let mut locked_cpu_state = cpu_state.lock().unwrap();
        if *locked_cpu_state == CpuLifecycleState::Running {
            *locked_cpu_state = CpuLifecycleState::Stopping;
        } else if *locked_cpu_state == CpuLifecycleState::Stopped
            || *locked_cpu_state == CpuLifecycleState::Paused
        {
            return Ok(());
        }
        drop(locked_cpu_state);

        self.kick_vcpu_thread(task)?;
        let mut locked_cpu_state = cpu_state.lock().unwrap();
        locked_cpu_state = cvar
            .wait_timeout(locked_cpu_state, Duration::from_millis(32))
            .unwrap()
            .0;

        if *locked_cpu_state == CpuLifecycleState::Stopped {
            Ok(())
        } else {
            Err(anyhow!(CpuError::DestroyVcpu(format!(
                "VCPU still in {:?} state",
                *locked_cpu_state
            ))))
        }
    }
}

struct KVMInterruptManager {
    pub irqfd_cap: bool,
    pub vm_fd: Arc<VmFd>,
    pub irq_route_table: Mutex<IrqRouteTable>,
}

impl KVMInterruptManager {
    pub fn new(irqfd_cap: bool, vm_fd: Arc<VmFd>, irq_route_table: Mutex<IrqRouteTable>) -> Self {
        KVMInterruptManager {
            irqfd_cap,
            vm_fd,
            irq_route_table,
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn arch_map_irq(&self, gsi: u32) -> u32 {
        gsi
    }

    #[cfg(target_arch = "aarch64")]
    pub fn arch_map_irq(&self, gsi: u32) -> u32 {
        let irq = gsi + GIC_IRQ_INTERNAL;
        let irqtype = KVM_ARM_IRQ_TYPE_SPI;
        irqtype << KVM_ARM_IRQ_TYPE_SHIFT | irq
    }
}

impl LineIrqManager for KVMInterruptManager {
    fn irqfd_enable(&self) -> bool {
        self.irqfd_cap
    }

    fn register_irqfd(
        &self,
        irq_fd: Arc<EventFd>,
        irq: u32,
        trigger_mode: TriggerMode,
    ) -> Result<()> {
        if !self.irqfd_cap {
            bail!("Hypervisor doesn't support irqfd feature!")
        }

        match trigger_mode {
            TriggerMode::Edge => {
                self.vm_fd.register_irqfd(&irq_fd, irq).map_err(|e| {
                    error!("Failed to register irq, error is {:?}", e);
                    e
                })?;
            }
            _ => {
                bail!("Unsupported registering irq fd for interrupt of level mode.");
            }
        }

        Ok(())
    }

    fn unregister_irqfd(&self, irq_fd: Arc<EventFd>, irq: u32) -> Result<()> {
        self.vm_fd.unregister_irqfd(&irq_fd, irq).map_err(|e| {
            error!("Failed to unregister irq, error is {:?}", e);
            e
        })?;

        Ok(())
    }

    fn set_level_irq(&self, gsi: u32, level: bool) -> Result<()> {
        let kvm_irq = self.arch_map_irq(gsi);
        self.vm_fd
            .set_irq_line(kvm_irq, level)
            .with_context(|| format!("Failed to set irq {} level {:?}.", kvm_irq, level))
    }

    fn set_edge_irq(&self, gsi: u32) -> Result<()> {
        let kvm_irq = self.arch_map_irq(gsi);
        self.vm_fd
            .set_irq_line(kvm_irq, true)
            .with_context(|| format!("Failed to set irq {} level {:?}.", kvm_irq, true))?;
        self.vm_fd
            .set_irq_line(kvm_irq, false)
            .with_context(|| format!("Failed to set irq {} level {:?}.", kvm_irq, false))
    }

    fn write_irqfd(&self, irq_fd: Arc<EventFd>) -> Result<()> {
        irq_fd.write(1)?;

        Ok(())
    }
}

impl MsiIrqManager for KVMInterruptManager {
    fn allocate_irq(&self, vector: MsiVector) -> Result<u32> {
        let mut locked_irq_route_table = self.irq_route_table.lock().unwrap();
        let gsi = locked_irq_route_table.allocate_gsi().map_err(|e| {
            error!("Failed to allocate gsi, error is {:?}", e);
            e
        })?;

        locked_irq_route_table
            .add_msi_route(gsi, vector)
            .map_err(|e| {
                error!("Failed to add MSI-X route, error is {:?}", e);
                e
            })?;

        locked_irq_route_table
            .commit_irq_routing(&self.vm_fd.clone())
            .map_err(|e| {
                error!("Failed to commit irq routing, error is {:?}", e);
                e
            })?;

        Ok(gsi)
    }

    fn release_irq(&self, irq: u32) -> Result<()> {
        let mut locked_irq_route_table = self.irq_route_table.lock().unwrap();

        locked_irq_route_table.release_gsi(irq).map_err(|e| {
            error!("Failed to release gsi, error is {:?}", e);
            e
        })
    }

    fn register_irqfd(&self, irq_fd: Arc<EventFd>, irq: u32) -> Result<()> {
        self.vm_fd.register_irqfd(&irq_fd, irq).map_err(|e| {
            error!("Failed to register irq, error is {:?}", e);
            e
        })?;

        Ok(())
    }

    fn unregister_irqfd(&self, irq_fd: Arc<EventFd>, irq: u32) -> Result<()> {
        self.vm_fd.unregister_irqfd(&irq_fd, irq).map_err(|e| {
            error!("Failed to unregister irq, error is {:?}", e);
            e
        })?;

        Ok(())
    }

    fn trigger(&self, irq_fd: Option<Arc<EventFd>>, vector: MsiVector, dev_id: u32) -> Result<()> {
        if irq_fd.is_some() {
            irq_fd.unwrap().write(1)?;
        } else {
            #[cfg(target_arch = "aarch64")]
            let flags: u32 = kvm_bindings::KVM_MSI_VALID_DEVID;
            #[cfg(target_arch = "x86_64")]
            let flags: u32 = 0;

            let kvm_msi = kvm_bindings::kvm_msi {
                address_lo: vector.msg_addr_lo,
                address_hi: vector.msg_addr_hi,
                data: vector.msg_data,
                flags,
                devid: dev_id,
                pad: [0; 12],
            };

            self.vm_fd.signal_msi(kvm_msi)?;
        }

        Ok(())
    }

    fn update_route_table(&self, gsi: u32, vector: MsiVector) -> Result<()> {
        let mut locked_irq_route_table = self.irq_route_table.lock().unwrap();
        locked_irq_route_table
            .update_msi_route(gsi, vector)
            .map_err(|e| {
                error!("Failed to update MSI-X route, error is {:?}", e);
                e
            })?;
        locked_irq_route_table
            .commit_irq_routing(&self.vm_fd.clone())
            .map_err(|e| {
                error!("Failed to commit irq routing, error is {:?}", e);
                e
            })
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[cfg(target_arch = "x86_64")]
    use kvm_bindings::kvm_segment;

    #[cfg(target_arch = "x86_64")]
    use cpu::{ArchCPU, CPUBootConfig};
    use machine_manager::machine::{
        MachineAddressInterface, MachineInterface, MachineLifecycle, VmState,
    };

    use super::*;

    struct TestVm {
        #[cfg(target_arch = "x86_64")]
        pio_in: Arc<Mutex<Vec<(u64, Vec<u8>)>>>,
        #[cfg(target_arch = "x86_64")]
        pio_out: Arc<Mutex<Vec<(u64, Vec<u8>)>>>,
        mmio_read: Arc<Mutex<Vec<(u64, Vec<u8>)>>>,
        mmio_write: Arc<Mutex<Vec<(u64, Vec<u8>)>>>,
    }

    impl TestVm {
        fn new() -> Self {
            TestVm {
                #[cfg(target_arch = "x86_64")]
                pio_in: Arc::new(Mutex::new(Vec::new())),
                #[cfg(target_arch = "x86_64")]
                pio_out: Arc::new(Mutex::new(Vec::new())),
                mmio_read: Arc::new(Mutex::new(Vec::new())),
                mmio_write: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl MachineLifecycle for TestVm {
        fn notify_lifecycle(&self, _old: VmState, _new: VmState) -> bool {
            true
        }
    }

    impl MachineAddressInterface for TestVm {
        #[cfg(target_arch = "x86_64")]
        fn pio_in(&self, addr: u64, data: &mut [u8]) -> bool {
            self.pio_in.lock().unwrap().push((addr, data.to_vec()));
            true
        }

        #[cfg(target_arch = "x86_64")]
        fn pio_out(&self, addr: u64, data: &[u8]) -> bool {
            self.pio_out.lock().unwrap().push((addr, data.to_vec()));
            true
        }

        fn mmio_read(&self, addr: u64, data: &mut [u8]) -> bool {
            #[cfg(target_arch = "aarch64")]
            {
                data[3] = 0x0;
                data[2] = 0x0;
                data[1] = 0x5;
                data[0] = 0x6;
            }
            self.mmio_read.lock().unwrap().push((addr, data.to_vec()));
            true
        }

        fn mmio_write(&self, addr: u64, data: &[u8]) -> bool {
            self.mmio_write.lock().unwrap().push((addr, data.to_vec()));
            true
        }
    }

    impl MachineInterface for TestVm {}

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_x86_64_kvm_cpu() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }

        let vm = Arc::new(Mutex::new(TestVm::new()));

        let code_seg = kvm_segment {
            base: 0,
            limit: 1048575,
            selector: 16,
            type_: 11,
            present: 1,
            dpl: 0,
            db: 0,
            s: 1,
            l: 1,
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };
        let data_seg = kvm_segment {
            base: 0,
            limit: 1048575,
            selector: 24,
            type_: 3,
            present: 1,
            dpl: 0,
            db: 1,
            s: 1,
            l: 0,
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };
        let cpu_config = CPUBootConfig {
            prot64_mode: true,
            boot_ip: 0,
            boot_sp: 0,
            boot_selector: 0,
            zero_page: 0x0000_7000,
            code_segment: code_seg,
            data_segment: data_seg,
            gdt_base: 0x500u64,
            gdt_size: 16,
            idt_base: 0x520u64,
            idt_size: 8,
            pml4_start: 0x0000_9000,
        };

        // For `get_lapic` in realize function to work,
        // you need to create a irq_chip for VM before creating the VCPU.
        let vm_fd = kvm_hyp.vm_fd.as_ref().unwrap();
        vm_fd.create_irq_chip().unwrap();
        let vcpu_fd = kvm_hyp.vm_fd.as_ref().unwrap().create_vcpu(0).unwrap();
        let hypervisor_cpu = Arc::new(KvmCpu::new(
            0,
            #[cfg(target_arch = "aarch64")]
            kvm_hyp.vm_fd.clone(),
            vcpu_fd,
        ));
        let x86_cpu = Arc::new(Mutex::new(ArchCPU::new(0, 1)));
        let cpu = CPU::new(hypervisor_cpu.clone(), 0, x86_cpu, vm.clone());
        // test `set_boot_config` function
        assert!(hypervisor_cpu
            .set_boot_config(cpu.arch().clone(), &cpu_config)
            .is_ok());

        // test setup special registers
        let cpu_caps = CPUCaps::init_capabilities();
        assert!(hypervisor_cpu.put_register(Arc::new(cpu)).is_ok());
        let x86_sregs = hypervisor_cpu.fd.get_sregs().unwrap();
        assert_eq!(x86_sregs.cs, code_seg);
        assert_eq!(x86_sregs.ds, data_seg);
        assert_eq!(x86_sregs.es, data_seg);
        assert_eq!(x86_sregs.fs, data_seg);
        assert_eq!(x86_sregs.gs, data_seg);
        assert_eq!(x86_sregs.ss, data_seg);
        assert_eq!(x86_sregs.gdt.base, cpu_config.gdt_base);
        assert_eq!(x86_sregs.gdt.limit, cpu_config.gdt_size);
        assert_eq!(x86_sregs.idt.base, cpu_config.idt_base);
        assert_eq!(x86_sregs.idt.limit, cpu_config.idt_size);
        assert_eq!(x86_sregs.cr0 & 0x1, 1);
        assert_eq!((x86_sregs.cr0 & 0x8000_0000) >> 31, 1);
        assert_eq!(x86_sregs.cr3, cpu_config.pml4_start);
        assert_eq!((x86_sregs.cr4 & 0x20) >> 5, 1);
        assert_eq!((x86_sregs.efer & 0x700) >> 8, 5);

        // test setup_regs function
        let x86_regs = hypervisor_cpu.fd.get_regs().unwrap();
        assert_eq!(x86_regs.rflags, 0x0002);
        assert_eq!(x86_regs.rip, 0);
        assert_eq!(x86_regs.rsp, 0);
        assert_eq!(x86_regs.rbp, 0);
        assert_eq!(x86_regs.rsi, 0x0000_7000);

        // test setup_fpu function
        if !cpu_caps.has_xsave {
            let x86_fpu = hypervisor_cpu.fd.get_fpu().unwrap();
            assert_eq!(x86_fpu.fcw, 0x37f);
        }
    }

    #[test]
    #[allow(unused)]
    fn test_cpu_lifecycle_with_kvm() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }

        let vcpu_fd = kvm_hyp.vm_fd.as_ref().unwrap().create_vcpu(0).unwrap();
        let hypervisor_cpu = Arc::new(KvmCpu::new(
            0,
            #[cfg(target_arch = "aarch64")]
            kvm_hyp.vm_fd.clone(),
            vcpu_fd,
        ));

        let vm = Arc::new(Mutex::new(TestVm::new()));
        let cpu = CPU::new(
            hypervisor_cpu.clone(),
            0,
            Arc::new(Mutex::new(ArchCPU::default())),
            vm.clone(),
        );
        let (cpu_state, _) = &*cpu.state;
        assert_eq!(*cpu_state.lock().unwrap(), CpuLifecycleState::Created);
        drop(cpu_state);

        let cpus_thread_barrier = Arc::new(Barrier::new(2));
        let cpu_thread_barrier = cpus_thread_barrier.clone();

        #[cfg(target_arch = "aarch64")]
        {
            let mut kvi = kvm_bindings::kvm_vcpu_init::default();
            kvm_hyp
                .vm_fd
                .as_ref()
                .unwrap()
                .get_preferred_target(&mut kvi)
                .unwrap();
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
            *hypervisor_cpu.kvi.lock().unwrap() = kvi;
            hypervisor_cpu.vcpu_init().unwrap();
        }

        // Test cpu life cycle as:
        // Created -> Paused -> Running -> Paused -> Running -> Destroy
        let cpu_arc = Arc::new(cpu);
        CPU::start(cpu_arc.clone(), cpu_thread_barrier, true).unwrap();

        // Wait for CPU thread init signal hook
        std::thread::sleep(Duration::from_millis(50));
        cpus_thread_barrier.wait();
        let (cpu_state, _) = &*cpu_arc.state;
        assert_eq!(*cpu_state.lock().unwrap(), CpuLifecycleState::Paused);
        drop(cpu_state);

        assert!(cpu_arc.resume().is_ok());

        // Wait for CPU finish state change.
        std::thread::sleep(Duration::from_millis(50));
        let (cpu_state, _) = &*cpu_arc.state;
        assert_eq!(*cpu_state.lock().unwrap(), CpuLifecycleState::Running);
        drop(cpu_state);

        assert!(cpu_arc.pause().is_ok());

        // Wait for CPU finish state change.
        std::thread::sleep(Duration::from_millis(50));
        let (cpu_state, _) = &*cpu_arc.state;
        assert_eq!(*cpu_state.lock().unwrap(), CpuLifecycleState::Paused);
        drop(cpu_state);

        assert!(cpu_arc.resume().is_ok());
        // Wait for CPU finish state change.
        std::thread::sleep(Duration::from_millis(50));

        assert!(cpu_arc.destroy().is_ok());

        // Wait for CPU finish state change.
        std::thread::sleep(Duration::from_millis(50));
        let (cpu_state, _) = &*cpu_arc.state;
        assert_eq!(*cpu_state.lock().unwrap(), CpuLifecycleState::Stopped);
        drop(cpu_state);
    }
}
