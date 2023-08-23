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

//! # Cpu
//!
//! This mod is to initialize vcpus to assigned state and drive them to run.
//!
//! ## Design
//!
//! This module offers support for:
//! 1. Create vcpu.
//! 2. According configuration, initialize vcpu registers and run.
//! 3. Handle vcpu VmIn/VmOut events.
//! 4. Handle vcpu lifecycle.
//!
//! ## Platform Support
//!
//! - `x86_64`
//! - `aarch64`

pub mod error;

#[allow(clippy::upper_case_acronyms)]
#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::ArmCPUBootConfig as CPUBootConfig;
#[cfg(target_arch = "aarch64")]
pub use aarch64::ArmCPUCaps as CPUCaps;
#[cfg(target_arch = "aarch64")]
pub use aarch64::ArmCPUFeatures as CPUFeatures;
#[cfg(target_arch = "aarch64")]
pub use aarch64::ArmCPUState as ArchCPU;
#[cfg(target_arch = "aarch64")]
pub use aarch64::ArmCPUTopology as CPUTopology;
#[cfg(target_arch = "aarch64")]
pub use aarch64::PMU_INTR;
#[cfg(target_arch = "aarch64")]
pub use aarch64::PPI_BASE;
pub use error::CpuError;
#[cfg(target_arch = "x86_64")]
pub use x86_64::X86CPUBootConfig as CPUBootConfig;
#[cfg(target_arch = "x86_64")]
pub use x86_64::X86CPUState as ArchCPU;
#[cfg(target_arch = "x86_64")]
pub use x86_64::X86CPUTopology as CPUTopology;

use std::cell::RefCell;
use std::sync::atomic::{fence, AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex, Weak};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use kvm_ioctls::{VcpuExit, VcpuFd};
use libc::{c_int, c_void, siginfo_t};
use log::{error, info, warn};
use vmm_sys_util::signal::{register_signal_handler, Killable};

use machine_manager::config::ShutdownAction::{ShutdownActionPause, ShutdownActionPoweroff};
use machine_manager::event;
use machine_manager::machine::MachineInterface;
use machine_manager::{qmp::qmp_schema, qmp::QmpChannel};
#[cfg(not(test))]
use util::test_helper::is_test_enabled;
#[cfg(target_arch = "x86_64")]
use x86_64::caps::X86CPUCaps as CPUCaps;

// SIGRTMIN = 34 (GNU, in MUSL is 35) and SIGRTMAX = 64  in linux, VCPU signal
// number should be assigned to SIGRTMIN + n, (n = 0...30).
#[cfg(not(target_env = "musl"))]
const VCPU_TASK_SIGNAL: i32 = 34;
#[cfg(target_env = "musl")]
const VCPU_TASK_SIGNAL: i32 = 35;
#[cfg(not(target_env = "musl"))]
const VCPU_RESET_SIGNAL: i32 = 35;
#[cfg(target_env = "musl")]
const VCPU_RESET_SIGNAL: i32 = 36;

/// Watch `0x3ff` IO port to record the magic value trapped from guest kernel.
#[cfg(all(target_arch = "x86_64", feature = "boot_time"))]
const MAGIC_SIGNAL_GUEST_BOOT: u64 = 0x3ff;
/// Watch Uart MMIO region to record the magic value trapped from guest kernel.
#[cfg(all(target_arch = "aarch64", feature = "boot_time"))]
const MAGIC_SIGNAL_GUEST_BOOT: u64 = 0x9000f00;
/// The boot start value can be verified before kernel start.
#[cfg(feature = "boot_time")]
const MAGIC_VALUE_SIGNAL_GUEST_BOOT_START: u8 = 0x01;
/// The boot complete value can be verified before init guest userspace.
#[cfg(feature = "boot_time")]
const MAGIC_VALUE_SIGNAL_GUEST_BOOT_COMPLETE: u8 = 0x02;

/// State for `CPU` lifecycle.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CpuLifecycleState {
    /// `CPU` structure's property is set with configuration.
    Created = 1,
    /// `CPU` start to be running.
    Running = 2,
    /// `CPU` thread is sleeping.
    Paused = 3,
    /// `CPU` structure is going to destroy.
    Stopping = 4,
    /// `CPU` structure destroyed, will be dropped soon.
    Stopped = 5,
}

/// Trait to handle `CPU` lifetime.
#[allow(clippy::upper_case_acronyms)]
pub trait CPUInterface {
    /// Realize `CPU` structure, set registers value for `CPU`.
    fn realize(
        &self,
        boot: &CPUBootConfig,
        topology: &CPUTopology,
        #[cfg(target_arch = "aarch64")] features: &CPUFeatures,
    ) -> Result<()>;

    /// Start `CPU` thread and run virtual CPU in kvm.
    ///
    /// # Arguments
    ///
    /// * `cpu` - The cpu instance shared in thread.
    /// * `thread_barrier` - The cpu thread barrier.
    /// * `paused` - After started, paused vcpu or not.
    fn start(cpu: Arc<Self>, thread_barrier: Arc<Barrier>, paused: bool) -> Result<()>
    where
        Self: std::marker::Sized;

    /// Kick `CPU` to exit kvm emulation.
    fn kick(&self) -> Result<()>;

    /// Make `CPU` lifecycle from `Running` to `Paused`.
    fn pause(&self) -> Result<()>;

    /// Make `CPU` lifecycle from `Paused` to `Running`.
    fn resume(&self) -> Result<()>;

    /// Make `CPU` lifecycle to `Stopping`, then `Stopped`.
    fn destroy(&self) -> Result<()>;

    /// Reset registers value for `CPU`.
    fn reset(&self) -> Result<()>;

    /// Make `CPU` destroy because of guest inner shutdown.
    fn guest_shutdown(&self) -> Result<()>;

    /// Make `CPU` destroy because of guest inner reset.
    fn guest_reset(&self) -> Result<()>;

    /// Handle vcpu event from `kvm`.
    fn kvm_vcpu_exec(&self) -> Result<bool>;
}

/// `CPU` is a wrapper around creating and using a kvm-based VCPU.
#[allow(clippy::upper_case_acronyms)]
pub struct CPU {
    /// ID of this virtual CPU, `0` means this cpu is primary `CPU`.
    id: u8,
    /// The file descriptor of this kvm-based VCPU.
    fd: Arc<VcpuFd>,
    /// Architecture special CPU property.
    arch_cpu: Arc<Mutex<ArchCPU>>,
    /// LifeCycle state of kvm-based VCPU.
    state: Arc<(Mutex<CpuLifecycleState>, Condvar)>,
    /// The thread handler of this virtual CPU.
    task: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
    /// The thread tid of this VCPU.
    tid: Arc<Mutex<Option<u64>>>,
    /// The VM combined by this VCPU.
    vm: Weak<Mutex<dyn MachineInterface + Send + Sync>>,
    /// The capability of VCPU.
    caps: CPUCaps,
    /// The state backup of architecture CPU right before boot.
    boot_state: Arc<Mutex<ArchCPU>>,
    /// Sync the pause state of vCPU in kvm and userspace.
    pause_signal: Arc<AtomicBool>,
}

impl CPU {
    /// Allocates a new `CPU` for `vm`
    ///
    /// # Arguments
    ///
    /// * `vcpu_fd` - The file descriptor of this `CPU`.
    /// * `id` - ID of this `CPU`.
    /// * `arch_cpu` - Architecture special `CPU` property.
    /// * `vm` - The virtual machine this `CPU` gets attached to.
    pub fn new(
        vcpu_fd: Arc<VcpuFd>,
        id: u8,
        arch_cpu: Arc<Mutex<ArchCPU>>,
        vm: Arc<Mutex<dyn MachineInterface + Send + Sync>>,
    ) -> Self {
        CPU {
            id,
            fd: vcpu_fd,
            arch_cpu,
            state: Arc::new((Mutex::new(CpuLifecycleState::Created), Condvar::new())),
            task: Arc::new(Mutex::new(None)),
            tid: Arc::new(Mutex::new(None)),
            vm: Arc::downgrade(&vm),
            caps: CPUCaps::init_capabilities(),
            boot_state: Arc::new(Mutex::new(ArchCPU::default())),
            pause_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_to_boot_state(&self) {
        self.arch_cpu.lock().unwrap().set(&self.boot_state);
    }

    /// Get this `CPU`'s ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Get this `CPU`'s file descriptor.
    pub fn fd(&self) -> &Arc<VcpuFd> {
        &self.fd
    }

    /// Get this `CPU`'s state.
    pub fn state(&self) -> &(Mutex<CpuLifecycleState>, Condvar) {
        self.state.as_ref()
    }

    /// Get this `CPU`'s architecture-special property.
    pub fn arch(&self) -> &Arc<Mutex<ArchCPU>> {
        &self.arch_cpu
    }

    /// Set task the `CPU` to handle.
    fn set_task(&self, task: Option<thread::JoinHandle<()>>) {
        let mut data = self.task.lock().unwrap();
        (*data).take().map(thread::JoinHandle::join);
        *data = task;
    }

    /// Get this `CPU`'s thread id.
    pub fn tid(&self) -> u64 {
        (*self.tid.lock().unwrap()).unwrap_or(0)
    }

    /// Set thread id for `CPU`.
    fn set_tid(&self) {
        *self.tid.lock().unwrap() = Some(util::unix::gettid());
    }
}

impl CPUInterface for CPU {
    fn realize(
        &self,
        boot: &CPUBootConfig,
        topology: &CPUTopology,
        #[cfg(target_arch = "aarch64")] config: &CPUFeatures,
    ) -> Result<()> {
        trace_cpu_boot_config(boot);
        let (cpu_state, _) = &*self.state;
        if *cpu_state.lock().unwrap() != CpuLifecycleState::Created {
            return Err(anyhow!(CpuError::RealizeVcpu(format!(
                "VCPU{} may has realized.",
                self.id()
            ))));
        }

        self.arch_cpu
            .lock()
            .unwrap()
            .set_boot_config(
                &self.fd,
                boot,
                #[cfg(target_arch = "aarch64")]
                config,
            )
            .with_context(|| "Failed to realize arch cpu")?;

        self.arch_cpu
            .lock()
            .unwrap()
            .set_cpu_topology(topology)
            .with_context(|| "Failed to realize arch cpu")?;

        self.boot_state.lock().unwrap().set(&self.arch_cpu);
        Ok(())
    }

    fn resume(&self) -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        self.arch()
            .lock()
            .unwrap()
            .set_virtual_timer_cnt(self.fd())?;

        let (cpu_state_locked, cvar) = &*self.state;
        let mut cpu_state = cpu_state_locked.lock().unwrap();
        if *cpu_state == CpuLifecycleState::Running {
            warn!("vcpu{} in running state, no need to resume", self.id());
            return Ok(());
        }

        *cpu_state = CpuLifecycleState::Running;
        self.pause_signal.store(false, Ordering::SeqCst);
        drop(cpu_state);
        cvar.notify_one();
        Ok(())
    }

    fn start(cpu: Arc<CPU>, thread_barrier: Arc<Barrier>, paused: bool) -> Result<()> {
        let (cpu_state, _) = &*cpu.state;
        if *cpu_state.lock().unwrap() == CpuLifecycleState::Running {
            return Err(anyhow!(CpuError::StartVcpu(
                "Cpu is already running".to_string()
            )));
        }
        if paused {
            *cpu_state.lock().unwrap() = CpuLifecycleState::Paused;
        } else {
            *cpu_state.lock().unwrap() = CpuLifecycleState::Running;
        }

        let local_cpu = cpu.clone();
        let cpu_thread_worker = CPUThreadWorker::new(cpu);
        let handle = thread::Builder::new()
            .name(format!("CPU {}/KVM", local_cpu.id))
            .spawn(move || {
                if let Err(e) = cpu_thread_worker.handle(thread_barrier) {
                    error!(
                        "Some error occurred in cpu{} thread: {:?}",
                        cpu_thread_worker.thread_cpu.id, e
                    );
                }
            })
            .with_context(|| format!("Failed to create thread for CPU {}/KVM", local_cpu.id()))?;
        local_cpu.set_task(Some(handle));
        Ok(())
    }

    fn reset(&self) -> Result<()> {
        let task = self.task.lock().unwrap();
        match task.as_ref() {
            Some(thread) => thread
                .kill(VCPU_RESET_SIGNAL)
                .with_context(|| CpuError::KickVcpu("Fail to reset vcpu".to_string())),
            None => {
                warn!("VCPU thread not started, no need to reset");
                Ok(())
            }
        }
    }

    fn kick(&self) -> Result<()> {
        let task = self.task.lock().unwrap();
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

    fn pause(&self) -> Result<()> {
        let task = self.task.lock().unwrap();
        let (cpu_state, cvar) = &*self.state;

        if *cpu_state.lock().unwrap() == CpuLifecycleState::Running {
            *cpu_state.lock().unwrap() = CpuLifecycleState::Paused;
            cvar.notify_one()
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

        // It shall wait for the vCPU pause state from kvm exits.
        loop {
            if self.pause_signal.load(Ordering::SeqCst) {
                break;
            }
        }

        #[cfg(target_arch = "aarch64")]
        self.arch()
            .lock()
            .unwrap()
            .get_virtual_timer_cnt(self.fd())?;

        Ok(())
    }

    fn destroy(&self) -> Result<()> {
        let (cpu_state, cvar) = &*self.state;
        let mut cpu_state = cpu_state.lock().unwrap();
        if *cpu_state == CpuLifecycleState::Running {
            *cpu_state = CpuLifecycleState::Stopping;
        } else if *cpu_state == CpuLifecycleState::Stopped
            || *cpu_state == CpuLifecycleState::Paused
        {
            return Ok(());
        }

        self.kick()?;
        cpu_state = cvar
            .wait_timeout(cpu_state, Duration::from_millis(32))
            .unwrap()
            .0;

        if *cpu_state == CpuLifecycleState::Stopped {
            Ok(())
        } else {
            Err(anyhow!(CpuError::DestroyVcpu(format!(
                "VCPU still in {:?} state",
                *cpu_state
            ))))
        }
    }

    fn guest_shutdown(&self) -> Result<()> {
        if let Some(vm) = self.vm.upgrade() {
            let shutdown_act = vm.lock().unwrap().get_shutdown_action();
            match shutdown_act {
                ShutdownActionPoweroff => {
                    let (cpu_state, _) = &*self.state;
                    *cpu_state.lock().unwrap() = CpuLifecycleState::Stopped;
                    vm.lock().unwrap().destroy();
                }
                ShutdownActionPause => {
                    vm.lock().unwrap().pause();
                }
            }
        } else {
            return Err(anyhow!(CpuError::NoMachineInterface));
        }

        if QmpChannel::is_connected() {
            let shutdown_msg = qmp_schema::Shutdown {
                guest: true,
                reason: "guest-shutdown".to_string(),
            };
            event!(Shutdown; shutdown_msg);
        }

        Ok(())
    }

    fn guest_reset(&self) -> Result<()> {
        if let Some(vm) = self.vm.upgrade() {
            vm.lock().unwrap().reset();
        } else {
            return Err(anyhow!(CpuError::NoMachineInterface));
        }

        Ok(())
    }

    fn kvm_vcpu_exec(&self) -> Result<bool> {
        let vm = self
            .vm
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
                    info!("Vcpu{} received KVM_EXIT_HLT signal", self.id());
                    return Err(anyhow!(CpuError::VcpuHltEvent(self.id())));
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::Shutdown => {
                    info!("Vcpu{} received an KVM_EXIT_SHUTDOWN signal", self.id());
                    self.guest_shutdown()?;

                    return Ok(false);
                }
                #[cfg(target_arch = "aarch64")]
                VcpuExit::SystemEvent(event, flags) => {
                    if event == kvm_bindings::KVM_SYSTEM_EVENT_SHUTDOWN {
                        info!(
                            "Vcpu{} received an KVM_SYSTEM_EVENT_SHUTDOWN signal",
                            self.id()
                        );
                        self.guest_shutdown()
                            .with_context(|| "Some error occurred in guest shutdown")?;
                        return Ok(true);
                    } else if event == kvm_bindings::KVM_SYSTEM_EVENT_RESET {
                        info!(
                            "Vcpu{} received an KVM_SYSTEM_EVENT_RESET signal",
                            self.id()
                        );
                        self.guest_reset()
                            .with_context(|| "Some error occurred in guest reset")?;
                        return Ok(true);
                    } else {
                        error!(
                            "Vcpu{} received unexpected system event with type 0x{:x}, flags 0x{:x}",
                            self.id(),
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
                    info!("Vcpu{} received KVM_EXIT_INTERNAL_ERROR signal", self.id());
                    return Ok(false);
                }
                r => {
                    return Err(anyhow!(CpuError::VcpuExitReason(
                        self.id(),
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
                        return Err(anyhow!(CpuError::UnhandledKvmExit(self.id())));
                    }
                };
            }
        }
        Ok(true)
    }
}

/// The struct to handle events in cpu thread.
#[allow(clippy::upper_case_acronyms)]
struct CPUThreadWorker {
    thread_cpu: Arc<CPU>,
}

impl CPUThreadWorker {
    thread_local!(static LOCAL_THREAD_VCPU: RefCell<Option<CPUThreadWorker>> = RefCell::new(None));

    /// Allocates a new `CPUThreadWorker`.
    fn new(thread_cpu: Arc<CPU>) -> Self {
        CPUThreadWorker { thread_cpu }
    }

    /// Init vcpu thread static variable.
    fn init_local_thread_vcpu(&self) {
        Self::LOCAL_THREAD_VCPU.with(|thread_vcpu| {
            *thread_vcpu.borrow_mut() = Some(CPUThreadWorker {
                thread_cpu: self.thread_cpu.clone(),
            });
        })
    }

    fn run_on_local_thread_vcpu<F>(func: F) -> Result<()>
    where
        F: FnOnce(&CPU),
    {
        Self::LOCAL_THREAD_VCPU.with(|thread_vcpu| {
            if let Some(local_thread_vcpu) = thread_vcpu.borrow().as_ref() {
                func(&local_thread_vcpu.thread_cpu);
                Ok(())
            } else {
                Err(anyhow!(CpuError::VcpuLocalThreadNotPresent))
            }
        })
    }

    /// Init signal for `CPU` event.
    fn init_signals() -> Result<()> {
        extern "C" fn handle_signal(signum: c_int, _: *mut siginfo_t, _: *mut c_void) {
            match signum {
                VCPU_TASK_SIGNAL => {
                    let _ = CPUThreadWorker::run_on_local_thread_vcpu(|vcpu| {
                        vcpu.fd().set_kvm_immediate_exit(1);
                        // Setting pause_signal to be `true` if kvm changes vCPU to pause state.
                        vcpu.pause_signal.store(true, Ordering::SeqCst);
                        fence(Ordering::Release)
                    });
                }
                VCPU_RESET_SIGNAL => {
                    let _ = CPUThreadWorker::run_on_local_thread_vcpu(|vcpu| {
                        if let Err(e) = vcpu.arch_cpu.lock().unwrap().reset_vcpu(
                            &vcpu.fd,
                            #[cfg(target_arch = "x86_64")]
                            &vcpu.caps,
                        ) {
                            error!("Failed to reset vcpu state: {:?}", e)
                        }
                    });
                }
                _ => {}
            }
        }

        register_signal_handler(VCPU_TASK_SIGNAL, handle_signal)
            .with_context(|| "Failed to register VCPU_TASK_SIGNAL signal.")?;
        register_signal_handler(VCPU_RESET_SIGNAL, handle_signal)
            .with_context(|| "Failed to register VCPU_TASK_SIGNAL signal.")?;

        Ok(())
    }

    /// Judge whether the kvm vcpu is ready to emulate.
    fn ready_for_running(&self) -> Result<bool> {
        let mut flag = 0_u32;
        let (cpu_state_locked, cvar) = &*self.thread_cpu.state;
        let mut cpu_state = cpu_state_locked.lock().unwrap();

        loop {
            match *cpu_state {
                CpuLifecycleState::Paused => {
                    if flag == 0 {
                        info!("Vcpu{} paused", self.thread_cpu.id);
                        flag = 1;
                    }
                    cpu_state = cvar.wait(cpu_state).unwrap();
                }
                CpuLifecycleState::Running => {
                    return Ok(true);
                }
                CpuLifecycleState::Stopping | CpuLifecycleState::Stopped => {
                    info!("Vcpu{} shutdown", self.thread_cpu.id);
                    return Ok(false);
                }
                _ => {
                    warn!("Unknown Vmstate");
                    return Ok(true);
                }
            }
        }
    }

    /// Handle the all events in vcpu thread.
    fn handle(&self, thread_barrier: Arc<Barrier>) -> Result<()> {
        self.init_local_thread_vcpu();
        if let Err(e) = Self::init_signals() {
            error!("Failed to init cpu{} signal:{:?}", self.thread_cpu.id, e);
        }

        self.thread_cpu.set_tid();

        // The vcpu thread is going to run,
        // reset its running environment.
        #[cfg(not(test))]
        self.thread_cpu
            .arch_cpu
            .lock()
            .unwrap()
            .reset_vcpu(
                &self.thread_cpu.fd,
                #[cfg(target_arch = "x86_64")]
                &self.thread_cpu.caps,
            )
            .with_context(|| "Failed to reset for cpu register state")?;

        // Wait for all vcpu to complete the running
        // environment initialization.
        thread_barrier.wait();

        info!("vcpu{} start running", self.thread_cpu.id);
        while let Ok(true) = self.ready_for_running() {
            #[cfg(not(test))]
            {
                if is_test_enabled() {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                if !self
                    .thread_cpu
                    .kvm_vcpu_exec()
                    .with_context(|| format!("VCPU {}/KVM emulate error!", self.thread_cpu.id()))?
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
        let (cpu_state, cvar) = &*self.thread_cpu.state;
        *cpu_state.lock().unwrap() = CpuLifecycleState::Stopped;
        cvar.notify_one();

        Ok(())
    }
}

/// The wrapper for topology for VCPU.
#[derive(Clone)]
pub struct CpuTopology {
    /// Number of vcpus in VM.
    pub nrcpus: u8,
    /// Number of sockets in VM.
    pub sockets: u8,
    /// Number of dies in one socket.
    pub dies: u8,
    /// Number of clusters in one die.
    pub clusters: u8,
    /// Number of cores in one cluster.
    pub cores: u8,
    /// Number of threads in one core.
    pub threads: u8,
    /// Number of online vcpus in VM.
    pub max_cpus: u8,
    /// Online mask number of all vcpus.
    pub online_mask: Arc<Mutex<Vec<u8>>>,
}

impl CpuTopology {
    /// * `nr_cpus`: Number of vcpus in one VM.
    /// * `nr_sockets`: Number of sockets in one VM.
    /// * `nr_dies`: Number of dies in one socket.
    /// * `nr_clusters`: Number of clusters in one die.
    /// * `nr_cores`: Number of cores in one cluster.
    /// * `nr_threads`: Number of threads in one core.
    /// * `max_cpus`: Number of online vcpus in VM.
    pub fn new(
        nr_cpus: u8,
        nr_sockets: u8,
        nr_dies: u8,
        nr_clusters: u8,
        nr_cores: u8,
        nr_threads: u8,
        max_cpus: u8,
    ) -> Self {
        let mut mask: Vec<u8> = vec![0; max_cpus as usize];
        (0..nr_cpus as usize).for_each(|index| {
            mask[index] = 1;
        });
        Self {
            nrcpus: nr_cpus,
            sockets: nr_sockets,
            dies: nr_dies,
            clusters: nr_clusters,
            cores: nr_cores,
            threads: nr_threads,
            max_cpus,
            online_mask: Arc::new(Mutex::new(mask)),
        }
    }

    /// Get online mask for a cpu.
    ///
    /// # Notes
    ///
    /// When `online_mask` is `0`, vcpu is offline. When `online_mask` is `1`,
    /// vcpu is online.
    ///
    /// # Arguments
    ///
    /// * `vcpu_id` - ID of vcpu.
    pub fn get_mask(&self, vcpu_id: usize) -> u8 {
        let mask = self.online_mask.lock().unwrap();
        mask[vcpu_id]
    }

    /// Get single cpu topology for vcpu, return this vcpu's `socket-id`,
    /// `core-id` and `thread-id`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_id` - ID of vcpu.
    fn get_topo_item(&self, vcpu_id: usize) -> (u8, u8, u8, u8, u8) {
        let socketid: u8 = vcpu_id as u8 / (self.dies * self.clusters * self.cores * self.threads);
        let dieid: u8 = (vcpu_id as u8 / (self.clusters * self.cores * self.threads)) % self.dies;
        let clusterid: u8 = (vcpu_id as u8 / (self.cores * self.threads)) % self.clusters;
        let coreid: u8 = (vcpu_id as u8 / self.threads) % self.cores;
        let threadid: u8 = vcpu_id as u8 % self.threads;
        (socketid, dieid, clusterid, coreid, threadid)
    }

    pub fn get_topo_instance_for_qmp(&self, cpu_index: usize) -> qmp_schema::CpuInstanceProperties {
        let (socketid, _dieid, _clusterid, coreid, threadid) = self.get_topo_item(cpu_index);
        qmp_schema::CpuInstanceProperties {
            node_id: None,
            socket_id: Some(socketid as isize),
            #[cfg(target_arch = "x86_64")]
            die_id: Some(_dieid as isize),
            #[cfg(target_arch = "aarch64")]
            cluster_id: Some(_clusterid as isize),
            core_id: Some(coreid as isize),
            thread_id: Some(threadid as isize),
        }
    }
}

fn trace_cpu_boot_config(cpu_boot_config: &CPUBootConfig) {
    util::ftrace!(trace_CPU_boot_config, "{:#?}", cpu_boot_config);
}

/// Capture the boot signal that trap from guest kernel, and then record
/// kernel boot timestamp.
#[cfg(feature = "boot_time")]
fn capture_boot_signal(addr: u64, data: &[u8]) {
    if addr == MAGIC_SIGNAL_GUEST_BOOT {
        if data[0] == MAGIC_VALUE_SIGNAL_GUEST_BOOT_START {
            info!("Kernel starts to boot!");
        } else if data[0] == MAGIC_VALUE_SIGNAL_GUEST_BOOT_COMPLETE {
            info!("Kernel boot complete!");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use hypervisor::kvm::{KVMFds, KVM_FDS};
    use machine_manager::machine::{
        KvmVmState, MachineAddressInterface, MachineInterface, MachineLifecycle,
    };

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
        fn notify_lifecycle(&self, _old: KvmVmState, _new: KvmVmState) -> bool {
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

    #[test]
    #[allow(unused)]
    fn test_cpu_lifecycle() {
        let kvm_fds = KVMFds::new();
        if kvm_fds.vm_fd.is_none() {
            return;
        }
        KVM_FDS.store(Arc::new(kvm_fds));

        let vm = Arc::new(Mutex::new(TestVm::new()));
        let cpu = CPU::new(
            Arc::new(
                KVM_FDS
                    .load()
                    .vm_fd
                    .as_ref()
                    .unwrap()
                    .create_vcpu(0)
                    .unwrap(),
            ),
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
            KVM_FDS
                .load()
                .vm_fd
                .as_ref()
                .unwrap()
                .get_preferred_target(&mut kvi)
                .unwrap();
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
            cpu.fd.vcpu_init(&kvi).unwrap();
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

    #[test]
    fn test_cpu_get_topu() {
        let test_nr_cpus: u8 = 16;
        let mask = Vec::with_capacity(test_nr_cpus as usize);

        let microvm_cpu_topo = CpuTopology {
            sockets: test_nr_cpus,
            dies: 1,
            clusters: 1,
            cores: 1,
            threads: 1,
            nrcpus: test_nr_cpus,
            max_cpus: test_nr_cpus,
            online_mask: Arc::new(Mutex::new(mask)),
        };

        assert_eq!(microvm_cpu_topo.get_topo_item(0), (0, 0, 0, 0, 0));
        assert_eq!(microvm_cpu_topo.get_topo_item(4), (4, 0, 0, 0, 0));
        assert_eq!(microvm_cpu_topo.get_topo_item(8), (8, 0, 0, 0, 0));
        assert_eq!(microvm_cpu_topo.get_topo_item(15), (15, 0, 0, 0, 0));

        let mask = Vec::with_capacity(test_nr_cpus as usize);
        let microvm_cpu_topo_x86 = CpuTopology {
            sockets: 1,
            dies: 2,
            clusters: 1,
            cores: 4,
            threads: 2,
            nrcpus: test_nr_cpus,
            max_cpus: test_nr_cpus,
            online_mask: Arc::new(Mutex::new(mask)),
        };

        assert_eq!(microvm_cpu_topo_x86.get_topo_item(0), (0, 0, 0, 0, 0));
        assert_eq!(microvm_cpu_topo_x86.get_topo_item(4), (0, 0, 0, 2, 0));
        assert_eq!(microvm_cpu_topo_x86.get_topo_item(8), (0, 1, 0, 0, 0));
        assert_eq!(microvm_cpu_topo_x86.get_topo_item(15), (0, 1, 0, 3, 1));

        let mask = Vec::with_capacity(test_nr_cpus as usize);
        let microvm_cpu_topo_arm = CpuTopology {
            sockets: 1,
            dies: 1,
            clusters: 2,
            cores: 4,
            threads: 2,
            nrcpus: test_nr_cpus,
            max_cpus: test_nr_cpus,
            online_mask: Arc::new(Mutex::new(mask)),
        };

        assert_eq!(microvm_cpu_topo_arm.get_topo_item(0), (0, 0, 0, 0, 0));
        assert_eq!(microvm_cpu_topo_arm.get_topo_item(4), (0, 0, 0, 2, 0));
        assert_eq!(microvm_cpu_topo_arm.get_topo_item(8), (0, 0, 1, 0, 0));
        assert_eq!(microvm_cpu_topo_arm.get_topo_item(15), (0, 0, 1, 3, 1));

        let test_nr_cpus: u8 = 32;
        let mask = Vec::with_capacity(test_nr_cpus as usize);
        let test_cpu_topo = CpuTopology {
            sockets: 2,
            dies: 1,
            clusters: 1,
            cores: 4,
            threads: 2,
            nrcpus: test_nr_cpus,
            max_cpus: test_nr_cpus,
            online_mask: Arc::new(Mutex::new(mask)),
        };

        assert_eq!(test_cpu_topo.get_topo_item(0), (0, 0, 0, 0, 0));
        assert_eq!(test_cpu_topo.get_topo_item(4), (0, 0, 0, 2, 0));
        assert_eq!(test_cpu_topo.get_topo_item(7), (0, 0, 0, 3, 1));
        assert_eq!(test_cpu_topo.get_topo_item(11), (1, 0, 0, 1, 1));
        assert_eq!(test_cpu_topo.get_topo_item(15), (1, 0, 0, 3, 1));
        assert_eq!(test_cpu_topo.get_topo_item(17), (2, 0, 0, 0, 1));
        assert_eq!(test_cpu_topo.get_topo_item(23), (2, 0, 0, 3, 1));
        assert_eq!(test_cpu_topo.get_topo_item(29), (3, 0, 0, 2, 1));
        assert_eq!(test_cpu_topo.get_topo_item(31), (3, 0, 0, 3, 1));
    }
}
