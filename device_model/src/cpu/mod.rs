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
#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use std::cell::RefCell;
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use kvm_ioctls::{VcpuExit, VcpuFd};
use libc::{c_int, c_void, siginfo_t};
use vmm_sys_util::signal::{register_signal_handler, Killable};

use machine_manager::{qmp::qmp_schema as schema, qmp::QmpChannel};

use self::errors::{ErrorKind, Result};
#[cfg(target_arch = "aarch64")]
pub use aarch64::errors as ArchCPUError;
#[cfg(target_arch = "aarch64")]
pub use aarch64::AArch64CPUBootConfig as CPUBootConfig;
#[cfg(target_arch = "aarch64")]
pub use aarch64::CPUAArch64 as ArchCPU;
use machine_manager::machine::MachineInterface;
#[cfg(target_arch = "x86_64")]
pub use x86_64::errors as ArchCPUError;
#[cfg(target_arch = "x86_64")]
pub use x86_64::X86CPUBootConfig as CPUBootConfig;
#[cfg(target_arch = "x86_64")]
pub use x86_64::X86CPU as ArchCPU;

pub mod errors {
    error_chain! {
        links {
            ArchCpu(super::ArchCPUError::Error, super::ArchCPUError::ErrorKind);
        }
        foreign_links {
            Signal(vmm_sys_util::errno::Error);
        }
        errors {
            CreateVcpu(err_info: String) {
                description("Create kvm vcpu error!")
                display("Failed to create kvm vcpu: {}!", err_info)
            }
            RealizeVcpu(err_info: String) {
                description("Configure vcpu error!")
                display("Failed to configure kvm vcpu: {}!", err_info)
            }
            StartVcpu(err_info: String) {
                description("Start vcpu error!")
                display("Failed to starting kvm vcpu: {}!", err_info)
            }
            StopVcpu(err_info: String) {
                description("Stop vcpu error!")
                display("Failed to stopping kvm vcpu: {}!", err_info)
            }
            DestroyVcpu(err_info: String) {
                description("Destroy vcpu error!")
                display("Failed to destroy kvm vcpu: {}!", err_info)
            }
        }
    }
}

// SIGRTMIN = 34 (GNU, in MUSL is 35) and SIGRTMAX = 64  in linux, VCPU signal
// number should be assigned to SIGRTMIN + n, (n = 0...30).
#[cfg(not(target_env = "musl"))]
const VCPU_EXIT_SIGNAL: i32 = 34;
#[cfg(target_env = "musl")]
const VCPU_EXIT_SIGNAL: i32 = 35;
#[cfg(not(target_env = "musl"))]
const VCPU_PAUSE_SIGNAL: i32 = 35;
#[cfg(target_env = "musl")]
const VCPU_PAUSE_SIGNAL: i32 = 36;
#[cfg(not(target_env = "musl"))]
const VCPU_TASK_SIGNAL: i32 = 36;
#[cfg(target_env = "musl")]
const VCPU_TASK_SIGNAL: i32 = 37;

const UNINITIALIZED_VCPU_ID: u32 = 9999;

/// State for `CPU` lifecycle.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CpuLifecycleState {
    /// `CPU` structure is only be initialized, but nothing set.
    Nothing = 0,
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

// Record vcpu information
struct ThreadVcpu {
    dirty_stamps: u64,
    vcpu_id: u32,
}

thread_local! {
    static LOCAL_THREAD_VCPU: RefCell<ThreadVcpu> = RefCell::new(
       ThreadVcpu {
           dirty_stamps: 0,
           vcpu_id: UNINITIALIZED_VCPU_ID,
       }
    )
}

fn init_local_thread_vcpu(vcpu_id: u8) {
    LOCAL_THREAD_VCPU.with(|thread_vcpu| {
        let mut vcpu_signal = thread_vcpu.borrow_mut();
        vcpu_signal.vcpu_id = u32::from(vcpu_id);
        vcpu_signal.dirty_stamps = 0;
    })
}

/// Trait to handle `CPU` lifetime.
pub trait CPUInterface {
    /// Realize `CPU` structure, set registers value for `CPU`.
    fn realize(&self, boot: &CPUBootConfig) -> Result<()>;

    ///
    /// # Arguments
    ///
    /// * `cpu` - The cpu instance shared in thread.
    /// * `thread_barrier` - The cpu thread barrier.
    /// * `paused` - After started, paused vcpu or not.
    /// * `use seccomp` - Use seccomp in vcpu thread.
    fn start(
        cpu: Arc<Self>,
        thread_barrier: Arc<Barrier>,
        paused: bool,
        use_seccomp: bool,
    ) -> Result<()>
    where
        Self: std::marker::Sized;

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

    /// Handle vcpu event from `kvm`.
    fn kvm_vcpu_exec(&self) -> Result<bool>;
}

/// Trait to handle `CPU` running statement.
pub trait CPUWorker {
    const SYNC_READ_CPU_STATE: u64 = 1;
    const SYNC_WRITE_CPU_STATE: u64 = 2;

    /// Handle `notify` change in vcpu thread.
    fn handle_workqueue(&self);

    /// Check vcpu thread is `paused` or `running`.
    fn ready_for_running(&self) -> bool;
}

/// `CPU` is a wrapper around creating and using a kvm-based VCPU.
pub struct CPU {
    /// ID of this virtual CPU, `0` means this cpu is primary `CPU`.
    id: u8,
    /// The file descriptor of this kvm-based VCPU.
    fd: Arc<VcpuFd>,
    /// Architecture special CPU property.
    arch_cpu: Arc<Mutex<ArchCPU>>,
    /// LifeCycle state of kvm-based VCPU.
    state: Arc<(Mutex<CpuLifecycleState>, Condvar)>,
    /// Works need to handled by this VCPU.
    work_queue: Arc<(Mutex<u64>, Condvar)>,
    /// The thread handler of this virtual CPU.
    task: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
    /// The thread tid of this VCPU.
    tid: Arc<Mutex<Option<u64>>>,
    /// The VM combined by this VCPU.
    vm: Arc<Box<Arc<dyn MachineInterface + Send + Sync>>>,
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
        vm: Arc<Box<Arc<dyn MachineInterface + Send + Sync>>>,
    ) -> Result<Self> {
        Ok(CPU {
            id,
            fd: vcpu_fd,
            arch_cpu,
            state: Arc::new((Mutex::new(CpuLifecycleState::Created), Condvar::new())),
            work_queue: Arc::new((Mutex::new(0), Condvar::new())),
            task: Arc::new(Mutex::new(None)),
            tid: Arc::new(Mutex::new(None)),
            vm,
        })
    }

    /// Get this `CPU`'s ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Get this `CPU`'s file descriptor.
    #[cfg(target_arch = "aarch64")]
    pub fn fd(&self) -> &Arc<VcpuFd> {
        &self.fd
    }

    /// Get this `CPU`'s architecture-special property.
    #[cfg(target_arch = "aarch64")]
    pub fn arch(&self) -> &Arc<Mutex<ArchCPU>> {
        &self.arch_cpu
    }

    /// Set task the `CPU` to handle.
    pub fn set_task(&self, task: Option<thread::JoinHandle<()>>) {
        let mut data = self.task.lock().unwrap();
        (*data).take().map(thread::JoinHandle::join);
        *data = task;
    }

    /// Get this `CPU`'s thread id.
    pub fn tid(&self) -> u64 {
        match *self.tid.lock().unwrap() {
            Some(tid) => tid,
            None => 0,
        }
    }

    /// Set thread id for `CPU`.
    pub fn set_tid(&self) {
        *self.tid.lock().unwrap() = Some(util::unix::gettid());
    }

    /// Init signal for `CPU` event.
    fn init_signals() -> Result<()> {
        extern "C" fn handle_signal(signum: c_int, _: *mut siginfo_t, _: *mut c_void) {
            match signum {
                VCPU_EXIT_SIGNAL => LOCAL_THREAD_VCPU.with(|thread_vcpu| {
                    let mut vcpu_signal = thread_vcpu.borrow_mut();
                    vcpu_signal.dirty_stamps = VCPU_EXIT_SIGNAL as u64;
                }),
                VCPU_PAUSE_SIGNAL => LOCAL_THREAD_VCPU.with(|thread_vcpu| {
                    let mut vcpu_signal = thread_vcpu.borrow_mut();
                    vcpu_signal.dirty_stamps = VCPU_PAUSE_SIGNAL as u64;
                }),
                _ => {}
            }
        }

        register_signal_handler(VCPU_EXIT_SIGNAL, handle_signal)?;
        register_signal_handler(VCPU_PAUSE_SIGNAL, handle_signal)?;
        register_signal_handler(VCPU_TASK_SIGNAL, handle_signal)?;

        Ok(())
    }
}

impl CPUInterface for CPU {
    fn realize(&self, boot: &CPUBootConfig) -> Result<()> {
        let (cpu_state, _) = &*self.state;
        if *cpu_state.lock().unwrap() != CpuLifecycleState::Created {
            return Err(
                ErrorKind::RealizeVcpu(format!("VCPU{} may has realized.", self.id())).into(),
            );
        }

        self.arch_cpu.lock().unwrap().realize(&self.fd, boot)?;

        Ok(())
    }

    fn resume(&self) -> Result<()> {
        let (cpu_state_locked, cvar) = &*self.state;
        let mut cpu_state = cpu_state_locked.lock().unwrap();
        if *cpu_state == CpuLifecycleState::Running {
            warn!("vcpu{} in running state, no need to resume", self.id());
            return Ok(());
        }

        *cpu_state = CpuLifecycleState::Running;
        drop(cpu_state);
        cvar.notify_one();
        Ok(())
    }

    fn start(
        cpu: Arc<CPU>,
        thread_barrier: Arc<Barrier>,
        paused: bool,
        use_seccomp: bool,
    ) -> Result<()> {
        let (cpu_state, _) = &*cpu.state;
        if *cpu_state.lock().unwrap() == CpuLifecycleState::Running {
            return Err(ErrorKind::StartVcpu("Cpu is already running".to_string()).into());
        }
        if paused {
            *cpu_state.lock().unwrap() = CpuLifecycleState::Paused;
        } else {
            *cpu_state.lock().unwrap() = CpuLifecycleState::Running;
        }

        let local_cpu = cpu.clone();
        let handle = thread::Builder::new()
            .name(format!("CPU {}/KVM", cpu.id))
            .spawn(move || {
                init_local_thread_vcpu(cpu.id);
                if let Err(e) = CPU::init_signals() {
                    error!("Failed to init cpu{} signal:{}", cpu.id, e);
                }

                cpu.set_tid();

                // The vcpu thread is going to run,
                // reset its running environment.
                cpu.reset().unwrap();

                // Wait for all vcpu to complete the running
                // environment initialization.
                thread_barrier.wait();

                info!("vcpu{} start running", cpu.id);
                if use_seccomp {
                    if let Err(e) = crate::micro_vm::micro_syscall::register_seccomp() {
                        error!("Failed to register seccomp in cpu{} thread:{}", cpu.id, e);
                    }
                }

                loop {
                    if !cpu.ready_for_running() {
                        break;
                    }

                    if !cpu.kvm_vcpu_exec().unwrap() {
                        break;
                    }
                }

                // The vcpu thread is about to exit, marking the state
                // of the CPU state as Stopped.
                let (cpu_state, cvar) = &*cpu.state;
                *cpu_state.lock().unwrap() = CpuLifecycleState::Stopped;
                cvar.notify_one();
            })
            .unwrap();
        local_cpu.set_task(Some(handle));
        Ok(())
    }

    fn reset(&self) -> Result<()> {
        self.arch_cpu.lock().unwrap().reset_vcpu(&self.fd)?;
        Ok(())
    }

    fn pause(&self) -> Result<()> {
        let task = self.task.lock().unwrap();
        let (cpu_state, cvar) = &*self.state;

        if *cpu_state.lock().unwrap() == CpuLifecycleState::Running {
            *cpu_state.lock().unwrap() = CpuLifecycleState::Paused;
            cvar.notify_one()
        }

        match &(*task) {
            Some(thread) => match thread.kill(VCPU_PAUSE_SIGNAL) {
                Ok(_) => Ok(()),
                Err(e) => Err(ErrorKind::StopVcpu(format!("{}", e)).into()),
            },
            None => {
                warn!("VCPU thread not started, no need to stop");
                Ok(())
            }
        }
    }

    fn destroy(&self) -> Result<()> {
        let task = self.task.lock().unwrap();
        let (cpu_state, cvar) = &*self.state;
        if *cpu_state.lock().unwrap() == CpuLifecycleState::Running {
            *cpu_state.lock().unwrap() = CpuLifecycleState::Stopping;
        } else {
            *cpu_state.lock().unwrap() = CpuLifecycleState::Stopped;
        }

        self.fd.set_kvm_immediate_exit(0);
        match &(*task) {
            Some(thread) => match thread.kill(VCPU_EXIT_SIGNAL) {
                Ok(_) => {}
                Err(e) => {
                    error!(
                        "killing VCPU{} thread({}) failed: {}",
                        self.id(),
                        self.tid(),
                        e
                    );
                }
            },
            None => {}
        }
        let mut cpu_state = cpu_state.lock().unwrap();
        cvar.notify_all();

        cpu_state = cvar
            .wait_timeout(cpu_state, Duration::from_millis(16))
            .unwrap()
            .0;

        if *cpu_state == CpuLifecycleState::Stopped {
            *cpu_state = CpuLifecycleState::Nothing;
            Ok(())
        } else {
            Err(ErrorKind::DestroyVcpu(format!("VCPU still in {:?} state", *cpu_state)).into())
        }
    }

    fn guest_shutdown(&self) -> Result<()> {
        let (cpu_state, _) = &*self.state;
        *cpu_state.lock().unwrap() = CpuLifecycleState::Stopped;
        self.vm.destroy();

        let shutdown_msg = schema::SHUTDOWN {
            guest: true,
            reason: "guest-shutdown".to_string(),
        };
        event!(SHUTDOWN; shutdown_msg);

        Ok(())
    }

    fn kvm_vcpu_exec(&self) -> Result<bool> {
        match self.fd.run() {
            Ok(run) => match run {
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoIn(addr, data) => {
                    self.vm.pio_in(u64::from(addr), data);
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoOut(addr, data) => {
                    self.vm.pio_out(u64::from(addr), data);
                }
                VcpuExit::MmioRead(addr, data) => {
                    self.vm.mmio_read(addr, data);
                }
                VcpuExit::MmioWrite(addr, data) => {
                    self.vm.mmio_write(addr, data);
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::Hlt => {
                    info!("Vcpu{} received KVM_EXIT_HLT signal", self.id());
                    panic!("Hlt vpu {}", self.id());
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::Shutdown => {
                    info!("Vcpu{} received an KVM_EXIT_SHUTDOWN signal", self.id());
                    self.guest_shutdown()?;

                    return Ok(false);
                }
                #[cfg(target_arch = "aarch64")]
                VcpuExit::SystemEvent(event, flags) => {
                    if event == kvm_bindings::KVM_SYSTEM_EVENT_SHUTDOWN
                        || event == kvm_bindings::KVM_SYSTEM_EVENT_RESET
                    {
                        info!(
                            "Vcpu{} received an KVM_SYSTEM_EVENT_SHUTDOWN signal",
                            self.id()
                        );
                        self.guest_shutdown()?;
                    } else {
                        error!(
                            "Vcpu{} recevied unexpected system event with type 0x{:x}, flags 0x{:x}",
                            self.id(),
                            event,
                            flags
                        );
                    }

                    return Ok(false);
                }
                VcpuExit::FailEntry => {
                    info!("Vcpu{} received KVM_EXIT_FAIL_ENTRY signal", self.id());
                    return Ok(false);
                }
                VcpuExit::InternalError => {
                    info!("Vcpu{} received KVM_EXIT_INTERNAL_ERROR signal", self.id());
                    return Ok(false);
                }
                r => panic!("Unexpected exit reason: {:?}", r),
            },
            Err(ref e) => {
                match e.errno() {
                    libc::EAGAIN => {}
                    libc::EINTR => {
                        self.fd.set_kvm_immediate_exit(0);
                    }
                    _ => {
                        error!("Failure during vcpu run: {}", e);
                        panic!("VcpuUnhandledKvmExit");
                    }
                };
            }
        }
        Ok(true)
    }
}

impl CPUWorker for CPU {
    fn handle_workqueue(&self) {
        LOCAL_THREAD_VCPU.with(|thread_vcpu| {
            let mut vcpu_signal = thread_vcpu.borrow_mut();
            if vcpu_signal.dirty_stamps != 0 {
                vcpu_signal.dirty_stamps = 0;
                drop(vcpu_signal);

                let (work_queue_locked, cvar) = &*self.work_queue;
                let mut work_queue = work_queue_locked.lock().unwrap();
                if *work_queue & Self::SYNC_READ_CPU_STATE == Self::SYNC_READ_CPU_STATE {
                    *work_queue &= !Self::SYNC_READ_CPU_STATE;
                    cvar.notify_all();
                }

                if *work_queue & Self::SYNC_WRITE_CPU_STATE == Self::SYNC_WRITE_CPU_STATE {
                    *work_queue &= !Self::SYNC_WRITE_CPU_STATE;
                    cvar.notify_all();
                }
            }
        });
    }

    fn ready_for_running(&self) -> bool {
        let mut flag = 0_u32;
        let (cpu_state_locked, cvar) = &*self.state;
        let mut cpu_state = cpu_state_locked.lock().unwrap();
        loop {
            self.handle_workqueue();

            match *cpu_state {
                CpuLifecycleState::Paused => {
                    if flag == 0 {
                        info!("Vcpu{} paused", self.id);
                        flag = 1;
                    }
                    cpu_state = cvar.wait(cpu_state).unwrap();
                }
                CpuLifecycleState::Running => {
                    return true;
                }
                CpuLifecycleState::Stopping => {
                    info!("Vcpu{} shutdown", self.id);
                    cvar.notify_all();
                    return false;
                }
                _ => {
                    warn!("Unknown Vmstate");
                    return true;
                }
            }
        }
    }
}

/// The wrapper for topology for VCPU.
#[derive(Clone)]
pub struct CpuTopology {
    /// Number of sockets in VM.
    pub sockets: u8,
    /// Number of cores in VM.
    pub cores: u8,
    /// Number of threads in VM.
    pub threads: u8,
    /// Number of vcpus in VM.
    pub nrcpus: u8,
    /// Number of online vcpus in VM.
    pub max_cpus: u8,
    /// Online mask number of all vcpus.
    pub online_mask: Arc<Mutex<Vec<u8>>>,
}

impl CpuTopology {
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
    pub fn get_topo(&self, vcpu_id: usize) -> (u8, u8, u8) {
        let cpu_per_socket = self.cores * self.threads;
        let cpu_per_core = self.threads;
        let socketid: u8 = vcpu_id as u8 / cpu_per_socket;
        let coreid: u8 = (vcpu_id as u8 % cpu_per_socket) / cpu_per_core;
        let threadid: u8 = (vcpu_id as u8 % cpu_per_socket) % cpu_per_core;
        (socketid, coreid, threadid)
    }
}
