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
pub use aarch64::ArmCPUFeatures as CPUFeatures;
#[cfg(target_arch = "aarch64")]
pub use aarch64::ArmCPUState as ArchCPU;
#[cfg(target_arch = "aarch64")]
pub use aarch64::ArmCPUTopology as CPUTopology;
#[cfg(target_arch = "aarch64")]
pub use aarch64::ArmRegsIndex as RegsIndex;
#[cfg(target_arch = "aarch64")]
pub use aarch64::CpregListEntry;
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
#[cfg(target_arch = "x86_64")]
pub use x86_64::X86RegsIndex as RegsIndex;

use std::cell::RefCell;
use std::sync::atomic::{fence, AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex, Weak};
use std::thread;

use anyhow::{anyhow, Context, Result};
use log::{error, info, warn};
use nix::unistd::gettid;

use machine_manager::config::ShutdownAction::{ShutdownActionPause, ShutdownActionPoweroff};
use machine_manager::event;
use machine_manager::machine::{HypervisorType, MachineInterface};
use machine_manager::qmp::{qmp_channel::QmpChannel, qmp_schema};

// SIGRTMIN = 34 (GNU, in MUSL is 35) and SIGRTMAX = 64  in linux, VCPU signal
// number should be assigned to SIGRTMIN + n, (n = 0...30).
#[cfg(target_env = "gnu")]
pub const VCPU_TASK_SIGNAL: i32 = 34;
#[cfg(target_env = "musl")]
pub const VCPU_TASK_SIGNAL: i32 = 35;
#[cfg(target_env = "ohos")]
pub const VCPU_TASK_SIGNAL: i32 = 40;

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

    /// Start `CPU` thread and run virtual CPU in hypervisor.
    ///
    /// # Arguments
    ///
    /// * `cpu` - The cpu instance shared in thread.
    /// * `thread_barrier` - The cpu thread barrier.
    /// * `paused` - After started, paused vcpu or not.
    fn start(cpu: Arc<Self>, thread_barrier: Arc<Barrier>, paused: bool) -> Result<()>
    where
        Self: std::marker::Sized;

    /// Make `CPU` lifecycle from `Running` to `Paused`.
    fn pause(&self) -> Result<()>;

    /// Make `CPU` lifecycle from `Paused` to `Running`.
    fn resume(&self) -> Result<()>;

    /// Make `CPU` lifecycle to `Stopping`, then `Stopped`.
    fn destroy(&self) -> Result<()>;

    /// Make `CPU` destroy because of guest inner shutdown.
    fn guest_shutdown(&self) -> Result<()>;

    /// Make `CPU` destroy because of guest inner reset.
    fn guest_reset(&self) -> Result<()>;
}

pub trait CPUHypervisorOps: Send + Sync {
    fn get_hypervisor_type(&self) -> HypervisorType;

    fn init_pmu(&self) -> Result<()>;

    fn vcpu_init(&self) -> Result<()>;

    fn set_boot_config(
        &self,
        arch_cpu: Arc<Mutex<ArchCPU>>,
        boot_config: &CPUBootConfig,
        #[cfg(target_arch = "aarch64")] vcpu_config: &CPUFeatures,
    ) -> Result<()>;

    fn get_one_reg(&self, reg_id: u64) -> Result<u128>;

    fn get_regs(&self, arch_cpu: Arc<Mutex<ArchCPU>>, regs_index: RegsIndex) -> Result<()>;

    fn set_regs(&self, arch_cpu: Arc<Mutex<ArchCPU>>, regs_index: RegsIndex) -> Result<()>;

    fn put_register(&self, cpu: Arc<CPU>) -> Result<()>;

    fn reset_vcpu(&self, cpu: Arc<CPU>) -> Result<()>;

    fn vcpu_exec(
        &self,
        cpu_thread_worker: CPUThreadWorker,
        thread_barrier: Arc<Barrier>,
    ) -> Result<()>;

    fn set_hypervisor_exit(&self) -> Result<()>;

    fn pause(
        &self,
        task: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
        state: Arc<(Mutex<CpuLifecycleState>, Condvar)>,
        pause_signal: Arc<AtomicBool>,
    ) -> Result<()>;

    fn resume(
        &self,
        state: Arc<(Mutex<CpuLifecycleState>, Condvar)>,
        pause_signal: Arc<AtomicBool>,
    ) -> Result<()>;

    fn destroy(
        &self,
        task: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
        state: Arc<(Mutex<CpuLifecycleState>, Condvar)>,
    ) -> Result<()>;
}

/// `CPU` is a wrapper around creating and using a hypervisor-based VCPU.
#[allow(clippy::upper_case_acronyms)]
pub struct CPU {
    /// ID of this virtual CPU, `0` means this cpu is primary `CPU`.
    pub id: u8,
    /// Architecture special CPU property.
    pub arch_cpu: Arc<Mutex<ArchCPU>>,
    /// LifeCycle state of hypervisor-based VCPU.
    pub state: Arc<(Mutex<CpuLifecycleState>, Condvar)>,
    /// The thread handler of this virtual CPU.
    task: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
    /// The thread tid of this VCPU.
    tid: Arc<Mutex<Option<u64>>>,
    /// The VM combined by this VCPU.
    vm: Weak<Mutex<dyn MachineInterface + Send + Sync>>,
    /// The state backup of architecture CPU right before boot.
    boot_state: Arc<Mutex<ArchCPU>>,
    /// Sync the pause state of vCPU in hypervisor and userspace.
    pause_signal: Arc<AtomicBool>,
    /// Interact between the vCPU and hypervisor.
    pub hypervisor_cpu: Arc<dyn CPUHypervisorOps>,
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
        hypervisor_cpu: Arc<dyn CPUHypervisorOps>,
        id: u8,
        arch_cpu: Arc<Mutex<ArchCPU>>,
        vm: Arc<Mutex<dyn MachineInterface + Send + Sync>>,
    ) -> Self {
        CPU {
            id,
            arch_cpu,
            state: Arc::new((Mutex::new(CpuLifecycleState::Created), Condvar::new())),
            task: Arc::new(Mutex::new(None)),
            tid: Arc::new(Mutex::new(None)),
            vm: Arc::downgrade(&vm),
            boot_state: Arc::new(Mutex::new(ArchCPU::default())),
            pause_signal: Arc::new(AtomicBool::new(false)),
            hypervisor_cpu,
        }
    }

    /// Get this `CPU`'s ID.
    pub fn id(&self) -> u8 {
        self.id
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
    pub fn set_tid(&self, tid: Option<u64>) {
        if tid.is_none() {
            *self.tid.lock().unwrap() = Some(gettid().as_raw() as u64);
        } else {
            *self.tid.lock().unwrap() = tid;
        }
    }

    /// Get the hypervisor of this `CPU`.
    pub fn hypervisor_cpu(&self) -> &Arc<dyn CPUHypervisorOps> {
        &self.hypervisor_cpu
    }

    pub fn vm(&self) -> Weak<Mutex<dyn MachineInterface + Send + Sync>> {
        self.vm.clone()
    }

    pub fn boot_state(&self) -> Arc<Mutex<ArchCPU>> {
        self.boot_state.clone()
    }

    pub fn pause_signal(&self) -> Arc<AtomicBool> {
        self.pause_signal.clone()
    }
}

impl CPUInterface for CPU {
    fn realize(
        &self,
        boot: &CPUBootConfig,
        topology: &CPUTopology,
        #[cfg(target_arch = "aarch64")] config: &CPUFeatures,
    ) -> Result<()> {
        trace::cpu_boot_config(boot);
        let (cpu_state, _) = &*self.state;
        if *cpu_state.lock().unwrap() != CpuLifecycleState::Created {
            return Err(anyhow!(CpuError::RealizeVcpu(format!(
                "VCPU{} may has realized.",
                self.id()
            ))));
        }

        self.hypervisor_cpu
            .set_boot_config(
                self.arch_cpu.clone(),
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
        self.hypervisor_cpu
            .set_regs(self.arch_cpu.clone(), RegsIndex::VtimerCount)?;

        self.hypervisor_cpu
            .resume(self.state.clone(), self.pause_signal.clone())
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
        let cpu_id = cpu.id();
        let hypervisor_cpu = cpu.hypervisor_cpu().clone();
        let hyp_type = hypervisor_cpu.get_hypervisor_type();
        let cpu_thread_worker = CPUThreadWorker::new(cpu);
        let handle = thread::Builder::new()
            .name(format!("CPU {}/{:?}", local_cpu.id, hyp_type))
            .spawn(move || {
                if let Err(e) = hypervisor_cpu.vcpu_exec(cpu_thread_worker, thread_barrier) {
                    error!("Some error occurred in cpu{} thread: {:?}", cpu_id, e);
                }
            })
            .with_context(|| {
                format!("Failed to create thread for CPU {}/{:?}", cpu_id, hyp_type)
            })?;
        local_cpu.set_task(Some(handle));
        Ok(())
    }

    fn pause(&self) -> Result<()> {
        self.hypervisor_cpu.pause(
            self.task.clone(),
            self.state.clone(),
            self.pause_signal.clone(),
        )?;

        #[cfg(target_arch = "aarch64")]
        self.hypervisor_cpu
            .get_regs(self.arch_cpu.clone(), RegsIndex::VtimerCount)?;

        Ok(())
    }

    fn destroy(&self) -> Result<()> {
        self.hypervisor_cpu
            .destroy(self.task.clone(), self.state.clone())
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
            let (cpu_state, _) = &*self.state;
            *cpu_state.lock().unwrap() = CpuLifecycleState::Paused;
            vm.lock().unwrap().reset();
        } else {
            return Err(anyhow!(CpuError::NoMachineInterface));
        }

        Ok(())
    }
}

/// The struct to handle events in cpu thread.
#[allow(clippy::upper_case_acronyms)]
pub struct CPUThreadWorker {
    pub thread_cpu: Arc<CPU>,
}

impl CPUThreadWorker {
    thread_local!(static LOCAL_THREAD_VCPU: RefCell<Option<CPUThreadWorker>> = RefCell::new(None));

    /// Allocates a new `CPUThreadWorker`.
    fn new(thread_cpu: Arc<CPU>) -> Self {
        CPUThreadWorker { thread_cpu }
    }

    /// Init vcpu thread static variable.
    pub fn init_local_thread_vcpu(&self) {
        Self::LOCAL_THREAD_VCPU.with(|thread_vcpu| {
            *thread_vcpu.borrow_mut() = Some(CPUThreadWorker {
                thread_cpu: self.thread_cpu.clone(),
            });
        })
    }

    pub fn run_on_local_thread_vcpu<F>(func: F) -> Result<()>
    where
        F: FnOnce(Arc<CPU>),
    {
        Self::LOCAL_THREAD_VCPU.with(|thread_vcpu| {
            if let Some(local_thread_vcpu) = thread_vcpu.borrow().as_ref() {
                func(local_thread_vcpu.thread_cpu.clone());
                Ok(())
            } else {
                Err(anyhow!(CpuError::VcpuLocalThreadNotPresent))
            }
        })
    }

    /// Judge whether the hypervisor vcpu is ready to emulate.
    pub fn ready_for_running(&self) -> Result<bool> {
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
                    // Setting pause_signal to be `true` if kvm changes vCPU to pause state.
                    self.thread_cpu.pause_signal().store(true, Ordering::SeqCst);
                    fence(Ordering::Release);
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

/// Capture the boot signal that trap from guest kernel, and then record
/// kernel boot timestamp.
#[cfg(feature = "boot_time")]
pub fn capture_boot_signal(addr: u64, data: &[u8]) {
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

    use super::*;

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
