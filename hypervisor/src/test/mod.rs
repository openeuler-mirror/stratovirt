// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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
mod aarch64;
mod listener;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use kvm_ioctls::DeviceFd;
use log::info;
use vmm_sys_util::eventfd::EventFd;

#[cfg(target_arch = "aarch64")]
use self::aarch64::{TestGicv3, TestGicv3Its};
use self::listener::TestMemoryListener;
use super::HypervisorOps;
use address_space::{AddressSpace, Listener};
#[cfg(target_arch = "aarch64")]
use cpu::CPUFeatures;
use cpu::{
    ArchCPU, CPUBootConfig, CPUHypervisorOps, CPUThreadWorker, CpuError, CpuLifecycleState,
    RegsIndex, CPU,
};
use devices::{pci::MsiVector, IrqManager, LineIrqManager, MsiIrqManager, TriggerMode};
#[cfg(target_arch = "aarch64")]
use devices::{GICVersion, GICv3, ICGICConfig, InterruptController, GIC_IRQ_INTERNAL};
use machine_manager::machine::HypervisorType;
use migration::{MigrateMemSlot, MigrateOps};
use util::test_helper::{IntxInfo, MsixMsg, TEST_INTX_LIST, TEST_MSIX_LIST};

pub struct TestHypervisor {}

impl TestHypervisor {
    pub fn new() -> Result<Self> {
        Ok(TestHypervisor {})
    }

    fn create_memory_listener(&self) -> Arc<Mutex<dyn Listener>> {
        Arc::new(Mutex::new(TestMemoryListener::default()))
    }
}

impl HypervisorOps for TestHypervisor {
    fn get_hypervisor_type(&self) -> HypervisorType {
        HypervisorType::Test
    }

    fn init_machine(
        &self,
        #[cfg(target_arch = "x86_64")] _sys_io: &Arc<AddressSpace>,
        sys_mem: &Arc<AddressSpace>,
    ) -> Result<()> {
        sys_mem
            .register_listener(self.create_memory_listener())
            .with_context(|| "Failed to register hypervisor listener for memory space.")
    }

    #[cfg(target_arch = "aarch64")]
    fn create_interrupt_controller(
        &mut self,
        gic_conf: &ICGICConfig,
    ) -> Result<Arc<InterruptController>> {
        gic_conf.check_sanity()?;

        let create_gicv3 = || {
            let gicv3 = Arc::new(GICv3::new(
                Arc::new(TestGicv3::default()),
                Arc::new(TestGicv3Its::default()),
                gic_conf,
            )?);

            Ok(Arc::new(InterruptController::new(gicv3)))
        };

        match &gic_conf.version {
            Some(GICVersion::GICv3) => create_gicv3(),
            Some(GICVersion::GICv2) => Err(anyhow!("MST doesn't support Gicv2.")),
            // Try v3 by default if no version specified.
            None => create_gicv3(),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn create_interrupt_controller(&mut self) -> Result<()> {
        Ok(())
    }

    fn create_hypervisor_cpu(
        &self,
        vcpu_id: u8,
    ) -> Result<Arc<dyn CPUHypervisorOps + Send + Sync>> {
        Ok(Arc::new(TestCpu::new(vcpu_id)))
    }

    fn create_irq_manager(&mut self) -> Result<IrqManager> {
        let test_irq_manager = Arc::new(TestInterruptManager {});
        Ok(IrqManager {
            line_irq_manager: Some(test_irq_manager.clone()),
            msi_irq_manager: Some(test_irq_manager),
        })
    }

    fn create_vfio_device(&self) -> Option<DeviceFd> {
        None
    }
}

pub struct TestCpu {
    #[allow(unused)]
    id: u8,
}

impl TestCpu {
    pub fn new(vcpu_id: u8) -> Self {
        Self { id: vcpu_id }
    }
}

impl CPUHypervisorOps for TestCpu {
    fn get_hypervisor_type(&self) -> HypervisorType {
        HypervisorType::Test
    }

    fn init_pmu(&self) -> Result<()> {
        Ok(())
    }

    fn vcpu_init(&self) -> Result<()> {
        Ok(())
    }

    #[allow(unused)]
    fn set_boot_config(
        &self,
        arch_cpu: Arc<Mutex<ArchCPU>>,
        boot_config: &CPUBootConfig,
        #[cfg(target_arch = "aarch64")] _vcpu_config: &CPUFeatures,
    ) -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            arch_cpu.lock().unwrap().mpidr = self.id as u64;
            arch_cpu.lock().unwrap().set_core_reg(boot_config);
        }
        Ok(())
    }

    fn get_one_reg(&self, _reg_id: u64) -> Result<u128> {
        Err(anyhow!("MST does not support getting one reg."))
    }

    fn get_regs(&self, _arch_cpu: Arc<Mutex<ArchCPU>>, _regs_index: RegsIndex) -> Result<()> {
        Ok(())
    }

    fn set_regs(&self, _arch_cpu: Arc<Mutex<ArchCPU>>, _regs_index: RegsIndex) -> Result<()> {
        Ok(())
    }

    fn put_register(&self, _cpu: Arc<CPU>) -> Result<()> {
        Err(anyhow!("Test does not support putting register."))
    }

    fn reset_vcpu(&self, cpu: Arc<CPU>) -> Result<()> {
        cpu.arch_cpu.lock().unwrap().set(&cpu.boot_state());
        Ok(())
    }

    fn vcpu_exec(
        &self,
        cpu_thread_worker: CPUThreadWorker,
        thread_barrier: Arc<Barrier>,
    ) -> Result<()> {
        cpu_thread_worker.init_local_thread_vcpu();
        cpu_thread_worker.thread_cpu.set_tid(None);

        // Wait for all vcpu to complete the running
        // environment initialization.
        thread_barrier.wait();

        info!("Test vcpu{} start running", cpu_thread_worker.thread_cpu.id);
        while let Ok(true) = cpu_thread_worker.ready_for_running() {
            thread::sleep(Duration::from_millis(5));
            continue;
        }

        // The vcpu thread is about to exit, marking the state
        // of the CPU state as Stopped.
        let (cpu_state, cvar) = &*cpu_thread_worker.thread_cpu.state;
        *cpu_state.lock().unwrap() = CpuLifecycleState::Stopped;
        cvar.notify_one();

        Ok(())
    }

    fn set_hypervisor_exit(&self) -> Result<()> {
        Ok(())
    }

    fn pause(
        &self,
        _task: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
        _state: Arc<(Mutex<CpuLifecycleState>, Condvar)>,
        _pause_signal: Arc<AtomicBool>,
    ) -> Result<()> {
        Ok(())
    }

    fn resume(
        &self,
        _state: Arc<(Mutex<CpuLifecycleState>, Condvar)>,
        _pause_signal: Arc<AtomicBool>,
    ) -> Result<()> {
        Ok(())
    }

    fn destroy(
        &self,
        _task: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
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

        let mut locked_cpu_state = cpu_state.lock().unwrap();
        locked_cpu_state = cvar
            .wait_timeout(locked_cpu_state, Duration::from_millis(10))
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

impl MigrateOps for TestHypervisor {
    fn get_mem_slots(&self) -> Arc<Mutex<HashMap<u32, MigrateMemSlot>>> {
        Arc::new(Mutex::new(HashMap::new()))
    }

    fn get_dirty_log(&self, _slot: u32, _mem_size: u64) -> Result<Vec<u64>> {
        Err(anyhow!(
            "Failed to get dirty log, mst doesn't support migration feature."
        ))
    }

    fn start_dirty_log(&self) -> Result<()> {
        Err(anyhow!(
            "Failed to start dirty log, mst doesn't support migration feature."
        ))
    }

    fn stop_dirty_log(&self) -> Result<()> {
        Err(anyhow!(
            "Failed to stop dirty log, mst doesn't support migration feature."
        ))
    }

    fn register_instance(&self) -> Result<()> {
        Ok(())
    }
}

struct TestInterruptManager {}

impl TestInterruptManager {
    #[cfg(target_arch = "x86_64")]
    pub fn arch_map_irq(&self, gsi: u32) -> u32 {
        gsi
    }

    #[cfg(target_arch = "aarch64")]
    pub fn arch_map_irq(&self, gsi: u32) -> u32 {
        gsi + GIC_IRQ_INTERNAL
    }

    pub fn add_msix_msg(addr: u64, data: u32) {
        let new_msg = MsixMsg::new(addr, data);
        let mut msix_list_lock = TEST_MSIX_LIST.lock().unwrap();

        for msg in msix_list_lock.iter() {
            if new_msg.addr == msg.addr && new_msg.data == msg.data {
                return;
            }
        }

        msix_list_lock.push(new_msg);
    }
}

impl LineIrqManager for TestInterruptManager {
    fn irqfd_enable(&self) -> bool {
        false
    }

    fn register_irqfd(
        &self,
        _irq_fd: Arc<EventFd>,
        _irq: u32,
        _trigger_mode: TriggerMode,
    ) -> Result<()> {
        Err(anyhow!(
            "Failed to register irqfd, mst doesn't support irqfd feature."
        ))
    }

    fn unregister_irqfd(&self, _irq_fd: Arc<EventFd>, _irq: u32) -> Result<()> {
        Err(anyhow!(
            "Failed to unregister irqfd, mst doesn't support irqfd feature."
        ))
    }

    fn set_level_irq(&self, gsi: u32, level: bool) -> Result<()> {
        let physical_irq = self.arch_map_irq(gsi);
        let level: i8 = if level { 1 } else { 0 };

        let mut intx_list_lock = TEST_INTX_LIST.lock().unwrap();

        for intx in intx_list_lock.iter_mut() {
            if intx.irq == physical_irq {
                intx.level = level;
                return Ok(());
            }
        }

        let new_intx = IntxInfo::new(physical_irq, level);
        intx_list_lock.push(new_intx);
        Ok(())
    }

    fn set_edge_irq(&self, _gsi: u32) -> Result<()> {
        Ok(())
    }

    fn write_irqfd(&self, _irq_fd: Arc<EventFd>) -> Result<()> {
        Err(anyhow!(
            "Failed to write irqfd, mst doesn't support irqfd feature."
        ))
    }
}

impl MsiIrqManager for TestInterruptManager {
    fn irqfd_enable(&self) -> bool {
        false
    }

    fn allocate_irq(&self, _vector: MsiVector) -> Result<u32> {
        Err(anyhow!(
            "Failed to allocate irq, mst doesn't support irq routing feature."
        ))
    }

    fn release_irq(&self, _irq: u32) -> Result<()> {
        Err(anyhow!(
            "Failed to release irq, mst doesn't support irq routing feature."
        ))
    }

    fn register_irqfd(&self, _irq_fd: Arc<EventFd>, _irq: u32) -> Result<()> {
        Err(anyhow!(
            "Failed to register msi irqfd, mst doesn't support irqfd feature."
        ))
    }

    fn unregister_irqfd(&self, _irq_fd: Arc<EventFd>, _irq: u32) -> Result<()> {
        Err(anyhow!(
            "Failed to unregister msi irqfd, mst doesn't support irqfd feature."
        ))
    }

    fn trigger(
        &self,
        _irq_fd: Option<Arc<EventFd>>,
        vector: MsiVector,
        _dev_id: u32,
    ) -> Result<()> {
        let data = vector.msg_data;
        let mut addr: u64 = vector.msg_addr_hi as u64;
        addr = (addr << 32) + vector.msg_addr_lo as u64;
        TestInterruptManager::add_msix_msg(addr, data);
        Ok(())
    }

    fn update_route_table(&self, _gsi: u32, _vector: MsiVector) -> Result<()> {
        Err(anyhow!(
            "Failed to update route table, mst doesn't support irq routing feature."
        ))
    }
}
