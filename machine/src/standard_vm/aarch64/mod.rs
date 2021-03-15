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

use std::sync::{Arc, Condvar, Mutex};

use address_space::{AddressSpace, Region};
use cpu::{CpuTopology, CPU};
use devices::InterruptController;
use kvm_ioctls::VmFd;
use machine_manager::config::{BootSource, VmConfig};
use machine_manager::machine::KvmVmState;
use pci::PciHost;
use sysbus::SysBus;
use vmm_sys_util::eventfd::EventFd;

use super::StdMachineOps;
use crate::errors::{ErrorKind, Result};

/// The type of memory layout entry on aarch64
#[allow(dead_code)]
pub enum LayoutEntryType {
    Flash = 0,
    GicDist,
    GicCpu,
    GicIts,
    GicRedist,
    Uart,
    Rtc,
    FwCfg,
    Mmio,
    PcieMmio,
    PciePio,
    PcieEcam,
    Mem,
    HighGicRedist,
    HighPcieEcam,
    HighPcieMmio,
}

/// Layout of aarch64
pub const MEM_LAYOUT: &[(u64, u64)] = &[
    (0, 0x0800_0000),              // Flash
    (0x0800_0000, 0x0001_0000),    // GicDist
    (0x0801_0000, 0x0001_0000),    // GicCpu
    (0x0808_0000, 0x0002_0000),    // GicIts
    (0x080A_0000, 0x00F6_0000),    // GicRedist (max 123 redistributors)
    (0x0900_0000, 0x0000_1000),    // Uart
    (0x0901_0000, 0x0000_1000),    // Rtc
    (0x0902_0000, 0x0000_0018),    // FwCfg
    (0x0A00_0000, 0x0000_0200),    // Mmio
    (0x1000_0000, 0x2EFF_0000),    // PcieMmio
    (0x3EFF_0000, 0x0001_0000),    // PciePio
    (0x3F00_0000, 0x0100_0000),    // PcieEcam
    (0x4000_0000, 0x80_0000_0000), // Mem
    (256 << 30, 0x200_0000),       // HighGicRedist, (where remaining redistributors locates)
    (257 << 30, 0x1000_0000),      // HighPcieEcam
    (258 << 30, 512 << 30),        // HighPcieMmio
];

/// Standard machine structure.
pub struct StdMachine {
    /// `vCPU` topology, support sockets, cores, threads.
    cpu_topo: CpuTopology,
    /// `vCPU` devices.
    cpus: Vec<Arc<CPU>>,
    // Interrupt controller device.
    #[cfg(target_arch = "aarch64")]
    irq_chip: Option<Arc<InterruptController>>,
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
    pub fn new(vm_config: &VmConfig) -> Result<Self> {
        use crate::errors::ResultExt;

        let cpu_topo = CpuTopology::new(vm_config.machine_config.nr_cpus);
        let sys_mem = AddressSpace::new(Region::init_container_region(u64::max_value()))
            .chain_err(|| ErrorKind::CrtIoSpaceErr)?;
        let sysbus = SysBus::new(
            &sys_mem,
            (32, 192),
            (
                MEM_LAYOUT[LayoutEntryType::Mmio as usize].0,
                MEM_LAYOUT[LayoutEntryType::Mmio as usize + 1].0,
            ),
        );

        Ok(StdMachine {
            cpu_topo,
            cpus: Vec::new(),
            irq_chip: None,
            sys_mem: sys_mem.clone(),
            sysbus,
            pci_host: Arc::new(Mutex::new(PciHost::new(&sys_mem))),
            boot_source: Arc::new(Mutex::new(vm_config.clone().boot_source)),
            vm_state: Arc::new((Mutex::new(KvmVmState::Created), Condvar::new())),
            power_button: EventFd::new(libc::EFD_NONBLOCK)
                .chain_err(|| ErrorKind::InitPwrBtnErr)?,
        })
    }
}

impl StdMachineOps for StdMachine {
    fn init_pci_host(&self, _vm_fd: &Arc<VmFd>) -> super::errors::Result<()> {
        Ok(())
    }
}
