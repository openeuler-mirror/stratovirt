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

mod syscall;

use std::sync::{Arc, Condvar, Mutex};

use address_space::{AddressSpace, Region};
use boot_loader::{load_linux, BootLoaderConfig};
use cpu::{CPUBootConfig, CpuTopology, CPU};
use devices::legacy::PL031;
use devices::{InterruptController, InterruptControllerConfig};
use kvm_ioctls::{Kvm, VmFd};
use machine_manager::config::{
    BalloonConfig, BootSource, ConsoleConfig, DriveConfig, NetworkInterfaceConfig, SerialConfig,
    VmConfig, VsockConfig,
};
use machine_manager::machine::KvmVmState;
use pci::PciHost;
use sysbus::SysBus;
use util::seccomp::BpfRule;
use vmm_sys_util::eventfd::EventFd;

use super::StdMachineOps;
use crate::errors::{ErrorKind, Result};
use crate::MachineOps;
use syscall::syscall_whitelist;

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

impl MachineOps for StdMachine {
    fn arch_ram_ranges(&self, mem_size: u64) -> Vec<(u64, u64)> {
        // ranges is the vector of (start_addr, size)
        let mut ranges = Vec::<(u64, u64)>::new();
        ranges.push((MEM_LAYOUT[LayoutEntryType::Mem as usize].0, mem_size));

        ranges
    }

    fn init_interrupt_controller(&mut self, vm_fd: &Arc<VmFd>, vcpu_count: u64) -> Result<()> {
        let intc_conf = InterruptControllerConfig {
            version: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            vcpu_count,
            max_irq: 192,
            msi: true,
            dist_range: MEM_LAYOUT[LayoutEntryType::GicDist as usize],
            redist_region_ranges: vec![
                MEM_LAYOUT[LayoutEntryType::GicRedist as usize],
                MEM_LAYOUT[LayoutEntryType::HighGicRedist as usize],
            ],
            its_range: Some(MEM_LAYOUT[LayoutEntryType::GicIts as usize]),
        };
        let irq_chip = InterruptController::new(vm_fd.clone(), &intc_conf)?;
        self.irq_chip = Some(Arc::new(irq_chip));
        self.irq_chip.as_ref().unwrap().realize()?;
        Ok(())
    }

    fn load_boot_source(&self) -> Result<CPUBootConfig> {
        use crate::errors::ResultExt;

        let mut boot_source = self.boot_source.lock().unwrap();
        let initrd = boot_source.initrd.as_ref().map(|b| b.initrd_file.clone());

        let bootloader_config = BootLoaderConfig {
            kernel: boot_source.kernel_file.clone(),
            initrd,
            mem_start: MEM_LAYOUT[LayoutEntryType::Mem as usize].0,
        };
        let layout =
            load_linux(&bootloader_config, &self.sys_mem).chain_err(|| ErrorKind::LoadKernErr)?;
        if let Some(rd) = &mut boot_source.initrd {
            rd.initrd_addr = layout.initrd_start;
            rd.initrd_size = layout.initrd_size;
        }

        Ok(CPUBootConfig {
            fdt_addr: layout.dtb_start,
            kernel_addr: layout.kernel_start,
        })
    }

    fn add_rtc_device(&mut self, vm_fd: &Arc<VmFd>) -> Result<()> {
        use crate::errors::ResultExt;

        let rtc = PL031::default();
        PL031::realize(
            rtc,
            &mut self.sysbus,
            MEM_LAYOUT[LayoutEntryType::Rtc as usize].0,
            MEM_LAYOUT[LayoutEntryType::Rtc as usize].1,
            vm_fd,
        )
        .chain_err(|| "Failed to realize PL031")?;
        Ok(())
    }

    fn add_serial_device(&mut self, _config: &SerialConfig, _vm_fd: &Arc<VmFd>) -> Result<()> {
        Ok(())
    }

    fn add_block_device(&mut self, _config: &DriveConfig) -> Result<()> {
        Ok(())
    }

    fn add_vsock_device(&mut self, _config: &VsockConfig, _vm_fd: &Arc<VmFd>) -> Result<()> {
        Ok(())
    }

    fn add_net_device(
        &mut self,
        _config: &NetworkInterfaceConfig,
        _vm_fd: &Arc<VmFd>,
    ) -> Result<()> {
        Ok(())
    }

    fn add_console_device(&mut self, _config: &ConsoleConfig, _vm_fd: &Arc<VmFd>) -> Result<()> {
        Ok(())
    }

    fn add_balloon_device(&mut self, _config: &BalloonConfig, _vm_fd: &Arc<VmFd>) -> Result<()> {
        Ok(())
    }

    fn add_devices(&mut self, vm_config: &VmConfig, vm_fd: &Arc<VmFd>) -> Result<()> {
        use crate::errors::ResultExt;

        if let Some(serial) = vm_config.serial.as_ref() {
            self.add_serial_device(&serial, vm_fd)
                .chain_err(|| ErrorKind::AddDevErr("serial".to_string()))?;
        }

        if let Some(vsock) = vm_config.vsock.as_ref() {
            self.add_vsock_device(&vsock, vm_fd)
                .chain_err(|| ErrorKind::AddDevErr("vsock".to_string()))?;
        }

        if let Some(drives) = vm_config.drives.as_ref() {
            for drive in drives {
                self.add_block_device(&drive)
                    .chain_err(|| ErrorKind::AddDevErr("block".to_string()))?;
            }
        }

        if let Some(nets) = vm_config.nets.as_ref() {
            for net in nets {
                self.add_net_device(&net, vm_fd)
                    .chain_err(|| ErrorKind::AddDevErr("net".to_string()))?;
            }
        }

        if let Some(consoles) = vm_config.consoles.as_ref() {
            for console in consoles {
                self.add_console_device(&console, vm_fd)
                    .chain_err(|| ErrorKind::AddDevErr("console".to_string()))?;
            }
        }

        if let Some(balloon) = vm_config.balloon.as_ref() {
            self.add_balloon_device(balloon, vm_fd)
                .chain_err(|| ErrorKind::AddDevErr("balloon".to_string()))?;
        }

        Ok(())
    }

    fn syscall_whitelist(&self) -> Vec<BpfRule> {
        syscall_whitelist()
    }

    fn realize(
        _vm: &Arc<Mutex<Self>>,
        _vm_config: &VmConfig,
        _fds: (Kvm, &Arc<VmFd>),
    ) -> Result<()> {
        Ok(())
    }
}
