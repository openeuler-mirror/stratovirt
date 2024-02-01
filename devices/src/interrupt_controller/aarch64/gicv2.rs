// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::marker::{Send, Sync};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use log::error;

use super::{GICConfig, GICDevice};
use crate::interrupt_controller::InterruptError;
use address_space::AddressSpace;
use machine_manager::machine::{MachineLifecycle, VmState};
use util::device_tree::{self, FdtBuilder};

// See arch/arm64/include/uapi/asm/kvm.h file from the linux kernel.
const VGIC_V2_DIST_SIZE: u64 = 0x1000;
const VGIC_V2_CPU_SIZE: u64 = 0x2000;

/// Configure a v2 Interrupt controller.
pub struct GICv2Config {
    /// GIC distributor address range.
    pub dist_range: (u64, u64),
    /// GIC cpu interface address range.
    pub cpu_range: (u64, u64),
    /// GIC v2m range .
    pub v2m_range: Option<(u64, u64)>,
    /// GIC system memory.
    pub sys_mem: Option<Arc<AddressSpace>>,
}

/// Access wrapper for GICv2.
pub trait GICv2Access: Send + Sync {
    fn init_gic(&self, nr_irqs: u32, dist_base: u64, cpu_if_base: u64) -> Result<()>;

    /// Returns `gicr_attr` of `vCPU`.
    fn vcpu_gicr_attr(&self, offset: u64, cpu: usize) -> u64;

    fn access_gic_distributor(&self, offset: u64, gicd_value: &mut u32, write: bool) -> Result<()>;

    fn access_gic_cpu(
        &self,
        offset: u64,
        cpu: usize,
        gicc_value: &mut u64,
        write: bool,
    ) -> Result<()>;

    fn pause(&self) -> Result<()>;
}

#[derive(Default)]
struct GicCpuInterfaceRegion {
    /// Base address.
    base: u64,
    /// Size of Cpu Interface region.
    size: u64,
}

#[derive(Default)]
struct GicDistGuestRegion {
    /// Base address.
    base: u64,
    /// Size of Cpu Interface region.
    size: u64,
}

/// A wrapper around creating and managing a `GICv2`.
pub struct GICv2 {
    /// The handler for the GICv2 device to access the corresponding device in hypervisor.
    pub hypervisor_gic: Arc<dyn GICv2Access>,
    /// Maximum irq number.
    nr_irqs: u32,
    /// GICv2 cpu interface region.
    cpu_interface_region: GicCpuInterfaceRegion,
    /// Guest physical address space of the GICv2 distributor register mappings.
    dist_guest_region: GicDistGuestRegion,
    /// Lifecycle state for GICv2.
    state: Arc<Mutex<VmState>>,
}

impl GICv2 {
    pub fn new(hypervisor_gic: Arc<dyn GICv2Access>, config: &GICConfig) -> Result<Self> {
        let v2config = match config.v2.as_ref() {
            Some(v2) => v2,
            None => {
                return Err(anyhow!(InterruptError::InvalidConfig(
                    "no v2 config found".to_string()
                )))
            }
        };

        let cpu_interface_region = GicCpuInterfaceRegion {
            base: v2config.dist_range.0 + VGIC_V2_DIST_SIZE,
            size: VGIC_V2_CPU_SIZE,
        };
        let dist_guest_region = GicDistGuestRegion {
            base: v2config.dist_range.0,
            size: v2config.dist_range.1,
        };

        Ok(GICv2 {
            hypervisor_gic,
            nr_irqs: config.max_irq,
            cpu_interface_region,
            dist_guest_region,
            state: Arc::new(Mutex::new(VmState::Created)),
        })
    }
}

impl MachineLifecycle for GICv2 {
    fn pause(&self) -> bool {
        if self.hypervisor_gic.pause().is_ok() {
            *self.state.lock().unwrap() = VmState::Running;
            true
        } else {
            false
        }
    }

    fn notify_lifecycle(&self, old: VmState, new: VmState) -> bool {
        let state = self.state.lock().unwrap();
        if *state != old {
            error!("GICv2 lifecycle error: state check failed.");
            return false;
        }
        drop(state);

        match (old, new) {
            (VmState::Running, VmState::Paused) => self.pause(),
            _ => true,
        }
    }
}

impl GICDevice for GICv2 {
    fn realize(&self) -> Result<()> {
        let dist_base = self.dist_guest_region.base;
        let cpu_if_base = self.cpu_interface_region.base;
        self.hypervisor_gic
            .init_gic(self.nr_irqs, dist_base, cpu_if_base)?;

        *self.state.lock().unwrap() = VmState::Running;

        Ok(())
    }

    fn generate_fdt(&self, fdt: &mut FdtBuilder) -> Result<()> {
        let gic_reg = vec![
            self.dist_guest_region.base,
            self.dist_guest_region.size,
            self.cpu_interface_region.base,
            self.cpu_interface_region.size,
        ];

        let intc_node_dep = fdt.begin_node("intc")?;
        fdt.set_property_string("compatible", "arm,cortex-a15-gic")?;
        fdt.set_property("interrupt-controller", &Vec::new())?;
        fdt.set_property_u32("#interrupt-cells", 0x3)?;
        fdt.set_property_u32("phandle", device_tree::GIC_PHANDLE)?;
        fdt.set_property_u32("#address-cells", 0x2)?;
        fdt.set_property_u32("#size-cells", 0x2)?;
        fdt.set_property_array_u64("reg", &gic_reg)?;

        let gic_intr = [
            device_tree::GIC_FDT_IRQ_TYPE_PPI,
            0x9,
            device_tree::IRQ_TYPE_LEVEL_HIGH,
        ];

        fdt.set_property_array_u32("interrupts", &gic_intr)?;

        fdt.end_node(intc_node_dep)?;

        Ok(())
    }
}
