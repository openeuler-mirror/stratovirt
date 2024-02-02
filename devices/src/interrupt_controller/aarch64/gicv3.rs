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

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use log::{error, info};

use super::{GICConfig, GICDevice};
use crate::interrupt_controller::error::InterruptError;
use machine_manager::machine::{MachineLifecycle, VmState};
use migration::StateTransfer;
use util::device_tree::{self, FdtBuilder};

// See arch/arm64/include/uapi/asm/kvm.h file from the linux kernel.
const SZ_64K: u64 = 0x0001_0000;
const VGIC_V3_REDIST_SIZE: u64 = 2 * SZ_64K;

/// Configure a v3 Interrupt controller.
pub struct GICv3Config {
    /// Config msi support
    pub msi: bool,
    /// GIC distributor address range.
    pub dist_range: (u64, u64),
    /// GIC redistributor address range, support multiple redistributor regions.
    pub redist_region_ranges: Vec<(u64, u64)>,
    /// GIC ITS address ranges.
    pub its_range: Option<(u64, u64)>,
}

/// Access wrapper for GICv3.
pub trait GICv3Access: Send + Sync {
    fn init_gic(
        &self,
        nr_irqs: u32,
        redist_regions: Vec<GicRedistRegion>,
        dist_base: u64,
    ) -> Result<()>;

    /// Returns `gicr_attr` of `vCPU`.
    fn vcpu_gicr_attr(&self, cpu: usize) -> u64;

    fn access_gic_distributor(&self, offset: u64, gicd_value: &mut u32, write: bool) -> Result<()>;

    fn access_gic_redistributor(
        &self,
        offset: u64,
        cpu: usize,
        gicr_value: &mut u32,
        write: bool,
    ) -> Result<()>;

    fn access_gic_cpu(
        &self,
        offset: u64,
        cpu: usize,
        gicc_value: &mut u64,
        write: bool,
    ) -> Result<()>;

    fn access_gic_line_level(&self, offset: u64, gicll_value: &mut u32, write: bool) -> Result<()>;

    fn pause(&self) -> Result<()>;
}

#[derive(Clone, Copy)]
pub struct GicRedistRegion {
    /// Base address.
    pub base: u64,
    /// Size of redistributor region.
    size: u64,
    /// Attribute of redistributor region.
    pub base_attr: u64,
}

/// A wrapper around creating and managing a `GICv3`.
pub struct GICv3 {
    /// The handler for the GICv3 device to access the corresponding device in hypervisor.
    pub hypervisor_gic: Arc<dyn GICv3Access>,
    /// Number of vCPUs, determines the number of redistributor and CPU interface.
    pub(crate) vcpu_count: u64,
    /// GICv3 ITS device.
    pub its_dev: Option<Arc<GICv3Its>>,
    /// Maximum irq number.
    pub(crate) nr_irqs: u32,
    /// GICv3 redistributor info, support multiple redistributor regions.
    pub redist_regions: Vec<GicRedistRegion>,
    /// Base address in the guest physical address space of the GICv3 distributor
    /// register mappings.
    dist_base: u64,
    /// GICv3 distributor region size.
    dist_size: u64,
    /// Lifecycle state for GICv3.
    state: Arc<Mutex<VmState>>,
}

impl GICv3 {
    pub fn new(
        hypervisor_gic: Arc<dyn GICv3Access>,
        its_handler: Arc<dyn GICv3ItsAccess>,
        config: &GICConfig,
    ) -> Result<Self> {
        let v3config = match config.v3.as_ref() {
            Some(v3) => v3,
            None => {
                return Err(anyhow!(InterruptError::InvalidConfig(
                    "no v3 config found".to_string()
                )))
            }
        };

        // Calculate GIC redistributor regions' address range according to vcpu count.
        let base = v3config.redist_region_ranges[0].0;
        let size = v3config.redist_region_ranges[0].1;
        let redist_capability = size / VGIC_V3_REDIST_SIZE;
        let redist_region_count = std::cmp::min(config.vcpu_count, redist_capability);
        let mut redist_regions = vec![GicRedistRegion {
            base,
            size,
            base_attr: (redist_region_count << 52) | base,
        }];

        if config.vcpu_count > redist_capability {
            let high_redist_base = v3config.redist_region_ranges[1].0;
            let high_redist_region_count = config.vcpu_count - redist_capability;
            let high_redist_attr = (high_redist_region_count << 52) | high_redist_base | 0x1;

            redist_regions.push(GicRedistRegion {
                base: high_redist_base,
                size: high_redist_region_count * VGIC_V3_REDIST_SIZE,
                base_attr: high_redist_attr,
            })
        }

        let mut gicv3 = GICv3 {
            hypervisor_gic,
            vcpu_count: config.vcpu_count,
            nr_irqs: config.max_irq,
            its_dev: None,
            redist_regions,
            dist_base: v3config.dist_range.0,
            dist_size: v3config.dist_range.1,
            state: Arc::new(Mutex::new(VmState::Created)),
        };

        if let Some(its_range) = v3config.its_range {
            gicv3.its_dev = Some(Arc::new(GICv3Its::new(its_handler, &its_range)));
        }

        Ok(gicv3)
    }

    fn reset_its_state(&self) -> Result<()> {
        if let Some(its) = &self.its_dev {
            its.reset()?;
        }

        Ok(())
    }

    fn reset_gic_state(&self) -> Result<()> {
        let reset_state = self.create_reset_state()?;
        self.set_state(&reset_state)
            .with_context(|| "Failed to reset gic")
    }

    pub(crate) fn access_gic_distributor(
        &self,
        offset: u64,
        gicd_value: &mut u32,
        write: bool,
    ) -> Result<()> {
        self.hypervisor_gic
            .access_gic_distributor(offset, gicd_value, write)
    }

    pub(crate) fn access_gic_redistributor(
        &self,
        offset: u64,
        cpu: usize,
        gicr_value: &mut u32,
        write: bool,
    ) -> Result<()> {
        self.hypervisor_gic
            .access_gic_redistributor(offset, cpu, gicr_value, write)
    }

    pub(crate) fn access_gic_cpu(
        &self,
        offset: u64,
        cpu: usize,
        gicc_value: &mut u64,
        write: bool,
    ) -> Result<()> {
        self.hypervisor_gic
            .access_gic_cpu(offset, cpu, gicc_value, write)
    }

    pub(crate) fn access_gic_line_level(
        &self,
        offset: u64,
        gicll_value: &mut u32,
        write: bool,
    ) -> Result<()> {
        self.hypervisor_gic
            .access_gic_line_level(offset, gicll_value, write)
    }
}

impl MachineLifecycle for GICv3 {
    fn pause(&self) -> bool {
        // VM change state will flush REDIST pending tables into guest RAM.
        if let Err(e) = self.hypervisor_gic.pause() {
            error!(
                "Failed to flush REDIST pending tables into guest RAM, error: {:?}",
                e
            );
            return false;
        }

        // The ITS tables need to be flushed into guest RAM before VM pause.
        if let Some(its_dev) = &self.its_dev {
            if let Err(e) = its_dev.its_handler.access_gic_its_tables(true) {
                error!("Failed to access GIC ITS tables, error: {:?}", e);
                return false;
            }
        }

        let mut state = self.state.lock().unwrap();
        *state = VmState::Running;

        true
    }

    fn notify_lifecycle(&self, old: VmState, new: VmState) -> bool {
        let state = self.state.lock().unwrap();
        if *state != old {
            error!("GICv3 lifecycle error: state check failed.");
            return false;
        }
        drop(state);

        match (old, new) {
            (VmState::Running, VmState::Paused) => self.pause(),
            _ => true,
        }
    }
}

impl GICDevice for GICv3 {
    fn realize(&self) -> Result<()> {
        self.hypervisor_gic
            .init_gic(self.nr_irqs, self.redist_regions.clone(), self.dist_base)
            .with_context(|| "Failed to init GICv3")?;

        if let Some(its) = &self.its_dev {
            its.realize().with_context(|| "Failed to realize ITS")?;
        }

        let mut state = self.state.lock().unwrap();
        *state = VmState::Running;

        Ok(())
    }

    fn generate_fdt(&self, fdt: &mut FdtBuilder) -> Result<()> {
        let redist_count = self.redist_regions.len() as u32;
        let mut gic_reg = vec![self.dist_base, self.dist_size];

        for redist in &self.redist_regions {
            gic_reg.push(redist.base);
            gic_reg.push(redist.size);
        }

        let node = "intc";
        let intc_node_dep = fdt.begin_node(node)?;
        fdt.set_property_string("compatible", "arm,gic-v3")?;
        fdt.set_property("interrupt-controller", &Vec::new())?;
        fdt.set_property_u32("#interrupt-cells", 0x3)?;
        fdt.set_property_u32("phandle", device_tree::GIC_PHANDLE)?;
        fdt.set_property_u32("#address-cells", 0x2)?;
        fdt.set_property_u32("#size-cells", 0x2)?;
        fdt.set_property_u32("#redistributor-regions", redist_count)?;
        fdt.set_property_array_u64("reg", &gic_reg)?;

        let gic_intr = [
            device_tree::GIC_FDT_IRQ_TYPE_PPI,
            0x9,
            device_tree::IRQ_TYPE_LEVEL_HIGH,
        ];
        fdt.set_property_array_u32("interrupts", &gic_intr)?;

        if let Some(its) = &self.its_dev {
            fdt.set_property("ranges", &Vec::new())?;
            let its_reg = [its.msi_base, its.msi_size];
            let node = "its";
            let its_node_dep = fdt.begin_node(node)?;
            fdt.set_property_string("compatible", "arm,gic-v3-its")?;
            fdt.set_property("msi-controller", &Vec::new())?;
            fdt.set_property_u32("phandle", device_tree::GIC_ITS_PHANDLE)?;
            fdt.set_property_array_u64("reg", &its_reg)?;
            fdt.end_node(its_node_dep)?;
        }
        fdt.end_node(intc_node_dep)?;

        Ok(())
    }

    fn reset(&self) -> Result<()> {
        info!("Reset gicv3its");
        self.reset_its_state()?;
        info!("Reset gicv3");
        self.reset_gic_state()
    }

    fn get_redist_count(&self) -> u8 {
        self.redist_regions.len() as u8
    }
}

pub trait GICv3ItsAccess: Send + Sync {
    fn init_gic_its(&self, msi_base: u64) -> Result<()>;

    fn access_gic_its(&self, attr: u32, its_value: &mut u64, write: bool) -> Result<()>;

    fn access_gic_its_tables(&self, save: bool) -> Result<()>;

    fn reset(&self) -> Result<()>;
}

pub struct GICv3Its {
    /// The handler for the GICv3Its device to access the corresponding device in hypervisor.
    pub its_handler: Arc<dyn GICv3ItsAccess>,

    /// Base address in the guest physical address space of the GICv3 ITS
    /// control register frame.
    msi_base: u64,

    /// GICv3 ITS needs to be 64K aligned and the region covers 128K.
    msi_size: u64,
}

impl GICv3Its {
    fn new(its_handler: Arc<dyn GICv3ItsAccess>, its_range: &(u64, u64)) -> Self {
        GICv3Its {
            its_handler,
            msi_base: its_range.0,
            msi_size: its_range.1,
        }
    }

    fn realize(&self) -> Result<()> {
        self.its_handler.init_gic_its(self.msi_base)?;

        Ok(())
    }

    pub(crate) fn access_gic_its(&self, attr: u32, its_value: &mut u64, write: bool) -> Result<()> {
        self.its_handler.access_gic_its(attr, its_value, write)
    }

    pub(crate) fn access_gic_its_tables(&self, save: bool) -> Result<()> {
        self.its_handler.access_gic_its_tables(save)
    }

    pub(crate) fn reset(&self) -> Result<()> {
        self.its_handler.reset()
    }
}
