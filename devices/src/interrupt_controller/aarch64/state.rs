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

use std::mem::size_of;

use libc::c_uint;

use super::gicv3::{GICv3, GICv3Access};
use super::GIC_IRQ_INTERNAL;
use crate::interrupt_controller::errors::Result;

/// Register data length can be get by `get_device_attr/set_device_attr` in kvm once.
const REGISTER_SIZE: u64 = size_of::<c_uint>() as u64;

/// Distributor registers, as offsets from the distributor base address
/// See: https://elixir.bootlin.com/linux/v5.6-rc5/source/include/linux/irqchip/arm-gic-v3.h
const GICD_CTLR: u64 = 0x0000;
const GICD_STATUSR: u64 = 0x0010;
const GICD_IGROUPR: u64 = 0x0080;
const GICD_ISENABLER: u64 = 0x0100;
const GICD_ISPENDR: u64 = 0x0200;
const GICD_ISACTIVER: u64 = 0x0300;
const GICD_IPRIORITYR: u64 = 0x0400;
const GICD_ICFGR: u64 = 0x0C00;
const GICD_IROUTER: u64 = 0x6000;
const NR_GICD_ICFGR: usize = 2;
const NR_GICD_IPRIORITYR: usize = 8;
const NR_GICD_IROUTER: usize = 32;

/// Redistributor registers, offsets from RD_base
const GICR_CTLR: u64 = 0x0000;
const GICR_TYPER: u64 = 0x0008;
const GICR_STATUSR: u64 = 0x0010;
const GICR_WAKER: u64 = 0x0014;
const GICR_PROPBASER: u64 = 0x0070;
const GICR_PENDBASER: u64 = 0x0078;

/// SGI and PPI Redistributor registers, offsets from RD_base
const GICR_IGROUPR0: u64 = 0x1_0080;
const GICR_ISENABLER0: u64 = 0x1_0100;
const GICR_ISPENDR0: u64 = 0x1_0200;
const GICR_ISACTIVER0: u64 = 0x1_0300;
const GICR_IPRIORITYR: u64 = 0x1_0400;
const GICR_ICFGR1: u64 = 0x1_0C04;
const NR_GICR_IPRIORITYR: usize = 8;

/// The status of GICv3 redistributor.
#[repr(C)]
#[derive(Copy, Clone, ByteCode)]
struct GICv3RedistState {
    vcpu: usize,
    edge_trigger: u32,
    gicr_ctlr: u32,
    gicr_statusr: u32,
    gicr_waker: u32,
    gicr_igroupr0: u32,
    gicr_ienabler0: u32,
    gicr_ipendr0: u32,
    gicr_iactiver0: u32,
    gicr_propbaser_l: u32,
    gicr_propbaser_h: u32,
    gicr_pendbaser_l: u32,
    gicr_pendbaser_h: u32,
    gicr_ipriorityr: [u32; 8],
}

/// The status of GICv3 distributor.
#[repr(C)]
#[derive(Copy, Clone, ByteCode)]
struct GICv3DistState {
    irq_base: u64,
    gicd_igroupr: u32,
    gicd_isenabler: u32,
    gicd_ispendr: u32,
    gicd_isactiver: u32,
    gicd_icfgr: [u32; 2],
    gicd_ipriorityr: [u32; 8],
    gicd_irouter_l: [u32; 32],
    gicd_irouter_h: [u32; 32],
    line_level: u32,
}

impl GICv3 {
    fn get_redist(&self, cpu: usize, plpis: bool) -> Result<GICv3RedistState> {
        let mut redist = GICv3RedistState {
            vcpu: cpu,
            ..Default::default()
        };

        self.access_gic_redistributor(GICR_CTLR, redist.vcpu, &mut redist.gicr_ctlr, false)?;
        self.access_gic_redistributor(GICR_STATUSR, redist.vcpu, &mut redist.gicr_statusr, false)?;
        self.access_gic_redistributor(GICR_WAKER, redist.vcpu, &mut redist.gicr_waker, false)?;
        self.access_gic_redistributor(
            GICR_IGROUPR0,
            redist.vcpu,
            &mut redist.gicr_igroupr0,
            false,
        )?;
        self.access_gic_redistributor(
            GICR_ISENABLER0,
            redist.vcpu,
            &mut redist.gicr_ienabler0,
            false,
        )?;
        self.access_gic_redistributor(GICR_ICFGR1, redist.vcpu, &mut redist.edge_trigger, false)?;
        self.access_gic_redistributor(GICR_ISPENDR0, redist.vcpu, &mut redist.gicr_ipendr0, false)?;
        self.access_gic_redistributor(
            GICR_ISACTIVER0,
            redist.vcpu,
            &mut redist.gicr_iactiver0,
            false,
        )?;

        for i in 0..NR_GICR_IPRIORITYR {
            self.access_gic_redistributor(
                GICR_IPRIORITYR + REGISTER_SIZE * i as u64,
                redist.vcpu,
                &mut redist.gicr_ipriorityr[i],
                false,
            )?;
        }

        // gic redistributor type is PLPIS
        if plpis {
            self.access_gic_redistributor(
                GICR_PROPBASER,
                redist.vcpu,
                &mut redist.gicr_propbaser_l,
                false,
            )?;
            self.access_gic_redistributor(
                GICR_PROPBASER + REGISTER_SIZE,
                redist.vcpu,
                &mut redist.gicr_propbaser_h,
                false,
            )?;
            self.access_gic_redistributor(
                GICR_PENDBASER,
                redist.vcpu,
                &mut redist.gicr_pendbaser_l,
                false,
            )?;
            self.access_gic_redistributor(
                GICR_PENDBASER + REGISTER_SIZE,
                redist.vcpu,
                &mut redist.gicr_pendbaser_h,
                false,
            )?;
        }

        Ok(redist)
    }

    fn set_redist(&self, mut redist: GICv3RedistState, plpis: bool) -> Result<()> {
        self.access_gic_redistributor(GICR_CTLR, redist.vcpu, &mut redist.gicr_ctlr, true)?;
        self.access_gic_redistributor(GICR_STATUSR, redist.vcpu, &mut redist.gicr_statusr, true)?;
        self.access_gic_redistributor(GICR_WAKER, redist.vcpu, &mut redist.gicr_waker, true)?;
        self.access_gic_redistributor(GICR_IGROUPR0, redist.vcpu, &mut redist.gicr_igroupr0, true)?;
        self.access_gic_redistributor(
            GICR_ISENABLER0,
            redist.vcpu,
            &mut redist.gicr_ienabler0,
            true,
        )?;

        self.access_gic_redistributor(GICR_ICFGR1, redist.vcpu, &mut redist.edge_trigger, true)?;
        self.access_gic_redistributor(GICR_ISPENDR0, redist.vcpu, &mut redist.gicr_ipendr0, true)?;
        self.access_gic_redistributor(
            GICR_ISACTIVER0,
            redist.vcpu,
            &mut redist.gicr_iactiver0,
            true,
        )?;

        for i in 0..NR_GICR_IPRIORITYR {
            self.access_gic_redistributor(
                GICR_IPRIORITYR + REGISTER_SIZE * i as u64,
                redist.vcpu,
                &mut redist.gicr_ipriorityr[i],
                true,
            )?;
        }

        // gic redistributor type is PLPIS
        if plpis {
            self.access_gic_redistributor(
                GICR_PROPBASER,
                redist.vcpu,
                &mut redist.gicr_propbaser_l,
                true,
            )?;
            self.access_gic_redistributor(
                GICR_PROPBASER + REGISTER_SIZE,
                redist.vcpu,
                &mut redist.gicr_propbaser_h,
                true,
            )?;
            self.access_gic_redistributor(
                GICR_PENDBASER,
                redist.vcpu,
                &mut redist.gicr_pendbaser_l,
                true,
            )?;
            self.access_gic_redistributor(
                GICR_PENDBASER + REGISTER_SIZE,
                redist.vcpu,
                &mut redist.gicr_pendbaser_h,
                true,
            )?;
        }

        Ok(())
    }

    fn get_dist(&self, irq_base: u64) -> Result<GICv3DistState> {
        let mut dist = GICv3DistState {
            irq_base,
            ..Default::default()
        };

        // edge trigger
        for i in 0..NR_GICD_ICFGR {
            if ((i * GIC_IRQ_INTERNAL as usize / NR_GICD_ICFGR) as u64 + dist.irq_base)
                > self.nr_irqs as u64
            {
                break;
            }
            let offset = (dist.irq_base + i as u64) / REGISTER_SIZE;
            self.access_gic_distributor(GICD_ICFGR + offset, &mut dist.gicd_icfgr[i], false)?;
        }

        for i in 0..NR_GICD_IPRIORITYR {
            if (i as u64 * REGISTER_SIZE + dist.irq_base) > self.nr_irqs as u64 {
                break;
            }
            let offset = dist.irq_base + REGISTER_SIZE * i as u64;
            self.access_gic_distributor(
                GICD_IPRIORITYR + offset,
                &mut dist.gicd_ipriorityr[i],
                false,
            )?;
        }

        for i in 0..NR_GICD_IROUTER {
            if (i as u64 + dist.irq_base) > self.nr_irqs as u64 {
                break;
            }
            let offset = dist.irq_base + i as u64;

            self.access_gic_distributor(GICD_IROUTER + offset, &mut dist.gicd_irouter_l[i], false)?;
            self.access_gic_distributor(
                GICD_IROUTER + offset + REGISTER_SIZE,
                &mut dist.gicd_irouter_h[i],
                false,
            )?;
        }

        if (dist.irq_base + GIC_IRQ_INTERNAL as u64) > self.nr_irqs as u64 {
            return Ok(dist);
        }

        let offset = dist.irq_base / (GIC_IRQ_INTERNAL as u64 / REGISTER_SIZE);
        self.access_gic_distributor(GICD_IGROUPR + offset, &mut dist.gicd_igroupr, false)?;
        self.access_gic_distributor(GICD_ISENABLER + offset, &mut dist.gicd_isenabler, false)?;
        self.access_gic_distributor(GICD_ISPENDR + offset, &mut dist.gicd_ispendr, false)?;
        self.access_gic_distributor(GICD_ISACTIVER + offset, &mut dist.gicd_isactiver, false)?;
        self.access_gic_line_level(dist.irq_base, &mut dist.line_level, false)?;

        Ok(dist)
    }

    fn set_dist(&self, mut dist: GICv3DistState) -> Result<()> {
        // edge trigger
        for i in 0..NR_GICD_ICFGR {
            if ((i * GIC_IRQ_INTERNAL as usize / NR_GICD_ICFGR) as u64 + dist.irq_base)
                > self.nr_irqs as u64
            {
                break;
            }
            let offset = (dist.irq_base + i as u64) / REGISTER_SIZE;
            self.access_gic_distributor(GICD_ICFGR + offset, &mut dist.gicd_icfgr[i], true)?;
        }

        for i in 0..NR_GICD_IPRIORITYR {
            if (i as u64 * REGISTER_SIZE + dist.irq_base) > self.nr_irqs as u64 {
                break;
            }
            let offset = dist.irq_base + REGISTER_SIZE * i as u64;
            self.access_gic_distributor(
                GICD_IPRIORITYR + offset,
                &mut dist.gicd_ipriorityr[i],
                true,
            )?;
        }

        for i in 0..NR_GICD_IROUTER {
            if (i as u64 + dist.irq_base) > self.nr_irqs as u64 {
                break;
            }
            let offset = dist.irq_base + i as u64;

            self.access_gic_distributor(GICD_IROUTER + offset, &mut dist.gicd_irouter_l[i], true)?;
            self.access_gic_distributor(
                GICD_IROUTER + offset + REGISTER_SIZE,
                &mut dist.gicd_irouter_h[i],
                true,
            )?;
        }

        if (dist.irq_base + GIC_IRQ_INTERNAL as u64) > self.nr_irqs as u64 {
            return Ok(());
        }

        let offset = dist.irq_base / (GIC_IRQ_INTERNAL as u64 / REGISTER_SIZE);
        self.access_gic_distributor(GICD_IGROUPR + offset, &mut dist.gicd_igroupr, true)?;
        self.access_gic_distributor(GICD_ISENABLER + offset, &mut dist.gicd_isenabler, true)?;
        self.access_gic_distributor(GICD_ISPENDR + offset, &mut dist.gicd_ispendr, true)?;
        self.access_gic_distributor(GICD_ISACTIVER + offset, &mut dist.gicd_isactiver, true)?;
        self.access_gic_line_level(dist.irq_base, &mut dist.line_level, true)?;

        Ok(())
    }
}
