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

use anyhow::{Context, Result};
use libc::c_uint;

use super::gicv3::{GICv3, GICv3Its};
use super::GIC_IRQ_INTERNAL;
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;

/// Register data length can be get in hypervisor once.
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
const NR_GICR_IPRIORITYR: usize = 8;

/// SGI and PPI Redistributor registers, offsets from RD_base
const GICR_IGROUPR0: u64 = 0x1_0080;
const GICR_ISENABLER0: u64 = 0x1_0100;
const GICR_ICENABLER0: u64 = 0x1_0180;
const GICR_ISPENDR0: u64 = 0x1_0200;
const GICR_ICPENDR0: u64 = 0x1_0280;
const GICR_ISACTIVER0: u64 = 0x1_0300;
const GICR_ICACTIVER0: u64 = 0x1_0380;
const GICR_IPRIORITYR: u64 = 0x1_0400;
const GICR_ICFGR1: u64 = 0x1_0C04;

/// GIC CPU interface registers
const ICC_PMR_EL1: u64 = 0xc230;
const ICC_BPR0_EL1: u64 = 0xc643;
const ICC_AP0R_EL1_N0: u64 = 0xc644;
const ICC_AP0R_EL1_N1: u64 = 0xc645;
const ICC_AP0R_EL1_N2: u64 = 0xc646;
const ICC_AP0R_EL1_N3: u64 = 0xc647;
const ICC_AP1R_EL1_N0: u64 = 0xc648;
const ICC_AP1R_EL1_N1: u64 = 0xc649;
const ICC_AP1R_EL1_N2: u64 = 0xc64a;
const ICC_AP1R_EL1_N3: u64 = 0xc64b;
const ICC_BPR1_EL1: u64 = 0xc663;
const ICC_CTLR_EL1: u64 = 0xc664;
const ICC_SRE_EL1: u64 = 0xc665;
const ICC_IGRPEN0_EL1: u64 = 0xc666;
const ICC_IGRPEN1_EL1: u64 = 0xc667;
/// GICv3 CPU interface control register pribits[8:10]
const ICC_CTLR_EL1_PRIBITS_MASK: u64 = 0x700;
const ICC_CTLR_EL1_PRIBITS_SHIFT: u64 = 0x8;

/// GIC Its registers
const GITS_CTLR: u32 = 0x0000;
const GITS_IIDR: u32 = 0x0004;
const GITS_CBASER: u32 = 0x0080;
const GITS_CWRITER: u32 = 0x0088;
const GITS_CREADR: u32 = 0x0090;
const GITS_BASER: u32 = 0x0100;

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
    gicd_statusr: u32,
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

/// The status of GICv3 CPU.
#[repr(C)]
#[derive(Copy, Clone, ByteCode)]
struct GICv3CPUState {
    vcpu: usize,
    icc_pmr_el1: u64,
    icc_bpr0_el1: u64,
    icc_ap0r_el1: [u64; 4],
    icc_ap1r_el1: [u64; 4],
    icc_bpr1_el1: u64,
    icc_sre_el1: u64,
    icc_ctlr_el1: u64,
    icc_igrpen0_el1: u64,
    icc_igrpen1_el1: u64,
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

        self.access_gic_redistributor(GICR_CTLR, redist.vcpu, &mut redist.gicr_ctlr, true)?;
        self.access_gic_redistributor(GICR_STATUSR, redist.vcpu, &mut redist.gicr_statusr, true)?;
        self.access_gic_redistributor(GICR_WAKER, redist.vcpu, &mut redist.gicr_waker, true)?;
        self.access_gic_redistributor(GICR_IGROUPR0, redist.vcpu, &mut redist.gicr_igroupr0, true)?;
        self.access_gic_redistributor(GICR_ICENABLER0, redist.vcpu, &mut !0, true)?;
        self.access_gic_redistributor(
            GICR_ISENABLER0,
            redist.vcpu,
            &mut redist.gicr_ienabler0,
            true,
        )?;
        self.access_gic_redistributor(GICR_ICFGR1, redist.vcpu, &mut redist.edge_trigger, true)?;
        self.access_gic_redistributor(GICR_ICPENDR0, redist.vcpu, &mut !0, true)?;
        self.access_gic_redistributor(GICR_ISPENDR0, redist.vcpu, &mut redist.gicr_ipendr0, true)?;
        self.access_gic_redistributor(GICR_ICACTIVER0, redist.vcpu, &mut !0, true)?;
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

        Ok(())
    }

    fn get_dist(&self, irq_base: u64) -> Result<GICv3DistState> {
        let mut dist = GICv3DistState {
            irq_base,
            ..Default::default()
        };

        let offset = dist.irq_base / (GIC_IRQ_INTERNAL as u64 / REGISTER_SIZE);
        self.access_gic_distributor(GICD_IGROUPR + offset, &mut dist.gicd_igroupr, false)?;
        self.access_gic_distributor(GICD_ISENABLER + offset, &mut dist.gicd_isenabler, false)?;
        self.access_gic_distributor(dist.irq_base, &mut dist.line_level, false)?;
        self.access_gic_distributor(GICD_ISPENDR + offset, &mut dist.gicd_ispendr, false)?;
        self.access_gic_distributor(GICD_ISACTIVER + offset, &mut dist.gicd_isactiver, false)?;

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

        Ok(dist)
    }

    fn set_dist(&self, mut dist: GICv3DistState) -> Result<()> {
        let offset = dist.irq_base / (GIC_IRQ_INTERNAL as u64 / REGISTER_SIZE);
        self.access_gic_distributor(GICD_ISENABLER + offset, &mut dist.gicd_isenabler, true)?;
        self.access_gic_distributor(GICD_IGROUPR + offset, &mut dist.gicd_igroupr, true)?;

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

        self.access_gic_line_level(dist.irq_base, &mut dist.line_level, true)?;
        self.access_gic_distributor(GICD_ISPENDR + offset, &mut dist.gicd_ispendr, true)?;
        self.access_gic_distributor(GICD_ISACTIVER + offset, &mut dist.gicd_isactiver, true)?;

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

        Ok(())
    }

    fn get_cpu(&self, cpu: usize) -> Result<GICv3CPUState> {
        let mut gic_cpu = GICv3CPUState {
            vcpu: cpu,
            ..Default::default()
        };

        self.access_gic_cpu(ICC_SRE_EL1, gic_cpu.vcpu, &mut gic_cpu.icc_sre_el1, false)?;
        self.access_gic_cpu(ICC_CTLR_EL1, gic_cpu.vcpu, &mut gic_cpu.icc_ctlr_el1, false)?;
        self.access_gic_cpu(
            ICC_IGRPEN0_EL1,
            gic_cpu.vcpu,
            &mut gic_cpu.icc_igrpen0_el1,
            false,
        )?;
        self.access_gic_cpu(
            ICC_IGRPEN1_EL1,
            gic_cpu.vcpu,
            &mut gic_cpu.icc_igrpen1_el1,
            false,
        )?;
        self.access_gic_cpu(ICC_PMR_EL1, gic_cpu.vcpu, &mut gic_cpu.icc_pmr_el1, false)?;
        self.access_gic_cpu(ICC_BPR0_EL1, gic_cpu.vcpu, &mut gic_cpu.icc_bpr0_el1, false)?;
        self.access_gic_cpu(ICC_BPR1_EL1, gic_cpu.vcpu, &mut gic_cpu.icc_bpr1_el1, false)?;

        // ICC_CTLR_EL1.PRIbits is [10:8] in ICC_CTLR_EL1
        // PRIBits indicate the number of priority bits implemented, independently for each target
        // PE.
        let icc_ctlr_el1_pri =
            ((gic_cpu.icc_ctlr_el1 & ICC_CTLR_EL1_PRIBITS_MASK) >> ICC_CTLR_EL1_PRIBITS_SHIFT) + 1;
        // Save APnR registers based on ICC_CTLR_EL1.PRIBITS
        match icc_ctlr_el1_pri {
            0b111 => {
                self.access_gic_cpu(
                    ICC_AP0R_EL1_N3,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap0r_el1[3],
                    false,
                )?;
                self.access_gic_cpu(
                    ICC_AP0R_EL1_N2,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap0r_el1[2],
                    false,
                )?;
                self.access_gic_cpu(
                    ICC_AP1R_EL1_N3,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap1r_el1[3],
                    false,
                )?;
                self.access_gic_cpu(
                    ICC_AP1R_EL1_N2,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap1r_el1[2],
                    false,
                )?;
            }
            0b110 => {
                self.access_gic_cpu(
                    ICC_AP0R_EL1_N1,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap0r_el1[1],
                    false,
                )?;
                self.access_gic_cpu(
                    ICC_AP1R_EL1_N1,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap1r_el1[1],
                    false,
                )?;
            }
            _ => {
                self.access_gic_cpu(
                    ICC_AP0R_EL1_N0,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap0r_el1[0],
                    false,
                )?;
                self.access_gic_cpu(
                    ICC_AP1R_EL1_N0,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap1r_el1[0],
                    false,
                )?;
            }
        }

        Ok(gic_cpu)
    }

    fn set_cpu(&self, mut gic_cpu: GICv3CPUState) -> Result<()> {
        self.access_gic_cpu(ICC_SRE_EL1, gic_cpu.vcpu, &mut gic_cpu.icc_sre_el1, true)?;
        self.access_gic_cpu(ICC_CTLR_EL1, gic_cpu.vcpu, &mut gic_cpu.icc_ctlr_el1, true)?;
        self.access_gic_cpu(
            ICC_IGRPEN0_EL1,
            gic_cpu.vcpu,
            &mut gic_cpu.icc_igrpen0_el1,
            true,
        )?;
        self.access_gic_cpu(
            ICC_IGRPEN1_EL1,
            gic_cpu.vcpu,
            &mut gic_cpu.icc_igrpen1_el1,
            true,
        )?;
        self.access_gic_cpu(ICC_PMR_EL1, gic_cpu.vcpu, &mut gic_cpu.icc_pmr_el1, true)?;
        self.access_gic_cpu(ICC_BPR0_EL1, gic_cpu.vcpu, &mut gic_cpu.icc_bpr0_el1, true)?;
        self.access_gic_cpu(ICC_BPR1_EL1, gic_cpu.vcpu, &mut gic_cpu.icc_bpr1_el1, true)?;

        // ICC_CTLR_EL1.PRIbits is [10:8] in ICC_CTLR_EL1
        // PRIBits indicate the number of priority bits implemented, independently for each target
        // PE.
        let icc_ctlr_el1_pri =
            ((gic_cpu.icc_ctlr_el1 & ICC_CTLR_EL1_PRIBITS_MASK) >> ICC_CTLR_EL1_PRIBITS_SHIFT) + 1;
        // Restore APnR registers based on ICC_CTLR_EL1.PRIBITS
        match icc_ctlr_el1_pri {
            0b111 => {
                self.access_gic_cpu(
                    ICC_AP0R_EL1_N3,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap0r_el1[3],
                    true,
                )?;
                self.access_gic_cpu(
                    ICC_AP0R_EL1_N2,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap0r_el1[2],
                    true,
                )?;
                self.access_gic_cpu(
                    ICC_AP1R_EL1_N3,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap1r_el1[3],
                    true,
                )?;
                self.access_gic_cpu(
                    ICC_AP1R_EL1_N2,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap1r_el1[2],
                    true,
                )?;
            }
            0b110 => {
                self.access_gic_cpu(
                    ICC_AP0R_EL1_N1,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap0r_el1[1],
                    true,
                )?;
                self.access_gic_cpu(
                    ICC_AP1R_EL1_N1,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap1r_el1[1],
                    true,
                )?;
            }
            _ => {
                self.access_gic_cpu(
                    ICC_AP0R_EL1_N0,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap0r_el1[0],
                    true,
                )?;
                self.access_gic_cpu(
                    ICC_AP1R_EL1_N0,
                    gic_cpu.vcpu,
                    &mut gic_cpu.icc_ap1r_el1[0],
                    true,
                )?;
            }
        }

        Ok(())
    }

    pub(crate) fn create_reset_state(&self) -> Result<Vec<u8>> {
        let mut gic_state = GICv3State::default();

        self.access_gic_redistributor(GICR_TYPER, 0, &mut gic_state.redist_typer_l, false)
            .with_context(|| "create_reset_state: redist_typer_l")?;
        self.access_gic_redistributor(GICR_TYPER + 4, 0, &mut gic_state.redist_typer_h, false)
            .with_context(|| "create_reset_state: redist_typer_h")?;

        // process cpu-state and redistriburor
        gic_state.iccr_len = self.vcpu_count as usize;
        gic_state.redist_len = self.vcpu_count as usize;
        for cpu in 0..self.vcpu_count {
            let mut gic_cpu = GICv3CPUState {
                vcpu: cpu as usize,
                ..Default::default()
            };

            gic_cpu.icc_sre_el1 = 0x7;

            // initialize to hardware supported configuration
            self.access_gic_cpu(ICC_CTLR_EL1, cpu as usize, &mut gic_cpu.icc_ctlr_el1, false)
                .with_context(|| format!("create_reset_state: VCPU-{} icc_ctlr_el1", cpu))?;

            gic_state.vcpu_iccr[cpu as usize] = gic_cpu;
            // setup redist state
            gic_state.vcpu_redist[cpu as usize] = GICv3RedistState {
                vcpu: cpu as usize,
                ..Default::default()
            }
        }

        // process distributor
        gic_state.dist_len = (self.nr_irqs / 32) as usize;

        Ok(gic_state.as_bytes().to_vec())
    }
}

/// The status of GICv3 interrupt controller.
#[repr(C)]
#[derive(Clone, Copy, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct GICv3State {
    redist_typer_l: u32,
    redist_typer_h: u32,
    gicd_ctlr: u32,
    gicd_statusr: u32,
    redist_len: usize,
    // vcpu redistributor length is less than max vcpu number 255
    vcpu_redist: [GICv3RedistState; 255],
    dist_len: usize,
    // irq dist is less than 8(255/32)
    irq_dist: [GICv3DistState; 8],
    iccr_len: usize,
    // vcpu iccr length is less than max vcpu number 255
    vcpu_iccr: [GICv3CPUState; 255],
}

impl StateTransfer for GICv3 {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        use migration::MigrationError;

        let mut state = GICv3State::default();

        self.access_gic_redistributor(GICR_TYPER, 0, &mut state.redist_typer_l, false)
            .map_err(|e| MigrationError::GetGicRegsError("redist_typer_l", e.to_string()))?;
        self.access_gic_redistributor(GICR_TYPER + 4, 0, &mut state.redist_typer_h, false)
            .map_err(|e| MigrationError::GetGicRegsError("redist_typer_h", e.to_string()))?;
        self.access_gic_distributor(GICD_CTLR, &mut state.gicd_ctlr, false)
            .map_err(|e| MigrationError::GetGicRegsError("gicd_ctlr", e.to_string()))?;

        let plpis = (state.redist_typer_l & 1) != 0;
        for cpu in 0..self.vcpu_count {
            state.vcpu_redist[state.redist_len] = self
                .get_redist(cpu as usize, plpis)
                .map_err(|e| MigrationError::GetGicRegsError("redist", e.to_string()))?;
            state.redist_len += 1;
        }

        self.access_gic_distributor(GICD_STATUSR, &mut state.gicd_statusr, false)
            .map_err(|e| MigrationError::GetGicRegsError("gicd_statusr", e.to_string()))?;
        for irq in (GIC_IRQ_INTERNAL..self.nr_irqs).step_by(32) {
            state.irq_dist[state.dist_len] = self
                .get_dist(irq as u64)
                .map_err(|e| MigrationError::GetGicRegsError("dist", e.to_string()))?;
            state.dist_len += 1;
        }

        for cpu in 0..self.vcpu_count {
            state.vcpu_iccr[state.iccr_len] = self
                .get_cpu(cpu as usize)
                .map_err(|e| MigrationError::GetGicRegsError("cpu", e.to_string()))?;
            state.iccr_len += 1;
        }

        Ok(state.as_bytes().to_vec())
    }

    fn set_state(&self, state: &[u8]) -> Result<()> {
        use migration::error::MigrationError;

        let state = GICv3State::from_bytes(state).unwrap();

        let mut regu32 = state.redist_typer_l;
        self.access_gic_redistributor(GICR_TYPER, 0, &mut regu32, false)
            .map_err(|e| MigrationError::SetGicRegsError("gicr_typer_l", e.to_string()))?;
        let plpis: bool = regu32 & 1 != 0;
        regu32 = state.redist_typer_h;
        self.access_gic_redistributor(GICR_TYPER + 4, 0, &mut regu32, false)
            .map_err(|e| MigrationError::SetGicRegsError("gicr_typer_h", e.to_string()))?;

        regu32 = state.gicd_ctlr;
        self.access_gic_distributor(GICD_CTLR, &mut regu32, true)
            .map_err(|e| MigrationError::SetGicRegsError("gicd_ctlr", e.to_string()))?;

        for gicv3_redist in state.vcpu_redist[0..state.redist_len].iter() {
            self.set_redist(*gicv3_redist, plpis)
                .map_err(|e| MigrationError::SetGicRegsError("redist", e.to_string()))?;
        }

        regu32 = state.gicd_statusr;
        self.access_gic_distributor(GICD_STATUSR, &mut regu32, true)
            .map_err(|e| MigrationError::SetGicRegsError("gicd_statusr", e.to_string()))?;

        for gicv3_dist in state.irq_dist[0..state.dist_len].iter() {
            self.set_dist(*gicv3_dist)
                .map_err(|e| MigrationError::SetGicRegsError("dist", e.to_string()))?
        }

        for gicv3_iccr in state.vcpu_iccr[0..state.iccr_len].iter() {
            self.set_cpu(*gicv3_iccr)
                .map_err(|e| MigrationError::SetGicRegsError("cpu", e.to_string()))?;
        }

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&GICv3State::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for GICv3 {}

// The state of GICv3Its device.
#[repr(C)]
#[derive(Clone, Copy, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct GICv3ItsState {
    ctlr: u64,
    iidr: u64,
    cbaser: u64,
    cwriter: u64,
    creadr: u64,
    baser: [u64; 8],
}

impl StateTransfer for GICv3Its {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        use migration::MigrationError;

        let mut state = GICv3ItsState::default();
        for i in 0..8 {
            self.access_gic_its(GITS_BASER + 8 * i as u32, &mut state.baser[i], false)
                .map_err(|e| MigrationError::GetGicRegsError("Its baser", e.to_string()))?;
        }
        self.access_gic_its(GITS_CTLR, &mut state.ctlr, false)
            .map_err(|e| MigrationError::GetGicRegsError("Its ctlr", e.to_string()))?;
        self.access_gic_its(GITS_CBASER, &mut state.cbaser, false)
            .map_err(|e| MigrationError::GetGicRegsError("Its cbaser", e.to_string()))?;
        self.access_gic_its(GITS_CREADR, &mut state.creadr, false)
            .map_err(|e| MigrationError::GetGicRegsError("Its creadr", e.to_string()))?;
        self.access_gic_its(GITS_CWRITER, &mut state.cwriter, false)
            .map_err(|e| MigrationError::GetGicRegsError("Its cwriter", e.to_string()))?;
        self.access_gic_its(GITS_IIDR, &mut state.iidr, false)
            .map_err(|e| MigrationError::GetGicRegsError("Its iidr", e.to_string()))?;

        Ok(state.as_bytes().to_vec())
    }

    fn set_state(&self, state: &[u8]) -> Result<()> {
        use migration::MigrationError;

        let mut its_state = *GICv3ItsState::from_bytes(state)
            .with_context(|| MigrationError::FromBytesError("GICv3Its"))?;

        self.access_gic_its(GITS_IIDR, &mut its_state.iidr, true)
            .map_err(|e| MigrationError::SetGicRegsError("Its iidr", e.to_string()))?;
        // It must be written before GITS_CREADR, because GITS_CBASER write access will reset
        // GITS_CREADR.
        self.access_gic_its(GITS_CBASER, &mut its_state.cbaser, true)
            .map_err(|e| MigrationError::SetGicRegsError("Its cbaser", e.to_string()))?;
        self.access_gic_its(GITS_CREADR, &mut its_state.creadr, true)
            .map_err(|e| MigrationError::SetGicRegsError("Its readr", e.to_string()))?;
        self.access_gic_its(GITS_CWRITER, &mut its_state.cwriter, true)
            .map_err(|e| MigrationError::SetGicRegsError("Its cwriter", e.to_string()))?;

        for i in 0..8 {
            self.access_gic_its(GITS_BASER + 8 * i as u32, &mut its_state.baser[i], true)
                .map_err(|e| MigrationError::SetGicRegsError("Its baser", e.to_string()))?;
        }
        self.access_gic_its_tables(false)
            .map_err(|e| MigrationError::SetGicRegsError("Its table", e.to_string()))?;
        self.access_gic_its(GITS_CTLR, &mut its_state.ctlr, true)
            .map_err(|e| MigrationError::SetGicRegsError("Its ctlr", e.to_string()))?;

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&GICv3ItsState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for GICv3Its {}
