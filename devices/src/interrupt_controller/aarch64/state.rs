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
use crate::interrupt_controller::errors::Result;

/// Register data length can be get by `get_device_attr/set_device_attr` in kvm once.
const REGISTER_SIZE: u64 = size_of::<c_uint>() as u64;

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
}
