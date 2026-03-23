// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
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

use anyhow::{Context, Result};
use log::{debug, error};
use vmm_sys_util::eventfd::EventFd;

use crate::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysBusDevType};
use crate::{convert_bus_mut, Device, DeviceBase, MUT_SYS_BUS};
use acpi::AmlBuilder;
use address_space::GuestAddress;
use util::gen_base_func;

/// IO port base of I8042 device.
const I8042_PORT_BASE: u64 = 0x61;

/// Offset from base for Port B register (port 0x61).
const I8042_PORT_B_REG: u64 = 0;
/// Offset from base for Command register (port 0x64).
const I8042_COMMAND_REG: u64 = 3;

/// Command byte for CPU reset.
const I8042_CMD_RESET: u8 = 0xFE;

/// i8042 PS/2 controller device. This is a minimal implementation that allows
/// the guest OS to trigger machine reset via port 0x64 with command 0xFE.
pub struct I8042 {
    base: SysBusDevBase,
    /// Reset request eventfd for triggering machine reset.
    reset_req: Arc<EventFd>,
}

impl I8042 {
    /// Construct function of I8042 device.
    ///
    /// # Arguments
    ///
    /// * `sysbus` - System bus reference.
    /// * `reset_req` - Reset request eventfd.
    pub fn new(sysbus: &Arc<Mutex<SysBus>>, reset_req: Arc<EventFd>) -> Result<I8042> {
        let mut i8042 = I8042 {
            base: SysBusDevBase::new(SysBusDevType::I8042),
            reset_req,
        };

        i8042
            .set_sys_resource(sysbus, I8042_PORT_BASE, 4, "I8042")
            .with_context(|| "Failed to allocate system resource for I8042.")?;
        i8042.set_parent_bus(sysbus.clone());

        Ok(i8042)
    }
}

impl Device for I8042 {
    gen_base_func!(device_base, device_base_mut, DeviceBase, base.base);

    fn realize(self) -> Result<Arc<Mutex<Self>>> {
        let parent_bus = self.parent_bus().unwrap().upgrade().unwrap();
        MUT_SYS_BUS!(parent_bus, locked_bus, sysbus);
        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_device(&dev)?;
        Ok(dev)
    }
}

impl SysBusDevOps for I8042 {
    gen_base_func!(sysbusdev_base, sysbusdev_base_mut, SysBusDevBase, base);

    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        if data.is_empty() {
            return false;
        }

        if offset == I8042_PORT_B_REG {
            // Return 0x20 to avoid pit_calibrate_tsc() hang in Linux kernel.
            data[0] = 0x20u8;
        } else if offset == I8042_COMMAND_REG {
            // No command pending.
            data[0] = 0x00u8;
        }

        trace::i8042_read(offset, data[0]);
        true
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        if data.is_empty() {
            return false;
        }

        // Only handle command register for reset command.
        if offset == I8042_COMMAND_REG && data[0] == I8042_CMD_RESET {
            debug!("I8042: Received CPU reset command 0xFE");
            // Trigger machine reset via reset_req eventfd.
            if let Err(e) = self.reset_req.write(1u64) {
                error!("I8042: Failed to trigger reset: {}", e);
            }
        }

        trace::i8042_write(offset, data[0]);
        true
    }

    fn set_sys_resource(
        &mut self,
        _sysbus: &Arc<Mutex<SysBus>>,
        region_base: u64,
        region_size: u64,
        region_name: &str,
    ) -> Result<()> {
        self.sysbusdev_base_mut()
            .set_sys(-1, region_base, region_size, region_name);
        Ok(())
    }
}

impl AmlBuilder for I8042 {
    fn aml_bytes(&self) -> Vec<u8> {
        // I8042 aims for being used in machine even without ACPI.
        Vec::new()
    }
}
