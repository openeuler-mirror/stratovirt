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
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use byteorder::{ByteOrder, LittleEndian};
use vmm_sys_util::eventfd::EventFd;

use super::error::LegacyError;
use crate::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysBusDevType, SysRes};
use crate::{Device, DeviceBase};
use acpi::AmlBuilder;
use address_space::GuestAddress;
use migration::{
    snapshot::PL031_SNAPSHOT_ID, DeviceStateDesc, FieldDesc, MigrationError, MigrationHook,
    MigrationManager, StateTransfer,
};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;
use util::num_ops::write_data_u32;

/// Registers for pl031 from ARM PrimeCell Real Time Clock Technical Reference Manual.
/// Data Register.
pub const RTC_DR: u64 = 0x00;
/// Match Register.
const RTC_MR: u64 = 0x04;
/// Load Register.
pub const RTC_LR: u64 = 0x08;
/// Control Register.
pub const RTC_CR: u64 = 0x0c;
/// Interrupt Mask Set or Clear Register.
pub const RTC_IMSC: u64 = 0x10;
/// Raw Interrupt Status Register.
const RTC_RIS: u64 = 0x14;
/// Masked Interrupt Status Register.
const RTC_MIS: u64 = 0x18;
/// Interrupt Clear Register.
const RTC_ICR: u64 = 0x1c;
/// Peripheral ID registers, default value.
const RTC_PERIPHERAL_ID: [u8; 8] = [0x31, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];

#[allow(clippy::upper_case_acronyms)]
/// Status of `PL031` device.
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
struct PL031State {
    /// Match register value.
    mr: u32,
    /// Load register value.
    lr: u32,
    /// Interrupt mask set or clear register value.
    imsr: u32,
    /// Raw interrupt status register value.
    risr: u32,
}

#[allow(clippy::upper_case_acronyms)]
/// PL031 structure.
pub struct PL031 {
    base: SysBusDevBase,
    /// State of device PL031.
    state: PL031State,
    /// The duplicate of Load register value.
    tick_offset: u32,
    /// Record the real time.
    base_time: Instant,
}

impl Default for PL031 {
    fn default() -> Self {
        Self {
            base: SysBusDevBase::new(SysBusDevType::Rtc),
            state: PL031State::default(),
            // since 1970-01-01 00:00:00,it never cause overflow.
            tick_offset: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time wrong")
                .as_secs() as u32,
            base_time: Instant::now(),
        }
    }
}

impl PL031 {
    pub fn realize(
        mut self,
        sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
    ) -> Result<()> {
        self.base.interrupt_evt = Some(Arc::new(EventFd::new(libc::EFD_NONBLOCK)?));
        self.set_sys_resource(sysbus, region_base, region_size)
            .with_context(|| LegacyError::SetSysResErr)?;

        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_device(&dev, region_base, region_size, "PL031")?;

        MigrationManager::register_device_instance(
            PL031State::descriptor(),
            dev,
            PL031_SNAPSHOT_ID,
        );

        Ok(())
    }

    /// Get current clock value.
    fn get_current_value(&self) -> u32 {
        (self.base_time.elapsed().as_secs() as u128 + self.tick_offset as u128) as u32
    }
}

impl Device for PL031 {
    fn device_base(&self) -> &DeviceBase {
        &self.base.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base.base
    }
}

impl SysBusDevOps for PL031 {
    fn sysbusdev_base(&self) -> &SysBusDevBase {
        &self.base
    }

    fn sysbusdev_base_mut(&mut self) -> &mut SysBusDevBase {
        &mut self.base
    }

    /// Read data from registers by guest.
    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        if (0xFE0..0x1000).contains(&offset) {
            let value = u32::from(RTC_PERIPHERAL_ID[((offset - 0xFE0) >> 2) as usize]);
            return write_data_u32(data, value);
        }

        let mut value: u32 = 0;
        match offset {
            RTC_DR => value = self.get_current_value(),
            RTC_MR => value = self.state.mr,
            RTC_LR => value = self.state.lr,
            RTC_CR => value = 1,
            RTC_IMSC => value = self.state.imsr,
            RTC_RIS => value = self.state.risr,
            RTC_MIS => value = self.state.risr & self.state.imsr,
            _ => {}
        }
        trace::pl031_read(offset, value);

        write_data_u32(data, value)
    }

    /// Write data to registers by guest.
    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        let value = LittleEndian::read_u32(data);
        trace::pl031_write(offset, value);

        match offset {
            RTC_MR => {
                // TODO: The MR register is used for implementing the RTC alarm. A RTC alarm is a
                // feature that can be used to allow a computer to 'wake up' after shut down to
                // execute tasks every day or on a certain day. It can sometimes be found in the
                // 'Power Management' section of motherboard's BIOS setup. This RTC alarm function
                // is not implemented yet, here is a reminder just in case.
                self.state.mr = value;
            }
            RTC_LR => {
                self.state.lr = value;
                self.tick_offset = value;
                self.base_time = Instant::now();
            }
            RTC_IMSC => {
                self.state.imsr = value & 1;
                self.inject_interrupt();
                trace::pl031_inject_interrupt();
            }
            RTC_ICR => {
                self.state.risr = 0;
                self.inject_interrupt();
                trace::pl031_inject_interrupt();
            }
            _ => {}
        }

        true
    }

    fn get_sys_resource_mut(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.base.res)
    }
}

impl AmlBuilder for PL031 {
    fn aml_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl StateTransfer for PL031 {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let state = self.state;

        Ok(state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
        self.state = *PL031State::from_bytes(state)
            .with_context(|| MigrationError::FromBytesError("PL031"))?;

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&PL031State::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for PL031 {}

#[cfg(test)]
mod test {
    use super::*;
    use util::time::mktime64;

    const WIGGLE: u32 = 2;

    #[test]
    fn test_set_year_20xx() {
        let mut rtc = PL031::default();
        // Set rtc time: 2013-11-13 02:04:56.
        let mut wtick = mktime64(2013, 11, 13, 2, 4, 56) as u32;
        let mut data = [0; 4];
        LittleEndian::write_u32(&mut data, wtick);
        PL031::write(&mut rtc, &mut data, GuestAddress(0), RTC_LR);

        PL031::read(&mut rtc, &mut data, GuestAddress(0), RTC_DR);
        let mut rtick = LittleEndian::read_u32(&data);

        assert!((rtick - wtick) <= WIGGLE);

        // Set rtc time: 2080-11-13 02:04:56, ensure there is no year-2080 overflow.
        wtick = mktime64(2080, 11, 13, 2, 4, 56) as u32;
        data = [0; 4];
        LittleEndian::write_u32(&mut data, wtick);
        PL031::write(&mut rtc, &mut data, GuestAddress(0), RTC_LR);

        PL031::read(&mut rtc, &mut data, GuestAddress(0), RTC_DR);
        rtick = LittleEndian::read_u32(&data);

        assert!((rtick - wtick) <= WIGGLE);
    }

    #[test]
    fn test_set_year_1970() {
        let mut rtc = PL031::default();
        // Set rtc time (min): 1970-01-01 00:00:00.
        let wtick = mktime64(1970, 1, 1, 0, 0, 0) as u32;
        let mut data = [0; 4];
        LittleEndian::write_u32(&mut data, wtick);
        PL031::write(&mut rtc, &mut data, GuestAddress(0), RTC_LR);

        PL031::read(&mut rtc, &mut data, GuestAddress(0), RTC_DR);
        let rtick = LittleEndian::read_u32(&data);

        assert!((rtick - wtick) <= WIGGLE);
    }
}
