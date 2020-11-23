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

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use address_space::GuestAddress;
use byteorder::{ByteOrder, LittleEndian};
use kvm_ioctls::VmFd;
use vmm_sys_util::eventfd::EventFd;

use super::super::mmio::{
    errors::{Result, ResultExt},
    DeviceResource, DeviceType, MmioDeviceOps,
};
use super::super::DeviceOps;

/// Registers for pl032 from ARM PrimeCell Real Time Clock Technical Reference Manual.
/// Data Register.
const RTC_DR: u64 = 0x00;
/// Match Register.
const RTC_MR: u64 = 0x04;
/// Load Register.
const RTC_LR: u64 = 0x08;
/// Control Register.
const RTC_CR: u64 = 0x0c;
/// Interrupt Mask Set or Clear Register.
const RTC_IMSC: u64 = 0x10;
/// Raw Interrupt Status Register.
const RTC_RIS: u64 = 0x14;
/// Masked Interrupt Status Register.
const RTC_MIS: u64 = 0x18;
/// Interrupt Clear Register.
const RTC_ICR: u64 = 0x1c;
/// Peripheral ID registers, default value.
const RTC_PERIPHERAL_ID: [u8; 8] = [0x31, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];

/// Pl032 structure.
pub struct PL031 {
    /// Match register value.
    mr: u32,
    /// Load register value.
    lr: u32,
    /// Interrupt Mask Set or Clear register value.
    imsr: u32,
    /// Raw Interrupt Status register value.
    risr: u32,
    /// The duplicate of Load register value.
    tick_offset: u32,
    /// Record the real time.
    base_time: Instant,
    /// Interrupt eventfd.
    interrupt_evt: Option<EventFd>,
}

impl PL031 {
    pub fn new() -> Self {
        PL031 {
            mr: 0,
            lr: 0,
            imsr: 0,
            risr: 0,
            tick_offset: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time wrong")
                .as_secs() as u32, // since 1970-01-01 00:00:00,it never cause overflow.
            base_time: Instant::now(),
            interrupt_evt: None,
        }
    }

    /// Send interrupt to guest.
    fn interrupt(&self) {
        if let Some(evt) = &self.interrupt_evt {
            let _ = evt.write(1);
        }
    }

    /// Get current clock value.
    fn get_current_value(&self) -> u32 {
        self.base_time.elapsed().as_secs() as u32 + self.tick_offset
    }
}

impl DeviceOps for PL031 {
    /// Read data from registers by guest.
    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        if offset >= 0xFE0 && offset < 0x1000 {
            let value = u32::from(RTC_PERIPHERAL_ID[((offset - 0xFE0) >> 2) as usize]);
            LittleEndian::write_u32(data, value);
            return true;
        }

        let mut value: u32 = 0;
        match offset {
            RTC_DR => {
                value = self.get_current_value();
            }
            RTC_MR => {
                value = self.mr;
            }
            RTC_LR => {
                value = self.lr;
            }
            RTC_CR => {
                value = 1;
            }
            RTC_IMSC => {
                value = self.imsr;
            }
            RTC_RIS => {
                value = self.risr;
            }
            RTC_MIS => {
                value = self.risr & self.imsr;
            }
            _ => {}
        }

        LittleEndian::write_u32(data, value);

        true
    }

    /// Write data to registers by guest.
    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        let value = LittleEndian::read_u32(data);

        match offset {
            RTC_MR => {
                self.mr = value;
            }
            RTC_LR => {
                self.lr = value;
                self.tick_offset = value;
                self.base_time = Instant::now();
            }
            RTC_IMSC => {
                self.imsr = value & 1;
                self.interrupt();
            }
            RTC_ICR => {
                self.risr = 0;
                self.interrupt();
            }
            _ => {}
        }

        true
    }
}

impl MmioDeviceOps for PL031 {
    /// Realize RTC device when VM starting.
    fn realize(&mut self, vm_fd: &VmFd, resource: DeviceResource) -> Result<()> {
        match EventFd::new(libc::EFD_NONBLOCK) {
            Ok(evt) => {
                vm_fd
                    .register_irqfd(&evt, resource.irq)
                    .chain_err(|| "Failed to register irqfd")?;
                self.interrupt_evt = Some(evt);

                Ok(())
            }
            Err(_) => Err("Failed to create new EventFd".into()),
        }
    }

    /// Get device type.
    fn get_type(&self) -> DeviceType {
        DeviceType::RTC
    }
}
