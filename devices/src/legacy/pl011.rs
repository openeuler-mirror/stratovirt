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

use std::io;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

use acpi::{
    AmlActiveLevel, AmlBuilder, AmlDevice, AmlEdgeLevel, AmlExtendedInterrupt, AmlIntShare,
    AmlInteger, AmlMemory32Fixed, AmlNameDecl, AmlReadAndWrite, AmlResTemplate, AmlResourceUsage,
    AmlScopeBuilder, AmlString,
};
use address_space::{errors::ResultExt, GuestAddress};
use byteorder::{ByteOrder, LittleEndian};
use machine_manager::config::{BootSource, Param};
use sysbus::{SysBus, SysBusDevOps, SysBusDevType, SysRes};
use util::byte_code::ByteCode;
use util::loop_context::{EventNotifier, EventNotifierHelper, NotifierOperation};
use util::set_termi_raw_mode;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::terminal::Terminal;

use crate::legacy::errors::Result;

const PL011_FLAG_TXFE: u8 = 0x80;
const PL011_FLAG_RXFF: u8 = 0x40;
const PL011_FLAG_RXFE: u8 = 0x10;

// Interrupt bits in UARTRIS, UARTMIS and UARTIMSC
// Receive timeout interrupt bit
const INT_RT: u32 = 1 << 6;
// Transmit interrupt bit
const INT_TX: u32 = 1 << 5;
// Receive interrupt bit
const INT_RX: u32 = 1 << 4;
// Framing/Panity/Break/Overrun error bits, bits 7~10.
const INT_E: u32 = 1 << 7 | 1 << 8 | 1 << 9 | 1 << 10;
// nUARTRI/nUARTCTS/nUARTDCD/nUARTDSR modem interrupt bits, bits 0~3.
const INT_MS: u32 = 1 | 1 << 1 | 1 << 2 | 1 << 3;

const PL011_FIFO_SIZE: usize = 16;

#[allow(clippy::upper_case_acronyms)]
pub struct PL011 {
    /// Read FIFO.
    rfifo: Vec<u32>,
    /// Flag Register.
    flags: u32,
    /// Line Control Register.
    lcr: u32,
    /// Receive Status Register.
    rsr: u32,
    /// Control Register.
    cr: u32,
    /// DMA Control Register.
    dmacr: u32,
    /// IrDA Low-Power Counter Register.
    ilpr: u32,
    /// Integer Baud Rate Register.
    ibrd: u32,
    /// Fractional Baud Rate Register.
    fbrd: u32,
    /// Interrut FIFO Level Select Register.
    ifl: u32,
    /// Identifier Register.
    id: Vec<u8>,
    /// FIFO Status.
    read_pos: i32,
    read_count: i32,
    read_trigger: i32,
    /// Raw Interrupt Status Register.
    int_level: u32,
    /// Interrupt Mask Set/Clear Register.
    int_enabled: u32,
    /// Interrupt event file descriptor.
    interrupt_evt: EventFd,
    /// Operation methods.
    output: Option<Box<dyn io::Write + Send + Sync>>,
    /// System Resource of device.
    res: SysRes,
}

impl PL011 {
    /// Create a new `PL011` instance with default parameters.
    pub fn new() -> Result<Self> {
        Ok(PL011 {
            rfifo: vec![0; PL011_FIFO_SIZE],
            flags: (PL011_FLAG_TXFE | PL011_FLAG_RXFE) as u32,
            lcr: 0,
            rsr: 0,
            cr: 0x300,
            dmacr: 0,
            ilpr: 0,
            ibrd: 0,
            fbrd: 0,
            ifl: 0x12, // Receive and transmit enable
            id: vec![0x11, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1],
            read_pos: 0,
            read_count: 0,
            read_trigger: 1,
            int_level: 0,
            int_enabled: 0,
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK)?,
            output: Some(Box::new(std::io::stdout())),
            res: SysRes::default(),
        })
    }

    fn interrupt(&self) {
        let irq_mask = INT_E | INT_MS | INT_RT | INT_TX | INT_RX;

        let flag = self.int_level & self.int_enabled;
        if flag & irq_mask != 0 {
            if let Err(e) = self.interrupt_evt.write(1) {
                error!(
                    "Failed to trigger interrupt for PL011, flag is 0x{:x}, error is {}",
                    flag, e,
                )
            }
        }
    }

    /// Append `data` to receiver buffer register, and trigger interrupt if necessary.
    ///
    /// # Arguments
    ///
    /// * `data` - A u8-type array.
    pub fn receive(&mut self, data: &[u8]) {
        self.flags &= !PL011_FLAG_RXFE as u32;
        for val in data {
            let mut slot = (self.read_pos + self.read_count) as usize;
            if slot >= PL011_FIFO_SIZE {
                slot -= PL011_FIFO_SIZE;
            }
            self.rfifo[slot] = *val as u32;
            self.read_count += 1;
        }

        // If in character-mode, or in FIFO-mode and FIFO is full, trigger the interrupt.
        if ((self.lcr & 0x10) == 0) || (self.read_count as usize == PL011_FIFO_SIZE) {
            self.flags |= PL011_FLAG_RXFF as u32;
        }
        if self.read_count >= self.read_trigger {
            self.int_level |= INT_RX as u32;
            self.interrupt();
        }
    }

    pub fn realize(
        mut self,
        sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
        bs: &Arc<Mutex<BootSource>>,
    ) -> Result<Arc<Mutex<Self>>> {
        set_termi_raw_mode().chain_err(|| "Failed to set terminal to raw mode")?;
        self.set_sys_resource(sysbus, region_base, region_size)
            .chain_err(|| "Failed to allocate system resource for PL011.")?;

        let dev = Arc::new(Mutex::new(self));
        sysbus
            .attach_device(&dev, region_base, region_size)
            .chain_err(|| "Failed to attach PL011 to system bus.")?;

        bs.lock().unwrap().kernel_cmdline.push(Param {
            param_type: "earlycon".to_string(),
            value: format!("pl011,mmio,0x{:08x}", region_base),
        });
        Ok(dev)
    }
}

impl SysBusDevOps for PL011 {
    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        let ret;

        match offset >> 2 {
            0 => {
                // Data register.
                self.flags &= !(PL011_FLAG_RXFF as u32);
                let c = self.rfifo[self.read_pos as usize];

                if self.read_count > 0 {
                    self.read_count -= 1;
                    self.read_pos += 1;
                    if self.read_pos as usize == PL011_FIFO_SIZE {
                        self.read_pos = 0;
                    }
                }
                if self.read_count == 0 {
                    self.flags |= PL011_FLAG_RXFE as u32;
                }
                if self.read_count == self.read_trigger - 1 {
                    self.int_level &= !(INT_RX as u32);
                }
                self.rsr = c >> 8;
                self.interrupt();
                ret = c;
            }
            1 => {
                ret = self.rsr;
            }
            6 => {
                ret = self.flags;
            }
            8 => {
                ret = self.ilpr;
            }
            9 => {
                ret = self.ibrd;
            }
            10 => {
                ret = self.fbrd;
            }
            11 => {
                ret = self.lcr;
            }
            12 => {
                ret = self.cr;
            }
            13 => {
                ret = self.ifl;
            }
            14 => {
                // Interrupt Mask Set/Clear Register
                ret = self.int_enabled;
            }
            15 => {
                // Raw Interrupt Status Register
                ret = self.int_level;
            }
            16 => {
                // Masked Interrupt Status Register
                ret = self.int_level & self.int_enabled;
            }
            18 => {
                ret = self.dmacr;
            }
            0x3f8..=0x400 => {
                // Register 0xFE0~0xFFC is UART Peripheral Identification Registers
                // and PrimeCell Identification Registers.
                ret = *self.id.get(((offset - 0xfe0) >> 2) as usize).unwrap() as u32;
            }
            _ => {
                error!("Failed to read pl011: Invalid offset 0x{:x}", offset);
                return false;
            }
        }
        data.copy_from_slice(&ret.as_bytes()[0..data.len()]);

        true
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        let value = match data.len() {
            1 => data[0] as u32,
            2 => LittleEndian::read_u16(data) as u32,
            4 => LittleEndian::read_u32(data) as u32,
            _ => return false,
        };

        match offset >> 2 {
            0 => {
                let ch = value as u8;

                let output = match &mut self.output {
                    Some(output_) => output_,
                    None => {
                        error!("Failed to get output fd.");
                        return false;
                    }
                };
                if let Err(e) = output.write_all(&[ch]) {
                    error!("Failed to write to pl011 output fd, error is {}", e);
                }
                if let Err(e) = output.flush() {
                    error!("Failed to flush pl011, error is {}", e);
                }

                self.int_level |= INT_TX as u32;
                self.interrupt();
            }
            1 => {
                self.rsr = 0;
            }
            8 => {
                self.ilpr = value;
            }
            9 => {
                self.ibrd = value;
            }
            10 => {
                self.fbrd = value;
            }
            11 => {
                // PL011 works in two modes: character mode or FIFO mode.
                // Reset FIFO if the mode is changed.
                if (self.lcr ^ value) & 0x10 != 0 {
                    self.read_count = 0;
                    self.read_pos = 0;
                }
                self.lcr = value;
                self.read_trigger = 1;
            }
            12 => {
                self.cr = value;
            }
            13 => {
                self.ifl = value;
                self.read_trigger = 1;
            }
            14 => {
                self.int_enabled = value;
                self.interrupt();
            }
            17 => {
                // Interrupt Clear Register, write only
                self.int_level &= !value;
                self.interrupt();
            }
            18 => {
                self.dmacr = value;
                if value & 3 != 0 {
                    error!("pl011: DMA not implemented");
                }
            }
            _ => {
                error!("Failed to write pl011: Invalid offset 0x{:x}", offset);
                return false;
            }
        }

        true
    }

    fn interrupt_evt(&self) -> Option<&EventFd> {
        Some(&self.interrupt_evt)
    }

    fn get_sys_resource(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.res)
    }

    fn get_type(&self) -> SysBusDevType {
        SysBusDevType::PL011
    }
}

impl AmlBuilder for PL011 {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut acpi_dev = AmlDevice::new("COM0");
        acpi_dev.append_child(AmlNameDecl::new("_HID", AmlString("ARMH0001".to_string())));
        acpi_dev.append_child(AmlNameDecl::new("_UID", AmlInteger(0)));

        let mut res = AmlResTemplate::new();
        res.append_child(AmlMemory32Fixed::new(
            AmlReadAndWrite::ReadWrite,
            self.res.region_base as u32,
            self.res.region_size as u32,
        ));
        // SPI start at interrupt number 32 on aarch64 platform.
        let irq_base = 32_u32;
        res.append_child(AmlExtendedInterrupt::new(
            AmlResourceUsage::Consumer,
            AmlEdgeLevel::Level,
            AmlActiveLevel::High,
            AmlIntShare::Exclusive,
            vec![self.res.irq as u32 + irq_base],
        ));
        acpi_dev.append_child(AmlNameDecl::new("_CRS", res));

        acpi_dev.aml_bytes()
    }
}

impl EventNotifierHelper for PL011 {
    /// Add PL011 to `EventNotifier`.
    ///
    /// # Arguments
    ///
    /// * `pl011` - PL011 Serial instance.
    fn internal_notifiers(pl011: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        let mut handlers = Vec::new();
        let handler: Box<dyn Fn(EventSet, RawFd) -> Option<Vec<EventNotifier>>> =
            Box::new(move |_, _| {
                let remain_space = PL011_FIFO_SIZE - pl011.lock().unwrap().read_count as usize;
                let mut out = vec![0_u8; remain_space];
                match std::io::stdin().lock().read_raw(&mut out) {
                    Ok(count) => {
                        pl011.lock().unwrap().receive(&out[..count]);
                    }
                    Err(e) => {
                        error!("PL011 receive error: error is {}", e);
                    }
                }
                None
            });

        handlers.push(Arc::new(Mutex::new(handler)));

        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            libc::STDIN_FILENO,
            None,
            EventSet::IN,
            handlers,
        );

        notifiers.push(notifier);
        notifiers
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_receive() {
        let mut pl011_dev = PL011::new().unwrap();
        assert_eq!(pl011_dev.rfifo, vec![0; PL011_FIFO_SIZE]);
        assert_eq!(pl011_dev.flags, 0x90);
        assert_eq!(pl011_dev.lcr, 0);
        assert_eq!(pl011_dev.rsr, 0);
        assert_eq!(pl011_dev.cr, 0x300);
        assert_eq!(pl011_dev.dmacr, 0);
        assert_eq!(pl011_dev.ilpr, 0);
        assert_eq!(pl011_dev.ibrd, 0);
        assert_eq!(pl011_dev.fbrd, 0);
        assert_eq!(pl011_dev.ifl, 0x12);
        assert_eq!(
            pl011_dev.id,
            vec![0x11, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1]
        );
        assert_eq!(pl011_dev.read_pos, 0);
        assert_eq!(pl011_dev.read_count, 0);
        assert_eq!(pl011_dev.read_trigger, 1);
        assert_eq!(pl011_dev.int_level, 0);
        assert_eq!(pl011_dev.int_enabled, 0);

        let data = vec![0x12, 0x34, 0x56, 0x78, 0x90];
        pl011_dev.receive(&data);
        assert_eq!(pl011_dev.read_count, data.len() as i32);
        for i in 0..data.len() {
            assert_eq!(pl011_dev.rfifo[i], data[i] as u32);
        }
        assert_eq!(pl011_dev.flags, 0xC0);
        assert_eq!(pl011_dev.int_level, INT_RX);
    }
}
