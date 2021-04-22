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

pub mod errors {
    error_chain! {
        foreign_links {
            Io(std::io::Error);
        }
    }
}

use std::collections::VecDeque;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

use address_space::GuestAddress;
use error_chain::ChainedError;
use kvm_ioctls::VmFd;
#[cfg(target_arch = "aarch64")]
use machine_manager::config::{BootSource, Param};
use sysbus::{errors::Result as SysBusResult, SysBus, SysBusDevOps, SysBusDevType, SysRes};
use util::loop_context::{EventNotifier, EventNotifierHelper, NotifierOperation};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd, terminal::Terminal};

use errors::Result;

const UART_IER_RDI: u8 = 0x01;
const UART_IER_THRI: u8 = 0x02;
const UART_IIR_NO_INT: u8 = 0x01;
const UART_IIR_THRI: u8 = 0x02;
const UART_IIR_RDI: u8 = 0x04;
const _UART_IIR_ID: u8 = 0x06;

const UART_LCR_DLAB: u8 = 0x80;
const UART_LSR_DR: u8 = 0x01;
const _UART_LSR_OE: u8 = 0x02;
const _UART_LSR_BI: u8 = 0x10;
const UART_LSR_THRE: u8 = 0x20;
const UART_LSR_TEMT: u8 = 0x40;

const UART_MCR_OUT2: u8 = 0x08;
const UART_MCR_LOOP: u8 = 0x10;
const UART_MSR_CTS: u8 = 0x10;
const UART_MSR_DSR: u8 = 0x20;
const UART_MSR_DCD: u8 = 0x80;

const RECEIVER_BUFF_SIZE: usize = 1024;

/// Contain registers and operation methods of serial.
pub struct Serial {
    /// Receiver buffer register.
    rbr: VecDeque<u8>,
    /// Interrupt enable register.
    ier: u8,
    /// interrupt identification register.
    iir: u8,
    /// Line control register.
    lcr: u8,
    /// Modem control register.
    mcr: u8,
    /// Line status register.
    lsr: u8,
    /// Modem status register.
    msr: u8,
    /// Scratch register.
    scr: u8,
    /// Used to set baud rate.
    div: u16,
    /// Transmitter holding register.
    thr_pending: u32,
    /// Interrupt event file descriptor.
    interrupt_evt: Option<EventFd>,
    /// Operation methods.
    output: Option<Box<dyn std::io::Write + Send + Sync>>,
    /// System resource.
    res: SysRes,
}

impl Default for Serial {
    fn default() -> Self {
        Self {
            rbr: VecDeque::new(),
            ier: 0,
            iir: UART_IIR_NO_INT,
            lcr: 0x03, // 8 bits
            mcr: UART_MCR_OUT2,
            lsr: UART_LSR_TEMT | UART_LSR_THRE,
            msr: UART_MSR_DCD | UART_MSR_DSR | UART_MSR_CTS,
            scr: 0,
            div: 0x0c,
            thr_pending: 0,
            interrupt_evt: None,
            output: None,
            res: SysRes::default(),
        }
    }
}

impl Serial {
    pub fn realize(
        mut self,
        sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
        #[cfg(target_arch = "aarch64")] bs: &Arc<Mutex<BootSource>>,
        vm_fd: &VmFd,
    ) -> Result<Arc<Mutex<Self>>> {
        self.output = Some(Box::new(std::io::stdout()));
        self.interrupt_evt = Some(EventFd::new(libc::EFD_NONBLOCK)?);

        if let Err(e) = self.set_sys_resource(sysbus, region_base, region_size, vm_fd) {
            error!("{}", e.display_chain());
            bail!("Failed to allocate system resource.");
        }

        let dev = Arc::new(Mutex::new(self));
        if let Err(e) = sysbus.attach_device(&dev, region_base, region_size) {
            error!("{}", e.display_chain());
            bail!("Failed to attach to system bus.");
        }

        #[cfg(target_arch = "aarch64")]
        bs.lock().unwrap().kernel_cmdline.push(Param {
            param_type: "earlycon".to_string(),
            value: format!("uart,mmio,0x{:08x}", region_base),
        });
        Ok(dev)
    }

    /// Update interrupt identification register,
    /// this method would be called when the interrupt identification changes.
    fn update_iir(&mut self) {
        let mut iir = UART_IIR_NO_INT;

        if self.ier & UART_IER_RDI != 0 && self.lsr & UART_LSR_DR != 0 {
            iir &= !UART_IIR_NO_INT;
            iir |= UART_IIR_RDI;
        } else if self.ier & UART_IER_THRI != 0 && self.thr_pending > 0 {
            iir &= !UART_IIR_NO_INT;
            iir |= UART_IIR_THRI;
        }

        self.iir = iir;
        if iir != UART_IIR_NO_INT {
            if let Some(evt) = self.interrupt_evt() {
                if let Err(e) = evt.write(1) {
                    error!("serial: failed to write interrupt eventfd ({}).", e);
                }
                return;
            }
            error!("serial: failed to update iir.");
        }
    }

    /// Append `data` to receiver buffer register, and update IIR.
    ///
    /// # Arguments
    ///
    /// * `data` - A u8-type array.
    pub fn receive(&mut self, data: &[u8]) {
        if self.mcr & UART_MCR_LOOP == 0 {
            if self.rbr.len() >= RECEIVER_BUFF_SIZE {
                error!(
                    "serial: receive buffer length exceeds the maximum size limit ({}).",
                    RECEIVER_BUFF_SIZE
                );
            }

            self.rbr.extend(data);
            self.lsr |= UART_LSR_DR;
            self.update_iir();
        }
    }

    // Read one byte data from a certain register selected by `offset`.
    //
    // # Arguments
    //
    // * `offset` - Used to select a register.
    //
    // # Errors
    //
    // Return Error if fail to update iir.
    fn read_internal(&mut self, offset: u64) -> u8 {
        let mut ret: u8 = 0;

        match offset {
            0 => {
                if self.lcr & UART_LCR_DLAB != 0 {
                    ret = self.div as u8;
                } else {
                    if !self.rbr.is_empty() {
                        ret = self.rbr.pop_front().unwrap_or_default();
                    }
                    if self.rbr.is_empty() {
                        self.lsr &= !UART_LSR_DR;
                    }
                    self.update_iir();
                }
            }
            1 => {
                if self.lcr & UART_LCR_DLAB != 0 {
                    ret = (self.div >> 8) as u8;
                } else {
                    ret = self.ier
                }
            }
            2 => {
                ret = self.iir | 0xc0;
                self.thr_pending = 0;
                self.iir = UART_IIR_NO_INT
            }
            3 => {
                ret = self.lcr;
            }
            4 => {
                ret = self.mcr;
            }
            5 => {
                ret = self.lsr;
            }
            6 => {
                if self.mcr & UART_MCR_LOOP != 0 {
                    ret = (self.mcr & 0x0c) << 4;
                    ret |= (self.mcr & 0x02) << 3;
                    ret |= (self.mcr & 0x01) << 5;
                } else {
                    ret = self.msr;
                }
            }
            7 => {
                ret = self.scr;
            }
            _ => {}
        }

        ret
    }

    // Write one byte data to a certain register selected by `offset`.
    //
    // # Arguments
    //
    // * `offset` - Used to select a register.
    // * `data` - A u8-type data, which will be written to the register.
    //
    // # Errors
    //
    // Return Error if
    // * fail to get output file descriptor.
    // * fail to write serial.
    // * fail to flush serial.
    fn write_internal(&mut self, offset: u64, data: u8) -> Result<()> {
        use errors::ResultExt;

        match offset {
            0 => {
                if self.lcr & UART_LCR_DLAB != 0 {
                    self.div = (self.div & 0xff00) | u16::from(data);
                } else {
                    self.thr_pending = 1;

                    if self.mcr & UART_MCR_LOOP != 0 {
                        // loopback mode
                        if self.rbr.len() >= RECEIVER_BUFF_SIZE {
                            bail!("Serial receive buffer extend the Max size.");
                        }

                        self.rbr.push_back(data);
                        self.lsr |= UART_LSR_DR;
                    } else {
                        let output = match &mut self.output {
                            Some(o) => o,
                            None => bail!("serial: failed to get output fd."),
                        };
                        output
                            .write_all(&[data])
                            .chain_err(|| "Failed to write for serial.")?;
                        output.flush().chain_err(|| "Failed to flush for serial.")?;
                    }

                    self.update_iir();
                }
            }
            1 => {
                if self.lcr & UART_LCR_DLAB != 0 {
                    self.div = (self.div & 0x00ff) | (u16::from(data) << 8);
                } else {
                    let changed = (self.ier ^ data) & 0x0f;
                    self.ier = data & 0x0f;

                    if changed != 0 {
                        self.update_iir();
                    }
                }
            }
            3 => {
                self.lcr = data;
            }
            4 => {
                self.mcr = data;
            }
            7 => {
                self.scr = data;
            }
            _ => {}
        }

        Ok(())
    }
}

impl SysBusDevOps for Serial {
    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        data[0] = self.read_internal(offset);
        true
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        self.write_internal(offset, data[0]).is_ok()
    }

    fn interrupt_evt(&self) -> Option<&EventFd> {
        self.interrupt_evt.as_ref()
    }

    fn set_irq(&mut self, _sysbus: &mut SysBus, vm_fd: &VmFd) -> SysBusResult<i32> {
        use sysbus::errors::ResultExt;

        let mut irq: i32 = -1;
        if let Some(e) = self.interrupt_evt() {
            irq = 4;
            vm_fd
                .register_irqfd(e, irq as u32)
                .chain_err(|| "Failed to register irqfd")?;
        }
        Ok(irq)
    }

    fn get_sys_resource(&mut self) -> &mut SysRes {
        &mut self.res
    }

    fn get_type(&self) -> SysBusDevType {
        SysBusDevType::Serial
    }
}

impl EventNotifierHelper for Serial {
    /// Add serial to `EventNotifier`.
    ///
    /// # Arguments
    ///
    /// * `serial` - Serial instance.
    fn internal_notifiers(serial: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        let mut handlers = Vec::new();
        let handler: Box<dyn Fn(EventSet, RawFd) -> Option<Vec<EventNotifier>>> =
            Box::new(move |_, _| {
                let mut out = [0_u8; 64];
                if let Ok(count) = std::io::stdin().lock().read_raw(&mut out) {
                    serial.lock().unwrap().receive(&out[..count]);
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
    fn test_methods_of_serial() {
        // test new method
        let mut usart = Serial::default();
        assert_eq!(usart.ier, 0);
        assert_eq!(usart.iir, 1);
        assert_eq!(usart.lcr, 3);
        assert_eq!(usart.mcr, 8);
        assert_eq!(usart.lsr, 0x60);
        assert_eq!(usart.msr, 0xb0);
        assert_eq!(usart.scr, 0);
        assert_eq!(usart.div, 0x0c);
        assert_eq!(usart.thr_pending, 0);

        // test receive method
        let data = [0x01, 0x02];
        usart.receive(&data);
        assert_eq!(usart.rbr.is_empty(), false);
        assert_eq!(usart.rbr.len(), 2);
        assert_eq!(usart.rbr.front(), Some(&0x01));
        assert_eq!((usart.lsr & 0x01), 1);

        // test write_and_read_internal method
        assert_eq!(usart.read_internal(0), 0x01);
        assert_eq!(usart.read_internal(0), 0x02);
        assert_eq!((usart.lsr & 0x01), 0);

        // for write_internal with first argument to work,
        // you need to set output at first
        assert!(usart.write_internal(0, 0x03).is_err());
        usart.output = Some(Box::new(std::io::stdout()));
        assert!(usart.write_internal(0, 0x03).is_ok());
        usart.write_internal(3, 0xff).unwrap();
        assert_eq!(usart.read_internal(3), 0xff);
        usart.write_internal(4, 0xff).unwrap();
        assert_eq!(usart.read_internal(4), 0xff);
        usart.write_internal(7, 0xff).unwrap();
        assert_eq!(usart.read_internal(7), 0xff);
        usart.write_internal(0, 0x0d).unwrap();
        assert_eq!(usart.read_internal(0), 0x0d);
        usart.write_internal(1, 0x0c).unwrap();
        assert_eq!(usart.read_internal(1), 0x0c);
        assert_eq!(usart.read_internal(2), 0xc1);
        assert_eq!(usart.read_internal(5), 0x60);
        assert_eq!(usart.read_internal(6), 0xf0);
    }
}
