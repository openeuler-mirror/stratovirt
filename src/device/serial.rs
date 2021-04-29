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

use std::collections::VecDeque;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use std::thread;

use kvm_ioctls::VmFd;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd, terminal::Terminal};

use super::{Error, Result};
use crate::helper::epoll::{EpollContext, EventNotifier};
#[cfg(target_arch = "aarch64")]
use crate::memory::{LayoutEntryType, MEM_LAYOUT};

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

#[cfg(target_arch = "x86_64")]
pub const MMIO_SERIAL_IRQ: u32 = 4;
#[cfg(target_arch = "aarch64")]
pub const MMIO_SERIAL_IRQ: u32 = 32;

#[cfg(target_arch = "x86_64")]
pub const MMIO_SERIAL_ADDR: u64 = 0x3f8;
#[cfg(target_arch = "x86_64")]
pub const MMIO_SERIAL_ADDR_SIZE: u64 = 8;
#[cfg(target_arch = "aarch64")]
pub const MMIO_SERIAL_ADDR: u64 = MEM_LAYOUT[LayoutEntryType::Mmio as usize].0;
#[cfg(target_arch = "aarch64")]
pub const MMIO_SERIAL_ADDR_SIZE: u64 = MEM_LAYOUT[LayoutEntryType::Mmio as usize].1;

pub fn judge_serial_addr(addr: u64) -> Option<u64> {
    if (MMIO_SERIAL_ADDR..MMIO_SERIAL_ADDR + MMIO_SERIAL_ADDR_SIZE).contains(&addr) {
        Some(addr - MMIO_SERIAL_ADDR)
    } else {
        None
    }
}

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
    interrupt_evt: EventFd,
    /// Operation methods.
    output: Box<dyn io::Write + Send + Sync>,
}

impl Serial {
    /// Create a new `Serial` instance with default parameters.
    pub fn new(vm_fd: &VmFd) -> Arc<Mutex<Self>> {
        std::io::stdin()
            .lock()
            .set_raw_mode()
            .expect("Failed to set raw mode to stdin");

        let evt_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        vm_fd
            .register_irqfd(&evt_fd, MMIO_SERIAL_IRQ)
            .expect("Failed to register irq fd for serial");

        let serial = Arc::new(Mutex::new(Serial {
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
            interrupt_evt: evt_fd,
            output: Box::new(std::io::stdout()),
        }));

        let serial_clone = serial.clone();
        let mut epoll = EpollContext::new();
        let handler: Box<dyn Fn(EventSet, RawFd) + Send + Sync> = Box::new(move |event, _| {
            if event == EventSet::IN && serial_clone.lock().unwrap().stdin_exce().is_err() {
                println!("Failed to excecute the stdin");
            }
        });

        let notifier = EventNotifier::new(
            libc::STDIN_FILENO,
            EventSet::IN,
            Arc::new(Mutex::new(handler)),
        );

        epoll.add_event(notifier);

        let _ = thread::Builder::new()
            .name("serial".to_string())
            .spawn(move || loop {
                if !epoll.run() {
                    break;
                }
            });

        serial
    }

    /// Update interrupt identification register,
    /// this method would be called when the interrupt identification changes.
    fn update_iir(&mut self) -> Result<()> {
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
            self.interrupt_evt.write(1).map_err(Error::IoError)?;
        }

        Ok(())
    }

    fn receive(&mut self, data: &[u8]) -> Result<()> {
        if self.mcr & UART_MCR_LOOP == 0 {
            if self.rbr.len() >= RECEIVER_BUFF_SIZE {
                return Err(Error::Overflow(self.rbr.len(), RECEIVER_BUFF_SIZE));
            }

            self.rbr.extend(data);
            self.lsr |= UART_LSR_DR;

            self.update_iir()?;
        }

        Ok(())
    }

    fn stdin_exce(&mut self) -> Result<()> {
        let mut out = [0_u8; 64];
        if let Ok(count) = std::io::stdin().lock().read_raw(&mut out) {
            self.receive(&out[..count])
        } else {
            Ok(())
        }
    }

    /// Read one byte data from a certain register selected by `offset`.
    ///
    /// # Arguments
    ///
    /// * `offset` - Used to select a register.
    ///
    /// # Errors
    ///
    /// Return Error if fail to update iir.
    pub fn read(&mut self, offset: u64) -> u8 {
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

                    if self.update_iir().is_err() {
                        println!(
                            "Failed to update iir for reading the register {} of serial",
                            offset
                        );
                    }
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

    /// Write one byte data to a certain register selected by `offset`.
    ///
    /// # Arguments
    ///
    /// * `offset` - Used to select a register.
    /// * `data` - A u8-type data, which will be written to the register.
    ///
    /// # Errors
    ///
    /// Return Error if
    /// * fail to get output file descriptor.
    /// * fail to write serial.
    /// * fail to flush serial.
    pub fn write(&mut self, offset: u64, data: u8) -> Result<()> {
        match offset {
            0 => {
                if self.lcr & UART_LCR_DLAB != 0 {
                    self.div = (self.div & 0xff00) | u16::from(data);
                } else {
                    self.thr_pending = 1;

                    if self.mcr & UART_MCR_LOOP != 0 {
                        // loopback mode
                        if self.rbr.len() >= RECEIVER_BUFF_SIZE {
                            return Err(Error::Overflow(self.rbr.len(), RECEIVER_BUFF_SIZE));
                        }

                        self.rbr.push_back(data);
                        self.lsr |= UART_LSR_DR;
                    } else {
                        self.output.write_all(&[data]).map_err(Error::IoError)?;
                        self.output.flush().map_err(Error::IoError)?;
                    }

                    self.update_iir()?;
                }
            }
            1 => {
                if self.lcr & UART_LCR_DLAB != 0 {
                    self.div = (self.div & 0x00ff) | (u16::from(data) << 8);
                } else {
                    let changed = (self.ier ^ data) & 0x0f;
                    self.ier = data & 0x0f;

                    if changed != 0 {
                        self.update_iir()?;
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
