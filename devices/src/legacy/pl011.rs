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

use sysbus::SysRes;
use vmm_sys_util::eventfd::EventFd;

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
}
