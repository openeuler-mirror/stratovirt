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
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use log::{debug, error};
use vmm_sys_util::eventfd::EventFd;

use super::error::LegacyError;
use crate::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysBusDevType, SysRes};
use crate::{Device, DeviceBase};
use acpi::{
    AmlActiveLevel, AmlBuilder, AmlDevice, AmlEdgeLevel, AmlEisaId, AmlExtendedInterrupt,
    AmlIntShare, AmlInteger, AmlIoDecode, AmlIoResource, AmlNameDecl, AmlResTemplate,
    AmlResourceUsage, AmlScopeBuilder,
};
use address_space::GuestAddress;
use chardev_backend::chardev::{Chardev, InputReceiver};
use machine_manager::{config::SerialConfig, event_loop::EventLoop};
use migration::{
    snapshot::SERIAL_SNAPSHOT_ID, DeviceStateDesc, FieldDesc, MigrationError, MigrationHook,
    MigrationManager, StateTransfer,
};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;
use util::loop_context::EventNotifierHelper;

pub const SERIAL_ADDR: u64 = 0x3f8;

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

/// IRQ number of serial device.
const UART_IRQ: i32 = 4;

const RECEIVER_BUFF_SIZE: usize = 1024;

/// Contain register status of serial device.
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
struct SerialState {
    /// Receiver buffer state.
    rbr_value: [u8; 1024],
    /// Length of rbr.
    rbr_len: usize,
    /// Interrupt enable register.
    ier: u8,
    /// Interrupt identification register.
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
    /// Used to set band rate.
    div: u16,
    /// Transmitter holding register.
    thr_pending: u32,
}

impl SerialState {
    fn new() -> Self {
        Self {
            rbr_value: [0u8; 1024],
            rbr_len: 0,
            ier: 0,
            iir: UART_IIR_NO_INT,
            lcr: 0x03,
            mcr: UART_MCR_OUT2,
            lsr: UART_LSR_TEMT | UART_LSR_THRE,
            msr: UART_MSR_DCD | UART_MSR_DSR | UART_MSR_CTS,
            scr: 0,
            div: 0x0c,
            thr_pending: 0,
        }
    }
}

/// Contain registers status and operation methods of serial.
pub struct Serial {
    base: SysBusDevBase,
    /// Whether rx paused
    paused: bool,
    /// Receiver buffer register.
    rbr: VecDeque<u8>,
    /// State of Device Serial.
    state: SerialState,
    /// Character device for redirection.
    chardev: Arc<Mutex<Chardev>>,
}

impl Serial {
    pub fn new(cfg: SerialConfig) -> Self {
        Serial {
            base: SysBusDevBase::new(SysBusDevType::Serial),
            paused: false,
            rbr: VecDeque::new(),
            state: SerialState::new(),
            chardev: Arc::new(Mutex::new(Chardev::new(cfg.chardev))),
        }
    }
    pub fn realize(
        mut self,
        sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
    ) -> Result<()> {
        self.chardev
            .lock()
            .unwrap()
            .realize()
            .with_context(|| "Failed to realize chardev")?;
        self.base.interrupt_evt = Some(Arc::new(EventFd::new(libc::EFD_NONBLOCK)?));
        self.set_sys_resource(sysbus, region_base, region_size)
            .with_context(|| LegacyError::SetSysResErr)?;

        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_device(&dev, region_base, region_size, "Serial")?;

        MigrationManager::register_device_instance(
            SerialState::descriptor(),
            dev.clone(),
            SERIAL_SNAPSHOT_ID,
        );
        let locked_dev = dev.lock().unwrap();
        locked_dev.chardev.lock().unwrap().set_receiver(&dev);
        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(locked_dev.chardev.clone()),
            None,
        )
        .with_context(|| LegacyError::RegNotifierErr)?;
        Ok(())
    }

    fn unpause_rx(&mut self) {
        if self.paused {
            trace::serial_unpause_rx();
            self.paused = false;
            self.chardev.lock().unwrap().unpause_rx();
        }
    }

    /// Update interrupt identification register,
    /// this method would be called when the interrupt identification changes.
    fn update_iir(&mut self) {
        let mut iir = UART_IIR_NO_INT;

        if self.state.ier & UART_IER_RDI != 0 && self.state.lsr & UART_LSR_DR != 0 {
            iir &= !UART_IIR_NO_INT;
            iir |= UART_IIR_RDI;
        } else if self.state.ier & UART_IER_THRI != 0 && self.state.thr_pending > 0 {
            iir &= !UART_IIR_NO_INT;
            iir |= UART_IIR_THRI;
        }

        self.state.iir = iir;
        if iir != UART_IIR_NO_INT {
            self.inject_interrupt();
        }
        trace::serial_update_iir(self.state.iir);
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
                if self.state.lcr & UART_LCR_DLAB != 0 {
                    ret = self.state.div as u8;
                } else {
                    if self.state.mcr & UART_MCR_LOOP == 0 {
                        self.unpause_rx();
                    }
                    if !self.rbr.is_empty() {
                        ret = self.rbr.pop_front().unwrap_or_default();
                    }
                    if self.rbr.is_empty() {
                        self.state.lsr &= !UART_LSR_DR;
                    }
                    self.update_iir();
                }
            }
            1 => {
                if self.state.lcr & UART_LCR_DLAB != 0 {
                    ret = (self.state.div >> 8) as u8;
                } else {
                    ret = self.state.ier
                }
            }
            2 => {
                ret = self.state.iir | 0xc0;
                self.state.thr_pending = 0;
                self.state.iir = UART_IIR_NO_INT
            }
            3 => {
                ret = self.state.lcr;
            }
            4 => {
                ret = self.state.mcr;
            }
            5 => {
                ret = self.state.lsr;
            }
            6 => {
                if self.state.mcr & UART_MCR_LOOP != 0 {
                    ret = (self.state.mcr & 0x0c) << 4;
                    ret |= (self.state.mcr & 0x02) << 3;
                    ret |= (self.state.mcr & 0x01) << 5;
                } else {
                    ret = self.state.msr;
                }
            }
            7 => {
                ret = self.state.scr;
            }
            _ => {}
        }
        trace::serial_read(offset, ret);

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
        trace::serial_write(offset, data);
        match offset {
            0 => {
                if self.state.lcr & UART_LCR_DLAB != 0 {
                    self.state.div = (self.state.div & 0xff00) | u16::from(data);
                } else {
                    self.state.thr_pending = 1;

                    if self.state.mcr & UART_MCR_LOOP != 0 {
                        // loopback mode
                        let len = self.rbr.len();
                        if len >= RECEIVER_BUFF_SIZE {
                            bail!(
                                "serial: maximum receive buffer size exceeded (len = {}).",
                                len
                            );
                        }

                        self.rbr.push_back(data);
                        self.state.lsr |= UART_LSR_DR;
                    } else {
                        let output = self.chardev.lock().unwrap().output.clone();
                        if output.is_none() {
                            self.update_iir();
                            bail!("serial: failed to get output fd.");
                        }
                        let mut locked_output = output.as_ref().unwrap().lock().unwrap();
                        locked_output
                            .write_all(&[data])
                            .with_context(|| "serial: failed to write.")?;
                        locked_output
                            .flush()
                            .with_context(|| "serial: failed to flush.")?;
                    }

                    self.update_iir();
                }
            }
            1 => {
                if self.state.lcr & UART_LCR_DLAB != 0 {
                    self.state.div = (self.state.div & 0x00ff) | (u16::from(data) << 8);
                } else {
                    let changed = (self.state.ier ^ data) & 0x0f;
                    self.state.ier = data & 0x0f;

                    if changed != 0 {
                        self.update_iir();
                    }
                }
            }
            3 => {
                self.state.lcr = data;
            }
            4 => {
                if data & UART_MCR_LOOP == 0 {
                    // loopback turned off. Unpause rx
                    self.unpause_rx();
                }
                self.state.mcr = data;
            }
            7 => {
                self.state.scr = data;
            }
            _ => {}
        }

        Ok(())
    }
}

impl InputReceiver for Serial {
    fn receive(&mut self, data: &[u8]) {
        if self.state.mcr & UART_MCR_LOOP == 0 {
            let len = self.rbr.len();
            if len >= RECEIVER_BUFF_SIZE {
                error!(
                    "serial: maximum receive buffer size exceeded (len = {}).",
                    len,
                );
                return;
            }

            self.rbr.extend(data);
            self.state.lsr |= UART_LSR_DR;
            self.update_iir();
            trace::serial_receive(data.len());
        }
    }

    fn remain_size(&mut self) -> usize {
        if (self.state.mcr & UART_MCR_LOOP == 0) && (self.rbr.len() < RECEIVER_BUFF_SIZE) {
            RECEIVER_BUFF_SIZE - self.rbr.len()
        } else {
            0
        }
    }

    fn set_paused(&mut self) {
        trace::serial_pause_rx();
        self.paused = true;
    }
}

impl Device for Serial {
    fn device_base(&self) -> &DeviceBase {
        &self.base.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base.base
    }
}

impl SysBusDevOps for Serial {
    fn sysbusdev_base(&self) -> &SysBusDevBase {
        &self.base
    }

    fn sysbusdev_base_mut(&mut self) -> &mut SysBusDevBase {
        &mut self.base
    }

    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        data[0] = self.read_internal(offset);
        true
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        if let Err(e) = self.write_internal(offset, data[0]) {
            debug!("Failed to write serial device {}: {:?}", self.name(), e);
            false
        } else {
            true
        }
    }

    fn get_irq(&self, _sysbus: &mut SysBus) -> Result<i32> {
        Ok(UART_IRQ)
    }

    fn get_sys_resource_mut(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.base.res)
    }
}

impl AmlBuilder for Serial {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut acpi_dev = AmlDevice::new("COM1");
        acpi_dev.append_child(AmlNameDecl::new("_HID", AmlEisaId::new("PNP0501")));
        acpi_dev.append_child(AmlNameDecl::new("_UID", AmlInteger(1)));
        acpi_dev.append_child(AmlNameDecl::new("_STA", AmlInteger(0xF)));

        let mut res = AmlResTemplate::new();
        res.append_child(AmlIoResource::new(
            AmlIoDecode::Decode16,
            self.base.res.region_base as u16,
            self.base.res.region_base as u16,
            0x00,
            self.base.res.region_size as u8,
        ));
        res.append_child(AmlExtendedInterrupt::new(
            AmlResourceUsage::Consumer,
            AmlEdgeLevel::Edge,
            AmlActiveLevel::High,
            AmlIntShare::Exclusive,
            vec![self.base.res.irq as u32],
        ));
        acpi_dev.append_child(AmlNameDecl::new("_CRS", res));

        acpi_dev.aml_bytes()
    }
}

impl StateTransfer for Serial {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let mut state = self.state;
        let (rbr_state, _) = self.rbr.as_slices();
        state.rbr_len = rbr_state.len();
        state.rbr_value[..state.rbr_len].copy_from_slice(rbr_state);

        Ok(state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
        let serial_state = *SerialState::from_bytes(state)
            .with_context(|| MigrationError::FromBytesError("SERIAL"))?;
        let mut rbr = VecDeque::<u8>::default();
        for i in 0..serial_state.rbr_len {
            rbr.push_back(serial_state.rbr_value[i]);
        }
        self.rbr = rbr;
        self.state = serial_state;
        self.unpause_rx();

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&SerialState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for Serial {}

#[cfg(test)]
mod test {
    use super::*;
    use machine_manager::config::{ChardevConfig, ChardevType};

    #[test]
    fn test_methods_of_serial() {
        // test new method
        let chardev_cfg = ChardevConfig {
            id: "chardev".to_string(),
            backend: ChardevType::Stdio,
        };
        let mut usart = Serial::new(SerialConfig {
            chardev: chardev_cfg.clone(),
        });
        assert_eq!(usart.state.ier, 0);
        assert_eq!(usart.state.iir, 1);
        assert_eq!(usart.state.lcr, 3);
        assert_eq!(usart.state.mcr, 8);
        assert_eq!(usart.state.lsr, 0x60);
        assert_eq!(usart.state.msr, 0xb0);
        assert_eq!(usart.state.scr, 0);
        assert_eq!(usart.state.div, 0x0c);
        assert_eq!(usart.state.thr_pending, 0);

        // test receive method
        let data = [0x01, 0x02];
        usart.receive(&data);
        assert_eq!(usart.rbr.is_empty(), false);
        assert_eq!(usart.rbr.len(), 2);
        assert_eq!(usart.rbr.front(), Some(&0x01));
        assert_eq!((usart.state.lsr & 0x01), 1);

        // test write_and_read_internal method
        assert_eq!(usart.read_internal(0), 0x01);
        assert_eq!(usart.read_internal(0), 0x02);
        assert_eq!((usart.state.lsr & 0x01), 0);

        // for write_internal with first argument to work,
        // you need to set output at first
        assert!(usart.write_internal(0, 0x03).is_err());
        let mut chardev = Chardev::new(chardev_cfg);
        chardev.output = Some(Arc::new(Mutex::new(std::io::stdout())));
        usart.chardev = Arc::new(Mutex::new(chardev));

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

    #[test]
    fn test_serial_migration_interface() {
        let chardev_cfg = ChardevConfig {
            id: "chardev".to_string(),
            backend: ChardevType::Stdio,
        };
        let mut usart = Serial::new(SerialConfig {
            chardev: chardev_cfg,
        });
        // Get state vector for usart
        let serial_state_result = usart.get_state_vec();
        assert!(serial_state_result.is_ok());
        let serial_state_vec = serial_state_result.unwrap();

        let serial_state_option = SerialState::from_bytes(&serial_state_vec);
        assert!(serial_state_option.is_some());
        let mut serial_state = *serial_state_option.unwrap();

        assert_eq!(serial_state.ier, 0);
        assert_eq!(serial_state.iir, 1);
        assert_eq!(serial_state.lcr, 3);
        assert_eq!(serial_state.mcr, 8);
        assert_eq!(serial_state.lsr, 0x60);
        assert_eq!(serial_state.msr, 0xb0);
        assert_eq!(serial_state.scr, 0);
        assert_eq!(serial_state.div, 0x0c);
        assert_eq!(serial_state.thr_pending, 0);

        // Change some value in serial_state.
        serial_state.ier = 3;
        serial_state.iir = 10;
        serial_state.lcr = 8;
        serial_state.mcr = 0;
        serial_state.lsr = 0x90;
        serial_state.msr = 0xbb;
        serial_state.scr = 2;
        serial_state.div = 0x02;
        serial_state.thr_pending = 1;

        // Check state value recovered.
        assert!(usart.set_state_mut(serial_state.as_bytes()).is_ok());
        assert_eq!(usart.state.ier, 3);
        assert_eq!(usart.state.iir, 10);
        assert_eq!(usart.state.lcr, 8);
        assert_eq!(usart.state.mcr, 0);
        assert_eq!(usart.state.lsr, 0x90);
        assert_eq!(usart.state.msr, 0xbb);
        assert_eq!(usart.state.scr, 2);
        assert_eq!(usart.state.div, 0x02);
        assert_eq!(usart.state.thr_pending, 1);
    }
}
