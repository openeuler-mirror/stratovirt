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

use std::cmp;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use log::{debug, error, warn};

use super::{TpmInterfaceType, TPM_CRB_SIZE, TPM_START};
use crate::legacy::error::LegacyError;
use crate::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysBusDevType};
use crate::{convert_bus_mut, Device, DeviceBase, MUT_SYS_BUS};
use acpi::{
    AmlBuilder, AmlDevice, AmlInteger, AmlMemory32Fixed, AmlNameDecl, AmlReadAndWrite,
    AmlResTemplate, AmlScopeBuilder, AmlString,
};
use address_space::GuestAddress;
use tpm::{emulator::Emulator, TpmBackend, TPM_CRB_BUFFER_MAX};
use util::gen_base_func;

#[allow(dead_code)]
#[derive(Copy, Clone)]
enum LocStateFields {
    TpmEstablished,
    LocAssigned,
    ActiveLocality,
    Reserved,
    TpmRegValidSts,
}

#[derive(Copy, Clone)]
enum LocStsFields {
    Granted,
    BeenSeized,
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
enum IntfIdFields {
    InterfaceType,
    InterfaceVersion,
    CapLocality,
    CapCRBIdleBypass,
    Reserved1,
    CapDataXferSizeSupport,
    CapFIFO,
    CapCRB,
    CapIFRes,
    InterfaceSelector,
    IntfSelLock,
    Reserved2,
    Rid,
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
enum IntfId2Fields {
    Vid,
    Did,
}

#[derive(Copy, Clone)]
enum CtrlStsFields {
    TpmSts,
    TpmIdle,
}

#[derive(Copy, Clone)]
enum CrbRegister {
    LocState(LocStateFields),
    LocSts(LocStsFields),
    IntfId(IntfIdFields),
    IntfId2(IntfId2Fields),
    CtrlSts(CtrlStsFields),
}

/* Crb 32-bit Loc */
const CRB_LOC_STATE: u32 = 0x0;
const CRB_LOC_CTRL: u32 = 0x08;
const CRB_LOC_CTRL_REQUEST_ACCESS: u32 = 1 << 0;
const CRB_LOC_CTRL_RELINQUISH: u32 = 1 << 1;
const CRB_LOC_CTRL_RESET_ESTABLISHMENT_BIT: u32 = 1 << 3;
const CRB_LOC_STS: u32 = 0x0C;
/* Crb 32-bit Intf */
const CRB_INTF_ID: u32 = 0x30;
const CRB_INTF_ID2: u32 = 0x34;
/* Crb 32-bit Ctrl */
const CRB_CTRL_REQ: u32 = 0x40;
const CRB_CTRL_REQ_CMD_READY: u32 = 1 << 0;
const CRB_CTRL_REQ_GO_IDLE: u32 = 1 << 1;
const CRB_CTRL_STS: u32 = 0x44;

const CRB_CTRL_CANCEL: u32 = 0x48;
const CRB_CANCEL_INVOKE: u32 = 1 << 0;
const CRB_CTRL_START: u32 = 0x4C;
const CRB_START_INVOKE: u32 = 1 << 0;
const CRB_CTRL_CMD_LADDR: u32 = 0x5C;
const CRB_CTRL_CMD_HADDR: u32 = 0x60;
const CRB_CTRL_RSP_SIZE: u32 = 0x64;
const CRB_CTRL_RSP_ADDR: u32 = 0x68;
const CRB_DATA_BUFFER: u32 = 0x80;

const TPM_CRB_NO_LOCALITY: u32 = 0xff;

const TPM_CRB_ADDR_BASE: u32 = TPM_START as u32;
const TPM_CRB_ADDR_SIZE: usize = TPM_CRB_SIZE as usize;

const TPM_CRB_R_MAX: usize = CRB_DATA_BUFFER as usize;

// CRB Protocol details
const CRB_INTF_TYPE_CRB_ACTIVE: u32 = 0b1;
const CRB_INTF_VERSION_CRB: u32 = 0b1;
const CRB_INTF_CAP_LOCALITY_0_ONLY: u32 = 0b0;
const CRB_INTF_CAP_IDLE_FAST: u32 = 0b0;
const CRB_INTF_CAP_XFER_SIZE_64: u32 = 0b11;
const CRB_INTF_CAP_FIFO_NOT_SUPPORTED: u32 = 0b0;
const CRB_INTF_CAP_CRB_SUPPORTED: u32 = 0b1;
const CRB_INTF_IF_SELECTOR_CRB: u32 = 0b1;
const PCI_VENDOR_ID_IBM: u32 = 0x1014;
const CRB_CTRL_CMD_SIZE_REG: u32 = 0x58;
const CRB_CTRL_CMD_SIZE: usize = TPM_CRB_ADDR_SIZE - CRB_DATA_BUFFER as usize;

// Register Fields
// Fields => (base, offset, length)
// base: starting position of the register
// offset: lowest bit in the bit field numbered from 0
// length: length of the bit field
const fn get_crb_loc_state_field(f: LocStateFields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        LocStateFields::TpmEstablished => (0, 1),
        LocStateFields::LocAssigned => (1, 1),
        LocStateFields::ActiveLocality => (2, 3),
        LocStateFields::Reserved => (5, 2),
        LocStateFields::TpmRegValidSts => (7, 1),
    };

    (CRB_LOC_STATE, offset, len)
}

const fn get_crb_loc_sts_field(f: LocStsFields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        LocStsFields::Granted => (0, 1),
        LocStsFields::BeenSeized => (1, 1),
    };

    (CRB_LOC_STS, offset, len)
}

const fn get_crb_intf_id_field(f: IntfIdFields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        IntfIdFields::InterfaceType => (0, 4),
        IntfIdFields::InterfaceVersion => (4, 4),
        IntfIdFields::CapLocality => (8, 1),
        IntfIdFields::CapCRBIdleBypass => (9, 1),
        IntfIdFields::Reserved1 => (10, 1),
        IntfIdFields::CapDataXferSizeSupport => (11, 2),
        IntfIdFields::CapFIFO => (13, 1),
        IntfIdFields::CapCRB => (14, 1),
        IntfIdFields::CapIFRes => (15, 2),
        IntfIdFields::InterfaceSelector => (17, 2),
        IntfIdFields::IntfSelLock => (19, 1),
        IntfIdFields::Reserved2 => (20, 4),
        IntfIdFields::Rid => (24, 8),
    };

    (CRB_INTF_ID, offset, len)
}

const fn get_crb_intf_id2_field(f: IntfId2Fields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        IntfId2Fields::Vid => (0, 16),
        IntfId2Fields::Did => (16, 16),
    };

    (CRB_INTF_ID2, offset, len)
}

const fn get_crb_ctrl_sts_field(f: CtrlStsFields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        CtrlStsFields::TpmSts => (0, 1),
        CtrlStsFields::TpmIdle => (1, 1),
    };

    (CRB_CTRL_STS, offset, len)
}

// Returns (register base, offset, len)
const fn get_field(reg: CrbRegister) -> (u32, u32, u32) {
    match reg {
        CrbRegister::LocState(f) => get_crb_loc_state_field(f),
        CrbRegister::LocSts(f) => get_crb_loc_sts_field(f),
        CrbRegister::IntfId(f) => get_crb_intf_id_field(f),
        CrbRegister::IntfId2(f) => get_crb_intf_id2_field(f),
        CrbRegister::CtrlSts(f) => get_crb_ctrl_sts_field(f),
    }
}

// Set a particular field in a Register
fn set_reg_field(regs: &mut [u32; TPM_CRB_R_MAX], reg: CrbRegister, value: u32) {
    let (base, offset, len) = get_field(reg);
    let mask = (!(0_u32) >> (32 - len)) << offset;
    regs[base as usize] = (regs[base as usize] & !mask) | ((value << offset) & mask);
}

// Get the value of a particular field in a Register
const fn get_reg_field(regs: &[u32; TPM_CRB_R_MAX], reg: CrbRegister) -> u32 {
    let (base, offset, len) = get_field(reg);
    let mask = (!(0_u32) >> (32 - len)) << offset;
    (regs[base as usize] & mask) >> offset
}

fn locality_from_addr(addr: u32) -> u8 {
    (addr >> 12) as u8
}

pub struct TpmCrb {
    base: SysBusDevBase,
    emulator: Emulator,
    regs: [u32; TPM_CRB_R_MAX],
    backend_buff_size: usize,
    data_buff: [u8; TPM_CRB_BUFFER_MAX],
    data_buff_len: usize,
}

impl TpmCrb {
    pub fn new(
        sysbus: &Arc<Mutex<SysBus>>,
        region_base: u64,
        region_size: u64,
        path: impl AsRef<Path>,
    ) -> Result<Self> {
        let emulator = Emulator::new(path)
            .map_err(|e| anyhow!("Failed while initializing tpm Emulator: {e:?}"))?;

        let mut tpm = TpmCrb {
            base: SysBusDevBase::new(SysBusDevType::Tpm(TpmInterfaceType::Crb)),
            emulator,
            regs: [0; TPM_CRB_R_MAX],
            backend_buff_size: TPM_CRB_BUFFER_MAX,
            data_buff: [0; TPM_CRB_BUFFER_MAX],
            data_buff_len: 0,
        };

        tpm.set_sys_resource(sysbus, region_base, region_size, "TPM-CRB")
            .with_context(|| LegacyError::SetSysResErr)?;
        tpm.set_parent_bus(sysbus.clone());

        tpm.reset()?;
        tpm.get_eatablished_flag()?;

        Ok(tpm)
    }

    fn get_active_locality(&mut self) -> u32 {
        if get_reg_field(
            &self.regs,
            CrbRegister::LocState(LocStateFields::LocAssigned),
        ) == 0
        {
            return TPM_CRB_NO_LOCALITY;
        }
        get_reg_field(
            &self.regs,
            CrbRegister::LocState(LocStateFields::ActiveLocality),
        )
    }

    fn get_eatablished_flag(&mut self) -> Result<()> {
        let established_flag = self.emulator.get_established_flag()?;
        if !established_flag {
            return Err(anyhow!("TPM not in established state"));
        }

        Ok(())
    }

    fn request_completed(&mut self, success: bool) {
        self.regs[CRB_CTRL_START as usize] = !CRB_START_INVOKE;
        if !success {
            set_reg_field(
                &mut self.regs,
                CrbRegister::CtrlSts(CtrlStsFields::TpmSts),
                1,
            );
        }
    }

    fn reset(&mut self) -> Result<()> {
        let cur_buff_size = self.emulator.get_buffer_size();
        self.regs = [0; TPM_CRB_R_MAX];
        set_reg_field(
            &mut self.regs,
            CrbRegister::LocState(LocStateFields::TpmRegValidSts),
            1,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::CtrlSts(CtrlStsFields::TpmIdle),
            1,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::InterfaceType),
            CRB_INTF_TYPE_CRB_ACTIVE,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::InterfaceVersion),
            CRB_INTF_VERSION_CRB,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapLocality),
            CRB_INTF_CAP_LOCALITY_0_ONLY,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapCRBIdleBypass),
            CRB_INTF_CAP_IDLE_FAST,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapDataXferSizeSupport),
            CRB_INTF_CAP_XFER_SIZE_64,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapFIFO),
            CRB_INTF_CAP_FIFO_NOT_SUPPORTED,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapCRB),
            CRB_INTF_CAP_CRB_SUPPORTED,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::InterfaceSelector),
            CRB_INTF_IF_SELECTOR_CRB,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::Rid),
            0b0000,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId2(IntfId2Fields::Vid),
            PCI_VENDOR_ID_IBM,
        );

        self.regs[CRB_CTRL_CMD_SIZE_REG as usize] = CRB_CTRL_CMD_SIZE as u32;
        self.regs[CRB_CTRL_CMD_LADDR as usize] = TPM_CRB_ADDR_BASE + CRB_DATA_BUFFER;
        self.regs[CRB_CTRL_RSP_SIZE as usize] = CRB_CTRL_CMD_SIZE as u32;
        self.regs[CRB_CTRL_RSP_ADDR as usize] = TPM_CRB_ADDR_BASE + CRB_DATA_BUFFER;

        self.backend_buff_size = cmp::min(cur_buff_size, TPM_CRB_BUFFER_MAX);

        if let Err(e) = self.emulator.startup_tpm(self.backend_buff_size, false) {
            return Err(anyhow!("Failed while running Startup TPM. Error: {e:?}"));
        }
        Ok(())
    }
}

impl Device for TpmCrb {
    gen_base_func!(device_base, device_base_mut, DeviceBase, base.base);

    fn realize(self) -> Result<Arc<Mutex<Self>>> {
        let parent_bus = self.parent_bus().unwrap().upgrade().unwrap();
        MUT_SYS_BUS!(parent_bus, locked_bus, sysbus);
        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_device(&dev)?;

        Ok(dev)
    }

    fn unrealize(&mut self) -> Result<()> {
        if let Err(e) = self.emulator.shutdown_tpm() {
            return Err(anyhow!("Failed while running Shutdown TPM. Error: {e:?}"));
        }

        Ok(())
    }

    fn reset(&mut self, _reset_child_device: bool) -> Result<()> {
        self.reset()
    }
}

impl SysBusDevOps for TpmCrb {
    gen_base_func!(sysbusdev_base, sysbusdev_base_mut, SysBusDevBase, base);

    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        let mut offset: u32 = offset as u32;
        let read_len: usize = data.len();

        if offset >= CRB_DATA_BUFFER
            && (offset + read_len as u32) < (CRB_DATA_BUFFER + self.data_buff.len() as u32)
        {
            let start: usize = (offset as usize) - (CRB_DATA_BUFFER as usize);
            let end: usize = start + read_len;
            data[..].clone_from_slice(&self.data_buff[start..end]);
        } else {
            offset &= 0xff;
            let mut val = self.regs[offset as usize];

            if offset == CRB_LOC_STATE && !self.emulator.get_established_flag().is_ok_and(|v| v) {
                val |= 0x1;
            }

            if data.len() <= 4 {
                data.clone_from_slice(val.to_ne_bytes()[0..read_len].as_ref());
            } else {
                error!(
                    "Invalid tpm read: offset {:#X}, data length {:?}",
                    offset,
                    data.len()
                );
            }
        }

        debug!(
            "MMIO Read: offset {:#X} len {:?} val = {:02X?}  ",
            offset,
            data.len(),
            data
        );

        true
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        debug!(
            "MMIO Write: offset {:#X} len {:?} input data {:02X?}",
            offset,
            data.len(),
            data
        );

        let mut offset: u32 = offset as u32;
        if offset < CRB_DATA_BUFFER {
            offset &= 0xff;
        }
        let locality = locality_from_addr(offset) as u32;
        let write_len = data.len();

        if offset >= CRB_DATA_BUFFER
            && (offset + write_len as u32) < (CRB_DATA_BUFFER + self.data_buff.len() as u32)
        {
            let start: usize = (offset as usize) - (CRB_DATA_BUFFER as usize);
            if start == 0 {
                self.data_buff_len = 0;
                self.data_buff.fill(0);
            }
            let end: usize = start + data.len();
            self.data_buff[start..end].clone_from_slice(data);
            self.data_buff_len += data.len();
        } else {
            // Ctrl Commands that take more than 4 bytes as input are not yet supported
            // CTRL_RSP_ADDR usually gets 8 byte write request. Last 4 bytes are zeros.
            if write_len > 4 && offset != CRB_CTRL_RSP_ADDR {
                error!(
                    "Invalid tpm write: offset {:#X}, data length {}",
                    offset,
                    data.len()
                );
                return true;
            }

            let mut input: [u8; 4] = [0; 4];
            input[..write_len].copy_from_slice(&data[..write_len]);
            let v = u32::from_le_bytes(input);

            match offset {
                CRB_CTRL_CMD_SIZE_REG => {
                    self.regs[CRB_CTRL_CMD_SIZE_REG as usize] = v;
                }
                CRB_CTRL_CMD_LADDR => {
                    self.regs[CRB_CTRL_CMD_LADDR as usize] = v;
                }
                CRB_CTRL_CMD_HADDR => {
                    self.regs[CRB_CTRL_CMD_HADDR as usize] = v;
                }
                CRB_CTRL_RSP_SIZE => {
                    self.regs[CRB_CTRL_RSP_SIZE as usize] = v;
                }
                CRB_CTRL_RSP_ADDR => {
                    self.regs[CRB_CTRL_RSP_ADDR as usize] = v;
                }
                CRB_CTRL_REQ => match v {
                    CRB_CTRL_REQ_CMD_READY => {
                        set_reg_field(
                            &mut self.regs,
                            CrbRegister::CtrlSts(CtrlStsFields::TpmIdle),
                            0,
                        );
                    }
                    CRB_CTRL_REQ_GO_IDLE => {
                        set_reg_field(
                            &mut self.regs,
                            CrbRegister::CtrlSts(CtrlStsFields::TpmIdle),
                            1,
                        );
                    }
                    _ => {
                        error!("Invalid value passed to CTRL_REQ register");
                        return true;
                    }
                },
                CRB_CTRL_CANCEL => {
                    if v == CRB_CANCEL_INVOKE
                        && (self.regs[CRB_CTRL_START as usize] & CRB_START_INVOKE != 0)
                    {
                        if let Err(e) = self.emulator.cancel_cmd() {
                            error!("Failed to run cancel command. Error: {e:?}");
                        }
                    }
                }
                CRB_CTRL_START => {
                    if v == CRB_START_INVOKE
                        && ((self.regs[CRB_CTRL_START as usize] & CRB_START_INVOKE) == 0)
                        && self.get_active_locality() == locality
                    {
                        self.regs[CRB_CTRL_START as usize] |= CRB_START_INVOKE;

                        let input_len = cmp::min(self.data_buff_len, TPM_CRB_BUFFER_MAX);
                        let status = self
                            .emulator
                            .process_request(&mut self.data_buff, input_len)
                            .is_ok();

                        self.request_completed(status);
                    }
                }
                CRB_LOC_CTRL => {
                    warn!("CRB_LOC_CTRL locality to write = {locality:?} val = {v:?}");
                    match v {
                        CRB_LOC_CTRL_RESET_ESTABLISHMENT_BIT => {}
                        CRB_LOC_CTRL_RELINQUISH => {
                            set_reg_field(
                                &mut self.regs,
                                CrbRegister::LocState(LocStateFields::LocAssigned),
                                0,
                            );
                            set_reg_field(
                                &mut self.regs,
                                CrbRegister::LocSts(LocStsFields::Granted),
                                0,
                            );
                        }
                        CRB_LOC_CTRL_REQUEST_ACCESS => {
                            set_reg_field(
                                &mut self.regs,
                                CrbRegister::LocSts(LocStsFields::Granted),
                                1,
                            );
                            set_reg_field(
                                &mut self.regs,
                                CrbRegister::LocSts(LocStsFields::BeenSeized),
                                0,
                            );
                            set_reg_field(
                                &mut self.regs,
                                CrbRegister::LocState(LocStateFields::LocAssigned),
                                1,
                            );
                        }
                        _ => {
                            error!("Invalid value to write in CRB_LOC_CTRL {v:#X} ");
                        }
                    }
                }
                _ => {
                    error!(
                        "Invalid tpm write: offset {:#X}, data length {:?}",
                        offset,
                        data.len()
                    );
                }
            }
        }
        true
    }
}

impl AmlBuilder for TpmCrb {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut tpm2_dev = AmlDevice::new("TPM2");
        tpm2_dev.append_child(AmlNameDecl::new("_HID", AmlString("MSFT0101".to_string())));
        tpm2_dev.append_child(AmlNameDecl::new("_STA", AmlInteger(0xF)));

        let mut res = AmlResTemplate::new();
        res.append_child(AmlMemory32Fixed::new(
            AmlReadAndWrite::ReadWrite,
            self.base.res.region_base as u32,
            self.base.res.region_size as u32,
        ));
        tpm2_dev.append_child(AmlNameDecl::new("_CRS", res));

        tpm2_dev.aml_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_get_reg_field() {
        let mut regs: [u32; TPM_CRB_R_MAX] = [0; TPM_CRB_R_MAX];
        set_reg_field(&mut regs, CrbRegister::IntfId(IntfIdFields::Rid), 0xAC);
        assert_eq!(
            get_reg_field(&regs, CrbRegister::IntfId(IntfIdFields::Rid)),
            0xAC,
            concat!("Test: ", stringify!(set_get_reg_field))
        );
    }
}
