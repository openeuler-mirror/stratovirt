// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex, Weak};

use anyhow::{bail, Context, Result};

use crate::ScsiCntlr::{
    ScsiCntlr, ScsiCompleteCb, ScsiXferMode, VirtioScsiCmdReq, VirtioScsiCmdResp,
    VirtioScsiRequest, VIRTIO_SCSI_CDB_DEFAULT_SIZE, VIRTIO_SCSI_S_OK,
};
use crate::ScsiDisk::ScsiDevice;
use byteorder::{BigEndian, ByteOrder};
use log::{debug, info};
use util::aio::{Aio, AioCb, IoCmd, Iovec};

/// Scsi Operation code.
pub const TEST_UNIT_READY: u8 = 0x00;
pub const REWIND: u8 = 0x01;
pub const REQUEST_SENSE: u8 = 0x03;
pub const FORMAT_UNIT: u8 = 0x04;
pub const READ_BLOCK_LIMITS: u8 = 0x05;
pub const INITIALIZE_ELEMENT_STATUS: u8 = 0x07;
pub const REASSIGN_BLOCKS: u8 = 0x07;
pub const READ_6: u8 = 0x08;
pub const WRITE_6: u8 = 0x0a;
pub const SET_CAPACITY: u8 = 0x0b;
pub const READ_REVERSE: u8 = 0x0f;
pub const WRITE_FILEMARKS: u8 = 0x10;
pub const SPACE: u8 = 0x11;
pub const INQUIRY: u8 = 0x12;
pub const RECOVER_BUFFERED_DATA: u8 = 0x14;
pub const MODE_SELECT: u8 = 0x15;
pub const RESERVE: u8 = 0x16;
pub const RELEASE: u8 = 0x17;
pub const COPY: u8 = 0x18;
pub const ERASE: u8 = 0x19;
pub const MODE_SENSE: u8 = 0x1a;
pub const LOAD_UNLOAD: u8 = 0x1b;
pub const SCAN: u8 = 0x1b;
pub const START_STOP: u8 = 0x1b;
pub const RECEIVE_DIAGNOSTIC: u8 = 0x1c;
pub const SEND_DIAGNOSTIC: u8 = 0x1d;
pub const ALLOW_MEDIUM_REMOVAL: u8 = 0x1e;
pub const SET_WINDOW: u8 = 0x24;
pub const READ_CAPACITY_10: u8 = 0x25;
pub const GET_WINDOW: u8 = 0x25;
pub const READ_10: u8 = 0x28;
pub const WRITE_10: u8 = 0x2a;
pub const SEND: u8 = 0x2a;
pub const SEEK_10: u8 = 0x2b;
pub const LOCATE_10: u8 = 0x2b;
pub const POSITION_TO_ELEMENT: u8 = 0x2b;
pub const WRITE_VERIFY_10: u8 = 0x2e;
pub const VERIFY_10: u8 = 0x2f;
pub const SEARCH_HIGH: u8 = 0x30;
pub const SEARCH_EQUAL: u8 = 0x31;
pub const OBJECT_POSITION: u8 = 0x31;
pub const SEARCH_LOW: u8 = 0x32;
pub const SET_LIMITS: u8 = 0x33;
pub const PRE_FETCH: u8 = 0x34;
pub const READ_POSITION: u8 = 0x34;
pub const GET_DATA_BUFFER_STATUS: u8 = 0x34;
pub const SYNCHRONIZE_CACHE: u8 = 0x35;
pub const LOCK_UNLOCK_CACHE: u8 = 0x36;
pub const INITIALIZE_ELEMENT_STATUS_WITH_RANGE: u8 = 0x37;
pub const READ_DEFECT_DATA: u8 = 0x37;
pub const MEDIUM_SCAN: u8 = 0x38;
pub const COMPARE: u8 = 0x39;
pub const COPY_VERIFY: u8 = 0x3a;
pub const WRITE_BUFFER: u8 = 0x3b;
pub const READ_BUFFER: u8 = 0x3c;
pub const UPDATE_BLOCK: u8 = 0x3d;
pub const READ_LONG_10: u8 = 0x3e;
pub const WRITE_LONG_10: u8 = 0x3f;
pub const CHANGE_DEFINITION: u8 = 0x40;
pub const WRITE_SAME_10: u8 = 0x41;
pub const UNMAP: u8 = 0x42;
pub const READ_TOC: u8 = 0x43;
pub const REPORT_DENSITY_SUPPORT: u8 = 0x44;
pub const GET_CONFIGURATION: u8 = 0x46;
pub const SANITIZE: u8 = 0x48;
pub const GET_EVENT_STATUS_NOTIFICATION: u8 = 0x4a;
pub const LOG_SELECT: u8 = 0x4c;
pub const LOG_SENSE: u8 = 0x4d;
pub const READ_DISC_INFORMATION: u8 = 0x51;
pub const RESERVE_TRACK: u8 = 0x53;
pub const MODE_SELECT_10: u8 = 0x55;
pub const RESERVE_10: u8 = 0x56;
pub const RELEASE_10: u8 = 0x57;
pub const MODE_SENSE_10: u8 = 0x5a;
pub const SEND_CUE_SHEET: u8 = 0x5d;
pub const PERSISTENT_RESERVE_IN: u8 = 0x5e;
pub const PERSISTENT_RESERVE_OUT: u8 = 0x5f;
pub const VARLENGTH_CDB: u8 = 0x7f;
pub const WRITE_FILEMARKS_16: u8 = 0x80;
pub const READ_REVERSE_16: u8 = 0x81;
pub const ALLOW_OVERWRITE: u8 = 0x82;
pub const EXTENDED_COPY: u8 = 0x83;
pub const ATA_PASSTHROUGH_16: u8 = 0x85;
pub const ACCESS_CONTROL_IN: u8 = 0x86;
pub const ACCESS_CONTROL_OUT: u8 = 0x87;
pub const READ_16: u8 = 0x88;
pub const COMPARE_AND_WRITE: u8 = 0x89;
pub const WRITE_16: u8 = 0x8a;
pub const WRITE_VERIFY_16: u8 = 0x8e;
pub const VERIFY_16: u8 = 0x8f;
pub const PRE_FETCH_16: u8 = 0x90;
pub const SPACE_16: u8 = 0x91;
pub const SYNCHRONIZE_CACHE_16: u8 = 0x91;
pub const LOCATE_16: u8 = 0x92;
pub const WRITE_SAME_16: u8 = 0x93;
pub const ERASE_16: u8 = 0x93;
pub const SERVICE_ACTION_IN_16: u8 = 0x9e;
pub const WRITE_LONG_16: u8 = 0x9f;
pub const REPORT_LUNS: u8 = 0xa0;
pub const ATA_PASSTHROUGH_12: u8 = 0xa1;
pub const MAINTENANCE_IN: u8 = 0xa3;
pub const MAINTENANCE_OUT: u8 = 0xa4;
pub const MOVE_MEDIUM: u8 = 0xa5;
pub const EXCHANGE_MEDIUM: u8 = 0xa6;
pub const SET_READ_AHEAD: u8 = 0xa7;
pub const READ_12: u8 = 0xa8;
pub const WRITE_12: u8 = 0xaa;
pub const SERVICE_ACTION_IN_12: u8 = 0xab;
pub const ERASE_12: u8 = 0xac;
pub const READ_DVD_STRUCTURE: u8 = 0xad;
pub const WRITE_VERIFY_12: u8 = 0xae;
pub const VERIFY_12: u8 = 0xaf;
pub const SEARCH_HIGH_12: u8 = 0xb0;
pub const SEARCH_EQUAL_12: u8 = 0xb1;
pub const SEARCH_LOW_12: u8 = 0xb2;
pub const READ_ELEMENT_STATUS: u8 = 0xb8;
pub const SEND_VOLUME_TAG: u8 = 0xb6;
pub const READ_DEFECT_DATA_12: u8 = 0xb7;
pub const SET_CD_SPEED: u8 = 0xbb;
pub const MECHANISM_STATUS: u8 = 0xbd;
pub const READ_CD: u8 = 0xbe;
pub const SEND_DVD_STRUCTURE: u8 = 0xbf;

/// SAM Status codes.
pub const GOOD: u8 = 0x00;
pub const CHECK_CONDITION: u8 = 0x02;
pub const CONDITION_GOOD: u8 = 0x04;
pub const BUSY: u8 = 0x08;
pub const INTERMEDIATE_GOOD: u8 = 0x10;
pub const INTERMEDIATE_C_GOOD: u8 = 0x14;
pub const RESERVATION_CONFLICT: u8 = 0x18;
pub const COMMAND_TERMINATED: u8 = 0x22;
pub const TASK_SET_FULL: u8 = 0x28;
pub const ACA_ACTIVE: u8 = 0x30;
pub const TASK_ABORTED: u8 = 0x40;

pub const STATUS_MASK: u8 = 0x3e;

pub const SCSI_CMD_BUF_SIZE: usize = 16;
pub const SCSI_SENSE_BUF_SIZE: usize = 252;

/// SERVICE ACTION IN subcodes.
pub const SAI_READ_CAPACITY_16: u8 = 0x10;

/// Used to compute the number of sectors.
const SECTOR_SHIFT: u8 = 9;
/// Size of a sector of the block device.
const SECTOR_SIZE: u64 = (0x01_u64) << SECTOR_SHIFT;

/// Sense Keys.
pub const NO_SENSE: u8 = 0x00;
pub const RECOVERED_ERROR: u8 = 0x01;
pub const NOT_READY: u8 = 0x02;
pub const MEDIUM_ERROR: u8 = 0x03;
pub const HARDWARE_ERROR: u8 = 0x04;
pub const ILLEGAL_REQUEST: u8 = 0x05;
pub const UNIT_ATTENTION: u8 = 0x06;
pub const DATA_PROTECT: u8 = 0x07;
pub const BLANK_CHECK: u8 = 0x08;
pub const COPY_ABORTED: u8 = 0x0a;
pub const ABORTED_COMMAND: u8 = 0x0b;
pub const VOLUME_OVERFLOW: u8 = 0x0d;
pub const MISCOMPARE: u8 = 0x0e;

macro_rules! scsisense {
    ( $key:expr, $asc: expr, $ascq:expr) => {
        ScsiSense {
            key: $key,
            asc: $asc,
            ascq: $ascq,
        }
    };
}

/// Sense Code.
pub const SCSI_SENSE_NO_SENSE: ScsiSense = scsisense!(NO_SENSE, 0x00, 0x00);
pub const SCSI_SENSE_LUN_NOT_READY: ScsiSense = scsisense!(NOT_READY, 0x04, 0x03);
pub const SCSI_SENSE_NO_MEDIUM: ScsiSense = scsisense!(NOT_READY, 0x3a, 0x00);
pub const SCSI_SENSE_NOT_READY_REMOVAL_PREVENTED: ScsiSense = scsisense!(NOT_READY, 0x53, 0x02);
pub const SCSI_SENSE_TARGET_FAILURE: ScsiSense = scsisense!(HARDWARE_ERROR, 0x44, 0x00);
pub const SCSI_SENSE_INVALID_OPCODE: ScsiSense = scsisense!(ILLEGAL_REQUEST, 0x20, 0x00);
pub const SCSI_SENSE_LBA_OUT_OF_RANGE: ScsiSense = scsisense!(ILLEGAL_REQUEST, 0x21, 0x00);
pub const SCSI_SENSE_INVALID_FIELD: ScsiSense = scsisense!(ILLEGAL_REQUEST, 0x24, 0x00);
pub const SCSI_SENSE_INVALID_PARAM: ScsiSense = scsisense!(ILLEGAL_REQUEST, 0x26, 0x00);
pub const SCSI_SENSE_INVALID_PARAM_VALUE: ScsiSense = scsisense!(ILLEGAL_REQUEST, 0x26, 0x01);
pub const SCSI_SENSE_INVALID_PARAM_LEN: ScsiSense = scsisense!(ILLEGAL_REQUEST, 0x1a, 0x00);
pub const SCSI_SENSE_LUN_NOT_SUPPORTED: ScsiSense = scsisense!(ILLEGAL_REQUEST, 0x25, 0x00);
pub const SCSI_SENSE_SAVING_PARAMS_NOT_SUPPORTED: ScsiSense =
    scsisense!(ILLEGAL_REQUEST, 0x39, 0x00);
pub const SCSI_SENSE_INCOMPATIBLE_FORMAT: ScsiSense = scsisense!(ILLEGAL_REQUEST, 0x30, 0x00);
pub const SCSI_SENSE_ILLEGAL_REQ_REMOVAL_PREVENTED: ScsiSense =
    scsisense!(ILLEGAL_REQUEST, 0x53, 0x02);
pub const SCSI_SENSE_INVALID_TAG: ScsiSense = scsisense!(ILLEGAL_REQUEST, 0x4b, 0x01);
pub const SCSI_SENSE_IO_ERROR: ScsiSense = scsisense!(ABORTED_COMMAND, 0x00, 0x06);
pub const SCSI_SENSE_I_T_NEXUS_LOSS: ScsiSense = scsisense!(ABORTED_COMMAND, 0x29, 0x07);
pub const SCSI_SENSE_LUN_FAILURE: ScsiSense = scsisense!(ABORTED_COMMAND, 0x3e, 0x01);
pub const SCSI_SENSE_OVERLAPPED_COMMANDS: ScsiSense = scsisense!(ABORTED_COMMAND, 0x4e, 0x00);
pub const SCSI_SENSE_LUN_COMM_FAILURE: ScsiSense = scsisense!(ABORTED_COMMAND, 0x08, 0x00);
pub const SCSI_SENSE_LUN_NOT_RESPONDING: ScsiSense = scsisense!(ABORTED_COMMAND, 0x05, 0x00);
pub const SCSI_SENSE_COMMAND_TIMEOUT: ScsiSense = scsisense!(ABORTED_COMMAND, 0x2e, 0x02);
pub const SCSI_SENSE_COMMAND_ABORTED: ScsiSense = scsisense!(ABORTED_COMMAND, 0x2f, 0x02);
pub const SCSI_SENSE_READ_ERROR: ScsiSense = scsisense!(MEDIUM_ERROR, 0x11, 0x00);
pub const SCSI_SENSE_NOT_READY: ScsiSense = scsisense!(NOT_READY, 0x04, 0x00);
pub const SCSI_SENSE_CAPACITY_CHANGED: ScsiSense = scsisense!(UNIT_ATTENTION, 0x2a, 0x09);
pub const SCSI_SENSE_RESET: ScsiSense = scsisense!(UNIT_ATTENTION, 0x29, 0x00);
pub const SCSI_SENSE_SCSI_BUS_RESET: ScsiSense = scsisense!(UNIT_ATTENTION, 0x29, 0x02);
pub const SCSI_SENSE_UNIT_ATTENTION_NO_MEDIUM: ScsiSense = scsisense!(UNIT_ATTENTION, 0x3a, 0x00);
pub const SCSI_SENSE_MEDIUM_CHANGED: ScsiSense = scsisense!(UNIT_ATTENTION, 0x28, 0x00);
pub const SCSI_SENSE_REPORTED_LUNS_CHANGED: ScsiSense = scsisense!(UNIT_ATTENTION, 0x3f, 0x0e);
pub const SCSI_SENSE_DEVICE_INTERNAL_RESET: ScsiSense = scsisense!(UNIT_ATTENTION, 0x29, 0x04);
pub const SCSI_SENSE_WRITE_PROTECTED: ScsiSense = scsisense!(DATA_PROTECT, 0x27, 0x00);
pub const SCSI_SENSE_SPACE_ALLOC_FAILED: ScsiSense = scsisense!(DATA_PROTECT, 0x27, 0x07);

#[derive(Default)]
pub struct ScsiSense {
    key: u8,
    asc: u8,
    ascq: u8,
}

pub const SCSI_SENSE_LEN: u32 = 18;

pub struct ScsiBus {
    /// Bus name.
    pub name: String,
    /// Scsi Devices attached to the bus.
    pub devices: HashMap<(u8, u16), Arc<Mutex<ScsiDevice>>>,
    /// Scsi Controller which the bus orignates from.
    pub parent_cntlr: Weak<Mutex<ScsiCntlr>>,
}

impl ScsiBus {
    pub fn new(bus_name: String, parent_cntlr: Weak<Mutex<ScsiCntlr>>) -> ScsiBus {
        ScsiBus {
            name: bus_name,
            devices: HashMap::new(),
            parent_cntlr,
        }
    }

    /// Get device by the target number and the lun number.
    pub fn get_device(&self, target: u8, lun: u16) -> Option<Arc<Mutex<ScsiDevice>>> {
        if let Some(dev) = self.devices.get(&(target, lun)) {
            return Some((*dev).clone());
        }
        debug!("Can't find scsi device target {} lun {}", target, lun);
        None
    }

    pub fn scsi_bus_parse_req_cdb(
        &self,
        cdb: [u8; VIRTIO_SCSI_CDB_DEFAULT_SIZE],
    ) -> Option<ScsiCommand> {
        let buf: [u8; SCSI_CMD_BUF_SIZE] = (cdb[0..SCSI_CMD_BUF_SIZE])
            .try_into()
            .expect("incorrect length");
        let command = cdb[0];
        let len = scsi_cdb_length(&cdb);
        if len < 0 {
            return None;
        }

        let xfer = scsi_cdb_xfer(&cdb);
        if xfer < 0 {
            return None;
        }

        let lba = scsi_cdb_lba(&cdb);
        if lba < 0 {
            return None;
        }

        Some(ScsiCommand {
            buf,
            command,
            len: len as u32,
            xfer: xfer as u32,
            lba: lba as u64,
            mode: scsi_cdb_xfer_mode(&cdb),
        })
    }
}

pub fn create_scsi_bus(bus_name: &str, scsi_cntlr: &Arc<Mutex<ScsiCntlr>>) -> Result<()> {
    let mut locked_scsi_cntlr = scsi_cntlr.lock().unwrap();
    let bus = ScsiBus::new(bus_name.to_string(), Arc::downgrade(scsi_cntlr));
    locked_scsi_cntlr.bus = Some(Arc::new(Mutex::new(bus)));
    Ok(())
}

#[derive(Clone)]
pub struct ScsiCommand {
    /// The Command Descriptor Block(CDB).
    pub buf: [u8; SCSI_CMD_BUF_SIZE],
    /// Scsi Operation Code.
    pub command: u8,
    /// Length of CDB.
    pub len: u32,
    /// Transfer length.
    pub xfer: u32,
    /// Logical Block Address.
    pub lba: u64,
    /// Transfer direction.
    mode: ScsiXferMode,
}

#[derive(Clone)]
pub struct ScsiRequest {
    cmd: ScsiCommand,
    _sense: [u8; SCSI_SENSE_BUF_SIZE],
    _sense_size: u32,
    _resid: u32,
    pub opstype: u32,
    pub virtioscsireq: Arc<Mutex<VirtioScsiRequest<VirtioScsiCmdReq, VirtioScsiCmdResp>>>,
    _dev: Arc<Mutex<ScsiDevice>>,
}

impl ScsiRequest {
    pub fn new(
        req: Arc<Mutex<VirtioScsiRequest<VirtioScsiCmdReq, VirtioScsiCmdResp>>>,
        scsibus: Arc<Mutex<ScsiBus>>,
        scsidevice: Arc<Mutex<ScsiDevice>>,
    ) -> Result<Self> {
        if let Some(cmd) = scsibus
            .lock()
            .unwrap()
            .scsi_bus_parse_req_cdb(req.lock().unwrap().req.cdb)
        {
            let ops = cmd.command;
            let opstype = scsi_operation_type(ops);
            let _resid = cmd.xfer;

            Ok(ScsiRequest {
                cmd,
                _sense: [0; SCSI_SENSE_BUF_SIZE],
                _sense_size: 0,
                _resid,
                opstype,
                virtioscsireq: req.clone(),
                _dev: scsidevice,
            })
        } else {
            bail!("Error CDB!");
        }
    }

    pub fn execute(
        &self,
        aio: &mut Box<Aio<ScsiCompleteCb>>,
        disk: &File,
        direct: bool,
        last_aio: bool,
        iocompletecb: ScsiCompleteCb,
    ) -> Result<u32> {
        let mut aiocb = AioCb {
            last_aio,
            file_fd: disk.as_raw_fd(),
            opcode: IoCmd::Noop,
            iovec: Vec::new(),
            offset: (self.cmd.lba << 9) as usize,
            process: true,
            iocb: None,
            iocompletecb,
        };

        for iov in self.virtioscsireq.lock().unwrap().iovec.iter() {
            let iovec = Iovec {
                iov_base: iov.iov_base,
                iov_len: iov.iov_len,
            };
            aiocb.iovec.push(iovec);
        }

        match self.cmd.mode {
            ScsiXferMode::ScsiXferFromDev => {
                aiocb.opcode = IoCmd::Preadv;
                if direct {
                    (*aio)
                        .as_mut()
                        .rw_aio(aiocb, SECTOR_SIZE)
                        .with_context(|| {
                            "Failed to process scsi request for reading asynchronously"
                        })?;
                } else {
                    (*aio).as_mut().rw_sync(aiocb).with_context(|| {
                        "Failed to process scsi request for reading synchronously"
                    })?;
                }
            }
            ScsiXferMode::ScsiXferToDev => {
                aiocb.opcode = IoCmd::Pwritev;
                if direct {
                    (*aio)
                        .as_mut()
                        .rw_aio(aiocb, SECTOR_SIZE)
                        .with_context(|| {
                            "Failed to process block request for writing asynchronously"
                        })?;
                } else {
                    (*aio).as_mut().rw_sync(aiocb).with_context(|| {
                        "Failed to process block request for writing synchronously"
                    })?;
                }
            }
            _ => {
                info!("xfer none");
            }
        }
        Ok(0)
    }

    pub fn emulate_execute(&self, iocompletecb: ScsiCompleteCb) -> Result<u32> {
        debug!("scsi command is {:#x}", self.cmd.command);
        match self.cmd.command {
            _ => {
                info!(
                    "emulation scsi command {:#x} is not supported",
                    self.cmd.command
                );
                self.set_scsi_sense(SCSI_SENSE_INVALID_OPCODE);

                let mut req = self.virtioscsireq.lock().unwrap();
                req.resp.response = VIRTIO_SCSI_S_OK;
                req.resp.status = CHECK_CONDITION;
                req.resp.resid = 0;

                req.complete(&iocompletecb.mem_space);
            }
        }

        Ok(0)
    }

    fn set_scsi_sense(&self, sense: ScsiSense) {
        let mut req = self.virtioscsireq.lock().unwrap();
        req.resp.sense[0] = 0x70; // Response code: current errors(0x70).
        req.resp.sense[2] = sense.key;
        req.resp.sense[7] = 10; // Additional sense length: sense len - 8.
        req.resp.sense[12] = sense.asc;
        req.resp.sense[13] = sense.ascq;
        req.resp.sense_len = SCSI_SENSE_LEN;
    }
}

pub const EMULATE_SCSI_OPS: u32 = 0;
pub const DMA_SCSI_OPS: u32 = 1;

fn scsi_operation_type(op: u8) -> u32 {
    match op {
        READ_6 | READ_10 | READ_12 | READ_16 | WRITE_6 | WRITE_10 | WRITE_12 | WRITE_16
        | WRITE_VERIFY_10 | WRITE_VERIFY_12 | WRITE_VERIFY_16 => DMA_SCSI_OPS,
        _ => EMULATE_SCSI_OPS,
    }
}

//   lun: [u8, 8]
//   | Byte 0 | Byte 1 | Byte 2 | Byte 3 | Byte 4 | Byte 5 | Byte 6 | Byte 7 |
//   |    1   | target |       lun       |                 0                 |
pub fn virtio_scsi_get_lun(lun: [u8; 8]) -> u16 {
    (((lun[2] as u16) << 8) | (lun[3] as u16)) & 0x3FFF
}

fn scsi_cdb_length(cdb: &[u8; VIRTIO_SCSI_CDB_DEFAULT_SIZE]) -> i32 {
    match cdb[0] >> 5 {
        0 => 6,
        1 | 2 => 10,
        4 => 16,
        5 => 12,
        _ => -1,
    }
}

fn scsi_cdb_xfer(cdb: &[u8; VIRTIO_SCSI_CDB_DEFAULT_SIZE]) -> i32 {
    let mut xfer = match cdb[0] >> 5 {
        0 => cdb[4] as i32,
        1 | 2 => BigEndian::read_u16(&cdb[7..]) as i32,
        4 => BigEndian::read_u32(&cdb[10..]) as i32,
        5 => BigEndian::read_u32(&cdb[6..]) as i32,
        _ => -1,
    };

    match cdb[0] {
        TEST_UNIT_READY | REWIND | START_STOP | SET_CAPACITY | WRITE_FILEMARKS
        | WRITE_FILEMARKS_16 | SPACE | RESERVE | RELEASE | ERASE | ALLOW_MEDIUM_REMOVAL
        | SEEK_10 | SYNCHRONIZE_CACHE | SYNCHRONIZE_CACHE_16 | LOCATE_16 | LOCK_UNLOCK_CACHE
        | SET_CD_SPEED | SET_LIMITS | WRITE_LONG_10 | UPDATE_BLOCK | RESERVE_TRACK
        | SET_READ_AHEAD | PRE_FETCH | PRE_FETCH_16 | ALLOW_OVERWRITE => {
            xfer = 0;
        }
        VERIFY_10 | VERIFY_12 | VERIFY_16 => {
            if cdb[1] & 2 == 0 {
                xfer = 0;
            } else if cdb[1] & 4 != 0 {
                xfer = 1;
            }
            // 512 : blocksize
            xfer *= 512;
        }
        WRITE_SAME_10 | WRITE_SAME_16 => {
            if cdb[1] & 1 == 0 {
                xfer = 0;
            } else {
                xfer = 512;
            }
        }
        READ_CAPACITY_10 => {
            xfer = 8;
        }
        READ_BLOCK_LIMITS => {
            xfer = 6;
        }
        SEND_VOLUME_TAG => {
            xfer = i32::from(cdb[9]) | i32::from(cdb[8]) << 8;
        }
        WRITE_6 => {
            if xfer == 0 {
                xfer = 256 * 512;
            }
        }
        WRITE_10 | WRITE_VERIFY_10 | WRITE_12 | WRITE_VERIFY_12 | WRITE_16 | WRITE_VERIFY_16 => {
            xfer *= 512;
        }
        READ_6 | READ_REVERSE => {
            if xfer == 0 {
                xfer = 256 * 512;
            }
        }
        READ_10 | READ_12 | READ_16 => {
            xfer *= 512;
        }
        FORMAT_UNIT => {
            xfer = match cdb[1] & 16 {
                0 => 0,
                _ => match cdb[1] & 32 {
                    0 => 4,
                    _ => 8,
                },
            };
        }
        INQUIRY | RECEIVE_DIAGNOSTIC | SEND_DIAGNOSTIC => {
            xfer = i32::from(cdb[4]) | i32::from(cdb[3]) << 8;
        }
        READ_CD | READ_BUFFER | WRITE_BUFFER | SEND_CUE_SHEET => {
            xfer = i32::from(cdb[8]) | i32::from(cdb[7]) << 8 | (u32::from(cdb[6]) << 16) as i32;
        }
        PERSISTENT_RESERVE_OUT => {
            xfer = BigEndian::read_i32(&cdb[5..]);
        }
        ERASE_12 | MECHANISM_STATUS | READ_DVD_STRUCTURE | SEND_DVD_STRUCTURE | MAINTENANCE_OUT
        | MAINTENANCE_IN => {}
        ATA_PASSTHROUGH_12 => {}
        ATA_PASSTHROUGH_16 => {}
        _ => {}
    }
    xfer
}

fn scsi_cdb_lba(cdb: &[u8; VIRTIO_SCSI_CDB_DEFAULT_SIZE]) -> i64 {
    match cdb[0] >> 5 {
        0 => (BigEndian::read_u32(&cdb[0..]) & 0x1fffff) as i64,
        1 | 2 | 5 => BigEndian::read_u32(&cdb[2..]) as i64,
        4 => BigEndian::read_u64(&cdb[2..]) as i64,
        _ => -1,
    }
}

fn scsi_cdb_xfer_mode(cdb: &[u8; VIRTIO_SCSI_CDB_DEFAULT_SIZE]) -> ScsiXferMode {
    match cdb[0] {
        WRITE_6
        | WRITE_10
        | WRITE_VERIFY_10
        | WRITE_12
        | WRITE_VERIFY_12
        | WRITE_16
        | WRITE_VERIFY_16
        | VERIFY_10
        | VERIFY_12
        | VERIFY_16
        | COPY
        | COPY_VERIFY
        | COMPARE
        | CHANGE_DEFINITION
        | LOG_SELECT
        | MODE_SELECT
        | MODE_SELECT_10
        | SEND_DIAGNOSTIC
        | WRITE_BUFFER
        | FORMAT_UNIT
        | REASSIGN_BLOCKS
        | SEARCH_EQUAL
        | SEARCH_HIGH
        | SEARCH_LOW
        | UPDATE_BLOCK
        | WRITE_LONG_10
        | WRITE_SAME_10
        | WRITE_SAME_16
        | UNMAP
        | SEARCH_HIGH_12
        | SEARCH_EQUAL_12
        | SEARCH_LOW_12
        | MEDIUM_SCAN
        | SEND_VOLUME_TAG
        | SEND_CUE_SHEET
        | SEND_DVD_STRUCTURE
        | PERSISTENT_RESERVE_OUT
        | MAINTENANCE_OUT
        | SET_WINDOW
        | SCAN => ScsiXferMode::ScsiXferToDev,

        ATA_PASSTHROUGH_12 | ATA_PASSTHROUGH_16 => match cdb[2] & 0x8 {
            0 => ScsiXferMode::ScsiXferToDev,
            _ => ScsiXferMode::ScsiXferFromDev,
        },

        _ => ScsiXferMode::ScsiXferFromDev,
    }
}
