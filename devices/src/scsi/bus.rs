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

use std::cmp;
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use byteorder::{BigEndian, ByteOrder};
use log::info;

use crate::ScsiDisk::{
    ScsiDevice, DEFAULT_SECTOR_SIZE, SCSI_CDROM_DEFAULT_BLOCK_SIZE_SHIFT,
    SCSI_DISK_DEFAULT_BLOCK_SIZE_SHIFT, SCSI_DISK_F_DPOFUA, SCSI_DISK_F_REMOVABLE, SCSI_TYPE_DISK,
    SCSI_TYPE_ROM, SECTOR_SHIFT,
};
use util::aio::{AioCb, AioReqResult, Iovec};
use util::AsAny;

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
/// The Read TOC command requests that the Drive read data from a table of contexts.
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

/// Scsi cdb length will be 6/10/12/16 bytes.
pub const SCSI_CMD_BUF_SIZE: usize = 16;
pub const SCSI_SENSE_BUF_SIZE: usize = 252;

/// SERVICE ACTION IN subcodes.
pub const SUBCODE_READ_CAPACITY_16: u8 = 0x10;

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
    /// Sense key.
    pub key: u8,
    /// Additional sense code.
    pub asc: u8,
    /// Additional sense code qualifier.
    pub ascq: u8,
}

/// Mode page codes for mode sense/set.
pub const MODE_PAGE_R_W_ERROR: u8 = 0x01;
pub const MODE_PAGE_HD_GEOMETRY: u8 = 0x04;
pub const MODE_PAGE_FLEXIBLE_DISK_GEOMETRY: u8 = 0x05;
pub const MODE_PAGE_CACHING: u8 = 0x08;
pub const MODE_PAGE_AUDIO_CTL: u8 = 0x0e;
pub const MODE_PAGE_POWER: u8 = 0x1a;
pub const MODE_PAGE_FAULT_FAIL: u8 = 0x1c;
pub const MODE_PAGE_TO_PROTECT: u8 = 0x1d;
pub const MODE_PAGE_CAPABILITIES: u8 = 0x2a;
pub const MODE_PAGE_ALLS: u8 = 0x3f;

pub const SCSI_MAX_INQUIRY_LEN: u32 = 256;
pub const SCSI_INQUIRY_PRODUCT_MAX_LEN: usize = 16;
pub const SCSI_INQUIRY_VENDOR_MAX_LEN: usize = 8;
pub const SCSI_INQUIRY_VERSION_MAX_LEN: usize = 4;
pub const SCSI_INQUIRY_VPD_SERIAL_NUMBER_MAX_LEN: usize = 32;

const SCSI_TARGET_INQUIRY_LEN: u32 = 36;

/// |     bit7 - bit 5     |     bit 4 - bit 0      |
/// | Peripheral Qualifier | Peripheral Device Type |
/// Unknown or no device type.
const TYPE_UNKNOWN: u8 = 0x1f;
/// A peripheral device having the specified peripheral device type is not connected to this logical
/// unit.
const TYPE_INACTIVE: u8 = 0x20;
/// Scsi target device is not capable of supporting a peripheral device connected to this logical
/// unit.
const TYPE_NO_LUN: u8 = 0x7f;

/// Notification Classes for GET EVENT STATUS NOTIFICATION.
/// 000b: No requested Event Classes are supported.
pub const GESN_NO_REQUESTED_EVENT: u8 = 0;
/// 001b: Operational Change Request/Notification.
pub const GESN_OPERATIONAL_CHANGE: u8 = 1;
/// 010b: Power Management.
pub const GESN_POWER_MANAGEMENT: u8 = 2;
/// 011b: External Request.
pub const GESN_EXTERNAL_REQUEST: u8 = 3;
/// 100b: Media.
pub const GESN_MEDIA: u8 = 4;
/// 101b: Multiple Hosts.
pub const GESN_MULTIPLE_HOSTS: u8 = 5;
/// 110b: Device Busy.
/// 111b: Reserved.
pub const GESN_DEVICE_BUSY: u8 = 6;

/// Media Status in Get Event Status Notification.
/// If the Media Present bit is set to zero, no media is present in the Drive.
/// If the Media Present bit is set to one, media is present in the Drive.
pub const GESN_MS_DOOR_OR_TRAY_OPEN_BIT: u8 = 0;
/// If the Door or Tray Open bit is set to zero, the Tray or Door mechanism is in the closed state.
/// If the Door or Tray Open bit is set to one, the Tray or Door mechanism is in the open state.
/// If the Drive does not have either a tray or a door, this bit shall be set to zero.
pub const GESN_MS_MEDIA_PRESENT_BIT: u8 = 1;

/// Event Code in Get Event Status Notification.
/// Media status is unchanged.
pub const GESN_EC_NOCHG: u8 = 0;
/// The Drive has received a request from the user(usually through a mechanical switch on the Drive)
/// to eject the specified slot or media.
pub const GESN_EC_EJECTREQUEST: u8 = 1;
/// The specified slot(or the Drive) has received new media, and is ready to access it.
pub const GESN_EC_NEWMEDIA: u8 = 2;
/// The media has been removed from the specified slot, and the Drive is unable to access the media
/// without user intervention. This applies to media changers only.
pub const GESN_EC_MEDIAREMOVAL: u8 = 3;
/// The user has requested that the media in the specified slot be loaded. This applies to media
/// changers only.
pub const GESN_EC_MEDIACHANGED: u8 = 4;
/// A DVD+RW background format has completed. Since DVD+RW Drives are capable of generationg
/// multiple media events concurrently, such Drives shall be capable of queuing media events.
pub const GESN_EC_BGFORMATCOMPLETED: u8 = 5;
/// A DVD+RW background format has been automatically restarted by the Drive. Since DVD+RW Drives
/// are capable of generationg multiple media events concurrently, such Drives shall be capable of
/// queuing media event.
pub const GESN_EC_BGFORMATRESTARTED: u8 = 6;

/// Some generally useful CD-ROM information. From <linux/cdrom.h>
/// Max. minutes per CD.
pub const CD_MINS: u32 = 74;
/// Seconds per minute.
pub const CD_SECS: u32 = 60;
/// Frames per second.
pub const CD_FRAMES: u32 = 75;
/// Bytes per frame, "cooked" mode.
pub const CD_FRAME_SIZE: u32 = 2048;
/// MSF numbering offset of the first frame.
pub const CD_MSF_OFFSET: u32 = 150;
/// Max bytes supported for CD in stratovirt now.
pub const CD_MAX_BYTES: u32 = CD_MINS * CD_SECS * CD_FRAMES * CD_FRAME_SIZE;
pub const CD_MAX_SECTORS: u32 = CD_MAX_BYTES / DEFAULT_SECTOR_SIZE;

/// Profile Number for GET CONFIGURATION command in MMC-6.
/// Read only Compact Disc capable.
const GC_PROFILE_CD_ROM: u16 = 0x0008;
/// Read only DVD.
const GC_PROFILE_DVD_ROM: u16 = 0x0010;

/// Features Codes for GET CONFIGURATION command in MMC-6.
/// A list of all Profiles supported by the Drive.
const GC_FC_PROFILE_LIST: u16 = 0x0000;
/// Mandatory behavior for all devices.
const GC_FC_CORE: u16 = 0x0001;
/// The medium may be removed from the device.
const GC_FC_REMOVABLE_MEDIUM: u16 = 0x0003;

#[derive(Clone, PartialEq, Eq)]
pub enum ScsiXferMode {
    /// TEST_UNIT_READY, ...
    ScsiXferNone,
    /// READ, INQUIRY, MODE_SENSE, ...
    ScsiXferFromDev,
    /// WRITE, MODE_SELECT, ...
    ScsiXferToDev,
}

pub struct ScsiBus {
    /// Bus name.
    pub name: String,
    /// Scsi Devices attached to the bus.
    pub devices: HashMap<(u8, u16), Arc<Mutex<ScsiDevice>>>,
}

impl ScsiBus {
    pub fn new(bus_name: String) -> ScsiBus {
        ScsiBus {
            name: bus_name,
            devices: HashMap::new(),
        }
    }

    /// Get device by the target number and the lun number.
    /// If the device requested by the target number and the lun number is non-existen,
    /// return the first device in ScsiBus's devices list. It's OK because we will not
    /// use this "random" device, we will just use it to prove that the target is existen.
    pub fn get_device(&self, target: u8, lun: u16) -> Option<Arc<Mutex<ScsiDevice>>> {
        if let Some(dev) = self.devices.get(&(target, lun)) {
            return Some((*dev).clone());
        }

        // If lun device requested in CDB's LUNS bytes is not found, it may be a target request.
        // Target request means if there is any lun in this scsi target, it will response some
        // scsi commands. And, if there is no lun found in this scsi target, it means such target
        // is non-existent. So, we should find if there exists a lun which has the same id with
        // target id in CBD's LUNS bytes. And, if there exist two or more luns which have the same
        // target id, just return the first one is OK enough.
        for (id, device) in self.devices.iter() {
            let (target_id, lun_id) = id;
            if *target_id == target {
                trace::scsi_bus_get_device(*target_id, lun, *lun_id);
                return Some((*device).clone());
            }
        }

        // No lun found in requested target. It seems there is no such target requested in
        // CDB's LUNS bytes.
        trace::scsi_bus_get_no_device(target, lun);
        None
    }
}

fn scsi_bus_parse_req_cdb(
    cdb: [u8; SCSI_CMD_BUF_SIZE],
    dev: Arc<Mutex<ScsiDevice>>,
) -> Option<ScsiCommand> {
    let op = cdb[0];
    let len = scsi_cdb_length(&cdb);
    if len < 0 {
        return None;
    }

    // When CDB's Group Code is vendor specific or reserved, len/xfer/lba will be negative.
    // So, don't need to check again after checking in cdb length.
    let xfer = scsi_cdb_xfer(&cdb, dev);
    let lba = scsi_cdb_lba(&cdb);

    Some(ScsiCommand {
        buf: cdb,
        op,
        len: len as u32,
        xfer: xfer as u32,
        lba: lba as u64,
        mode: scsi_cdb_xfer_mode(&cdb),
    })
}

#[derive(Clone)]
pub struct ScsiCommand {
    /// The Command Descriptor Block(CDB).
    pub buf: [u8; SCSI_CMD_BUF_SIZE],
    /// Scsi Operation Code.
    pub op: u8,
    /// Length of CDB.
    pub len: u32,
    /// Transfer length.
    pub xfer: u32,
    /// Logical Block Address.
    pub lba: u64,
    /// Transfer direction.
    pub mode: ScsiXferMode,
}

#[derive(Clone)]
pub struct ScsiCompleteCb {
    pub req: Arc<Mutex<ScsiRequest>>,
}

pub fn aio_complete_cb(aiocb: &AioCb<ScsiCompleteCb>, mut ret: i64) -> Result<()> {
    match aiocb.req_is_completed(ret) {
        AioReqResult::Inflight => return Ok(()),
        AioReqResult::Error(v) => ret = v,
        AioReqResult::Done => (),
    }

    let (status, sense) = if ret < 0 {
        (CHECK_CONDITION, Some(SCSI_SENSE_IO_ERROR))
    } else {
        (GOOD, None)
    };

    let sreq = &mut aiocb.iocompletecb.req.lock().unwrap();
    sreq.upper_req
        .as_mut()
        .scsi_request_complete_cb(status, sense)?;
    Ok(())
}

pub trait ScsiRequestOps: Send + Sync + AsAny {
    // Will be called in the end of this scsi instruction execution.
    fn scsi_request_complete_cb(&mut self, status: u8, scsisense: Option<ScsiSense>) -> Result<()>;
}

pub struct ScsiRequest {
    pub cmd: ScsiCommand,
    // Requested lun id for scsi request. It may be not equal to scsi device's lun id when it's a
    // scsi target request.
    pub req_lun: u16,
    pub opstype: u32,
    // For datain and dataout. Can be empty when it's a ScsiXferMode::ScsiXferNone request.
    pub iovec: Vec<Iovec>,
    // Provided buffer's length.
    pub datalen: u32,
    pub dev: Arc<Mutex<ScsiDevice>>,
    // Upper level request which contains this ScsiRequest.
    pub upper_req: Box<dyn ScsiRequestOps>,
}

impl ScsiRequest {
    pub fn new(
        cdb: [u8; SCSI_CMD_BUF_SIZE],
        req_lun: u16,
        iovec: Vec<Iovec>,
        datalen: u32,
        scsidevice: Arc<Mutex<ScsiDevice>>,
        upper_req: Box<dyn ScsiRequestOps>,
    ) -> Result<Self> {
        let cmd = scsi_bus_parse_req_cdb(cdb, scsidevice.clone()).with_context(|| "Error cdb!")?;
        let op = cmd.op;
        let opstype = scsi_operation_type(op);

        if op == WRITE_10 || op == READ_10 {
            let dev_lock = scsidevice.lock().unwrap();
            let disk_size = dev_lock.disk_sectors << SECTOR_SHIFT;
            let disk_type = dev_lock.scsi_type;
            drop(dev_lock);
            let offset_shift = match disk_type {
                SCSI_TYPE_DISK => SCSI_DISK_DEFAULT_BLOCK_SIZE_SHIFT,
                _ => SCSI_CDROM_DEFAULT_BLOCK_SIZE_SHIFT,
            };
            let offset = cmd
                .lba
                .checked_shl(offset_shift)
                .with_context(|| "Too large offset IO!")?;

            offset
                .checked_add(datalen as u64)
                .filter(|&off| off <= disk_size)
                .with_context(|| {
                    format!(
                        "op 0x{:x} read/write length {} from {} is larger than disk size {}",
                        op, datalen, offset, disk_size
                    )
                })?;
        }

        Ok(ScsiRequest {
            cmd,
            req_lun,
            opstype,
            iovec,
            datalen,
            dev: scsidevice,
            upper_req,
        })
    }

    pub fn execute(self) -> Result<Arc<Mutex<ScsiRequest>>> {
        let mode = self.cmd.mode.clone();
        let op = self.cmd.op;
        let dev = self.dev.clone();
        let locked_dev = dev.lock().unwrap();
        // SAFETY: the block_backend is assigned after device realized.
        let block_backend = locked_dev.block_backend.as_ref().unwrap();
        let mut locked_backend = block_backend.lock().unwrap();
        let s_req = Arc::new(Mutex::new(self));

        let scsicompletecb = ScsiCompleteCb { req: s_req.clone() };
        let offset_bits = match locked_dev.scsi_type {
            SCSI_TYPE_DISK => SCSI_DISK_DEFAULT_BLOCK_SIZE_SHIFT,
            _ => SCSI_CDROM_DEFAULT_BLOCK_SIZE_SHIFT,
        };
        let locked_req = s_req.lock().unwrap();
        let iovecs = locked_req.iovec.clone();
        let offset = (locked_req.cmd.lba << offset_bits) as usize;
        drop(locked_req);

        if op == SYNCHRONIZE_CACHE {
            locked_backend
                .datasync(scsicompletecb)
                .with_context(|| "Failed to process scsi request for flushing")?;
            locked_backend.flush_request()?;

            return Ok(s_req);
        }

        match mode {
            ScsiXferMode::ScsiXferFromDev => {
                locked_backend
                    .read_vectored(iovecs, offset, scsicompletecb)
                    .with_context(|| "Failed to process scsi request for reading")?;
            }
            ScsiXferMode::ScsiXferToDev => {
                locked_backend
                    .write_vectored(iovecs, offset, scsicompletecb)
                    .with_context(|| "Failed to process scsi request for writing")?;
            }
            _ => {
                info!("xfer none");
            }
        }

        locked_backend.flush_request()?;
        Ok(s_req)
    }

    fn emulate_target_execute(
        &self,
        not_supported_flag: &mut bool,
        sense: &mut Option<ScsiSense>,
    ) -> Result<Vec<u8>> {
        match self.cmd.op {
            REPORT_LUNS => scsi_command_emulate_report_luns(&self.cmd, &self.dev),
            INQUIRY => scsi_command_emulate_target_inquiry(self.req_lun, &self.cmd),
            REQUEST_SENSE => {
                if self.req_lun != 0 {
                    *sense = Some(SCSI_SENSE_LUN_NOT_SUPPORTED);
                }
                // Scsi Device does not realize sense buffer now, so just return.
                Ok(Vec::new())
            }
            TEST_UNIT_READY => Ok(Vec::new()),
            _ => {
                *not_supported_flag = true;
                *sense = Some(SCSI_SENSE_INVALID_OPCODE);
                Err(anyhow!("Invalid emulation target scsi command"))
            }
        }
    }

    fn emulate_device_execute(
        &self,
        not_supported_flag: &mut bool,
        sense: &mut Option<ScsiSense>,
    ) -> Result<Vec<u8>> {
        match self.cmd.op {
            REQUEST_SENSE => {
                *sense = Some(SCSI_SENSE_NO_SENSE);
                Ok(Vec::new())
            }
            TEST_UNIT_READY => {
                let dev_lock = self.dev.lock().unwrap();
                if dev_lock.block_backend.is_none() {
                    Err(anyhow!("No scsi backend!"))
                } else {
                    Ok(Vec::new())
                }
            }
            // Do not support SCSI_DISK_F_REMOVABLE now.
            // Return Ok is enough for START_STOP/ALLOW_MEDIUM_REMOVAL.
            // TODO: implement SCSI_DISK_F_REMOVABLE.
            START_STOP => Ok(Vec::new()),
            ALLOW_MEDIUM_REMOVAL => Ok(Vec::new()),
            INQUIRY => scsi_command_emulate_inquiry(&self.cmd, &self.dev),
            READ_CAPACITY_10 => scsi_command_emulate_read_capacity_10(&self.cmd, &self.dev),
            MODE_SENSE | MODE_SENSE_10 => scsi_command_emulate_mode_sense(&self.cmd, &self.dev),
            SERVICE_ACTION_IN_16 => scsi_command_emulate_service_action_in_16(&self.cmd, &self.dev),
            READ_DISC_INFORMATION => {
                scsi_command_emulate_read_disc_information(&self.cmd, &self.dev)
            }
            GET_EVENT_STATUS_NOTIFICATION => {
                scsi_command_emulate_get_event_status_notification(&self.cmd, &self.dev)
            }
            READ_TOC => scsi_command_emulate_read_toc(&self.cmd, &self.dev),
            GET_CONFIGURATION => scsi_command_emulate_get_configuration(&self.cmd, &self.dev),
            _ => {
                *not_supported_flag = true;
                Err(anyhow!("Emulation scsi command is not supported now!"))
            }
        }
    }

    pub fn emulate_execute(mut self) -> Result<Arc<Mutex<ScsiRequest>>> {
        trace::scsi_emulate_execute(self.cmd.op);
        let mut not_supported_flag = false;
        let mut sense = None;
        let mut status = GOOD;
        let found_lun = self.dev.lock().unwrap().config.lun;

        // Requested lun id is not equal to found device id means it may be a target request.
        // REPORT LUNS is also a target request command.
        let result = if self.req_lun != found_lun || self.cmd.op == REPORT_LUNS {
            self.emulate_target_execute(&mut not_supported_flag, &mut sense)
        } else {
            // It's not a target request.
            self.emulate_device_execute(&mut not_supported_flag, &mut sense)
        };

        match result {
            Ok(outbuf) => {
                outbuf_to_iov(self.cmd.op, &outbuf, &self.iovec)?;
            }
            Err(ref e) => {
                if not_supported_flag {
                    trace::scsi_emulate_execute_error(self.cmd.op, &"not supported");
                    status = CHECK_CONDITION;
                    sense = Some(SCSI_SENSE_INVALID_OPCODE);
                } else {
                    trace::scsi_emulate_execute_error(self.cmd.op, e);
                    status = CHECK_CONDITION;
                    sense = Some(SCSI_SENSE_INVALID_FIELD);
                }
            }
        }

        self.upper_req
            .as_mut()
            .scsi_request_complete_cb(status, sense)?;

        Ok(Arc::new(Mutex::new(self)))
    }
}

fn write_buf_mem(buf: &[u8], max: u64, hva: u64) -> Result<usize> {
    let mut slice =
    // SAFETY: The hva is managed by Address Space, it can be guaranteed to be legal.
    unsafe {
        std::slice::from_raw_parts_mut(hva as *mut u8, cmp::min(buf.len(), max as usize))
    };
    let size = (&mut slice)
        .write(buf)
        .with_context(|| format!("Failed to write buf(hva:{})", hva))?;

    Ok(size)
}

fn outbuf_to_iov(command: u8, outbuf: &[u8], iovec: &[Iovec]) -> Result<()> {
    let mut start = 0;
    for (idx, iov) in iovec.iter().enumerate() {
        if start >= outbuf.len() {
            return Ok(());
        }

        trace::scsi_outbuf_to_iov(command, outbuf.len(), iov.iov_len, idx, iovec.len());

        start += write_buf_mem(&outbuf[start..], iov.iov_len, iov.iov_base)
            .with_context(|| "Failed to write buf for scsi command result iov")?;
    }

    Ok(())
}

// Scsi Commands which are emulated in stratovirt and do noting to the backend.
pub const EMULATE_SCSI_OPS: u32 = 0;
// Scsi Commands which will do something(eg: read and write) to the backend.
pub const NON_EMULATE_SCSI_OPS: u32 = 1;

fn scsi_operation_type(op: u8) -> u32 {
    match op {
        READ_6 | READ_10 | READ_12 | READ_16 | WRITE_6 | WRITE_10 | WRITE_12 | WRITE_16
        | WRITE_VERIFY_10 | WRITE_VERIFY_12 | WRITE_VERIFY_16 | SYNCHRONIZE_CACHE => {
            NON_EMULATE_SCSI_OPS
        }
        _ => EMULATE_SCSI_OPS,
    }
}

fn scsi_cdb_length(cdb: &[u8; SCSI_CMD_BUF_SIZE]) -> i32 {
    match cdb[0] >> 5 {
        // CDB[0]: Operation Code Byte. Bits[0-4]: Command Code. Bits[5-7]: Group Code.
        // Group Code |  Meaning            |
        // 000b       |  6 bytes commands.  |
        // 001b       |  10 bytes commands. |
        // 010b       |  10 bytes commands. |
        // 011b       |  reserved.          |
        // 100b       |  16 bytes commands. |
        // 101b       |  12 bytes commands. |
        // 110b       |  vendor specific.   |
        // 111b       |  vendor specific.   |
        0 => 6,
        1 | 2 => 10,
        4 => 16,
        5 => 12,
        _ => -1,
    }
}

fn scsi_cdb_xfer(cdb: &[u8; SCSI_CMD_BUF_SIZE], dev: Arc<Mutex<ScsiDevice>>) -> i32 {
    let dev_lock = dev.lock().unwrap();
    let block_size = dev_lock.block_size as i32;
    drop(dev_lock);

    let mut xfer = match cdb[0] >> 5 {
        // Group Code  |  Transfer length. |
        // 000b        |  Byte[4].         |
        // 001b        |  Bytes[7-8].      |
        // 010b        |  Bytes[7-8].      |
        // 100b        |  Bytes[10-13].    |
        // 101b        |  Bytes[6-9].      |
        0 => cdb[4] as i32,
        1 | 2 => BigEndian::read_u16(&cdb[7..]) as i32,
        4 => BigEndian::read_u32(&cdb[10..]) as i32,
        5 => BigEndian::read_u32(&cdb[6..]) as i32,
        _ => -1,
    };

    match cdb[0] {
        TEST_UNIT_READY | START_STOP | SYNCHRONIZE_CACHE | SYNCHRONIZE_CACHE_16 => {
            xfer = 0;
        }
        READ_CAPACITY_10 => {
            xfer = 8;
        }
        WRITE_6 | READ_6 => {
            // length 0 means 256 blocks.
            if xfer == 0 {
                xfer = 256 * block_size;
            }
        }
        WRITE_10 | WRITE_12 | WRITE_16 | READ_10 | READ_12 | READ_16 => {
            xfer *= block_size;
        }
        INQUIRY => {
            xfer = i32::from(cdb[4]) | i32::from(cdb[3]) << 8;
        }
        _ => {}
    }
    xfer
}

fn scsi_cdb_lba(cdb: &[u8; SCSI_CMD_BUF_SIZE]) -> i64 {
    match cdb[0] >> 5 {
        // Group Code  |  Logical Block Address.       |
        // 000b        |  Byte[1].bits[0-4]~Byte[3].   |
        // 001b        |  Bytes[2-5].                  |
        // 010b        |  Bytes[2-5].                  |
        // 100b        |  Bytes[2-9].                  |
        // 101b        |  Bytes[2-5].                  |
        0 => (BigEndian::read_u32(&cdb[0..]) & 0x1fffff) as i64,
        1 | 2 | 5 => BigEndian::read_u32(&cdb[2..]) as i64,
        4 => BigEndian::read_u64(&cdb[2..]) as i64,
        _ => -1,
    }
}

fn scsi_cdb_xfer_mode(cdb: &[u8; SCSI_CMD_BUF_SIZE]) -> ScsiXferMode {
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

/// VPD: Vital Product Data.
fn scsi_command_emulate_vpd_page(
    cmd: &ScsiCommand,
    dev: &Arc<Mutex<ScsiDevice>>,
) -> Result<Vec<u8>> {
    let buflen: usize;
    let mut outbuf: Vec<u8> = vec![0; 4];

    let dev_lock = dev.lock().unwrap();
    let page_code = cmd.buf[2];

    outbuf[0] = dev_lock.scsi_type as u8 & 0x1f;
    outbuf[1] = page_code;

    match page_code {
        0x00 => {
            // Supported VPD Pages.
            outbuf.push(0_u8);
            if !dev_lock.state.serial.is_empty() {
                // 0x80: Unit Serial Number.
                outbuf.push(0x80);
            }
            // 0x83: Device Identification.
            outbuf.push(0x83);
            if dev_lock.scsi_type == SCSI_TYPE_DISK {
                // 0xb0: Block Limits.
                outbuf.push(0xb0);
                // 0xb1: Block Device Characteristics.
                outbuf.push(0xb1);
                // 0xb2: Logical Block Provisioning.
                outbuf.push(0xb2);
            }
            buflen = outbuf.len();
        }
        0x80 => {
            // Unit Serial Number.
            let len = dev_lock.state.serial.len();
            if len == 0 {
                bail!("Missed serial number!");
            }

            let l = cmp::min(SCSI_INQUIRY_VPD_SERIAL_NUMBER_MAX_LEN, len);
            let mut serial_vec = dev_lock.state.serial.as_bytes().to_vec();
            serial_vec.truncate(l);
            outbuf.append(&mut serial_vec);
            buflen = outbuf.len();
        }
        0x83 => {
            // Device Identification.
            let mut len: u8 = dev_lock.state.device_id.len() as u8;
            if len > (255 - 8) {
                len = 255 - 8;
            }

            if len > 0 {
                // 0x2: Code Set: ASCII, Protocol Identifier: reserved.
                // 0: Identifier Type, Association, Reserved, Piv.
                // 0: Reserved.
                // len: identifier length.
                outbuf.append(&mut [0x2_u8, 0_u8, 0_u8, len].to_vec());

                let mut device_id_vec = dev_lock.state.device_id.as_bytes().to_vec();
                device_id_vec.truncate(len as usize);
                outbuf.append(&mut device_id_vec);
            }
            buflen = outbuf.len();
        }
        0xb0 => {
            // Block Limits.
            if dev_lock.scsi_type == SCSI_TYPE_ROM {
                bail!("Invalid scsi type: SCSI_TYPE_ROM !");
            }
            outbuf.resize(64, 0);

            // Byte[4]: bit 0: wsnz: Write Same Non-zero.
            // Byte[5] = 0: Maximum compare and write length (COMPARE_AND_WRITE not supported).
            // Byte[6-7] = 0: Optimal transfer length granularity.
            // Byte[8-11]: Maximum transfer length.
            // Byte[12-15] = 0: Optimal Transfer Length.
            // Byte[16-19] = 0: Maximum Prefetch Length.
            // Byte[20-23]: Maximum unmap lba count.
            // Byte[24-27]: Maximum unmap block descriptor count.
            // Byte[28-31]: Optimal unmap granulatity.
            // Byte[32-35] = 0: Unmap Granularity alignment.
            // Byte[36-43]: Maximum write same length.
            // Bytes[44-47] = 0: Maximum atomic Transfer length.
            // Bytes[48-51] = 0: Atomic Alignment.
            // Bytes[52-55] = 0: Atomic Transfer Length Granularity.
            // Bytes[56-59] = 0: Maximum Atomic Transfer Length With Atomic Boundary.
            // Bytes[60-63] = 0: Maximum Atomic Boundary Size.
            outbuf[4] = 1;
            let max_xfer_length: u32 = u32::MAX / 512;
            BigEndian::write_u32(&mut outbuf[8..12], max_xfer_length);
            BigEndian::write_u64(&mut outbuf[36..44], max_xfer_length as u64);
            buflen = outbuf.len();
        }
        0xb1 => {
            // Block Device Characteristics.
            // 0: Medium Rotation Rate: 2Bytes.
            // 0: Product Type.
            // 0: Nominal Form Factor, Wacereq, Wabereq.
            // 0: Vbuls, Fuab, Bocs, Reserved, Zoned, Reserved.
            outbuf.append(&mut [0_u8, 0_u8, 0_u8, 0_u8, 0_u8].to_vec());
            buflen = 0x40;
        }
        0xb2 => {
            // Logical Block Provisioning.
            // 0: Threshold exponent.
            // 0xe0: LBPU(bit 7) | LBPWS | LBPWS10 | LBPRZ | ANC_SUP | DP.
            // 0: Threshold percentage | Provisioning Type.
            // 0: Threshold percentage.
            outbuf.append(&mut [0_u8, 0x60_u8, 1_u8, 0_u8].to_vec());
            buflen = 8;
        }
        _ => {
            bail!("Invalid INQUIRY pagecode {}", page_code);
        }
    }

    // It's OK for just using outbuf byte 3, because all page_code's buflen in stratovirt is less
    // than 255 now.
    outbuf[3] = buflen as u8 - 4;
    Ok(outbuf)
}

fn scsi_command_emulate_target_inquiry(lun: u16, cmd: &ScsiCommand) -> Result<Vec<u8>> {
    let mut outbuf: Vec<u8> = vec![0; 4];

    // Byte1: bit0: EVPD (Enable Vital product bit).
    if cmd.buf[1] == 0x1 {
        // Vital Product Data.
        // Byte2: Page Code.
        let page_code = cmd.buf[2];
        outbuf[1] = page_code;
        match page_code {
            0x00 => {
                // Supported page codes.
                // Page Length: outbuf.len() - 4. Supported VPD page list only has 0x00 item.
                outbuf[3] = 0x1;
                // Supported VPD page list. Only support this page.
                outbuf.push(0x00);
            }
            _ => {
                bail!("Emulate target inquiry invalid page code {:x}", page_code);
            }
        }
        return Ok(outbuf);
    }

    // EVPD = 0 means it's a Standard INQUIRY command.
    // Byte2: page code.
    if cmd.buf[2] != 0 {
        bail!("Invalid standard inquiry command!");
    }

    outbuf.resize(SCSI_TARGET_INQUIRY_LEN as usize, 0);
    let len = cmp::min(cmd.xfer, SCSI_TARGET_INQUIRY_LEN);

    // outbuf.
    // Byte0: Peripheral Qualifier | peripheral device type.
    // Byte1：RMB.
    // Byte2: VERSION.
    // Byte3: NORMACA | HISUP | Response Data Format.
    // Byte4: Additional length(outbuf.len() - 5).
    // Byte5: SCCS | ACC | TPGS | 3PC | RESERVED | PROTECT.
    // Byte6: ENCSERV | VS | MULTIP | ADDR16.
    // Byte7: WBUS16 | SYNC | CMDQUE | VS.
    if lun != 0 {
        outbuf[0] = TYPE_NO_LUN;
    } else {
        outbuf[0] = TYPE_UNKNOWN | TYPE_INACTIVE;
        // scsi version.
        outbuf[2] = 5;
        // HISUP(hierarchical support). Response Data Format(must be 2).
        outbuf[3] = 0x12;
        outbuf[4] = if len <= 5 {
            bail!("Invalid xfer field in INQUIRY command");
        } else {
            len as u8 - 5
        };
        // SYNC, CMDQUE(the logical unit supports the task management model).
        outbuf[7] = 0x12;
    }

    Ok(outbuf)
}

fn scsi_command_emulate_inquiry(
    cmd: &ScsiCommand,
    dev: &Arc<Mutex<ScsiDevice>>,
) -> Result<Vec<u8>> {
    // Byte1 bit0: EVPD(enable vital product data).
    if cmd.buf[1] == 0x1 {
        return scsi_command_emulate_vpd_page(cmd, dev);
    }

    if cmd.buf[2] != 0 {
        bail!("Invalid INQUIRY!");
    }

    let buflen = cmp::min(cmd.xfer, SCSI_MAX_INQUIRY_LEN);
    let mut outbuf: Vec<u8> = vec![0; SCSI_MAX_INQUIRY_LEN as usize];

    let dev_lock = dev.lock().unwrap();

    outbuf[0] = (dev_lock.scsi_type & 0x1f) as u8;
    outbuf[1] = match dev_lock.state.features & SCSI_DISK_F_REMOVABLE {
        1 => 0x80,
        _ => 0,
    };

    let product_bytes = dev_lock.state.product.as_bytes();
    let product_len = cmp::min(product_bytes.len(), SCSI_INQUIRY_PRODUCT_MAX_LEN);
    let vendor_bytes = dev_lock.state.vendor.as_bytes();
    let vendor_len = cmp::min(vendor_bytes.len(), SCSI_INQUIRY_VENDOR_MAX_LEN);
    let version_bytes = dev_lock.state.version.as_bytes();
    let vension_len = cmp::min(version_bytes.len(), SCSI_INQUIRY_VERSION_MAX_LEN);

    outbuf[16..16 + product_len].copy_from_slice(product_bytes);
    outbuf[8..8 + vendor_len].copy_from_slice(vendor_bytes);
    outbuf[32..32 + vension_len].copy_from_slice(version_bytes);

    drop(dev_lock);

    // outbuf:
    // Byte2: Version.
    // Byte3: bits[0-3]: Response Data Format; bit 4:Hisup.
    // Byte4: Additional Length(outbuf.len()-5).
    // Byte7: bit2: Cmdque; bit4: SYNC.
    outbuf[2] = 5;
    outbuf[3] = (2 | 0x10) as u8;

    if buflen > 36 {
        outbuf[4] = (buflen - 5) as u8;
    } else {
        outbuf[4] = 36 - 5;
    }

    outbuf[7] = 0x12;

    Ok(outbuf)
}

fn scsi_command_emulate_read_capacity_10(
    cmd: &ScsiCommand,
    dev: &Arc<Mutex<ScsiDevice>>,
) -> Result<Vec<u8>> {
    if cmd.buf[8] & 1 == 0 && cmd.lba != 0 {
        // PMI(Partial Medium Indicator)
        bail!("Invalid scsi cmd READ_CAPACITY_10!");
    }

    let dev_lock = dev.lock().unwrap();
    let block_size = dev_lock.block_size;
    let mut outbuf: Vec<u8> = vec![0; 8];
    let mut nb_sectors = cmp::min(dev_lock.disk_sectors as u32, u32::MAX);
    nb_sectors /= block_size / DEFAULT_SECTOR_SIZE;
    nb_sectors -= 1;

    // Bytes[0-3]: Returned Logical Block Address(the logical block address of the last logical
    //             block).
    // Bytes[4-7]: Logical Block Length In Bytes.
    BigEndian::write_u32(&mut outbuf[0..4], nb_sectors);
    BigEndian::write_u32(&mut outbuf[4..8], block_size);

    Ok(outbuf)
}

fn scsi_command_emulate_mode_sense(
    cmd: &ScsiCommand,
    dev: &Arc<Mutex<ScsiDevice>>,
) -> Result<Vec<u8>> {
    // disable block descriptors(DBD) bit.
    let mut dbd: bool = cmd.buf[1] & 0x8 != 0;
    let page_code = cmd.buf[2] & 0x3f;
    let page_control = (cmd.buf[2] & 0xc0) >> 6;
    let mut outbuf: Vec<u8> = vec![0];
    let dev_lock = dev.lock().unwrap();
    let mut dev_specific_parameter: u8 = 0;
    let mut nb_sectors = dev_lock.disk_sectors as u32;
    let scsi_type = dev_lock.scsi_type;
    let block_size = dev_lock.block_size;
    nb_sectors /= block_size / DEFAULT_SECTOR_SIZE;

    trace::scsi_emulate_mode_sense(
        page_code,
        page_control,
        cmd.buf[3],
        cmd.buf[1] & 0x8,
        cmd.buf[4],
    );

    // Device specific paramteter field for direct access block devices:
    // Bit 7: WP(Write Protect); bit 4: DPOFUA;
    if scsi_type == SCSI_TYPE_DISK {
        if dev_lock.state.features & (1 << SCSI_DISK_F_DPOFUA) != 0 {
            dev_specific_parameter = 0x10;
        }
        if dev_lock.config.read_only {
            // Readonly.
            dev_specific_parameter |= 0x80;
        }
    } else {
        dbd = true;
    }
    drop(dev_lock);

    if cmd.op == MODE_SENSE {
        outbuf.resize(4, 0);
        // Device Specific Parameter.
        outbuf[2] = dev_specific_parameter;
    } else {
        // MODE_SENSE_10.
        outbuf.resize(8, 0);
        // Device Specific Parameter.
        outbuf[3] = dev_specific_parameter;
    }

    if !dbd && nb_sectors > 0 {
        if cmd.op == MODE_SENSE {
            // Block Descriptor Length.
            outbuf[3] = 8;
        } else {
            // Block Descriptor Length.
            outbuf[7] = 8;
        }

        // Block descriptors.
        // Byte[0]: density code.
        // Bytes[1-3]: number of blocks.
        // Byte[4]: Reserved.
        // Byte[5-7]: Block Length.
        let mut block_desc: Vec<u8> = vec![0; 8];
        BigEndian::write_u32(&mut block_desc[0..4], nb_sectors & 0xffffff);
        BigEndian::write_u32(&mut block_desc[4..8], block_size);
        outbuf.append(&mut block_desc);
    }

    if page_control == 3 {
        bail!("Invalid Mode Sense command, Page control 0x11 is not supported!");
    }

    if page_code == 0x3f {
        // 3Fh Return all pages not including subpages.
        for pg in 0..page_code {
            let _ = scsi_command_emulate_mode_sense_page(pg, page_control, &mut outbuf, scsi_type);
        }
    } else {
        scsi_command_emulate_mode_sense_page(page_code, page_control, &mut outbuf, scsi_type)?;
    }

    // The Mode Data Length field indicates the length in bytes of the following data
    // that is available to be transferred. The Mode data length does not include the
    // number of bytes in the Mode Data Length field.
    let buflen = outbuf.len();
    if cmd.op == MODE_SENSE {
        outbuf[0] = (buflen - 1) as u8;
    } else {
        outbuf[0] = (((buflen - 2) >> 8) & 0xff) as u8;
        outbuf[1] = ((buflen - 2) & 0xff) as u8;
    }

    Ok(outbuf)
}

fn scsi_command_emulate_mode_sense_page(
    page: u8,
    page_control: u8,
    outbuf: &mut Vec<u8>,
    scsi_type: u32,
) -> Result<Vec<u8>> {
    if scsi_type == SCSI_TYPE_DISK
        && ![
            MODE_PAGE_HD_GEOMETRY,
            MODE_PAGE_FLEXIBLE_DISK_GEOMETRY,
            MODE_PAGE_CACHING,
            MODE_PAGE_R_W_ERROR,
        ]
        .contains(&page)
        || scsi_type == SCSI_TYPE_ROM
            && ![
                MODE_PAGE_CACHING,
                MODE_PAGE_R_W_ERROR,
                MODE_PAGE_AUDIO_CTL,
                MODE_PAGE_CAPABILITIES,
            ]
            .contains(&page)
    {
        bail!(
            "Invalid Mode Sense command, page control ({:x}), page ({:x}), scsi device type ({})",
            page_control,
            page,
            scsi_type
        );
    }
    let buflen = outbuf.len();
    match page {
        MODE_PAGE_CACHING => {
            // Caching Mode Page.
            outbuf.resize(buflen + 20, 0);
            outbuf[buflen] = page;
            outbuf[buflen + 1] = 18;
            // 0x4: WCE(Write Cache Enable).
            outbuf[buflen + 2] = 0x4;
        }
        MODE_PAGE_R_W_ERROR => {
            // Read-Write Error Recovery mode page.
            outbuf.resize(buflen + 12, 0);
            outbuf[buflen] = page;
            outbuf[buflen + 1] = 10;

            if page_control != 1 {
                // 0x80: AWRE(Automatic Write Reallocation Enabled).
                outbuf[buflen + 2] = 0x80;
            }
        }
        MODE_PAGE_CAPABILITIES => {
            // MM Capabilities and Mechanical Status Page(Page Code 0x2A).
            // This mode page is legacy and was most recently defined in MMC-3.
            // Outbuf in CD/DVD Capabilities and Mechanical Status Page:
            // Byte[buflen + 0]: PS | Reserved | Bits[0-5]: Page Code(0x2A).
            // Byte[buflen + 1]: Page Length(28 + 4 * (maximum number of n)).
            // Byte[buflen + 2]: Bits[6-7]: Reserved | DVD-RAW Read(1) | DVD-R READ(1) |
            //                   DVD-ROM READ(1) | Method 2 | CD-RW Read(1) | CD-R Read(1).
            // Byte[buflen + 3]: Bits[6-7]: Reserved | DVD-RAW WRITE | DVD-R WRITE |
            //                   Reserved | Test Write | CD-R/RW Write | CD-R Write.
            // Byte[buflen + 4]: BUF | Multi Session(1) | Mode 2 Form 2(1) | Mode 2 Form 1(1) |
            //                   Digital Port 2(1) | Digital Port 1(1) | Composite(1) |
            //                   Audio Play(1).
            // Byte[buflen + 5]: Read Bar Code(1) | UPC(1) | ISRC(1) | C2 Pointers supported(1) |
            //                   R-W Deinterleaved & corrected(1) | R-W supported(1) |
            //                   CD-DA Stream is Accurate(1) | CD-DA Cmds supported(1).
            // Byte[buflen + 6]: Bits[5-7]: Loading Mechanism Type(1) | Reserved | Eject(1) |
            //                   Prevent Jumper(1) | Lock State | Lock(1).
            // Byte[buflen + 7]: Bits[6-7]: Reserved | R-W in Lead-in | Side Change Capable | SSS |
            //                   Changer Supports Disc Present | Separate Channel Mute |
            //                   Separate volume levels.
            // Bytes[buflen + 8 - buflen + 9]: Obsolete.
            // Bytes[buflen + 10 - buflen + 11]: Number of Volume Levels Supported.
            // Bytes[buflen + 12 - buflen + 13]: Buffer Size Supported.
            // Bytes[buflen + 14 - buflen + 15]: Obsolete.
            // Byte[buflen + 16]: Reserved.
            // Byte[buflen + 17]: Bits[6-7]: Reserved | Bits[4-5]: Length | LSBF | RCK | BCKF |
            //                    Reserved.
            // Bytes[buflen + 18 - buflen + 21]: Obsolete.
            // Bytes[buflen + 22 - buflen + 23]: Copy Management Revision Supported.
            // Bytes[buflen + 24 - buflen + 26]: Reserved.
            // Byte[buflen + 27]: Bits[2-7]: Reserved. Bits[0-1]: Rotation Control Selected.
            // Bytes[buflen + 28 - buflen + 29]: Current Write Speed Selected.
            // Bytes[buflen + 31]: Number of Logical Unit Write Speed Performance Descriptor
            //                     Tables(n).
            outbuf.resize(buflen + 32, 0);
            outbuf[buflen] = page;
            outbuf[buflen + 1] = 28;

            if page_control == 1 {
                bail!("Not supported page control");
            }

            outbuf[buflen + 2] = 0x3b;
            outbuf[buflen + 4] = 0x7f;
            outbuf[buflen + 5] = 0xff;
            // Stratovirt does not implement tray for CD, so set "Lock State" to 0.
            outbuf[buflen + 6] = 0x2d;
            BigEndian::write_u16(&mut outbuf[(buflen + 10)..(buflen + 12)], 2);
            BigEndian::write_u16(&mut outbuf[(buflen + 12)..(buflen + 14)], 2048);
        }
        _ => {
            bail!(
                "Invalid Mode Sense command, page control ({:x}), page ({:x})",
                page_control,
                page
            );
        }
    }

    Ok(outbuf.to_vec())
}

fn scsi_command_emulate_report_luns(
    cmd: &ScsiCommand,
    dev: &Arc<Mutex<ScsiDevice>>,
) -> Result<Vec<u8>> {
    let dev_lock = dev.lock().unwrap();
    // Byte 0-3: Lun List Length. Byte 4-7: Reserved.
    let mut outbuf: Vec<u8> = vec![0; 8];
    let target = dev_lock.config.target;

    if cmd.xfer < 16 {
        bail!("scsi REPORT LUNS xfer {} too short!", cmd.xfer);
    }

    // Byte2: SELECT REPORT:00h/01h/02h. 03h to FFh is reserved.
    if cmd.buf[2] > 2 {
        bail!(
            "Invalid REPORT LUNS cmd, SELECT REPORT Byte is {}",
            cmd.buf[2]
        );
    }

    let scsi_bus = dev_lock.parent_bus.upgrade().unwrap();
    let scsi_bus_clone = scsi_bus.lock().unwrap();

    drop(dev_lock);

    for (_pos, device) in scsi_bus_clone.devices.iter() {
        let device_lock = device.lock().unwrap();
        if device_lock.config.target != target {
            drop(device_lock);
            continue;
        }
        let len = outbuf.len();
        if device_lock.config.lun < 256 {
            outbuf.push(0);
            outbuf.push(device_lock.config.lun as u8);
        } else {
            outbuf.push(0x40 | ((device_lock.config.lun >> 8) & 0xff) as u8);
            outbuf.push((device_lock.config.lun & 0xff) as u8);
        }
        outbuf.resize(len + 8, 0);
        drop(device_lock);
    }

    let len: u32 = outbuf.len() as u32 - 8;
    BigEndian::write_u32(&mut outbuf[0..4], len);
    Ok(outbuf)
}

fn scsi_command_emulate_service_action_in_16(
    cmd: &ScsiCommand,
    dev: &Arc<Mutex<ScsiDevice>>,
) -> Result<Vec<u8>> {
    // Read Capacity(16) Command.
    // Byte 0: Operation Code(0x9e)
    // Byte 1: bit0 - bit4: Service Action(0x10), bit 5 - bit 7: Reserved.
    if cmd.buf[1] & 0x1f == SUBCODE_READ_CAPACITY_16 {
        let dev_lock = dev.lock().unwrap();
        let block_size = dev_lock.block_size;
        let mut outbuf: Vec<u8> = vec![0; 32];
        let mut nb_sectors = dev_lock.disk_sectors;
        nb_sectors /= (block_size / DEFAULT_SECTOR_SIZE) as u64;
        nb_sectors -= 1;

        drop(dev_lock);

        // Byte[0-7]: Returned Logical BLock Address(the logical block address of the last logical
        //            block).
        // Byte[8-11]: Logical Block Length in Bytes.
        BigEndian::write_u64(&mut outbuf[0..8], nb_sectors);
        BigEndian::write_u32(&mut outbuf[8..12], block_size);

        return Ok(outbuf);
    }

    bail!(
        "Invalid combination Scsi Command, operation code ({:x}), service action ({:x})",
        SERVICE_ACTION_IN_16,
        cmd.buf[1] & 31
    );
}

fn scsi_command_emulate_read_disc_information(
    cmd: &ScsiCommand,
    dev: &Arc<Mutex<ScsiDevice>>,
) -> Result<Vec<u8>> {
    // Byte1: Bits[0-2]: Data type.
    // Data Type | Returned Data.               |
    //    000b   | Standard Disc Information.   |
    //    001b   | Track Resources Information. |
    //    010b   | POW Resources Information.   |
    // 011b-111b | Reserved                     |
    let data_type = cmd.buf[1] & 7;

    // Types 001b/010b are only defined for Blu-Ray.
    if data_type != 0 {
        bail!("Unsupported read disc information data type {}!", data_type);
    }
    if dev.lock().unwrap().scsi_type != SCSI_TYPE_ROM {
        bail!("Read disc information command is only for scsi multi-media device!");
    }

    // Outbuf:
    // Bytes[0-1]: Disc Information Length(32).
    // Byte2: Disc Information Data Type(000b) | Erasable(0) | State of last Session(01b) |
    //        Disc Status(11b).
    // Byte3: Number of First Track on Disc.
    // Byte4: Number of Sessions.
    // Byte5: First Track Number in Last Session(Least Significant Byte).
    // Byte6: Last Track Number in Last Session(Last Significant Byte).
    // Byte7: DID_V | DBC_V | URU:Unrestricted Use Disc(1) | DAC_V | Reserved | Legacy |
    //        BG Format Status.
    // Byte8: Disc Type(00h: CD-DA or CD-ROM Disc).
    // Byte9: Number of sessions(Most Significant Byte).
    // Byte10: First Trace Number in Last Session(Most Significant Byte).
    // Byte11: Last Trace Number in Last Session(Most Significant Byte).
    // Bytes12-15: Disc Identification.
    // Bytes16-19: Last Session Lead-in Start Address.
    // Bytes20-23: Last Possible Lead-Out Start Address.
    // Bytes24-31: Disc Bar Code.
    // Byte32: Disc Application Code.
    // Byte33: Number of OPC Tables.(0)
    let mut outbuf: Vec<u8> = vec![0; 34];
    outbuf[1] = 32;
    outbuf[2] = 0xe;
    outbuf[3] = 1;
    outbuf[4] = 1;
    outbuf[5] = 1;
    outbuf[6] = 1;
    outbuf[7] = 0x20;

    Ok(outbuf)
}

/// Format field for READ TOC command.
/// The Track/Session Number field specifies starting track number for which the data is returned.
/// For multi-session discs, TOC data is returned for all sessions. Track number Aah is reported
/// only for the Lead-out area of the last complete session.
const RT_FORMATTED_TOC: u8 = 0x0000;
/// This format returns the first complete session number, last complete session number and last
/// complete session starting address.
const RT_MULTI_SESSION_INFORMATION: u8 = 0x0001;
/// This format returns all Q sub-code data in the Lead-IN(TOC) areas starting from a session number
/// as specified in the Track/Session Number field.
const RT_RAW_TOC: u8 = 0x0010;

fn scsi_command_emulate_read_toc(
    cmd: &ScsiCommand,
    dev: &Arc<Mutex<ScsiDevice>>,
) -> Result<Vec<u8>> {
    // Byte1: Bit1: MSF.(MSF: Minute, Second, Frame)
    // MSF = 1: the address fields in some returned data formats shall be in MSF form.
    // MSF = 0: the address fields in some returned data formats shall be in LBA form.
    let msf = cmd.buf[1] & 2;
    // Byte2: Bits[0-3]: Format(Select specific returned data format)(CD: 0,1,2).
    let format = cmd.buf[2] & 0xf;
    // Byte6: Track/Session Number.
    let track_number = cmd.buf[6];
    let mut outbuf: Vec<u8> = vec![0; 0];

    match format {
        RT_FORMATTED_TOC => {
            let nb_sectors = dev.lock().unwrap().disk_sectors as u32;
            let mut buf = cdrom_read_formatted_toc(nb_sectors, msf, track_number)?;
            outbuf.append(&mut buf);
        }
        RT_MULTI_SESSION_INFORMATION => {
            outbuf.resize(12, 0);
            outbuf[1] = 0x0a;
            outbuf[2] = 0x01;
            outbuf[3] = 0x01;
        }
        RT_RAW_TOC => {}
        _ => {
            bail!("Invalid read toc format {}", format);
        }
    }

    Ok(outbuf)
}

fn scsi_command_emulate_get_configuration(
    _cmd: &ScsiCommand,
    dev: &Arc<Mutex<ScsiDevice>>,
) -> Result<Vec<u8>> {
    let dev_lock = dev.lock().unwrap();
    if dev_lock.scsi_type != SCSI_TYPE_ROM {
        bail!("Invalid scsi type {}", dev_lock.scsi_type);
    }

    // 8 bytes(Feature Header) + 12 bytes(Profile List Feature) +
    // 12bytes(Core Feature) + 8bytes(Removable media feature) = 40 bytes.
    let mut outbuf = vec![0; 40];

    // Outbuf:
    // Bytes[0-7]: Feature Header.
    // Bytes[0-3]: Data Length(36 = 40 - 4).
    // Bytes[4-5]: Reserved.
    // Bytes[6-7]: Current Profile.
    BigEndian::write_u32(&mut outbuf[0..4], 36);
    let current = if dev_lock.disk_sectors > CD_MAX_SECTORS as u64 {
        GC_PROFILE_DVD_ROM
    } else {
        GC_PROFILE_CD_ROM
    };
    BigEndian::write_u16(&mut outbuf[6..8], current);

    // Bytes[8-n]: Feature Descriptor(s):
    // Bytes[8-19]: Feature 0: Profile List Feature:
    // Bytes[8-9]: Feature code(0000h).
    // Byte[10]: Bits[6-7]: Reserved. Bits[2-5]: Version. Bit 1: Persistent. Bit 0: Current(1).
    // Byte[11]: Additional Length.
    // Byte[12-19]: Profile Descriptors.(2 descriptors: CD and DVD)
    // Byte[12-13]： Profile Number(CD).
    // Byte[14]: Bits[1-7]: Reserved. Bit 0: CurrentP.
    // Byte[15]: Reserved.
    // Byte[16-17]: Profile Number(DVD).
    // Byte[18]: Bits[1-7]: Reserved. Bit 0: CurrentP.
    // Byte[19]: Reserved.
    BigEndian::write_u16(&mut outbuf[8..10], GC_FC_PROFILE_LIST);
    outbuf[10] = 0x03;
    outbuf[11] = 8;
    BigEndian::write_u16(&mut outbuf[12..14], GC_PROFILE_CD_ROM);
    outbuf[14] |= (current == GC_PROFILE_CD_ROM) as u8;
    BigEndian::write_u16(&mut outbuf[16..18], GC_PROFILE_DVD_ROM);
    outbuf[18] |= (current == GC_PROFILE_DVD_ROM) as u8;

    // Bytes[8-n]: Feature Descriptor(s):
    // Bytes[20-31]: Feature 1: Core Feature:
    // Bytes[20-21]: Feature Code(0001h).
    // Byte[22]: Bits[6-7]: Reserved. Bits[2-5]: Version(0010b). Bit 1: Persistent(1).
    //           Bit 0: Current(1).
    // Byte[23]: Additional Length(8).
    // Bytes[24-27]: Physical Interface Standard. (Scsi Family: 00000001h)
    // Byte[28]: Bits[2-7]: Reserved. Bit 1: INQ2. Bit 0: DBE(1).
    // Bytes[29-31]: Reserved.
    BigEndian::write_u16(&mut outbuf[20..22], GC_FC_CORE);
    outbuf[22] = 0x0b;
    outbuf[23] = 8;
    BigEndian::write_u32(&mut outbuf[24..28], 1);
    outbuf[28] = 1;

    // Bytes[8-n]: Feature Descriptor(s):
    // Bytes[32-40]: Feature 2: Removable media feature:
    // Bytes[32-33]: Feature Code(0003h).
    // Byte[34]: Bits[6-7]: Reserved. Bit[2-5]: Version(0010b). Bit 1: Persistent(1).
    //           Bit 0: Current(1).
    // Byte[35]: Additional Length(4).
    // Byte[36]: Bits[5-7]: Loading Mechanism Type(001b). Bit4: Load(1). Bit 3: Eject(1).
    //           Bit 2: Pvnt Jmpr. Bit 1: DBML. Bit 0: Lock(1).
    // Byte[37-39]: Reserved.
    BigEndian::write_u16(&mut outbuf[32..34], GC_FC_REMOVABLE_MEDIUM);
    outbuf[34] = 0x0b;
    outbuf[35] = 4;
    outbuf[36] = 0x39;

    Ok(outbuf)
}

fn scsi_command_emulate_get_event_status_notification(
    cmd: &ScsiCommand,
    dev: &Arc<Mutex<ScsiDevice>>,
) -> Result<Vec<u8>> {
    // Byte4: Notification Class Request.
    let notification_class_request = cmd.buf[4];
    let dev_lock = dev.lock().unwrap();

    if dev_lock.scsi_type != SCSI_TYPE_ROM {
        bail!("Invalid scsi type {}", dev_lock.scsi_type);
    }

    // Byte1: Bit0: Polled.
    // Polled = 1: the Host is requesting polled operation.
    // Polled = 0: the Host is requesting asynchronous operation.
    if cmd.buf[1] & 1 == 0 {
        bail!("Asynchronous. Do not support.");
    }

    // Outbuf:
    // Bytes[0-3]: Event Header.
    // Bytes[4-n]: Event Descriptor.
    // Bytes[0-1]: Event Descriptor Length.
    // Byte2: Bit7: NEC(No Event Available). Bits[0-2]: Notification Class.
    // NEC = 1: The Drive supports none of the requested notification classes.
    // NEC = 0: At least one of the requested notification classes is supported.
    // Byte3: Supported Event Class.
    let mut outbuf: Vec<u8> = vec![0; 4];

    outbuf[3] = 1 << GESN_MEDIA;
    if notification_class_request & (1 << GESN_MEDIA) != 0 {
        // NCE = 0, notification class = media.
        outbuf[2] = GESN_MEDIA;
        outbuf.resize(8, 0);
        // Bytes[4-7]: Media Event Descriptor.
        // Byte4: Bits[4-7]: reserved. Bits[0-3]: Event Code.
        // Byte5: Media Status. Bits[2-7] reserved. Bit 1: Media Present. Bit 0: Door or Tray open.
        // Byte6: Start Slot.
        // Byte7: End Slot.

        // Do not support hot-plug/hot-unplug scsi cd which will be present all the time once vm
        // starts. To do: this outbuf event code and media status should be changed after
        // allowing hot-plug.
        outbuf[4] = GESN_EC_NOCHG;
        outbuf[5] = 1 << GESN_MS_MEDIA_PRESENT_BIT;
    } else {
        // NCE = 1.
        outbuf[2] = 0x80;
    }

    let len = outbuf.len() as u16 - 2;
    BigEndian::write_u16(&mut outbuf[0..2], len);

    Ok(outbuf)
}

/// LBA to MSF translation is defined in MMC6 Table 647.
/// MSF values are converted to LBA values via such formula:
/// lba = ((m * CD_SECS) + s) * CD_FRAMES + f) - CD_MSF_OFFSET.
fn lba_to_msf(lba: u32) -> Vec<u8> {
    // Note: lba is logical block address and it is in sectors.
    // Max lba is u32::MAX * 512byte / 1024 / 1024 / 1024 = 2047GB.
    // But, dvd size is less than 4.7G usually and cd size is less than 700M usually.
    // So it will not overflow here.
    let minute = ((lba + CD_MSF_OFFSET) / CD_FRAMES / CD_SECS) as u8;
    let second = ((lba + CD_MSF_OFFSET) / CD_FRAMES % CD_SECS) as u8;
    let frame = ((lba + CD_MSF_OFFSET) % CD_FRAMES) as u8;

    vec![minute, second, frame]
}

fn cdrom_read_formatted_toc(nb_sectors: u32, msf: u8, track_number: u8) -> Result<Vec<u8>> {
    // Track number 0xaa is reported only for the Lead-out area of the last complete session.
    if track_number > 1 && track_number != 0xaa {
        bail!("Invalid track number!");
    }

    let mut outbuf: Vec<u8> = vec![0; 4];

    // Outbuf:
    // Bytes[0-1]: TOC Data Length.
    // Byte[2]: First Track Number(1).
    // Byte[3]: Last Track Number(1).
    outbuf[2] = 1;
    outbuf[3] = 1;
    if track_number <= 1 {
        // Byte[4]: Reserved.
        // Byte[5]: Bits[5-7]: ADR, Bits[0-4]: CONTROL.
        // Byte[6]: Track Number.
        // Byte[7]: Reserved.
        // Bytes[8-11]: Track Start Address(LBA form = 000000h, MSF form = 00:00:02:00).
        outbuf.append(&mut [0, 0x14, 1, 0].to_vec());
        if msf != 0 {
            // MSF form.
            outbuf.push(0);
            outbuf.append(&mut lba_to_msf(0));
        } else {
            outbuf.append(&mut [0, 0, 0, 0].to_vec());
        }
    }

    // Lead Out Track.
    // Byte[temporary buflen]: Reserved.
    // Byte[temporary buflen + 1]: Bits[5-7]: ADR, Bits[0-4]: CONTROL.
    // Byte[temporary buflen + 2]: Track Number.
    // Byte[temporary buflen + 3]: Reserved.
    // Bytes[temporary buflen + 4 - temporary buflen + 7]: Track Start Address.
    outbuf.append(&mut [0, 0x14, 0xaa, 0].to_vec());
    if msf != 0 {
        outbuf.push(0);
        outbuf.append(&mut lba_to_msf(nb_sectors));
    } else {
        let pos = outbuf.len();
        outbuf.resize(pos + 4, 0);
        BigEndian::write_u32(&mut outbuf[pos..pos + 4], nb_sectors);
    }

    let len = outbuf.len() as u16;
    BigEndian::write_u16(&mut outbuf[0..2], len - 2);

    Ok(outbuf)
}
