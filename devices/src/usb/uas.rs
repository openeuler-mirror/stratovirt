// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::array;
use std::cmp::min;
use std::collections::HashMap;
use std::mem::size_of;
use std::sync::{Arc, Mutex, Weak};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};
use once_cell::sync::Lazy;
use strum::EnumCount;
use strum_macros::EnumCount;

use super::config::*;
use super::descriptor::{
    UsbConfigDescriptor, UsbDescConfig, UsbDescDevice, UsbDescEndpoint, UsbDescIface,
    UsbDescriptorOps, UsbDeviceDescriptor, UsbEndpointDescriptor, UsbInterfaceDescriptor,
    UsbSuperSpeedEndpointCompDescriptor,
};
use super::xhci::xhci_controller::XhciDevice;
use super::{
    UsbDevice, UsbDeviceBase, UsbDeviceRequest, UsbPacket, UsbPacketStatus,
    USB_DEVICE_BUFFER_DEFAULT_LEN,
};
use crate::ScsiBus::{
    get_scsi_key, scsi_cdb_xfer, ScsiBus, ScsiRequest, ScsiRequestOps, ScsiSense, ScsiXferMode,
    CHECK_CONDITION, EMULATE_SCSI_OPS, GOOD, SCSI_SENSE_INVALID_PARAM_VALUE,
    SCSI_SENSE_INVALID_TAG, SCSI_SENSE_NO_SENSE,
};
use crate::ScsiDisk::{ScsiDevConfig, ScsiDevice};
use crate::{Bus, Device};
use machine_manager::config::{DriveConfig, DriveFile};
use util::byte_code::ByteCode;
use util::gen_base_func;

// Size of UasIUBody
const UAS_IU_BODY_SIZE: usize = 30;

// Size of cdb in UAS Command IU
const UAS_COMMAND_CDB_SIZE: usize = 16;

// UAS Pipe IDs
const UAS_PIPE_ID_COMMAND: u8 = 0x01;
const UAS_PIPE_ID_STATUS: u8 = 0x02;
const UAS_PIPE_ID_DATA_IN: u8 = 0x03;
const UAS_PIPE_ID_DATA_OUT: u8 = 0x04;

// UAS Streams Attributes
const UAS_MAX_STREAMS_BM_ATTR: u8 = 4;
const UAS_MAX_STREAMS: usize = 1 << UAS_MAX_STREAMS_BM_ATTR;

// UAS IU IDs
const UAS_IU_ID_COMMAND: u8 = 0x01;
const UAS_IU_ID_SENSE: u8 = 0x03;
const UAS_IU_ID_RESPONSE: u8 = 0x04;
const UAS_IU_ID_TASK_MGMT: u8 = 0x05;

// UAS Response Codes
const UAS_RC_TMF_COMPLETE: u8 = 0x00;
const _UAS_RC_INVALID_IU: u8 = 0x02;
const UAS_RC_TMF_NOT_SUPPORTED: u8 = 0x04;
const _UAS_RC_TMF_FAILED: u8 = 0x05;
const _UAS_RC_TMF_SUCCEEDED: u8 = 0x08;
const _UAS_RC_INCORRECT_LUN: u8 = 0x09;
const _UAS_RC_OVERLAPPED_TAG: u8 = 0x0A;

// UAS Task Management Functions
const UAS_TMF_ABORT_TASK: u8 = 0x01;
const _UAS_TMF_ABORT_TASK_SET: u8 = 0x02;
const _UAS_TMF_CLEAR_TASK_SET: u8 = 0x04;
const _UAS_TMF_LOGICAL_UNIT_RESET: u8 = 0x08;
const _UAS_TMF_I_T_NEXUS_RESET: u8 = 0x10;
const _UAS_TMF_CLEAR_ACA: u8 = 0x40;
const _UAS_TMF_QUERY_TASK: u8 = 0x80;
const _UAS_TMF_QUERY_TASK_SET: u8 = 0x81;
const _UAS_TMF_QUERY_ASYNC_EVENT: u8 = 0x82;

#[derive(Parser, Clone, Debug)]
#[command(no_binary_name(true))]
pub struct UsbUasConfig {
    #[arg(long, value_parser = ["usb-uas"])]
    pub classtype: String,
    #[arg(long)]
    pub drive: String,
    #[arg(long)]
    pub id: Option<String>,
    #[arg(long)]
    pub speed: Option<String>,
    #[arg(long)]
    bus: Option<String>,
    #[arg(long)]
    port: Option<String>,
}

pub struct UsbUas {
    base: UsbDeviceBase,
    uas_config: UsbUasConfig,
    scsi_bus: Arc<Mutex<ScsiBus>>,
    scsi_device: Option<Arc<Mutex<ScsiDevice>>>,
    drive_cfg: DriveConfig,
    drive_files: Arc<Mutex<HashMap<String, DriveFile>>>,
    commands: [Option<UasIU>; UAS_MAX_STREAMS + 1],
    statuses: [Option<Arc<Mutex<UsbPacket>>>; UAS_MAX_STREAMS + 1],
    data: [Option<Arc<Mutex<UsbPacket>>>; UAS_MAX_STREAMS + 1],
}

#[derive(Debug, Default, EnumCount)]
enum UsbUasStringId {
    #[default]
    Invalid = 0,
    Manufacturer = 1,
    Product = 2,
    SerialNumber = 3,
    Configuration = 4,
}

const UAS_DESC_STRINGS: [&str; UsbUasStringId::COUNT] = [
    "",
    "StratoVirt",
    "StratoVirt USB Uas",
    "5",
    "Super speed config (usb 3.0)",
];

struct UasRequest {
    data: Option<Arc<Mutex<UsbPacket>>>,
    status: Arc<Mutex<UsbPacket>>,
    iu: UasIU,
    completed: bool,
}

impl ScsiRequestOps for UasRequest {
    fn scsi_request_complete_cb(
        &mut self,
        scsi_status: u8,
        scsi_sense: Option<ScsiSense>,
    ) -> Result<()> {
        let tag = u16::from_be(self.iu.header.tag);
        let sense = scsi_sense.unwrap_or(SCSI_SENSE_NO_SENSE);
        UsbUas::fill_sense(&mut self.status.lock().unwrap(), tag, sense, scsi_status);
        self.complete();
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum UasPacketStatus {
    Completed = 0,
    Pending = 1,
}

impl From<bool> for UasPacketStatus {
    fn from(status: bool) -> Self {
        match status {
            true => Self::Completed,
            false => Self::Pending,
        }
    }
}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct UsbPipeUsageDescriptor {
    bLength: u8,
    bDescriptorType: u8,
    bPipeId: u8,
    bReserved: u8,
}

impl ByteCode for UsbPipeUsageDescriptor {}

#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
struct UasIUHeader {
    id: u8,
    reserved: u8,
    tag: u16,
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
struct UasIUCommand {
    prio_task_attr: u8, // 6:3 priority, 2:0 task attribute
    reserved_1: u8,
    add_cdb_len: u8,
    reserved_2: u8,
    lun: u64,
    cdb: [u8; UAS_COMMAND_CDB_SIZE],
    add_cdb: [u8; 1], // not supported by stratovirt
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
struct UasIUSense {
    status_qualifier: u16,
    status: u8,
    reserved: [u8; 7],
    sense_length: u16,
    sense_data: [u8; 18],
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
struct UasIUResponse {
    add_response_info: [u8; 3],
    response_code: u8,
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
struct UasIUTaskManagement {
    function: u8,
    reserved: u8,
    task_tag: u16,
    lun: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
union UasIUBody {
    command: UasIUCommand,
    sense: UasIUSense,
    response: UasIUResponse,
    task_management: UasIUTaskManagement,
    raw_data: [u8; UAS_IU_BODY_SIZE],
}

impl Default for UasIUBody {
    fn default() -> Self {
        Self {
            raw_data: [0; UAS_IU_BODY_SIZE],
        }
    }
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
struct UasIU {
    header: UasIUHeader,
    body: UasIUBody,
}

impl ByteCode for UasIU {}

static DESC_DEVICE_UAS: Lazy<Arc<UsbDescDevice>> = Lazy::new(|| {
    Arc::new(UsbDescDevice {
        device_desc: UsbDeviceDescriptor {
            bLength: USB_DT_DEVICE_SIZE,
            bDescriptorType: USB_DT_DEVICE,
            bcdUSB: 0x0300,
            bDeviceClass: 0,
            bDeviceSubClass: 0,
            bDeviceProtocol: 0,
            bMaxPacketSize0: 9,
            idVendor: USB_VENDOR_ID_STRATOVIRT,
            idProduct: USB_PRODUCT_ID_UAS,
            bcdDevice: 0,
            iManufacturer: UsbUasStringId::Manufacturer as u8,
            iProduct: UsbUasStringId::Product as u8,
            iSerialNumber: UsbUasStringId::SerialNumber as u8,
            bNumConfigurations: 1,
        },
        configs: vec![Arc::new(UsbDescConfig {
            config_desc: UsbConfigDescriptor {
                bLength: USB_DT_CONFIG_SIZE,
                bDescriptorType: USB_DT_CONFIGURATION,
                wTotalLength: 0,
                bNumInterfaces: 1,
                bConfigurationValue: 1,
                iConfiguration: UsbUasStringId::Configuration as u8,
                bmAttributes: USB_CONFIGURATION_ATTR_ONE | USB_CONFIGURATION_ATTR_SELF_POWER,
                bMaxPower: 50,
            },
            iad_desc: vec![],
            interfaces: vec![DESC_IFACE_BOT.clone(), DESC_IFACE_UAS.clone()],
        })],
    })
});

static DESC_IFACE_UAS: Lazy<Arc<UsbDescIface>> = Lazy::new(|| {
    Arc::new(UsbDescIface {
        interface_desc: UsbInterfaceDescriptor {
            bLength: USB_DT_INTERFACE_SIZE,
            bDescriptorType: USB_DT_INTERFACE,
            bInterfaceNumber: 0,
            bAlternateSetting: 1,
            bNumEndpoints: 4,
            bInterfaceClass: USB_CLASS_MASS_STORAGE,
            bInterfaceSubClass: USB_SUBCLASS_SCSI,
            bInterfaceProtocol: USB_IFACE_PROTOCOL_UAS,
            iInterface: 0,
        },
        other_desc: vec![],
        endpoints: vec![
            Arc::new(UsbDescEndpoint {
                endpoint_desc: UsbEndpointDescriptor {
                    bLength: USB_DT_ENDPOINT_SIZE,
                    bDescriptorType: USB_DT_ENDPOINT,
                    bEndpointAddress: USB_DIRECTION_HOST_TO_DEVICE | UAS_PIPE_ID_COMMAND,
                    bmAttributes: USB_ENDPOINT_ATTR_BULK,
                    wMaxPacketSize: 1024,
                    bInterval: 0,
                },
                extra: [
                    UsbSuperSpeedEndpointCompDescriptor {
                        bLength: USB_DT_SS_EP_COMP_SIZE,
                        bDescriptorType: USB_DT_ENDPOINT_COMPANION,
                        bMaxBurst: 15,
                        bmAttributes: 0,
                        wBytesPerInterval: 0,
                    }
                    .as_bytes(),
                    UsbPipeUsageDescriptor {
                        bLength: USB_DT_PIPE_USAGE_SIZE,
                        bDescriptorType: USB_DT_PIPE_USAGE,
                        bPipeId: UAS_PIPE_ID_COMMAND,
                        bReserved: 0,
                    }
                    .as_bytes(),
                ]
                .concat()
                .to_vec(),
            }),
            Arc::new(UsbDescEndpoint {
                endpoint_desc: UsbEndpointDescriptor {
                    bLength: USB_DT_ENDPOINT_SIZE,
                    bDescriptorType: USB_DT_ENDPOINT,
                    bEndpointAddress: USB_DIRECTION_DEVICE_TO_HOST | UAS_PIPE_ID_STATUS,
                    bmAttributes: USB_ENDPOINT_ATTR_BULK,
                    wMaxPacketSize: 1024,
                    bInterval: 0,
                },
                extra: [
                    UsbSuperSpeedEndpointCompDescriptor {
                        bLength: USB_DT_SS_EP_COMP_SIZE,
                        bDescriptorType: USB_DT_ENDPOINT_COMPANION,
                        bMaxBurst: 15,
                        bmAttributes: UAS_MAX_STREAMS_BM_ATTR,
                        wBytesPerInterval: 0,
                    }
                    .as_bytes(),
                    UsbPipeUsageDescriptor {
                        bLength: USB_DT_PIPE_USAGE_SIZE,
                        bDescriptorType: USB_DT_PIPE_USAGE,
                        bPipeId: UAS_PIPE_ID_STATUS,
                        bReserved: 0,
                    }
                    .as_bytes(),
                ]
                .concat()
                .to_vec(),
            }),
            Arc::new(UsbDescEndpoint {
                endpoint_desc: UsbEndpointDescriptor {
                    bLength: USB_DT_ENDPOINT_SIZE,
                    bDescriptorType: USB_DT_ENDPOINT,
                    bEndpointAddress: USB_DIRECTION_DEVICE_TO_HOST | UAS_PIPE_ID_DATA_IN,
                    bmAttributes: USB_ENDPOINT_ATTR_BULK,
                    wMaxPacketSize: 1024,
                    bInterval: 0,
                },
                extra: [
                    UsbSuperSpeedEndpointCompDescriptor {
                        bLength: USB_DT_SS_EP_COMP_SIZE,
                        bDescriptorType: USB_DT_ENDPOINT_COMPANION,
                        bMaxBurst: 15,
                        bmAttributes: UAS_MAX_STREAMS_BM_ATTR,
                        wBytesPerInterval: 0,
                    }
                    .as_bytes(),
                    UsbPipeUsageDescriptor {
                        bLength: USB_DT_PIPE_USAGE_SIZE,
                        bDescriptorType: USB_DT_PIPE_USAGE,
                        bPipeId: UAS_PIPE_ID_DATA_IN,
                        bReserved: 0,
                    }
                    .as_bytes(),
                ]
                .concat()
                .to_vec(),
            }),
            Arc::new(UsbDescEndpoint {
                endpoint_desc: UsbEndpointDescriptor {
                    bLength: USB_DT_ENDPOINT_SIZE,
                    bDescriptorType: USB_DT_ENDPOINT,
                    bEndpointAddress: USB_DIRECTION_HOST_TO_DEVICE | UAS_PIPE_ID_DATA_OUT,
                    bmAttributes: USB_ENDPOINT_ATTR_BULK,
                    wMaxPacketSize: 1024,
                    bInterval: 0,
                },
                extra: [
                    UsbSuperSpeedEndpointCompDescriptor {
                        bLength: USB_DT_SS_EP_COMP_SIZE,
                        bDescriptorType: USB_DT_ENDPOINT_COMPANION,
                        bMaxBurst: 15,
                        bmAttributes: UAS_MAX_STREAMS_BM_ATTR,
                        wBytesPerInterval: 0,
                    }
                    .as_bytes(),
                    UsbPipeUsageDescriptor {
                        bLength: USB_DT_PIPE_USAGE_SIZE,
                        bDescriptorType: USB_DT_PIPE_USAGE,
                        bPipeId: UAS_PIPE_ID_DATA_OUT,
                        bReserved: 0,
                    }
                    .as_bytes(),
                ]
                .concat()
                .to_vec(),
            }),
        ],
    })
});

// NOTE: Fake BOT interface descriptor is needed here since Windows UASP driver always expects two
// interfaces: both BOT and UASP. It also anticipates the UASP descriptor to be the second one.
// Therefore, the first one can be a BOT storage stub.
static DESC_IFACE_BOT: Lazy<Arc<UsbDescIface>> = Lazy::new(|| {
    Arc::new(UsbDescIface {
        interface_desc: UsbInterfaceDescriptor {
            bLength: USB_DT_INTERFACE_SIZE,
            bDescriptorType: USB_DT_INTERFACE,
            bInterfaceNumber: 0,
            bAlternateSetting: 0,
            bNumEndpoints: 0,
            bInterfaceClass: USB_CLASS_MASS_STORAGE,
            bInterfaceSubClass: USB_SUBCLASS_SCSI,
            bInterfaceProtocol: USB_IFACE_PROTOCOL_BOT,
            iInterface: 0,
        },
        other_desc: vec![],
        endpoints: vec![],
    })
});

fn complete_async_packet(packet: &Arc<Mutex<UsbPacket>>) {
    let locked_packet = packet.lock().unwrap();

    if let Some(xfer_ops) = locked_packet.xfer_ops.as_ref() {
        if let Some(xfer_ops) = xfer_ops.clone().upgrade() {
            drop(locked_packet);
            xfer_ops.lock().unwrap().submit_transfer();
        }
    }
}

impl UsbUas {
    pub fn new(
        uas_config: UsbUasConfig,
        drive_cfg: DriveConfig,
        drive_files: Arc<Mutex<HashMap<String, DriveFile>>>,
    ) -> Self {
        Self {
            base: UsbDeviceBase::new(
                uas_config.id.as_ref().unwrap().clone(),
                USB_DEVICE_BUFFER_DEFAULT_LEN,
            ),
            uas_config,
            scsi_bus: Arc::new(Mutex::new(ScsiBus::new("".to_string()))),
            scsi_device: None,
            drive_cfg,
            drive_files,
            commands: array::from_fn(|_| None),
            statuses: array::from_fn(|_| None),
            data: array::from_fn(|_| None),
        }
    }

    fn cancel_io(&mut self) {
        self.commands = array::from_fn(|_| None);
        self.statuses = array::from_fn(|_| None);
        self.data = array::from_fn(|_| None);
    }

    fn handle_iu_command(
        &mut self,
        iu: &UasIU,
        mut uas_request: UasRequest,
    ) -> Result<UasPacketStatus> {
        // SAFETY: IU is guaranteed to be of type command.
        let add_cdb_len = unsafe { iu.body.command.add_cdb_len };
        let tag = u16::from_be(iu.header.tag);

        if add_cdb_len > 0 {
            Self::fill_fake_sense(
                &mut uas_request.status.lock().unwrap(),
                tag,
                SCSI_SENSE_INVALID_PARAM_VALUE,
            );
            uas_request.complete();
            bail!("additional cdb length is not supported");
        }

        if tag > UAS_MAX_STREAMS as u16 {
            Self::fill_fake_sense(
                &mut uas_request.status.lock().unwrap(),
                tag,
                SCSI_SENSE_INVALID_TAG,
            );
            uas_request.complete();
            bail!("invalid tag {}", tag);
        }

        let (scsi_iovec, scsi_iovec_size) = match &uas_request.data {
            Some(data) => {
                let mut locked_data = data.lock().unwrap();
                let iov_size = locked_data.get_iovecs_size() as u32;
                locked_data.actual_length = iov_size;
                (locked_data.iovecs.clone(), iov_size)
            }
            None => (Vec::new(), 0),
        };

        // SAFETY: IU is guaranteed to of type command.
        let cdb = unsafe { iu.body.command.cdb };
        // SAFETY: IU is guaranteed to of type command.
        let lun = unsafe { iu.body.command.lun } as u16;
        trace::usb_uas_handle_iu_command(self.device_id(), cdb[0]);
        let uas_request = Box::new(uas_request);
        let scsi_request = ScsiRequest::new(
            cdb,
            lun,
            scsi_iovec,
            scsi_iovec_size,
            self.scsi_device.as_ref().unwrap().clone(),
            uas_request,
        )
        .with_context(|| "failed to create SCSI request")?;

        if scsi_request.cmd.xfer > u64::from(scsi_request.datalen)
            && scsi_request.cmd.mode != ScsiXferMode::ScsiXferNone
        {
            bail!(
                "insufficient buffer provided (requested length {}, provided length {})",
                scsi_request.cmd.xfer,
                scsi_request.datalen
            );
        }

        let scsi_request = match scsi_request.opstype {
            EMULATE_SCSI_OPS => scsi_request.emulate_execute(),
            _ => scsi_request.execute(),
        }
        .with_context(|| "failed to execute SCSI request")?;

        let upper_request = &mut scsi_request.lock().unwrap().upper_req;
        let uas_request = upper_request
            .as_mut()
            .as_any_mut()
            .downcast_mut::<UasRequest>()
            .unwrap();

        Ok(uas_request.completed.into())
    }

    fn handle_iu_task_management(
        &mut self,
        iu: &UasIU,
        mut uas_request: UasRequest,
    ) -> Result<UasPacketStatus> {
        let tag = u16::from_be(iu.header.tag);

        if tag > UAS_MAX_STREAMS as u16 {
            Self::fill_fake_sense(
                &mut uas_request.status.lock().unwrap(),
                tag,
                SCSI_SENSE_INVALID_TAG,
            );
            uas_request.complete();
            bail!("invalid tag {}", tag);
        }

        // SAFETY: IU is guaranteed to be of type task management.
        let tmf = unsafe { iu.body.task_management.function };
        trace::usb_uas_handle_iu_task_management(self.device_id(), tmf, tag);

        match tmf {
            UAS_TMF_ABORT_TASK => {
                // SAFETY: IU is guaranteed to be of type task management.
                let task_tag = unsafe { iu.body.task_management.task_tag } as usize;
                self.commands[task_tag] = None;
                self.statuses[task_tag] = None;
                self.data[task_tag] = None;
                trace::usb_uas_tmf_abort_task(self.device_id(), task_tag);
                Self::fill_response(
                    &mut uas_request.status.lock().unwrap(),
                    tag,
                    UAS_RC_TMF_COMPLETE,
                );
            }
            _ => {
                warn!("UAS {} device unsupported TMF {}.", self.device_id(), tmf);
                Self::fill_response(
                    &mut uas_request.status.lock().unwrap(),
                    tag,
                    UAS_RC_TMF_NOT_SUPPORTED,
                );
            }
        };

        uas_request.complete();
        Ok(UasPacketStatus::Completed)
    }

    fn fill_response(packet: &mut UsbPacket, tag: u16, code: u8) {
        let mut iu = UasIU::new(UAS_IU_ID_RESPONSE, tag);
        iu.body.response.response_code = code;
        let iu_len = size_of::<UasIUHeader>() + size_of::<UasIUResponse>();
        Self::fill_packet(packet, &mut iu, iu_len);
    }

    fn fill_fake_sense(packet: &mut UsbPacket, tag: u16, sense: ScsiSense) {
        let mut iu = UasIU::new(UAS_IU_ID_SENSE, tag);
        // SAFETY: IU is guaranteed to be of type status.
        let iu_sense = unsafe { &mut iu.body.sense };

        iu_sense.status = CHECK_CONDITION;
        iu_sense.status_qualifier = 0_u16.to_be();
        iu_sense.sense_length = 18_u16.to_be();
        iu_sense.sense_data[0] = 0x70; // Error code: current errors
        iu_sense.sense_data[2] = sense.key;
        iu_sense.sense_data[7] = 10; // Additional sense length: total length - 8
        iu_sense.sense_data[12] = sense.asc;
        iu_sense.sense_data[13] = sense.ascq;

        let iu_len = size_of::<UasIUHeader>() + size_of::<UasIUSense>();
        trace::usb_uas_fill_fake_sense(CHECK_CONDITION, iu_len, iu_sense.sense_length as usize);
        Self::fill_packet(packet, &mut iu, iu_len);
    }

    fn fill_sense(packet: &mut UsbPacket, tag: u16, sense: ScsiSense, status: u8) {
        let mut iu = UasIU::new(UAS_IU_ID_SENSE, tag);
        // SAFETY: IU is guaranteed to be of type status.
        let iu_sense = unsafe { &mut iu.body.sense };

        iu_sense.status = status;
        iu_sense.status_qualifier = 0_u16.to_be();
        iu_sense.sense_length = 0_u16.to_be();

        if status != GOOD {
            iu_sense.sense_length = 18_u16.to_be();
            iu_sense.sense_data[0] = 0x71; // Error code: deferred errors
            iu_sense.sense_data[2] = sense.key;
            iu_sense.sense_data[7] = 10; // Additional sense length: total length - 8
            iu_sense.sense_data[12] = sense.asc;
            iu_sense.sense_data[13] = sense.ascq;
        }

        let sense_len =
            size_of::<UasIUSense>() - iu_sense.sense_data.len() + iu_sense.sense_length as usize;
        let iu_len = size_of::<UasIUHeader>() + sense_len;
        trace::usb_uas_fill_sense(status, iu_len, iu_sense.sense_length as usize);
        Self::fill_packet(packet, &mut iu, iu_len);
    }

    fn fill_packet(packet: &mut UsbPacket, iu: &mut UasIU, iu_len: usize) {
        let iov_size = packet.get_iovecs_size() as usize;
        let iu_len = min(iov_size, iu_len);
        trace::usb_uas_fill_packet(iov_size);
        packet.transfer_packet(iu.as_mut_bytes(), iu_len);
    }

    fn try_start_next_transfer(&mut self, stream: usize) -> UasPacketStatus {
        if self.commands[stream].is_none() {
            debug!(
                "UAS {} device no inflight command on stream {}.",
                self.device_id(),
                stream
            );
            return UasPacketStatus::Pending;
        }

        if self.statuses[stream].is_none() {
            debug!(
                "UAS {} device no inflight status on stream {}.",
                self.device_id(),
                stream
            );
            return UasPacketStatus::Pending;
        }

        // SAFETY: Command was checked to be Some.
        let command = self.commands[stream].as_ref().unwrap();
        // SAFETY: IU is guaranteed to be of type command.
        let cdb = unsafe { &command.body.command.cdb };
        let xfer_len = scsi_cdb_xfer(cdb, self.scsi_device.as_ref().unwrap().clone());
        trace::usb_uas_try_start_next_transfer(self.device_id(), xfer_len);

        if xfer_len == 0 {
            return self.start_next_transfer(stream);
        }

        if self.data[stream].is_some() {
            self.start_next_transfer(stream)
        } else {
            debug!(
                "UAS {} device no inflight data on stream {}.",
                self.device_id(),
                stream
            );
            UasPacketStatus::Pending
        }
    }

    fn start_next_transfer(&mut self, stream: usize) -> UasPacketStatus {
        trace::usb_uas_start_next_transfer(self.device_id(), stream);
        // SAFETY: Status and command must have been checked in try_start_next_transfer.
        let status = self.statuses[stream].take().unwrap();
        let command = self.commands[stream].take().unwrap();
        let mut uas_request = UasRequest::new(&status, &command);
        uas_request.data = self.data[stream].take();

        let result = match command.header.id {
            UAS_IU_ID_COMMAND => self.handle_iu_command(&command, uas_request),
            UAS_IU_ID_TASK_MGMT => self.handle_iu_task_management(&command, uas_request),
            _ => Err(anyhow!("impossible command IU {}", command.header.id)),
        };

        match result {
            Ok(result) => result,
            Err(err) => {
                error!("UAS {} device error: {:#?}.", self.device_id(), err);
                UasPacketStatus::Completed
            }
        }
    }
}

impl UsbDevice for UsbUas {
    gen_base_func!(usb_device_base, usb_device_base_mut, UsbDeviceBase, base);

    fn realize(mut self) -> Result<Arc<Mutex<dyn UsbDevice>>> {
        info!("UAS {} device realize.", self.device_id());
        self.base.reset_usb_endpoint();
        self.base.speed = USB_SPEED_SUPER;
        let mut s: Vec<String> = UAS_DESC_STRINGS.iter().map(|&s| s.to_string()).collect();
        let prefix = &s[UsbUasStringId::SerialNumber as usize];
        s[UsbUasStringId::SerialNumber as usize] = self.base.generate_serial_number(prefix);
        self.base.init_descriptor(DESC_DEVICE_UAS.clone(), s)?;

        // NOTE: "aio=off,direct=false" must be configured and other aio/direct values are not
        // supported.
        let scsidev_classtype = match self.drive_cfg.media.as_str() {
            "disk" => "scsi-hd".to_string(),
            _ => "scsi-cd".to_string(),
        };
        let scsi_dev_cfg = ScsiDevConfig {
            classtype: scsidev_classtype,
            drive: self.uas_config.drive.clone(),
            ..Default::default()
        };
        let scsi_device = ScsiDevice::new(
            scsi_dev_cfg,
            self.drive_cfg.clone(),
            self.drive_files.clone(),
            None,
            self.scsi_bus.clone(),
        );
        let realized_scsi = scsi_device.realize()?;
        self.scsi_device = Some(realized_scsi.clone());
        self.scsi_bus
            .lock()
            .unwrap()
            .attach_child(get_scsi_key(0, 0), realized_scsi)?;
        let uas = Arc::new(Mutex::new(self));
        Ok(uas)
    }

    fn cancel_packet(&mut self, _packet: &Arc<Mutex<UsbPacket>>) {
        self.cancel_io();
    }

    fn reset(&mut self) {
        info!("UAS {} device reset.", self.device_id());
        self.base.remote_wakeup = 0;
        self.base.addr = 0;
        self.cancel_io();
    }

    fn handle_control(&mut self, packet: &Arc<Mutex<UsbPacket>>, device_req: &UsbDeviceRequest) {
        let mut locked_packet = packet.lock().unwrap();
        trace::usb_uas_handle_control(
            locked_packet.packet_id,
            self.device_id(),
            device_req.as_bytes(),
        );

        match self
            .base
            .handle_control_for_descriptor(&mut locked_packet, device_req)
        {
            Ok(handled) => {
                if handled {
                    debug!(
                        "UAS {} device control handled by descriptor, return directly.",
                        self.device_id()
                    );
                    return;
                }

                error!(
                    "UAS {} device unhandled control request {:?}.",
                    self.device_id(),
                    device_req
                );
                locked_packet.status = UsbPacketStatus::Stall;
            }
            Err(err) => {
                warn!(
                    "{} received incorrect UAS descriptor message: {:?}",
                    self.device_id(),
                    err
                );
                locked_packet.status = UsbPacketStatus::Stall;
            }
        }
    }

    fn handle_data(&mut self, packet: &Arc<Mutex<UsbPacket>>) {
        let locked_packet = packet.lock().unwrap();
        let stream = locked_packet.stream as usize;
        let ep_number = locked_packet.ep_number;
        let packet_id = locked_packet.packet_id;
        trace::usb_uas_handle_data(self.device_id(), ep_number, stream);
        drop(locked_packet);

        if stream > UAS_MAX_STREAMS || ep_number != UAS_PIPE_ID_COMMAND && stream == 0 {
            warn!("UAS {} device invalid stream {}.", self.device_id(), stream);
            packet.lock().unwrap().status = UsbPacketStatus::Stall;
            return;
        }

        // NOTE: The architecture of this device is rather simple: it first waits for all of the
        // required USB packets to arrive, and only then creates and sends an actual UAS request.
        // The number of USB packets differs from 2 to 3 and depends on whether the command involves
        // data transfers or not. Since the packets arrive in arbitrary order, some of them may be
        // queued asynchronously. Note that the command packet is always completed right away. For
        // all the other types of packets, their asynchronous status is determined by the return
        // value of try_start_next_transfer(). All the asynchronously queued packets will be
        // completed in scsi_request_complete_cb() callback.
        match ep_number {
            UAS_PIPE_ID_COMMAND => {
                let mut locked_packet = packet.lock().unwrap();
                let mut iu = UasIU::default();
                let iov_size = locked_packet.get_iovecs_size() as usize;
                let iu_len = min(iov_size, size_of::<UasIU>());
                locked_packet.transfer_packet(iu.as_mut_bytes(), iu_len);
                let stream = u16::from_be(iu.header.tag) as usize;

                if self.commands[stream].is_some() {
                    warn!(
                        "UAS {} device multiple command packets on stream {}.",
                        self.device_id(),
                        stream
                    );
                    packet.lock().unwrap().status = UsbPacketStatus::Stall;
                    return;
                }

                trace::usb_uas_command_received(packet_id, self.device_id());
                self.commands[stream] = Some(iu);
                self.try_start_next_transfer(stream);
                trace::usb_uas_command_completed(packet_id, self.device_id());
            }
            UAS_PIPE_ID_STATUS => {
                if self.statuses[stream].is_some() {
                    warn!(
                        "UAS {} device multiple status packets on stream {}.",
                        self.device_id(),
                        stream
                    );
                    packet.lock().unwrap().status = UsbPacketStatus::Stall;
                    return;
                }

                trace::usb_uas_status_received(packet_id, self.device_id());
                self.statuses[stream] = Some(Arc::clone(packet));
                let result = self.try_start_next_transfer(stream);

                match result {
                    UasPacketStatus::Completed => {
                        trace::usb_uas_status_completed(packet_id, self.device_id())
                    }
                    UasPacketStatus::Pending => {
                        packet.lock().unwrap().is_async = true;
                        trace::usb_uas_status_queued_async(packet_id, self.device_id());
                    }
                }
            }
            UAS_PIPE_ID_DATA_OUT | UAS_PIPE_ID_DATA_IN => {
                if self.data[stream].is_some() {
                    warn!(
                        "UAS {} device multiple data packets on stream {}.",
                        self.device_id(),
                        stream
                    );
                    packet.lock().unwrap().status = UsbPacketStatus::Stall;
                    return;
                }

                trace::usb_uas_data_received(packet_id, self.device_id());
                self.data[stream] = Some(Arc::clone(packet));
                let result = self.try_start_next_transfer(stream);

                match result {
                    UasPacketStatus::Completed => {
                        trace::usb_uas_data_completed(packet_id, self.device_id())
                    }
                    UasPacketStatus::Pending => {
                        packet.lock().unwrap().is_async = true;
                        trace::usb_uas_data_queued_async(packet_id, self.device_id());
                    }
                }
            }
            _ => {
                error!(
                    "UAS {} device bad endpoint number {}.",
                    self.device_id(),
                    ep_number
                );
            }
        }
    }

    fn set_controller(&mut self, _cntlr: std::sync::Weak<Mutex<XhciDevice>>) {}

    fn get_controller(&self) -> Option<Weak<Mutex<XhciDevice>>> {
        None
    }
}

impl UasRequest {
    fn new(status: &Arc<Mutex<UsbPacket>>, iu: &UasIU) -> Self {
        Self {
            data: None,
            status: Arc::clone(status),
            iu: *iu,
            completed: false,
        }
    }

    fn complete(&mut self) {
        let status = &self.status;
        let status_async = status.lock().unwrap().is_async;

        // NOTE: Due to the specifics of this device, it waits for all of the required USB packets
        // to arrive before starting an actual transfer. Therefore, some packets may arrive earlier
        // than others, and they won't be completed right away (except for the command packets), but
        // rather queued asynchronously. A certain packet may also be async if it was the last to
        // arrive, but UasRequest didn't complete right away.
        if status_async {
            complete_async_packet(status);
        }

        if let Some(data) = &self.data {
            let data_async = data.lock().unwrap().is_async;

            if data_async {
                complete_async_packet(data);
            }
        }

        self.completed = true;
    }
}

impl UasIUHeader {
    fn new(id: u8, tag: u16) -> Self {
        UasIUHeader {
            id,
            reserved: 0,
            tag: tag.to_be(),
        }
    }
}

impl UasIU {
    fn new(id: u8, tag: u16) -> Self {
        Self {
            header: UasIUHeader::new(id, tag),
            body: UasIUBody::default(),
        }
    }
}
