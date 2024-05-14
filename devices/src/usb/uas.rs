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
use std::collections::{HashMap, VecDeque};
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
    UsbDevice, UsbDeviceBase, UsbDeviceRequest, UsbEndpoint, UsbPacket, UsbPacketStatus,
    USB_DEVICE_BUFFER_DEFAULT_LEN,
};
use crate::{
    ScsiBus::{
        scsi_cdb_xfer, scsi_cdb_xfer_mode, ScsiBus, ScsiRequest, ScsiRequestOps, ScsiSense,
        ScsiXferMode, CHECK_CONDITION, EMULATE_SCSI_OPS, GOOD, SCSI_SENSE_INVALID_PARAM_VALUE,
        SCSI_SENSE_INVALID_TAG, SCSI_SENSE_NO_SENSE, SCSI_SENSE_OVERLAPPED_COMMANDS,
    },
    ScsiDisk::{ScsiDevConfig, ScsiDevice},
};
use machine_manager::config::{DriveConfig, DriveFile};
use util::byte_code::ByteCode;

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
const UAS_MAX_STREAMS_BM_ATTR: u8 = 0;
const UAS_MAX_STREAMS: usize = 1 << UAS_MAX_STREAMS_BM_ATTR;

// UAS IU IDs
const UAS_IU_ID_COMMAND: u8 = 0x01;
const UAS_IU_ID_SENSE: u8 = 0x03;
const UAS_IU_ID_RESPONSE: u8 = 0x04;
const UAS_IU_ID_TASK_MGMT: u8 = 0x05;
const UAS_IU_ID_READ_READY: u8 = 0x06;
const UAS_IU_ID_WRITE_READY: u8 = 0x07;

// UAS Response Codes
const _UAS_RC_TMF_COMPLETE: u8 = 0x00;
const _UAS_RC_INVALID_IU: u8 = 0x02;
const UAS_RC_TMF_NOT_SUPPORTED: u8 = 0x04;
const _UAS_RC_TMF_FAILED: u8 = 0x05;
const _UAS_RC_TMF_SUCCEEDED: u8 = 0x08;
const _UAS_RC_INCORRECT_LUN: u8 = 0x09;
const _UAS_RC_OVERLAPPED_TAG: u8 = 0x0A;

// UAS Task Management Functions
const _UAS_TMF_ABORT_TASK: u8 = 0x01;
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
    scsi_bus: Arc<Mutex<ScsiBus>>,
    scsi_device: Arc<Mutex<ScsiDevice>>,
    commands_high: VecDeque<UasIU>,
    statuses_high: VecDeque<Arc<Mutex<UsbPacket>>>,
    commands_super: [Option<UasIU>; UAS_MAX_STREAMS + 1],
    statuses_super: [Option<Arc<Mutex<UsbPacket>>>; UAS_MAX_STREAMS + 1],
    data: [Option<Arc<Mutex<UsbPacket>>>; UAS_MAX_STREAMS + 1],
    data_ready_sent: bool,
}

#[derive(Debug, EnumCount)]
enum UsbUasStringId {
    #[allow(unused)]
    Invalid = 0,
    Manufacturer = 1,
    Product = 2,
    SerialNumber = 3,
    ConfigHigh = 4,
    ConfigSuper = 5,
}

const UAS_DESC_STRINGS: [&str; UsbUasStringId::COUNT] = [
    "",
    "StratoVirt",
    "StratoVirt USB Uas",
    "5",
    "High speed config (usb 2.0)",
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
        UsbUas::fill_sense(&mut self.status.lock().unwrap(), tag, scsi_status, &sense);
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

static DESC_DEVICE_UAS_SUPER: Lazy<Arc<UsbDescDevice>> = Lazy::new(|| {
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
                iConfiguration: UsbUasStringId::ConfigSuper as u8,
                bmAttributes: USB_CONFIGURATION_ATTR_ONE | USB_CONFIGURATION_ATTR_SELF_POWER,
                bMaxPower: 50,
            },
            iad_desc: vec![],
            interfaces: vec![DESC_IFACE_EMPTY.clone(), DESC_IFACE_UAS_SUPER.clone()],
        })],
    })
});

static DESC_IFACE_UAS_SUPER: Lazy<Arc<UsbDescIface>> = Lazy::new(|| {
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

static DESC_DEVICE_UAS_HIGH: Lazy<Arc<UsbDescDevice>> = Lazy::new(|| {
    Arc::new(UsbDescDevice {
        device_desc: UsbDeviceDescriptor {
            bLength: USB_DT_DEVICE_SIZE,
            bDescriptorType: USB_DT_DEVICE,
            bcdUSB: 0x0200,
            bDeviceClass: 0,
            bDeviceSubClass: 0,
            bDeviceProtocol: 0,
            bMaxPacketSize0: 64,
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
                iConfiguration: UsbUasStringId::ConfigHigh as u8,
                bmAttributes: USB_CONFIGURATION_ATTR_ONE | USB_CONFIGURATION_ATTR_SELF_POWER,
                bMaxPower: 50,
            },
            iad_desc: vec![],
            interfaces: vec![DESC_IFACE_EMPTY.clone(), DESC_IFACE_UAS_HIGH.clone()],
        })],
    })
});

static DESC_IFACE_UAS_HIGH: Lazy<Arc<UsbDescIface>> = Lazy::new(|| {
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
                    wMaxPacketSize: 512,
                    bInterval: 0,
                },
                extra: UsbPipeUsageDescriptor {
                    bLength: USB_DT_PIPE_USAGE_SIZE,
                    bDescriptorType: USB_DT_PIPE_USAGE,
                    bPipeId: UAS_PIPE_ID_COMMAND,
                    bReserved: 0,
                }
                .as_bytes()
                .to_vec(),
            }),
            Arc::new(UsbDescEndpoint {
                endpoint_desc: UsbEndpointDescriptor {
                    bLength: USB_DT_ENDPOINT_SIZE,
                    bDescriptorType: USB_DT_ENDPOINT,
                    bEndpointAddress: USB_DIRECTION_DEVICE_TO_HOST | UAS_PIPE_ID_STATUS,
                    bmAttributes: USB_ENDPOINT_ATTR_BULK,
                    wMaxPacketSize: 512,
                    bInterval: 0,
                },
                extra: UsbPipeUsageDescriptor {
                    bLength: USB_DT_PIPE_USAGE_SIZE,
                    bDescriptorType: USB_DT_PIPE_USAGE,
                    bPipeId: UAS_PIPE_ID_STATUS,
                    bReserved: 0,
                }
                .as_bytes()
                .to_vec(),
            }),
            Arc::new(UsbDescEndpoint {
                endpoint_desc: UsbEndpointDescriptor {
                    bLength: USB_DT_ENDPOINT_SIZE,
                    bDescriptorType: USB_DT_ENDPOINT,
                    bEndpointAddress: USB_DIRECTION_DEVICE_TO_HOST | UAS_PIPE_ID_DATA_IN,
                    bmAttributes: USB_ENDPOINT_ATTR_BULK,
                    wMaxPacketSize: 512,
                    bInterval: 0,
                },
                extra: UsbPipeUsageDescriptor {
                    bLength: USB_DT_PIPE_USAGE_SIZE,
                    bDescriptorType: USB_DT_PIPE_USAGE,
                    bPipeId: UAS_PIPE_ID_DATA_IN,
                    bReserved: 0,
                }
                .as_bytes()
                .to_vec(),
            }),
            Arc::new(UsbDescEndpoint {
                endpoint_desc: UsbEndpointDescriptor {
                    bLength: USB_DT_ENDPOINT_SIZE,
                    bDescriptorType: USB_DT_ENDPOINT,
                    bEndpointAddress: USB_DIRECTION_HOST_TO_DEVICE | UAS_PIPE_ID_DATA_OUT,
                    bmAttributes: USB_ENDPOINT_ATTR_BULK,
                    wMaxPacketSize: 512,
                    bInterval: 0,
                },
                extra: UsbPipeUsageDescriptor {
                    bLength: USB_DT_PIPE_USAGE_SIZE,
                    bDescriptorType: USB_DT_PIPE_USAGE,
                    bPipeId: UAS_PIPE_ID_DATA_OUT,
                    bReserved: 0,
                }
                .as_bytes()
                .to_vec(),
            }),
        ],
    })
});

// NOTE: Fake BOT interface descriptor is needed here since Windows UASP driver always expects two
// interfaces: both BOT and UASP. It also anticipates the UASP descriptor to be the second one.
// Therefore, the first one can be a BOT storage stub.
static DESC_IFACE_EMPTY: Lazy<Arc<UsbDescIface>> = Lazy::new(|| {
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
        let scsidev_classtype = match &drive_cfg.media as &str {
            "disk" => "scsi-hd".to_string(),
            _ => "scsi-cd".to_string(),
        };
        let scsi_dev_cfg = ScsiDevConfig {
            classtype: scsidev_classtype,
            drive: uas_config.drive.clone(),
            ..Default::default()
        };

        let mut base = UsbDeviceBase::new(
            uas_config.id.clone().unwrap(),
            USB_DEVICE_BUFFER_DEFAULT_LEN,
        );

        base.speed = match uas_config.speed.as_deref() {
            Some("super") => USB_SPEED_SUPER,
            _ => USB_SPEED_HIGH,
        };

        Self {
            base,
            scsi_bus: Arc::new(Mutex::new(ScsiBus::new("".to_string()))),
            scsi_device: Arc::new(Mutex::new(ScsiDevice::new(
                scsi_dev_cfg,
                drive_cfg,
                drive_files,
            ))),
            commands_high: VecDeque::new(),
            commands_super: array::from_fn(|_| None),
            statuses_high: VecDeque::new(),
            statuses_super: array::from_fn(|_| None),
            data: array::from_fn(|_| None),
            data_ready_sent: false,
        }
    }

    fn streams_enabled(&self) -> bool {
        self.base.speed == USB_SPEED_SUPER
    }

    fn cancel_io(&mut self) {
        self.commands_high = VecDeque::new();
        self.commands_super = array::from_fn(|_| None);
        self.statuses_high = VecDeque::new();
        self.statuses_super = array::from_fn(|_| None);
        self.data = array::from_fn(|_| None);
        self.data_ready_sent = false;
    }

    fn peek_next_status(&self, stream: usize) -> Option<&Arc<Mutex<UsbPacket>>> {
        match self.streams_enabled() {
            true => self.statuses_super[stream].as_ref(),
            false => self.statuses_high.front(),
        }
    }

    fn take_next_status(&mut self, stream: usize) -> Arc<Mutex<UsbPacket>> {
        match self.streams_enabled() {
            true => self.statuses_super[stream].take().unwrap(),
            false => self.statuses_high.pop_front().unwrap(),
        }
    }

    fn queue_status(&mut self, status: &Arc<Mutex<UsbPacket>>, stream: usize) {
        match self.streams_enabled() {
            true => self.statuses_super[stream] = Some(Arc::clone(status)),
            false => self.statuses_high.push_back(Arc::clone(status)),
        };
    }

    fn peek_next_command(&self, stream: usize) -> Option<&UasIU> {
        match self.streams_enabled() {
            true => self.commands_super[stream].as_ref(),
            false => self.commands_high.front(),
        }
    }

    fn take_next_command(&mut self, stream: usize) -> UasIU {
        match self.streams_enabled() {
            true => self.commands_super[stream].take().unwrap(),
            false => self.commands_high.pop_front().unwrap(),
        }
    }

    fn queue_command(&mut self, command: UasIU, stream: usize) {
        match self.streams_enabled() {
            true => self.commands_super[stream] = Some(command),
            false => self.commands_high.push_back(command),
        }
    }

    fn handle_iu_command(
        &mut self,
        iu: &UasIU,
        mut uas_request: UasRequest,
    ) -> Result<UasPacketStatus> {
        // SAFETY: iu is guaranteed to be of type command
        let add_cdb_len = unsafe { iu.body.command.add_cdb_len };
        let tag = u16::from_be(iu.header.tag);

        if add_cdb_len > 0 {
            Self::fill_fake_sense(
                &mut uas_request.status.lock().unwrap(),
                tag,
                &SCSI_SENSE_INVALID_PARAM_VALUE,
            );
            uas_request.complete();
            bail!("additional cdb length is not supported");
        }

        if self.streams_enabled() && tag > UAS_MAX_STREAMS as u16 {
            Self::fill_fake_sense(
                &mut uas_request.status.lock().unwrap(),
                tag,
                &SCSI_SENSE_INVALID_TAG,
            );
            uas_request.complete();
            bail!("invalid tag {}", tag);
        }

        if self.streams_enabled() && self.commands_super[tag as usize].is_some() {
            Self::fill_fake_sense(
                &mut uas_request.status.lock().unwrap(),
                tag,
                &SCSI_SENSE_OVERLAPPED_COMMANDS,
            );
            uas_request.complete();
            bail!("overlapped tag {}", tag);
        }

        let (scsi_iovec, scsi_iovec_size) = match uas_request.data.as_ref() {
            Some(data) => {
                let mut locked_data = data.lock().unwrap();
                let iov_size = locked_data.get_iovecs_size() as u32;
                locked_data.actual_length = iov_size;
                (locked_data.iovecs.clone(), iov_size)
            }
            None => (Vec::new(), 0),
        };

        // SAFETY: iu is guaranteed to of type command
        let cdb = unsafe { iu.body.command.cdb };
        // SAFETY: iu is guaranteed to of type command
        let lun = unsafe { iu.body.command.lun } as u16;
        trace::usb_uas_handle_iu_command(self.device_id(), cdb[0]);
        let uas_request = Box::new(uas_request);
        let scsi_request = ScsiRequest::new(
            cdb,
            lun,
            scsi_iovec,
            scsi_iovec_size,
            Arc::clone(&self.scsi_device),
            uas_request,
        )
        .with_context(|| "Failed to create SCSI request.")?;

        if scsi_request.cmd.xfer > scsi_request.datalen
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
        .with_context(|| "Failed to execute SCSI request.")?;

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

        if self.streams_enabled() && tag > UAS_MAX_STREAMS as u16 {
            Self::fill_fake_sense(
                &mut uas_request.status.lock().unwrap(),
                tag,
                &SCSI_SENSE_INVALID_TAG,
            );
            uas_request.complete();
            bail!("invalid tag {}", tag);
        }

        if self.streams_enabled() && self.commands_super[tag as usize].is_some() {
            Self::fill_fake_sense(
                &mut uas_request.status.lock().unwrap(),
                tag,
                &SCSI_SENSE_OVERLAPPED_COMMANDS,
            );
            uas_request.complete();
            bail!("overlapped tag {}", tag);
        }

        // SAFETY: iu is guaranteed to be of type task management
        let tmf = unsafe { iu.body.task_management.function };

        #[allow(clippy::match_single_binding)]
        match tmf {
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

    fn fill_sense(packet: &mut UsbPacket, tag: u16, status: u8, sense: &ScsiSense) {
        let mut iu = UasIU::new(UAS_IU_ID_SENSE, tag);
        // SAFETY: iu is guaranteed to be of type status
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

        let sense_len = iu_sense.sense_length as usize;
        let real_sense_len = size_of::<UasIUSense>() - iu_sense.sense_data.len() + sense_len;
        let iu_len = size_of::<UasIUHeader>() + real_sense_len;
        trace::usb_uas_fill_sense(status, iu_len, sense_len);
        Self::fill_packet(packet, &mut iu, iu_len);
    }

    fn fill_fake_sense(packet: &mut UsbPacket, tag: u16, sense: &ScsiSense) {
        let mut iu = UasIU::new(UAS_IU_ID_SENSE, tag);
        // SAFETY: iu is guaranteed to be of type status
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
        trace::usb_uas_fill_fake_sense(CHECK_CONDITION, iu_len, 18);
        Self::fill_packet(packet, &mut iu, iu_len);
    }

    fn fill_read_ready(packet: &mut UsbPacket, tag: u16) {
        let mut iu = UasIU::new(UAS_IU_ID_READ_READY, tag);
        let iu_len = size_of::<UasIUHeader>();
        Self::fill_packet(packet, &mut iu, iu_len);
    }

    fn fill_write_ready(packet: &mut UsbPacket, tag: u16) {
        let mut iu = UasIU::new(UAS_IU_ID_WRITE_READY, tag);
        let iu_len = size_of::<UasIUHeader>();
        Self::fill_packet(packet, &mut iu, iu_len);
    }

    fn fill_packet(packet: &mut UsbPacket, iu: &mut UasIU, iu_len: usize) {
        let iov_size = packet.get_iovecs_size() as usize;
        let iu_len = min(iov_size, iu_len);
        trace::usb_uas_fill_packet(iov_size);
        packet.transfer_packet(iu.as_mut_bytes(), iu_len);
    }

    fn try_start_next_transfer(&mut self, stream: usize) -> UasPacketStatus {
        let command = self.peek_next_command(stream);

        if let Some(command) = command {
            // SAFETY: iu is guaranteed to be of type command
            let cdb = unsafe { &command.body.command.cdb };
            let xfer_len = scsi_cdb_xfer(cdb, Arc::clone(&self.scsi_device));
            trace::usb_uas_try_start_next_transfer(self.device_id(), xfer_len);

            if xfer_len > 0 {
                self.try_start_next_data(stream)
            } else {
                self.try_start_next_non_data(stream)
            }
        } else {
            debug!(
                "UAS {} device no inflight command when trying to start the next transfer.",
                self.device_id()
            );
            UasPacketStatus::Pending
        }
    }

    fn try_start_next_data(&mut self, stream: usize) -> UasPacketStatus {
        let status = self.peek_next_status(stream);

        if status.is_none() {
            debug!(
                "UAS {} device no inflight status when trying to start the next data transfer.",
                self.device_id()
            );
            return UasPacketStatus::Pending;
        }

        if !self.data_ready_sent {
            return self.fill_data_ready(stream);
        }

        if self.data[stream].is_some() {
            self.start_next_transfer(stream)
        } else {
            debug!(
                "UAS {} device no inflight data when trying to start the next data transfer.",
                self.device_id()
            );
            UasPacketStatus::Pending
        }
    }

    fn fill_data_ready(&mut self, stream: usize) -> UasPacketStatus {
        // SAFETY: status must have been checked in try_start_next_data
        let status = self.take_next_status(stream);
        let mut locked_status = status.lock().unwrap();

        // SAFETY: command must have been checked in try_start_next_transfer
        let iu = self.peek_next_command(stream).unwrap();
        let tag = u16::from_be(iu.header.tag);

        // SAFETY: iu is guaranteed to be of type command
        let cdb = unsafe { &iu.body.command.cdb };
        let xfer_mode = scsi_cdb_xfer_mode(cdb);

        match xfer_mode {
            ScsiXferMode::ScsiXferFromDev => Self::fill_read_ready(&mut locked_status, tag),
            ScsiXferMode::ScsiXferToDev => Self::fill_write_ready(&mut locked_status, tag),
            ScsiXferMode::ScsiXferNone => {
                warn!(
                    "UAS {} device cannot fill data ready, operation {} is not a data transfer.",
                    self.device_id(),
                    cdb[0]
                );
                Self::fill_fake_sense(&mut locked_status, tag, &SCSI_SENSE_INVALID_PARAM_VALUE);
            }
        }

        let status_async = locked_status.is_async;
        drop(locked_status);

        if status_async {
            complete_async_packet(&status);
        }

        self.data_ready_sent = true;
        trace::usb_uas_fill_data_ready(self.device_id(), self.data_ready_sent);
        UasPacketStatus::Completed
    }

    fn try_start_next_non_data(&mut self, stream: usize) -> UasPacketStatus {
        let status = self.peek_next_status(stream);

        if status.is_none() {
            debug!(
                "UAS {} device no inflight status when trying to start the next non-data transfer.",
                self.device_id()
            );
            return UasPacketStatus::Pending;
        }

        self.start_next_transfer(stream)
    }

    fn start_next_transfer(&mut self, stream: usize) -> UasPacketStatus {
        trace::usb_uas_start_next_transfer(self.device_id(), stream);

        // SAFETY: status must have been checked in try_start_next_data or try_start_next_non_data
        let status = self.take_next_status(stream);

        // SAFETY: command must have been checked in try_start_next_transfer
        let command = self.take_next_command(stream);

        let mut uas_request = UasRequest::new(&status, &command);
        uas_request.data = self.data[stream].take();

        let result = match command.header.id {
            UAS_IU_ID_COMMAND => self.handle_iu_command(&command, uas_request),
            UAS_IU_ID_TASK_MGMT => self.handle_iu_task_management(&command, uas_request),
            _ => Err(anyhow!("impossible command IU {}", command.header.id)),
        };

        self.data_ready_sent = false;
        self.try_start_next_transfer(stream);

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
    fn usb_device_base(&self) -> &UsbDeviceBase {
        &self.base
    }

    fn usb_device_base_mut(&mut self) -> &mut UsbDeviceBase {
        &mut self.base
    }

    fn realize(mut self) -> Result<Arc<Mutex<dyn UsbDevice>>> {
        info!("UAS {} device realize.", self.device_id());
        self.base.reset_usb_endpoint();
        let mut desc_strings: Vec<String> =
            UAS_DESC_STRINGS.iter().map(|str| str.to_string()).collect();
        let prefix = &desc_strings[UsbUasStringId::SerialNumber as usize];
        desc_strings[UsbUasStringId::SerialNumber as usize] =
            self.base.generate_serial_number(prefix);

        match self.base.speed {
            USB_SPEED_HIGH => self
                .base
                .init_descriptor(DESC_DEVICE_UAS_HIGH.clone(), desc_strings)?,
            USB_SPEED_SUPER => self
                .base
                .init_descriptor(DESC_DEVICE_UAS_SUPER.clone(), desc_strings)?,
            _ => bail!("USB UAS unsupported device speed {}.", self.base.speed),
        }

        // NOTE: "aio=off,direct=false" must be configured and other aio/direct values are not
        // supported.
        let mut locked_scsi_device = self.scsi_device.lock().unwrap();
        locked_scsi_device.realize(None)?;
        locked_scsi_device.parent_bus = Arc::downgrade(&self.scsi_bus);
        drop(locked_scsi_device);
        self.scsi_bus
            .lock()
            .unwrap()
            .devices
            .insert((0, 0), Arc::clone(&self.scsi_device));

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
                error!(
                    "UAS {} device descriptor error {:?}.",
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

        if self.streams_enabled() && (stream > UAS_MAX_STREAMS || stream == 0) {
            warn!("UAS {} device invalid stream {}.", self.device_id(), stream);
            packet.lock().unwrap().status = UsbPacketStatus::Stall;
            return;
        }

        // NOTE: The architecture of this device is rather simple: it first waits for all of the
        // required USB packets to arrive, and only then creates and sends an actual UAS request.
        // The number of USB packets differs from 2 to 4 and depends on whether the command involves
        // data transfers or not. Since the packets arrive in arbitrary order, some of them may be
        // queued asynchronously. Note that the command packet is always completed right away. For
        // all the other types of packets, their asynchronous status is determined by the return
        // value of try_start_next_transfer(). All the asynchronously queued packets will be
        // completed in scsi_request_complete_cb() callback.
        match ep_number {
            UAS_PIPE_ID_COMMAND => {
                if self.streams_enabled() && self.commands_super[stream].is_some() {
                    warn!(
                        "UAS {} device multiple command packets on stream {}.",
                        self.device_id(),
                        stream
                    );
                    packet.lock().unwrap().status = UsbPacketStatus::Stall;
                    return;
                }

                let mut locked_packet = packet.lock().unwrap();
                let mut iu = UasIU::default();
                let iov_size = locked_packet.get_iovecs_size() as usize;
                let iu_len = min(iov_size, size_of::<UasIU>());
                locked_packet.transfer_packet(iu.as_mut_bytes(), iu_len);

                trace::usb_uas_command_received(packet_id, self.device_id());
                self.queue_command(iu, stream);
                self.try_start_next_transfer(stream);
                trace::usb_uas_command_completed(packet_id, self.device_id());
            }
            UAS_PIPE_ID_STATUS => {
                if self.streams_enabled() && self.statuses_super[stream].is_some() {
                    warn!(
                        "UAS {} device multiple status packets on stream {}.",
                        self.device_id(),
                        stream
                    );
                    packet.lock().unwrap().status = UsbPacketStatus::Stall;
                    return;
                }

                trace::usb_uas_status_received(packet_id, self.device_id());
                self.queue_status(packet, stream);
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

    fn set_controller(&mut self, _controller: std::sync::Weak<Mutex<XhciDevice>>) {}

    fn get_controller(&self) -> Option<Weak<Mutex<XhciDevice>>> {
        None
    }

    fn get_wakeup_endpoint(&self) -> &UsbEndpoint {
        self.base.get_endpoint(true, 1)
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
        // than others, and they won't be completed right away (except for command packets) but
        // rather queued asynchronously. A certain packet may also be async if it was the last to
        // arrive and UasRequest didn't complete right away.
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
