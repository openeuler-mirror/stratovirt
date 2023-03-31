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

use std::sync::{Arc, Mutex, Weak};

use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian};
use log::info;
use once_cell::sync::Lazy;

use super::config::*;
use super::descriptor::{
    UsbConfigDescriptor, UsbDescConfig, UsbDescDevice, UsbDescEndpoint, UsbDescIface,
    UsbDescriptorOps, UsbDeviceDescriptor, UsbEndpointDescriptor, UsbInterfaceDescriptor,
};
use super::xhci::xhci_controller::XhciDevice;
use super::{UsbDevice, UsbDeviceOps, UsbDeviceRequest, UsbEndpoint, UsbPacket};

// Storage device descriptor
static DESC_DEVICE_STORAGE: Lazy<Arc<UsbDescDevice>> = Lazy::new(|| {
    Arc::new(UsbDescDevice {
        device_desc: UsbDeviceDescriptor {
            bLength: USB_DT_DEVICE_SIZE,
            bDescriptorType: USB_DT_DEVICE,
            idVendor: USB_STORAGE_VENDOR_ID,
            idProduct: 0x0001,
            bcdDevice: 0,
            iManufacturer: STR_MANUFACTURER_INDEX,
            iProduct: STR_PRODUCT_STORAGE_INDEX,
            iSerialNumber: STR_SERIAL_STORAGE_INDEX,
            bcdUSB: 0x0200,
            bDeviceClass: 0,
            bDeviceSubClass: 0,
            bDeviceProtocol: 0,
            bMaxPacketSize0: 64,
            bNumConfigurations: 1,
        },
        configs: vec![Arc::new(UsbDescConfig {
            config_desc: UsbConfigDescriptor {
                bLength: USB_DT_CONFIG_SIZE,
                bDescriptorType: USB_DT_CONFIGURATION,
                wTotalLength: 0,
                bNumInterfaces: 1,
                bConfigurationValue: 1,
                iConfiguration: STR_CONFIG_STORAGE_HIGH_INDEX,
                bmAttributes: USB_CONFIGURATION_ATTR_ONE | USB_CONFIGURATION_ATTR_SELF_POWER,
                bMaxPower: 50,
            },
            iad_desc: vec![],
            interfaces: vec![DESC_IFACE_STORAGE.clone()],
        })],
    })
});

// Storage interface descriptor
static DESC_IFACE_STORAGE: Lazy<Arc<UsbDescIface>> = Lazy::new(|| {
    Arc::new(UsbDescIface {
        interface_desc: UsbInterfaceDescriptor {
            bLength: USB_DT_INTERFACE_SIZE,
            bDescriptorType: USB_DT_INTERFACE,
            bInterfaceNumber: 0,
            bAlternateSetting: 0,
            bNumEndpoints: 2,
            bInterfaceClass: USB_CLASS_MASS_STORAGE,
            bInterfaceSubClass: 0x06, // SCSI
            bInterfaceProtocol: 0x50, // Bulk-only
            iInterface: 0,
        },
        other_desc: vec![],
        endpoints: vec![
            Arc::new(UsbDescEndpoint {
                endpoint_desc: UsbEndpointDescriptor {
                    bLength: USB_DT_ENDPOINT_SIZE,
                    bDescriptorType: USB_DT_ENDPOINT,
                    bEndpointAddress: USB_DIRECTION_DEVICE_TO_HOST | 0x01,
                    bmAttributes: USB_ENDPOINT_ATTR_BULK,
                    wMaxPacketSize: 512,
                    bInterval: 0,
                },
                extra: None,
            }),
            Arc::new(UsbDescEndpoint {
                endpoint_desc: UsbEndpointDescriptor {
                    bLength: USB_DT_ENDPOINT_SIZE,
                    bDescriptorType: USB_DT_ENDPOINT,
                    bEndpointAddress: USB_DIRECTION_HOST_TO_DEVICE | 0x02,
                    bmAttributes: USB_ENDPOINT_ATTR_BULK,
                    wMaxPacketSize: 512,
                    bInterval: 0,
                },
                extra: None,
            }),
        ],
    })
});

// CRC16 of "STRATOVIRT"
const USB_STORAGE_VENDOR_ID: u16 = 0xB74C;

// String descriptor index
const STR_MANUFACTURER_INDEX: u8 = 1;
const STR_PRODUCT_STORAGE_INDEX: u8 = 2;
const STR_SERIAL_STORAGE_INDEX: u8 = 3;
const STR_CONFIG_STORAGE_HIGH_INDEX: u8 = 5;

// String descriptor
const DESC_STRINGS: [&str; 7] = [
    "",
    "StratoVirt",
    "StratoVirt USB Storage",
    "1",
    "Full speed config (usb 1.1)",
    "High speed config (usb 2.0)",
    "Super speed config (usb 3.0)",
];

pub const GET_MAX_LUN: u8 = 0xfe;
pub const MASS_STORAGE_RESET: u8 = 0xff;

pub const CBW_SIGNATURE: u32 = 0x43425355;
pub const CSW_SIGNATURE: u32 = 0x53425355;
pub const CBW_FLAG_IN: u8 = 1 << 7;
pub const CBW_FLAG_OUT: u8 = 0;
pub const CBW_SIZE: u8 = 31;
pub const CSW_SIZE: u8 = 13;

#[allow(dead_code)]
struct UsbStorageState {
    mode: UsbMsdMode,
    cbw: UsbMsdCbw,
    csw: UsbMsdCsw,
}

impl UsbStorageState {
    fn new() -> Self {
        UsbStorageState {
            mode: UsbMsdMode::Cbw,
            cbw: UsbMsdCbw::default(),
            csw: UsbMsdCsw::new(),
        }
    }
}

/// USB storage device.
pub struct UsbStorage {
    id: String,
    usb_device: UsbDevice,
    state: UsbStorageState,
    /// USB controller used to notify controller to transfer data.
    cntlr: Option<Weak<Mutex<XhciDevice>>>,
}

#[allow(dead_code)]
#[derive(Debug)]
enum UsbMsdMode {
    Cbw,
    DataOut,
    DataIn,
    Csw,
}

#[allow(dead_code)]
enum UsbMsdCswStatus {
    Passed,
    Failed,
    PhaseError,
}

#[allow(dead_code)]
#[derive(Debug, Default)]
struct UsbMsdCbw {
    sig: u32,
    tag: u32,
    data_len: u32,
    flags: u8,
    lun: u8,
    cmd_len: u8,
    cmd: [u8; 16],
}

#[allow(dead_code)]
impl UsbMsdCbw {
    fn convert(&mut self, data: &[u8]) {
        self.sig = LittleEndian::read_u32(&data[0..4]);
        self.tag = LittleEndian::read_u32(&data[4..8]);
        self.data_len = LittleEndian::read_u32(&data[8..12]);
        self.flags = data[12];
        self.lun = data[13];
        self.cmd_len = data[14];
        self.cmd.copy_from_slice(&data[15..31]);
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct UsbMsdCsw {
    sig: u32,
    tag: u32,
    residue: u32,
    status: u8,
}

#[allow(dead_code)]
impl UsbMsdCsw {
    fn new() -> Self {
        UsbMsdCsw {
            sig: CSW_SIGNATURE,
            tag: 0,
            residue: 0,
            status: 0,
        }
    }

    fn convert(&mut self, data: &mut [u8]) {
        LittleEndian::write_u32(&mut data[0..4], self.sig);
        LittleEndian::write_u32(&mut data[4..8], self.tag);
        LittleEndian::write_u32(&mut data[8..12], self.residue);
        data[12] = self.status;
    }
}

impl UsbStorage {
    pub fn new() -> Self {
        Self {
            id: "".to_string(),
            usb_device: UsbDevice::new(),
            state: UsbStorageState::new(),
            cntlr: None,
        }
    }

    pub fn realize(mut self) -> Result<Arc<Mutex<Self>>> {
        self.usb_device.reset_usb_endpoint();
        self.usb_device.speed = USB_SPEED_HIGH;
        let s = DESC_STRINGS.iter().map(|&s| s.to_string()).collect();
        self.usb_device
            .init_descriptor(DESC_DEVICE_STORAGE.clone(), s)?;

        let storage: Arc<Mutex<UsbStorage>> = Arc::new(Mutex::new(self));
        Ok(storage)
    }
}

impl UsbDeviceOps for UsbStorage {
    fn reset(&mut self) {
        info!("Storage device reset");
        self.usb_device.remote_wakeup = 0;
        self.usb_device.addr = 0;
        self.state = UsbStorageState::new();
    }

    fn handle_control(&mut self, _packet: &mut UsbPacket, _device_req: &UsbDeviceRequest) {}

    fn handle_data(&mut self, _packet: &mut UsbPacket) {}

    fn device_id(&self) -> String {
        self.id.clone()
    }

    fn get_usb_device(&self) -> &UsbDevice {
        &self.usb_device
    }

    fn get_mut_usb_device(&mut self) -> &mut UsbDevice {
        &mut self.usb_device
    }

    fn set_controller(&mut self, cntlr: Weak<Mutex<XhciDevice>>) {
        self.cntlr = Some(cntlr);
    }

    fn get_controller(&self) -> Option<Weak<Mutex<XhciDevice>>> {
        self.cntlr.clone()
    }

    fn get_wakeup_endpoint(&self) -> &UsbEndpoint {
        self.usb_device.get_endpoint(true, 1)
    }
}
