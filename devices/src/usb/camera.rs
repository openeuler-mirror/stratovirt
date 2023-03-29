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

//! Emulated camera device that based on UVC(USB video class) protocol.

use anyhow::{bail, Result};
use log::{debug, error};
use once_cell::sync::Lazy;

use std::sync::{Arc, Mutex, Weak};
use strum::EnumCount;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

use super::config::USB_SPEED_HIGH;
use super::xhci::xhci_controller::XhciDevice;
use crate::camera_backend::{v4l2::V4l2HostDev, CameraHostdevOps};
use crate::usb::config::*;
use crate::usb::descriptor::*;
use crate::usb::{
    UsbDevice, UsbDeviceOps, UsbDeviceRequest, UsbEndpoint, UsbPacket, UsbPacketStatus,
};
use machine_manager::config::{CamBackendType, UsbCameraConfig};

// CRC16 of "STRATOVIRT"
const UVC_VENDOR_ID: u16 = 0xB74C;
// The first 4 chars of "VIDEO", 5 substitutes V.
const UVC_PRODUCT_ID: u16 = 0x51DE;

#[allow(dead_code)]
pub struct UsbCamera {
    id: String,                                 // uniq device id
    usb_device: UsbDevice,                      // general usb device object
    frame: Vec<u64>,                            // video frame data
    max_pkt_size: u32,                          // the max size of the packet that can be seperated
    vs_eps: Vec<u8>,                            // the endpoints that the VS uses
    backend_type: CamBackendType,               // backend interface, eg. v4l2
    backend_path: String,                       // backend interface file, eg. /dev/video0
    hostdev: Option<Box<dyn CameraHostdevOps>>, // backend device, eg. v4l2, demo, etc.
}

#[derive(Debug, EnumCountMacro, EnumIter)]
enum UsbCameraStringIDs {
    Invalid = 0,
    Manufacture,
    Product,
    SerialNumber,
    Configuration,
    Iad,
    VideoControl,
    InputTerminal,
    OutputTerminal,
    SelectUnit,
    ProcessingUnit,
    VideoStreaming,
}

const UVC_CAMERA_STRINGS: [&str; UsbCameraStringIDs::COUNT] = [
    "",
    "StratoVirt",
    "USB Camera",
    "1",
    "USB Camera Configuration",
    "USB Camera Interface Associated Description",
    "Video Control",
    "Input Terminal",
    "Output Terminal",
    "Select Unit",
    "Processing Unit",
    "Video Streaming",
];

/// UVC Camera device descriptor
static DESC_DEVICE_CAMERA: Lazy<Arc<UsbDescDevice>> = Lazy::new(|| {
    Arc::new(UsbDescDevice {
        device_desc: UsbDeviceDescriptor {
            bLength: USB_DT_DEVICE_SIZE,
            bDescriptorType: USB_DT_DEVICE,
            idVendor: UVC_VENDOR_ID,
            idProduct: UVC_PRODUCT_ID,
            bcdDevice: 0,
            iManufacturer: UsbCameraStringIDs::Manufacture as u8,
            iProduct: UsbCameraStringIDs::Product as u8,
            iSerialNumber: UsbCameraStringIDs::SerialNumber as u8,
            bcdUSB: 0x0200, // TODO: support 3.0 Super
            bDeviceClass: USB_CLASS_MISCELLANEOUS,
            // Refer to https://www.usb.org/defined-class-codes for details.
            bDeviceSubClass: 2,
            bDeviceProtocol: 1, // Interface Association
            bMaxPacketSize0: 64,
            bNumConfigurations: 1,
        },
        configs: vec![Arc::new(UsbDescConfig {
            config_desc: UsbConfigDescriptor {
                bLength: USB_DT_CONFIG_SIZE,
                bDescriptorType: USB_DT_CONFIGURATION,
                wTotalLength: 0,
                bNumInterfaces: 2,
                bConfigurationValue: 1,
                iConfiguration: UsbCameraStringIDs::Configuration as u8,
                bmAttributes: USB_CONFIGURATION_ATTR_ONE | USB_CONFIGURATION_ATTR_SELF_POWER,
                bMaxPower: 50,
            },
            // TODO: Add IAD descriptor, including VC&VS
            iad_desc: vec![],
            interfaces: vec![],
        })],
    })
});

#[allow(dead_code)]
impl UsbCamera {
    pub fn new(config: UsbCameraConfig) -> Self {
        UsbCamera {
            id: config.id.unwrap(),
            usb_device: UsbDevice::new(),
            frame: Vec::new(),
            max_pkt_size: 0,
            vs_eps: Vec::new(),
            backend_type: config.backend,
            backend_path: config.path.unwrap(),
            hostdev: None,
        }
    }

    pub fn realize(mut self) -> Result<Arc<Mutex<UsbCamera>>> {
        self.set_hostdev()?;

        self.usb_device.reset_usb_endpoint();
        self.usb_device.speed = USB_SPEED_HIGH;
        let s = UVC_CAMERA_STRINGS.iter().map(|&s| s.to_string()).collect();
        self.usb_device
            .init_descriptor(DESC_DEVICE_CAMERA.clone(), s)?;
        // TODO: add device qualifier table.
        let camera = Arc::new(Mutex::new(self));

        Ok(camera)
    }

    fn set_hostdev(&mut self) -> Result<()> {
        match self.backend_type {
            CamBackendType::V4l2 => {
                let mut hostdev = V4l2HostDev::new(self.backend_path.clone());
                hostdev.realize()?;
                self.hostdev = Some(Box::new(hostdev));
            }
            _ => {
                bail!("Unsupported backend yet.");
            }
        }

        Ok(())
    }

    fn read_backend_video_frame() -> Result<()> {
        Ok(())
    }

    fn send_video_frame_to_guest() -> Result<()> {
        Ok(())
    }

    fn set_control() -> Result<()> {
        Ok(())
    }
}

impl Default for UsbCamera {
    fn default() -> Self {
        Self::new(UsbCameraConfig::new())
    }
}

impl UsbDeviceOps for UsbCamera {
    fn reset(&mut self) {}

    fn handle_control(&mut self, packet: &mut UsbPacket, device_req: &UsbDeviceRequest) {
        debug!("Into camera handle_control");
        match self
            .usb_device
            .handle_control_for_descriptor(packet, device_req)
        {
            Ok(handled) => {
                if handled {
                    debug!("Camera control handled by descriptor, return directly.");
                } else {
                    error!("Camera: unhandled control msg: {}", device_req.request_type);
                }
            }
            Err(e) => {
                error!("Camera descriptor error {:?}", e);
                packet.status = UsbPacketStatus::Stall;
            }
        }
    }

    fn handle_data(&mut self, _p: &mut UsbPacket) {}

    fn device_id(&self) -> String {
        self.id.clone()
    }

    fn set_controller(&mut self, _ctrl: Weak<Mutex<XhciDevice>>) {}

    fn get_controller(&self) -> Option<Weak<Mutex<XhciDevice>>> {
        None
    }

    fn get_wakeup_endpoint(&self) -> &UsbEndpoint {
        self.usb_device.get_endpoint(true, 1)
    }

    fn get_usb_device(&self) -> &UsbDevice {
        &self.usb_device
    }

    fn get_mut_usb_device(&mut self) -> &mut UsbDevice {
        &mut self.usb_device
    }
}
