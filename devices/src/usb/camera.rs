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

const INTERFACE_ID_CONTROL: u8 = 0;
const INTERFACE_ID_STREAMING: u8 = 1;

const TERMINAL_ID_INPUT_TERMINAL: u8 = 1;
const TERMINAL_ID_OUTPUT_TERMINAL: u8 = 3;
const UNIT_ID_SELECTOR_UNIT: u8 = 4;
const UNIT_ID_PROCESSING_UNIT: u8 = 5;

const ENDPOINT_ID_CONTROL: u8 = 0x1;
const ENDPOINT_ID_STREAMING: u8 = 0x2;

// According to UVC specification 1.5
// A.2. Video Interface Subclass Codes
const SC_VIDEOCONTROL: u8 = 0x01;
const SC_VIDEOSTREAMING: u8 = 0x02;
const SC_VIDEO_INTERFACE_COLLECTION: u8 = 0x03;
// A.3. Video Interface Protocol Codes
const PC_PROTOCOL_UNDEFINED: u8 = 0x0;
const PC_PROTOCOL_15: u8 = 0x1;
// A.4. Video Class-Specific Descriptor Types
const CS_INTERFACE: u8 = 0x24;
// A.5. Video Class-Specific VC Interface Descriptor Subtypes
const VC_HEADER: u8 = 0x01;
const VC_INPUT_TERMINAL: u8 = 0x02;
const VC_OUTPUT_TERMINAL: u8 = 0x03;
const VC_SELECTOR_UNIT: u8 = 0x04;
const VC_PROCESSING_UNIT: u8 = 0x05;
// A.6 Video Class-Specific VS Interface Descriptor Subtypes
const VS_INPUT_HEADER: u8 = 0x01;
const VS_FORMAT_UNCOMPRESSED: u8 = 0x04;
const VS_FRAME_UNCOMPRESSED: u8 = 0x05;
const VS_COLORFORMAT: u8 = 0x0D;

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

static DESC_INTERFACE_CAMERA_VC: Lazy<Arc<UsbDescIface>> = Lazy::new(|| {
    // VideoControl Interface Descriptor
    Arc::new(UsbDescIface {
        interface_desc: UsbInterfaceDescriptor {
            bLength: 0x9,
            bDescriptorType: USB_DT_INTERFACE,
            bInterfaceNumber: INTERFACE_ID_CONTROL,
            bAlternateSetting: 0,
            bNumEndpoints: 1,
            bInterfaceClass: USB_CLASS_VIDEO,
            bInterfaceSubClass: SC_VIDEOCONTROL,
            bInterfaceProtocol: PC_PROTOCOL_15,
            iInterface: UsbCameraStringIDs::VideoControl as u8,
        },
        other_desc: vec![
            Arc::new(UsbDescOther {
                // Class-specific VS Interface Input Header Descriptor
                data: vec![
                    0xd,          // bLength
                    CS_INTERFACE, // bDescriptorType
                    VC_HEADER,    // bDescriptorSubtype
                    0x10,         // bcdADC
                    0x01,
                    0x3b, //wTotalLength
                    0x00,
                    0x80, //dwClockFrequency, 6MHz
                    0x8D,
                    0x5B,
                    0x00,
                    0x01, // bInCollection
                    0x01, // baInterfaceNr
                ],
            }),
            // Input Terminal Descriptor
            Arc::new(UsbDescOther {
                data: vec![
                    0x11,                       // bLength
                    CS_INTERFACE,               // bDescriptorType
                    VC_INPUT_TERMINAL,          // bDescriptorSubtype
                    TERMINAL_ID_INPUT_TERMINAL, // bTerminalID
                    0x01,                       // Fixme, wTerminalType, ITT_CAMERA, 0x0201
                    0x02,
                    0x00, // bAssocTerminal
                    UsbCameraStringIDs::InputTerminal as u8,
                    0x00, // wObjectiveFocalLengthMin
                    0x00,
                    0x00, // wObjectiveFocalLengthMax
                    0x00,
                    0x00, // wOcularFocalLength
                    0x00,
                    0x02, // bControlSize
                    0x00, // bmControls
                    0x00,
                ],
            }),
            // Output Terminal Descriptor
            Arc::new(UsbDescOther {
                data: vec![
                    0x09,                        // bLength
                    CS_INTERFACE,                // bDescriptorType
                    VC_OUTPUT_TERMINAL,          // bDescriptorSubtype
                    TERMINAL_ID_OUTPUT_TERMINAL, // bTerminalID
                    0x01,                        // wTerminalType, TT_STREAMING, 0x0101
                    0x01,
                    0x00,                                     // bAssocTerminal
                    UNIT_ID_PROCESSING_UNIT,                  // bSourceID
                    UsbCameraStringIDs::OutputTerminal as u8, // iTerminal
                ],
            }),
            // Selector Unit Descriptor
            Arc::new(UsbDescOther {
                data: vec![
                    0x07,                                 // bLength
                    CS_INTERFACE,                         //bDescriptorType
                    VC_SELECTOR_UNIT,                     //bDescriptorSubtype
                    UNIT_ID_SELECTOR_UNIT,                // bUnitID
                    0x01,                                 // bNrInPins
                    TERMINAL_ID_INPUT_TERMINAL,           // baSourceID(1)
                    UsbCameraStringIDs::SelectUnit as u8, // iSelector
                ],
            }),
            // Processing Unit Descriptor
            Arc::new(UsbDescOther {
                data: vec![
                    0x0d,                    // bLength
                    CS_INTERFACE,            // bDescriptorType
                    VC_PROCESSING_UNIT,      // bDescriptorSubtype
                    UNIT_ID_PROCESSING_UNIT, // bUnitID
                    UNIT_ID_SELECTOR_UNIT,   // bSourceID
                    0x00,                    // u16  wMaxMultiplier
                    0x00,
                    0x03, // bControlSize
                    0x00, // u24  bmControls
                    0x00,
                    0x00,
                    UsbCameraStringIDs::ProcessingUnit as u8, // iProcessing
                    0x00,                                     // bmVideoStandards
                ],
            }),
        ],
        endpoints: vec![Arc::new(UsbDescEndpoint {
            endpoint_desc: UsbEndpointDescriptor {
                bLength: USB_DT_ENDPOINT_SIZE,
                bDescriptorType: USB_DT_ENDPOINT,
                bEndpointAddress: USB_DIRECTION_DEVICE_TO_HOST | ENDPOINT_ID_CONTROL,
                bmAttributes: USB_ENDPOINT_ATTR_INT,
                wMaxPacketSize: 0x40,
                bInterval: 0x20,
            },
            extra: None,
        })],
    })
});

static DESC_INTERFACE_CAMERA_VS: Lazy<Arc<UsbDescIface>> = Lazy::new(|| {
    // VideoStreaming Interface Descriptor
    Arc::new(UsbDescIface {
        interface_desc: UsbInterfaceDescriptor {
            bLength: USB_DT_INTERFACE_SIZE,
            bDescriptorType: USB_DT_INTERFACE,
            bInterfaceNumber: INTERFACE_ID_STREAMING,
            bAlternateSetting: 0,
            bNumEndpoints: 1,
            bInterfaceClass: USB_CLASS_VIDEO,
            bInterfaceSubClass: SC_VIDEOSTREAMING,
            bInterfaceProtocol: PC_PROTOCOL_15,
            iInterface: UsbCameraStringIDs::VideoStreaming as u8,
        },
        other_desc: vec![
            // VC-Specific VS Video Input Header Descriptor
            Arc::new(UsbDescOther {
                data: vec![
                    0xf,             // bLength
                    CS_INTERFACE,    // bDescriptorType
                    VS_INPUT_HEADER, // bDescriptorSubtype
                    0x1,             // bNumFormats
                    0x4E,            //wTotalLength
                    0x00,
                    0x81,                                     // bEndpointAddress, EP 1 IN
                    0x00,                                     // bmInfo
                    UsbCameraStringIDs::OutputTerminal as u8, // bTerminalLink
                    0x00,                                     // bStillCaptureMethod
                    0x00,                                     // bTriggerSupport
                    0x00,                                     // bTriggerUsage
                    0x01,                                     // bControlSize
                    0x00,                                     // bmaControls(0)
                    0x00,                                     // bmaControls(1)
                ],
            }),
            // VS Uncompressed Format Type Descriptor
            Arc::new(UsbDescOther {
                data: vec![
                    0x1B,                   // bLength
                    CS_INTERFACE,           // bDescriptorType
                    VS_FORMAT_UNCOMPRESSED, //bDescriptorSubtype
                    0x01,                   // bFormatIndex
                    0x01,                   // bNumFrameDescriptors
                    0x59, // guidFormat  {32595559-0000-0010-8000-00AA00389B71} (YUY2)
                    0x55,
                    0x59,
                    0x32,
                    0x00,
                    0x00,
                    0x10,
                    0x00,
                    0x80,
                    0x00,
                    0x00,
                    0xaa,
                    0x00,
                    0x38,
                    0x9b,
                    0x71,
                    0x10, // bBitsPerPixel (16 bits per pixel)
                    0x01, // bDefaultFrameIndex (Index 1)
                    0x00, // bAspectRatioX
                    0x00, // bAspectRatioY
                    0x00, // bmInterlaceFlags
                    0x00, // bCopyProtect
                ],
            }),
            // VS Uncompressed Frame Type Descriptor
            Arc::new(UsbDescOther {
                data: vec![
                    0x1E,                  // bLength
                    CS_INTERFACE,          // bDescriptorType
                    VS_FRAME_UNCOMPRESSED, // bDescriptorSubtype
                    0x01,                  // bFrameIndex
                    0x00,                  // bmCapabilities (Still image unsupported)
                    0x00,                  // wWidth, 1280
                    0x05,                  //
                    0xD0,                  // wHeight, 720
                    0x02,                  //
                    0x00,                  // dwMinBitRate, (147456000 bps -> 18.432 MB/s)
                    0x00,                  //
                    0xCA,                  //
                    0x08,                  //
                    0x00,                  // dwMaxBitRate, (147456000 bps -> 18.432 MB/s)
                    0x00,                  //
                    0xCA,                  //
                    0x08,                  //
                    0x00,                  // dwMaxVideoFrameBufferSize,  (1843200 bytes)
                    0x20,                  //
                    0x1C,                  //
                    0x00,                  //
                    0x40,                  // dwDefaultFrameInterval, (100.0000 ms -> 10.0000 fps)
                    0x42,                  //
                    0x0F,                  //
                    0x00,                  //
                    0x01, // bFrameIntervalType, (1 discrete frame interval supported)
                    0x40, // adwFrameInterval，(100.0000 ms -> 10.0000 fps)
                    0x42, //
                    0x0F, //
                    0x00, //
                ],
            }),
            // VS Color Matching Descriptor Descriptor
            Arc::new(UsbDescOther {
                data: vec![
                    0x06,           // bLength
                    CS_INTERFACE,   // bDescriptorType
                    VS_COLORFORMAT, // bDescriptorSubtype
                    0x01,           // bColorPrimaries (BT.709,sRGB)
                    0x01,           // bTransferCharacteristics (BT.709)
                    0x04,           // bMatrixCoefficients (SMPTE 170M (BT.601))
                ],
            }),
        ],
        endpoints: vec![Arc::new(UsbDescEndpoint {
            endpoint_desc: UsbEndpointDescriptor {
                bLength: USB_DT_ENDPOINT_SIZE,
                bDescriptorType: USB_DT_ENDPOINT,
                bEndpointAddress: USB_DIRECTION_DEVICE_TO_HOST | ENDPOINT_ID_STREAMING,
                bmAttributes: USB_ENDPOINT_ATTR_BULK,
                wMaxPacketSize: 0x400,
                bInterval: 0x20,
            },
            extra: None,
        })],
    })
});

static DESC_IAD_CAMERA: Lazy<Arc<UsbDescIAD>> = Lazy::new(|| {
    Arc::new(UsbDescIAD {
        iad_desc: UsbIadDescriptor {
            bLength: 0x8,
            bDescriptorType: USB_DT_INTERFACE_ASSOCIATION,
            bFirstInterface: INTERFACE_ID_CONTROL,
            bInterfaceCount: 2,
            bFunctionClass: USB_CLASS_VIDEO,
            bFunctionSubClass: SC_VIDEO_INTERFACE_COLLECTION,
            bFunctionProtocol: PC_PROTOCOL_UNDEFINED,
            iFunction: UsbCameraStringIDs::Iad as u8,
        },
        itfs: vec![
            DESC_INTERFACE_CAMERA_VC.clone(),
            DESC_INTERFACE_CAMERA_VS.clone(),
        ],
    })
});

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
            iad_desc: vec![DESC_IAD_CAMERA.clone()],
            interfaces: vec![],
        })],
    })
});

static DESC_DEVICE_QUALIFIER_CAMERA: Lazy<Arc<UsbDescDeviceQualifier>> = Lazy::new(|| {
    Arc::new(UsbDescDeviceQualifier {
        qualifier_desc: UsbDeviceQualifierDescriptor {
            bLength: 0xa,
            bDescriptorType: USB_DT_DEVICE_QUALIFIER,
            bcdUSB: DESC_DEVICE_CAMERA.device_desc.bcdUSB,
            bDeviceClass: DESC_DEVICE_CAMERA.device_desc.bDeviceClass,
            bDeviceSubClass: DESC_DEVICE_CAMERA.device_desc.bDeviceSubClass,
            bDeviceProtocol: DESC_DEVICE_CAMERA.device_desc.bDeviceProtocol,
            bMaxPacketSize0: DESC_DEVICE_CAMERA.device_desc.bMaxPacketSize0,
            bNumConfigurations: DESC_DEVICE_CAMERA.device_desc.bNumConfigurations,
            bReserved: 0,
        },
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
        self.usb_device
            .init_device_qualifier_descriptor(DESC_DEVICE_QUALIFIER_CAMERA.clone())?;
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
