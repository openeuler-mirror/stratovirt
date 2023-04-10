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

use std::collections::LinkedList;
use std::os::unix::prelude::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use anyhow::{bail, Context, Result};
use log::{debug, error, info};
use strum::EnumCount;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use machine_manager::config::{CamBackendType, ConfigError, UsbCameraConfig};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use util::aio::{iov_discard_front_direct, Iovec};
use util::byte_code::ByteCode;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};

use super::camera_media_type_guid::MEDIA_TYPE_GUID_HASHMAP;
use super::xhci::xhci_controller::XhciDevice;
use crate::camera_backend::{
    v4l2::V4l2CameraBackend, CamBasicFmt, CameraBrokenCallback, CameraHostdevOps,
    CameraNotifyCallback,
};
use crate::camera_backend::{CameraFormatList, CameraFrame, FmtType};
use crate::usb::config::*;
use crate::usb::descriptor::*;
use crate::usb::{
    UsbDevice, UsbDeviceOps, UsbDeviceRequest, UsbEndpoint, UsbPacket, UsbPacketStatus,
};

// CRC16 of "STRATOVIRT"
const UVC_VENDOR_ID: u16 = 0xB74C;
// The first 4 chars of "VIDEO", 5 substitutes V.
const UVC_PRODUCT_ID: u16 = 0x51DE;

const INTERFACE_ID_CONTROL: u8 = 0;
const INTERFACE_ID_STREAMING: u8 = 1;

const TERMINAL_ID_INPUT_TERMINAL: u8 = 1;
const TERMINAL_ID_OUTPUT_TERMINAL: u8 = 2;

const ENDPOINT_ID_STREAMING: u8 = 0x1;
const VS_INTERFACE_NUM: u8 = 1;

// According to UVC specification 1.5
// A.2. Video Interface Subclass Codes
const SC_VIDEOCONTROL: u8 = 0x01;
const SC_VIDEOSTREAMING: u8 = 0x02;
const SC_VIDEO_INTERFACE_COLLECTION: u8 = 0x03;
// A.3. Video Interface Protocol Codes
const PC_PROTOCOL_UNDEFINED: u8 = 0x0;
// A.4. Video Class-Specific Descriptor Types
const CS_INTERFACE: u8 = 0x24;
// A.5. Video Class-Specific VC Interface Descriptor Subtypes
const VC_HEADER: u8 = 0x01;
const VC_INPUT_TERMINAL: u8 = 0x02;
const VC_OUTPUT_TERMINAL: u8 = 0x03;
// A.6 Video Class-Specific VS Interface Descriptor Subtypes
const VS_INPUT_HEADER: u8 = 0x01;
const VS_FORMAT_UNCOMPRESSED: u8 = 0x04;
const VS_FRAME_UNCOMPRESSED: u8 = 0x05;
const VS_FORMAT_MJPEG: u8 = 0x06;
const VS_FRAME_MJPEG: u8 = 0x07;
const VS_COLORFORMAT: u8 = 0x0D;
// A.8. Video Class-Specific Request Codes
const SET_CUR: u8 = 0x1;
const GET_CUR: u8 = 0x81;
const GET_MIN: u8 = 0x82;
const GET_MAX: u8 = 0x83;
const GET_INFO: u8 = 0x86;
const GET_DEF: u8 = 0x87;
const UVC_FID: u8 = 1;
// A.9.8. VideoStreaming Interface Control Selectors
const VS_PROBE_CONTROL: u8 = 1;
const VS_COMMIT_CONTROL: u8 = 2;

const MAX_PAYLOAD: u32 = 1024 * 3 - 2;
const FPS_30_INTERVAL: u32 = 333333;
const FRAME_SIZE_1280_720: u32 = 1280 * 720 * 2;

pub struct UsbCamera {
    id: String,                                                 // uniq device id
    usb_device: UsbDevice,                                      // general usb device object
    vs_control: VideoStreamingControl,                          // video stream control info
    camera_fd: Arc<EventFd>,                                    // camera io fd
    camera_dev: Arc<Mutex<dyn CameraHostdevOps>>,               // backend device
    packet_list: Arc<Mutex<LinkedList<Arc<Mutex<UsbPacket>>>>>, // packet to be processed
    payload: Arc<Mutex<UvcPayload>>,                            // uvc payload
    listening: bool,                                            // if the camera is listening or not
    broken: Arc<AtomicBool>,                                    // if the device broken or not
    iothread: Option<String>,
    delete_evts: Vec<RawFd>,
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

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct VCHeaderDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bDescriptorSubType: u8,
    pub bcdUVC: u16,
    pub wTotalLength: u16,
    pub dwClockFrequency: u32,
    pub bInCollection: u8,
    pub baInterfaceNr: u8,
}

impl ByteCode for VCHeaderDescriptor {}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct InputTerminalDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bDescriptorSubType: u8,
    pub bTerminalID: u8,
    pub wTerminalType: u16,
    pub bAssocTerminal: u8,
    pub iTerminal: u8,
    pub wObjectiveFocalLengthMin: u16,
    pub wObjectiveFocalLengthMax: u16,
    pub wOcularFocalLength: u16,
    pub bControlSize: u8,
    pub bmControls: [u8; 3],
}

impl ByteCode for InputTerminalDescriptor {}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct OutputTerminalDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bDescriptorSubType: u8,
    pub bTerminalID: u8,
    pub wTerminalType: u16,
    pub bAssocTerminal: u8,
    pub bSourceID: u8,
    pub iTerminal: u8,
}

impl ByteCode for OutputTerminalDescriptor {}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct VSInputHeaderDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bDescriptorSubType: u8,
    pub bNumFormats: u8,
    pub wTotalLength: u16,
    pub bEndpointAddress: u8,
    pub bmInfo: u8,
    pub bTerminalLink: u8,
    pub bStillCaptureMethod: u8,
    pub bTriggerSupport: u8,
    pub bTriggerUsage: u8,
    pub bControlSize: u8,
    pub bmaControls: [u8; 2],
}

impl ByteCode for VSInputHeaderDescriptor {}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct MjpgFormatDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bDescriptorSubType: u8,
    pub bFormatIndex: u8,
    pub bNumFrameDescriptors: u8,
    pub bmFlags: u8,
    pub bDefaultFrameIndex: u8,
    pub bAspectRatioX: u8,
    pub bAspectRatioY: u8,
    pub bmInterfaceFlags: u8,
    pub bCopyProtect: u8,
}

impl ByteCode for MjpgFormatDescriptor {}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct MjpgFrameDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bDescriptorSubType: u8,
    pub bFrameIndex: u8,
    pub bmCapabilities: u8,
    pub wWidth: u16,
    pub wHeight: u16,
    pub dwMinBitRate: u32,
    pub dwMaxBitRate: u32,
    pub dwMaxVideoFrameBufferSize: u32,
    pub dwDefaultFrameInterval: u32,
    pub bFrameIntervalType: u8,
    pub dwFrameInterval: u32,
}

impl ByteCode for MjpgFrameDescriptor {}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct ColorMatchingDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bDescriptorSubType: u8,
    pub bColorPrimaries: u8,
    pub bTransferCharacteristics: u8,
    pub bMatrixCoefficients: u8,
}

impl ByteCode for ColorMatchingDescriptor {}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct UncompressedFormatDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bDescriptorSubType: u8,
    pub bFormatIndex: u8,
    pub bNumFrameDescriptors: u8,
    pub guidFormat: [u8; 16],
    pub bBitsPerPixel: u8,
    pub bDefaultFrameIndex: u8,
    pub bAspectRatioX: u8,
    pub bAspectRatioY: u8,
    pub bmInterfaceFlags: u8,
    pub bCopyProtect: u8,
}

impl ByteCode for UncompressedFormatDescriptor {}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct UncompressedFrameDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bDescriptorSubType: u8,
    pub bFrameIndex: u8,
    pub bmCapabilities: u8,
    pub wWidth: u16,
    pub wHeight: u16,
    pub dwMinBitRate: u32,
    pub dwMaxBitRate: u32,
    pub dwMaxVideoFrameBufferSize: u32,
    pub dwDefaultFrameInterval: u32,
    pub bFrameIntervalType: u8,
    pub dwFrameInterval: u32,
}

impl ByteCode for UncompressedFrameDescriptor {}

fn gen_desc_interface_camera_vc() -> Result<Arc<UsbDescIface>> {
    // VideoControl Interface Descriptor
    let desc = Arc::new(UsbDescIface {
        interface_desc: UsbInterfaceDescriptor {
            bLength: USB_DT_INTERFACE_SIZE,
            bDescriptorType: USB_DT_INTERFACE,
            bInterfaceNumber: INTERFACE_ID_CONTROL,
            bAlternateSetting: 0,
            bNumEndpoints: 0,
            bInterfaceClass: USB_CLASS_VIDEO,
            bInterfaceSubClass: SC_VIDEOCONTROL,
            bInterfaceProtocol: 0,
            iInterface: UsbCameraStringIDs::VideoControl as u8,
        },
        other_desc: vec![
            Arc::new(UsbDescOther {
                data: VCHeaderDescriptor {
                    bLength: 0x0d,
                    bDescriptorType: CS_INTERFACE,
                    bDescriptorSubType: VC_HEADER,
                    bcdUVC: 0x100,
                    wTotalLength: 40,
                    dwClockFrequency: 0x02dc6c00,
                    bInCollection: 0x1,
                    baInterfaceNr: 0x1,
                }
                .as_bytes()
                .to_vec(),
            }),
            // Input Terminal Descriptor
            Arc::new(UsbDescOther {
                data: InputTerminalDescriptor {
                    bLength: 0x12,
                    bDescriptorType: CS_INTERFACE,
                    bDescriptorSubType: VC_INPUT_TERMINAL,
                    bTerminalID: TERMINAL_ID_INPUT_TERMINAL,
                    wTerminalType: 0x0201,
                    bAssocTerminal: 0,
                    iTerminal: UsbCameraStringIDs::InputTerminal as u8,
                    wObjectiveFocalLengthMin: 0,
                    wObjectiveFocalLengthMax: 0,
                    wOcularFocalLength: 0,
                    bControlSize: 0x3,
                    bmControls: [0; 3],
                }
                .as_bytes()
                .to_vec(),
            }),
            // Output Terminal Descriptor
            Arc::new(UsbDescOther {
                data: OutputTerminalDescriptor {
                    bLength: 0x9,
                    bDescriptorType: CS_INTERFACE,
                    bDescriptorSubType: VC_OUTPUT_TERMINAL,
                    bTerminalID: TERMINAL_ID_OUTPUT_TERMINAL,
                    wTerminalType: 0x0101,
                    bAssocTerminal: 0,
                    bSourceID: 1,
                    iTerminal: UsbCameraStringIDs::OutputTerminal as u8,
                }
                .as_bytes()
                .to_vec(),
            }),
        ],
        endpoints: vec![],
    });

    Ok(desc)
}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VsDescInputHeader {
    bLength: u8,
    bDescriptorType: u8,
    bDescriptorSubtype: u8,
    bNumFormats: u8,
    wTotalLength: u16,
    bEndpointAddress: u8,
    bmInfo: u8,
    bTerminalLink: u8,
    bStillCaptureMethod: u8,
    bTriggerSupport: u8,
    bTriggerUsage: u8,
    bControlSize: u8,
    bmaControls: u16,
}

impl ByteCode for VsDescInputHeader {}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VsDescUncompressedFmt {
    bLength: u8,
    bDescriptorType: u8,
    bDescriptorSubtype: u8,
    bFormatIndex: u8,
    bNumFrameDescriptors: u8,
    guidFormat: [u8; 16],
    bBitsPerPixel: u8,
    bDefaultFrameIndex: u8,
    bAspectRatioX: u8,
    bAspectRatioY: u8,
    bmInterlaceFlags: u8,
    bCopyProtect: u8,
}

impl ByteCode for VsDescUncompressedFmt {}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VsDescMjpgFmt {
    bLength: u8,
    bDescriptorType: u8,
    bDescriptorSubtype: u8,
    bFormatIndex: u8,
    bNumFrameDescriptors: u8,
    bmFlags: u8,
    bDefaultFrameIndex: u8,
    bAspectRatioX: u8,
    bAspectRatioY: u8,
    bmInterlaceFlags: u8,
    bCopyProtect: u8,
}

impl ByteCode for VsDescMjpgFmt {}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VsDescFrm {
    bLength: u8,
    bDescriptorType: u8,
    bDescriptorSubtype: u8,
    bFrameIndex: u8,
    bmCapabilities: u8,
    wWidth: u16,
    wHeight: u16,
    dwMinBitRate: u32,
    dwMaxBitRate: u32,
    dwMaxVideoFrameBufSize: u32,
    dwDefaultFrameInterval: u32,
    bFrameIntervalType: u8,
    dwIntervalVals: u32,
}

impl ByteCode for VsDescFrm {}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VsDescColorMatching {
    bLength: u8,
    bDescriptorType: u8,
    bDescriptorSubtype: u8,
    bColorPrimaries: u8,
    bTransferCharacteristics: u8,
    bMatrixCoefficients: u8,
}

impl ByteCode for VsDescColorMatching {}

fn gen_desc_interface_camera_vs(fmt_list: Vec<CameraFormatList>) -> Result<Arc<UsbDescIface>> {
    let desc = Arc::new(UsbDescIface {
        interface_desc: UsbInterfaceDescriptor {
            bLength: USB_DT_INTERFACE_SIZE,
            bDescriptorType: USB_DT_INTERFACE,
            bInterfaceNumber: INTERFACE_ID_STREAMING,
            bAlternateSetting: 0,
            bNumEndpoints: 1,
            bInterfaceClass: USB_CLASS_VIDEO,
            bInterfaceSubClass: SC_VIDEOSTREAMING,
            bInterfaceProtocol: 0,
            iInterface: UsbCameraStringIDs::VideoStreaming as u8,
        },
        other_desc: gen_fmt_desc(fmt_list)?,
        endpoints: vec![Arc::new(UsbDescEndpoint {
            endpoint_desc: UsbEndpointDescriptor {
                bLength: USB_DT_ENDPOINT_SIZE,
                bDescriptorType: USB_DT_ENDPOINT,
                bEndpointAddress: USB_DIRECTION_DEVICE_TO_HOST | ENDPOINT_ID_STREAMING,
                bmAttributes: USB_ENDPOINT_ATTR_BULK,
                wMaxPacketSize: 0x400,
                bInterval: 0x0,
            },
            extra: UsbSuperSpeedEndpointCompDescriptor {
                bLength: USB_DT_SS_EP_COMP_SIZE,
                bDescriptorType: USB_DT_ENDPOINT_COMPANION,
                bMaxBurst: 0,
                bmAttributes: 0,
                wBytesPerInterval: 0,
            }
            .as_bytes()
            .to_vec(),
        })],
    });

    Ok(desc)
}

fn gen_desc_iad_camera(fmt_list: Vec<CameraFormatList>) -> Result<Arc<UsbDescIAD>> {
    let desc = Arc::new(UsbDescIAD {
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
            gen_desc_interface_camera_vc()?,
            gen_desc_interface_camera_vs(fmt_list)?,
        ],
    });

    Ok(desc)
}

/// UVC Camera device descriptor
fn gen_desc_device_camera(fmt_list: Vec<CameraFormatList>) -> Result<Arc<UsbDescDevice>> {
    let desc = Arc::new(UsbDescDevice {
        device_desc: UsbDeviceDescriptor {
            bLength: USB_DT_DEVICE_SIZE,
            bDescriptorType: USB_DT_DEVICE,
            idVendor: UVC_VENDOR_ID,
            idProduct: UVC_PRODUCT_ID,
            bcdDevice: 0,
            iManufacturer: UsbCameraStringIDs::Manufacture as u8,
            iProduct: UsbCameraStringIDs::Product as u8,
            iSerialNumber: UsbCameraStringIDs::SerialNumber as u8,
            bcdUSB: 0x0300,
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
            iad_desc: vec![gen_desc_iad_camera(fmt_list)?],
            interfaces: vec![],
        })],
    });

    Ok(desc)
}

#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct VideoStreamingControl {
    pub bmHint: u16,
    pub bFormatIndex: u8,
    pub bFrameIndex: u8,
    pub dwFrameInterval: u32,
    pub wKeyFrameRate: u16,
    pub wPFrameRate: u16,
    pub wCompQuality: u16,
    pub wCompWindowSize: u16,
    pub wDelay: u16,
    pub dwMaxVideoFrameSize: u32,
    pub dwMaxPayloadTransferSize: u32,
}

impl ByteCode for VideoStreamingControl {}

impl VideoStreamingControl {
    fn reset(&mut self) {
        self.bFormatIndex = 1;
        self.bFormatIndex = 2;
        self.dwFrameInterval = FPS_30_INTERVAL;
        self.dwMaxVideoFrameSize = FRAME_SIZE_1280_720;
        self.dwMaxPayloadTransferSize = MAX_PAYLOAD;
    }
}

impl UsbCamera {
    pub fn new(config: UsbCameraConfig) -> Result<Self> {
        let cam = match config.backend {
            CamBackendType::V4l2 => V4l2CameraBackend::new(
                config.id.clone().unwrap(),
                config.path.clone().with_context(|| {
                    ConfigError::FieldIsMissing("path".to_string(), "V4L2".to_string())
                })?,
                config.iothread.clone(),
            )?,
            CamBackendType::Demo => bail!("Not supported type"),
        };
        let camera = Arc::new(Mutex::new(cam));
        Ok(Self {
            id: config.id.unwrap(),
            usb_device: UsbDevice::new(),
            vs_control: VideoStreamingControl::default(),
            camera_fd: Arc::new(EventFd::new(libc::EFD_NONBLOCK)?),
            camera_dev: camera,
            packet_list: Arc::new(Mutex::new(LinkedList::new())),
            payload: Arc::new(Mutex::new(UvcPayload::new())),
            listening: false,
            broken: Arc::new(AtomicBool::new(false)),
            iothread: config.iothread,
            delete_evts: Vec::new(),
        })
    }

    fn register_cb(&mut self) {
        let clone_fd = self.camera_fd.clone();
        let notify_cb: CameraNotifyCallback = Arc::new(move || {
            if let Err(e) = clone_fd.write(1) {
                error!(
                    "Failed to write camera device fd {} {:?}",
                    clone_fd.as_raw_fd(),
                    e
                );
            }
        });
        let clone_broken = self.broken.clone();
        let clone_id = self.id.clone();
        let broken_cb: CameraBrokenCallback = Arc::new(move || {
            clone_broken.store(true, Ordering::SeqCst);
            error!("USB Camera {} device broken", clone_id);
        });
        let mut locked_camera = self.camera_dev.lock().unwrap();
        locked_camera.register_notify_cb(notify_cb);
        locked_camera.register_broken_cb(broken_cb);
    }

    fn activate(&mut self, fmt: &CamBasicFmt) -> Result<()> {
        info!("USB Camera {} activate", self.id);
        self.camera_dev.lock().unwrap().reset();
        self.payload.lock().unwrap().reset();
        let mut locked_camera = self.camera_dev.lock().unwrap();
        locked_camera.set_fmt(fmt)?;
        locked_camera.video_stream_on()?;
        drop(locked_camera);
        self.register_camera_fd()?;
        Ok(())
    }

    fn register_camera_fd(&mut self) -> Result<()> {
        if self.listening {
            return Ok(());
        }
        let cam_handler = Arc::new(Mutex::new(CameraIoHander::new(
            &self.camera_fd,
            &self.packet_list,
            &self.camera_dev,
            &self.payload,
        )));
        register_event_helper(
            EventNotifierHelper::internal_notifiers(cam_handler),
            self.iothread.as_ref(),
            &mut self.delete_evts,
        )?;
        self.listening = true;
        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        info!("USB Camera {} deactivate", self.id);
        if self.broken.load(Ordering::Acquire) {
            info!("USB Camera {} broken when deactivate, reset it.", self.id);
            self.camera_dev.lock().unwrap().reset();
            self.broken.store(false, Ordering::SeqCst);
        } else {
            self.camera_dev.lock().unwrap().video_stream_off()?;
        }
        self.unregister_camera_fd()?;
        self.packet_list.lock().unwrap().clear();
        Ok(())
    }

    fn unregister_camera_fd(&mut self) -> Result<()> {
        if !self.listening {
            return Ok(());
        }
        unregister_event_helper(self.iothread.as_ref(), &mut self.delete_evts)?;
        self.listening = false;
        Ok(())
    }

    fn handle_uvc_request(
        &mut self,
        packet: &mut UsbPacket,
        device_req: &UsbDeviceRequest,
    ) -> Result<()> {
        let inter_num = (device_req.index & 0xff) as u8;
        match device_req.request_type {
            USB_INTERFACE_IN_REQUEST => {
                if device_req.request == USB_REQUEST_GET_STATUS {
                    self.usb_device.data_buf[0] = 0;
                    self.usb_device.data_buf[1] = 0;
                    packet.actual_length = 2;
                    return Ok(());
                }
            }
            USB_INTERFACE_OUT_REQUEST => {
                if device_req.request == USB_REQUEST_SET_FEATURE {
                    return Ok(());
                }
            }
            USB_INTERFACE_CLASS_IN_REQUEST => {
                if inter_num == VS_INTERFACE_NUM {
                    return self.do_vs_interface_in_request(packet, device_req);
                }
            }
            USB_INTERFACE_CLASS_OUT_REQUEST => {
                if inter_num == VS_INTERFACE_NUM {
                    return self.do_vs_interface_out_request(device_req);
                }
            }
            USB_ENDPOINT_OUT_REQUEST => {
                if device_req.request == USB_REQUEST_CLEAR_FEATURE {
                    return self
                        .deactivate()
                        .with_context(|| "Failed to deactivate device");
                }
            }
            _ => (),
        }
        bail!("Unknown UVC request {:?}", device_req.request);
    }

    fn do_vs_interface_in_request(
        &mut self,
        packet: &mut UsbPacket,
        device_req: &UsbDeviceRequest,
    ) -> Result<()> {
        match device_req.request {
            GET_INFO => {
                self.usb_device.data_buf[0] = 1 | 2;
                packet.actual_length = 1;
            }
            GET_CUR | GET_MIN | GET_MAX | GET_DEF => {
                self.video_stream_in_request(packet, device_req)?;
            }
            _ => {
                bail!(
                    "Unsupported VS interface in request {:?}",
                    device_req.request
                );
            }
        }
        Ok(())
    }

    fn video_stream_in_request(
        &mut self,
        packet: &mut UsbPacket,
        device_req: &UsbDeviceRequest,
    ) -> Result<()> {
        let cs = (device_req.value >> 8) as u8;
        if cs != VS_PROBE_CONTROL {
            bail!("Invalid VS Control Selector {}", cs);
        }
        let len = self.vs_control.as_bytes().len();
        self.usb_device.data_buf[0..len].copy_from_slice(self.vs_control.as_bytes());
        packet.actual_length = len as u32;
        Ok(())
    }

    fn do_vs_interface_out_request(&mut self, device_req: &UsbDeviceRequest) -> Result<()> {
        let mut vs_control = VideoStreamingControl::default();
        let len = vs_control.as_mut_bytes().len();
        vs_control
            .as_mut_bytes()
            .copy_from_slice(&self.usb_device.data_buf[0..len]);
        let cs = (device_req.value >> 8) as u8;
        debug!("VideoStreamingControl {} {:?}", cs, vs_control);
        match device_req.request {
            SET_CUR => match cs {
                VS_PROBE_CONTROL => {
                    self.vs_control.bFormatIndex = vs_control.bFormatIndex;
                    self.vs_control.bFrameIndex = vs_control.bFrameIndex;
                    self.vs_control.dwMaxVideoFrameSize = vs_control.dwMaxVideoFrameSize;
                    self.vs_control.dwFrameInterval = vs_control.dwFrameInterval;
                }
                VS_COMMIT_CONTROL => {
                    self.vs_control.bFormatIndex = vs_control.bFormatIndex;
                    self.vs_control.bFrameIndex = vs_control.bFrameIndex;
                    self.vs_control.dwMaxVideoFrameSize = vs_control.dwMaxVideoFrameSize;
                    self.vs_control.dwFrameInterval = vs_control.dwFrameInterval;
                    let fmt = self
                        .camera_dev
                        .lock()
                        .unwrap()
                        .get_format_by_index(vs_control.bFormatIndex, vs_control.bFrameIndex)?;

                    self.activate(&fmt)
                        .with_context(|| "Failed to activate device")?;
                }
                _ => {
                    bail!("Invalid VS control selector {}", cs);
                }
            },
            _ => {
                bail!("Unsupported VS interface out request {:?}", device_req);
            }
        }
        Ok(())
    }
}

impl UsbDeviceOps for UsbCamera {
    fn realize(mut self) -> Result<Arc<Mutex<dyn UsbDeviceOps>>> {
        self.camera_dev.lock().unwrap().list_format()?;
        let fmt_list = self.camera_dev.lock().unwrap().get_fmt()?;

        self.usb_device.reset_usb_endpoint();
        self.usb_device.speed = USB_SPEED_SUPER;
        let s = UVC_CAMERA_STRINGS.iter().map(|&s| s.to_string()).collect();
        let device_desc = gen_desc_device_camera(fmt_list)?;
        self.usb_device.init_descriptor(device_desc, s)?;
        self.register_cb();

        let camera = Arc::new(Mutex::new(self));
        Ok(camera)
    }

    fn unrealize(&mut self) -> Result<()> {
        info!("Camera {} unrealize", self.id);
        self.camera_dev.lock().unwrap().reset();
        Ok(())
    }

    fn reset(&mut self) {
        info!("Camera {} device reset", self.id);
        self.usb_device.addr = 0;
        if let Err(e) = self.unregister_camera_fd() {
            error!("Failed to unregister fd when reset {:?}", e);
        }
        self.vs_control.reset();
        self.payload.lock().unwrap().reset();
        self.camera_dev.lock().unwrap().reset();
        self.packet_list.lock().unwrap().clear();
        self.broken.store(false, Ordering::SeqCst);
    }

    fn handle_control(&mut self, packet: &Arc<Mutex<UsbPacket>>, device_req: &UsbDeviceRequest) {
        let mut locked_packet = packet.lock().unwrap();
        match self
            .usb_device
            .handle_control_for_descriptor(&mut locked_packet, device_req)
        {
            Ok(handled) => {
                if handled {
                    debug!("Camera control handled by descriptor, return directly.");
                    return;
                }
            }
            Err(e) => {
                error!("Camera descriptor error {:?}", e);
                locked_packet.status = UsbPacketStatus::Stall;
                return;
            }
        }

        if let Err(e) = self.handle_uvc_request(&mut locked_packet, device_req) {
            error!("Camera uvc descriptor error {:?}", e);
            locked_packet.status = UsbPacketStatus::Stall;
        }
    }

    fn handle_data(&mut self, packet: &Arc<Mutex<UsbPacket>>) {
        if packet.lock().unwrap().ep_number == ENDPOINT_ID_STREAMING {
            packet.lock().unwrap().is_async = true;
            let mut locked_list = self.packet_list.lock().unwrap();
            locked_list.push_back(packet.clone());
            // Notify the camera to deal with the request.
            if let Err(e) = self.camera_fd.write(1) {
                error!(
                    "Failed to write fd when handle data for {} {:?}",
                    self.id, e
                );
                // SAFETY: packet is push before, and no other thread modify the list.
                let p = locked_list.pop_back().unwrap();
                let mut locked_p = p.lock().unwrap();
                locked_p.status = UsbPacketStatus::Stall;
                // Async request failed, let controller report the error.
                locked_p.is_async = false;
            }
        } else {
            error!("Invalid ep number {}", packet.lock().unwrap().ep_number);
            packet.lock().unwrap().status = UsbPacketStatus::Stall;
        }
    }

    fn device_id(&self) -> String {
        self.id.clone()
    }

    fn set_controller(&mut self, _cntlr: Weak<Mutex<XhciDevice>>) {}

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

/// UVC payload
struct UvcPayload {
    header: Vec<u8>,
    frame_offset: usize,
    payload_offset: usize,
}

impl UvcPayload {
    fn new() -> Self {
        Self {
            header: vec![2, 0],
            frame_offset: 0,
            payload_offset: 0,
        }
    }

    fn reset(&mut self) {
        self.header[0] = 2;
        self.header[1] = 0;
        self.frame_offset = 0;
        self.payload_offset = 0;
    }

    fn get_frame_data_size(&self, current_frame_size: usize, iov_size: u64) -> Result<u64> {
        let mut frame_data_size = iov_size;
        let header_len = self.header.len();
        // Within the scope of the frame.
        if self.frame_offset + frame_data_size as usize >= current_frame_size {
            if self.frame_offset > current_frame_size {
                bail!(
                    "Invalid frame offset {} {}",
                    self.frame_offset,
                    current_frame_size
                );
            }
            frame_data_size = (current_frame_size - self.frame_offset) as u64;
        }
        // Within the scope of the payload.
        if self.payload_offset + frame_data_size as usize >= MAX_PAYLOAD as usize {
            if self.payload_offset > MAX_PAYLOAD as usize {
                bail!(
                    "Invalid payload offset {} {}",
                    self.payload_offset,
                    MAX_PAYLOAD
                );
            }
            frame_data_size = MAX_PAYLOAD as u64 - self.payload_offset as u64;
        }
        // payload start, reserve the header.
        if self.payload_offset == 0 && frame_data_size + header_len as u64 > iov_size {
            if iov_size <= header_len as u64 {
                bail!("Invalid iov size {}", iov_size);
            }
            frame_data_size = iov_size as u64 - header_len as u64;
        }
        Ok(frame_data_size)
    }

    fn next_frame(&mut self) {
        self.frame_offset = 0;
        self.payload_offset = 0;
        self.header[1] ^= UVC_FID;
    }
}

/// Camere handler for copying frame data to usb packet.
struct CameraIoHander {
    camera: Arc<Mutex<dyn CameraHostdevOps>>,
    fd: Arc<EventFd>,
    packet_list: Arc<Mutex<LinkedList<Arc<Mutex<UsbPacket>>>>>,
    payload: Arc<Mutex<UvcPayload>>,
}

impl CameraIoHander {
    fn new(
        fd: &Arc<EventFd>,
        list: &Arc<Mutex<LinkedList<Arc<Mutex<UsbPacket>>>>>,
        camera: &Arc<Mutex<dyn CameraHostdevOps>>,
        payload: &Arc<Mutex<UvcPayload>>,
    ) -> Self {
        CameraIoHander {
            camera: camera.clone(),
            fd: fd.clone(),
            packet_list: list.clone(),
            payload: payload.clone(),
        }
    }

    fn handle_io(&mut self) {
        const REQUEST_LIMIT: u32 = 100;
        for _ in 0..REQUEST_LIMIT {
            let len = self.camera.lock().unwrap().get_frame_size();
            if len == 0 {
                break;
            }
            let mut locked_list = self.packet_list.lock().unwrap();
            if locked_list.is_empty() {
                break;
            }
            // SAFETY: packet list is not empty.
            let p = locked_list.pop_front().unwrap();
            drop(locked_list);
            let mut locked_p = p.lock().unwrap();
            if let Err(e) = self.handle_payload(&mut locked_p) {
                error!("Failed handle uvc data {:?}", e);
                locked_p.status = UsbPacketStatus::IoError;
            }
            if let Some(transfer) = locked_p.xfer_ops.as_ref() {
                if let Some(ops) = transfer.clone().upgrade() {
                    drop(locked_p);
                    ops.lock().unwrap().submit_transfer();
                }
            }
        }
    }

    fn handle_payload(&mut self, pkt: &mut UsbPacket) -> Result<()> {
        let mut locked_camera = self.camera.lock().unwrap();
        let current_frame_size = locked_camera.get_frame_size();
        let mut locked_payload = self.payload.lock().unwrap();
        let header_len = locked_payload.header.len();
        let pkt_size = pkt.get_iovecs_size();
        let frame_data_size = locked_payload.get_frame_data_size(current_frame_size, pkt_size)?;
        if frame_data_size == 0 {
            bail!(
                "Invalid frame data size, frame offset {} payload offset {} packet size {}",
                locked_payload.frame_offset,
                locked_payload.payload_offset,
                pkt.get_iovecs_size(),
            );
        }
        let mut iovecs: &mut [Iovec] = &mut pkt.iovecs;
        if locked_payload.payload_offset == 0 {
            // Payload start, add header.
            pkt.transfer_packet(&mut locked_payload.header, header_len);
            locked_payload.payload_offset += header_len as usize;
            iovecs = iov_discard_front_direct(&mut pkt.iovecs, pkt.actual_length as u64)
                .with_context(|| format!("Invalid iov size {}", pkt_size))?;
        }
        let copyed = locked_camera.get_frame(
            iovecs,
            locked_payload.frame_offset,
            frame_data_size as usize,
        )?;
        pkt.actual_length += copyed as u32;
        debug!(
            "Camera handle payload, frame_offset {} payloadoffset {} data_size {} copyed {}",
            locked_payload.frame_offset, locked_payload.payload_offset, frame_data_size, copyed
        );
        locked_payload.frame_offset += frame_data_size as usize;
        locked_payload.payload_offset += frame_data_size as usize;

        if locked_payload.payload_offset >= MAX_PAYLOAD as usize {
            locked_payload.payload_offset = 0;
        }
        if locked_payload.frame_offset >= current_frame_size {
            locked_payload.next_frame();
            locked_camera.next_frame()?;
        }
        Ok(())
    }
}

impl EventNotifierHelper for CameraIoHander {
    fn internal_notifiers(io_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let cloned_io_handler = io_handler.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_event, fd: RawFd| {
            read_fd(fd);
            cloned_io_handler.lock().unwrap().handle_io();
            None
        });
        vec![EventNotifier::new(
            NotifierOperation::AddShared,
            io_handler.lock().unwrap().fd.as_raw_fd(),
            None,
            EventSet::IN,
            vec![handler],
        )]
    }
}

fn gen_fmt_desc(fmt_list: Vec<CameraFormatList>) -> Result<Vec<Arc<UsbDescOther>>> {
    let mut body = vec![];
    let mut buf = vec![];

    let mut header_struct = gen_intface_header_desc(fmt_list.len() as u8);

    for fmt in fmt_list {
        let data = gen_fmt_header(&fmt)?;
        body.push(Arc::new(UsbDescOther { data: data.clone() }));

        for frm in &fmt.frame {
            let data = gen_frm_desc(fmt.format, frm)?;
            body.push(Arc::new(UsbDescOther { data: data.clone() }));
        }
        let data = gen_color_matching_desc()?;
        body.push(Arc::new(UsbDescOther { data }));
    }

    header_struct.wTotalLength = header_struct.bLength as u16
        + body.clone().iter().fold(0, |len, x| len + x.data.len()) as u16;

    buf.push(Arc::new(UsbDescOther {
        data: header_struct.as_bytes().to_vec(),
    }));
    buf.append(&mut body);

    Ok(buf)
}

fn gen_intface_header_desc(fmt_num: u8) -> VsDescInputHeader {
    VsDescInputHeader {
        bLength: 0xf,
        bDescriptorType: CS_INTERFACE,
        bDescriptorSubtype: VS_INPUT_HEADER,
        bNumFormats: fmt_num,
        wTotalLength: 0x00, // Shall be filled later after all members joined together.
        bEndpointAddress: USB_DIRECTION_DEVICE_TO_HOST | ENDPOINT_ID_STREAMING, // EP 1 IN
        bmInfo: 0x00,
        bTerminalLink: 2,
        bStillCaptureMethod: 0x00,
        bTriggerSupport: 0x00,
        bTriggerUsage: 0x00,
        bControlSize: 0x01,
        bmaControls: 0x00,
    }
}

fn gen_fmt_header(fmt: &CameraFormatList) -> Result<Vec<u8>> {
    let header = match fmt.format {
        FmtType::Yuy2 | FmtType::Rgb565 => VsDescUncompressedFmt {
            bLength: 0x1B,
            bDescriptorType: CS_INTERFACE,
            bDescriptorSubtype: VS_FORMAT_UNCOMPRESSED,
            bFormatIndex: fmt.fmt_index,
            bNumFrameDescriptors: fmt.frame.len() as u8,
            guidFormat: *MEDIA_TYPE_GUID_HASHMAP
                .get(&fmt.format)
                .with_context(|| "unsupported video format.")?,
            bBitsPerPixel: 0x10,
            bDefaultFrameIndex: 1,
            bAspectRatioX: 0,
            bAspectRatioY: 0,
            bmInterlaceFlags: 0,
            bCopyProtect: 0,
        }
        .as_bytes()
        .to_vec(),
        FmtType::Mjpg => VsDescMjpgFmt {
            bLength: 0xb,
            bDescriptorType: CS_INTERFACE,
            bDescriptorSubtype: VS_FORMAT_MJPEG,
            bFormatIndex: fmt.fmt_index,
            bNumFrameDescriptors: fmt.frame.len() as u8,
            bmFlags: 0x01,
            bDefaultFrameIndex: 0x01,
            bAspectRatioX: 0x00,
            bAspectRatioY: 0x00,
            bmInterlaceFlags: 0x00,
            bCopyProtect: 0x00,
        }
        .as_bytes()
        .to_vec(),
    };

    Ok(header)
}

fn gen_frm_desc(pixfmt: FmtType, frm: &CameraFrame) -> Result<Vec<u8>> {
    let desc = VsDescFrm {
        bLength: 0x1e, // TODO: vary with interval number.
        bDescriptorType: CS_INTERFACE,
        bDescriptorSubtype: match pixfmt {
            FmtType::Rgb565 | FmtType::Yuy2 => VS_FRAME_UNCOMPRESSED,
            FmtType::Mjpg => VS_FRAME_MJPEG,
        },
        bFrameIndex: frm.index,
        bmCapabilities: 0x00,
        wWidth: frm.width as u16,
        wHeight: frm.height as u16,
        dwMinBitRate: 442368000,
        dwMaxBitRate: 442368000,
        dwMaxVideoFrameBufSize: frm.width as u32 * frm.height as u32 * 2 + 589,
        dwDefaultFrameInterval: frm.interval,
        bFrameIntervalType: 1,
        dwIntervalVals: frm.interval,
    }
    .as_bytes()
    .to_vec();

    Ok(desc)
}

fn gen_color_matching_desc() -> Result<Vec<u8>> {
    Ok(VsDescColorMatching {
        bLength: 0x06,
        bDescriptorType: CS_INTERFACE,
        bDescriptorSubtype: VS_COLORFORMAT,
        bColorPrimaries: 0x01,          // BT.709,sRGB
        bTransferCharacteristics: 0x01, // BT.709
        bMatrixCoefficients: 0x04,      // SMPTE 170M (BT.601)
    }
    .as_bytes()
    .to_vec())
}

#[cfg(test)]
mod test {
    use crate::camera_backend::{CameraFormatList, CameraFrame, FmtType};

    use super::*;

    fn test_interface_table_data_len(interface: Arc<UsbDescIface>, size_offset: usize) {
        let descs = &interface.other_desc;
        let mut total_len_exact: usize = 0;

        let total_len_set: usize = (descs[0].data[size_offset] as usize
            + ((descs[0].data[size_offset + 1] as usize) << 8))
            as usize; // field 'wTotalLength' in the 1st data desc

        for desc in descs {
            let sub_len_set = desc.data[0] as usize; // field 'bLength'
            let sub_len_exact = desc.data.len();
            assert_eq!(sub_len_set, sub_len_exact);

            total_len_exact += sub_len_exact;
        }

        assert_eq!(total_len_set, total_len_exact);
    }

    fn list_format() -> Vec<CameraFormatList> {
        vec![
            CameraFormatList {
                format: FmtType::Yuy2,
                fmt_index: 1,
                frame: vec![
                    CameraFrame {
                        width: 1980,
                        height: 720,
                        interval: 30,
                        index: 1,
                    },
                    CameraFrame {
                        width: 640,
                        height: 480,
                        interval: 30,
                        index: 2,
                    },
                ],
            },
            CameraFormatList {
                format: FmtType::Mjpg,
                frame: vec![
                    CameraFrame {
                        width: 1980,
                        height: 720,
                        interval: 30,
                        index: 1,
                    },
                    CameraFrame {
                        width: 640,
                        height: 680,
                        interval: 20,
                        index: 2,
                    },
                ],
                fmt_index: 2,
            },
        ]
    }

    #[test]
    fn test_interfaces_table_data_len() {
        // VC and VS's header differents, their wTotalSize field's offset are the bit 5 and 4 respectively in their data[0] vector.
        // the rest datas follow the same principle that the 1st element is the very data vector's length.
        test_interface_table_data_len(gen_desc_interface_camera_vc().unwrap(), 5);
        test_interface_table_data_len(gen_desc_interface_camera_vs(list_format()).unwrap(), 4);
    }
}
