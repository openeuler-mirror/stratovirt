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

use anyhow::Result;
use std::sync::{Mutex, Weak};

use super::xhci::xhci_controller::XhciDevice;
use crate::camera_backend::CameraHostdevOps;
use crate::usb::{UsbDevice, UsbDeviceOps, UsbDeviceRequest, UsbEndpoint, UsbPacket};

#[allow(dead_code)]
pub struct UsbCamera {
    id: String,                                 // uniq device id
    usb_device: UsbDevice,                      // general usb device object
    frame: Vec<u64>,                            // video frame data
    max_pkt_size: u32,                          // the max size of the packet that can be seperated
    vs_eps: Vec<u8>,                            // the endpoints that the VS uses
    hostdev: Option<Box<dyn CameraHostdevOps>>, // backend device, eg. v4l2, demo, etc.
}

#[allow(dead_code)]
impl UsbCamera {
    pub fn new() -> Self {
        UsbCamera {
            id: "".to_string(),
            usb_device: UsbDevice::new(),
            frame: Vec::new(),
            max_pkt_size: 0,
            vs_eps: Vec::new(),
            hostdev: None,
        }
    }

    pub fn realize(&mut self) -> Result<()> {
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
        Self::new()
    }
}

impl UsbDeviceOps for UsbCamera {
    fn reset(&mut self) {}

    fn handle_control(&mut self, _packet: &mut UsbPacket, _device_req: &UsbDeviceRequest) {}

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
