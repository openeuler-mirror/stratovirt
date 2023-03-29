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
use machine_manager::config::{CamBackendType, UsbCameraConfig};
use std::sync::{Arc, Mutex, Weak};

use super::config::USB_SPEED_HIGH;
use super::xhci::xhci_controller::XhciDevice;
use crate::camera_backend::{v4l2::V4l2HostDev, CameraHostdevOps};
use crate::usb::{UsbDevice, UsbDeviceOps, UsbDeviceRequest, UsbEndpoint, UsbPacket};

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
        //TODO: init descriptor.
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
