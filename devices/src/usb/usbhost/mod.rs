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

use anyhow::{Ok, Result};

use super::{
    xhci::xhci_controller::XhciDevice, UsbDevice, UsbDeviceOps, UsbDeviceRequest, UsbEndpoint,
    UsbPacket,
};
use machine_manager::config::UsbHostConfig;

/// Abstract object of the host USB device.
pub struct UsbHost {
    id: String,
    _config: UsbHostConfig,
    usb_device: UsbDevice,
}

impl UsbHost {
    pub fn new(config: UsbHostConfig) -> Self {
        Self {
            id: config.id.clone().unwrap(),
            _config: config,
            usb_device: UsbDevice::new(),
        }
    }
}

impl UsbDeviceOps for UsbHost {
    fn realize(self) -> Result<Arc<Mutex<dyn UsbDeviceOps>>> {
        let usbhost = Arc::new(Mutex::new(self));
        Ok(usbhost)
    }

    fn reset(&mut self) {}

    fn set_controller(&mut self, _cntlr: std::sync::Weak<Mutex<XhciDevice>>) {}

    fn get_controller(&self) -> Option<Weak<Mutex<XhciDevice>>> {
        None
    }

    fn get_wakeup_endpoint(&self) -> &UsbEndpoint {
        self.usb_device.get_endpoint(true, 1)
    }

    fn handle_control(&mut self, _packet: &Arc<Mutex<UsbPacket>>, _device_req: &UsbDeviceRequest) {}

    fn handle_data(&mut self, _packet: &Arc<Mutex<UsbPacket>>) {}

    fn device_id(&self) -> String {
        self.id.clone()
    }

    fn get_usb_device(&self) -> &UsbDevice {
        &self.usb_device
    }

    fn get_mut_usb_device(&mut self) -> &mut UsbDevice {
        &mut self.usb_device
    }
}
