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

use std::collections::{HashMap, LinkedList};
use std::sync::{Arc, Mutex};

use crate::usb::{UsbDeviceOps, UsbPort};
use anyhow::{bail, Result};

/// The key is bus name, the value is the device which can attach other devices.
pub type BusDeviceMap = Arc<Mutex<HashMap<String, Arc<Mutex<dyn BusDeviceOps>>>>>;

/// USB bus used to manage USB ports.
#[derive(Default)]
pub struct UsbBus {
    free_ports: LinkedList<Arc<Mutex<UsbPort>>>,
    used_ports: LinkedList<Arc<Mutex<UsbPort>>>,
}

impl UsbBus {
    pub fn new() -> Self {
        UsbBus {
            free_ports: LinkedList::new(),
            used_ports: LinkedList::new(),
        }
    }

    /// Register USB port to the bus.
    pub fn register_usb_port(&mut self, port: &Arc<Mutex<UsbPort>>) {
        let mut locked_port = port.lock().unwrap();
        locked_port.path = format!("{}", locked_port.index + 1);
        self.free_ports.push_back(port.clone());
    }

    /// Assign USB port and attach the device.
    pub fn assign_usb_port(
        &mut self,
        dev: &Arc<Mutex<dyn UsbDeviceOps>>,
    ) -> Result<Arc<Mutex<UsbPort>>> {
        if let Some(port) = self.free_ports.pop_front() {
            let mut locked_dev = dev.lock().unwrap();
            locked_dev.set_usb_port(Some(Arc::downgrade(&port)));
            let mut locked_port = port.lock().unwrap();
            locked_port.dev = Some(dev.clone());
            drop(locked_port);
            self.used_ports.push_back(port.clone());
            Ok(port)
        } else {
            bail!("No available usb port");
        }
    }

    /// Find USB port by path.
    pub fn find_usb_port(&self, path: String) -> Option<Arc<Mutex<UsbPort>>> {
        for usb in &self.used_ports {
            if usb.lock().unwrap().path == path {
                return Some(usb.clone());
            }
        }
        None
    }
}

/// Bus device ops for USB controller to handle USB device attach/detach.
pub trait BusDeviceOps: Send + Sync {
    fn attach_device(&mut self, dev: &Arc<Mutex<dyn UsbDeviceOps>>) -> Result<()>;

    fn detach_device(&mut self, dev: &Arc<Mutex<dyn UsbDeviceOps>>) -> Result<()>;
}
