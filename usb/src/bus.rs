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

use super::errors::Result;
use crate::usb::{UsbDeviceOps, UsbPort};

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
}

/// Bus device ops for USB controller to handle USB device attach/detach.
pub trait BusDeviceOps: Send + Sync {
    fn attach_device(&mut self, dev: &Arc<Mutex<dyn UsbDeviceOps>>) -> Result<()>;

    fn detach_device(&mut self, dev: &Arc<Mutex<dyn UsbDeviceOps>>) -> Result<()>;
}
