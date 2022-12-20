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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::usb::UsbDeviceOps;
use anyhow::Result;

/// The key is bus name, the value is the device which can attach other devices.
pub type BusDeviceMap = Arc<Mutex<HashMap<String, Arc<Mutex<dyn BusDeviceOps>>>>>;

/// Bus device ops for USB controller to handle USB device attach/detach.
pub trait BusDeviceOps: Send + Sync {
    fn attach_device(&mut self, dev: &Arc<Mutex<dyn UsbDeviceOps>>) -> Result<()>;

    fn detach_device(&mut self, dev: &Arc<Mutex<dyn UsbDeviceOps>>) -> Result<()>;
}
