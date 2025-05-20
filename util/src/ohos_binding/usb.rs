// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

pub use super::hwf_adapter::usb::OhusbDevice;

use std::sync::Arc;

use anyhow::{bail, Result};

use super::hwf_adapter::hwf_adapter_usb_api;
use super::hwf_adapter::usb::UsbFuncTable;

#[derive(Clone)]
pub struct OhUsb {
    capi: Arc<UsbFuncTable>,
}

impl OhUsb {
    pub fn new() -> Result<OhUsb> {
        let capi = hwf_adapter_usb_api();
        Ok(Self { capi })
    }

    pub fn open_device(&self, dev_handle: *mut OhusbDevice) -> Result<i32> {
        // SAFETY: We call related API sequentially for specified ctx.
        let ret = unsafe { (self.capi.open_device)(dev_handle) };
        if ret < 0 {
            bail!("OH USB: open device failed.");
        }
        Ok(ret)
    }

    pub fn close_device(&self, dev_handle: *mut OhusbDevice) -> Result<i32> {
        // SAFETY: We call related API sequentially for specified ctx.
        let ret = unsafe { (self.capi.close_device)(dev_handle) };
        if ret < 0 {
            bail!("OH USB: close device failed.");
        }
        Ok(ret)
    }
}
