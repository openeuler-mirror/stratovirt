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

use std::ptr;
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

    pub fn open_device(&self, dev_handle: &mut OhusbDevice) -> Result<()> {
        // SAFETY: We call related API sequentially for specified ctx and dev_handle is
        // valid while calling this function. In addition we need to check the returned
        // value. At the same time, the C API "open_device" can be reenterred.
        let ret = unsafe { (self.capi.open_device)(ptr::addr_of_mut!(*dev_handle)) };
        if ret != 0 {
            bail!("OH USB: open device failed, err {}", ret);
        }
        Ok(())
    }

    pub fn close_device(&self, dev_handle: *mut OhusbDevice) -> Result<()> {
        // SAFETY: We call related API sequentially for specified ctx and dev_handle is
        // valid while calling this function. It's not harmful to call it with invalid
        // content in device_handle.
        let ret = unsafe { (self.capi.close_device)(ptr::addr_of_mut!(*dev_handle)) };
        if ret != 0 {
            bail!("OH USB: close device failed, err {}", ret);
        }
        Ok(())
    }
}
