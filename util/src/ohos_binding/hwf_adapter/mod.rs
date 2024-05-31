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

#[cfg(feature = "usb_camera_oh")]
pub mod camera;
#[cfg(feature = "usb_host")]
pub mod usb;

use std::ffi::OsStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use libloading::Library;
use log::error;
use once_cell::sync::Lazy;

#[cfg(feature = "usb_camera_oh")]
use camera::CamFuncTable;
#[cfg(feature = "usb_host")]
use usb::UsbFuncTable;

static LIB_HWF_ADAPTER: Lazy<LibHwfAdapter> = Lazy::new(||
    // SAFETY: The dynamic library should be always existing.
    unsafe {
        LibHwfAdapter::new(OsStr::new("/system/lib64/libhwf_adapter.so"))
            .map_err(|e| {
                error!("failed to init LibHwfAdapter with error: {:?}", e);
                e
            })
            .unwrap()
    });

struct LibHwfAdapter {
    #[allow(unused)]
    library: Library,
    #[cfg(feature = "usb_camera_oh")]
    camera: Arc<CamFuncTable>,
    #[cfg(feature = "usb_host")]
    usb: Arc<UsbFuncTable>,
}

impl LibHwfAdapter {
    unsafe fn new(library_name: &OsStr) -> Result<LibHwfAdapter> {
        let library =
            Library::new(library_name).with_context(|| "failed to load hwf_adapter library")?;

        #[cfg(feature = "usb_camera_oh")]
        let camera = Arc::new(
            CamFuncTable::new(&library).with_context(|| "failed to init camera function table")?,
        );

        #[cfg(feature = "usb_host")]
        let usb = Arc::new(
            UsbFuncTable::new(&library).with_context(|| "failed to init usb function table")?,
        );

        Ok(Self {
            library,
            #[cfg(feature = "usb_camera_oh")]
            camera,
            #[cfg(feature = "usb_host")]
            usb,
        })
    }

    #[cfg(feature = "usb_camera_oh")]
    fn get_camera_api(&self) -> Arc<CamFuncTable> {
        self.camera.clone()
    }

    #[cfg(feature = "usb_host")]
    fn get_usb_api(&self) -> Arc<UsbFuncTable> {
        self.usb.clone()
    }
}

#[cfg(feature = "usb_camera_oh")]
pub fn hwf_adapter_camera_api() -> Arc<CamFuncTable> {
    LIB_HWF_ADAPTER.get_camera_api()
}

#[cfg(feature = "usb_host")]
pub fn hwf_adapter_usb_api() -> Arc<UsbFuncTable> {
    LIB_HWF_ADAPTER.get_usb_api()
}
