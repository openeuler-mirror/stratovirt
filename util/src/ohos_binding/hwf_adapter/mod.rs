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

use std::ffi::OsStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use libloading::Library;
use log::error;
use once_cell::sync::Lazy;

#[cfg(feature = "usb_camera_oh")]
use camera::CamFuncTable;

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
}

impl LibHwfAdapter {
    unsafe fn new(library_name: &OsStr) -> Result<LibHwfAdapter> {
        let library =
            Library::new(library_name).with_context(|| "failed to load hwf_adapter library")?;

        #[cfg(feature = "usb_camera_oh")]
        let camera = Arc::new(
            CamFuncTable::new(&library).with_context(|| "failed to init camera function table")?,
        );

        Ok(Self {
            library,
            #[cfg(feature = "usb_camera_oh")]
            camera,
        })
    }

    #[cfg(feature = "usb_camera_oh")]
    fn get_camera_api(&self) -> Arc<CamFuncTable> {
        self.camera.clone()
    }
}

#[cfg(feature = "usb_camera_oh")]
pub fn hwf_adapter_camera_api() -> Arc<CamFuncTable> {
    LIB_HWF_ADAPTER.get_camera_api()
}

#[macro_export]
macro_rules! get_libfn {
    ( $lib: ident, $tname: ident, $fname: ident ) => {
        $lib.get::<$tname>(stringify!($fname).as_bytes())
            .with_context(|| {
                format!(
                    "failed to get function {} from libhwf_adapter",
                    stringify!($fname)
                )
            })?
            .into_raw()
    };
}
