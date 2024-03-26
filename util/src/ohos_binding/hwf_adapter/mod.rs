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

#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub mod camera;

use std::ffi::OsStr;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use libloading::Library;
use log::error;
use once_cell::sync::Lazy;

#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
use camera::CamFuncTable;

static LIB_HWF_ADAPTER: Lazy<RwLock<LibHwfAdapter>> = Lazy::new(||
    // SAFETY: The dynamic library should be always existing.
    unsafe {
        RwLock::new(
            LibHwfAdapter::new(OsStr::new("/system/lib64/libhwf_adapter.so"))
                .map_err(|e| {
                    error!("failed to init LibHwfAdapter with error: {:?}", e);
                    e
                })
                .unwrap()
        )
    });

struct LibHwfAdapter {
    #[allow(unused)]
    library: Library,
    #[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
    camera: Arc<CamFuncTable>,
}

impl LibHwfAdapter {
    unsafe fn new(library_name: &OsStr) -> Result<LibHwfAdapter> {
        let library =
            Library::new(library_name).with_context(|| "failed to load hwf_adapter library")?;

        #[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
        let camera = Arc::new(
            CamFuncTable::new(&library).with_context(|| "failed to init camera function table")?,
        );

        Ok(Self {
            library,
            #[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
            camera,
        })
    }

    #[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
    fn get_camera_api(&self) -> Arc<CamFuncTable> {
        self.camera.clone()
    }
}

#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub fn hwf_adapter_camera_api() -> Arc<CamFuncTable> {
    LIB_HWF_ADAPTER.read().unwrap().get_camera_api()
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
