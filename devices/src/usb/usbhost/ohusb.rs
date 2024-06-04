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

use std::os::fd::AsRawFd;
use std::ptr;

use anyhow::{bail, Context as anyhowContext, Result};
use libusb1_sys::constants::LIBUSB_OPTION_NO_DEVICE_DISCOVERY;
use log::{error, info};
use rusb::{Context, DeviceHandle, UsbContext};

use super::host_usblib::set_option;
use super::{check_device_valid, UsbHostConfig};
use util::ohos_binding::usb::*;

pub struct OhUsbDev {
    dev: OhusbDevice,
    lib: OhUsb,
}

impl Drop for OhUsbDev {
    fn drop(&mut self) {
        if let Err(e) = self.lib.close_device(ptr::addr_of_mut!(self.dev)) {
            error!("Failed to close usb device with error {:?}", e)
        }
    }
}

impl OhUsbDev {
    pub fn new() -> Result<Self> {
        // In combination with libusb_wrap_sys_device(), in order to access a device directly without prior device scanning on ohos.
        set_option(LIBUSB_OPTION_NO_DEVICE_DISCOVERY)?;

        Ok(Self {
            dev: OhusbDevice {
                busNum: u8::MAX,
                devAddr: u8::MAX,
                fd: -1,
            },
            lib: OhUsb::new()?,
        })
    }

    pub fn open(&mut self, cfg: UsbHostConfig, ctx: Context) -> Result<DeviceHandle<Context>> {
        self.dev.busNum = cfg.hostbus;
        self.dev.devAddr = cfg.hostaddr;

        match self.lib.open_device(ptr::addr_of_mut!(self.dev))? {
            0 => {
                if self.dev.fd < 0 {
                    bail!(
                        "Failed to open usb device due to invalid fd {}",
                        self.dev.fd
                    );
                }
            }
            _ => bail!("Failed to open usb device"),
        }
        info!("OH USB: open_device: returned fd is {}", self.dev.fd);

        // SAFETY: fd is valid.
        let handle = unsafe {
            ctx.open_device_with_fd(self.dev.fd.as_raw_fd())
                .with_context(|| format!("os last error: {:?}", std::io::Error::last_os_error()))?
        };

        if !check_device_valid(&handle.device()) {
            bail!("Invalid USB host config: {:?}", cfg);
        }

        Ok(handle)
    }
}
