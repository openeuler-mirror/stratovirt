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

//! The abstract layer that connects different frontend & backend camera devices.
//! Backend devices, such as v4l2, usb, or demo device, etc., shall implement trait CameraHostdevOps.

pub mod demo;
pub mod v4l2;

use anyhow::Result;

#[allow(dead_code)]
#[derive(Default)]
pub struct CamFmt {
    // Basic 3 configurations: frame size, format, frame frequency.
    basic_fmt: CamBasicFmt,
    // Processing Unit Configuration: brightness, hue, etc.
    pu_fmt: CamPUFmt,
    // Camera Terminal Configuration: focus, exposure time, iris, etc.
    lens_fmt: CamLensFmt,
}

impl CamFmt {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

#[allow(dead_code)]
#[derive(Default)]
pub struct CamBasicFmt {
    width: u16,
    height: u16,
    fps: u16,
    fmttype: FmtType,
}

#[allow(dead_code)]
#[derive(Default)]
pub struct CamPUFmt {
    bright: u64,
    contrast: u64,
    hue: u64,
    saturatio: u64,
    // TODO: to be extended.
}

#[allow(dead_code)]
#[derive(Default)]
pub struct CamLensFmt {
    focus: u64,
    zoom: u64,
    // TODO: to be extended.
}

#[allow(dead_code)]
enum FmtType {
    Uncompressed = 0,
    Mjpg,
}

impl Default for FmtType {
    fn default() -> Self {
        FmtType::Uncompressed
    }
}

pub trait CameraHostdevOps: Send + Sync {
    fn init(&self) -> Result<()>;
    fn is_camera(&self) -> Result<bool>;
    fn get_fmt(&self) -> Result<()>;
    fn set_fmt(&self, fmt: u64) -> Result<()>;
    fn set_ctl(&self) -> Result<()>;

    // Turn stream on to start to receive frame buffer.
    fn video_stream_on(&self) -> Result<()>;
    // The callback function used to poll on backend video devices, such as /dev/video0.
    fn video_stream_run(&self) -> Result<()>;
    // Turn stream off to end receiving frame buffer.
    fn video_stream_off(&self) -> Result<()>;
}
