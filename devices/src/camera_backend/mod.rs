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
//! Backend devices, such as v4l2, usb, or demo device, etc., shall implement trait
//! CameraHostdevOps.

pub mod demo;
#[cfg(feature = "usb_camera_v4l2")]
pub mod v4l2;

use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};

use self::demo::DemoCamera;
#[cfg(feature = "usb_camera_v4l2")]
use self::v4l2::V4l2CameraBackend;
use machine_manager::config::{CamBackendType, ConfigError, UsbCameraConfig};
use util::aio::Iovec;

/// Frame interval in 100ns units.
pub const INTERVALS_PER_SEC: u32 = 10_000_000;

#[derive(Clone, Copy, Default, Debug)]
pub struct CamBasicFmt {
    pub width: u32,
    pub height: u32,
    fps: u32,
    fmttype: FmtType,
}

impl CamBasicFmt {
    pub fn get_frame_intervals(&self) -> Result<u32> {
        if self.fps == 0 {
            bail!("Invalid fps!");
        }
        Ok(INTERVALS_PER_SEC / self.fps)
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Default)]
pub enum FmtType {
    #[default]
    Yuy2 = 0,
    Rgb565,
    Mjpg,
}

#[derive(Clone, Debug)]
pub struct CameraFrame {
    pub width: u32,
    pub height: u32,
    pub index: u8,
    pub interval: u32,
}

#[derive(Clone)]
pub struct CameraFormatList {
    pub format: FmtType,
    pub fmt_index: u8,
    pub frame: Vec<CameraFrame>,
}

pub fn get_video_frame_size(width: u32, height: u32) -> Result<u32> {
    width
        .checked_mul(height)
        .with_context(|| format!("Invalid width {} or height {}", width, height))?
        .checked_mul(2)
        .with_context(|| format!("Invalid width {} or height {}", width, height))
}

pub fn get_bit_rate(width: u32, height: u32, interval: u32) -> Result<u32> {
    let fm_size = get_video_frame_size(width, height)?;
    let size_in_bit = fm_size as u64 * INTERVALS_PER_SEC as u64 * 8;
    let rate = size_in_bit
        .checked_div(interval as u64)
        .with_context(|| format!("Invalid size {} or interval {}", size_in_bit, interval))?;
    Ok(rate as u32)
}

#[macro_export]
macro_rules! video_fourcc {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        $a as u32 | (($b as u32) << 8) | (($c as u32) << 16) | (($d as u32) << 24)
    };
}

pub const PIXFMT_RGB565: u32 = video_fourcc!('R', 'G', 'B', 'P');
pub const PIXFMT_YUYV: u32 = video_fourcc!('Y', 'U', 'Y', 'V');
pub const PIXFMT_MJPG: u32 = video_fourcc!('M', 'J', 'P', 'G');

/// Callback function which is called when frame data is coming.
pub type CameraNotifyCallback = Arc<dyn Fn() + Send + Sync>;

/// Callback function which is called when backend is broken.
pub type CameraBrokenCallback = Arc<dyn Fn() + Send + Sync>;

pub trait CameraHostdevOps: Send + Sync {
    /// Set a specific format.
    fn set_fmt(&mut self, fmt: &CamBasicFmt) -> Result<()>;

    /// Set control capabilities and properties.
    fn set_ctl(&self) -> Result<()>;

    // Turn stream on to start to receive frame buffer.
    fn video_stream_on(&mut self) -> Result<()>;

    // Turn stream off to end receiving frame buffer.
    fn video_stream_off(&mut self) -> Result<()>;

    /// List all formats supported by backend.
    fn list_format(&mut self) -> Result<Vec<CameraFormatList>>;

    /// Reset the device.
    fn reset(&mut self);

    /// Get the total size of current frame.
    fn get_frame_size(&self) -> usize;

    /// Copy frame data to iovecs.
    fn get_frame(&self, iovecs: &[Iovec], frame_offset: usize, len: usize) -> Result<usize>;

    /// Get format/frame info including width/height/interval/fmt according to format/frame index.
    fn get_format_by_index(&self, format_index: u8, frame_index: u8) -> Result<CamBasicFmt>;

    /// Get next frame when current frame is read complete.
    fn next_frame(&mut self) -> Result<()>;

    /// Register notify callback which is called when data is coming.
    fn register_notify_cb(&mut self, cb: CameraNotifyCallback);

    /// Register broken callback which is called when backend is broken.
    fn register_broken_cb(&mut self, cb: CameraBrokenCallback);
}

pub fn camera_ops(config: UsbCameraConfig) -> Result<Arc<Mutex<dyn CameraHostdevOps>>> {
    let cam: Arc<Mutex<dyn CameraHostdevOps>> = match config.backend {
        #[cfg(feature = "usb_camera_v4l2")]
        CamBackendType::V4l2 => Arc::new(Mutex::new(V4l2CameraBackend::new(
            config.drive.id.clone().unwrap(),
            config.drive.path.clone().with_context(|| {
                ConfigError::FieldIsMissing("path".to_string(), "V4L2".to_string())
            })?,
            config.iothread,
        )?)),
        CamBackendType::Demo => Arc::new(Mutex::new(DemoCamera::new(
            config.id.clone().unwrap(),
            config.path.with_context(|| {
                ConfigError::FieldIsMissing("path".to_string(), "Demo".to_string())
            })?,
        )?)),
    };

    Ok(cam)
}
