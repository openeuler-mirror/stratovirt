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

//! Demo backend for vCamera device, that helps for testing.

use std::fs::read_to_string;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};
#[cfg(not(target_env = "ohos"))]
use cairo::{Format, ImageSurface};
use log::{debug, error, info};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

use super::INTERVALS_PER_SEC;
use crate::camera_backend::{
    check_path, CamBasicFmt, CameraBackend, CameraBrokenCallback, CameraFormatList, CameraFrame,
    CameraNotifyCallback, FmtType,
};
use util::aio::{mem_from_buf, Iovec};

#[derive(Debug)]
enum RgbColor {
    Red,
    Orange,
    Yellow,
    Green,
    Blue,
    Indigo,
    Violet,
    White,
    Black,
}

fn get_rgb_color(color: &RgbColor) -> (u8, u8, u8) {
    match color {
        RgbColor::Red => (0xff, 0x0, 0x0),
        RgbColor::Orange => (0xff, 0x80, 0x0),
        RgbColor::Yellow => (0xff, 0xff, 0x0),
        RgbColor::Green => (0x0, 0xff, 0x0),
        RgbColor::Blue => (0x0, 0x0, 0xff),
        RgbColor::Indigo => (0x4b, 0x0, 0x82),
        RgbColor::Violet => (0xee, 0x82, 0xee),
        RgbColor::White => (0xff, 0xff, 0xff),
        RgbColor::Black => (0x0, 0x0, 0x0),
    }
}

impl From<u8> for RgbColor {
    fn from(t: u8) -> Self {
        match t {
            0 => RgbColor::Red,
            1 => RgbColor::Orange,
            2 => RgbColor::Yellow,
            3 => RgbColor::Green,
            4 => RgbColor::Blue,
            5 => RgbColor::Indigo,
            6 => RgbColor::Violet,
            7 => RgbColor::White,
            _ => RgbColor::Black,
        }
    }
}

#[derive(Default)]
struct FrameImage {
    image: Vec<u8>,
    used_len: u64,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum DeviceState {
    Uninitialized,
    Running,
    Exit,
}

enum ImageMode {
    Default,
    Random,
}

impl From<&str> for ImageMode {
    fn from(t: &str) -> Self {
        match t {
            "default" => ImageMode::Default,
            "random" => ImageMode::Random,
            _ => ImageMode::Default,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceConfig {
    check_interval: u64,
    image_mode: String,
    force_frame_len: Option<u64>,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            check_interval: 50,
            image_mode: String::from("default"),
            force_frame_len: None,
        }
    }
}

/// Demo camera backend used for test.
pub struct DemoCameraBackend {
    id: String,
    /// Device config path.
    config_path: String,
    /// Frame image data.
    frame_image: Arc<Mutex<FrameImage>>,
    /// Callback to used to notify when data is coming.
    notify_cb: Option<CameraNotifyCallback>,
    /// Callback to used to notify the broken.
    broken_cb: Option<CameraNotifyCallback>,
    /// Current format.
    cur_format: Arc<Mutex<CamBasicFmt>>,
    /// Format list supported by the device.
    format_list: Vec<CameraFormatList>,
    /// Device state.
    state: Arc<Mutex<DeviceState>>,
}

impl DemoCameraBackend {
    pub fn new(id: String, config_path: String) -> Result<Self> {
        let checked_path = check_path(config_path.as_str())?;
        Ok(DemoCameraBackend {
            id,
            config_path: checked_path,
            frame_image: Arc::new(Mutex::new(FrameImage::default())),
            notify_cb: None,
            broken_cb: None,
            cur_format: Arc::new(Mutex::new(CamBasicFmt::default())),
            format_list: build_format_list(),
            state: Arc::new(Mutex::new(DeviceState::Uninitialized)),
        })
    }

    fn start_worker(&mut self) -> Result<()> {
        let cloned_fmt = self.cur_format.clone();
        let cloned_frame = self.frame_image.clone();
        let cloned_notify = self.notify_cb.clone();
        let cloned_state = self.state.clone();
        let cloned_path = self.config_path.clone();

        std::thread::Builder::new()
            .name("demo camera worker".to_string())
            .spawn(move || {
                let mut image_frame = ImageFrame::default();
                let config = read_config(&cloned_path).unwrap_or_else(|_| DeviceConfig::default());
                info!("Demo device config {:?}", config);
                loop {
                    let locked_state = cloned_state.lock().unwrap();
                    match *locked_state {
                        DeviceState::Uninitialized => {
                            std::thread::sleep(std::time::Duration::from_millis(
                                config.check_interval,
                            ));
                            continue;
                        }
                        DeviceState::Running => (),
                        DeviceState::Exit => break,
                    }
                    drop(locked_state);
                    let mut locked_frame = cloned_frame.lock().unwrap();
                    if locked_frame.used_len == 0 {
                        // Build next frame.
                        let locked_fmt = cloned_fmt.lock().unwrap();
                        if let Some(len) = config.force_frame_len {
                            locked_frame.used_len = len;
                            locked_frame.image = vec![0xfe; len as usize];
                            debug!("Demo camera force used_len {}", locked_frame.used_len);
                        } else {
                            locked_frame.image = match image_frame.build_image(
                                &ImageMode::from(config.image_mode.as_str()),
                                &locked_fmt.fmttype,
                                locked_fmt.width,
                                locked_fmt.height,
                            ) {
                                Ok(img) => img,
                                Err(e) => {
                                    error!("Failed to build image {:?}", e);
                                    break;
                                }
                            };
                            locked_frame.used_len = locked_frame.image.len() as u64;
                            debug!("Demo camera used_len {}", locked_frame.used_len);
                        }
                        if let Some(notify) = cloned_notify.as_ref() {
                            notify();
                        }
                        let interval = if locked_fmt.fps != 0 {
                            1000 / locked_fmt.fps as u64
                        } else {
                            20
                        };
                        drop(locked_frame);
                        std::thread::sleep(std::time::Duration::from_millis(interval));
                    }
                }
            })?;
        Ok(())
    }
}

#[derive(Default)]
struct ImageFrame {
    frame_idx: u64,
}

impl ImageFrame {
    fn build_image(
        &mut self,
        image_mode: &ImageMode,
        format: &FmtType,
        width: u32,
        height: u32,
    ) -> Result<Vec<u8>> {
        const FRAME_IDX_LIMIT: u64 = 1000;
        let color = match image_mode {
            ImageMode::Default => RgbColor::Red,
            ImageMode::Random => RgbColor::from(self.frame_idx as u8 % 8),
        };
        debug!("Demo Image color {:?}", color);
        let mut surface = ImageSurface::create(Format::Rgb24, width as i32, height as i32)?;
        let cr = cairo::Context::new(&surface)?;
        let (r, g, b) = get_rgb_color(&color);
        cr.set_source_rgb(r as f64, g as f64, b as f64);
        cr.rectangle(0.0, 0.0, width as f64, height as f64);
        cr.fill()?;
        cr.paint()?;
        drop(cr);
        let data = surface.data()?;
        let image = match format {
            FmtType::Mjpg => build_fake_mjpg(width, height),
            FmtType::Yuy2 => convert_to_yuy2(data.deref(), width, height),
            FmtType::Rgb565 => data.deref().to_vec(),
            FmtType::Nv12 => bail!("demo device does not support NV12 now"),
        };
        self.frame_idx += 1;
        if self.frame_idx > FRAME_IDX_LIMIT {
            self.frame_idx = 0;
        }
        Ok(image)
    }
}

fn read_config(path: &str) -> Result<DeviceConfig> {
    let str = read_to_string(path)?;
    let conf = serde_json::from_str::<DeviceConfig>(&str)?;
    Ok(conf)
}

fn build_format_list() -> Vec<CameraFormatList> {
    vec![build_yuy2_list(), build_mjpg_list(), build_rgb565_list()]
}

fn build_yuy2_list() -> CameraFormatList {
    CameraFormatList {
        format: FmtType::Yuy2,
        fmt_index: 1,
        frame: vec![
            CameraFrame {
                width: 1280,
                height: 720,
                interval: INTERVALS_PER_SEC / 10,
                index: 1,
            },
            CameraFrame {
                width: 1920,
                height: 1280,
                interval: INTERVALS_PER_SEC / 5,
                index: 2,
            },
            CameraFrame {
                width: 960,
                height: 540,
                interval: INTERVALS_PER_SEC / 30,
                index: 3,
            },
            CameraFrame {
                width: 640,
                height: 480,
                interval: INTERVALS_PER_SEC / 30,
                index: 4,
            },
            CameraFrame {
                width: 480,
                height: 240,
                interval: INTERVALS_PER_SEC / 30,
                index: 5,
            },
            CameraFrame {
                width: 160,
                height: 120,
                interval: INTERVALS_PER_SEC / 60,
                index: 6,
            },
        ],
    }
}

fn build_mjpg_list() -> CameraFormatList {
    CameraFormatList {
        format: FmtType::Mjpg,
        fmt_index: 2,
        frame: vec![
            CameraFrame {
                width: 1920,
                height: 1080,
                interval: INTERVALS_PER_SEC / 30,
                index: 1,
            },
            CameraFrame {
                width: 1280,
                height: 720,
                interval: INTERVALS_PER_SEC / 30,
                index: 2,
            },
            CameraFrame {
                width: 960,
                height: 540,
                interval: INTERVALS_PER_SEC / 30,
                index: 3,
            },
            CameraFrame {
                width: 480,
                height: 240,
                interval: INTERVALS_PER_SEC / 30,
                index: 4,
            },
        ],
    }
}

fn build_rgb565_list() -> CameraFormatList {
    CameraFormatList {
        format: FmtType::Rgb565,
        fmt_index: 3,
        frame: vec![
            CameraFrame {
                width: 1280,
                height: 720,
                interval: INTERVALS_PER_SEC / 10,
                index: 1,
            },
            CameraFrame {
                width: 640,
                height: 480,
                interval: INTERVALS_PER_SEC / 30,
                index: 2,
            },
            CameraFrame {
                width: 480,
                height: 240,
                interval: INTERVALS_PER_SEC / 30,
                index: 3,
            },
        ],
    }
}

impl CameraBackend for DemoCameraBackend {
    fn set_fmt(&mut self, cam_fmt: &CamBasicFmt) -> Result<()> {
        *self.cur_format.lock().unwrap() = *cam_fmt;
        info!("Demo camera backend set format {:?}", cam_fmt);
        Ok(())
    }

    fn set_ctl(&self) -> Result<()> {
        Ok(())
    }

    fn video_stream_on(&mut self) -> Result<()> {
        if *self.state.lock().unwrap() == DeviceState::Running {
            return Ok(());
        }
        info!("Demo camera backend {} stream on", self.id);
        let mut locked_state = self.state.lock().unwrap();
        *locked_state = DeviceState::Running;
        drop(locked_state);
        self.start_worker()
    }

    fn video_stream_off(&mut self) -> Result<()> {
        if *self.state.lock().unwrap() == DeviceState::Exit {
            return Ok(());
        }
        info!("Demo camera backend {} stream off", self.id);
        let mut locked_state = self.state.lock().unwrap();
        *locked_state = DeviceState::Exit;
        Ok(())
    }

    fn list_format(&mut self) -> Result<Vec<CameraFormatList>> {
        Ok(self.format_list.clone())
    }

    fn reset(&mut self) {
        info!("Demo camera backend {} reset", self.id);
        let mut locked_state = self.state.lock().unwrap();
        *locked_state = DeviceState::Exit;
        let mut locked_frame = self.frame_image.lock().unwrap();
        locked_frame.used_len = 0;
    }

    fn get_frame_size(&self) -> usize {
        self.frame_image.lock().unwrap().used_len as usize
    }

    fn next_frame(&mut self) -> Result<()> {
        let mut locked_frame = self.frame_image.lock().unwrap();
        locked_frame.used_len = 0;
        Ok(())
    }

    fn get_frame(&self, iovecs: &[Iovec], frame_offset: usize, len: usize) -> Result<usize> {
        let locked_frame = self.frame_image.lock().unwrap();
        if frame_offset + len > locked_frame.used_len as usize {
            bail!("Invalid frame offset {} or len {}", frame_offset, len);
        }
        let mut copied = 0;
        for iov in iovecs {
            if len == copied {
                break;
            }
            let cnt = std::cmp::min(iov.iov_len as usize, len - copied);
            let start = frame_offset + copied;
            let end = start + cnt;
            let tmp = &locked_frame.image[start..end];
            mem_from_buf(tmp, iov.iov_base)
                .with_context(|| format!("Failed to write data to {:x}", iov.iov_base))?;
            copied += cnt;
        }
        Ok(copied)
    }

    fn get_format_by_index(&self, format_index: u8, frame_index: u8) -> Result<CamBasicFmt> {
        let mut out = CamBasicFmt::default();
        for fmt in &self.format_list {
            if fmt.fmt_index != format_index {
                continue;
            }
            out.fmttype = fmt.format;
            for frm in &fmt.frame {
                if frm.index != frame_index {
                    continue;
                }
                out.width = frm.width;
                out.height = frm.height;
                out.fps = INTERVALS_PER_SEC
                    .checked_div(frm.interval)
                    .with_context(|| {
                        format!(
                            "Invalid interval {} for format/frame {}:{}",
                            frm.interval, format_index, frame_index
                        )
                    })?;
                return Ok(out);
            }
        }
        bail!(
            "format/frame with idx {}/{} is not found",
            format_index,
            frame_index
        );
    }

    fn register_notify_cb(&mut self, cb: CameraNotifyCallback) {
        self.notify_cb = Some(cb);
    }

    fn register_broken_cb(&mut self, cb: CameraBrokenCallback) {
        self.broken_cb = Some(cb);
    }
}

fn clip(x: i32) -> u8 {
    if x > 255 {
        255
    } else if x < 0 {
        0
    } else {
        x as u8
    }
}

fn convert_to_yuy2(source: &[u8], width: u32, height: u32) -> Vec<u8> {
    let pixbytes = 4;
    let sz = width * height * 2;
    let mut yuv = vec![0; sz as usize];
    for x in 0..height {
        for y in 0..(width / 2) {
            let offset = x * width * pixbytes + y * pixbytes * 2;
            let src = &source[offset as usize..];
            let val = LittleEndian::read_i32(src);
            let r1 = (val >> 16) & 0xff;
            let g1 = (val >> 8) & 0xff;
            let b1 = val & 0xff;
            let src = &source[pixbytes as usize..];
            let val = LittleEndian::read_i32(src);
            let r2 = (val >> 16) & 0xff;
            let g2 = (val >> 8) & 0xff;
            let b2 = val & 0xff;

            let y1 = clip(((66 * r1 + 129 * g1 + 25 * b1 + 128) >> 8) + 16);
            let u1 = clip(
                (((-38 * r1 - 74 * g1 + 112 * b1 + 128) >> 8)
                    + ((-38 * r2 - 74 * g2 + 112 * b2 + 128) >> 8))
                    / 2
                    + 128,
            );
            let y2 = clip(((66 * r2 + 129 * g2 + 25 * b2 + 128) >> 8) + 16);
            let v1 = clip(
                (((112 * r1 - 94 * g1 - 18 * b1 + 128) >> 8)
                    + ((112 * r2 - 94 * g2 - 18 * b2 + 128) >> 8))
                    / 2
                    + 128,
            );
            let mut dst = (x * width * 2 + y * 4) as usize;
            yuv[dst] = y1;
            dst += 1;
            yuv[dst] = u1;
            dst += 1;
            yuv[dst] = y2;
            dst += 1;
            yuv[dst] = v1;
        }
    }
    yuv
}

// NOTE: Fake mjpg data, which is used to simulate frame data of different lengths.
fn build_fake_mjpg(width: u32, height: u32) -> Vec<u8> {
    let mut rng = thread_rng();
    let len = rng.gen_range((width * height / 20)..(width * height / 4));
    let start = vec![0xff, 0xd8, 0xff, 0xe0];
    let data = vec![0xfc; len as usize];
    let end = vec![0xff, 0xf9];
    [start, data, end].concat()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_yuy2() {
        let mut frame = ImageFrame::default();
        let buf = frame
            .build_image(&ImageMode::Default, &FmtType::Yuy2, 2, 2)
            .unwrap();
        assert_eq!(buf, [82, 90, 82, 240, 82, 90, 82, 240]);
    }

    #[test]
    fn test_rgb() {
        let mut frame = ImageFrame::default();
        let buf = frame
            .build_image(&ImageMode::Default, &FmtType::Rgb565, 1, 1)
            .unwrap();
        assert_eq!(buf, [0, 0, 255, 255]);
    }
}
