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

//! V4L2 backend for vCamera device. /dev/videoX and VIDIOC_XX ioctls are used.

use anyhow::Result;
use std::os::unix::io::RawFd;

use super::CamFmt;
use super::CameraHostdevOps;

#[allow(dead_code)]
pub struct V4l2HostDev {
    device: String, // backend host device, eg. "/dev/video0"
    pub fd: RawFd,  // the fd for "device"

    buffer: Vec<u8>, // buffer that stores video frame
    buf_addr: u64,   // video buffer related hpa
    buf_len: u64,    // video buffer size

    hostfmt: CamFmt, // the combination of video formats that the hardware supports
    pub cur_fmt: CamFmt, // the combination of video formats that we negotiated with the hardware
}

#[allow(dead_code)]
impl V4l2HostDev {
    pub fn new(device: String) -> Self {
        V4l2HostDev {
            device,
            fd: -1,
            buffer: vec![],
            buf_addr: 0,
            buf_len: 0,
            hostfmt: CamFmt::new(),
            cur_fmt: CamFmt::new(),
        }
    }

    pub fn realize(self) -> Result<()> {
        Ok(())
    }

    // Below funcs are just encapsulation for v4l2 ioctls.
    fn map_buffer() -> Result<()> {
        Ok(())
    }
    fn query_cap() -> Result<()> {
        Ok(())
    }
    fn query_buffer() -> Result<()> {
        Ok(())
    }
    fn g_fmt() -> Result<()> {
        Ok(())
    }
    fn s_fmt() -> Result<()> {
        Ok(())
    }
    fn require_buf() -> Result<()> {
        Ok(())
    }
    fn query_buf() -> Result<()> {
        Ok(())
    }
    fn qbuf() -> Result<()> {
        Ok(())
    }
    fn dqbuf() -> Result<()> {
        Ok(())
    }
    fn stream_on() -> Result<()> {
        Ok(())
    }
    fn stream_off() -> Result<()> {
        Ok(())
    }
}

impl CameraHostdevOps for V4l2HostDev {
    fn init(&self) -> Result<()> {
        Ok(())
    }
    fn is_camera(&self) -> Result<bool> {
        Ok(true)
    }
    fn get_fmt(&self) -> Result<()> {
        Ok(())
    }
    fn set_fmt(&self, _fmt: u64) -> Result<()> {
        Ok(())
    }
    fn set_ctl(&self) -> Result<()> {
        Ok(())
    }

    fn video_stream_on(&self) -> Result<()> {
        Ok(())
    }
    fn video_stream_run(&self) -> Result<()> {
        Ok(())
    }
    fn video_stream_off(&self) -> Result<()> {
        Ok(())
    }
}
