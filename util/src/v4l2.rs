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

use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::prelude::{AsRawFd, OpenOptionsExt, RawFd};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use log::{debug, error};
use v4l2_sys_mit::{
    v4l2_buffer, v4l2_capability, v4l2_fmtdesc, v4l2_format, v4l2_frmivalenum, v4l2_frmsizeenum,
    v4l2_requestbuffers, v4l2_streamparm,
};
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref};
use vmm_sys_util::{ioctl_ioc_nr, ioctl_ior_nr, ioctl_iow_nr, ioctl_iowr_nr};

use crate::aio::Iovec;

const VIDEO: u32 = 86;

ioctl_ior_nr!(VIDIOC_QUERYCAP, VIDEO, 0, v4l2_capability);
ioctl_iowr_nr!(VIDIOC_ENUM_FMT, VIDEO, 2, v4l2_fmtdesc);
ioctl_iowr_nr!(VIDIOC_G_FMT, VIDEO, 4, v4l2_format);
ioctl_iowr_nr!(VIDIOC_S_FMT, VIDEO, 5, v4l2_format);
ioctl_iowr_nr!(VIDIOC_REQBUFS, VIDEO, 8, v4l2_requestbuffers);
ioctl_iowr_nr!(VIDIOC_QUERYBUF, VIDEO, 9, v4l2_buffer);
ioctl_iowr_nr!(VIDIOC_QBUF, VIDEO, 15, v4l2_buffer);
ioctl_iowr_nr!(VIDIOC_DQBUF, VIDEO, 17, v4l2_buffer);
ioctl_iow_nr!(VIDIOC_STREAMON, VIDEO, 18, std::os::raw::c_int);
ioctl_iow_nr!(VIDIOC_STREAMOFF, VIDEO, 19, std::os::raw::c_int);
ioctl_iowr_nr!(VIDIOC_S_PARM, VIDEO, 22, v4l2_streamparm);
ioctl_iowr_nr!(VIDIOC_ENUM_FRAMESIZES, VIDEO, 74, v4l2_frmsizeenum);
ioctl_iowr_nr!(VIDIOC_ENUM_FRAMEINTERVALS, VIDEO, 75, v4l2_frmivalenum);

pub struct V4l2Backend {
    /// V4L2 backend path, such as /dev/video0.
    path: String,
    /// V4L2 backend device fd.
    fd: File,
    /// V4L2 image buffer.
    pub buffer: Arc<Mutex<Vec<Iovec>>>,
}

impl Drop for V4l2Backend {
    fn drop(&mut self) {
        debug!("Drop v4l2 backend fd {}", self.as_raw_fd());
        if let Err(e) = self.release_buffers() {
            error!("Failed to release buffer for {}, {:?}", self.path, e);
        }
    }
}

impl V4l2Backend {
    pub fn new(path: String, buf_cnt: usize) -> Result<Self> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)
            .with_context(|| format!("Failed to open v4l2 backend {}.", &path))?;
        Ok(Self {
            path,
            fd,
            buffer: Arc::new(Mutex::new(vec![Iovec::new(0, 0); buf_cnt])),
        })
    }

    pub fn query_cap(&self) -> Result<v4l2_capability> {
        let mut cap = new_init::<v4l2_capability>();
        // SAFETY: self.fd is created in function new().
        let ret = unsafe { ioctl_with_mut_ref(self, VIDIOC_QUERYCAP(), &mut cap) };
        if ret < 0 {
            bail!(
                "Failed to query cap, error {:?}",
                std::io::Error::last_os_error()
            );
        }
        Ok(cap)
    }

    pub fn set_format(&self, fmt: &v4l2_format) -> Result<()> {
        // SAFETY: self.fd is created in function new().
        let ret = unsafe { ioctl_with_ref(self, VIDIOC_S_FMT(), fmt) };
        if ret < 0 {
            bail!(
                "Failed to set format, error {:?}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    pub fn request_buffers(&self, bufs: &mut v4l2_requestbuffers) -> Result<()> {
        // Ensure that there are no residual buffers.
        self.release_buffers()?;
        let mut locked_buf = self.buffer.lock().unwrap();
        let cnt = locked_buf.len() as u32;
        // Ensure the count is equal to the length of buffer.
        bufs.count = cnt;
        // SAFETY: self.fd is created in function new().
        let ret = unsafe { ioctl_with_ref(self, VIDIOC_REQBUFS(), bufs) };
        if ret < 0 {
            bail!(
                "Failed to request buffers, error {:?}",
                std::io::Error::last_os_error()
            );
        }

        for i in 0..cnt {
            let mut buf = new_init::<v4l2_buffer>();
            buf.index = i;
            buf.type_ = bufs.type_;
            buf.memory = bufs.memory;
            // SAFETY: self.fd is created in function new().
            let ret = unsafe { ioctl_with_ref(self, VIDIOC_QUERYBUF(), &buf) };
            if ret < 0 {
                bail!(
                    "Failed to query buffer {}, error {:?}",
                    i,
                    std::io::Error::last_os_error()
                );
            }

            // SAFETY:
            // 1. self.fd is created in function new().
            // 2. buf can be guaranteed not be null.
            let ret = unsafe {
                libc::mmap(
                    std::ptr::null_mut() as *mut libc::c_void,
                    buf.length as libc::size_t,
                    libc::PROT_WRITE | libc::PROT_READ,
                    libc::MAP_SHARED,
                    self.as_raw_fd(),
                    buf.m.offset.into(),
                )
            };
            if ret == libc::MAP_FAILED {
                bail!(
                    "Failed to mmap for buffer {}, error {:?}",
                    i,
                    std::io::Error::last_os_error()
                );
            }
            locked_buf[i as usize].iov_base = ret as u64;
            locked_buf[i as usize].iov_len = buf.length as u64;
            // Queue buffer to get data.
            self.queue_buffer(&buf)?;
        }
        Ok(())
    }

    pub fn release_buffers(&self) -> Result<()> {
        let mut locked_buf = self.buffer.lock().unwrap();
        for buf in locked_buf.iter_mut() {
            if buf.is_none() {
                continue;
            }
            // SAFETY: buf can be guaranteed not be null.
            let ret = unsafe {
                libc::munmap(
                    buf.iov_base as *mut libc::c_void,
                    buf.iov_len as libc::size_t,
                )
            };
            if ret < 0 {
                bail!(
                    "Failed to release buffers, error {:?}",
                    std::io::Error::last_os_error()
                );
            }
            buf.iov_base = 0;
            buf.iov_len = 0;
        }
        Ok(())
    }

    pub fn stream_on(&self, vtype: std::os::raw::c_int) -> Result<()> {
        // SAFETY: self.fd is created in function new().
        let ret = unsafe { ioctl_with_ref(self, VIDIOC_STREAMON(), &vtype) };
        if ret < 0 {
            bail!(
                "Failed to stream on, error {:?}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    pub fn stream_off(&self, vtype: std::os::raw::c_int) -> Result<()> {
        // SAFETY: self.fd is created in function new().
        let ret = unsafe { ioctl_with_ref(self, VIDIOC_STREAMOFF(), &vtype) };
        if ret < 0 {
            bail!(
                "Failed to stream off, error {:?}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    pub fn queue_buffer(&self, buf: &v4l2_buffer) -> Result<()> {
        // SAFETY: self.fd is created in function new().
        let ret = unsafe { ioctl_with_ref(self, VIDIOC_QBUF(), buf) };
        if ret < 0 {
            bail!(
                "Failed to queue buffer, error {:?}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    pub fn dequeue_buffer(&self, buf: &v4l2_buffer) -> Result<bool> {
        // SAFETY: self.fd is created in function new().
        let ret = unsafe { ioctl_with_ref(self, VIDIOC_DQBUF(), buf) };
        if ret < 0 {
            if nix::errno::errno() == libc::EAGAIN {
                return Ok(false);
            }
            bail!(
                "Failed to dequeue buffer, error {:?}",
                std::io::Error::last_os_error()
            );
        }
        Ok(true)
    }

    pub fn enum_format(&self, desc: &mut v4l2_fmtdesc) -> Result<bool> {
        // SAFETY: self.fd is created in function new().
        let ret = unsafe { ioctl_with_mut_ref(self, VIDIOC_ENUM_FMT(), desc) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::InvalidInput {
                return Ok(true);
            }
            bail!("Failed to enumerate format, error {:?}", err);
        }
        Ok(false)
    }

    pub fn enum_frame_size(&self, frmsize: &mut v4l2_frmsizeenum) -> Result<bool> {
        // SAFETY: self.fd is created in function new().
        let ret = unsafe { ioctl_with_mut_ref(self, VIDIOC_ENUM_FRAMESIZES(), frmsize) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::InvalidInput {
                return Ok(true);
            }
            bail!("Failed to enumerate frame size, error {:?}", err);
        }
        Ok(false)
    }

    pub fn enum_frame_interval(&self, frame_val: &mut v4l2_frmivalenum) -> Result<bool> {
        // SAFETY: self.fd is created in function new().
        let ret = unsafe { ioctl_with_mut_ref(self, VIDIOC_ENUM_FRAMEINTERVALS(), frame_val) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::InvalidInput {
                return Ok(true);
            }
            bail!("Failed to enumerate frame interval, error {:?}", err);
        }
        Ok(false)
    }

    pub fn set_stream_parameter(&self, parm: &v4l2_streamparm) -> Result<()> {
        // SAFETY: self.fd is created in function new().
        let ret = unsafe { ioctl_with_ref(self, VIDIOC_S_PARM(), parm) };
        if ret < 0 {
            bail!(
                "Failed to set stream parameter, error {:?}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }
}

impl AsRawFd for V4l2Backend {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

pub fn new_init<T>() -> T {
    let mut s = ::std::mem::MaybeUninit::<T>::uninit();
    // SAFETY: s can be guaranteed not be null.
    unsafe {
        ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
        s.assume_init()
    }
}
