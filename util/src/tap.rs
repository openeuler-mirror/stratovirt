// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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
use std::io::{ErrorKind, Read, Result as IoResult, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use log::error;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref, ioctl_with_val};
use vmm_sys_util::{ioctl_ioc_nr, ioctl_ior_nr, ioctl_iow_nr};

use crate::aio::Iovec;

const IFF_ATTACH_QUEUE: u16 = 0x0200;
const IFF_DETACH_QUEUE: u16 = 0x0400;

pub const TUN_F_CSUM: u32 = 1;
pub const TUN_F_TSO4: u32 = 2;
pub const TUN_F_TSO6: u32 = 4;
pub const TUN_F_TSO_ECN: u32 = 8;
pub const TUN_F_UFO: u32 = 16;
pub const TUN_F_VIRTIO: u32 = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_UFO;

const IFF_TAP: u16 = 0x02;
pub const IFF_MULTI_QUEUE: u16 = 0x100;
const IFF_NO_PI: u16 = 0x1000;
const IFF_VNET_HDR: u16 = 0x4000;
const TUNTAP_PATH: &str = "/dev/net/tun";
const IFNAME_SIZE: usize = 16;

ioctl_iow_nr!(TUNSETIFF, 84, 202, ::std::os::raw::c_int);
ioctl_ior_nr!(TUNGETFEATURES, 84, 207, ::std::os::raw::c_uint);
ioctl_iow_nr!(TUNSETOFFLOAD, 84, 208, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETVNETHDRSZ, 84, 216, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETQUEUE, 84, 217, ::std::os::raw::c_int);

#[repr(C)]
pub struct IfReq {
    ifr_name: [u8; IFNAME_SIZE],
    ifr_flags: u16,
}

#[derive(Clone)]
pub struct Tap {
    pub file: Arc<File>,
    pub enabled: bool,
    pub upload_stats: Arc<AtomicU64>,
    pub download_stats: Arc<AtomicU64>,
}

impl Tap {
    pub fn new(name: Option<&str>, fd: Option<RawFd>, queue_pairs: u16) -> Result<Self> {
        let file;

        if let Some(name) = name {
            if name.len() > IFNAME_SIZE - 1 {
                return Err(anyhow!("Open tap {} failed, name too long.", name));
            }

            let mut ifr_name = [0_u8; IFNAME_SIZE];
            let (left, _) = ifr_name.split_at_mut(name.len());
            left.copy_from_slice(name.as_bytes());

            let mut if_req = IfReq {
                ifr_name,
                ifr_flags: IFF_TAP | IFF_NO_PI | IFF_VNET_HDR,
            };

            if queue_pairs > 1 {
                if_req.ifr_flags |= IFF_MULTI_QUEUE;
            }

            let file_ = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(TUNTAP_PATH)
                .with_context(|| format!("Open {} failed.", TUNTAP_PATH))?;

            // SAFETY: The parameter of file can be guaranteed to be legal, and other parameters are constant.
            let ret = unsafe { ioctl_with_mut_ref(&file_, TUNSETIFF(), &mut if_req) };
            if ret < 0 {
                return Err(anyhow!(
                    "Failed to set tap ifr flags, error is {}",
                    std::io::Error::last_os_error()
                ));
            }

            file = file_;
        } else if let Some(fd) = fd {
            let fcnt_arg = FcntlArg::F_SETFL(OFlag::from_bits(libc::O_NONBLOCK).unwrap());
            fcntl(fd, fcnt_arg)?;
            // SAFETY: The fd has been verified.
            file = unsafe { File::from_raw_fd(fd) };
        } else {
            return Err(anyhow!(
                "Open tap failed, unsupported operation, error is {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut features: u16 = 0;
        // SAFETY: The parameter of file can be guaranteed to be legal, and other parameters are constant.
        let ret = unsafe { ioctl_with_mut_ref(&file, TUNGETFEATURES(), &mut features) };
        if ret < 0 {
            return Err(anyhow!(
                "Failed to get tap features, error is {}.",
                std::io::Error::last_os_error()
            ));
        }

        if (features & IFF_MULTI_QUEUE == 0) && queue_pairs > 1 {
            bail!("Needs multiqueue, but no kernel support for IFF_MULTI_QUEUE available");
        }

        Ok(Tap {
            file: Arc::new(file),
            enabled: true,
            upload_stats: Arc::new(AtomicU64::new(0)),
            download_stats: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn set_offload(&self, flags: u32) -> Result<()> {
        let ret =
            // SAFETY: The parameter of file can be guaranteed to be legal, and other parameters are constant.
            unsafe { ioctl_with_val(self.file.as_ref(), TUNSETOFFLOAD(), u64::from(flags)) };
        if ret < 0 {
            return Err(anyhow!("ioctl TUNSETOFFLOAD failed.".to_string()));
        }

        Ok(())
    }

    pub fn set_hdr_size(&self, len: u32) -> Result<()> {
        // SAFETY: The parameter of file can be guaranteed to be legal, and other parameters are constant.
        let ret = unsafe { ioctl_with_ref(self.file.as_ref(), TUNSETVNETHDRSZ(), &len) };
        if ret < 0 {
            return Err(anyhow!("ioctl TUNSETVNETHDRSZ failed.".to_string()));
        }

        Ok(())
    }

    pub fn has_ufo(&self) -> bool {
        let flags = TUN_F_CSUM | TUN_F_UFO;
        (
            // SAFETY: The parameter of file can be guaranteed to be legal, and other parameters are constant.
            unsafe { ioctl_with_val(self.file.as_ref(), TUNSETOFFLOAD(), u64::from(flags)) }
        ) >= 0
    }

    pub fn set_queue(&mut self, enable: bool) -> i32 {
        if enable == self.enabled {
            return 0;
        }
        let ifr_flags = if enable {
            IFF_ATTACH_QUEUE
        } else {
            IFF_DETACH_QUEUE
        };
        let mut if_req = IfReq {
            ifr_name: [0_u8; IFNAME_SIZE],
            ifr_flags,
        };

        // SAFETY: The parameter of file can be guaranteed to be legal, and other parameters are constant.
        let ret = unsafe { ioctl_with_mut_ref(self.file.as_ref(), TUNSETQUEUE(), &mut if_req) };
        if ret == 0 {
            self.enabled = enable;
        } else {
            error!(
                "Failed to set queue, flags is {}, error is {}",
                ifr_flags,
                std::io::Error::last_os_error()
            );
        }
        ret
    }

    pub fn receive_packets(&self, iovecs: &[Iovec]) -> i32 {
        // SAFETY: the arguments of readv has been checked and is correct.
        let size = unsafe {
            libc::readv(
                self.as_raw_fd() as libc::c_int,
                iovecs.as_ptr() as *const libc::iovec,
                iovecs.len() as libc::c_int,
            )
        } as i32;
        if size < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                return size;
            }

            // If the backend tap device is removed, readv returns less than 0.
            // At this time, the content in the tap needs to be cleaned up.
            // Here, read is called to process, otherwise handle_rx may be triggered all the time.
            let mut buf = [0; 1024];
            match self.read(&mut buf) {
                Ok(cnt) => error!("Failed to call readv but tap read is ok: cnt {}", cnt),
                Err(e) => {
                    // When the backend tap device is abnormally removed, read return EBADFD.
                    error!("Failed to read tap: {:?}", e);
                }
            }
            error!("Failed to call readv for net handle_rx: {:?}", e);
        } else {
            self.download_stats.fetch_add(size as u64, Ordering::SeqCst);
        }

        size
    }

    pub fn send_packets(&self, iovecs: &[Iovec]) -> i8 {
        loop {
            // SAFETY: the arguments of writev has been checked and is correct.
            let size = unsafe {
                libc::writev(
                    self.as_raw_fd(),
                    iovecs.as_ptr() as *const libc::iovec,
                    iovecs.len() as libc::c_int,
                )
            };
            if size < 0 {
                let e = std::io::Error::last_os_error();
                match e.kind() {
                    ErrorKind::Interrupted => continue,
                    ErrorKind::WouldBlock => return -1_i8,
                    // Ignore other errors which can not be handled.
                    _ => error!("Failed to call writev for net handle_tx: {:?}", e),
                }
            } else {
                self.upload_stats.fetch_add(size as u64, Ordering::SeqCst);
            }

            break;
        }
        0_i8
    }

    pub fn read(&self, buf: &mut [u8]) -> IoResult<usize> {
        self.file.as_ref().read(buf)
    }

    pub fn write(&self, buf: &[u8]) -> IoResult<usize> {
        self.file.as_ref().write(buf)
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}
