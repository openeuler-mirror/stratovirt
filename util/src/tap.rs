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

use anyhow::{anyhow, bail, Context};
use std::fs::{File, OpenOptions};
use std::io::{Read, Result as IoResult, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref, ioctl_with_val};
use vmm_sys_util::{ioctl_ioc_nr, ioctl_ior_nr, ioctl_iow_nr};

use anyhow::Result;

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

ioctl_iow_nr!(TUNSETIFF, 84, 202, ::std::os::raw::c_int);
ioctl_ior_nr!(TUNGETFEATURES, 84, 207, ::std::os::raw::c_uint);
ioctl_iow_nr!(TUNSETOFFLOAD, 84, 208, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETVNETHDRSZ, 84, 216, ::std::os::raw::c_int);

#[repr(C)]
pub struct IfReq {
    ifr_name: [u8; 16],
    ifr_flags: u16,
}

pub struct Tap {
    pub file: File,
}

impl Tap {
    pub fn new(name: Option<&str>, fd: Option<RawFd>, queue_pairs: u16) -> Result<Self> {
        let file;

        if let Some(name) = name {
            if name.len() > 15 {
                return Err(anyhow!("Open tap {} failed, name too long.", name));
            }

            let mut ifr_name = [0_u8; 16];
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

            let ret = unsafe { ioctl_with_mut_ref(&file_, TUNSETIFF(), &mut if_req) };
            if ret < 0 {
                return Err(anyhow!(
                    "Failed to set tap ifr flags, error is {}",
                    std::io::Error::last_os_error()
                ));
            }

            file = file_;
        } else if let Some(fd) = fd {
            file = unsafe {
                libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
                File::from_raw_fd(fd)
            };
        } else {
            return Err(anyhow!(
                "Open tap failed, unsupported operation, error is {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut features = 0;
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

        Ok(Tap { file })
    }

    pub fn set_offload(&self, flags: u32) -> Result<()> {
        let ret = unsafe { ioctl_with_val(&self.file, TUNSETOFFLOAD(), flags as libc::c_ulong) };
        if ret < 0 {
            return Err(anyhow!("ioctl TUNSETOFFLOAD failed.".to_string()));
        }

        Ok(())
    }

    pub fn set_hdr_size(&self, len: u32) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(&self.file, TUNSETVNETHDRSZ(), &len) };
        if ret < 0 {
            return Err(anyhow!("ioctl TUNSETVNETHDRSZ failed.".to_string()));
        }

        Ok(())
    }

    pub fn has_ufo(&self) -> bool {
        let flags = TUN_F_CSUM | TUN_F_UFO;
        (unsafe { ioctl_with_val(&self.file, TUNSETOFFLOAD(), flags as libc::c_ulong) }) >= 0
    }

    pub fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.file.read(buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.file.write(buf)
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Clone for Tap {
    fn clone(&self) -> Self {
        Tap {
            file: self.file.try_clone().unwrap(),
        }
    }
}
