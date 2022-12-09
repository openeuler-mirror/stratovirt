// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use super::fs::FileSystem;
use super::fuse_msg::*;
use super::fuse_proc::*;
use address_space::AddressSpace;
use log::error;
use std::sync::{Arc, Mutex};
use virtio::Element;

/// The request of fuse message parsed from virtio queue.
pub struct FuseReq {
    desc_index: u16,
    reader: FuseBuffer,
    writer: FuseBuffer,
}

impl FuseReq {
    /// Construct a request of fuse message by the element from virtio queue.
    ///
    /// # Arguments
    ///
    /// * `elem` - The element parsed from virtio queue.
    pub fn new(elem: &Element) -> Self {
        FuseReq {
            desc_index: elem.index,
            reader: FuseBuffer::new(&elem.out_iovec),
            writer: FuseBuffer::new(&elem.in_iovec),
        }
    }

    /// The function to deal with fuse message from the request.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - Address space mapped with StratoVirt.
    /// * `fs` - The management of userspace filesystem.
    pub fn execute(
        &mut self,
        sys_mem: &Arc<AddressSpace>,
        fs: Arc<Mutex<FileSystem>>,
    ) -> (u16, u32) {
        let in_header = match self.reader.read_obj::<FuseInHeader>(sys_mem) {
            Ok(data) => data,
            Err(err) => {
                error!("Failed to read the header of fuse msg, {:?}", err,);
                return (self.desc_index, 0);
            }
        };

        let written_len = match in_header.opcode {
            FUSE_LOOKUP => {
                do_fuse_lookup(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_FORGET => do_fuse_forget(sys_mem, fs, &mut self.reader, &in_header),
            FUSE_GETATTR => do_fuse_getattr(sys_mem, fs, &mut self.writer, &in_header),
            FUSE_SETATTR => {
                do_fuse_setattr(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_READLINK => do_fuse_readlink(sys_mem, fs, &mut self.writer, &in_header),
            FUSE_SYMLINK => {
                do_fuse_symlink(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_MKNOD => {
                do_fuse_mknod(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_MKDIR => {
                do_fuse_mkdir(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_UNLINK => {
                do_fuse_unlink(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_RMDIR => {
                do_fuse_rmdir(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_RENAME => {
                do_fuse_rename(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_LINK => do_fuse_link(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header),
            FUSE_OPEN => do_fuse_open(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header),
            FUSE_READ => do_fuse_read(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header),
            FUSE_WRITE => {
                do_fuse_write(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_STATFS => do_fuse_statfs(sys_mem, fs, &mut self.writer, &in_header),
            FUSE_RELEASE => {
                do_fuse_release(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_FSYNC => {
                do_fuse_fsync(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_SETXATTR => {
                do_fuse_setxattr(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_GETXATTR => {
                do_fuse_getxattr(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_LISTXATTR => {
                do_fuse_listxattr(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_REMOVEXATTR => {
                do_fuse_removexattr(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_FLUSH => {
                do_fuse_flush(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_INIT => do_fuse_init(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header),
            FUSE_OPENDIR => {
                do_fuse_opendir(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_READDIR => {
                do_fuse_readdir(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_RELEASEDIR => {
                do_fuse_releasedir(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_FSYNCDIR => {
                do_fuse_fsyncdir(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_GETLK => {
                do_fuse_getlk(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_SETLK => {
                do_fuse_setlk(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_SETLKW => {
                do_fuse_setlkw(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_CREATE => {
                do_fuse_create(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_DESTROY => do_fuse_destroy(sys_mem, fs, &mut self.writer, &in_header),
            FUSE_BATCH_FORGET => do_fuse_batch_forget(sys_mem, fs, &mut self.reader),
            FUSE_FALLOCATE => {
                do_fuse_fallocate(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_READDIRPLUS => {
                do_fuse_readdirplus(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_LSEEK => {
                do_fuse_lseek(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            FUSE_IOCTL => {
                do_fuse_ioctl(sys_mem, fs, &mut self.reader, &mut self.writer, &in_header)
            }
            _ => {
                error!("The fuse msg {} is unsupported", in_header.opcode);
                reply_fuse_msg(
                    &mut self.writer,
                    sys_mem,
                    &in_header,
                    libc::ENOSYS,
                    None,
                    0_usize,
                )
            }
        };

        // return the index of element and the length which is written
        (self.desc_index, written_len)
    }
}
