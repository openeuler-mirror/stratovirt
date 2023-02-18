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

pub const FUSE_LOOKUP: u32 = 1;
pub const FUSE_FORGET: u32 = 2;
pub const FUSE_GETATTR: u32 = 3;
pub const FUSE_SETATTR: u32 = 4;
pub const FUSE_READLINK: u32 = 5;
pub const FUSE_SYMLINK: u32 = 6;
pub const FUSE_MKNOD: u32 = 8;
pub const FUSE_MKDIR: u32 = 9;
pub const FUSE_UNLINK: u32 = 10;
pub const FUSE_RMDIR: u32 = 11;
pub const FUSE_RENAME: u32 = 12;
pub const FUSE_LINK: u32 = 13;
pub const FUSE_OPEN: u32 = 14;
pub const FUSE_READ: u32 = 15;
pub const FUSE_WRITE: u32 = 16;
pub const FUSE_STATFS: u32 = 17;
pub const FUSE_RELEASE: u32 = 18;
pub const FUSE_FSYNC: u32 = 20;
pub const FUSE_SETXATTR: u32 = 21;
pub const FUSE_GETXATTR: u32 = 22;
pub const FUSE_LISTXATTR: u32 = 23;
pub const FUSE_REMOVEXATTR: u32 = 24;
pub const FUSE_FLUSH: u32 = 25;
pub const FUSE_INIT: u32 = 26;
pub const FUSE_OPENDIR: u32 = 27;
pub const FUSE_READDIR: u32 = 28;
pub const FUSE_RELEASEDIR: u32 = 29;
pub const FUSE_FSYNCDIR: u32 = 30;
pub const FUSE_GETLK: u32 = 31;
pub const FUSE_SETLK: u32 = 32;
pub const FUSE_SETLKW: u32 = 33;
pub const FUSE_ACCESS: u32 = 34;
pub const FUSE_CREATE: u32 = 35;
pub const FUSE_INTERRUPT: u32 = 36;
pub const FUSE_BMAP: u32 = 37;
pub const FUSE_DESTROY: u32 = 38;
pub const FUSE_IOCTL: u32 = 39;
pub const FUSE_POLL: u32 = 40;
pub const FUSE_NOTIFY_REPLY: u32 = 41;
pub const FUSE_BATCH_FORGET: u32 = 42;
pub const FUSE_FALLOCATE: u32 = 43;
pub const FUSE_READDIRPLUS: u32 = 44;
pub const FUSE_RENAME2: u32 = 45;
pub const FUSE_LSEEK: u32 = 46;
pub const FUSE_COPY_FILE_RANGE: u32 = 47;
pub const FUSE_SETUPMAPPING: u32 = 48;
pub const FUSE_REMOVEMAPPING: u32 = 49;

/// The kernel version which is supported by fuse messages.
pub const FUSE_KERNEL_VERSION: u32 = 7;
/// The minor version which is supported by fuse messages.
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 32;

/// The capability bit supports asynchronous read requests.
pub const FUSE_CAP_ASYNC_READ: u32 = 1 << 0;
/// The capability bit supports posix file locks.
pub const FUSE_CAP_POSIX_LOCKS: u32 = 1 << 1;
/// The capability bit supports the O_TRUNC open flag.
pub const FUSE_CAP_ATOMIC_O_TRUNC: u32 = 1 << 3;
/// The capability bit supports lookups of "." and "..".
pub const FUSE_CAP_EXPORT_SUPPORT: u32 = 1 << 4;
/// The capability bit don't apply umask to file mode on create operation.
pub const FUSE_CAP_DONT_MASK: u32 = 1 << 6;
/// The capability bit supports BSD file locks.
pub const FUSE_CAP_FLOCK_LOCKS: u32 = 1 << 10;
/// The capability bit automatically checks invalid cached file.
pub const FUSE_CAP_AUTO_INVAL_DATA: u32 = 1 << 12;
/// The capability bit supports readdirplus.
pub const FUSE_CAP_READDIRPLUS: u32 = 1 << 13;
/// The capability bit supports adaptive readdirplus.
pub const FUSE_CAP_READDIRPLUS_AUTO: u32 = 1 << 14;
/// The capability bit supports asynchronous direct I/O submission.
pub const FUSE_CAP_ASYNC_DIO: u32 = 1 << 15;
/// The capability bit supports for parallel directory operations.
pub const FUSE_CAP_PARALLEL_DIROPS: u32 = 1 << 18;
/// The capability bit supports POSIX ACLs.
pub const FUSE_CAP_POSIX_ACL: u32 = 1 << 19;

/// The supported bit that supports asynchronous read requests.
pub const FUSE_ASYNC_READ: u32 = 1 << 0;
/// The supported bit that supports posix file locks.
pub const FUSE_POSIX_LOCKS: u32 = 1 << 1;
/// The supported bit that supports the O_TRUNC open flag.
pub const FUSE_ATOMIC_O_TRUNC: u32 = 1 << 3;
/// The supported bit that supports lookups of "." and "..".
pub const FUSE_EXPORT_SUPPORT: u32 = 1 << 4;
/// The supported bit that don't apply umask to file mode on create operation.
pub const FUSE_DONT_MASK: u32 = 1 << 6;
/// The supported bit that supports BSD file locks.
pub const FUSE_FLOCK_LOCKS: u32 = 1 << 10;
/// The supported bit that automatically checks invalid cached file.
pub const FUSE_AUTO_INVAL_DATA: u32 = 1 << 12;
/// The supported bit that supports readdirplus.
pub const FUSE_DO_READDIRPLUS: u32 = 1 << 13;
/// The supported bit that supports adaptive readdirplus.
pub const FUSE_READDIRPLUS_AUTO: u32 = 1 << 14;
/// The supported bit that supports asynchronous direct I/O submission.
pub const FUSE_ASYNC_DIO: u32 = 1 << 15;
/// The capability bit that supports for parallel directory operations.
pub const FUSE_PARALLEL_DIROPS: u32 = 1 << 18;
/// The capability bit that supports POSIX ACLs.
pub const FUSE_POSIX_ACL: u32 = 1 << 20;
/// The capability bit that needs to reply the max number of pages in init fuse message.
pub const FUSE_MAX_PAGES: u32 = 1 << 22;

pub const FATTR_MODE: u32 = 1 << 0;
pub const FATTR_UID: u32 = 1 << 1;
pub const FATTR_GID: u32 = 1 << 2;
pub const FATTR_SIZE: u32 = 1 << 3;
pub const FATTR_ATIME: u32 = 1 << 4;
pub const FATTR_MTIME: u32 = 1 << 5;
pub const FATTR_FH: u32 = 1 << 6;
pub const FATTR_ATIME_NOW: u32 = 1 << 7;
pub const FATTR_MTIME_NOW: u32 = 1 << 8;
pub const FATTR_LOCKOWNER: u32 = 1 << 9;
pub const FATTR_CTIME: u32 = 1 << 10;

/// Successfully process the fuse message.
pub const FUSE_OK: i32 = 0;
pub const FUSE_SET_ATTR_MODE: u32 = 1 << 0;
pub const FUSE_SET_ATTR_UID: u32 = 1 << 1;
pub const FUSE_SET_ATTR_GID: u32 = 1 << 2;
pub const FUSE_SET_ATTR_SIZE: u32 = 1 << 3;
pub const FUSE_SET_ATTR_ATIME: u32 = 1 << 4;
pub const FUSE_SET_ATTR_MTIME: u32 = 1 << 5;
pub const FUSE_SET_ATTR_ATIME_NOW: u32 = 1 << 7;
pub const FUSE_SET_ATTR_MTIME_NOW: u32 = 1 << 8;
pub const FUSE_SET_ATTR_CTIME: u32 = 1 << 10;

use std::cmp;
use std::collections::VecDeque;
use std::ffi::CString;
use std::mem::size_of;
use std::sync::Arc;

use address_space::AddressSpace;
use log::error;
use util::byte_code::ByteCode;

use anyhow::{bail, Context, Result};
use virtio::ElemIovec;

/// Get the buffers from the element of virtio queue to parse fuse message or
/// reply fuse message.
pub struct FuseBuffer {
    /// Get the buffers to read or write from the element of virtio queue.
    pub bufs: VecDeque<ElemIovec>,
    /// The total size of the buffers from the element of virtio queue.
    bytes_total: usize,
    /// The processed bytes to read or write fuse message.
    bytes_processed: usize,
}

impl FuseBuffer {
    /// Construct a fuse buffer to process fuse message.
    ///
    /// # Arguments
    ///
    /// * `elem_iovec` - The vectors of IO vector element from virtio queue.
    pub fn new(elem_iovec: &[ElemIovec]) -> Self {
        let mut bytes_total = 0;
        let mut bufs = VecDeque::new();

        for iov in elem_iovec {
            bytes_total += iov.len as usize;
            bufs.push_back(*iov);
        }

        FuseBuffer {
            bufs,
            bytes_total,
            bytes_processed: 0_usize,
        }
    }

    /// Read the CString ending with '\0' from the fuse buffers.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - Address space mapped with StratoVirt.
    pub fn read_cstring(&mut self, sys_mem: &Arc<AddressSpace>) -> Result<CString> {
        let bytes_remain = self.bytes_total - self.bytes_processed;
        let mut buffer = vec![0; bytes_remain];

        let mut offset = 0_usize;
        for buf in &self.bufs {
            let mut slice = &mut buffer[offset..];
            let read_count = cmp::min(slice.len(), buf.len as usize);
            sys_mem
                .read(&mut slice, buf.addr, read_count as u64)
                .with_context(|| "Failed to read buffer for fuse req")?;
            offset += read_count;
        }

        let pos = match buffer.iter().position(|c| *c == b'\0') {
            Some(p) => p + 1,
            None => bail!("It is not a string"),
        };

        let str_slice = buffer.as_slice();
        let cstring = unsafe { CString::from_vec_unchecked(str_slice[0..pos].to_vec()) };

        // Remove the processed bytes in self.bufs.
        let mut need_read_count = pos;
        let bufs = self.bufs.clone();
        for buf in bufs {
            let read_count = cmp::min(need_read_count, buf.len as usize);
            self.bytes_processed += read_count;

            if let Some(buftmp) = self.bufs.pop_front() {
                if read_count < buftmp.len as usize {
                    // Add the remain length to the head of self.bufs.
                    let len = buftmp.len - read_count as u32;
                    let addr = buftmp.addr.unchecked_add(read_count as u64);
                    let remain = ElemIovec { addr, len };
                    self.bufs.push_front(remain);
                    break;
                } else {
                    need_read_count -= buftmp.len as usize;
                }
            }
        }

        Ok(cstring)
    }

    pub fn read_slice(
        &mut self,
        sys_mem: &Arc<AddressSpace>,
        dst: &mut [u8],
        count: usize,
    ) -> Result<()> {
        if dst.len() != count {
            bail!(
                "The length {} of dst slice is not equal to the count {}",
                dst.len(),
                count
            );
        }

        let read_end = match self.bytes_processed.checked_add(count) {
            Some(end_) => end_,
            None => bail!("The read count {} {} overflow", count, self.bytes_processed),
        };

        if read_end > self.bytes_total {
            bail!(
                "The read count {} exceeds maximum {}",
                read_end,
                self.bytes_total
            );
        }

        let bufs = self.bufs.clone();
        let mut offset = 0_usize;
        for buf in bufs {
            let mut slice = &mut dst[offset..];
            let read_count = cmp::min(slice.len(), buf.len as usize);

            sys_mem
                .read(&mut slice, buf.addr, read_count as u64)
                .with_context(|| "Failed to read buffer for fuse req")?;
            self.bytes_processed += read_count;
            offset += read_count;

            // Remove the processed bytes in self.bufs.
            if let Some(buftmp) = self.bufs.pop_front() {
                if read_count < buftmp.len as usize {
                    // Add the remain length to the head of self.bufs.
                    let len = buftmp.len - read_count as u32;
                    let addr = buftmp.addr.unchecked_add(read_count as u64);
                    let remain = ElemIovec { addr, len };
                    self.bufs.push_front(remain);
                    break;
                }
            }
        }

        Ok(())
    }

    /// read an object from the fuse buffers.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - Address space mapped with StratoVirt.
    ///
    /// # Note
    /// To use this method, it is necessary to implement `ByteCode` trait for your object.
    pub fn read_obj<T: ByteCode>(&mut self, sys_mem: &Arc<AddressSpace>) -> Result<T> {
        let mut obj = T::default();
        self.read_slice(sys_mem, obj.as_mut_bytes(), size_of::<T>())?;
        Ok(obj)
    }

    fn write_slice(&mut self, sys_mem: &Arc<AddressSpace>, src: &[u8], count: usize) -> Result<()> {
        if src.len() != count {
            bail!(
                "The length {} of src slice is not equal to the count {}",
                src.len(),
                count
            );
        }

        let write_end = match self.bytes_processed.checked_add(count) {
            Some(end_) => end_,
            None => bail!("The read count {} {} overflow", count, self.bytes_processed),
        };

        if write_end > self.bytes_total {
            bail!(
                "The read count {} exceeds maximum {}",
                write_end,
                self.bytes_total
            );
        }

        let bufs = self.bufs.clone();
        let mut offset = 0_usize;
        for buf in bufs {
            let mut slice = &src[offset..];
            let write_count = cmp::min(slice.len(), buf.len as usize);

            sys_mem
                .write(&mut slice, buf.addr, write_count as u64)
                .with_context(|| "Failed to read buffer for fuse req")?;
            self.bytes_processed += write_count;
            offset += write_count;

            // Remove the processed bytes in self.bufs.
            if let Some(buftmp) = self.bufs.pop_front() {
                if write_count < buftmp.len as usize {
                    // Add the remain length to the head of self.bufs.
                    let len = buftmp.len - write_count as u32;
                    let addr = buftmp.addr.unchecked_add(write_count as u64);
                    let remain = ElemIovec { addr, len };
                    self.bufs.push_front(remain);
                    break;
                }
            }
        }

        Ok(())
    }

    /// write an object to the fuse buffers.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - Address space mapped with StratoVirt.
    /// * `data` - The object the will be written to the fuse buffers.
    ///
    /// # Note
    /// To use this method, it is necessary to implement `ByteCode` trait for your object.
    pub fn write_obj<T: ByteCode>(&mut self, sys_mem: &Arc<AddressSpace>, data: &T) -> Result<()> {
        self.write_slice(sys_mem, data.as_bytes(), size_of::<T>())
    }

    /// Process the data for host file. if is_read is true, writing the data which is read from host
    /// file to the fuse buffers. if is_read is false, writing the data which is read from the fuse
    /// buffers to host file.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - Address space mapped with StratoVirt.
    /// * `fd` - The file descriptor in host.
    /// * `offset` - The offset which needs to be read and written in host file.
    /// * `size` - The size which needs to be read and written in host file.
    /// * `is_read` - If it is true, writing the data which is read from host file to the fuse buffers.
    /// If it is false, writing the data which is read from the fuse buffers to host file.
    pub fn access_file(
        &mut self,
        sys_mem: &Arc<AddressSpace>,
        fd: i32,
        offset: u64,
        size: u32,
        is_read: bool,
    ) -> Result<u32> {
        let mut remain_len = size;
        let mut file_off = offset;

        let mut index = 0;
        let mut bufs = self.bufs.clone();

        loop {
            if index >= bufs.len() {
                bail!("{} out of bufs's index", index);
            }

            let buf = if let Some(b) = bufs.get_mut(index) {
                b
            } else {
                bail!("{} out of bufs's bound", index);
            };

            let len = if remain_len < buf.len {
                remain_len
            } else {
                buf.len
            };

            let hva = if let Some(hva) = sys_mem.get_host_address(buf.addr) {
                hva
            } else {
                bail!("read file error: get hva failed.");
            };

            let iov = vec![libc::iovec {
                iov_base: hva as *mut libc::c_void,
                iov_len: len as usize,
            }];

            let ret = unsafe {
                if is_read {
                    libc::preadv(fd, iov.as_ptr(), iov.len() as i32, file_off as i64)
                } else {
                    libc::pwritev(fd, iov.as_ptr(), iov.len() as i32, file_off as i64)
                }
            } as u32;
            if ret == u32::MAX {
                bail!("read file error");
            }

            remain_len -= ret;
            file_off += ret as u64;

            self.bufs.pop_front();
            if ret < len {
                buf.addr.0 += ret as u64;
                buf.len -= ret;

                self.bufs.push_front(*buf);
            } else {
                index += 1;
            }

            if ret == 0 || remain_len == 0 {
                break; // finish.
            }
        }

        Ok(size - remain_len)
    }
}

/// Save the address and the length for replying fuse message.
pub struct FuseIovec<'a> {
    body: &'a [u8],
    len: usize,
}

impl<'a> FuseIovec<'a> {
    /// Convert an object to the struct of FuseIovec for replying fuse message.
    ///
    /// # Arguments
    ///
    /// * `obj` - The object the will be converted to the struct of FuseIovec.
    ///
    /// # Note
    /// To use this method, it is necessary to implement `ByteCode` trait for your object.
    pub fn from_obj<T: ByteCode>(obj: &'a T) -> Self {
        let body = obj.as_bytes();
        FuseIovec {
            body,
            len: body.len(),
        }
    }

    /// Convert a slice to the struct of FuseIovec for replying fuse message.
    ///
    /// # Arguments
    ///
    /// * `obj` - The slice the will be converted to the struct of FuseIovec.
    pub fn from_slice(body: &'a [u8]) -> Self {
        FuseIovec {
            body,
            len: body.len(),
        }
    }
}

/// Reply the fuse messages by writing the data to the writable fuse buffers.
///
/// # Arguments
///
/// * `writer` - The writable fuse buffers.
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `in_header` - The in_header reading from the read-only fuse buffers.
/// * `err` - The error number for processing the fuse message. If it is ok, set
/// error number to 0. If it is false, set error number from linux.
/// * `body_opt` - The body for replying the fuse message needs to be written
/// to fuse buffers.
/// * `body_len` - The length fo body for replying the fuse message. if the body
/// is none, set the length to 0.
pub fn reply_fuse_msg(
    writer: &mut FuseBuffer,
    sys_mem: &Arc<AddressSpace>,
    in_header: &FuseInHeader,
    err: i32,
    body_opt: Option<Vec<FuseIovec>>,
    body_len: usize,
) -> u32 {
    let len = size_of::<FuseOutHeader>() + body_len;
    let mut written_len = len as u32;

    let fuse_out_header = FuseOutHeader {
        len: len as u32,
        error: -err,
        unique: in_header.unique,
    };

    if let Err(e) = writer.write_obj(sys_mem, &fuse_out_header) {
        error!(
            "Failed to write out_header of fuse msg {}, {:?}",
            in_header.opcode, e,
        );
        written_len = 0_u32;
    };

    //write the body of fuse message in address space
    if let Some(body) = body_opt {
        for fuse_iov in body.iter() {
            if let Err(e) = writer.write_slice(sys_mem, fuse_iov.body, fuse_iov.len) {
                error!(
                    "Failed to write the body of fuse msg {}, {:?}",
                    in_header.opcode, e,
                );
                written_len = 0_u32;
            }
        }
    }

    written_len
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseInHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub padding: u32,
}

impl ByteCode for FuseInHeader {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseOutHeader {
    pub len: u32,
    pub error: i32,
    pub unique: u64,
}

impl ByteCode for FuseOutHeader {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub flags: u32,
}

impl ByteCode for FuseAttr {}

impl FuseAttr {
    pub fn from_stat(stat: libc::stat) -> Self {
        FuseAttr {
            ino: stat.st_ino,
            size: stat.st_size as u64,
            blocks: stat.st_blocks as u64,
            atime: stat.st_atime as u64,
            mtime: stat.st_mtime as u64,
            ctime: stat.st_ctime as u64,
            atimensec: stat.st_atime_nsec as u32,
            mtimensec: stat.st_mtime_nsec as u32,
            ctimensec: stat.st_ctime_nsec as u32,
            mode: stat.st_mode,
            nlink: stat.st_nlink as u32,
            uid: stat.st_uid,
            gid: stat.st_gid,
            rdev: stat.st_rdev as u32,
            blksize: stat.st_blksize as u32,
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseEntryOut {
    pub nodeid: u64,
    pub generation: u64,
    pub entry_valid: u64,
    pub attr_valid: u64,
    pub entry_valid_nsec: u32,
    pub attr_valid_nsec: u32,
    pub attr: FuseAttr,
}

impl ByteCode for FuseEntryOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseForgetIn {
    pub nlookup: u64,
}

impl ByteCode for FuseForgetIn {}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseAttrOut {
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub dummy: u32,
    pub attr: FuseAttr,
}

impl ByteCode for FuseAttrOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseGetAttrIn {
    pub getattr_flags: u32,
    pub dummy: u32,
    pub fh: u64,
}

impl ByteCode for FuseGetAttrIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseSetattrIn {
    pub valid: u32,
    pub padding: u32,
    pub fh: u64,
    pub size: u64,
    pub lock_owner: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub unused4: u32,
    pub uid: u32,
    pub gid: u32,
    pub unused5: u32,
}

impl ByteCode for FuseSetattrIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseMknodIn {
    pub mode: u32,
    pub rdev: u32,
    pub umask: u32,
    pub padding: u32,
}

impl ByteCode for FuseMknodIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseMkdirIn {
    pub mode: u32,
    pub umask: u32,
}

impl ByteCode for FuseMkdirIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseRenameIn {
    pub newdir: u64,
}

impl ByteCode for FuseRenameIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseLinkIn {
    pub oldnodeid: u64,
}

impl ByteCode for FuseLinkIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseOpenIn {
    pub flags: u32,
    pub unused: u32,
}

impl ByteCode for FuseOpenIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseOpenOut {
    pub fh: u64,
    pub open_flags: u32,
    pub padding: u32,
}

impl ByteCode for FuseOpenOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

impl ByteCode for FuseReadIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseWriteIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub write_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

impl ByteCode for FuseWriteIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseWriteOut {
    pub size: u32,
    pub padding: u32,
}

impl ByteCode for FuseWriteOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseKstatfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
    pub padding: u32,
    pub spare: [u32; 6],
}

impl ByteCode for FuseKstatfs {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseStatfsOut {
    pub st: FuseKstatfs,
}

impl ByteCode for FuseStatfsOut {}

impl FuseStatfsOut {
    pub fn from_stat(stat: libc::statvfs) -> Self {
        let st = FuseKstatfs {
            blocks: stat.f_blocks,
            bfree: stat.f_bfree,
            bavail: stat.f_bavail,
            files: stat.f_files,
            ffree: stat.f_ffree,
            bsize: stat.f_bsize as u32,
            namelen: stat.f_namemax as u32,
            frsize: stat.f_frsize as u32,
            ..Default::default()
        };

        FuseStatfsOut { st }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseReleaseIn {
    pub fh: u64,
    pub flags: u32,
    pub release_flags: u32,
    pub lock_owner: u64,
}

impl ByteCode for FuseReleaseIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseFsyncIn {
    pub fh: u64,
    pub fsync_flags: u32,
    pub padding: u32,
}

impl ByteCode for FuseFsyncIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseSetxattrIn {
    pub size: u32,
    pub flags: u32,
}

impl ByteCode for FuseSetxattrIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseGetxattrIn {
    pub size: u32,
    pub padding: u32,
}

impl ByteCode for FuseGetxattrIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseInitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
}

impl ByteCode for FuseInitIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseInitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
    pub map_alignment: u16,
    pub unused: [u32; 8],
}

impl ByteCode for FuseInitOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseDirent {
    pub ino: u64,
    pub off: u64,
    pub namelen: u32,
    pub type_: u32,
    pub name: [u8; 0],
}

impl ByteCode for FuseDirent {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseDirentplus {
    pub entry_out: FuseEntryOut,
    pub dirent: FuseDirent,
}

impl ByteCode for FuseDirentplus {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseFlushIn {
    pub fh: u64,
    pub unused: u32,
    pub padding: u32,
    pub lock_owner: u64,
}

impl ByteCode for FuseFlushIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseFileLock {
    pub start: u64,
    pub end: u64,
    pub lock_type: u32,
    pub pid: u32,
}

impl ByteCode for FuseFileLock {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseLkIn {
    pub fh: u64,
    pub owner: u64,
    pub lk: FuseFileLock,
    pub lk_flags: u32,
    pub padding: u32,
}

impl ByteCode for FuseLkIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseLkOut {
    pub lk: FuseFileLock,
}

impl ByteCode for FuseLkOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseCreateIn {
    pub flags: u32,
    pub mode: u32,
    pub umask: u32,
    pub padding: u32,
}

impl ByteCode for FuseCreateIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseBatchForgetIn {
    pub count: u32,
    pub dummy: u32,
}

impl ByteCode for FuseBatchForgetIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseForgetDataIn {
    pub ino: u64,
    pub nlookup: u64,
}

impl ByteCode for FuseForgetDataIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseFallocateIn {
    pub fh: u64,
    pub offset: u64,
    pub length: u64,
    pub mode: u32,
    pub padding: u32,
}

impl ByteCode for FuseFallocateIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseLseekIn {
    pub fh: u64,
    pub offset: u64,
    pub whence: u32,
    pub padding: u32,
}

impl ByteCode for FuseLseekIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseLseekOut {
    pub offset: u64,
}

impl ByteCode for FuseLseekOut {}
