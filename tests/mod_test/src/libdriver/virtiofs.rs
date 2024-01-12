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

use std::mem::size_of;

use util::byte_code::ByteCode;

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
/// The supported bit that supports for parallel directory operations.
pub const FUSE_PARALLEL_DIROPS: u32 = 1 << 18;
/// The supported bit that supports POSIX ACLs.
pub const FUSE_POSIX_ACL: u32 = 1 << 20;
/// The supported bit that needs to reply the max number of pages in init fuse message.
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

pub const XATTR_CREATE: u32 = 0x1; // set value, fail if attr already exists
pub const XATTR_REPLACE: u32 = 0x2; // set value, fail if attr does not exist

pub const TEST_MAX_READAHEAD: u32 = 1048576;

pub const TEST_FLAG: u32 = FUSE_ASYNC_READ
    | FUSE_POSIX_LOCKS
    | FUSE_ATOMIC_O_TRUNC
    | FUSE_EXPORT_SUPPORT
    | FUSE_DONT_MASK
    | FUSE_FLOCK_LOCKS
    | FUSE_AUTO_INVAL_DATA
    | FUSE_DO_READDIRPLUS
    | FUSE_READDIRPLUS_AUTO
    | FUSE_ASYNC_DIO
    | FUSE_PARALLEL_DIROPS
    | FUSE_POSIX_ACL
    | FUSE_MAX_PAGES;

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

impl FuseInHeader {
    pub fn new(
        len: u32,
        opcode: u32,
        unique: u64,
        nodeid: u64,
        uid: u32,
        gid: u32,
        pid: u32,
        padding: u32,
    ) -> FuseInHeader {
        FuseInHeader {
            len,
            opcode,
            unique,
            nodeid,
            uid,
            gid,
            pid,
            padding,
        }
    }
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
pub struct FuseForgetOut {
    pub dummy: u64,
}

impl ByteCode for FuseForgetOut {}

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
#[derive(Debug, Default, Clone)]
pub struct FuseMknodIn {
    pub mode: u32,
    pub rdev: u32,
    pub umask: u32,
    pub padding: u32,
    pub name: String,
}

impl FuseMknodIn {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.append(&mut self.mode.as_bytes().to_vec());
        bytes.append(&mut self.rdev.as_bytes().to_vec());
        bytes.append(&mut self.umask.as_bytes().to_vec());
        bytes.append(&mut self.padding.as_bytes().to_vec());
        bytes.append(&mut self.name.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes
    }

    pub fn len(&self) -> usize {
        size_of::<u32>() * 4 + self.name.len() + 1
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct FuseRenameIn {
    pub newdir: u64,
    pub oldname: String,
    pub newname: String,
}

impl FuseRenameIn {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.append(&mut self.newdir.as_bytes().to_vec());
        bytes.append(&mut self.oldname.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes.append(&mut self.newname.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes
    }

    pub fn len(&self) -> usize {
        size_of::<u64>() + self.oldname.len() + self.newname.len() + 2
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct FuseLinkIn {
    pub oldnodeid: u64,
    pub newname: String,
}

impl FuseLinkIn {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.append(&mut self.oldnodeid.as_bytes().to_vec());
        bytes.append(&mut self.newname.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes
    }

    pub fn len(&self) -> usize {
        size_of::<u64>() + self.newname.len() + 1
    }
}

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
#[derive(Debug, Default, Clone)]
pub struct FuseWriteIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub write_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
    pub write_buf: String,
}

impl FuseWriteIn {
    pub fn new(fh: u64, offset: u64, write_buf: String) -> Self {
        FuseWriteIn {
            fh,
            offset,
            size: (write_buf.len() + 1) as u32,
            write_flags: 0_u32,
            lock_owner: 0_u64,
            flags: O_WRONLY,
            padding: 0,
            write_buf,
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.append(&mut self.fh.as_bytes().to_vec());
        bytes.append(&mut self.offset.as_bytes().to_vec());
        bytes.append(&mut self.size.as_bytes().to_vec());
        bytes.append(&mut self.write_flags.as_bytes().to_vec());
        bytes.append(&mut self.lock_owner.as_bytes().to_vec());
        bytes.append(&mut self.flags.as_bytes().to_vec());
        bytes.append(&mut self.padding.as_bytes().to_vec());
        bytes.append(&mut self.write_buf.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes
    }
}

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
#[derive(Debug, Default, Clone)]
pub struct FuseSetxattrIn {
    pub size: u32,
    pub flags: u32,
    pub name: String,
    pub value: String,
}

impl FuseSetxattrIn {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.append(&mut self.size.as_bytes().to_vec());
        bytes.append(&mut self.flags.as_bytes().to_vec());
        bytes.append(&mut self.name.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes.append(&mut self.value.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes
    }

    pub fn len(&self) -> usize {
        size_of::<u32>() * 2 + self.name.len() + self.value.len() + 2
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct FuseGetxattrIn {
    pub size: u32,
    pub padding: u32,
    pub name: String,
}

impl FuseGetxattrIn {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.append(&mut self.size.as_bytes().to_vec());
        bytes.append(&mut self.padding.as_bytes().to_vec());
        bytes.append(&mut self.name.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes
    }

    pub fn len(&self) -> usize {
        size_of::<u32>() * 2 + self.name.len() + 1
    }
}

pub struct FuseRemoveXattrIn {
    pub name: String,
}

impl FuseRemoveXattrIn {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.append(&mut self.name.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes
    }
}

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

pub const F_RDLCK: u32 = 0;
pub const F_WRLCK: u32 = 1;
pub const F_UNLCK: u32 = 2;

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
#[derive(Debug, Default, Clone)]
pub struct FuseCreateIn {
    pub flags: u32,
    pub mode: u32,
    pub umask: u32,
    pub padding: u32,
    pub name: String,
}

impl FuseCreateIn {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.append(&mut self.flags.as_bytes().to_vec());
        bytes.append(&mut self.mode.as_bytes().to_vec());
        bytes.append(&mut self.umask.as_bytes().to_vec());
        bytes.append(&mut self.padding.as_bytes().to_vec());
        bytes.append(&mut self.name.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FuseCreateOut {
    pub create_out: FuseEntryOut,
    pub open_out: FuseOpenOut,
}

impl ByteCode for FuseCreateOut {}

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

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct FuseLookupIn {
    pub name: String,
}

impl FuseLookupIn {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.append(&mut self.name.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes
    }
}

pub struct FuseUnlinkrIn {
    pub name: String,
}

impl FuseUnlinkrIn {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.append(&mut self.name.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes
    }

    pub fn len(&self) -> usize {
        self.name.len() + 1
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct FusesysmlinkIn {
    pub name: String,
    pub linkname: String,
}

impl FusesysmlinkIn {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.append(&mut self.name.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes.append(&mut self.linkname.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct FuseMkdirIn {
    pub mode: u32,
    pub umask: u32,
    pub name: String,
}

impl FuseMkdirIn {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.append(&mut self.mode.as_bytes().to_vec());
        bytes.append(&mut self.umask.as_bytes().to_vec());
        bytes.append(&mut self.name.as_bytes().to_vec());
        bytes.append(&mut vec![0]);
        bytes
    }

    pub fn len(&self) -> usize {
        size_of::<u32>() * 2 + self.name.len() + 1
    }
}

pub enum SeccompAction {
    None,
    Kill,
    Log,
    Trap,
}

impl std::fmt::Display for SeccompAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SeccompAction::None => "none",
                SeccompAction::Kill => "kill",
                SeccompAction::Log => "log",
                SeccompAction::Trap => "trap",
            }
        )
    }
}

pub enum SandBoxMechanism {
    Chroot,
    Namespace,
}

impl std::fmt::Display for SandBoxMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SandBoxMechanism::Chroot => "chroot",
                SandBoxMechanism::Namespace => "namespace",
            }
        )
    }
}

// Read only.
pub const O_RDONLY: u32 = 0o000000;
// Write only.
pub const O_WRONLY: u32 = 0o000001;
// Read-Write.
pub const O_RDWR: u32 = 0o000002;
pub const O_CREAT: u32 = 0o000100;
pub const O_TRUNC: u32 = 0o001000;
pub const O_NONBLOCK: u32 = 0o004000;
// Direct disk access hint.
pub const O_DIRECT: u32 = 0o040000;
// Don't follow links.
pub const O_NOFOLLOW: u32 = 0o400000;

// lseek.
pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;
