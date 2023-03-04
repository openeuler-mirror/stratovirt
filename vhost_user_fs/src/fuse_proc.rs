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

const MAX_WRITE_SIZE: u32 = 1 << 20;

use super::fs::FileSystem;
use super::fuse_msg::*;
use address_space::AddressSpace;
use log::error;
use std::convert::TryInto;
use std::ffi::CString;
use std::mem;
use std::sync::{Arc, Mutex};

fn is_safe_path(path: &CString) -> bool {
    let path_str = match path.clone().into_string() {
        Ok(str_) => str_,
        Err(_e) => return false,
    };

    if path_str.find('/').is_some() {
        return false;
    }

    // Check if the path is "." or ".."
    let bytes = path_str.as_bytes();
    if bytes[0] == 0x2e && (bytes[1] == 0x0 || (bytes[1] == 0x2e && bytes[2] == 0x0)) {
        return false;
    }

    true
}

fn is_empty_path(path: &CString) -> bool {
    let bytes = path.clone().into_bytes();

    bytes[0] == 0x0
}

/// Process the fuse message of FUSE_LOOKUP.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_lookup(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let name = match reader.read_cstring(sys_mem) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read name for lookup, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let mut fuse_attr = FuseAttr::default();
    let mut node_id = 0_u64;
    let ret = fs.lock().unwrap().lookup(
        in_header.nodeid as usize,
        name,
        &mut node_id,
        &mut fuse_attr,
    );

    if ret == FUSE_OK {
        let entry_out = FuseEntryOut {
            nodeid: node_id,
            generation: 0,
            entry_valid: 0,
            entry_valid_nsec: 0,
            attr_valid: 0,
            attr_valid_nsec: 0,
            attr: fuse_attr,
        };
        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            ret,
            Some(vec![FuseIovec::from_obj(&entry_out)]),
            mem::size_of::<FuseEntryOut>(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_FORGET.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_forget(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let forget_in = match reader.read_obj::<FuseForgetIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for forget_in, {:?}", e);
            return 0_u32;
        }
    };

    fs.lock()
        .unwrap()
        .forget(in_header.nodeid as usize, forget_in.nlookup);
    0_u32
}

/// Process the fuse message of FUSE_GETATTR.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_getattr(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let mut fuse_attr = FuseAttr::default();
    let ret = fs
        .lock()
        .unwrap()
        .getattr(in_header.nodeid as usize, &mut fuse_attr);
    if ret == 0 {
        let attr_out = FuseAttrOut {
            attr_valid: 1,
            attr_valid_nsec: 0,
            dummy: 0,
            attr: fuse_attr,
        };

        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            ret,
            Some(vec![FuseIovec::from_obj(&attr_out)]),
            mem::size_of::<FuseAttrOut>(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_SETATTR.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_setattr(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let setattr_in = match reader.read_obj::<FuseSetattrIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for setattr_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let mut fuse_attr = FuseAttr::default();
    let ret = fs
        .lock()
        .unwrap()
        .setattr(in_header.nodeid as usize, &setattr_in, &mut fuse_attr);
    if ret == FUSE_OK {
        let attr_out = FuseAttrOut {
            attr_valid: 1,
            attr_valid_nsec: 0,
            dummy: 0,
            attr: fuse_attr,
        };

        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            ret,
            Some(vec![FuseIovec::from_obj(&attr_out)]),
            mem::size_of::<FuseAttrOut>(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_READLINK.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_readlink(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let mut buff = Vec::new();
    let ret = fs
        .lock()
        .unwrap()
        .readlink(in_header.nodeid as usize, &mut buff);

    if ret == FUSE_OK {
        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            FUSE_OK,
            Some(vec![FuseIovec::from_slice(buff.as_slice())]),
            buff.len(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_SYMLINK.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_symlink(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let name = match reader.read_cstring(sys_mem) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read name for symlink, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let link_name = match reader.read_cstring(sys_mem) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read link name for symlink, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    if is_empty_path(&link_name) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::ENOENT, None, 0_usize);
    }

    if !is_safe_path(&link_name) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
    }

    let mut node_id = 0_u64;
    let mut fuse_attr = FuseAttr::default();
    let ret = fs
        .lock()
        .unwrap()
        .symlink(in_header, name, link_name, &mut node_id, &mut fuse_attr);
    if ret == FUSE_OK {
        let entry_out = FuseEntryOut {
            nodeid: node_id,
            generation: 0,
            entry_valid: 0,
            entry_valid_nsec: 0,
            attr_valid: 0,
            attr_valid_nsec: 0,
            attr: fuse_attr,
        };

        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            FUSE_OK,
            Some(vec![FuseIovec::from_obj(&entry_out)]),
            mem::size_of::<FuseEntryOut>(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_MKNOD.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_mknod(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let mknod_in = match reader.read_obj::<FuseMknodIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for mknod_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let name = match reader.read_cstring(sys_mem) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read name for mknod, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    if is_empty_path(&name) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::ENOENT, None, 0_usize);
    }

    if !is_safe_path(&name) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
    }

    let mut node_id = 0_u64;
    let mut fuse_attr = FuseAttr::default();
    let ret = fs
        .lock()
        .unwrap()
        .mknod(in_header, &mknod_in, name, &mut node_id, &mut fuse_attr);
    if ret == FUSE_OK {
        let entry_out = FuseEntryOut {
            nodeid: node_id,
            generation: 0,
            entry_valid: 0,
            entry_valid_nsec: 0,
            attr_valid: 0,
            attr_valid_nsec: 0,
            attr: fuse_attr,
        };

        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            FUSE_OK,
            Some(vec![FuseIovec::from_obj(&entry_out)]),
            mem::size_of::<FuseEntryOut>(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_MKDIR.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_mkdir(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let mkdir_in = match reader.read_obj::<FuseMkdirIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for mkdir_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let name = match reader.read_cstring(sys_mem) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read name for mkdir, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    if is_empty_path(&name) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::ENOENT, None, 0_usize);
    }

    if !is_safe_path(&name) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
    }

    let mut node_id = 0_u64;
    let mut fuse_attr = FuseAttr::default();
    let ret = fs
        .lock()
        .unwrap()
        .mkdir(in_header, &mkdir_in, name, &mut node_id, &mut fuse_attr);
    if ret == FUSE_OK {
        let entry_out = FuseEntryOut {
            nodeid: node_id,
            generation: 0,
            entry_valid: 0,
            entry_valid_nsec: 0,
            attr_valid: 0,
            attr_valid_nsec: 0,
            attr: fuse_attr,
        };

        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            FUSE_OK,
            Some(vec![FuseIovec::from_obj(&entry_out)]),
            mem::size_of::<FuseEntryOut>(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_UNLINK.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_unlink(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let name = match reader.read_cstring(sys_mem) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read name for unlink, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    if is_empty_path(&name) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::ENOENT, None, 0_usize);
    }

    if !is_safe_path(&name) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
    }

    let ret = fs.lock().unwrap().unlink(in_header.nodeid as usize, name);

    reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
}

/// Process the fuse message of FUSE_RMDIR.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_rmdir(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let name = match reader.read_cstring(sys_mem) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read name for rmdir, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    if is_empty_path(&name) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::ENOENT, None, 0_usize);
    }

    if !is_safe_path(&name) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
    }

    let ret = fs.lock().unwrap().rmdir(in_header.nodeid as usize, name);

    reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
}

/// Process the fuse message of FUSE_RENAME.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_rename(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let rename_in = match reader.read_obj::<FuseRenameIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for rename_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let oldname = match reader.read_cstring(sys_mem) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read old name for rename, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let newname = match reader.read_cstring(sys_mem) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read new name for rename, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    if is_empty_path(&oldname) || is_empty_path(&newname) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::ENOENT, None, 0_usize);
    }

    if !is_safe_path(&oldname) || !is_safe_path(&newname) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
    }

    let ret = fs.lock().unwrap().rename(
        in_header.nodeid as usize,
        oldname,
        rename_in.newdir as usize,
        newname,
    );
    reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
}

/// Process the fuse message of FUSE_LINK.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_link(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let link_in = match reader.read_obj::<FuseLinkIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for link_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let name = match reader.read_cstring(sys_mem) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read name for link, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    if is_empty_path(&name) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::ENOENT, None, 0_usize);
    }

    if !is_safe_path(&name) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
    }

    let mut fuse_attr = FuseAttr::default();
    let mut node_id = 0_u64;
    let ret = fs.lock().unwrap().link(
        in_header.nodeid as usize,
        link_in.oldnodeid as usize,
        name,
        &mut node_id,
        &mut fuse_attr,
    );

    if ret == FUSE_OK {
        let entry_out = FuseEntryOut {
            nodeid: node_id,
            generation: 0,
            entry_valid: 0,
            entry_valid_nsec: 0,
            attr_valid: 0,
            attr_valid_nsec: 0,
            attr: fuse_attr,
        };
        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            ret,
            Some(vec![FuseIovec::from_obj(&entry_out)]),
            mem::size_of::<FuseEntryOut>(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_OPEN.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_open(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let open_in = match reader.read_obj::<FuseOpenIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for open_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let mut fh = 0_u64;
    let ret = fs
        .lock()
        .unwrap()
        .open(in_header.nodeid as usize, open_in.flags, &mut fh);
    if ret == FUSE_OK {
        let open_out = FuseOpenOut {
            fh,
            open_flags: 0,
            padding: 0,
        };

        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            ret,
            Some(vec![FuseIovec::from_obj(&open_out)]),
            mem::size_of::<FuseOpenOut>(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_READ.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_read(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let read_in = match reader.read_obj::<FuseReadIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for read_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let mut fd = 0;
    let ret = fs.lock().unwrap().read(read_in.fh as usize, &mut fd);
    if ret == FUSE_OK {
        let buf_header = match writer.bufs.get(0) {
            Some(b) => *b,
            None => {
                error!("Failed to get the address of out_header");
                return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
            }
        };

        let mut f_ret = reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize);

        match writer.access_file(sys_mem, fd, read_in.offset, read_in.size, true) {
            Ok(size) => {
                f_ret += size;
                // write size to FuseOutHeader.len
                sys_mem.write_object(&f_ret, buf_header.addr).unwrap();
            }
            Err(e) => {
                error!("Failed to access file for reading, {:?}", e);
            }
        };

        f_ret
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_WRITE.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_write(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let write_in = match reader.read_obj::<FuseWriteIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for write_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let mut fd = 0;
    let ret = fs.lock().unwrap().write(write_in.fh as usize, &mut fd);
    if ret == FUSE_OK {
        match reader.access_file(sys_mem, fd, write_in.offset, write_in.size, false) {
            Ok(size) => {
                let write_out = FuseWriteOut { size, padding: 0 };

                reply_fuse_msg(
                    writer,
                    sys_mem,
                    in_header,
                    ret,
                    Some(vec![FuseIovec::from_obj(&write_out)]),
                    mem::size_of::<FuseWriteOut>(),
                )
            }
            Err(e) => {
                error!("Failed to access file for writing, {:?}", e);
                reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize)
            }
        }
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_STATFS.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_statfs(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let mut statfs = FuseStatfsOut::default();
    let ret = fs
        .lock()
        .unwrap()
        .statfs(in_header.nodeid as usize, &mut statfs);
    if ret == FUSE_OK {
        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            ret,
            Some(vec![FuseIovec::from_obj(&statfs)]),
            mem::size_of::<FuseStatfsOut>(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_RELEASE.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_release(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let release_in = match reader.read_obj::<FuseReleaseIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for release_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let ret = fs.lock().unwrap().release(release_in.fh as usize);
    reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
}

/// Process the fuse message of FUSE_FSYNC.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_fsync(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let fsync_in = match reader.read_obj::<FuseFsyncIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read name for fsync_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let datasync = fsync_in.fsync_flags & 0x1 == 0x1;

    let ret = fs.lock().unwrap().fsyncfile(fsync_in.fh as usize, datasync);
    reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
}

/// Process the fuse message of FUSE_SETXATTR.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_setxattr(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let setxattr_in = match reader.read_obj::<FuseSetxattrIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for setxattr_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let name = match reader.read_cstring(sys_mem) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read name for setxattr_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let mut value = Vec::new();
    value.resize(setxattr_in.size as usize, 0);

    if let Err(e) = reader.read_slice(sys_mem, &mut value, setxattr_in.size as usize) {
        error!("Failed to read value for setxattr_in, {:?}", e);
        return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
    }

    let cvalue = CString::new(value).unwrap_or_else(|_| CString::from(Vec::new()));

    let ret = fs.lock().unwrap().setxattr(
        in_header.nodeid as usize,
        name,
        cvalue,
        setxattr_in.size,
        setxattr_in.flags,
    );

    reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
}

/// Process the fuse message of FUSE_GETXATTR.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_getxattr(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let getxattr_in = match reader.read_obj::<FuseGetxattrIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for getxattr_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let name = match reader.read_cstring(sys_mem) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read name for getxattr_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let mut buff = Vec::new();
    let ret =
        fs.lock()
            .unwrap()
            .getxattr(in_header.nodeid as usize, name, getxattr_in.size, &mut buff);
    if ret == FUSE_OK {
        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            FUSE_OK,
            Some(vec![FuseIovec::from_slice(buff.as_slice())]),
            buff.len(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_LISTXATTR.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_listxattr(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let getxattr_in = match reader.read_obj::<FuseGetxattrIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for listxattr_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let mut buff = Vec::new();
    let ret = fs
        .lock()
        .unwrap()
        .listxattr(in_header.nodeid as usize, getxattr_in.size, &mut buff);
    if ret == FUSE_OK {
        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            FUSE_OK,
            Some(vec![FuseIovec::from_slice(buff.as_slice())]),
            buff.len(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_REMOVEXATTR.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_removexattr(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let name = match reader.read_cstring(sys_mem) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read name for removexattr_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let ret = fs
        .lock()
        .unwrap()
        .removexattr(in_header.nodeid as usize, name);

    reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
}

/// Process the fuse message of FUSE_FLUSH.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_flush(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let flush_in = match reader.read_obj::<FuseFlushIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for flush_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let ret = fs
        .lock()
        .unwrap()
        .flush(in_header.nodeid as usize, flush_in.lock_owner);

    reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
}

/// Process the fuse message of FUSE_INIT.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_init(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let init_in = match reader.read_obj::<FuseInitIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for init_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let mut support_flags = 0_u32;
    fs.lock().unwrap().init(init_in.flags, &mut support_flags);
    let pagesize: u32 = unsafe { libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap() };
    let init_out = FuseInitOut {
        major: FUSE_KERNEL_VERSION,
        minor: FUSE_KERNEL_MINOR_VERSION,
        max_readahead: init_in.max_readahead,
        flags: support_flags,
        max_background: 0,
        congestion_threshold: 0,
        max_write: MAX_WRITE_SIZE,
        /* Granularity of c/m/atime in ns (cannot be worse than a second), default 1 */
        time_gran: 1,
        max_pages: ((MAX_WRITE_SIZE + pagesize - 1) / pagesize) as u16,
        map_alignment: 0,
        ..Default::default()
    };

    reply_fuse_msg(
        writer,
        sys_mem,
        in_header,
        FUSE_OK,
        Some(vec![FuseIovec::from_obj(&init_out)]),
        mem::size_of::<FuseInitOut>(),
    )
}

/// Process the fuse message of FUSE_OPENDIR.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_opendir(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let _open_in = match reader.read_obj::<FuseOpenIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for opendir_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let mut dir_fh = 0_u64;
    let ret = fs
        .lock()
        .unwrap()
        .opendir(in_header.nodeid as usize, &mut dir_fh);
    if ret == FUSE_OK {
        let open_out = FuseOpenOut {
            fh: dir_fh,
            open_flags: 0,
            padding: 0,
        };

        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            FUSE_OK,
            Some(vec![FuseIovec::from_obj(&open_out)]),
            mem::size_of::<FuseOpenOut>(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_READDIR.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_readdir(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let read_in = match reader.read_obj::<FuseReadIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for readdir_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let mut buff = Vec::new();
    let ret = fs.lock().unwrap().readdir(
        in_header.nodeid as usize,
        read_in.fh as usize,
        read_in.size,
        read_in.offset,
        false,
        &mut buff,
    );
    if ret == FUSE_OK {
        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            FUSE_OK,
            Some(vec![FuseIovec::from_slice(buff.as_slice())]),
            buff.len(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_RELEASEDIR.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_releasedir(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let release_in = match reader.read_obj::<FuseReleaseIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for releasedir_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let ret = fs.lock().unwrap().releasedir(release_in.fh as usize);
    reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
}

/// Process the fuse message of FUSE_FSYNCDIR.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_fsyncdir(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let fsync_in = match reader.read_obj::<FuseFsyncIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for fsync_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let datasync = fsync_in.fsync_flags & 0x1 == 0x1;
    let ret = fs.lock().unwrap().fsyncdir(fsync_in.fh as usize, datasync);
    reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
}

/// Process the fuse message of FUSE_GETLK.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_getlk(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let lk_in = match reader.read_obj::<FuseLkIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for get_lk_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let mut file_lock = FuseFileLock::default();
    let ret = fs.lock().unwrap().getlk(
        in_header.nodeid as usize,
        lk_in.owner,
        &lk_in.lk,
        &mut file_lock,
    );

    if ret == FUSE_OK {
        let lk_out = FuseLkOut { lk: file_lock };
        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            FUSE_OK,
            Some(vec![FuseIovec::from_obj(&lk_out)]),
            mem::size_of::<FuseLkOut>(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

fn do_fuse_setlk_common(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    lk_in: &FuseLkIn,
    is_blocking: bool,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let ret = fs.lock().unwrap().setlk(
        in_header.nodeid as usize,
        lk_in.owner,
        is_blocking,
        &lk_in.lk,
    );

    reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
}

fn do_fuse_flock(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    lk_in: &FuseLkIn,
    is_blocking: bool,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let ret = fs
        .lock()
        .unwrap()
        .flock(lk_in.fh as usize, lk_in.lk.lock_type, is_blocking);

    reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
}

const FUSE_LOCK_FLOCK: u32 = (1 << 0) as u32;

/// Process the fuse message of FUSE_SETLK.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_setlk(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let lk_in = match reader.read_obj::<FuseLkIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for set_lk_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    if lk_in.lk_flags & FUSE_LOCK_FLOCK == FUSE_LOCK_FLOCK {
        do_fuse_flock(sys_mem, fs, &lk_in, false, writer, in_header)
    } else {
        do_fuse_setlk_common(sys_mem, fs, &lk_in, false, writer, in_header)
    }
}

/// Process the fuse message of FUSE_SETLKW.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_setlkw(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let lk_in = match reader.read_obj::<FuseLkIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for setlkw_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    if lk_in.lk_flags & FUSE_LOCK_FLOCK == FUSE_LOCK_FLOCK {
        do_fuse_flock(sys_mem, fs, &lk_in, true, writer, in_header)
    } else {
        do_fuse_setlk_common(sys_mem, fs, &lk_in, true, writer, in_header)
    }
}

/// Process the fuse message of FUSE_CREATE.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_create(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let create_in = match reader.read_obj::<FuseCreateIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for create_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let name = match reader.read_cstring(sys_mem) {
        Ok(string) => string,
        Err(e) => {
            error!("Failed to read name for creating file, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    if is_empty_path(&name) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::ENOENT, None, 0_usize);
    }

    if !is_safe_path(&name) {
        return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
    }

    let mut fh = 0_u64;
    let mut node_id = 0_u64;
    let mut fuse_attr = FuseAttr::default();
    let ret = fs.lock().unwrap().create(
        in_header,
        &create_in,
        name,
        &mut fh,
        &mut node_id,
        &mut fuse_attr,
    );
    if ret == FUSE_OK {
        let entry_out = FuseEntryOut {
            nodeid: node_id,
            generation: 0,
            entry_valid: 0,
            entry_valid_nsec: 0,
            attr_valid: 0,
            attr_valid_nsec: 0,
            attr: fuse_attr,
        };

        let open_out = FuseOpenOut {
            fh,
            open_flags: 0,
            padding: 0,
        };

        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            ret,
            Some(vec![
                FuseIovec::from_obj(&entry_out),
                FuseIovec::from_obj(&open_out),
            ]),
            mem::size_of::<FuseEntryOut>() + mem::size_of::<FuseOpenOut>(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_DESTROY.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_destroy(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let ret = fs.lock().unwrap().destroy();

    reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
}

/// Process the fuse message of FUSE_BATCH_FORGET.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
pub fn do_fuse_batch_forget(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
) -> u32 {
    let batch_forget_in = match reader.read_obj::<FuseBatchForgetIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for batch_forget_in, {:?}", e);
            return 0_u32;
        }
    };

    for _i in 0..batch_forget_in.count as usize {
        let forget_data_in = match reader.read_obj::<FuseForgetDataIn>(sys_mem) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to read object for forget_date_in, {:?}", e);
                return 0;
            }
        };

        fs.lock()
            .unwrap()
            .forget(forget_data_in.ino as usize, forget_data_in.nlookup);
    }

    0_u32
}

/// Process the fuse message of FUSE_FALLOCATE.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_fallocate(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let fallocate_in = match reader.read_obj::<FuseFallocateIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for fallocate_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let ret = fs.lock().unwrap().fallocate(
        fallocate_in.fh as usize,
        fallocate_in.mode,
        fallocate_in.offset,
        fallocate_in.length,
    );

    reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
}

/// Process the fuse message of FUSE_READDIRPLUS.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_readdirplus(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let read_in = match reader.read_obj::<FuseReadIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for readdirplus_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let mut buff = Vec::new();
    let ret = fs.lock().unwrap().readdir(
        in_header.nodeid as usize,
        read_in.fh as usize,
        read_in.size,
        read_in.offset,
        true,
        &mut buff,
    );
    if ret == FUSE_OK {
        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            FUSE_OK,
            Some(vec![FuseIovec::from_slice(buff.as_slice())]),
            buff.len(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_LSEEK.
///
/// # Arguments
///
/// * `sys_mem` - Address space mapped with StratoVirt.
/// * `fs` - The management of userspace filesystem.
/// * `reader` - The read-only buffers parsed from the element of virtio queue.
/// * `writer` - The write-only buffers parsed from the element of virtio queue.
/// * `in_header` - The in_header reading from the read-only buffers.
pub fn do_fuse_lseek(
    sys_mem: &Arc<AddressSpace>,
    fs: Arc<Mutex<FileSystem>>,
    reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    let lseek_in = match reader.read_obj::<FuseLseekIn>(sys_mem) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read object for lseek_in, {:?}", e);
            return reply_fuse_msg(writer, sys_mem, in_header, libc::EINVAL, None, 0_usize);
        }
    };

    let mut outoffset = 0_u64;
    let ret = fs.lock().unwrap().lseek(
        lseek_in.fh as usize,
        lseek_in.offset,
        lseek_in.whence,
        &mut outoffset,
    );

    if ret == FUSE_OK {
        let lseekout = FuseLseekOut { offset: outoffset };

        reply_fuse_msg(
            writer,
            sys_mem,
            in_header,
            ret,
            Some(vec![FuseIovec::from_obj(&lseekout)]),
            mem::size_of::<FuseLseekOut>(),
        )
    } else {
        reply_fuse_msg(writer, sys_mem, in_header, ret, None, 0_usize)
    }
}

/// Process the fuse message of FUSE_IOCTL.
/// Currently not supported, and ENOSYS is directly returned.
/// Normally the VM should not use ioctl to modify files, but it can be useful
/// in some cases. For example: to modify inode attrs, witch is required for per
/// inode DAX. We set aside the ioctl interface, and to implement it in the future
/// if needed.
pub fn do_fuse_ioctl(
    sys_mem: &Arc<AddressSpace>,
    _fs: Arc<Mutex<FileSystem>>,
    _reader: &mut FuseBuffer,
    writer: &mut FuseBuffer,
    in_header: &FuseInHeader,
) -> u32 {
    reply_fuse_msg(writer, sys_mem, in_header, libc::ENOSYS, None, 0_usize)
}
