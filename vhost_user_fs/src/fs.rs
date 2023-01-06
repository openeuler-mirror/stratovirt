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

/// The map length used to extend the file/inode map.
const MAP_EXTEND_LENGTH: usize = 256;
const F_RDLCK: u32 = 0;
const F_WDLCK: u32 = 1;
const F_UNLCK: u32 = 2;
const RLIMIT_NOFILE_MIN: u64 = 20;
/// The inode 0 is reserved, 1 is root inode.
const ROOT_INODE: usize = 1;

use super::fs_ops::*;
use super::fuse_msg::*;
use crate::cmdline::FsConfig;
use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::ffi::CString;
use std::fs::{read_to_string, File};
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use util::byte_code::ByteCode;
use util::num_ops::round_up;

/// Used as the key of the inode.
#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
struct StatKey {
    /// Inode number.
    ino: libc::ino64_t,
    /// ID of device containing file.
    dev: libc::dev_t,
}

/// The entry of the inode/file.
struct Entry<T> {
    /// The value stored in the Entry.
    value: Option<T>,
    /// If the entry is used or not.
    used: bool,
    /// The next free entry.
    free_next: usize,
}

/// The map used to store inodes/files.
struct Map<T> {
    /// The vector used to store Entry.
    list: Vec<Entry<T>>,
    /// The first free entry in list.
    free_head: usize,
}

impl<T> Map<T> {
    fn new() -> Self {
        Map {
            list: Vec::new(),
            free_head: ROOT_INODE,
        }
    }

    fn destroy_map(&mut self) {
        self.list = Vec::new();
        self.free_head = ROOT_INODE;
    }

    /// Add MAP_EXTEND_LENGTH elems to the map.
    fn extend_map(&mut self) {
        let mut next = self.list.len();

        for _ in 0..MAP_EXTEND_LENGTH {
            next += 1;
            self.list.push(Entry {
                value: None,
                used: false,
                free_next: next,
            });
        }
    }

    /// Add entry to the map.
    fn get_map(&mut self, value: T) -> usize {
        let id = self.free_head;
        if id == ROOT_INODE || id == self.list.len() {
            self.extend_map();
        }

        match self.list.get_mut(id) {
            Some(e) => {
                e.value = Some(value);
                e.used = true;
                self.free_head = e.free_next;

                id
            }
            None => 0,
        }
    }

    /// Delete entry from the map.
    fn put_map(&mut self, id: usize) {
        if id >= self.list.len() {
            return;
        }

        if let Some(e) = self.list.get_mut(id) {
            if !e.used {
                return;
            }

            e.value = None;
            e.used = false;
            e.free_next = self.free_head;
            self.free_head = id
        }
    }

    fn get_value(&self, id: usize) -> Option<&T> {
        if let Some(e) = self.list.get(id) {
            e.value.as_ref()
        } else {
            None
        }
    }

    fn get_value_mut(&mut self, id: usize) -> Option<&mut T> {
        if let Some(e) = self.list.get_mut(id) {
            e.value.as_mut()
        } else {
            None
        }
    }
}

/// Used to lock file.
struct FileLock {
    /// The owner of the lock
    lock_owner: u64,
    /// The file which is locked
    file: File,
}

impl FileLock {
    fn new(file: File, lock_owner: u64) -> Self {
        FileLock { lock_owner, file }
    }
}

impl Clone for FileLock {
    fn clone(&self) -> Self {
        FileLock {
            lock_owner: self.lock_owner,
            file: self.file.try_clone().unwrap(),
        }
    }
}

/// The inode info.
struct Inode {
    /// The inode file.
    file: File,
    /// The refcount of the inode.
    nlookup: u64,
    /// Store the map index of the inode.
    node_id: usize,
    /// the file type.
    file_type: u32,
    /// The key of the inode.
    key: StatKey,
    /// The locks on the file of the Inode.
    locks: HashMap<u64, FileLock>,
}

impl Inode {
    fn new(file: File, nlookup: u64, node_id: usize, file_type: u32, key: StatKey) -> Self {
        Inode {
            file,
            nlookup,
            node_id,
            file_type,
            key,
            locks: HashMap::new(),
        }
    }

    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Clone for Inode {
    fn clone(&self) -> Self {
        Inode {
            file: self.file.try_clone().unwrap(),
            nlookup: self.nlookup,
            node_id: self.node_id,
            file_type: self.file_type,
            key: self.key,
            locks: self.locks.clone(),
        }
    }
}

fn array_to_cstring(
    #[cfg(target_arch = "x86_64")] array: &[i8],
    #[cfg(target_arch = "aarch64")] array: &[u8],
) -> Result<(usize, CString)> {
    let mut vec = Vec::new();
    for item in array {
        if *item == 0 {
            break;
        }
        vec.push(*item as u8);
    }

    let len = vec.len();
    if len == 0 {
        bail!("convert array to CString failed")
    }

    let cstring = match CString::new(vec) {
        Ok(c) => c,
        Err(_) => bail!("convert array to CString failed"),
    };

    Ok((len, cstring))
}

fn path_is_dot(path: &CString) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() == 1 && bytes[0] == b'.' {
        return true;
    }

    false
}

fn path_is_dotdot(path: &CString) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() == 2 && bytes[0] == b'.' && bytes[1] == b'.' {
        return true;
    }

    false
}

/// Set file resources limits for the process. The limit value
/// must be more than or equal to 20 to ensure that the process
/// can start normally. The limit value must be less than or equal
/// to the value of "/proc/sys/fs/file-max" and "/proc/sys/fs/nr_open".
///
/// # Arguments
///
/// * `limit` - The limit value which needs to be set.
pub fn set_rlimit_nofile(limit: u64) -> Result<()> {
    if limit < RLIMIT_NOFILE_MIN {
        bail!(
            "The limit {} exceeds minimum of files {}",
            limit,
            RLIMIT_NOFILE_MIN
        );
    }

    let max_file_str =
        read_to_string("/proc/sys/fs/file-max").with_context(|| "Failed to read file-max")?;
    let max_file = max_file_str
        .trim()
        .parse::<u64>()
        .with_context(|| "Failed to convert the string of max files")?;
    if limit > max_file {
        bail!("The limit {} exceeds maximum of files {}", limit, max_file);
    }

    let nr_open_str =
        read_to_string("/proc/sys/fs/nr_open").with_context(|| "Failed to read nr_open")?;
    let max_file = nr_open_str
        .trim()
        .parse::<u64>()
        .with_context(|| "Failed to convert the string of nr_open")?;
    if limit > max_file {
        bail!(
            "The limit {} exceeds maximum of nr_open {}",
            limit,
            max_file
        );
    }

    let ret = set_rlimit(limit, limit);
    if ret != FUSE_OK {
        bail!("Failed to set rlimit, err: {}", ret);
    }

    Ok(())
}

/// The management structure of filesystem that contains the management of inodes
/// and the information of files in host directory which needs to be shared.
pub struct FileSystem {
    root_inode: Inode,
    inodes: BTreeMap<StatKey, Inode>,
    inode_key_map: Map<StatKey>,
    file_map: Map<File>,
    proc_dir: File,
}

impl FileSystem {
    /// Create a filesystem management structure.
    ///
    /// # Arguments
    ///
    /// * `source_dir` - The path of the host directory which needs to be shared.
    pub fn new(fs_config: FsConfig) -> Result<Self> {
        let root_dir = fs_config.root_dir.clone();
        let (root_file_opt, ret) = open(CString::new(root_dir).unwrap(), libc::O_PATH);
        if ret != FUSE_OK {
            bail!("Failed to open root file {}", fs_config.root_dir);
        }
        let root_file = root_file_opt.unwrap();
        let (stat, ret) = fstat_at(
            &root_file,
            CString::new("").unwrap(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        );
        if ret != FUSE_OK {
            bail!("Failed to get stat of root file {}", fs_config.root_dir);
        }
        let key = StatKey {
            ino: stat.st_ino,
            dev: stat.st_dev,
        };
        let mut inode_key_map = Map::new();
        let root_id = inode_key_map.get_map(key);
        // The default folder nlookup is 2
        let root_inode = Inode::new(root_file, 2, root_id, libc::S_IFDIR, key);
        let mut inodes = BTreeMap::new();
        inodes.insert(key, root_inode.clone());
        Ok(FileSystem {
            root_inode,
            inodes,
            inode_key_map,
            file_map: Map::new(),
            proc_dir: fs_config.proc_dir_opt.unwrap(),
        })
    }

    fn find_inode(&self, node_id: usize) -> Option<&Inode> {
        match self.inode_key_map.get_value(node_id) {
            Some(k) => self.inodes.get(k),
            _ => None,
        }
    }

    fn find_mut_inode(&mut self, node_id: usize) -> Option<&mut Inode> {
        match self.inode_key_map.get_value(node_id) {
            Some(k) => self.inodes.get_mut(k),
            _ => None,
        }
    }

    fn unref_inode(&mut self, inode: &mut Inode, count: u64) {
        if count > inode.nlookup {
            inode.nlookup = 0;
        } else {
            inode.nlookup -= count;
        }

        if inode.nlookup == 0 {
            self.inodes.remove(&inode.key);
            self.inode_key_map.put_map(inode.node_id);
        } else if let Some(inode_) = self.find_mut_inode(inode.node_id) {
            inode_.nlookup = inode.nlookup;
        }
    }

    fn create_file_lock(&mut self, node_id: usize, owner: u64) -> (Option<File>, i32) {
        let proc_file = self.proc_dir.try_clone().unwrap();
        let inode = match self.find_mut_inode(node_id) {
            Some(inode_) => inode_,
            None => return (None, libc::EBADF),
        };

        if let Some(lock) = inode.locks.get_mut(&owner) {
            return (Some(lock.file.try_clone().unwrap()), FUSE_OK);
        }

        if inode.file_type & libc::S_IFDIR == 0 && inode.file_type & libc::S_IFREG == 0 {
            return (None, libc::EBADF);
        }

        let (file_opt, ret) = open_at(
            &proc_file,
            CString::new(format!("{}", inode.as_raw_fd())).unwrap(),
            libc::O_RDWR,
            0,
        );

        if ret != FUSE_OK {
            return (None, ret);
        }

        let file = file_opt.unwrap().try_clone().unwrap();
        let file_lock = FileLock::new(file.try_clone().unwrap(), owner);
        inode.locks.insert(owner, file_lock);

        (Some(file), FUSE_OK)
    }

    fn delete_file_lock(&mut self, node_id: usize, owner: u64) -> i32 {
        let inode = match self.find_mut_inode(node_id) {
            Some(inode_) => inode_,
            None => return libc::EBADF,
        };

        inode.locks.remove(&owner);

        FUSE_OK
    }

    fn internal_lookup(
        &mut self,
        parent_inode: &Inode,
        name: CString,
        node_id: &mut u64,
        fuse_attr: &mut FuseAttr,
    ) -> i32 {
        let mut son_name = name.clone();
        if parent_inode.node_id == self.root_inode.node_id && path_is_dotdot(&name) {
            son_name = CString::new(".").unwrap();
        }

        let (stat, ret) = fstat_at(
            &parent_inode.file,
            son_name.clone(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        );
        if ret != FUSE_OK {
            return ret;
        }

        let key = StatKey {
            ino: stat.st_ino,
            dev: stat.st_dev,
        };
        if let Some(inode) = self.inodes.get_mut(&key) {
            inode.nlookup += 1;
            *node_id = inode.node_id as u64;
        } else {
            let (file_opt, ret) = open_at(
                &parent_inode.file,
                son_name,
                libc::O_PATH | libc::O_NOFOLLOW,
                0,
            );
            if ret != FUSE_OK {
                return ret;
            }

            let map_id = self.inode_key_map.get_map(key);
            if let Some(file) = file_opt {
                self.inodes.insert(
                    key,
                    Inode::new(file, 1, map_id, stat.st_mode & libc::S_IFMT, key),
                );
            }
            *node_id = map_id as u64;
        };

        *fuse_attr = FuseAttr::from_stat(stat);

        FUSE_OK
    }

    /// Look up the directory or file information by name and reply attributes.
    ///
    /// # Arguments
    ///
    /// * `parent_nodeid` - The parent node id that is the starting directory to look up.
    /// * `name` - The name that needs to be looked up.
    /// * `node_id` - The node id that needs to be looked up by name.
    /// * `fuse_attr` - The attributes that needs to be looked up by name.
    pub fn lookup(
        &mut self,
        parent_nodeid: usize,
        name: CString,
        node_id: &mut u64,
        fuse_attr: &mut FuseAttr,
    ) -> i32 {
        let inode = match self.find_inode(parent_nodeid) {
            Some(i) => i.clone(),
            _ => {
                return libc::EBADF;
            }
        };
        self.internal_lookup(&inode, name, node_id, fuse_attr)
    }

    /// When the nlookup of inode is reduced to 0, delete the inode from the management structure.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to find the inode.
    /// * `nlookup` - The number of nlookup for inode needs to be reduced.
    pub fn forget(&mut self, node_id: usize, nlookup: u64) -> i32 {
        let mut inode = match self.find_inode(node_id) {
            Some(i) => i.clone(),
            _ => {
                return libc::EBADF;
            }
        };
        self.unref_inode(&mut inode, nlookup);
        FUSE_OK
    }

    /// Get the attributes of a file or directory.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to find the inode.
    /// * `fuse_attr` - The attributes will be returned by the found inode.
    pub fn getattr(&mut self, node_id: usize, fuse_attr: &mut FuseAttr) -> i32 {
        let inode = match self.find_inode(node_id) {
            Some(i) => i.clone(),
            _ => {
                return libc::EBADF;
            }
        };
        let (stat, ret) = fstat_at(
            &inode.file,
            CString::new("").unwrap(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        );
        if ret != FUSE_OK {
            return ret;
        }
        *fuse_attr = FuseAttr::from_stat(stat);
        FUSE_OK
    }

    /// Set the attributes of a file or directory.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to find the inode.
    /// * `attr` - The attributes will be set to the found inode.
    /// * `fuse_attr` - The attributes will be returned by the found inode.
    pub fn setattr(
        &mut self,
        node_id: usize,
        attr: &FuseSetattrIn,
        fuse_attr: &mut FuseAttr,
    ) -> i32 {
        if attr.valid & FUSE_SET_ATTR_MODE != 0 {
            if attr.valid & FATTR_FH != 0 {
                match self.file_map.get_value(attr.fh as usize) {
                    Some(file) => {
                        let ret = fchmod(file, attr.mode);
                        if ret != FUSE_OK {
                            return ret;
                        }
                    }
                    _ => {
                        return libc::EBADF;
                    }
                };
            } else {
                match self.find_inode(node_id) {
                    Some(i) => {
                        let ret = fchmod_at(
                            &self.proc_dir,
                            CString::new(format!("{}", &i.file.as_raw_fd())).unwrap(),
                            attr.mode,
                        );
                        if ret != FUSE_OK {
                            return ret;
                        }
                    }
                    _ => {
                        return libc::EBADF;
                    }
                };
            }
        }

        if attr.valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID) != 0 {
            let uid = if attr.valid & FUSE_SET_ATTR_UID != 0 {
                attr.uid
            } else {
                u32::MAX
            };

            let gid = if attr.valid & FUSE_SET_ATTR_GID != 0 {
                attr.gid
            } else {
                u32::MAX
            };

            match self.find_inode(node_id) {
                Some(i) => {
                    let ret = fchown_at(
                        &i.file,
                        CString::new("").unwrap(),
                        uid,
                        gid,
                        libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                    );
                    if ret != FUSE_OK {
                        return ret;
                    }
                }
                _ => {
                    return libc::EBADF;
                }
            };
        }

        if attr.valid & FUSE_SET_ATTR_SIZE != 0 {
            if attr.valid & FATTR_FH != 0 {
                match self.file_map.get_value(attr.fh as usize) {
                    Some(file) => {
                        let ret = ftruncate(file, attr.size);
                        if ret != FUSE_OK {
                            return ret;
                        }
                    }
                    _ => {
                        return libc::EBADF;
                    }
                };
            } else {
                match self.find_inode(node_id) {
                    Some(i) => {
                        if i.file_type & libc::S_IFREG == 0 && i.file_type & libc::S_IFDIR == 0 {
                            return libc::EBADF;
                        }

                        let (file_opt, ret) = open_at(
                            &self.proc_dir,
                            CString::new(format!("{}", &i.file.as_raw_fd())).unwrap(),
                            libc::O_RDWR,
                            0,
                        );
                        if ret != FUSE_OK {
                            return ret;
                        }

                        if let Some(file) = file_opt {
                            let ret = ftruncate(&file, attr.size);
                            if ret != FUSE_OK {
                                return ret;
                            }
                        }
                    }
                    _ => {
                        return libc::EBADF;
                    }
                };
            }
        }

        if attr.valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME) != 0 {
            let (a_sec, a_nsec) = if attr.valid & FUSE_SET_ATTR_ATIME_NOW != 0 {
                (0, libc::UTIME_NOW)
            } else if attr.valid & FUSE_SET_ATTR_ATIME != 0 {
                (attr.atime, attr.atimensec as i64)
            } else {
                (0, libc::UTIME_OMIT)
            };

            let (m_sec, m_nsec) = if attr.valid & FUSE_SET_ATTR_MTIME_NOW != 0 {
                (0, libc::UTIME_NOW)
            } else if attr.valid & FUSE_SET_ATTR_MTIME != 0 {
                (attr.mtime, attr.mtimensec as i64)
            } else {
                (0, libc::UTIME_OMIT)
            };

            if attr.valid & FATTR_FH != 0 {
                match self.file_map.get_value(attr.fh as usize) {
                    Some(file) => {
                        let ret = futimens(file, a_sec, a_nsec, m_sec, m_nsec);
                        if ret != FUSE_OK {
                            return ret;
                        }
                    }
                    _ => {
                        return libc::EBADF;
                    }
                };
            } else {
                match self.find_inode(node_id) {
                    Some(i) => {
                        let ret = utimensat(
                            &self.proc_dir,
                            CString::new(format!("{}", &i.file.as_raw_fd())).unwrap(),
                            a_sec,
                            a_nsec,
                            m_sec,
                            m_nsec,
                            0,
                        );
                        if ret != FUSE_OK {
                            return ret;
                        }
                    }
                    _ => {
                        return libc::EBADF;
                    }
                };
            }
        }

        self.getattr(node_id, fuse_attr)
    }

    /// Get the contexts of the symbolic link into the buffer.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to find the inode.
    /// * `buff` - The buffer is saved by the contexts of the symbolic link.
    pub fn readlink(&self, node_id: usize, buff: &mut Vec<u8>) -> i32 {
        let inode = match self.find_inode(node_id) {
            Some(i) => i.clone(),
            None => {
                return libc::EBADF;
            }
        };

        let (buf_opt, ret) = readlinkat(&inode.file, CString::new("").unwrap());
        if ret != FUSE_OK {
            return ret;
        }

        if let Some(mut buf) = buf_opt {
            buff.append(&mut buf);
        } else {
            return libc::EBADF;
        }

        FUSE_OK
    }

    /// Get the contexts of the symbolic link into the buffer.
    ///
    /// # Arguments
    ///
    /// * `in_header` - The in_header of fuse message used to get uid and gid.
    /// * `name` - The target link name used to create a symbolic link.
    /// * `link_name` - The link name that will be created a symbolic link.
    /// * `node_id` - The node id that is found by name.
    /// * `fuse_attr` - The attributes will be returned by the found inode.
    pub fn symlink(
        &mut self,
        in_header: &FuseInHeader,
        name: CString,
        link_name: CString,
        node_id: &mut u64,
        fuse_attr: &mut FuseAttr,
    ) -> i32 {
        let parent_inode = match self.find_inode(in_header.nodeid as usize) {
            Some(i) => i.clone(),
            _ => {
                return libc::EBADF;
            }
        };

        let mut old_uid = 0_u32;
        let mut old_gid = 0_u32;
        let ret = change_uid_gid(in_header.uid, in_header.gid, &mut old_uid, &mut old_gid);
        if ret != FUSE_OK {
            return ret;
        }

        let ret = symlinkat(&parent_inode.file, name.clone(), link_name);

        recover_uid_gid(old_uid, old_gid);

        if ret != FUSE_OK {
            return ret;
        }

        self.internal_lookup(&parent_inode, name, node_id, fuse_attr)
    }

    /// Create a file system node(file, device special file or named pipe) by the path name
    /// with the mode and dev in the mknod information.
    ///
    /// # Arguments
    ///
    /// * `in_header` - The in_header of fuse message used to get uid and gid.
    /// * `mknod_in` - The information of mknod to get the permissions and dev.
    /// * `name` - The path name used to create a file system node.
    /// * `node_id` - The node id that is found by name.
    /// * `fuse_attr` - The attributes will be returned by the found inode.
    pub fn mknod(
        &mut self,
        in_header: &FuseInHeader,
        mknod_in: &FuseMknodIn,
        name: CString,
        node_id: &mut u64,
        fuse_attr: &mut FuseAttr,
    ) -> i32 {
        let parent_inode = match self.find_inode(in_header.nodeid as usize) {
            Some(i) => i.clone(),
            _ => {
                return libc::EBADF;
            }
        };

        let mut old_uid = 0_u32;
        let mut old_gid = 0_u32;
        let ret = change_uid_gid(in_header.uid, in_header.gid, &mut old_uid, &mut old_gid);
        if ret != FUSE_OK {
            return ret;
        }

        let ret = mknodat(
            &parent_inode.file,
            name.clone(),
            mknod_in.mode & !mknod_in.umask,
            mknod_in.rdev,
        );

        recover_uid_gid(old_uid, old_gid);

        if ret != FUSE_OK {
            return ret;
        }

        self.internal_lookup(&parent_inode, name, node_id, fuse_attr)
    }

    /// Create a directory by the name with the permissions in the mkdir information.
    ///
    /// # Arguments
    ///
    /// * `in_header` - The in_header of fuse message used to get uid and gid.
    /// * `mkdir_in` - The information of mkdir used to get permissions.
    /// * `name` - The path name that will be created a directory.
    /// * `node_id` - The node id that is found by the path name.
    /// * `fuse_attr` - The attributes will be returned by the found inode.
    pub fn mkdir(
        &mut self,
        in_header: &FuseInHeader,
        mkdir_in: &FuseMkdirIn,
        name: CString,
        node_id: &mut u64,
        fuse_attr: &mut FuseAttr,
    ) -> i32 {
        let parent_dir = match self.find_inode(in_header.nodeid as usize) {
            Some(i) => i.clone(),
            _ => {
                return libc::EBADF;
            }
        };

        let mut old_uid = 0_u32;
        let mut old_gid = 0_u32;
        let ret = change_uid_gid(in_header.uid, in_header.gid, &mut old_uid, &mut old_gid);
        if ret != FUSE_OK {
            return ret;
        }

        let ret = mkdir_at(
            &parent_dir.file,
            name.clone(),
            mkdir_in.mode & !mkdir_in.umask,
        );

        recover_uid_gid(old_uid, old_gid);

        if ret != FUSE_OK {
            return ret;
        }

        self.internal_lookup(&parent_dir, name, node_id, fuse_attr)
    }

    /// Delete a name from the host filesystem.
    ///
    /// # Arguments
    ///
    /// * `parent_nodeid` - The parent node id that is the starting directory to look up
    /// in the management of filesystem.
    /// * `name` - The name will be deleted.
    pub fn unlink(&mut self, parent_nodeid: usize, name: CString) -> i32 {
        let parent_inode = match self.find_inode(parent_nodeid) {
            Some(i) => i.clone(),
            None => return libc::EBADF,
        };

        let (stat, ret) = fstat_at(
            &parent_inode.file,
            name.clone(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        );
        if ret != FUSE_OK {
            return ret;
        }

        let key = StatKey {
            ino: stat.st_ino,
            dev: stat.st_dev,
        };

        match self.inodes.get(&key) {
            Some(i) => i.clone(),
            None => return libc::EIO,
        };

        let ret = unlinkat(&parent_inode.file, name, 0);
        if ret != FUSE_OK {
            return ret;
        }

        FUSE_OK
    }

    /// Delete a directory from the host filesystem by the path name.
    ///
    /// # Arguments
    ///
    /// * `parent_nodeid` - The parent node id that is the starting directory to look up
    /// in the management of filesystem.
    /// * `name` - The path name of the directory will be deleted.
    pub fn rmdir(&mut self, parent_nodeid: usize, name: CString) -> i32 {
        let parent_inode = match self.find_inode(parent_nodeid) {
            Some(i) => i.clone(),
            None => return libc::EBADF,
        };

        let (stat, ret) = fstat_at(
            &parent_inode.file,
            name.clone(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        );
        if ret != FUSE_OK {
            return ret;
        }

        let key = StatKey {
            ino: stat.st_ino,
            dev: stat.st_dev,
        };

        match self.inodes.get(&key) {
            Some(i) => i.clone(),
            None => return libc::EIO,
        };

        let ret = unlinkat(&parent_inode.file, name, libc::AT_REMOVEDIR);
        if ret != FUSE_OK {
            return ret;
        }

        FUSE_OK
    }

    /// Rename the old path name to the new path name in the host filesystem..
    ///
    /// # Arguments
    ///
    /// * `parent_nodeid` - The parent node id that is the starting directory to look up
    /// for old path name in the management of filesystem.
    /// * `oldname` - The old path name that is relative to the directory of parent node.
    /// * `newparent_nodeid` - The new parent node id that is the starting directory to
    /// look up for new path name in the management of filesystem.
    /// * `newname` - The new path name that is relative to the directory of new parent node.
    pub fn rename(
        &self,
        parent_nodeid: usize,
        oldname: CString,
        newparent_nodeid: usize,
        newname: CString,
    ) -> i32 {
        let parent_inode = match self.find_inode(parent_nodeid) {
            Some(i) => i.clone(),
            None => {
                return libc::EBADF;
            }
        };

        let newparent_inode = match self.find_inode(newparent_nodeid) {
            Some(i) => i.clone(),
            None => {
                return libc::EBADF;
            }
        };

        let (stat, ret) = fstat_at(
            &parent_inode.file,
            oldname.clone(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        );
        if ret != FUSE_OK {
            return ret;
        }

        let key = StatKey {
            ino: stat.st_ino,
            dev: stat.st_dev,
        };

        match self.inodes.get(&key) {
            Some(_) => {}
            None => return libc::EIO,
        };

        rename(&parent_inode.file, oldname, &newparent_inode.file, newname)
    }

    /// Create a new link to an existing file for the host filesystem.
    ///
    /// # Arguments
    ///
    /// * `parent_nodeid` - The parent node id that is the starting directory to look up.
    /// * `old_nodeid` - The old node id in the management of filesystem.
    /// * `name` - The path name that is relative to the directory of parent node.
    /// * `node_id` - The node id that is found by the path name in the management of filesystem.
    /// * `fuse_attr` - The attributes will be returned by the found inode.
    pub fn link(
        &mut self,
        parent_nodeid: usize,
        old_nodeid: usize,
        name: CString,
        node_id: &mut u64,
        fuse_attr: &mut FuseAttr,
    ) -> i32 {
        let proc_file = self.proc_dir.try_clone().unwrap();
        let parent_inode = match self.find_inode(parent_nodeid) {
            Some(i) => i.clone(),
            None => return libc::EBADF,
        };

        let inode = match self.find_mut_inode(old_nodeid) {
            Some(inode_) => inode_,
            None => return libc::EBADF,
        };

        let ret = linkat(
            &proc_file,
            CString::new(format!("{}", inode.as_raw_fd())).unwrap(),
            &parent_inode.file,
            name,
            libc::AT_SYMLINK_FOLLOW,
        );
        if ret != FUSE_OK {
            return ret;
        }

        let (stat, ret) = fstat_at(
            &inode.file,
            CString::new("").unwrap(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        );

        if ret != FUSE_OK {
            return ret;
        }

        *fuse_attr = FuseAttr::from_stat(stat);
        *node_id = inode.node_id as u64;
        inode.nlookup += 1;

        FUSE_OK
    }

    /// Open the file with the node id in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to look up the inode.
    /// * `flags` - The flags used to open the file.
    /// * `fh` - The file handler is returned in the management of filesystem.
    pub fn open(&mut self, node_id: usize, flags: u32, fh: &mut u64) -> i32 {
        // File creation should be done with create and mknod fuse messages.
        if (flags & (libc::O_CREAT as u32 | libc::O_TMPFILE as u32)) != 0 {
            return libc::EINVAL;
        }

        let (inode_fd, file_type) = match self.find_inode(node_id) {
            Some(i) => (i.as_raw_fd(), i.file_type),
            None => {
                return libc::EBADF;
            }
        };

        if file_type & libc::S_IFREG == 0 && file_type & libc::S_IFDIR == 0 {
            return libc::EBADF;
        }

        let (file_opt, ret) = open_at(
            &self.proc_dir,
            CString::new(format!("{}", inode_fd)).unwrap(),
            (flags as i32) & !libc::O_NOFOLLOW,
            0,
        );
        if ret != FUSE_OK {
            return ret;
        }

        if let Some(file) = file_opt {
            *fh = self.file_map.get_map(file.try_clone().unwrap()) as u64;
        }

        FUSE_OK
    }

    /// Read the file descriptor by file hander in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `fh` - The file handler in the management of filesystem.
    /// * `fd` - The file descriptor in the host filesystem.
    pub fn read(&mut self, fh: usize, fd: &mut RawFd) -> i32 {
        match self.file_map.get_value(fh) {
            Some(file) => {
                *fd = file.as_raw_fd();
            }
            _ => {
                return libc::EBADF;
            }
        }

        FUSE_OK
    }

    /// write the file descriptor by file hander in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `fh` - The file handler in the management of filesystem.
    /// * `fd` - The file descriptor in the host filesystem.
    pub fn write(&mut self, fh: usize, fd: &mut RawFd) -> i32 {
        match self.file_map.get_value(fh) {
            Some(file) => {
                *fd = file.as_raw_fd();
            }
            _ => {
                return libc::EBADF;
            }
        }

        FUSE_OK
    }

    /// Get the information about a mounted filesystem.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to look up the inode.
    /// * `fuse_statfs` - The information about the mounted filesystem is
    /// returned by the found inode.
    pub fn statfs(&mut self, node_id: usize, fuse_statfs: &mut FuseStatfsOut) -> i32 {
        let inode = match self.find_inode(node_id) {
            Some(i) => i.clone(),
            None => {
                return libc::EBADF;
            }
        };

        let (stat, ret) = fstat_vfs(&inode.file);
        if ret != FUSE_OK {
            return ret;
        }

        *fuse_statfs = FuseStatfsOut::from_stat(stat);

        FUSE_OK
    }

    /// Release the file with file handler in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `fh` - The file handler in the management of filesystem.
    pub fn release(&mut self, fh: usize) -> i32 {
        self.file_map.put_map(fh);

        FUSE_OK
    }

    /// Transfer the file data to the storage device with file handler in
    /// the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `fh` - The file handler in the management of filesystem.
    /// * `datasync` - The datasync indicates whether to use the fdatasync
    /// or fsync interface.
    pub fn fsyncfile(&self, fh: usize, datasync: bool) -> i32 {
        let mut ret = FUSE_OK;

        if fh == u64::max_value() as usize {
            let (inode_fd, file_type) = match self.find_inode(fh) {
                Some(i) => (i.as_raw_fd(), i.file_type),
                None => {
                    return libc::EBADF;
                }
            };

            if file_type & libc::S_IFREG == 0 && file_type & libc::S_IFDIR == 0 {
                return libc::EBADF;
            }

            let (file_opt, ret_) = open_at(
                &self.proc_dir,
                CString::new(format!("{}", inode_fd)).unwrap(),
                libc::O_RDWR,
                0,
            );
            if ret_ != FUSE_OK {
                return ret;
            }

            if let Some(file) = file_opt {
                ret = fsync(&file, datasync);
            } else {
                return libc::EBADF;
            }
        } else {
            match self.file_map.get_value(fh) {
                Some(file) => {
                    ret = fsync(file, datasync);
                }
                _ => {
                    return libc::EBADF;
                }
            }
        }

        ret
    }

    /// Set an extended attribute identified by name and associated with the node id
    /// in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to look up the inode.
    /// * `name` - The name associated with inode.
    /// * `value` - The value of the extended attribute.
    /// * `size` - The size of the value string.
    /// * `flags` - The flags used to set an extended attribute.
    pub fn setxattr(
        &self,
        node_id: usize,
        name: CString,
        value: CString,
        size: u32,
        flags: u32,
    ) -> i32 {
        let inode = match self.find_inode(node_id) {
            Some(i) => i.clone(),
            None => {
                return libc::EBADF;
            }
        };

        if inode.file_type & libc::S_IFREG != 0 || inode.file_type & libc::S_IFDIR != 0 {
            let (file_opt, ret_) = open_at(
                &self.proc_dir,
                CString::new(format!("{}", &inode.file.as_raw_fd())).unwrap(),
                libc::O_RDONLY,
                0,
            );
            if ret_ != FUSE_OK {
                return ret_;
            }

            if let Some(file) = file_opt {
                fset_xattr(&file, name, value, size, flags)
            } else {
                libc::EBADF
            }
        } else {
            if fchdir(&self.proc_dir) != FUSE_OK {
                panic!("setxattr: failed to change process directoy");
            }

            let ret_ = set_xattr(
                CString::new(format!("{}", &inode.file.as_raw_fd())).unwrap(),
                name,
                value,
                size,
                flags,
            );

            if fchdir(&self.root_inode.file) != FUSE_OK {
                panic!("setxattr: failed to change directoy of root inode");
            }

            ret_
        }
    }

    /// Get an extended attribute identified by name and associated with the node id
    /// in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to look up the inode.
    /// * `name` - The name associated with inode.
    /// * `size` - The size of the buffer.
    /// * `buff` - The buffer of the extended attribute.
    pub fn getxattr(&self, node_id: usize, name: CString, size: u32, buff: &mut Vec<u8>) -> i32 {
        let inode = match self.find_inode(node_id) {
            Some(i) => i.clone(),
            None => {
                return libc::EBADF;
            }
        };

        if inode.file_type & libc::S_IFREG != 0 || inode.file_type & libc::S_IFDIR != 0 {
            let (file_opt, ret) = open_at(
                &self.proc_dir,
                CString::new(format!("{}", &inode.file.as_raw_fd())).unwrap(),
                libc::O_RDONLY,
                0,
            );
            if ret != FUSE_OK {
                return ret;
            }

            if let Some(file) = file_opt {
                let (buf_opt, ret) = fget_xattr(&file, name, size as usize);
                if ret != FUSE_OK {
                    return ret;
                }
                if let Some(mut buf) = buf_opt {
                    buff.append(&mut buf);
                }
            } else {
                return libc::EBADF;
            }
        } else {
            if fchdir(&self.proc_dir) != FUSE_OK {
                panic!("getxattr: failed to change process directoy");
            }

            let (buf_opt, ret) = get_xattr(
                CString::new(format!("{}", &inode.file.as_raw_fd())).unwrap(),
                name,
                size as usize,
            );

            if fchdir(&self.root_inode.file) != FUSE_OK {
                panic!("getxattr: failed to change directoy of root inode");
            }
            if ret != FUSE_OK {
                return ret;
            }
            if let Some(mut buf) = buf_opt {
                buff.append(&mut buf);
            }
        }

        FUSE_OK
    }

    /// List extended attribute names associated with the node id
    /// in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to look up the inode.
    /// * `size` - The size of the buffer.
    /// * `buff` - The buffer of the extended attribute.
    pub fn listxattr(&self, node_id: usize, size: u32, buff: &mut Vec<u8>) -> i32 {
        let inode = match self.find_inode(node_id) {
            Some(i) => i.clone(),
            None => {
                return libc::EBADF;
            }
        };

        if inode.file_type & libc::S_IFREG != 0 || inode.file_type & libc::S_IFDIR != 0 {
            let (file_opt, ret) = open_at(
                &self.proc_dir,
                CString::new(format!("{}", &inode.file.as_raw_fd())).unwrap(),
                libc::O_RDONLY,
                0,
            );
            if ret != FUSE_OK {
                return ret;
            }

            if let Some(file) = file_opt {
                let (buf_opt, ret) = flist_xattr(&file, size as usize);
                if ret != FUSE_OK {
                    return ret;
                }
                if let Some(mut buf) = buf_opt {
                    buff.append(&mut buf);
                }
            } else {
                return libc::EBADF;
            }
        } else {
            if fchdir(&self.proc_dir) != FUSE_OK {
                panic!("listxattr: failed to change process directoy");
            }

            let (buf_opt, ret) = list_xattr(
                CString::new(format!("{}", &inode.file.as_raw_fd())).unwrap(),
                size as usize,
            );

            if fchdir(&self.root_inode.file) != FUSE_OK {
                panic!("listxattr: failed to change directoy of root inode");
            }
            if ret != FUSE_OK {
                return ret;
            }
            if let Some(mut buf) = buf_opt {
                buff.append(&mut buf);
            }
        }

        FUSE_OK
    }

    /// Remove an extended attribute identified by name and associated with the node id
    /// in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to look up the inode in the management of filesystem.
    /// * `name` - The name associated with inode.
    pub fn removexattr(&self, node_id: usize, name: CString) -> i32 {
        let inode = match self.find_inode(node_id) {
            Some(i) => i.clone(),
            None => {
                return libc::EBADF;
            }
        };

        if inode.file_type & libc::S_IFREG != 0 || inode.file_type & libc::S_IFDIR != 0 {
            let (file_opt, ret) = open_at(
                &self.proc_dir,
                CString::new(format!("{}", &inode.file.as_raw_fd())).unwrap(),
                libc::O_RDONLY,
                0,
            );
            if ret != FUSE_OK {
                return ret;
            }

            if let Some(file) = file_opt {
                let ret = fremove_xattr(&file, name);
                if ret != FUSE_OK {
                    return ret;
                }
            } else {
                return libc::EBADF;
            }
        } else {
            if fchdir(&self.proc_dir) != FUSE_OK {
                panic!("removexattr: failed to change process directoy");
            }

            let ret = remove_xattr(
                CString::new(format!("{}", &inode.file.as_raw_fd())).unwrap(),
                name,
            );

            if fchdir(&self.root_inode.file) != FUSE_OK {
                panic!("removexattr: failed to change directoy of root inode");
            }
            if ret != FUSE_OK {
                return ret;
            }
        }

        FUSE_OK
    }

    /// Delete the file lock by the node id in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to look up the inode in the management of filesystem.
    /// * `owner` - The name associated with inode.
    pub fn flush(&mut self, node_id: usize, owner: u64) -> i32 {
        self.delete_file_lock(node_id, owner)
    }

    /// Initialize fuse message for getting supported features in the process.
    ///
    /// # Arguments
    ///
    /// * `flags` - The supported features in StratoVirt.
    /// * `support_flags` - The supported features in the process.
    pub fn init(&self, flags: u32, support_flags: &mut u32) {
        if flags & FUSE_MAX_PAGES != 0 {
            *support_flags |= FUSE_MAX_PAGES;
        }
        if flags & FUSE_CAP_ASYNC_READ != 0 {
            *support_flags |= FUSE_ASYNC_READ;
        }
        if flags & FUSE_CAP_PARALLEL_DIROPS != 0 {
            *support_flags |= FUSE_PARALLEL_DIROPS;
        }
        if flags & FUSE_CAP_POSIX_LOCKS != 0 {
            *support_flags |= FUSE_POSIX_LOCKS;
        }
        if flags & FUSE_CAP_ATOMIC_O_TRUNC != 0 {
            *support_flags |= FUSE_ATOMIC_O_TRUNC;
        }
        if flags & FUSE_CAP_EXPORT_SUPPORT != 0 {
            *support_flags |= FUSE_EXPORT_SUPPORT;
        }
        if flags & FUSE_CAP_DONT_MASK != 0 {
            *support_flags |= FUSE_DONT_MASK;
        }
        if flags & FUSE_CAP_FLOCK_LOCKS != 0 {
            *support_flags |= FUSE_FLOCK_LOCKS;
        }
        if flags & FUSE_CAP_AUTO_INVAL_DATA != 0 {
            *support_flags |= FUSE_AUTO_INVAL_DATA;
        }
        if flags & FUSE_CAP_READDIRPLUS != 0 {
            *support_flags |= FUSE_DO_READDIRPLUS;
        }
        if flags & FUSE_CAP_READDIRPLUS_AUTO != 0 {
            *support_flags |= FUSE_READDIRPLUS_AUTO;
        }
        if flags & FUSE_CAP_ASYNC_DIO != 0 {
            *support_flags |= FUSE_ASYNC_DIO;
        }

        if flags & FUSE_CAP_POSIX_ACL != 0 {
            *support_flags |= FUSE_POSIX_ACL;
        }

        umask(0o000);
    }

    /// Open a directory with the node id in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to look up the inode in the management of filesystem.
    /// * `dir_fh` - The directory handler is returned in the management of filesystem.
    pub fn opendir(&mut self, node_id: usize, dir_fh: &mut u64) -> i32 {
        let inode = match self.find_inode(node_id) {
            Some(i) => i.clone(),
            None => {
                return libc::EBADF;
            }
        };

        let (file_opt, ret) = open_at(&inode.file, CString::new(".").unwrap(), libc::O_RDONLY, 0);
        if ret != FUSE_OK {
            return ret;
        }

        if let Some(file) = file_opt {
            *dir_fh = self.file_map.get_map(file) as u64;
            return FUSE_OK;
        }

        libc::EBADF
    }

    /// read a directory stream with the directory handler in the host filesystem.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to look up the inode in the management of filesystem.
    /// * `dh` - The directory handler in the management of filesystem.
    /// * `size` - The size of the buffer.
    /// * `offset` - The offset indicates it opens a directory stream with the offset.
    /// * `plus` - The plus indicates it uses FuseDirentplus struct to the buffer.
    /// * `buff` - The buffer of all FuseDirent structs or FuseDirentplus structs.
    pub fn readdir(
        &mut self,
        node_id: usize,
        dh: usize,
        size: u32,
        offset: u64,
        plus: bool,
        buff: &mut Vec<u8>,
    ) -> i32 {
        let dir_inode = match self.find_inode(node_id) {
            Some(i) => i.clone(),
            None => {
                return libc::EBADF;
            }
        };

        let mut dirp = match self.file_map.get_value_mut(dh) {
            Some(file) => {
                let (dirp_opt, ret) = fdopen_dir(file.as_raw_fd());
                if ret != FUSE_OK {
                    return libc::EBADF;
                }
                dirp_opt.unwrap()
            }
            _ => {
                return libc::EBADF;
            }
        };

        seek_dir(&mut dirp, offset);

        let mut remain = size;
        let mut son_nodeid = 0_u64;
        loop {
            let (dirent_opt, ret) = read_dir(&mut dirp);
            if ret != FUSE_OK {
                return ret;
            }
            let direntp = dirent_opt.unwrap();
            if direntp.is_null() {
                break;
            }

            // The above code has checked the validity of direntp, so it is safe for *direntp.
            let dirent = unsafe { *direntp };

            let (name_len, son_name) = match array_to_cstring(&dirent.d_name[..]) {
                Ok(v) => v,
                Err(_) => {
                    continue;
                }
            };

            let only_entry_size = if plus {
                mem::size_of::<FuseDirentplus>()
            } else {
                mem::size_of::<FuseDirent>()
            };

            let (entry_size, gap) = match round_up((only_entry_size + name_len) as u64, 8) {
                Some(v) => (v as u32, v as usize - (only_entry_size + name_len)),
                _ => {
                    return libc::EINVAL;
                }
            };
            if entry_size > remain {
                if son_nodeid != 0 {
                    self.forget(son_nodeid as usize, 1);
                }
                break;
            }

            let mut fuse_dirent = FuseDirent {
                ino: dirent.d_ino,
                off: dirent.d_off as u64,
                namelen: name_len as u32,
                type_: dirent.d_type as u32 & (libc::S_IFMT >> 12),
                name: [0u8; 0],
            };

            if dir_inode.node_id == self.root_inode.node_id && path_is_dotdot(&son_name) {
                fuse_dirent.ino = self.root_inode.key.ino;
                fuse_dirent.type_ = libc::DT_DIR as u32 & (libc::S_IFMT >> 12);
            }

            if plus {
                son_nodeid = 0;
                let mut son_attr = FuseAttr::default();
                if !path_is_dot(&son_name) && !path_is_dotdot(&son_name) {
                    let ret = self.internal_lookup(
                        &dir_inode,
                        son_name.clone(),
                        &mut son_nodeid,
                        &mut son_attr,
                    );
                    if ret != FUSE_OK {
                        return ret;
                    }
                }

                buff.extend_from_slice(
                    FuseDirentplus {
                        entry_out: FuseEntryOut {
                            nodeid: son_nodeid,
                            generation: 0,
                            entry_valid: 0,
                            entry_valid_nsec: 0,
                            attr_valid: 0,
                            attr_valid_nsec: 0,
                            attr: son_attr,
                        },
                        dirent: fuse_dirent,
                    }
                    .as_bytes(),
                );
            } else {
                buff.extend_from_slice(fuse_dirent.as_bytes());
            };

            buff.extend_from_slice(son_name.as_bytes());
            if gap > 0 {
                buff.append(&mut vec![0u8; gap]);
            }

            remain -= entry_size;
        }

        FUSE_OK
    }

    /// Release a directory in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `dir_fh` - The directory handler in the management of filesystem.
    pub fn releasedir(&mut self, dir_fh: usize) -> i32 {
        self.file_map.put_map(dir_fh);

        FUSE_OK
    }

    /// Transfer the directory data to the storage device with directory handler in
    /// the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `dir_fh` - The directory handler in the management of filesystem.
    /// * `datasync` - The datasync indicates whether to use the fdatasync
    /// or fsync interface.
    pub fn fsyncdir(&self, dir_fh: usize, datasync: bool) -> i32 {
        if let Some(file) = self.file_map.get_value(dir_fh) {
            let ret = fsync(file, datasync);
            if ret != FUSE_OK {
                return ret;
            }
        } else {
            return libc::EBADF;
        }

        FUSE_OK
    }

    /// Create the POSIX file lock with the node id in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to look up the inode in the management of filesystem.
    /// * `owner` - The unique index for file lock in the inode.
    /// * `file_lock_in` - The information of file lock will be set.
    /// * `file_lock_out` - The information of file lock will be returned.
    pub fn getlk(
        &mut self,
        node_id: usize,
        owner: u64,
        file_lock_in: &FuseFileLock,
        file_lock_out: &mut FuseFileLock,
    ) -> i32 {
        let (file_opt, ret) = self.create_file_lock(node_id, owner);
        if ret != FUSE_OK {
            return ret;
        }

        let ret = fcntl_flock(
            &file_opt.unwrap(),
            libc::F_GETLK,
            file_lock_in,
            file_lock_out,
        );
        if ret != FUSE_OK {
            return ret;
        }

        FUSE_OK
    }

    /// Lock the file or unlock the file by POSIX lock with the node id in
    /// the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node id used to look up the inode in the management of filesystem.
    /// * `owner` - The unique index for file lock in the inode.
    /// * `is_blocking` - The is_blocking indicates whether to use a blocking lock.
    /// * `file_lock_in` - The information of file lock will be set.
    pub fn setlk(
        &mut self,
        node_id: usize,
        owner: u64,
        is_blocking: bool,
        file_lock_in: &FuseFileLock,
    ) -> i32 {
        if is_blocking {
            return libc::EOPNOTSUPP;
        }

        let (file_opt, ret) = self.create_file_lock(node_id, owner);
        if ret != FUSE_OK {
            return ret;
        }

        let mut file_lock_out = FuseFileLock::default();
        let ret = fcntl_flock(
            &file_opt.unwrap(),
            libc::F_SETLK,
            file_lock_in,
            &mut file_lock_out,
        );
        if ret != FUSE_OK {
            return ret;
        }

        FUSE_OK
    }

    /// Lock the file or unlock the file by BSD lock with file handler in
    /// the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `fh` - The file handler in the management of filesystem.
    /// * `lock_type` - The lock type contains the type of read lock, write lock and unlocking.
    /// * `is_blocking` - The is_blocking indicates whether to use a blocking lock.
    pub fn flock(&self, fh: usize, lock_type: u32, is_blocking: bool) -> i32 {
        let mut operation: i32 = 0;

        if lock_type == F_RDLCK {
            operation = libc::LOCK_SH;
        } else if lock_type == F_WDLCK {
            operation = libc::LOCK_EX;
        } else if lock_type == F_UNLCK {
            operation = libc::LOCK_UN;
        }

        if !is_blocking {
            operation |= libc::LOCK_NB;
        }

        if let Some(file) = self.file_map.get_value(fh) {
            let ret = flock(file, operation);
            if ret != FUSE_OK {
                return ret;
            }
        } else {
            return libc::EBADF;
        }

        FUSE_OK
    }

    /// Create a file with name in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `in_header` - The in_header of fuse message used to get uid and gid.
    /// * `create_in` - The information of creating a file contains the flags, mode and umask.
    /// * `name` - The string of name used to create a file.
    /// * `fh` - The file handler is returned in the management of filesystem.
    /// * `node_id` - The node id that is found by the name in the management of filesystem.
    /// * `fuse_attr` - The attributes will be returned by the found inode.
    pub fn create(
        &mut self,
        in_header: &FuseInHeader,
        create_in: &FuseCreateIn,
        name: CString,
        fh: &mut u64,
        node_id: &mut u64,
        fuse_attr: &mut FuseAttr,
    ) -> i32 {
        let parent_dir = match self.find_inode(in_header.nodeid as usize) {
            Some(i) => i.clone(),
            _ => {
                return libc::EBADF;
            }
        };

        let mut old_uid = 0_u32;
        let mut old_gid = 0_u32;
        let ret = change_uid_gid(in_header.uid, in_header.gid, &mut old_uid, &mut old_gid);
        if ret != FUSE_OK {
            return ret;
        }

        let (file_opt, ret) = open_at(
            &parent_dir.file,
            name.clone(),
            (create_in.flags as i32 | libc::O_CREAT) & !libc::O_NOFOLLOW,
            create_in.mode & !(create_in.umask & 0o777),
        );

        recover_uid_gid(old_uid, old_gid);

        if ret != FUSE_OK {
            return ret;
        }

        if let Some(file) = file_opt {
            *fh = self.file_map.get_map(file.try_clone().unwrap()) as u64;
        }

        self.internal_lookup(&parent_dir, name, node_id, fuse_attr)
    }

    /// Destroy the management of filesystem, except for the root inode.
    pub fn destroy(&mut self) -> i32 {
        let root_key = self.root_inode.key;

        self.inode_key_map.destroy_map();
        self.file_map.destroy_map();
        self.inodes = BTreeMap::new();

        // Need to add root_inode back to the inode table and inode_key_map table for
        // the filesystem function
        let root_id = self.inode_key_map.get_map(root_key);
        self.root_inode.node_id = root_id;
        self.inodes.insert(root_key, self.root_inode.clone());

        FUSE_OK
    }

    /// Allocate the disk space with file handler in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `fh` - The file handler in the management of filesystem.
    /// * `mode` - The mode determines the operation to be performed on the given range.
    /// * `offset` - The offset in the file.
    /// * `length` - The length that needs to be allocated.
    pub fn fallocate(&self, fh: usize, mode: u32, offset: u64, length: u64) -> i32 {
        if let Some(file) = self.file_map.get_value(fh) {
            let ret = fallocate(file, mode, offset, length);
            if ret != FUSE_OK {
                return ret;
            }
        } else {
            return libc::EBADF;
        }

        FUSE_OK
    }

    /// Reposition the file offset of the open file with file handler
    /// in the management of filesystem.
    ///
    /// # Arguments
    ///
    /// * `fh` - The file handler in the management of filesystem.
    /// * `offset` - The offset in the file used together with the whence.
    /// * `whence` - The whence determines the operation to be performed in the file.
    /// * `outoffset` - The offset from the beginning of the file is returned.
    pub fn lseek(&self, fh: usize, offset: u64, whence: u32, outoffset: &mut u64) -> i32 {
        if let Some(file) = self.file_map.get_value(fh) {
            let (offset_tmp, ret) = lseek(file, offset, whence);
            if ret != FUSE_OK {
                return ret;
            }
            *outoffset = offset_tmp;
        } else {
            return libc::EBADF;
        }

        FUSE_OK
    }
}
