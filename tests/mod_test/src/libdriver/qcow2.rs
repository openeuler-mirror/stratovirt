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

use std::cell::RefCell;
use std::rc::Rc;
use std::{
    fs::File,
    io::{Seek, SeekFrom, Write},
    os::unix::prelude::{AsRawFd, OpenOptionsExt},
};

use anyhow::{bail, Result};
use byteorder::{BigEndian, ByteOrder};
use libc::{c_int, iovec, off_t, preadv};
use serde_json::Value;

use crate::libtest::TestState;
use util::aio::Iovec;

const QCOW_MAGIC: u32 = 0x514649fb;
const ENTRY_SIZE: u64 = 8;
const QCOW_VERSION_2_MIN_LEN: usize = 72;
const QCOW_VERSION_3_MIN_LEN: usize = 104;
const QCOW2_OFFSET_COPIED: u64 = 1 << 63;
const CLUSTER_BITS: u64 = 16;
pub const CLUSTER_SIZE: u64 = 1 << CLUSTER_BITS;

#[derive(Debug)]
pub struct Qcow2Driver {
    header: QcowHeader,
    file: File,
}

impl Qcow2Driver {
    fn new(image_path: String) -> Self {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(image_path)
            .unwrap();

        let mut qcow2 = Qcow2Driver {
            header: QcowHeader::default(),
            file,
        };
        qcow2.load_header();
        qcow2
    }

    fn load_header(&mut self) {
        let mut buf = vec![0; QcowHeader::len()];
        let ret = self.raw_read(0, &mut buf);
        assert_eq!(ret, buf.len() as i64);
        self.header = QcowHeader::from_vec(&buf).unwrap();
    }

    fn raw_read(&self, offset: u64, buf: &mut [u8]) -> i64 {
        let ptr = buf.as_mut_ptr() as u64;
        let cnt = buf.len() as u64;
        let iovec = vec![Iovec::new(ptr, cnt)];
        let ret = unsafe {
            preadv(
                self.file.as_raw_fd() as c_int,
                iovec.as_ptr() as *const iovec,
                iovec.len() as c_int,
                offset as off_t,
            ) as i64
        };
        ret
    }

    fn raw_write(&mut self, offset: u64, buf: &mut [u8]) {
        self.file.seek(SeekFrom::Start(offset)).unwrap();
        self.file.write_all(&buf).unwrap();
    }
}

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct QcowHeader {
    pub magic: u32,
    pub version: u32,
    pub backing_file_offset: u64,
    pub backing_file_size: u32,
    pub cluster_bits: u32,
    pub size: u64,
    pub crypt_method: u32,
    pub l1_size: u32,
    pub l1_table_offset: u64,
    pub refcount_table_offset: u64,
    pub refcount_table_clusters: u32,
    pub nb_snapshots: u32,
    pub snapshots_offset: u64,
    // version >= v3
    pub incompatible_features: u64,
    pub compatible_features: u64,
    pub autoclear_features: u64,
    pub refcount_order: u32,
    pub header_length: u32,
}

impl QcowHeader {
    pub fn from_vec(buf: &[u8]) -> Result<QcowHeader> {
        if buf.len() < QCOW_VERSION_2_MIN_LEN {
            bail!(
                "Invalid header len {}, the min len {}",
                buf.len(),
                QCOW_VERSION_2_MIN_LEN
            );
        }
        let mut header = QcowHeader {
            magic: BigEndian::read_u32(&buf[0..4]),
            version: BigEndian::read_u32(&buf[4..8]),
            backing_file_offset: BigEndian::read_u64(&buf[8..16]),
            backing_file_size: BigEndian::read_u32(&buf[16..20]),
            cluster_bits: BigEndian::read_u32(&buf[20..24]),
            size: BigEndian::read_u64(&buf[24..32]),
            crypt_method: BigEndian::read_u32(&buf[32..36]),
            l1_size: BigEndian::read_u32(&buf[36..40]),
            l1_table_offset: BigEndian::read_u64(&buf[40..48]),
            refcount_table_offset: BigEndian::read_u64(&buf[48..56]),
            refcount_table_clusters: BigEndian::read_u32(&buf[56..60]),
            nb_snapshots: BigEndian::read_u32(&buf[60..64]),
            snapshots_offset: BigEndian::read_u64(&buf[64..72]),
            ..Default::default()
        };
        if header.magic != QCOW_MAGIC {
            bail!("Invalid format {}", header.magic);
        }
        if header.version == 2 {
            header.refcount_order = 4;
            header.header_length = QCOW_VERSION_2_MIN_LEN as u32;
        } else if header.version == 3 {
            if buf.len() < QCOW_VERSION_3_MIN_LEN {
                bail!("Invalid header len for version 3 {}", buf.len());
            }
            header.incompatible_features = BigEndian::read_u64(&buf[72..80]);
            header.compatible_features = BigEndian::read_u64(&buf[80..88]);
            header.autoclear_features = BigEndian::read_u64(&buf[88..96]);
            header.refcount_order = BigEndian::read_u32(&buf[96..100]);
            header.header_length = BigEndian::read_u32(&buf[100..104]);
        } else {
            bail!("Invalid version {}", header.version);
        }
        Ok(header)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let sz = if self.version == 2 {
            QCOW_VERSION_2_MIN_LEN
        } else {
            QcowHeader::len()
        };
        let mut buf = vec![0; sz];
        BigEndian::write_u32(&mut buf[0..4], self.magic);
        BigEndian::write_u32(&mut buf[4..8], self.version);
        BigEndian::write_u64(&mut buf[8..16], self.backing_file_offset);
        BigEndian::write_u32(&mut buf[16..20], self.backing_file_size);
        BigEndian::write_u32(&mut buf[20..24], self.cluster_bits);
        BigEndian::write_u64(&mut buf[24..32], self.size);
        BigEndian::write_u32(&mut buf[32..36], self.crypt_method);
        BigEndian::write_u32(&mut buf[36..40], self.l1_size);
        BigEndian::write_u64(&mut buf[40..48], self.l1_table_offset);
        BigEndian::write_u64(&mut buf[48..56], self.refcount_table_offset);
        BigEndian::write_u32(&mut buf[56..60], self.refcount_table_clusters);
        BigEndian::write_u32(&mut buf[60..64], self.nb_snapshots);
        BigEndian::write_u64(&mut buf[64..72], self.snapshots_offset);
        if self.version >= 3 {
            BigEndian::write_u64(&mut buf[72..80], self.incompatible_features);
            BigEndian::write_u64(&mut buf[80..88], self.compatible_features);
            BigEndian::write_u64(&mut buf[88..96], self.autoclear_features);
            BigEndian::write_u32(&mut buf[96..100], self.refcount_order);
            BigEndian::write_u32(&mut buf[100..104], self.header_length);
        }
        buf
    }

    #[inline]
    pub fn len() -> usize {
        std::mem::size_of::<Self>()
    }
}

// From size to bits.
fn size_to_bits(size: u64) -> Option<u64> {
    for i in 0..63 {
        if size >> i == 1 {
            return Some(i);
        }
    }
    return None;
}

/// Create a qcow2 format image for test.
pub fn create_qcow2_img(image_path: String, image_size: u64) {
    let img_bits = size_to_bits(image_size).unwrap();
    let img_size = image_size;
    let cluster_bits = CLUSTER_BITS;
    let cluster_sz = 1 << cluster_bits;

    let l1_entry_size: u64 = 1 << (cluster_bits * 2 - 3);
    let l1_size = (img_size + l1_entry_size - 1) / l1_entry_size;
    let header = QcowHeader {
        magic: QCOW_MAGIC,
        version: 3,
        backing_file_offset: 0,
        backing_file_size: 0,
        cluster_bits: cluster_bits as u32,
        size: 1 << img_bits,
        crypt_method: 0,
        l1_size: l1_size as u32,
        l1_table_offset: 3 * cluster_sz,
        refcount_table_offset: cluster_sz,
        refcount_table_clusters: 1,
        nb_snapshots: 0,
        snapshots_offset: 0,
        incompatible_features: 0,
        compatible_features: 0,
        autoclear_features: 0,
        refcount_order: 4,
        header_length: std::mem::size_of::<QcowHeader>() as u32,
    };

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CREAT | libc::O_TRUNC)
        .open(image_path.clone())
        .unwrap();
    file.set_len(cluster_sz * 3 + header.l1_size as u64 * ENTRY_SIZE)
        .unwrap();
    file.write_all(&header.to_vec()).unwrap();

    // Cluster 1 is the refcount table.
    assert_eq!(header.refcount_table_offset, cluster_sz * 1);
    let mut refcount_table = [0_u8; ENTRY_SIZE as usize];
    BigEndian::write_u64(&mut refcount_table, cluster_sz * 2);
    file.seek(SeekFrom::Start(cluster_sz * 1)).unwrap();
    file.write_all(&refcount_table).unwrap();

    // Clusters which has been allocated.
    assert_eq!(header.refcount_order, 4);
    let clusters =
        3 + ((header.l1_size * ENTRY_SIZE as u32 + cluster_sz as u32 - 1) >> cluster_bits);
    let mut refcount_block = Vec::new();
    for _ in 0..clusters {
        refcount_block.push(0x00);
        refcount_block.push(0x01);
    }
    file.seek(SeekFrom::Start(cluster_sz * 2)).unwrap();
    file.write_all(&refcount_block).unwrap();

    // Full the disk.
    write_full_disk(image_path);
}

/// Full the disk(this function is only used for test).
/// By default, the data occupied by the l2 table and refcount table should not exceed one cluster.
/// If the defined disk is too large, it may result in incorrect data format for.
/// For example.
/// If you defined cluster size = 1 <<  16, the max disk size cannout exceed the
/// 1 << (16 * 2 - 3) = 512M.
fn write_full_disk(image_path: String) {
    let mut qcow2 = Qcow2Driver::new(image_path);
    let cluster_bits = qcow2.header.cluster_bits;
    let cluster_size = 1 << cluster_bits;
    let image_size = qcow2.header.size;

    let n_cluster = image_size / cluster_size;
    // Header + refcount table + refcount block + l1 table + l2 table = 5 cluster.
    qcow2.file.set_len((5 + n_cluster) * cluster_size).unwrap();
    // Write l2 table.
    let mut refcount_block: Vec<u8> = Vec::new();
    let mut l1_table = [0_u8; ENTRY_SIZE as usize];
    BigEndian::write_u64(&mut l1_table, cluster_size * 4 | QCOW2_OFFSET_COPIED);
    let mut l2_table: Vec<u8> = Vec::new();
    for _ in 0..5 {
        refcount_block.push(0x00);
        refcount_block.push(0x01);
    }
    let offset_start = 5 * cluster_size;
    for i in 0..n_cluster {
        let addr = offset_start + i * cluster_size;
        let l2_table_value = addr | QCOW2_OFFSET_COPIED;

        let mut tmp_buf = vec![0_u8; ENTRY_SIZE as usize];
        BigEndian::write_u64(&mut tmp_buf, l2_table_value);
        l2_table.append(&mut tmp_buf);
        refcount_block.push(0x00);
        refcount_block.push(0x01);

        let mut cluster_buff = vec![0_u8; cluster_size as usize];
        qcow2.raw_write(addr, &mut cluster_buff);
    }
    qcow2.raw_write(cluster_size * 2, &mut refcount_block);
    qcow2.raw_write(cluster_size * 3, &mut l1_table);
    qcow2.raw_write(cluster_size * 4, &mut l2_table);
}

pub fn create_snapshot(state: Rc<RefCell<TestState>>, device: &str, snap: &str) {
    let qmp_str = format!("{{\"execute\":\"blockdev-snapshot-internal-sync\",\"arguments\":{{\"device\":\"{}\",\"name\":\"{}\"}}}}", device, snap);
    state.borrow_mut().qmp(&qmp_str);
}

pub fn delete_snapshot(state: Rc<RefCell<TestState>>, device: &str, snap: &str) {
    let qmp_str = format!("{{\"execute\":\"blockdev-snapshot-delete-internal-sync\",\"arguments\":{{\"device\":\"{}\",\"name\":\"{}\"}}}}", device, snap);
    state.borrow_mut().qmp(&qmp_str);
}

pub fn query_snapshot(state: Rc<RefCell<TestState>>) -> Value {
    let qmp_str =
        format!("{{\"execute\":\"human-monitor-command\",\"arguments\":{{\"command-line\":\"info snapshots\"}}}}");
    let value = state.borrow_mut().qmp(&qmp_str);

    value
}

// Check if there exists snapshot with the specified name.
pub fn check_snapshot(state: Rc<RefCell<TestState>>, snap: &str) -> bool {
    let value = query_snapshot(state.clone());
    let str = (*value.get("return").unwrap()).as_str().unwrap();
    let lines: Vec<&str> = str.split("\r\n").collect();
    for line in lines {
        let buf: Vec<&str> = line.split_whitespace().collect();
        if buf.len() > 2 && buf[1] == snap {
            return true;
        }
    }

    false
}
