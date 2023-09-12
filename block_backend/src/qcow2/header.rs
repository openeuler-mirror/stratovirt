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

use anyhow::{bail, Context, Result};
use byteorder::{BigEndian, ByteOrder};

use super::ENTRY_SIZE;
use util::num_ops::div_round_up;

pub const QCOW_MAGIC: u32 = 0x514649fb;
const QCOW_VERSION_2_MIN_LEN: usize = 72;
const QCOW_VERSION_3_MIN_LEN: usize = 104;
const MIN_CLUSTER_BIT: u32 = 9;
const MAX_CLUSTER_BIT: u32 = 21;
const MAX_REFTABLE_SIZE: u64 = 8 * (1 << 20);
const MAX_L1TABLE_SIZE: u64 = 32 * (1 << 20);

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

    #[inline]
    pub fn cluster_size(&self) -> u64 {
        0x1 << self.cluster_bits
    }

    pub fn check(&self) -> Result<()> {
        if !(MIN_CLUSTER_BIT..=MAX_CLUSTER_BIT).contains(&self.cluster_bits) {
            bail!("Invalid cluster bits {}", self.cluster_bits);
        }
        if self.header_length as u64 > self.cluster_size() {
            bail!(
                "Header length {} over cluster size {}",
                self.header_length,
                self.cluster_size()
            );
        }
        // NOTE: not support backing file now.
        if self.backing_file_offset != 0 {
            bail!(
                "Don't support backing file offset, {}",
                self.backing_file_offset
            );
        }
        // NOTE: only support refcount_order == 4.
        if self.refcount_order != 4 {
            bail!(
                "Invalid refcount order {}, only support 4 now",
                self.refcount_order
            );
        }
        self.check_refcount_table()?;
        self.check_l1_table()?;
        Ok(())
    }

    fn check_refcount_table(&self) -> Result<()> {
        if self.refcount_table_clusters == 0 {
            bail!("Refcount table clusters is zero");
        }
        if self.refcount_table_clusters as u64 > MAX_REFTABLE_SIZE / self.cluster_size() {
            bail!(
                "Refcount table size over limit {}",
                self.refcount_table_clusters
            );
        }
        if !self.cluster_aligned(self.refcount_table_offset) {
            bail!(
                "Refcount table offset not aligned {}",
                self.refcount_table_offset
            );
        }
        self.refcount_table_offset
            .checked_add(self.refcount_table_clusters as u64 * self.cluster_size())
            .with_context(|| {
                format!(
                    "Invalid offset {} or refcount table clusters {}",
                    self.refcount_table_offset, self.refcount_table_clusters
                )
            })?;
        Ok(())
    }

    fn check_l1_table(&self) -> Result<()> {
        if self.l1_size as u64 > MAX_L1TABLE_SIZE / ENTRY_SIZE {
            bail!("L1 table size over limit {}", self.l1_size);
        }
        if !self.cluster_aligned(self.l1_table_offset) {
            bail!("L1 table offset not aligned {}", self.l1_table_offset);
        }
        let size_per_l1_entry = self.cluster_size() * self.cluster_size() / ENTRY_SIZE;
        let l1_need_sz =
            div_round_up(self.size, size_per_l1_entry).with_context(|| "Failed to get l1 size")?;
        if (self.l1_size as u64) < l1_need_sz {
            bail!(
                "L1 table is too small, l1 size {} expect {}",
                self.l1_size,
                l1_need_sz
            );
        }
        self.l1_table_offset
            .checked_add(self.l1_size as u64 * ENTRY_SIZE)
            .with_context(|| {
                format!(
                    "Invalid offset {} or entry size {}",
                    self.l1_table_offset, self.l1_size
                )
            })?;
        Ok(())
    }

    #[inline]
    fn cluster_aligned(&self, offset: u64) -> bool {
        offset & (self.cluster_size() - 1) == 0
    }
}

#[cfg(test)]
mod test {
    use crate::qcow2::header::*;

    const DEFAULT_CLUSTER_SIZE: u64 = 64 * 1024;

    fn valid_header_v3() -> Vec<u8> {
        // 10G
        vec![
            0x51, 0x46, 0x49, 0xfb, // magic
            0x00, 0x00, 0x00, 0x03, // version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // backing file offset
            0x00, 0x00, 0x00, 0x00, // backing file size
            0x00, 0x00, 0x00, 0x10, // cluster bits
            0x00, 0x00, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00, // size
            0x00, 0x00, 0x00, 0x00, // crypt method
            0x00, 0x00, 0x00, 0x14, // l1 size
            0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, // l1 table offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // refcount table offset
            0x00, 0x00, 0x00, 0x01, // refcount table clusters
            0x00, 0x00, 0x00, 0x00, // nb snapshots
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // snapshots offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // incompatible features
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // compatible features
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // autoclear features
            0x00, 0x00, 0x00, 0x04, // refcount order
            0x00, 0x00, 0x00, 0x68, // header length
        ]
    }

    fn extended_header_v3() -> Vec<u8> {
        // 10G
        let mut buf = valid_header_v3();
        buf.append(&mut vec![0_u8; 8]);
        BigEndian::write_u32(&mut buf[100..104], 112);
        buf
    }

    fn valid_header_v2() -> Vec<u8> {
        // 5G
        vec![
            0x51, 0x46, 0x49, 0xfb, // magic
            0x00, 0x00, 0x00, 0x02, // version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // backing file offset
            0x00, 0x00, 0x00, 0x00, // backing file size
            0x00, 0x00, 0x00, 0x10, // cluster bits
            0x00, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x00, // size
            0x00, 0x00, 0x00, 0x00, // crypt method
            0x00, 0x00, 0x00, 0x0a, // l1 size
            0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, // l1 table offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // refcount table offset
            0x00, 0x00, 0x00, 0x01, // refcount table clusters
            0x00, 0x00, 0x00, 0x00, // nb snapshots
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // snapshots offset
        ]
    }

    #[test]
    fn test_header_align() {
        // 8 bytes alignments
        let sz = std::mem::size_of::<QcowHeader>();
        assert_eq!(sz % 8, 0);
    }

    #[test]
    fn test_valid_header() {
        let buf = valid_header_v2();
        let header = QcowHeader::from_vec(&buf).unwrap();
        assert_eq!(header.magic, QCOW_MAGIC);
        assert_eq!(header.version, 2);
        assert_eq!(header.cluster_size(), DEFAULT_CLUSTER_SIZE);
        assert_eq!(header.header_length, QCOW_VERSION_2_MIN_LEN as u32);
        assert_eq!(buf, header.to_vec());

        let buf = valid_header_v3();
        let header = QcowHeader::from_vec(&buf).unwrap();
        assert_eq!(header.magic, QCOW_MAGIC);
        assert_eq!(header.version, 3);
        assert_eq!(header.cluster_size(), DEFAULT_CLUSTER_SIZE);
        assert_eq!(header.header_length, QCOW_VERSION_3_MIN_LEN as u32);
        assert_eq!(buf, header.to_vec());

        let buf = extended_header_v3();
        let header = QcowHeader::from_vec(&buf).unwrap();
        assert_eq!(header.magic, QCOW_MAGIC);
        assert_eq!(header.version, 3);
        assert_eq!(header.cluster_size(), DEFAULT_CLUSTER_SIZE);
        assert_eq!(header.header_length, 112);
        // NOTE: only care the length we supported.
        assert_eq!(buf[0..QcowHeader::len()], header.to_vec());
    }

    fn invalid_header_list() -> Vec<(Vec<u8>, String)> {
        let mut list = Vec::new();
        // Invalid buffer length.
        list.push((vec![0_u8; 16], format!("Invalid header len")));
        // Invalid buffer length for v3.
        let buf = valid_header_v3();
        list.push((
            buf[0..90].to_vec(),
            format!("Invalid header len for version 3"),
        ));
        // Invalid magic.
        let mut buf = valid_header_v2();
        BigEndian::write_u32(&mut buf[0..4], 1234);
        list.push((buf, format!("Invalid format")));
        // Invalid version.
        let mut buf = valid_header_v3();
        BigEndian::write_u32(&mut buf[4..8], 1);
        list.push((buf, format!("Invalid version")));
        // Large header length.
        let mut buf = valid_header_v3();
        BigEndian::write_u32(&mut buf[100..104], 0x10000000_u32);
        list.push((
            buf,
            format!("Header length {} over cluster size", 0x10000000_u32),
        ));
        // Small cluster bit.
        let mut buf = valid_header_v3();
        BigEndian::write_u32(&mut buf[20..24], 0);
        list.push((buf, format!("Invalid cluster bit")));
        // Large cluster bit.
        let mut buf = valid_header_v3();
        BigEndian::write_u32(&mut buf[20..24], 65);
        list.push((buf, format!("Invalid cluster bit")));
        // Invalid backing file offset.
        let mut buf = valid_header_v3();
        BigEndian::write_u32(&mut buf[8..16], 0x2000);
        list.push((buf, format!("Don't support backing file offset")));
        // Invalid refcount order.
        let mut buf = valid_header_v3();
        BigEndian::write_u32(&mut buf[96..100], 5);
        list.push((buf, format!("Invalid refcount order")));
        // Refcount table offset is not aligned.
        let mut buf = valid_header_v3();
        BigEndian::write_u64(&mut buf[48..56], 0x1234);
        list.push((buf, format!("Refcount table offset not aligned")));
        // Refcount table offset is large.
        let mut buf = valid_header_v3();
        BigEndian::write_u32(&mut buf[36..40], 4 * 1024 * 1024);
        BigEndian::write_u64(&mut buf[48..56], 0xffff_ffff_ffff_0000_u64);
        BigEndian::write_u32(&mut buf[56..60], 128);
        list.push((
            buf,
            format!(
                "Invalid offset {} or refcount table clusters {}",
                0xffff_ffff_ffff_0000_u64, 128
            ),
        ));
        // Invalid refcount table cluster.
        let mut buf = valid_header_v3();
        BigEndian::write_u32(&mut buf[56..60], 256);
        list.push((buf, format!("Refcount table size over limit")));
        // Refcount table cluster is 0.
        let mut buf = valid_header_v3();
        BigEndian::write_u32(&mut buf[56..60], 0);
        list.push((buf, format!("Refcount table clusters is zero")));
        // L1 table offset is not aligned.
        let mut buf = valid_header_v3();
        BigEndian::write_u64(&mut buf[40..48], 0x123456);
        list.push((buf, format!("L1 table offset not aligned")));
        // L1 table offset is large.
        let mut buf = valid_header_v3();
        BigEndian::write_u32(&mut buf[36..40], 4 * 1024 * 1024);
        BigEndian::write_u64(&mut buf[40..48], 0xffff_ffff_ffff_0000_u64);
        list.push((
            buf,
            format!(
                "Invalid offset {} or entry size {}",
                0xffff_ffff_ffff_0000_u64,
                4 * 1024 * 1024
            ),
        ));
        // Invalid l1 table size.
        let mut buf = valid_header_v3();
        BigEndian::write_u32(&mut buf[36..40], 0xffff_0000_u32);
        list.push((buf, format!("L1 table size over limit")));
        // File size is large than l1 table size.
        let mut buf = valid_header_v3();
        BigEndian::write_u64(&mut buf[24..32], 0xffff_ffff_ffff_0000_u64);
        BigEndian::write_u32(&mut buf[36..40], 10);
        list.push((buf, format!("L1 table is too small")));
        list
    }

    #[test]
    fn test_invalid_header() {
        let list = invalid_header_list();
        for (buf, err) in list {
            match QcowHeader::from_vec(&buf) {
                Ok(header) => {
                    let e = header.check().err().unwrap();
                    assert!(e.to_string().contains(&err));
                }
                Err(e) => {
                    assert!(e.to_string().contains(&err));
                }
            }
        }
    }
}
