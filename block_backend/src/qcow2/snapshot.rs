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

use std::{cell::RefCell, rc::Rc};
use std::{mem::size_of, str::from_utf8};

use anyhow::{bail, Context, Result};
use byteorder::{BigEndian, ByteOrder};

use super::{is_aligned, SyncAioInfo};
use util::num_ops::round_up;

/// Maximum number of snapshots.
pub const QCOW2_MAX_SNAPSHOTS: usize = 65536;

// Length of Qcow2 internal snapshot which doesn't have icount in extra data.
// Qcow2 snapshots created by qemu-img(version <= 5.0) may have this format.
const SNAPSHOT_EXTRA_DATA_LEN_16: usize = 16;
// Length of Qcow2 internal snapshot which has icount in extra data.
const SNAPSHOT_EXTRA_DATA_LEN_24: usize = 24;

#[derive(Clone)]
pub struct InternalSnapshot {
    pub snapshots: Vec<QcowSnapshot>,
    sync_aio: Rc<RefCell<SyncAioInfo>>,
    cluster_size: u64,
    // Total snapshot table size in bytes.
    pub snapshot_size: u64,
    pub snapshot_table_offset: u64,
    // Number of snapshot table entry.
    pub(crate) nb_snapshots: u32,
}

impl InternalSnapshot {
    pub fn new(sync_aio: Rc<RefCell<SyncAioInfo>>) -> Self {
        Self {
            snapshots: Vec::new(),
            sync_aio,
            cluster_size: 0,
            snapshot_size: 0,
            snapshot_table_offset: 0,
            nb_snapshots: 0,
        }
    }

    pub fn snapshots_number(&self) -> usize {
        self.nb_snapshots as usize
    }

    pub fn find_snapshot(&self, name: &String) -> i32 {
        for (idx, snap) in self.snapshots.iter().enumerate() {
            if snap.name.eq(name) {
                return idx as i32;
            }
        }
        -1
    }

    pub fn set_cluster_size(&mut self, cluster_size: u64) {
        self.cluster_size = cluster_size;
    }

    pub fn add_snapshot(&mut self, snap: QcowSnapshot) {
        let size = snap.get_size();
        self.snapshots.push(snap);
        self.snapshot_size += size;
        self.nb_snapshots += 1;
    }

    pub fn del_snapshot(&mut self, index: usize) -> QcowSnapshot {
        let snap = self.snapshots.remove(index);
        self.nb_snapshots -= 1;
        self.snapshot_size -= snap.get_size();

        snap
    }

    pub fn find_new_snapshot_id(&self) -> u64 {
        let mut id_max = 0;
        for snap in &self.snapshots {
            if id_max < snap.id {
                id_max = snap.id;
            }
        }

        id_max + 1
    }

    pub fn save_snapshot_table(
        &self,
        addr: u64,
        extra_snap: &QcowSnapshot,
        attach: bool,
    ) -> Result<()> {
        let mut buf = Vec::new();
        for snap in &self.snapshots {
            if !attach && snap.id == extra_snap.id {
                continue;
            }
            buf.append(&mut snap.gen_snapshot_table_entry());
        }
        if attach {
            buf.append(&mut extra_snap.gen_snapshot_table_entry());
        }
        self.sync_aio.borrow_mut().write_buffer(addr, &buf)
    }

    pub(crate) fn load_snapshot_table(
        &mut self,
        addr: u64,
        nb_snapshots: u32,
        repair: bool,
    ) -> Result<(i32, i32)> {
        let mut extra_data_dropped: i32 = 0;
        let mut clusters_reduced: i32 = 0;

        if nb_snapshots == 0 {
            self.nb_snapshots = 0;
            self.snapshots.clear();
            return Ok((clusters_reduced, extra_data_dropped));
        }

        if addr == 0 || !is_aligned(self.cluster_size, addr) {
            bail!(
                "The offset of snapshot table {} can't be 0 and mut aligned to cluster size",
                addr
            );
        }

        for i in 0..nb_snapshots {
            let offset = addr + self.snapshot_size;

            let mut pos = 0;
            let header_size = size_of::<QcowSnapshotHeader>();
            let mut header_buf = vec![0_u8; header_size];
            self.sync_aio
                .borrow_mut()
                .read_buffer(offset, &mut header_buf)
                .with_context(|| format!("read snapshot header error(addr {:x}).", offset))?;
            let header = QcowSnapshotHeader::from_vec(&header_buf)?;
            pos += header_size;

            let extra_size = header.extra_date_size as usize;
            if ![SNAPSHOT_EXTRA_DATA_LEN_16, SNAPSHOT_EXTRA_DATA_LEN_24].contains(&extra_size) {
                if !repair {
                    bail!("Too much extra metadata in snapshot table entry {}", i);
                }
                let err_msg = format!(
                    "Discarding too much extra metadata in snapshot table entry {}, {} > {}",
                    i, extra_size, SNAPSHOT_EXTRA_DATA_LEN_24
                );
                println!("{:?}", err_msg);
                extra_data_dropped += 1;
            }
            let mut extra_buf = vec![0_u8; extra_size];
            self.sync_aio
                .borrow_mut()
                .read_buffer(offset + pos as u64, &mut extra_buf)
                .with_context(|| {
                    format!(
                        "read snapshot extra data error(addr {:x}).",
                        offset + pos as u64
                    )
                })?;
            let extra = QcowSnapshotExtraData::from_vec(&extra_buf)?;
            pos += extra_size;

            if header.id_str_size == 0 {
                bail!("Invalid snapshot id size: 0");
            }
            let mut id_buf = vec![0_u8; header.id_str_size as usize];
            self.sync_aio
                .borrow_mut()
                .read_buffer(offset + pos as u64, &mut id_buf)
                .with_context(|| {
                    format!("read snapshot ID error(addr {:x}).", offset + pos as u64)
                })?;
            let id = from_utf8(&id_buf)?.parse::<u64>()?;
            pos += header.id_str_size as usize;

            let mut name_buf = vec![0_u8; header.name_size as usize];
            self.sync_aio
                .borrow_mut()
                .read_buffer(offset + pos as u64, &mut name_buf)
                .with_context(|| {
                    format!("read snapshot name error(addr {:x}).", offset + pos as u64)
                })?;
            let name = from_utf8(&name_buf)?;

            let snap = QcowSnapshot {
                l1_table_offset: header.l1_table_offset,
                l1_size: header.l1_size,
                id,
                name: name.to_string(),
                disk_size: extra.disk_size,
                vm_state_size: header.vm_state_size,
                date_sec: header.date_sec,
                date_nsec: header.date_nsec,
                vm_clock_nsec: header.vm_clock_nsec,
                icount: extra.icount,
                extra_data_size: header.extra_date_size,
            };

            self.add_snapshot(snap);
            if self.snapshot_size > QCOW2_MAX_SNAPSHOTS as u64 * 1024
                || offset - addr > i32::MAX as u64
            {
                if !repair {
                    bail!("Snapshot table is too big");
                }
                let err_msg = format!(
                    "Discarding {} overhanging snapshots(snapshot) table is too big",
                    nb_snapshots - i
                );
                println!("{:?}", err_msg);
                clusters_reduced += (nb_snapshots - i) as i32;
                self.del_snapshot(i as usize);
                self.nb_snapshots = i;
                break;
            }
        }

        Ok((clusters_reduced, extra_data_dropped))
    }
}

#[derive(Clone)]
pub struct QcowSnapshot {
    pub l1_table_offset: u64,
    pub l1_size: u32,
    pub id: u64,
    pub name: String,
    pub disk_size: u64,
    // VM state info size, used for vm snapshot.
    // Set to 0 for disk internal snapshot.
    pub vm_state_size: u32,
    pub date_sec: u32,
    pub date_nsec: u32,
    pub vm_clock_nsec: u64,
    // Icount value which corresponds to the record/replay instruction count when the snapshots was
    // token. Sed to -1 which means icount was disabled.
    pub icount: u64,
    pub extra_data_size: u32,
}

impl QcowSnapshot {
    pub fn get_size(&self) -> u64 {
        let tmp_size = size_of::<QcowSnapshotHeader>()
            + self.extra_data_size as usize
            + self.id.to_string().len()
            + self.name.len();

        round_up(tmp_size as u64, 8).unwrap()
    }

    pub(crate) fn gen_snapshot_table_entry(&self) -> Vec<u8> {
        let id_str = self.id.to_string();
        let entry_size = size_of::<QcowSnapshotHeader>() + self.extra_data_size as usize;
        let mut buf = vec![0_u8; entry_size];

        // Snapshot Header.
        BigEndian::write_u64(&mut buf[0..8], self.l1_table_offset);
        BigEndian::write_u32(&mut buf[8..12], self.l1_size);
        BigEndian::write_u16(&mut buf[12..14], id_str.len() as u16);
        BigEndian::write_u16(&mut buf[14..16], self.name.len() as u16);
        BigEndian::write_u32(&mut buf[16..20], self.date_sec);
        BigEndian::write_u32(&mut buf[20..24], self.date_nsec);
        BigEndian::write_u64(&mut buf[24..32], self.vm_clock_nsec);
        BigEndian::write_u32(&mut buf[32..36], self.vm_state_size);
        BigEndian::write_u32(&mut buf[36..40], self.extra_data_size);

        // Snapshot Extra data.
        // vm_state_size_large is used for vm snapshot.
        // It's equal to vm_state_size which is also 0 in disk snapshot.
        BigEndian::write_u64(&mut buf[40..48], self.vm_state_size as u64);
        BigEndian::write_u64(&mut buf[48..56], self.disk_size);
        if self.extra_data_size == SNAPSHOT_EXTRA_DATA_LEN_24 as u32 {
            BigEndian::write_u64(&mut buf[56..64], self.icount);
        }

        // Snapshot ID.
        let mut id_vec = id_str.as_bytes().to_vec();
        buf.append(&mut id_vec);

        // Snapshot Name.
        let mut name_vec = self.name.as_bytes().to_vec();
        buf.append(&mut name_vec);

        // 8 bytes Alignment.
        let tmp_size = buf.len();
        let size = round_up(tmp_size as u64, 8).unwrap();
        // SAFETY: The size is a round up of old size.
        buf.resize(size as usize, 0);

        buf
    }
}

pub struct QcowSnapshotHeader {
    l1_table_offset: u64,
    l1_size: u32,
    id_str_size: u16,
    name_size: u16,
    date_sec: u32,
    date_nsec: u32,
    vm_clock_nsec: u64,
    vm_state_size: u32,
    extra_date_size: u32,
}

impl QcowSnapshotHeader {
    fn from_vec(buf: &[u8]) -> Result<QcowSnapshotHeader> {
        if buf.len() < size_of::<QcowSnapshotHeader>() {
            bail!("Invalid qcow2 snapshot header length {}.", buf.len());
        }

        Ok(QcowSnapshotHeader {
            l1_table_offset: BigEndian::read_u64(&buf[0..8]),
            l1_size: BigEndian::read_u32(&buf[8..12]),
            id_str_size: BigEndian::read_u16(&buf[12..14]),
            name_size: BigEndian::read_u16(&buf[14..16]),
            date_sec: BigEndian::read_u32(&buf[16..20]),
            date_nsec: BigEndian::read_u32(&buf[20..24]),
            vm_clock_nsec: BigEndian::read_u64(&buf[24..32]),
            vm_state_size: BigEndian::read_u32(&buf[32..36]),
            extra_date_size: BigEndian::read_u32(&buf[36..40]),
        })
    }
}

pub struct QcowSnapshotExtraData {
    _vm_state_size_large: u64,
    disk_size: u64,
    icount: u64,
}

impl QcowSnapshotExtraData {
    fn from_vec(buf: &[u8]) -> Result<QcowSnapshotExtraData> {
        let has_icount = match buf.len() {
            SNAPSHOT_EXTRA_DATA_LEN_24 => true,
            SNAPSHOT_EXTRA_DATA_LEN_16 => false,
            _ => bail!("Invalid snapshot extra data length {}.", buf.len()),
        };

        let mut extra = QcowSnapshotExtraData {
            _vm_state_size_large: BigEndian::read_u64(&buf[0..8]),
            disk_size: BigEndian::read_u64(&buf[8..16]),
            icount: u64::MAX,
        };

        if has_icount {
            extra.icount = BigEndian::read_u64(&buf[16..24]);
        }

        Ok(extra)
    }
}
