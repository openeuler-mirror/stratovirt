// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
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

//! Test cases for the `stratovirt-img tailappend` subcommand.
//!
//! Each case constructs a tail-cluster-loss qcow2 by truncating the host file
//! (mimicking host-power-loss i_size reversion), confirms the image is corrupt
//! via `check`, repairs it with `tailappend`, then verifies it is check-clean.

use std::env;
use std::fs::{remove_file, File};
use std::os::unix::prelude::FileExt;
use std::process::Command;
use std::sync::Arc;

use block_backend::{
    qcow2::{
        header::QcowHeader, InternalSnapshotOps, Qcow2Driver, SyncAioInfo, L1_TABLE_OFFSET_MASK,
        L2_TABLE_OFFSET_MASK, REFCOUNT_TABLE_OFFSET_MASK,
    },
    BlockDriverOps, BlockProperty,
};
use machine_manager::config::DiskFormat;
use util::aio::{Aio, AioEngine, Iovec};
use util::file::open_file;

/// Virtual size used for the generated test images.
const IMG_SIZE: &str = "128M";

/// Resize target that makes the active L1 table span 2 clusters, so it can be
/// lost whole or partly. With a 64K cluster size: one L2 entry maps 64K, one
/// L2 cluster maps (64K / 8B) * 64K = 512M, one L1 cluster maps (64K / 8B) *
/// 512M = 4T.
///
/// So any size above 4T needs 2 L1 clusters (5T = 10240 entries = 80K = 2
/// clusters).
const RESIZE_TO_5T: u64 = 5 * (1 << 40);
/// Guest offsets at or above it are mapped by the lost L1 cluster in the
/// partial-loss case.
const L1_LOST_HALF: u64 = 4 * (1 << 40);

/// Snapshot count and name padding for the partial snapshot-table loss: each
/// entry is 40B header + 16B extra + id + name, 8-byte aligned; with a 1K
/// name that is ~1088B per entry, so 64 entries = ~68K > one 64K cluster and
/// the table spans 2 clusters.
const SNAPSHOT_TABLE_PARTIAL_COUNT: u32 = 64;
const SNAPSHOT_NAME_PAD: usize = 1024;

/// The cluster type whose tail cluster is dropped by truncation.
///
/// `SnapshotData`, `SnapshotL2`, `SnapshotL1Partial` and `Header` are NOT
/// CONSTRUCTIBLE: no power-loss sequence can reach that state. Their
/// constructors are absent; the variants exist only to complete the type
/// matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // not-constructible variants exist to complete the matrix only
enum TailLossType {
    /// Active (currently visible) data cluster at the file tail.
    ActiveData,
    /// NOT CONSTRUCTIBLE: a snapshot references tail clusters only together
    /// with the active L1 (identical entries when no COW happened after
    /// create_snapshot; COW'd tail clusters belong to the active side).
    SnapshotData,

    /// Active L2 table (whole cluster; no partial form).
    ActiveL2,
    /// NOT CONSTRUCTIBLE: same as SnapshotData.
    SnapshotL2,

    /// The whole active L1 table (moved to the tail by resize).
    ActiveL1,
    /// The upper half of the active L1 table (2 clusters after resize to 5T).
    ActiveL1Partial,

    /// Snapshot L1 table together with the snapshot table above it.
    SnapshotL1,
    /// NOT CONSTRUCTIBLE: the snapshot table is always allocated directly
    /// above the snapshot L1, so any cut inside the L1 also cuts the table.
    SnapshotL1Partial,

    /// The snapshot table (the snapshot L1 below it survives).
    SnapshotTable,
    /// The 2nd cluster of a 2-cluster snapshot table (64 snapshots with 1K
    /// names); the entries fully inside the 1st cluster survive.
    SnapshotTablePartial,

    /// The tail refcount block (whole cluster; no partial form).
    RefcountBlock,

    /// The whole refcount table (moved to the tail by small-cluster growth).
    RefcountTable,
    /// The upper half of the refcount table.
    RefcountTablePartial,
    /// NOT CONSTRUCTIBLE: the header lives in cluster 0.
    Header,
}

impl TailLossType {
    fn as_str(self) -> &'static str {
        match self {
            TailLossType::ActiveData => "active-data",
            TailLossType::SnapshotData => "snapshot-data",
            TailLossType::ActiveL2 => "active-l2",
            TailLossType::SnapshotL2 => "snapshot-l2",
            TailLossType::ActiveL1 => "active-l1",
            TailLossType::ActiveL1Partial => "active-l1-partial",
            TailLossType::SnapshotL1 => "snapshot-l1",
            TailLossType::SnapshotL1Partial => "snapshot-l1-partial",
            TailLossType::SnapshotTable => "snapshot-table",
            TailLossType::SnapshotTablePartial => "snapshot-table-partial",
            TailLossType::RefcountBlock => "refcount-block",
            TailLossType::RefcountTable => "refcount-table",
            TailLossType::RefcountTablePartial => "refcount-table-partial",
            TailLossType::Header => "header",
        }
    }

    fn cluster_size_opt(self) -> u64 {
        match self {
            TailLossType::RefcountBlock
            | TailLossType::RefcountTable
            | TailLossType::RefcountTablePartial => 512,
            _ => 65536,
        }
    }

    fn needs_snapshot(self) -> bool {
        matches!(
            self,
            TailLossType::SnapshotL1
                | TailLossType::SnapshotL1Partial
                | TailLossType::SnapshotTable
                | TailLossType::SnapshotTablePartial
        )
    }

    fn snapshot_count(self) -> u32 {
        match self {
            TailLossType::SnapshotTablePartial => SNAPSHOT_TABLE_PARTIAL_COUNT,
            _ => 1,
        }
    }

    /// Name of the i-th snapshot: SnapshotTablePartial needs a large name so
    /// that the snapshot table spans multiple clusters.
    fn snapshot_name(self, i: u32) -> String {
        if self == TailLossType::SnapshotTablePartial {
            format!("inject{i}_{}", "s".repeat(SNAPSHOT_NAME_PAD))
        } else {
            format!("inject{i}")
        }
    }

    /// Resize target: expanding to 5T re-allocates the L1 table (2 clusters)
    /// at the file tail, where truncation can reach it.
    fn resize_to(self) -> Option<u64> {
        match self {
            TailLossType::ActiveL1 | TailLossType::ActiveL1Partial => Some(RESIZE_TO_5T),
            _ => None,
        }
    }

    /// Whether growth must run until the refcount table migrates to the tail.
    fn needs_rt_migration(self) -> bool {
        matches!(
            self,
            TailLossType::RefcountTable | TailLossType::RefcountTablePartial
        )
    }
}

/// Path of the stratovirt-img binary, from the STRATOVIRT_IMG_BINARY
/// environment variable (same pattern as STRATOVIRT_BINARY in libtest).
fn stratovirt_img_binary() -> String {
    env::var("STRATOVIRT_IMG_BINARY")
        .expect("STRATOVIRT_IMG_BINARY is not set (path of the stratovirt-img binary)")
}

/// Run `stratovirt-img <args...>` and assert it succeeds.
fn run_stratovirt_img(args: &[&str]) {
    let (ok, stdout) = run_stratovirt_img_raw(args);
    assert!(ok, "stratovirt-img {args:?} failed:\n{stdout}");
}

/// Open the image read-only and run `check`; return true when the image is
/// fully consistent (no errors, corruptions or leaks).
fn image_is_clean(path: &str) -> bool {
    let Ok(output) = Command::new(stratovirt_img_binary())
        .args(["check", path])
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.contains("No errors were found on the image.")
        && !stdout.contains("corruption")
        && !stdout.contains("leak")
}

/// Run `stratovirt-img <args...>` without asserting success; return (success, stdout).
fn run_stratovirt_img_raw(args: &[&str]) -> (bool, String) {
    let output = Command::new(stratovirt_img_binary())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run stratovirt-img: {}", e));
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

/// Snapshot tags of an image, in order, via `stratovirt-img snapshot -l`.
fn snapshot_tags(path: &str) -> Vec<String> {
    let (_, stdout) = run_stratovirt_img_raw(&["snapshot", "-l", path]);
    // List lines look like "1  s1  0 B  ..."; header lines start with a letter.
    stdout
        .lines()
        .filter(|l| l.starts_with(char::is_numeric))
        .filter_map(|l| l.split_whitespace().nth(1).map(String::from))
        .collect()
}

/// Construct a tail-cluster-loss qcow2: create a fresh image, grow it so the
/// targeted structure sits at the file tail, then truncate the host file so
/// it falls beyond EOF. No metadata is rewritten -- faithful to host-power-loss
/// i_size reversion.
fn inject_tail_loss(path: &str, typ: TailLossType) {
    let (ok, stdout) = run_stratovirt_img_raw(&[
        "create",
        "-f",
        "qcow2",
        "-o",
        &format!("cluster_size={}", typ.cluster_size_opt()),
        path,
        IMG_SIZE,
    ]);
    assert!(ok, "stratovirt-img create failed:\n{stdout}");

    let file = Arc::new(
        open_file(path, false, false).unwrap_or_else(|e| panic!("open {path} failed: {e:?}")),
    );
    let mut header_buf = vec![0u8; QcowHeader::len()];
    file.read_at(&mut header_buf, 0).unwrap();
    let cluster_size = QcowHeader::from_vec(&header_buf).unwrap().cluster_size();

    let conf = BlockProperty {
        format: DiskFormat::Qcow2,
        ..Default::default()
    };
    let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off, None)
        .expect("create aio failed");
    let mut drv = Qcow2Driver::new(file.clone(), aio, conf.clone()).expect("open qcow2 failed");
    drv.load_metadata(conf.clone())
        .expect("load metadata failed");
    let buf = vec![0xAA_u8; cluster_size as usize];

    if typ.needs_rt_migration() {
        // Write data until the refcount table migrates to the file tail.
        let rt_off_initial = drv.header.refcount_table_offset;
        let mut guest_off: u64 = 0;
        loop {
            let iov = Iovec {
                iov_base: buf.as_ptr() as u64,
                iov_len: buf.len() as u64,
            };
            drv.write_vectored(vec![iov], guest_off as usize, ())
                .expect("write failed");
            guest_off += cluster_size;
            if drv.header.refcount_table_offset != rt_off_initial {
                break;
            }
        }
    } else if typ == TailLossType::RefcountBlock {
        // Write data until the 2nd refblock appears (allocated after the
        // triggering data cluster, so it lands at the file tail).
        let mut guest_off: u64 = 0;
        loop {
            let iov = Iovec {
                iov_base: buf.as_ptr() as u64,
                iov_len: buf.len() as u64,
            };
            drv.write_vectored(vec![iov], guest_off as usize, ())
                .expect("write failed");
            guest_off += cluster_size;
            let nonzero = drv
                .refcount
                .refcount_table
                .iter()
                .filter(|e| **e & REFCOUNT_TABLE_OFFSET_MASK != 0)
                .count();
            if nonzero >= 2 {
                break;
            }
        }
    } else {
        for i in 0..4u64 {
            let iov = Iovec {
                iov_base: buf.as_ptr() as u64,
                iov_len: buf.len() as u64,
            };
            drv.write_vectored(vec![iov], (i * cluster_size) as usize, ())
                .expect("write failed");
        }
    }

    // Move the L1 table to the file tail by expanding the image.
    if let Some(sz) = typ.resize_to() {
        drv.resize(sz).expect("resize failed");

        // For the partial-L1 case, dirty the upper half too: the data written
        // after resize is mapped by the upper (to-be-lost) L1 cluster and its
        // L2/data clusters land above the L1, all beyond the cut. This way
        // "reads back as zeros after repair" is a real assertion.
        if typ == TailLossType::ActiveL1Partial {
            let bb = vec![0xBB_u8; cluster_size as usize];
            let iov = Iovec {
                iov_base: bb.as_ptr() as u64,
                iov_len: bb.len() as u64,
            };
            drv.write_vectored(vec![iov], L1_LOST_HALF as usize, ())
                .expect("write failed");
        }
    }

    if typ.needs_snapshot() {
        for i in 0..typ.snapshot_count() {
            drv.create_snapshot(typ.snapshot_name(i), 0)
                .expect("create_snapshot failed");
        }
    }

    // Flush metadata so the disk reads below observe the just-written entries.
    drv.flush().expect("flush failed");

    let target_offset = compute_truncate_target(&file, &drv, typ)
        .unwrap_or_else(|e| panic!("compute_truncate_target failed: {e:?}"));

    let cur_len = file.metadata().unwrap().len();
    assert!(
        target_offset < cur_len,
        "target offset {target_offset:#X} must be < file size {cur_len:#X}"
    );
    file.set_len(target_offset).unwrap();
}

/// Compute the host-file offset to truncate to for each loss type.
fn compute_truncate_target(
    file: &Arc<File>,
    drv: &Qcow2Driver<()>,
    typ: TailLossType,
) -> anyhow::Result<u64> {
    let cluster_size = drv.header.cluster_size();
    match typ {
        TailLossType::ActiveData | TailLossType::ActiveL2 => {
            let l1_table = drv.table.l1_table.clone();
            let mut l2_offs: Vec<u64> = Vec::new();
            let mut data_offs: Vec<u64> = Vec::new();
            let mut l2_buf = vec![0u8; cluster_size as usize];
            for l1e in l1_table.iter() {
                let l2o = *l1e & L1_TABLE_OFFSET_MASK;
                if l2o == 0 {
                    continue;
                }
                l2_offs.push(l2o);
                file.read_at(&mut l2_buf, l2o)?;
                for chunk in l2_buf.chunks_exact(8) {
                    let d = u64::from_be_bytes(chunk.try_into().unwrap()) & L2_TABLE_OFFSET_MASK;
                    if d != 0 {
                        data_offs.push(d);
                    }
                }
            }
            if typ == TailLossType::ActiveData {
                data_offs.sort_unstable();
                Ok(*data_offs
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("no data clusters found"))?)
            } else {
                l2_offs.sort_unstable();
                Ok(*l2_offs
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("no L2 table clusters found"))?)
            }
        }
        TailLossType::ActiveL1 => Ok(drv.header.l1_table_offset),
        TailLossType::ActiveL1Partial => Ok(drv.header.l1_table_offset + cluster_size),
        TailLossType::RefcountBlock => Ok(drv
            .refcount
            .refcount_table
            .get(1)
            .and_then(|e| {
                let o = *e & REFCOUNT_TABLE_OFFSET_MASK;
                if o != 0 {
                    Some(o)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow::anyhow!("2nd refcount block not found"))?),
        TailLossType::RefcountTable | TailLossType::RefcountTablePartial => {
            let rt_off = drv.header.refcount_table_offset;
            if typ == TailLossType::RefcountTablePartial {
                // Cut inside the table: the first cluster survives.
                Ok(rt_off + cluster_size)
            } else {
                Ok(rt_off)
            }
        }
        TailLossType::SnapshotTable => Ok(drv.header.snapshots_offset),
        TailLossType::SnapshotL1 => {
            // The snapshot L1 offset is the first 8 bytes of the table entry.
            let mut ebuf = [0u8; 8];
            file.read_at(&mut ebuf, drv.header.snapshots_offset)?;
            Ok(u64::from_be_bytes(ebuf))
        }
        TailLossType::SnapshotTablePartial => {
            // Cut at the 2nd table cluster: the entries in the 1st cluster
            // survive, the rest is lost.
            Ok(drv.header.snapshots_offset + cluster_size)
        }
        // Not constructible by any power-loss sequence (see the enum docs).
        TailLossType::SnapshotData
        | TailLossType::SnapshotL2
        | TailLossType::SnapshotL1Partial
        | TailLossType::Header => {
            anyhow::bail!("{} tail loss is not constructible", typ.as_str())
        }
    }
}

/// One tailappend case: inject a tail loss, check the image is corrupt, repair
/// with tailappend, then check it is clean again. Data readback: everything
/// the surviving metadata maps must read back as 0xAA (the injected data),
/// proving the repair does not touch what survived the loss.
fn tailappend_case(typ: TailLossType) {
    let path = format!("/tmp/tailappend_{}.qcow2", typ.as_str());
    let _ = remove_file(&path);

    inject_tail_loss(&path, typ);
    assert!(
        !image_is_clean(&path),
        "image must be corrupt after {} tail loss",
        typ.as_str()
    );

    run_stratovirt_img(&["tailappend", &path]);

    assert!(
        image_is_clean(&path),
        "image must be check-clean after tailappend ({} tail loss)",
        typ.as_str()
    );
    let data = read_guest(&path, 0, 4096);
    assert!(
        data.iter().all(|&b| b == 0xAA),
        "data must read back as the injected 0xAA after repair ({} tail loss)",
        typ.as_str()
    );

    let _ = remove_file(&path);
}

/// Read guest data from an image via a fresh qcow2 driver (for readback
/// assertions after repair).
fn read_guest(path: &str, offset: u64, len: usize) -> Vec<u8> {
    let file = Arc::new(
        open_file(path, false, false).unwrap_or_else(|e| panic!("open {path} failed: {e:?}")),
    );
    let conf = BlockProperty {
        format: DiskFormat::Qcow2,
        ..Default::default()
    };
    let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off, None)
        .expect("create aio failed");
    let mut drv = Qcow2Driver::new(file, aio, conf.clone()).expect("open qcow2 failed");
    drv.load_metadata(conf).expect("load metadata failed");
    let buf = vec![0u8; len];
    let iov = Iovec {
        iov_base: buf.as_ptr() as u64,
        iov_len: len as u64,
    };
    drv.read_vectored(vec![iov], offset as usize, ())
        .expect("read failed");
    buf
}

/// Tail data-cluster loss: the first 3 clusters survive, the 4th (the highest
/// data offset) is lost. After repair the survivors read back as 0xAA and the
/// lost one as zeros.
#[test]
fn test_tailappend_active_data() {
    let path = format!(
        "/tmp/tailappend_{}.qcow2",
        TailLossType::ActiveData.as_str()
    );
    let _ = remove_file(&path);

    inject_tail_loss(&path, TailLossType::ActiveData);
    assert!(
        !image_is_clean(&path),
        "image must be corrupt after active data tail loss"
    );

    run_stratovirt_img(&["tailappend", &path]);

    assert!(image_is_clean(&path), "repaired image must be check-clean");
    let data = read_guest(&path, 0, 3 * 65536);
    assert!(
        data.iter().all(|&b| b == 0xAA),
        "surviving data clusters must be preserved"
    );
    let data = read_guest(&path, 3 * 65536, 65536);
    assert!(
        data.iter().all(|&b| b == 0),
        "lost data cluster must read back as zeros"
    );

    let _ = remove_file(&path);
}

/// Whole L2-cluster loss (no partial form): the only L2 table is lost, so all
/// guest data becomes unreachable and reads back as zeros after repair.
#[test]
fn test_tailappend_active_l2() {
    let path = format!("/tmp/tailappend_{}.qcow2", TailLossType::ActiveL2.as_str());
    let _ = remove_file(&path);

    inject_tail_loss(&path, TailLossType::ActiveL2);
    assert!(
        !image_is_clean(&path),
        "image must be corrupt after active L2 tail loss"
    );

    run_stratovirt_img(&["tailappend", &path]);

    assert!(image_is_clean(&path), "repaired image must be check-clean");
    let data = read_guest(&path, 0, 65536);
    assert!(
        data.iter().all(|&b| b == 0),
        "data mapped by the lost L2 cluster must read back as zeros"
    );

    let _ = remove_file(&path);
}

#[test]
fn test_tailappend_refcount_block() {
    tailappend_case(TailLossType::RefcountBlock);
}

/// Whole snapshot-table loss: the snapshot list is dropped, the active data
/// survives untouched.
#[test]
fn test_tailappend_snapshot_table() {
    let path = format!(
        "/tmp/tailappend_{}.qcow2",
        TailLossType::SnapshotTable.as_str()
    );
    let _ = remove_file(&path);

    inject_tail_loss(&path, TailLossType::SnapshotTable);
    assert!(
        !image_is_clean(&path),
        "image must be corrupt after snapshot-table tail loss"
    );

    run_stratovirt_img(&["tailappend", &path]);

    assert!(image_is_clean(&path), "repaired image must be check-clean");
    let data = read_guest(&path, 0, 4096);
    assert!(
        data.iter().all(|&b| b == 0xAA),
        "active data must survive the snapshot loss"
    );
    assert!(
        snapshot_tags(&path).is_empty(),
        "all snapshots must be dropped when the snapshot table is lost"
    );

    let _ = remove_file(&path);
}

/// Snapshot-L1 loss (the snapshot table goes with it): the snapshot list is
/// dropped, the active data survives untouched.
#[test]
fn test_tailappend_snapshot_l1() {
    let path = format!(
        "/tmp/tailappend_{}.qcow2",
        TailLossType::SnapshotL1.as_str()
    );
    let _ = remove_file(&path);

    inject_tail_loss(&path, TailLossType::SnapshotL1);
    assert!(
        !image_is_clean(&path),
        "image must be corrupt after snapshot L1 tail loss"
    );

    run_stratovirt_img(&["tailappend", &path]);

    assert!(image_is_clean(&path), "repaired image must be check-clean");
    let data = read_guest(&path, 0, 4096);
    assert!(
        data.iter().all(|&b| b == 0xAA),
        "active data must survive the snapshot loss"
    );
    assert!(
        snapshot_tags(&path).is_empty(),
        "all snapshots must be dropped when the snapshot L1 is lost"
    );

    let _ = remove_file(&path);
}

/// Whole active L1 loss after resize: every visible cluster becomes orphaned,
/// so the guest data reads back as zeros after repair.
#[test]
fn test_tailappend_active_l1() {
    let path = format!("/tmp/tailappend_{}.qcow2", TailLossType::ActiveL1.as_str());
    let _ = remove_file(&path);

    inject_tail_loss(&path, TailLossType::ActiveL1);
    assert!(
        !image_is_clean(&path),
        "image must be corrupt after active L1 tail loss"
    );

    run_stratovirt_img(&["tailappend", &path]);

    assert!(image_is_clean(&path), "repaired image must be check-clean");
    let data = read_guest(&path, 0, 4096);
    assert!(
        data.iter().all(|&b| b == 0),
        "lost contents become zeros: guest data must read back as zeros"
    );

    let _ = remove_file(&path);
}

/// Upper half of the active L1 lost after resize: data mapped by the surviving
/// lower cluster (guest offset 0) must survive the repair intact, while data
/// that was mapped by the lost upper cluster reads back as zeros.
#[test]
fn test_tailappend_active_l1_partial() {
    let path = format!(
        "/tmp/tailappend_{}.qcow2",
        TailLossType::ActiveL1Partial.as_str()
    );
    let _ = remove_file(&path);

    inject_tail_loss(&path, TailLossType::ActiveL1Partial);
    assert!(
        !image_is_clean(&path),
        "image must be corrupt after partial active L1 tail loss"
    );

    run_stratovirt_img(&["tailappend", &path]);

    assert!(image_is_clean(&path), "repaired image must be check-clean");
    let data = read_guest(&path, 0, 4 * 65536);
    assert!(
        data.iter().all(|&b| b == 0xAA),
        "data mapped by the surviving L1 cluster must be preserved"
    );
    let data = read_guest(&path, L1_LOST_HALF, 65536);
    assert!(
        data.iter().all(|&b| b == 0),
        "data mapped by the lost L1 cluster must read back as zeros"
    );

    let _ = remove_file(&path);
}

/// Partial snapshot-table loss (64 snapshots with 1K names span 2 table
/// clusters): the 2nd cluster is lost. tailappend keeps the snapshots whose
/// entries live in the surviving 1st cluster.
#[test]
fn test_tailappend_snapshot_table_partial() {
    let path = format!(
        "/tmp/tailappend_{}.qcow2",
        TailLossType::SnapshotTablePartial.as_str()
    );
    let _ = remove_file(&path);

    inject_tail_loss(&path, TailLossType::SnapshotTablePartial);
    assert!(
        !image_is_clean(&path),
        "image must be corrupt after partial snapshot-table tail loss"
    );

    let (ok, stdout) = run_stratovirt_img_raw(&["tailappend", &path]);
    assert!(ok, "tailappend failed: {stdout}");
    let kept = snapshot_tags(&path);
    assert!(
        stdout.contains(&format!(
            "kept {} of {SNAPSHOT_TABLE_PARTIAL_COUNT}",
            kept.len()
        )),
        "tailappend should report 'kept {} of {}', got: {stdout}",
        kept.len(),
        SNAPSHOT_TABLE_PARTIAL_COUNT
    );
    assert!(image_is_clean(&path), "repaired image must be check-clean");
    assert!(
        kept.len() < SNAPSHOT_TABLE_PARTIAL_COUNT as usize,
        "some snapshots must be lost (kept {} of {SNAPSHOT_TABLE_PARTIAL_COUNT})",
        kept.len()
    );
    assert_eq!(
        kept,
        (0..kept.len() as u32)
            .map(|i| TailLossType::SnapshotTablePartial.snapshot_name(i))
            .collect::<Vec<_>>(),
        "the surviving snapshots must be the prefix of the created list"
    );
    let data = read_guest(&path, 0, 4096);
    assert!(
        data.iter().all(|&b| b == 0xAA),
        "active data must survive the snapshot loss"
    );

    let _ = remove_file(&path);
}

/// tailappend is idempotent: on an already-consistent image it is a no-op
/// success (file size unchanged) and the image stays clean.
#[test]
fn test_tailappend_idempotent() {
    let path = "/tmp/tailappend_idempotent.qcow2";
    let _ = remove_file(&path);

    inject_tail_loss(path, TailLossType::ActiveData);
    run_stratovirt_img(&["tailappend", path]);
    assert!(image_is_clean(path));
    let size_after_repair = std::fs::metadata(path).unwrap().len();

    // Second run on the repaired image: a no-op. Appended zero clusters would
    // be refcount-0 free space, so the file size proves the no-op, not check.
    let (ok, stdout) = run_stratovirt_img_raw(&["tailappend", path]);
    assert!(ok, "second tailappend on repaired image failed: {stdout}");
    assert!(
        stdout.contains("nothing to extend"),
        "second tailappend must not extend the file, got: {stdout}"
    );
    assert_eq!(
        std::fs::metadata(path).unwrap().len(),
        size_after_repair,
        "second tailappend must not change the file size"
    );
    assert!(image_is_clean(path), "image must stay clean");

    // A run on a never-corrupted image is also a no-op.
    let fresh = "/tmp/tailappend_idempotent_fresh.qcow2";
    let _ = remove_file(fresh);
    let (_, stdout) = run_stratovirt_img_raw(&["create", "-f", "qcow2", fresh, IMG_SIZE]);
    assert!(
        image_is_clean(fresh),
        "fresh image should be clean: {stdout}"
    );
    let fresh_size = std::fs::metadata(fresh).unwrap().len();
    let (ok, stdout) = run_stratovirt_img_raw(&["tailappend", fresh]);
    assert!(ok, "tailappend on fresh image failed: {stdout}");
    assert!(
        stdout.contains("nothing to extend"),
        "tailappend on fresh image must not extend the file, got: {stdout}"
    );
    assert_eq!(
        std::fs::metadata(fresh).unwrap().len(),
        fresh_size,
        "tailappend on fresh image must not change the file size"
    );
    assert!(image_is_clean(fresh));

    let _ = remove_file(path);
    let _ = remove_file(fresh);
}

#[test]
fn test_tailappend_refcount_table() {
    tailappend_case(TailLossType::RefcountTable);
}

#[test]
fn test_tailappend_refcount_table_partial() {
    tailappend_case(TailLossType::RefcountTablePartial);
}
