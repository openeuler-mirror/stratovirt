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
use std::mem::size_of;
use std::rc::Rc;
use util::num_ops::round_up;

use super::machine::TestStdMachine;
use super::malloc::GuestAllocator;
use super::virtio::TestVirtQueue;
use super::virtio::VirtioDeviceOps;
use super::virtio_pci_modern::TestVirtioPciDev;
use crate::libdriver::virtio::{
    TestVringDescEntry, VIRTIO_F_BAD_FEATURE, VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use crate::libtest::{test_init, TestState};
use crate::utils::{cleanup_img, create_img, TEST_IMAGE_SIZE};

pub const VIRTIO_BLK_F_BARRIER: u64 = 0;
pub const VIRTIO_BLK_F_SIZE_MAX: u64 = 1;
pub const VIRTIO_BLK_F_SEG_MAX: u64 = 2;
pub const VIRTIO_BLK_F_GEOMETRY: u64 = 4;
pub const VIRTIO_BLK_F_RO: u64 = 5;
pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 6;
pub const VIRTIO_BLK_F_SCSI: u64 = 7;
pub const VIRTIO_BLK_F_FLUSH: u64 = 9;
pub const VIRTIO_BLK_F_TOPOLOGY: u64 = 10;
pub const VIRTIO_BLK_F_CONFIG_WCE: u64 = 11;
pub const VIRTIO_BLK_F_MQ: u64 = 12;
pub const VIRTIO_BLK_F_DISCARD: u64 = 13;
pub const VIRTIO_BLK_F_WRITE_ZEROES: u64 = 14;
pub const VIRTIO_BLK_F_LIFETIME: u64 = 15;
pub const VIRTIO_BLK_F_SECURE_ERASE: u64 = 16;

pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
pub const VIRTIO_BLK_T_GET_ID: u32 = 8;
pub const VIRTIO_BLK_T_DISCARD: u32 = 11;
pub const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;
pub const VIRTIO_BLK_T_ILLGEAL: u32 = 32;
/// Success
pub const VIRTIO_BLK_S_OK: u8 = 0;
/// IO error.
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
/// Unsupport request.
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

pub const TIMEOUT_US: u64 = 15 * 1000 * 1000;
pub const DEFAULT_IO_REQS: u64 = 5;
pub const REQ_ADDR_LEN: u32 = 16;
pub const REQ_DATA_LEN: u32 = 512;
pub const REQ_STATUS_LEN: u32 = 1;
pub const REQ_DATA_OFFSET: u64 = REQ_ADDR_LEN as u64;
pub const REQ_STATUS_OFFSET: u64 = (REQ_ADDR_LEN + REQ_DATA_LEN) as u64;

#[allow(unused)]
pub struct VirtBlkDiscardWriteZeroes {
    sector: u64,
    num_sectors: u32,
    flags: u32,
}

#[allow(unused)]
pub struct TestVirtBlkReq {
    req_type: u32,
    io_priority: u32,
    sector: u64,
    pub data: String,
    status: u8,
}

impl TestVirtBlkReq {
    pub fn new(req_type: u32, io_priority: u32, sector: u64, data_size: usize) -> Self {
        Self {
            req_type,
            io_priority,
            sector,
            data: String::with_capacity(data_size),
            status: 0,
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes_buf = Vec::new();
        bytes_buf.append(&mut self.req_type.to_le_bytes().to_vec());
        bytes_buf.append(&mut self.io_priority.to_le_bytes().to_vec());
        bytes_buf.append(&mut self.sector.to_le_bytes().to_vec());
        bytes_buf
    }
}

pub fn create_blk(
    image_path: Rc<String>,
    device_args: Rc<String>,
    drive_args: Rc<String>,
    other_args: Rc<String>,
) -> (
    Rc<RefCell<TestVirtioPciDev>>,
    Rc<RefCell<TestState>>,
    Rc<RefCell<GuestAllocator>>,
) {
    let pci_slot: u8 = 0x4;
    let pci_fn: u8 = 0x0;
    let mut extra_args: Vec<&str> = Vec::new();

    let mut args: Vec<&str> = "-machine virt".split(' ').collect();
    extra_args.append(&mut args);

    let blk_pci_args = format!(
        "-device {},id=drv0,drive=drive0,bus=pcie.0,addr={}.0{}",
        "virtio-blk-pci", pci_slot, device_args,
    );
    args = blk_pci_args[..].split(' ').collect();
    extra_args.append(&mut args);
    let blk_args = format!(
        "-drive if=none,id=drive0,file={},format=raw{}",
        image_path, drive_args,
    );
    args = blk_args.split(' ').collect();
    extra_args.append(&mut args);

    if !other_args.is_empty() {
        args = other_args.split(' ').collect();
        extra_args.append(&mut args);
    }

    let test_state = Rc::new(RefCell::new(test_init(extra_args)));
    let machine = TestStdMachine::new(test_state.clone());
    let allocator = machine.allocator.clone();

    let virtio_blk = Rc::new(RefCell::new(TestVirtioPciDev::new(machine.pci_bus.clone())));

    virtio_blk.borrow_mut().init(pci_slot, pci_fn);

    (virtio_blk, test_state, allocator)
}

pub fn virtio_blk_request(
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    req: TestVirtBlkReq,
    align: bool,
) -> u64 {
    let status: u8 = 0xFF;
    let data_size = req.data.capacity();

    match req.req_type {
        VIRTIO_BLK_T_IN | VIRTIO_BLK_T_OUT => {
            assert_eq!(data_size % (REQ_DATA_LEN as usize), 0)
        }
        VIRTIO_BLK_T_FLUSH => {}
        VIRTIO_BLK_T_GET_ID => {}
        VIRTIO_BLK_T_DISCARD => {
            assert_eq!(data_size % (REQ_DATA_LEN as usize), 0)
        }
        VIRTIO_BLK_T_WRITE_ZEROES => {
            assert_eq!(data_size % size_of::<VirtBlkDiscardWriteZeroes>(), 0)
        }
        VIRTIO_BLK_T_ILLGEAL => {}
        _ => {
            assert_eq!(data_size, 0)
        }
    }

    let addr = alloc.borrow_mut().alloc(
        (size_of::<TestVirtBlkReq>() + data_size + 512)
            .try_into()
            .unwrap(),
    );

    let data_addr = if align {
        round_up(addr + REQ_ADDR_LEN as u64, 512).unwrap()
    } else {
        addr + REQ_DATA_OFFSET
    };

    let req_bytes = req.as_bytes();
    test_state.borrow().memwrite(addr, req_bytes.as_slice());
    let mut data_bytes = req.data.as_bytes().to_vec();
    data_bytes.resize(data_size, 0);
    test_state
        .borrow()
        .memwrite(data_addr, data_bytes.as_slice());
    test_state
        .borrow()
        .memwrite(data_addr + data_size as u64, &status.to_le_bytes());

    addr
}

pub fn add_blk_request(
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vq: Rc<RefCell<TestVirtQueue>>,
    req_type: u32,
    sector: u64,
    align: bool,
) -> (u32, u64) {
    let mut read = true;
    // [req_type, io_priority, sector, data_size]
    let mut blk_req = TestVirtBlkReq::new(req_type, 1, sector, REQ_DATA_LEN as usize);
    if req_type == VIRTIO_BLK_T_OUT {
        blk_req.data.push_str("TEST");
        read = false;
    }
    // Get addr and write to Stratovirt.
    let req_addr = virtio_blk_request(test_state.clone(), alloc.clone(), blk_req, align);
    // Desc elem: [addr, len, flags, next].

    let data_addr = if align {
        round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap()
    } else {
        req_addr + REQ_DATA_OFFSET
    };

    let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(3);
    data_entries.push(TestVringDescEntry {
        data: req_addr,
        len: REQ_ADDR_LEN,
        write: false,
    });
    data_entries.push(TestVringDescEntry {
        data: data_addr,
        len: REQ_DATA_LEN,
        write: read,
    });
    data_entries.push(TestVringDescEntry {
        data: data_addr + REQ_DATA_LEN as u64,
        len: REQ_STATUS_LEN,
        write: true,
    });

    let free_head = vq
        .borrow_mut()
        .add_chained(test_state.clone(), data_entries);

    (free_head, req_addr)
}

/// Write DEFAULT_IO_REQS requests to disk.
pub fn virtio_blk_write(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    virtqueue: Rc<RefCell<TestVirtQueue>>,
    sector: u64,
    align: bool,
) {
    let mut free_head = 0_u32;
    let mut req_addr = 0_u64;
    for i in sector..sector + DEFAULT_IO_REQS {
        (free_head, req_addr) = add_blk_request(
            test_state.clone(),
            alloc.clone(),
            virtqueue.clone(),
            VIRTIO_BLK_T_OUT,
            i,
            align,
        );
    }

    blk.borrow()
        .kick_virtqueue(test_state.clone(), virtqueue.clone());
    blk.borrow().poll_used_elem(
        test_state.clone(),
        virtqueue.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );

    let status_addr = if align {
        round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64
    } else {
        req_addr + REQ_STATUS_OFFSET
    };

    let status = test_state.borrow().readb(status_addr);
    assert_eq!(status, VIRTIO_BLK_S_OK);
}

/// Read 512 byte from disk.
pub fn virtio_blk_read(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    virtqueue: Rc<RefCell<TestVirtQueue>>,
    sector: u64,
    align: bool,
) {
    let (free_head, req_addr) = add_blk_request(
        test_state.clone(),
        alloc.clone(),
        virtqueue.clone(),
        VIRTIO_BLK_T_IN,
        sector,
        align,
    );

    blk.borrow()
        .kick_virtqueue(test_state.clone(), virtqueue.clone());
    blk.borrow().poll_used_elem(
        test_state.clone(),
        virtqueue.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );

    let data_addr = if align {
        round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap()
    } else {
        req_addr + REQ_ADDR_LEN as u64
    };

    let status_addr = if align {
        round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64
    } else {
        req_addr + REQ_STATUS_OFFSET
    };

    let status = test_state.borrow().readb(status_addr);
    assert_eq!(status, VIRTIO_BLK_S_OK);

    assert_eq!(
        String::from_utf8(test_state.borrow().memread(data_addr, 4)).unwrap(),
        "TEST"
    );
}

pub fn virtio_blk_defalut_feature(blk: Rc<RefCell<TestVirtioPciDev>>) -> u64 {
    let mut features = blk.borrow().get_device_features();
    features &= !(VIRTIO_F_BAD_FEATURE
        | 1 << VIRTIO_RING_F_INDIRECT_DESC
        | 1 << VIRTIO_RING_F_EVENT_IDX
        | 1 << VIRTIO_BLK_F_SCSI);

    features
}

pub fn set_up() -> (
    Rc<RefCell<TestVirtioPciDev>>,
    Rc<RefCell<TestState>>,
    Rc<RefCell<GuestAllocator>>,
    Rc<String>,
) {
    let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 0));
    let device_args = Rc::new(String::from(""));
    let drive_args = Rc::new(String::from(",direct=false"));
    let other_args = Rc::new(String::from(""));
    let (blk, test_state, alloc) =
        create_blk(image_path.clone(), device_args, drive_args, other_args);

    (blk, test_state, alloc, image_path)
}

pub fn tear_down(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vqs: Vec<Rc<RefCell<TestVirtQueue>>>,
    image_path: Rc<String>,
) {
    blk.borrow_mut().destroy_device(alloc.clone(), vqs);
    test_state.borrow_mut().stop();
    if !image_path.is_empty() {
        cleanup_img(image_path.to_string());
    }
}
