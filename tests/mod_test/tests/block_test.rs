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
use std::os::linux::fs::MetadataExt;
use std::rc::Rc;
use std::time::{Duration, Instant};
use std::{thread, time};

use mod_test::libdriver::malloc::GuestAllocator;
use mod_test::libdriver::qcow2::CLUSTER_SIZE;
use mod_test::libdriver::qcow2::{check_snapshot, create_snapshot, delete_snapshot};
use mod_test::libdriver::virtio::TestVringDescEntry;
use mod_test::libdriver::virtio::{TestVirtQueue, VirtioDeviceOps};
use mod_test::libdriver::virtio_block::{
    add_blk_request, create_blk, set_up, tear_down, virtio_blk_default_feature, virtio_blk_read,
    virtio_blk_read_write_zeroes, virtio_blk_request, virtio_blk_write, TestVirtBlkReq,
    VirtBlkDiscardWriteZeroes, DEFAULT_IO_REQS, MAX_REQUEST_SECTORS, REQ_ADDR_LEN, REQ_DATA_LEN,
    REQ_DATA_OFFSET, REQ_STATUS_LEN, TIMEOUT_US, VIRTIO_BLK_F_BARRIER, VIRTIO_BLK_F_BLK_SIZE,
    VIRTIO_BLK_F_CONFIG_WCE, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_GEOMETRY,
    VIRTIO_BLK_F_LIFETIME, VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_RO, VIRTIO_BLK_F_SECURE_ERASE,
    VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_WRITE_ZEROES,
    VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP, VIRTIO_BLK_T_DISCARD,
    VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_GET_ID, VIRTIO_BLK_T_ILLGEAL, VIRTIO_BLK_T_IN,
    VIRTIO_BLK_T_OUT, VIRTIO_BLK_T_WRITE_ZEROES,
};
use mod_test::libdriver::virtio_pci_modern::TestVirtioPciDev;
use mod_test::libtest::TestState;
use mod_test::utils::{create_img, ImageType, TEST_IMAGE_SIZE};
use util::aio::{aio_probe, AioEngine};
use util::byte_code::ByteCode;
use util::num_ops::round_up;
use util::offset_of;
use virtio::device::block::VirtioBlkConfig;

const TEST_IMAGE_SIZE_1M: u64 = 1024 * 1024;
const DEFAULT_SECTOR_SIZE: u64 = 512;

fn virtio_blk_discard_and_write_zeroes(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    virtqueue: Rc<RefCell<TestVirtQueue>>,
    req_data: &[u8],
    status: u8,
    need_poll_elem: bool,
    discard: bool,
) {
    let req_len = req_data.len();
    let mut blk_req = if discard {
        TestVirtBlkReq::new(VIRTIO_BLK_T_DISCARD, 1, 0, req_len)
    } else {
        TestVirtBlkReq::new(VIRTIO_BLK_T_WRITE_ZEROES, 1, 0, req_len)
    };
    blk_req.data = unsafe { String::from_utf8_unchecked(req_data.to_vec()) };
    let req_addr = virtio_blk_request(test_state.clone(), alloc.clone(), blk_req, false);

    let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(3);
    data_entries.push(TestVringDescEntry {
        data: req_addr,
        len: REQ_ADDR_LEN,
        write: false,
    });
    data_entries.push(TestVringDescEntry {
        data: req_addr + REQ_DATA_OFFSET,
        len: req_len as u32,
        write: false,
    });
    data_entries.push(TestVringDescEntry {
        data: req_addr + REQ_DATA_OFFSET + req_len as u64,
        len: REQ_STATUS_LEN,
        write: true,
    });
    let free_head = virtqueue
        .borrow_mut()
        .add_chained(test_state.clone(), data_entries);
    blk.borrow()
        .kick_virtqueue(test_state.clone(), virtqueue.clone());
    if need_poll_elem {
        blk.borrow().poll_used_elem(
            test_state.clone(),
            virtqueue.clone(),
            free_head,
            TIMEOUT_US,
            &mut None,
            true,
        );
    }
    let status_addr = req_addr + REQ_DATA_OFFSET + req_len as u64;
    let read_status = test_state.borrow().readb(status_addr);
    assert_eq!(read_status, status);
}

fn get_disk_size(img_path: Rc<String>) -> u64 {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(img_path.as_ref())
        .unwrap();
    let meta_data = file.metadata().unwrap();
    let blk_size = meta_data.st_blocks() * DEFAULT_SECTOR_SIZE;
    blk_size >> 10
}

fn virtio_blk_check_discard_config(blk: Rc<RefCell<TestVirtioPciDev>>) {
    // (offset, expected_value).
    let reqs = [
        (
            offset_of!(VirtioBlkConfig, max_discard_sectors),
            MAX_REQUEST_SECTORS,
        ),
        (offset_of!(VirtioBlkConfig, max_discard_seg), 1),
        (offset_of!(VirtioBlkConfig, discard_sector_alignment), 1),
    ];
    for (offset, expected_value) in reqs {
        assert_eq!(blk.borrow().config_readl(offset as u64), expected_value);
    }
}

fn virtio_blk_check_write_zeroes_config(blk: Rc<RefCell<TestVirtioPciDev>>) {
    // (offset, expected_value).
    let reqs = [
        (
            offset_of!(VirtioBlkConfig, max_write_zeroes_sectors),
            MAX_REQUEST_SECTORS,
        ),
        (offset_of!(VirtioBlkConfig, max_write_zeroes_seg), 1),
    ];
    for (offset, expected_value) in reqs {
        assert_eq!(blk.borrow().config_readl(offset as u64), expected_value);
    }
    let offset = offset_of!(VirtioBlkConfig, write_zeroes_may_unmap);
    assert_eq!(blk.borrow().config_readb(offset as u64), 1);
}

fn virtio_blk_get_id(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    virtqueue: Rc<RefCell<TestVirtQueue>>,
    serial_num: String,
) {
    let (free_head, req_addr) = add_blk_request(
        test_state.clone(),
        alloc.clone(),
        virtqueue.clone(),
        VIRTIO_BLK_T_GET_ID,
        0,
        true,
    );
    blk.borrow().virtqueue_notify(virtqueue.clone());
    blk.borrow().poll_used_elem(
        test_state.clone(),
        virtqueue.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );

    let status_addr = round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
    let status = test_state.borrow().readb(status_addr);
    assert_eq!(status, VIRTIO_BLK_S_OK);

    let data_addr = round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap();
    assert_eq!(
        String::from_utf8(
            test_state
                .borrow()
                .memread(data_addr, serial_num.len() as u64)
        )
        .unwrap(),
        serial_num
    );
}

fn virtio_blk_flush(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    virtqueue: Rc<RefCell<TestVirtQueue>>,
    sector: u64,
) {
    let (free_head, req_addr) = add_blk_request(
        test_state.clone(),
        alloc.clone(),
        virtqueue.clone(),
        VIRTIO_BLK_T_FLUSH,
        sector,
        true,
    );
    blk.borrow().virtqueue_notify(virtqueue.clone());
    blk.borrow().poll_used_elem(
        test_state.clone(),
        virtqueue.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );

    let status_addr = round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
    let status = test_state.borrow().readb(status_addr);
    assert_eq!(status, VIRTIO_BLK_S_OK);
}

fn virtio_blk_illegal_req(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    virtqueue: Rc<RefCell<TestVirtQueue>>,
    req_type: u32,
) {
    let (free_head, req_addr) = add_blk_request(
        test_state.clone(),
        alloc.clone(),
        virtqueue.clone(),
        req_type,
        0,
        true,
    );
    blk.borrow().virtqueue_notify(virtqueue.clone());
    blk.borrow().poll_used_elem(
        test_state.clone(),
        virtqueue.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );

    let status_addr = round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
    let status = test_state.borrow().readb(status_addr);
    assert_eq!(status, VIRTIO_BLK_S_UNSUPP);
}

/// Block device sends I/O request.
/// TestStep:
///   1. Init block device.
///   2. Do the I/O request.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_basic() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let (blk, test_state, alloc, image_path) = set_up(&image_type);

        let features = virtio_blk_default_feature(blk.clone());

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        let capacity = blk.borrow().config_readq(0);
        assert_eq!(capacity, TEST_IMAGE_SIZE / REQ_DATA_LEN as u64);

        virtio_blk_write(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            true,
        );

        virtio_blk_read(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            true,
        );

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device negotiate different features.
/// TestStep:
///   1. Init block device.
///   2. Negotiate supported features.
///   3. Negotiate unsupported features.
///   4. Destroy device.
/// Expect:
///   1/2/4: success, 3: failed.
#[test]
fn blk_features_negotiate() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 0, &image_type));
        let device_args = Rc::new(String::from(",num-queues=4"));
        let drive_args = Rc::new(String::from(",direct=false,readonly=on"));
        let other_args = Rc::new(String::from(""));
        let (blk, test_state, alloc) = create_blk(
            &image_type,
            image_path.clone(),
            device_args,
            drive_args,
            other_args,
        );

        blk.borrow_mut().pci_dev.enable_msix(None);
        blk.borrow_mut()
            .setup_msix_configuration_vector(alloc.clone(), 0);

        let mut features = blk.borrow().get_device_features();
        features |= 1 << VIRTIO_BLK_F_SEG_MAX
            | 1 << VIRTIO_BLK_F_RO
            | 1 << VIRTIO_BLK_F_FLUSH
            | 1 << VIRTIO_BLK_F_MQ;
        blk.borrow_mut().negotiate_features(features);
        blk.borrow_mut().set_features_ok();
        assert_eq!(features, blk.borrow_mut().get_guest_features());

        let unsupported_features = 1 << VIRTIO_BLK_F_BARRIER
            | 1 << VIRTIO_BLK_F_SIZE_MAX
            | 1 << VIRTIO_BLK_F_GEOMETRY
            | 1 << VIRTIO_BLK_F_BLK_SIZE
            | 1 << VIRTIO_BLK_F_TOPOLOGY
            | 1 << VIRTIO_BLK_F_CONFIG_WCE
            | 1 << VIRTIO_BLK_F_DISCARD
            | 1 << VIRTIO_BLK_F_WRITE_ZEROES
            | 1 << VIRTIO_BLK_F_LIFETIME
            | 1 << VIRTIO_BLK_F_SECURE_ERASE;
        features |= unsupported_features;
        blk.borrow_mut().negotiate_features(features);
        blk.borrow_mut().set_features_ok();
        assert_ne!(features, blk.borrow_mut().get_guest_features());
        assert_eq!(
            unsupported_features & blk.borrow_mut().get_guest_features(),
            0
        );

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            Vec::new(),
            image_path.clone(),
        );
    }
}

/// Block device sends I/O request with feature 'VIRTIO_BLK_F_SEG_MAX'.
/// TestStep:
///   1. Init block device with feature 'VIRTIO_BLK_F_SEG_MAX'.
///   2. Do the I/O request, check seg_max.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_feature_seg_max() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let (blk, test_state, alloc, image_path) = set_up(&image_type);

        let mut features = virtio_blk_default_feature(blk.clone());
        features |= 1 << VIRTIO_BLK_F_SEG_MAX;

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        let seg_max = blk
            .borrow()
            .config_readl(offset_of!(VirtioBlkConfig, seg_max) as u64);
        let queue_size = virtqueues[0].borrow_mut().size;
        assert_eq!(seg_max, (queue_size - 2));

        virtio_blk_write(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            true,
        );

        virtio_blk_read(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            true,
        );

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device sends I/O request with feature 'VIRTIO_BLK_F_RO'.
/// TestStep:
///   1. Init block device with feature 'VIRTIO_BLK_F_RO'.
///   2. Do the 'read' I/O request.
///   3. Do the 'write' I/O request.
///   4. Destroy device.
/// Expect:
///   1/2/4: success, failed: 3.
#[test]
fn blk_feature_ro() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let (blk, test_state, alloc, image_path) = set_up(&image_type);

        let mut features = virtio_blk_default_feature(blk.clone());

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        let capacity = blk.borrow().config_readq(0);
        assert_eq!(capacity, TEST_IMAGE_SIZE / REQ_DATA_LEN as u64);

        virtio_blk_write(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            true,
        );

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            Rc::new("".to_string()),
        );

        let device_args = Rc::new(String::from(""));
        let drive_args = Rc::new(String::from(",direct=false,readonly=on"));
        let other_args = Rc::new(String::from(""));
        let (blk, test_state, alloc) = create_blk(
            &image_type,
            image_path.clone(),
            device_args,
            drive_args,
            other_args,
        );

        features |= 1 << VIRTIO_BLK_F_RO;

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        let capacity = blk.borrow().config_readq(0);
        assert_eq!(capacity, TEST_IMAGE_SIZE / REQ_DATA_LEN as u64);

        virtio_blk_read(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            true,
        );

        let (free_head, req_addr) = add_blk_request(
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            VIRTIO_BLK_T_OUT,
            0,
            true,
        );
        blk.borrow().virtqueue_notify(virtqueues[0].clone());
        blk.borrow().poll_used_elem(
            test_state.clone(),
            virtqueues[0].clone(),
            free_head,
            TIMEOUT_US,
            &mut None,
            true,
        );

        let status_addr =
            round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
        let status = test_state.borrow().readb(status_addr);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device sends I/O request with feature 'VIRTIO_BLK_F_FLUSH'.
/// TestStep:
///   1. Init block device with feature 'VIRTIO_BLK_F_FLUSH'.
///   2. Do the I/O request.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_feature_flush() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let (blk, test_state, alloc, image_path) = set_up(&image_type);

        let mut features = virtio_blk_default_feature(blk.clone());
        features |= 1 << VIRTIO_BLK_F_FLUSH;

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        virtio_blk_flush(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            10,
        );

        virtio_blk_write(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            true,
        );

        virtio_blk_read(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            true,
        );

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device sends I/O request with feature 'VIRTIO_BLK_F_MQ'.
/// TestStep:
///   1. Init block device with feature 'VIRTIO_BLK_F_MQ'.
///   2. Do the I/O multiple queue requests.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_feature_mq() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 0, &image_type));
        let device_args = Rc::new(String::from(",num-queues=4"));
        let drive_args = Rc::new(String::from(",direct=false"));
        let other_args = Rc::new(String::from(""));
        let (blk, test_state, alloc) = create_blk(
            &image_type,
            image_path.clone(),
            device_args,
            drive_args,
            other_args,
        );

        let mut features = virtio_blk_default_feature(blk.clone());
        features |= 1 << VIRTIO_BLK_F_MQ;

        let num_queues = 4;
        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, num_queues);

        let cfg_num_queues = blk
            .borrow()
            .config_readw(offset_of!(VirtioBlkConfig, num_queues) as u64);
        assert_eq!(num_queues as u16, cfg_num_queues);

        let mut free_head: Vec<u32> = Vec::with_capacity(num_queues);
        let mut req_addr: Vec<u64> = Vec::with_capacity(num_queues);
        for i in 0..num_queues {
            let mut blk_req =
                TestVirtBlkReq::new(VIRTIO_BLK_T_OUT, 1, i as u64, REQ_DATA_LEN as usize);
            blk_req.data.push_str("TEST");

            req_addr.push(virtio_blk_request(
                test_state.clone(),
                alloc.clone(),
                blk_req,
                true,
            ));

            let data_addr = round_up(req_addr[i] + REQ_ADDR_LEN as u64, 512).unwrap();

            let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(3);
            data_entries.push(TestVringDescEntry {
                data: req_addr[i],
                len: REQ_ADDR_LEN,
                write: false,
            });
            data_entries.push(TestVringDescEntry {
                data: data_addr,
                len: REQ_DATA_LEN,
                write: false,
            });
            data_entries.push(TestVringDescEntry {
                data: data_addr + REQ_DATA_LEN as u64,
                len: REQ_STATUS_LEN,
                write: true,
            });

            free_head.push(
                virtqueues[i]
                    .borrow_mut()
                    .add_chained(test_state.clone(), data_entries),
            );
        }

        for i in 0..num_queues {
            blk.borrow()
                .kick_virtqueue(test_state.clone(), virtqueues[i].clone());
        }

        for i in 0..num_queues {
            blk.borrow().poll_used_elem(
                test_state.clone(),
                virtqueues[i].clone(),
                free_head[i],
                TIMEOUT_US,
                &mut None,
                true,
            );
        }

        for i in 0..num_queues {
            let status_addr =
                round_up(req_addr[i] + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
            let status = test_state.borrow().readb(status_addr);
            assert_eq!(status, VIRTIO_BLK_S_OK);
        }

        for i in 0..num_queues {
            virtio_blk_read(
                blk.clone(),
                test_state.clone(),
                alloc.clone(),
                virtqueues[i].clone(),
                i as u64,
                true,
            );
        }

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device sends I/O request, configure all parameters.
/// TestStep:
///   1. Init block device, configure all parameters.
///   2. Do the I/O request.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_all_features() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let image_path = Rc::new(create_img(TEST_IMAGE_SIZE_1M, 1, &image_type));
        let device_args = Rc::new(String::from(
            ",multifunction=on,serial=111111,num-queues=4,bootindex=1,iothread=iothread1",
        ));
        let drive_args = if aio_probe(AioEngine::IoUring).is_ok() {
            Rc::new(String::from(
                ",direct=on,aio=io_uring,readonly=off,throttling.iops-total=1024",
            ))
        } else {
            Rc::new(String::from(
                ",direct=false,readonly=off,throttling.iops-total=1024",
            ))
        };
        let other_args = Rc::new(String::from("-object iothread,id=iothread1"));
        let (blk, test_state, alloc) = create_blk(
            &image_type,
            image_path.clone(),
            device_args,
            drive_args,
            other_args,
        );

        let mut features = virtio_blk_default_feature(blk.clone());
        features |= 1 << VIRTIO_BLK_F_SEG_MAX | 1 << VIRTIO_BLK_F_FLUSH | 1 << VIRTIO_BLK_F_MQ;

        let num_queues = 4;
        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, num_queues);

        virtio_blk_write(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            true,
        );

        virtio_blk_read(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            true,
        );

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device sends I/O request to a file with a size of 511b.
/// TestStep:
///   1. Init block device with a 511b file.
///   2. Do the I/O request.
///   3. Destroy device.
/// Expect:
///   1/3: success, 2: failed.
#[test]
fn blk_small_file_511b() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let size = 511;
        let image_path = Rc::new(create_img(size, 1, &image_type));
        let device_args = Rc::new(String::from(""));
        let drive_args = Rc::new(String::from(",direct=false"));
        let other_args = Rc::new(String::from(""));
        let (blk, test_state, alloc) = create_blk(
            &image_type,
            image_path.clone(),
            device_args,
            drive_args,
            other_args,
        );

        let features = virtio_blk_default_feature(blk.clone());

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        let capacity = blk.borrow().config_readq(0);
        assert_eq!(capacity, size / REQ_DATA_LEN as u64);

        let mut blk_req = TestVirtBlkReq::new(VIRTIO_BLK_T_OUT, 1, 0, REQ_DATA_LEN as usize);
        blk_req.data.push_str("TEST");

        let req_addr = virtio_blk_request(test_state.clone(), alloc.clone(), blk_req, true);
        let data_addr = round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap();

        let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(3);
        data_entries.push(TestVringDescEntry {
            data: req_addr,
            len: REQ_ADDR_LEN,
            write: false,
        });
        data_entries.push(TestVringDescEntry {
            data: data_addr,
            len: REQ_DATA_LEN,
            write: false,
        });
        data_entries.push(TestVringDescEntry {
            data: data_addr + REQ_DATA_LEN as u64,
            len: REQ_STATUS_LEN,
            write: true,
        });
        let free_head = virtqueues[0]
            .borrow_mut()
            .add_chained(test_state.clone(), data_entries);

        blk.borrow()
            .kick_virtqueue(test_state.clone(), virtqueues[0].clone());
        blk.borrow().poll_used_elem(
            test_state.clone(),
            virtqueues[0].clone(),
            free_head,
            TIMEOUT_US,
            &mut None,
            true,
        );

        let status_addr =
            round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
        let status = test_state.borrow().readb(status_addr);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);

        let (free_head, req_addr) = add_blk_request(
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            VIRTIO_BLK_T_IN,
            0,
            true,
        );

        blk.borrow()
            .kick_virtqueue(test_state.clone(), virtqueues[0].clone());
        blk.borrow().poll_used_elem(
            test_state.clone(),
            virtqueues[0].clone(),
            free_head,
            TIMEOUT_US,
            &mut None,
            true,
        );

        let status_addr =
            round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
        let status = test_state.borrow().readb(status_addr);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device sends I/O request, configured as 'serial=11111111111111111111'.
/// TestStep:
///   1. Init block device, configured as 'serial=11111111111111111111'.
///   2. Do the I/O request, check serial number.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_serial() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let serial_num = String::from("11111111111111111111");
        let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 0, &image_type));
        let device_args = Rc::new(format!(",serial={}", serial_num));
        let drive_args = Rc::new(String::from(",direct=false"));
        let other_args = Rc::new(String::from(""));
        let (blk, test_state, alloc) = create_blk(
            &image_type,
            image_path.clone(),
            device_args,
            drive_args,
            other_args,
        );

        let features = virtio_blk_default_feature(blk.clone());

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        virtio_blk_write(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            true,
        );

        virtio_blk_read(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            true,
        );

        virtio_blk_get_id(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            serial_num,
        );

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device sends I/O request, configured as 'throttling.iops-total=1'.
/// TestStep:
///   1. Init block device, configured as 'throttling.iops-total=1'.
///   2. Do the I/O request, check iops.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_iops() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 0, &image_type));
        let device_args = Rc::new(String::from(""));
        let drive_args = Rc::new(String::from(",direct=false,throttling.iops-total=1"));
        let other_args = Rc::new(String::from(""));
        let (blk, test_state, alloc) = create_blk(
            &image_type,
            image_path.clone(),
            device_args,
            drive_args,
            other_args,
        );

        let features = virtio_blk_default_feature(blk.clone());

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        let mut free_head = 0_u32;
        let mut req_addr = 0_u64;

        for i in 0..DEFAULT_IO_REQS {
            (free_head, req_addr) = add_blk_request(
                test_state.clone(),
                alloc.clone(),
                virtqueues[0].clone(),
                VIRTIO_BLK_T_OUT,
                i,
                true,
            );
        }

        blk.borrow()
            .kick_virtqueue(test_state.clone(), virtqueues[0].clone());

        loop {
            test_state.borrow().clock_step_ns(100);

            if blk.borrow().queue_was_notified(virtqueues[0].clone())
                && virtqueues[0].borrow_mut().get_buf(test_state.clone())
            {
                assert!(!virtqueues[0].borrow().desc_len.contains_key(&free_head));
                break;
            }
        }

        let status_addr =
            round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
        let status = test_state.borrow().readb(status_addr);
        assert_ne!(status, VIRTIO_BLK_S_OK);

        let time_out = Instant::now() + Duration::from_micros(TIMEOUT_US);
        loop {
            test_state.borrow().clock_step();

            if blk.borrow().queue_was_notified(virtqueues[0].clone())
                && virtqueues[0].borrow_mut().get_buf(test_state.clone())
            {
                if virtqueues[0].borrow().desc_len.contains_key(&free_head) {
                    break;
                }
            }
            assert!(Instant::now() <= time_out);
        }

        let status_addr =
            round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
        let status = test_state.borrow().readb(status_addr);
        assert_eq!(status, VIRTIO_BLK_S_OK);

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device sends I/O request, configured as 'aio=[off|threads|io_uring|native]'.
/// TestStep:
///   1. Init block device, configured with different aio type.
///   2. Do the I/O request.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_with_different_aio() {
    const BLOCK_DRIVER_CFG: [(ImageType, &str, AioEngine); 6] = [
        (ImageType::Raw, "off", AioEngine::Off),
        (ImageType::Qcow2, "off", AioEngine::Off),
        (ImageType::Raw, "off", AioEngine::Threads),
        (ImageType::Qcow2, "off", AioEngine::Threads),
        (ImageType::Raw, "on", AioEngine::Native),
        (ImageType::Raw, "on", AioEngine::IoUring),
    ];

    for (image_type, direct, aio_engine) in BLOCK_DRIVER_CFG {
        println!("Image type: {:?}", image_type);
        let image_path = Rc::new(create_img(TEST_IMAGE_SIZE_1M, 1, &image_type));
        let device_args = Rc::new(String::from(""));
        let drive_args = if aio_probe(aio_engine).is_ok() {
            Rc::new(format!(",direct={},aio={}", direct, aio_engine.to_string()))
        } else {
            continue;
        };
        let other_args = Rc::new(String::from(""));
        let (blk, test_state, alloc) = create_blk(
            &image_type,
            image_path.clone(),
            device_args,
            drive_args,
            other_args,
        );

        let features = virtio_blk_default_feature(blk.clone());

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        virtio_blk_write(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            true,
        );

        virtio_blk_read(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            true,
        );

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device sends I/O request, configured as 'aio=io_uring'.
/// TestStep:
///   1. Init block device, configured as 'aio=io_uring'.
///   2. Do the I/O request.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_aio_io_uring() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let image_path = Rc::new(create_img(TEST_IMAGE_SIZE_1M, 1, &image_type));
        let device_args = Rc::new(String::from(""));
        let drive_args = if aio_probe(AioEngine::IoUring).is_ok() {
            Rc::new(String::from(",direct=on,aio=io_uring"))
        } else {
            Rc::new(String::from(",direct=false"))
        };
        let other_args = Rc::new(String::from(""));
        let (blk, test_state, alloc) = create_blk(
            &image_type,
            image_path.clone(),
            device_args,
            drive_args,
            other_args,
        );

        let features = virtio_blk_default_feature(blk.clone());

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        virtio_blk_write(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            false,
        );

        virtio_blk_read(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            0,
            false,
        );

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device sends an illegal type of I/O request.
/// TestStep:
///   1. Init block device.
///   2. Do the I/O request of illegal type.
///   3. Destroy device.
/// Expect:
///   1/3: success, 2: failed.
#[test]
fn blk_illegal_req_type() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let (blk, test_state, alloc, image_path) = set_up(&image_type);

        let features = virtio_blk_default_feature(blk.clone());

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        virtio_blk_illegal_req(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            VIRTIO_BLK_T_ILLGEAL,
        );

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device configuration space read and write.
/// TestStep:
///   1. Init block device.
///   2. Read block device configuration space.
///   3. Write block device configuration space.
///   4. Destroy device.
/// Expect:
///   1/2/4: success, 3: failed.
#[test]
fn blk_rw_config() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let (blk, test_state, alloc, image_path) = set_up(&image_type);

        let features = virtio_blk_default_feature(blk.clone());

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        let capacity = blk.borrow().config_readq(0);
        assert_eq!(capacity, TEST_IMAGE_SIZE / REQ_DATA_LEN as u64);

        blk.borrow().config_writeq(0, 1024);
        let capacity = blk.borrow().config_readq(0);
        assert_ne!(capacity, 1024);

        let discard_sector_alignment = blk.borrow().config_readl(40);
        blk.borrow().config_writel(40, 1024);
        assert_eq!(blk.borrow().config_readl(40), discard_sector_alignment);
        assert_ne!(blk.borrow().config_readl(40), 1024);

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device send I/O requests in an abnormal format.
/// TestStep:
///   1. Init block device.
///   2. Do the I/O requests in an abnormal format.
///   3. Destroy device.
/// Expect:
///   1/3: success, 2: failed.
#[test]
fn blk_abnormal_req() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let (blk, test_state, alloc, image_path) = set_up(&image_type);

        let features = virtio_blk_default_feature(blk.clone());

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        let mut blk_req = TestVirtBlkReq::new(VIRTIO_BLK_T_OUT, 1, 0, REQ_DATA_LEN as usize);
        blk_req.data.push_str("TEST");

        let req_addr = virtio_blk_request(test_state.clone(), alloc.clone(), blk_req, false);

        // Desc: req_hdr length 8, data length 256.
        let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(3);
        data_entries.push(TestVringDescEntry {
            data: req_addr,
            len: 8,
            write: false,
        });
        data_entries.push(TestVringDescEntry {
            data: req_addr + 8,
            len: 256,
            write: false,
        });
        data_entries.push(TestVringDescEntry {
            data: req_addr + 264,
            len: 1,
            write: true,
        });
        let free_head = virtqueues[0]
            .borrow_mut()
            .add_chained(test_state.clone(), data_entries);

        blk.borrow()
            .kick_virtqueue(test_state.clone(), virtqueues[0].clone());
        blk.borrow().poll_used_elem(
            test_state.clone(),
            virtqueues[0].clone(),
            free_head,
            TIMEOUT_US,
            &mut None,
            true,
        );

        let status = test_state.borrow().readb(req_addr + 264);
        assert_ne!(status, VIRTIO_BLK_S_OK);

        // Desc: req_hdr length 32.
        let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(3);
        data_entries.push(TestVringDescEntry {
            data: req_addr,
            len: 32,
            write: false,
        });
        data_entries.push(TestVringDescEntry {
            data: req_addr + 32,
            len: 512,
            write: false,
        });
        data_entries.push(TestVringDescEntry {
            data: req_addr + 544,
            len: 1,
            write: true,
        });
        let free_head = virtqueues[0]
            .borrow_mut()
            .add_chained(test_state.clone(), data_entries);

        blk.borrow()
            .kick_virtqueue(test_state.clone(), virtqueues[0].clone());
        blk.borrow().poll_used_elem(
            test_state.clone(),
            virtqueues[0].clone(),
            free_head,
            TIMEOUT_US,
            &mut None,
            true,
        );

        let status = test_state.borrow().readb(req_addr + 544);
        assert_ne!(status, VIRTIO_BLK_S_OK);

        // Desc: data length 256.
        let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(3);
        data_entries.push(TestVringDescEntry {
            data: req_addr,
            len: 16,
            write: false,
        });
        data_entries.push(TestVringDescEntry {
            data: req_addr + 16,
            len: 256,
            write: false,
        });
        data_entries.push(TestVringDescEntry {
            data: req_addr + 272,
            len: 1,
            write: true,
        });
        let free_head = virtqueues[0]
            .borrow_mut()
            .add_chained(test_state.clone(), data_entries);

        blk.borrow()
            .kick_virtqueue(test_state.clone(), virtqueues[0].clone());
        blk.borrow().poll_used_elem(
            test_state.clone(),
            virtqueues[0].clone(),
            free_head,
            TIMEOUT_US,
            &mut None,
            true,
        );

        let status = test_state.borrow().readb(req_addr + 272);
        assert_ne!(status, VIRTIO_BLK_S_OK);

        // Desc: data length 4, small size desc.
        let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(3);
        data_entries.push(TestVringDescEntry {
            data: req_addr,
            len: 16,
            write: false,
        });
        data_entries.push(TestVringDescEntry {
            data: req_addr + 16,
            len: 4,
            write: false,
        });
        data_entries.push(TestVringDescEntry {
            data: req_addr + 20,
            len: 1,
            write: true,
        });
        let free_head = virtqueues[0]
            .borrow_mut()
            .add_chained(test_state.clone(), data_entries);

        blk.borrow()
            .kick_virtqueue(test_state.clone(), virtqueues[0].clone());
        blk.borrow().poll_used_elem(
            test_state.clone(),
            virtqueues[0].clone(),
            free_head,
            TIMEOUT_US,
            &mut None,
            true,
        );

        let status = test_state.borrow().readb(req_addr + 20);
        assert_ne!(status, VIRTIO_BLK_S_OK);

        // Desc: miss data.
        let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(3);
        data_entries.push(TestVringDescEntry {
            data: req_addr,
            len: 16,
            write: false,
        });
        data_entries.push(TestVringDescEntry {
            data: req_addr + 16,
            len: 1,
            write: true,
        });
        let _free_head = virtqueues[0]
            .borrow_mut()
            .add_chained(test_state.clone(), data_entries);

        blk.borrow()
            .kick_virtqueue(test_state.clone(), virtqueues[0].clone());
        thread::sleep(time::Duration::from_secs(1));

        let status = test_state.borrow().readb(req_addr + 16);
        assert_ne!(status, VIRTIO_BLK_S_OK);

        // Desc: all 'out' desc.
        let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(3);
        data_entries.push(TestVringDescEntry {
            data: req_addr,
            len: 16,
            write: true,
        });
        data_entries.push(TestVringDescEntry {
            data: req_addr + 16,
            len: 512,
            write: true,
        });
        data_entries.push(TestVringDescEntry {
            data: req_addr + 528,
            len: 1,
            write: true,
        });
        let _free_head = virtqueues[0]
            .borrow_mut()
            .add_chained(test_state.clone(), data_entries);

        blk.borrow()
            .kick_virtqueue(test_state.clone(), virtqueues[0].clone());
        thread::sleep(time::Duration::from_secs(1));

        let status = test_state.borrow().readb(req_addr + 528);
        assert_ne!(status, VIRTIO_BLK_S_OK);

        // Desc: data length 0.
        let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(3);
        data_entries.push(TestVringDescEntry {
            data: req_addr,
            len: 16,
            write: false,
        });
        data_entries.push(TestVringDescEntry {
            data: req_addr + 16,
            len: 0,
            write: true,
        });
        data_entries.push(TestVringDescEntry {
            data: req_addr + 20,
            len: 1,
            write: true,
        });
        let _free_head = virtqueues[0]
            .borrow_mut()
            .add_chained(test_state.clone(), data_entries);

        blk.borrow()
            .kick_virtqueue(test_state.clone(), virtqueues[0].clone());
        thread::sleep(time::Duration::from_secs(1));

        let status = test_state.borrow().readb(req_addr + 20);
        assert_ne!(status, VIRTIO_BLK_S_OK);

        // Desc: only status desc.
        let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(3);
        data_entries.push(TestVringDescEntry {
            data: req_addr,
            len: 1,
            write: true,
        });
        let _free_head = virtqueues[0]
            .borrow_mut()
            .add_chained(test_state.clone(), data_entries);

        blk.borrow()
            .kick_virtqueue(test_state.clone(), virtqueues[0].clone());
        thread::sleep(time::Duration::from_secs(1));

        let status = test_state.borrow().readb(req_addr);
        assert_ne!(status, VIRTIO_BLK_S_OK);

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device send different types of I/O requests in parallel.
/// TestStep:
///   1. Init block device.
///   2. Do the different types I/O requests in parallel.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_parallel_req() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let (blk, test_state, alloc, image_path) = set_up(&image_type);

        let mut features = virtio_blk_default_feature(blk.clone());
        features |= 1 << VIRTIO_BLK_F_FLUSH;

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        let mut free_head_vec: Vec<u32> = Vec::with_capacity(4);
        let mut req_addr_vec: Vec<u64> = Vec::with_capacity(4);

        let (free_head, req_addr) = add_blk_request(
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            VIRTIO_BLK_T_OUT,
            0,
            true,
        );
        free_head_vec.push(free_head);
        req_addr_vec.push(req_addr);

        let (free_head, req_addr) = add_blk_request(
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            VIRTIO_BLK_T_IN,
            0,
            true,
        );
        free_head_vec.push(free_head);
        req_addr_vec.push(req_addr);

        let (free_head, req_addr) = add_blk_request(
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            VIRTIO_BLK_T_FLUSH,
            0,
            true,
        );
        free_head_vec.push(free_head);
        req_addr_vec.push(req_addr);

        let (free_head, req_addr) = add_blk_request(
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            VIRTIO_BLK_T_GET_ID,
            0,
            true,
        );
        free_head_vec.push(free_head);
        req_addr_vec.push(req_addr);

        blk.borrow()
            .kick_virtqueue(test_state.clone(), virtqueues[0].clone());
        blk.borrow().poll_used_elem(
            test_state.clone(),
            virtqueues[0].clone(),
            free_head_vec[3],
            TIMEOUT_US,
            &mut None,
            true,
        );

        for i in 0..4 {
            let status_addr =
                round_up(req_addr_vec[i] + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
            let status = test_state.borrow().readb(status_addr);
            assert_eq!(status, VIRTIO_BLK_S_OK);
        }

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device sends an I/O request that exceeds the capacity range.
/// TestStep:
///   1. Init block device.
///   2. Do the I/O request that exceeds the capacity range.
///   3. Destroy device.
/// Expect:
///   1/3: success, 2: failed.
#[test]
fn blk_exceed_capacity() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let (blk, test_state, alloc, image_path) = set_up(&image_type);

        let features = virtio_blk_default_feature(blk.clone());

        let virtqueues =
            blk.borrow_mut()
                .init_device(test_state.clone(), alloc.clone(), features, 1);

        let capacity = blk.borrow().config_readq(0);
        assert_eq!(capacity, TEST_IMAGE_SIZE / REQ_DATA_LEN as u64);

        let (free_head, req_addr) = add_blk_request(
            test_state.clone(),
            alloc.clone(),
            virtqueues[0].clone(),
            VIRTIO_BLK_T_OUT,
            capacity + 1,
            true,
        );

        blk.borrow().virtqueue_notify(virtqueues[0].clone());
        blk.borrow().poll_used_elem(
            test_state.clone(),
            virtqueues[0].clone(),
            free_head,
            TIMEOUT_US,
            &mut None,
            true,
        );

        let status_addr =
            round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
        let status = test_state.borrow().readb(status_addr);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            virtqueues,
            image_path.clone(),
        );
    }
}

/// Block device sends I/O request with feature 'VIRTIO_BLK_F_DISCARD'.
/// TestStep:
///   1. Init block device with feature 'VIRTIO_BLK_F_DISCARD'.
///   2. Do the discard request with different arguments.
///   3. Destroy device.
/// Expect:
///   1/3: success.
///   2: success or failure, stratovirt process is normal.
#[test]
fn blk_feature_discard() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let req_len = std::mem::size_of::<VirtBlkDiscardWriteZeroes>();
        // (sector, num_sectors, flags, req_len, enable_feature, discard, status)
        let reqs = [
            (0, 2048, 0, req_len, true, "unmap", VIRTIO_BLK_S_OK),
            (0, 2048, 0, req_len, false, "unmap", VIRTIO_BLK_S_OK),
            (0, 2048, 0, 8, true, "unmap", 0xff),
            (0, 2048, 0, 32, true, "unmap", VIRTIO_BLK_S_UNSUPP),
            (0, 2048, 1, req_len, true, "unmap", VIRTIO_BLK_S_UNSUPP),
            (0, 2048, 0xff, req_len, true, "unmap", VIRTIO_BLK_S_UNSUPP),
            (
                0,
                (TEST_IMAGE_SIZE >> 9) as u32 + 1,
                0,
                req_len,
                true,
                "unmap",
                VIRTIO_BLK_S_IOERR,
            ),
            (
                0,
                MAX_REQUEST_SECTORS + 1,
                0,
                req_len,
                true,
                "unmap",
                VIRTIO_BLK_S_IOERR,
            ),
            (0, 2048, 0, req_len, false, "ignore", VIRTIO_BLK_S_UNSUPP),
        ];
        let mut i = 1;
        for (sector, num_sectors, flags, len, enabled, discard, status) in reqs {
            println!("blk_feature_discard: request {}", i);
            i += 1;
            let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 0, &image_type));
            let full_disk_size = get_disk_size(image_path.clone());
            let device_args = Rc::new(String::from(""));
            let drive_args = Rc::new(format!(",discard={},direct=false", discard));
            let other_args = Rc::new(String::from(""));
            let (blk, test_state, alloc) = create_blk(
                &image_type,
                image_path.clone(),
                device_args,
                drive_args,
                other_args,
            );

            let mut features = virtio_blk_default_feature(blk.clone());
            if enabled {
                features |= 1 << VIRTIO_BLK_F_DISCARD;
            } else {
                features &= !(1 << VIRTIO_BLK_F_DISCARD);
            }

            let virtqueues =
                blk.borrow_mut()
                    .init_device(test_state.clone(), alloc.clone(), features, 1);
            if discard != "ignore" {
                virtio_blk_check_discard_config(blk.clone());
            }

            let mut need_poll_elem = true;
            let req_data = if len == req_len {
                let req = VirtBlkDiscardWriteZeroes {
                    sector,
                    num_sectors,
                    flags,
                };
                req.as_bytes().to_vec()
            } else {
                if len < req_len {
                    need_poll_elem = false;
                }
                vec![0; len]
            };
            virtio_blk_discard_and_write_zeroes(
                blk.clone(),
                test_state.clone(),
                alloc.clone(),
                virtqueues[0].clone(),
                &req_data,
                status,
                need_poll_elem,
                true,
            );
            if image_type == ImageType::Raw && status == VIRTIO_BLK_S_OK {
                let image_size = get_disk_size(image_path.clone());
                assert_eq!(image_size, full_disk_size - num_sectors as u64 / 2);
            } else if image_type == ImageType::Qcow2
                && status == VIRTIO_BLK_S_OK
                && (num_sectors as u64 * 512 & CLUSTER_SIZE - 1) == 0
            {
                // If the disk format is equal to Qcow2.
                // the length of the num sectors needs to be aligned with the cluster size,
                // otherwise the calculated file size is not accurate.
                let image_size = get_disk_size(image_path.clone());
                let delete_num = (num_sectors as u64 * 512) >> 10;
                assert_eq!(image_size, full_disk_size - delete_num);
            }

            tear_down(
                blk.clone(),
                test_state.clone(),
                alloc.clone(),
                virtqueues,
                image_path.clone(),
            );
        }
    }
}

/// Block device sends I/O request with feature 'VIRTIO_BLK_F_WRITE_ZEROES'.
/// TestStep:
///   1. Init block device with feature 'VIRTIO_BLK_F_WRITE_ZEROES'.
///   2. Do the write-zeroes request with different arguments.
///   3. Destroy device.
/// Expect:
///   1/3: success.
///   2: success or failure, stratovirt process is normal.
#[test]
fn blk_feature_write_zeroes() {
    for image_type in ImageType::IMAGE_TYPE {
        println!("Image type: {:?}", image_type);
        let wz_len = size_of::<VirtBlkDiscardWriteZeroes>();
        let req_len = size_of::<TestVirtBlkReq>();
        // (sector, num_sectors, flags, req_len, enable_feature, write_zeroes, discard, status)
        let reqs = [
            (0, 2048, 0, wz_len, true, "on", "ignore", VIRTIO_BLK_S_OK),
            (0, 2048, 0, wz_len, true, "on", "unmap", VIRTIO_BLK_S_OK),
            (0, 2048, 0, wz_len, false, "on", "ignore", VIRTIO_BLK_S_OK),
            (0, 2048, 0, wz_len, false, "on", "unmap", VIRTIO_BLK_S_OK),
            (0, 2048, 0, wz_len, true, "unmap", "ignore", VIRTIO_BLK_S_OK),
            (
                0,
                2048,
                0,
                wz_len,
                false,
                "unmap",
                "ignore",
                VIRTIO_BLK_S_OK,
            ),
            (
                0,
                2048,
                0,
                wz_len,
                false,
                "off",
                "ignore",
                VIRTIO_BLK_S_UNSUPP,
            ),
            (
                0,
                2048,
                0,
                wz_len,
                false,
                "off",
                "unmap",
                VIRTIO_BLK_S_UNSUPP,
            ),
            (0, 2048, 1, wz_len, true, "unmap", "unmap", VIRTIO_BLK_S_OK),
            (0, 8, 0, req_len, true, "unmap", "unmap", VIRTIO_BLK_S_OK),
            (0, 0, 0, req_len, true, "on", "unmap", VIRTIO_BLK_S_OK),
        ];
        let mut i = 1;
        for (sector, num_sectors, flags, len, enabled, write_zeroes, discard, status) in reqs {
            println!("blk_feature_write_zeroes: request {}", i);
            i += 1;
            let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 1, &image_type));
            let full_disk_size = get_disk_size(image_path.clone());
            let device_args = Rc::new(String::from(""));
            let drive_args = Rc::new(format!(
                ",detect-zeroes={},discard={},direct=false",
                write_zeroes, discard
            ));
            let other_args = Rc::new(String::from(""));
            let (blk, test_state, alloc) = create_blk(
                &image_type,
                image_path.clone(),
                device_args,
                drive_args,
                other_args,
            );

            let mut features = virtio_blk_default_feature(blk.clone());
            if discard == "unmap" {
                features |= 1 << VIRTIO_BLK_F_DISCARD;
            }
            if enabled {
                features |= 1 << VIRTIO_BLK_F_WRITE_ZEROES;
            } else {
                features &= !(1 << VIRTIO_BLK_F_WRITE_ZEROES);
            }

            let virtqueues =
                blk.borrow_mut()
                    .init_device(test_state.clone(), alloc.clone(), features, 1);
            if enabled {
                virtio_blk_check_write_zeroes_config(blk.clone());
            }

            virtio_blk_write(
                blk.clone(),
                test_state.clone(),
                alloc.clone(),
                virtqueues[0].clone(),
                0,
                true,
            );

            if len == wz_len {
                let req_data = VirtBlkDiscardWriteZeroes {
                    sector,
                    num_sectors,
                    flags,
                };
                virtio_blk_discard_and_write_zeroes(
                    blk.clone(),
                    test_state.clone(),
                    alloc.clone(),
                    virtqueues[0].clone(),
                    &req_data.as_bytes().to_vec(),
                    status,
                    true,
                    false,
                );
            } else {
                virtio_blk_read_write_zeroes(
                    blk.clone(),
                    test_state.clone(),
                    alloc.clone(),
                    virtqueues[0].clone(),
                    VIRTIO_BLK_T_OUT,
                    0,
                    4096,
                );
            }

            if write_zeroes != "off" {
                virtio_blk_read_write_zeroes(
                    blk.clone(),
                    test_state.clone(),
                    alloc.clone(),
                    virtqueues[0].clone(),
                    VIRTIO_BLK_T_IN,
                    0,
                    512,
                );
            }

            if image_type == ImageType::Raw
                && status == VIRTIO_BLK_S_OK
                && (write_zeroes == "unmap" && discard == "unmap" && flags == 1 || len != wz_len)
            {
                let image_size = get_disk_size(image_path.clone());
                assert_eq!(image_size, full_disk_size - num_sectors as u64 / 2);
            } else if image_type == ImageType::Qcow2
                && status == VIRTIO_BLK_S_OK
                && (write_zeroes == "unmap" && discard == "unmap" && flags == 1 || len != wz_len)
                && (num_sectors as u64 * 512 & CLUSTER_SIZE - 1) == 0
            {
                // If the disk format is equal to Qcow2.
                // the length of the num sectors needs to be aligned with the cluster size,
                // otherwise the calculated file size is not accurate.
                let image_size = get_disk_size(image_path.clone());
                let delete_num = (num_sectors as u64 * 512) >> 10;
                assert_eq!(image_size, full_disk_size - delete_num);
            }

            tear_down(
                blk.clone(),
                test_state.clone(),
                alloc.clone(),
                virtqueues,
                image_path.clone(),
            );
        }
    }
}

/// Block device using snapshot sends I/O request.
/// TestStep:
///   1. Init block device. Create internal snapshot.
///   2. Do the I/O request.
///   3. Delete internal snapshot.
///   4. Do the I/O request.
///   5. Destroy device.
/// Expect:
///   1/2/3/4/5: success.
#[test]
fn blk_snapshot_basic() {
    let (blk, test_state, alloc, image_path) = set_up(&ImageType::Qcow2);
    let features = virtio_blk_default_feature(blk.clone());
    let virtqueues = blk
        .borrow_mut()
        .init_device(test_state.clone(), alloc.clone(), features, 1);

    create_snapshot(test_state.clone(), "drive0", "snap0");
    assert_eq!(check_snapshot(test_state.clone(), "snap0"), true);

    virtio_blk_write(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        0,
        true,
    );
    virtio_blk_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        0,
        true,
    );

    delete_snapshot(test_state.clone(), "drive0", "snap0");
    assert_eq!(check_snapshot(test_state.clone(), "snap0"), false);

    virtio_blk_write(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        0,
        true,
    );
    virtio_blk_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        0,
        true,
    );

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues,
        image_path.clone(),
    );
}

/// Block device whose backend file has snapshot sends I/O request.
/// TestStep:
///   1. Create snapshot snap0 in qcow2 backend file.
///   2. Init device.
///   3. Do the I/O request.
///   4. Create internal snapshot snap1. Delete internal snapshot snap0.
///   5. Do the I/O request.
///   6. Destroy device.
/// Expect:
///   1/2/3/4/5/6: success.
#[test]
fn blk_snapshot_basic2() {
    // Note: We can not use stratovirt-img to create snapshot now.
    // So, we use qmp to create snapshot in existed qcow2 file.
    // TODO: use stratovirt-img instead of qmp in the future.
    let (blk, test_state, alloc, image_path) = set_up(&ImageType::Qcow2);
    let features = virtio_blk_default_feature(blk.clone());
    let virtqueues = blk
        .borrow_mut()
        .init_device(test_state.clone(), alloc.clone(), features, 1);
    create_snapshot(test_state.clone(), "drive0", "snap0");
    assert_eq!(check_snapshot(test_state.clone(), "snap0"), true);
    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues,
        Rc::new("".to_string()),
    );

    let device_args = Rc::new(String::from(""));
    let drive_args = Rc::new(String::from(",direct=false"));
    let other_args = Rc::new(String::from(""));
    let (blk, test_state, alloc) = create_blk(
        &ImageType::Qcow2,
        image_path.clone(),
        device_args,
        drive_args,
        other_args,
    );

    let features = virtio_blk_default_feature(blk.clone());
    let virtqueues = blk
        .borrow_mut()
        .init_device(test_state.clone(), alloc.clone(), features, 1);

    virtio_blk_write(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        0,
        true,
    );
    virtio_blk_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        0,
        true,
    );

    create_snapshot(test_state.clone(), "drive0", "snap1");
    assert_eq!(check_snapshot(test_state.clone(), "snap1"), true);

    delete_snapshot(test_state.clone(), "drive0", "snap0");
    assert_eq!(check_snapshot(test_state.clone(), "snap0"), false);

    virtio_blk_write(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        0,
        true,
    );
    virtio_blk_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        0,
        true,
    );

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues,
        image_path.clone(),
    );
}
