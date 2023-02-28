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

use virtio::block::VirtioBlkConfig;

use mod_test::libdriver::malloc::GuestAllocator;
use mod_test::libdriver::virtio::TestVringDescEntry;
use mod_test::libdriver::virtio::{TestVirtQueue, VirtioDeviceOps};
use mod_test::libdriver::virtio_block::{
    add_blk_request, create_blk, set_up, tear_down, virtio_blk_defalut_feature, virtio_blk_read,
    virtio_blk_request, virtio_blk_write, TestVirtBlkReq, DEFAULT_IO_REQS, REQ_ADDR_LEN,
    REQ_DATA_LEN, REQ_STATUS_LEN, TIMEOUT_US, VIRTIO_BLK_F_BARRIER, VIRTIO_BLK_F_BLK_SIZE,
    VIRTIO_BLK_F_CONFIG_WCE, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_GEOMETRY,
    VIRTIO_BLK_F_LIFETIME, VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_RO, VIRTIO_BLK_F_SECURE_ERASE,
    VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_WRITE_ZEROES,
    VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP, VIRTIO_BLK_T_FLUSH,
    VIRTIO_BLK_T_GET_ID, VIRTIO_BLK_T_ILLGEAL, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT,
};
use mod_test::libdriver::virtio_pci_modern::TestVirtioPciDev;
use mod_test::libtest::TestState;
use mod_test::utils::{create_img, TEST_IMAGE_SIZE};

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};
use util::aio::{aio_probe, AioEngine};
use util::num_ops::round_up;
use util::offset_of;

const TEST_IMAGE_SIZE_1M: u64 = 1024 * 1024;

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
    let (blk, test_state, alloc, image_path) = set_up();

    let features = virtio_blk_defalut_feature(blk.clone());

    let virtqueues = blk
        .borrow_mut()
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
    let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 0));
    let device_args = Rc::new(String::from(",num-queues=4"));
    let drive_args = Rc::new(String::from(",direct=false,readonly=on"));
    let other_args = Rc::new(String::from(""));
    let (blk, test_state, alloc) =
        create_blk(image_path.clone(), device_args, drive_args, other_args);

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

/// Block device sends I/O request with feature 'VIRTIO_BLK_F_SEG_MAX'.
/// TestStep:
///   1. Init block device with feature 'VIRTIO_BLK_F_SEG_MAX'.
///   2. Do the I/O request, check seg_max.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_feature_seg_max() {
    let (blk, test_state, alloc, image_path) = set_up();

    let mut features = virtio_blk_defalut_feature(blk.clone());
    features |= 1 << VIRTIO_BLK_F_SEG_MAX;

    let virtqueues = blk
        .borrow_mut()
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
    let (blk, test_state, alloc, image_path) = set_up();

    let mut features = virtio_blk_defalut_feature(blk.clone());

    let virtqueues = blk
        .borrow_mut()
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
    let (blk, test_state, alloc) =
        create_blk(image_path.clone(), device_args, drive_args, other_args);

    features |= 1 << VIRTIO_BLK_F_RO;

    let virtqueues = blk
        .borrow_mut()
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

    let status_addr = round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
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

/// Block device sends I/O request with feature 'VIRTIO_BLK_F_FLUSH'.
/// TestStep:
///   1. Init block device with feature 'VIRTIO_BLK_F_FLUSH'.
///   2. Do the I/O request.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_feature_flush() {
    let (blk, test_state, alloc, image_path) = set_up();

    let mut features = virtio_blk_defalut_feature(blk.clone());
    features |= 1 << VIRTIO_BLK_F_FLUSH;

    let virtqueues = blk
        .borrow_mut()
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

/// Block device sends I/O request with feature 'VIRTIO_BLK_F_MQ'.
/// TestStep:
///   1. Init block device with feature 'VIRTIO_BLK_F_MQ'.
///   2. Do the I/O multiple queue requests.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_feature_mq() {
    let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 0));
    let device_args = Rc::new(String::from(",num-queues=4"));
    let drive_args = Rc::new(String::from(",direct=false"));
    let other_args = Rc::new(String::from(""));
    let (blk, test_state, alloc) =
        create_blk(image_path.clone(), device_args, drive_args, other_args);

    let mut features = virtio_blk_defalut_feature(blk.clone());
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
        let mut blk_req = TestVirtBlkReq::new(VIRTIO_BLK_T_OUT, 1, i as u64, REQ_DATA_LEN as usize);
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

/// Block device sends I/O request, configure all parameters.
/// TestStep:
///   1. Init block device, configure all parameters.
///   2. Do the I/O request.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_all_features() {
    let image_path = Rc::new(create_img(TEST_IMAGE_SIZE_1M, 1));
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
    let (blk, test_state, alloc) =
        create_blk(image_path.clone(), device_args, drive_args, other_args);

    let mut features = virtio_blk_defalut_feature(blk.clone());
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

/// Block device sends I/O request to a file with a size of 511b.
/// TestStep:
///   1. Init block device with a 511b file.
///   2. Do the I/O request.
///   3. Destroy device.
/// Expect:
///   1/3: success, 2: failed.
#[test]
fn blk_small_file_511b() {
    let size = 511;
    let image_path = Rc::new(create_img(size, 1));
    let device_args = Rc::new(String::from(""));
    let drive_args = Rc::new(String::from(",direct=false"));
    let other_args = Rc::new(String::from(""));
    let (blk, test_state, alloc) =
        create_blk(image_path.clone(), device_args, drive_args, other_args);

    let features = virtio_blk_defalut_feature(blk.clone());

    let virtqueues = blk
        .borrow_mut()
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

    let status_addr = round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
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

    let status_addr = round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
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

/// Block device sends I/O request, configured as 'serial=11111111111111111111'.
/// TestStep:
///   1. Init block device, configured as 'serial=11111111111111111111'.
///   2. Do the I/O request, check serial number.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_serial() {
    let serial_num = String::from("11111111111111111111");
    let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 0));
    let device_args = Rc::new(format!(",serial={}", serial_num));
    let drive_args = Rc::new(String::from(",direct=false"));
    let other_args = Rc::new(String::from(""));
    let (blk, test_state, alloc) =
        create_blk(image_path.clone(), device_args, drive_args, other_args);

    let features = virtio_blk_defalut_feature(blk.clone());

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

/// Block device sends I/O request, configured as 'throttling.iops-total=1'.
/// TestStep:
///   1. Init block device, configured as 'throttling.iops-total=1'.
///   2. Do the I/O request, check iops.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_iops() {
    let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 0));
    let device_args = Rc::new(String::from(""));
    let drive_args = Rc::new(String::from(",direct=false,throttling.iops-total=1"));
    let other_args = Rc::new(String::from(""));
    let (blk, test_state, alloc) =
        create_blk(image_path.clone(), device_args, drive_args, other_args);

    let features = virtio_blk_defalut_feature(blk.clone());

    let virtqueues = blk
        .borrow_mut()
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

    let status_addr = round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
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

    let status_addr = round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
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

/// Block device sends I/O request, configured as 'aio=native'.
/// TestStep:
///   1. Init block device, configured as 'aio=native'.
///   2. Do the I/O request.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn blk_aio_native() {
    let image_path = Rc::new(create_img(TEST_IMAGE_SIZE_1M, 1));
    let device_args = Rc::new(String::from(""));
    let drive_args = if aio_probe(AioEngine::Native).is_ok() {
        Rc::new(String::from(",direct=on,aio=native"))
    } else {
        Rc::new(String::from(",direct=false"))
    };
    let other_args = Rc::new(String::from(""));
    let (blk, test_state, alloc) =
        create_blk(image_path.clone(), device_args, drive_args, other_args);

    let features = virtio_blk_defalut_feature(blk.clone());

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

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues,
        image_path.clone(),
    );
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
    let image_path = Rc::new(create_img(TEST_IMAGE_SIZE_1M, 1));
    let device_args = Rc::new(String::from(""));
    let drive_args = if aio_probe(AioEngine::IoUring).is_ok() {
        Rc::new(String::from(",direct=on,aio=io_uring"))
    } else {
        Rc::new(String::from(",direct=false"))
    };
    let other_args = Rc::new(String::from(""));
    let (blk, test_state, alloc) =
        create_blk(image_path.clone(), device_args, drive_args, other_args);

    let features = virtio_blk_defalut_feature(blk.clone());

    let virtqueues = blk
        .borrow_mut()
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

/// Block device sends an illegal type of I/O request.
/// TestStep:
///   1. Init block device.
///   2. Do the I/O request of illegal type.
///   3. Destroy device.
/// Expect:
///   1/3: success, 2: failed.
#[test]
fn blk_illegal_req_type() {
    let (blk, test_state, alloc, image_path) = set_up();

    let features = virtio_blk_defalut_feature(blk.clone());

    let virtqueues = blk
        .borrow_mut()
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
    let (blk, test_state, alloc, image_path) = set_up();

    let features = virtio_blk_defalut_feature(blk.clone());

    let virtqueues = blk
        .borrow_mut()
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

/// Block device send I/O requests in an abnormal format.
/// TestStep:
///   1. Init block device.
///   2. Do the I/O requests in an abnormal format.
///   3. Destroy device.
/// Expect:
///   1/3: success, 2: failed.
#[test]
fn blk_abnormal_req() {
    let (blk, test_state, alloc, image_path) = set_up();

    let features = virtio_blk_defalut_feature(blk.clone());

    let virtqueues = blk
        .borrow_mut()
        .init_device(test_state.clone(), alloc.clone(), features, 1);

    let mut blk_req = TestVirtBlkReq::new(VIRTIO_BLK_T_OUT, 1, 0, REQ_DATA_LEN as usize);
    blk_req.data.push_str("TEST");

    let req_addr = virtio_blk_request(test_state.clone(), alloc.clone(), blk_req, false);

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

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues,
        image_path.clone(),
    );
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
    let (blk, test_state, alloc, image_path) = set_up();

    let mut features = virtio_blk_defalut_feature(blk.clone());
    features |= 1 << VIRTIO_BLK_F_FLUSH;

    let virtqueues = blk
        .borrow_mut()
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

/// Block device sends an I/O request that exceeds the capacity range.
/// TestStep:
///   1. Init block device.
///   2. Do the I/O request that exceeds the capacity range.
///   3. Destroy device.
/// Expect:
///   1/3: success, 2: failed.
#[test]
fn blk_exceed_capacity() {
    let (blk, test_state, alloc, image_path) = set_up();

    let features = virtio_blk_defalut_feature(blk.clone());

    let virtqueues = blk
        .borrow_mut()
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

    let status_addr = round_up(req_addr + REQ_ADDR_LEN as u64, 512).unwrap() + REQ_DATA_LEN as u64;
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
