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

use rand::Rng;
use serde_json::json;
use std::cell::RefCell;
use std::mem::size_of;
use std::rc::Rc;
use util::offset_of;

use mod_test::libdriver::malloc::GuestAllocator;
use mod_test::libdriver::virtio::{
    get_vring_size, TestVirtQueue, TestVringIndirectDesc, VirtioDeviceOps, VringDesc,
    VIRTIO_CONFIG_S_NEEDS_RESET, VIRTIO_F_VERSION_1, VIRTIO_PCI_VRING_ALIGN,
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC, VRING_AVAIL_F_NO_INTERRUPT,
    VRING_DESC_F_INDIRECT, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE, VRING_DESC_SIZE,
};
use mod_test::libdriver::virtio_block::{
    add_blk_request, set_up, tear_down, virtio_blk_read, virtio_blk_request, virtio_blk_write,
    TestVirtBlkReq, DEFAULT_IO_REQS, REQ_ADDR_LEN, REQ_DATA_LEN, REQ_STATUS_OFFSET, TIMEOUT_US,
    VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT,
};
use mod_test::libdriver::virtio_pci_modern::{TestVirtioPciDev, VirtioPciCommonCfg};
use mod_test::libtest::TestState;
use mod_test::utils::TEST_IMAGE_SIZE;

fn add_request(
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vq: Rc<RefCell<TestVirtQueue>>,
    req_type: u32,
    sector: u64,
) -> (u32, u64) {
    add_blk_request(test_state, alloc, vq, req_type, sector, false)
}

fn virtio_read(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vq: Rc<RefCell<TestVirtQueue>>,
    sector: u64,
) {
    virtio_blk_read(blk, test_state, alloc, vq, sector, false);
}

fn virtio_write(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vq: Rc<RefCell<TestVirtQueue>>,
    sector: u64,
) {
    virtio_blk_write(blk, test_state, alloc, vq, sector, false);
}

fn virtio_request(
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    req: TestVirtBlkReq,
) -> u64 {
    virtio_blk_request(test_state, alloc, req, false)
}

fn send_one_request(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vq: Rc<RefCell<TestVirtQueue>>,
) {
    let (free_head, req_addr) = add_request(
        test_state.clone(),
        alloc.clone(),
        vq.clone(),
        VIRTIO_BLK_T_OUT,
        0,
    );
    blk.borrow().virtqueue_notify(vq.clone());
    blk.borrow().poll_used_elem(
        test_state.clone(),
        vq.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );

    let status = test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET);
    assert_eq!(status, VIRTIO_BLK_S_OK);
}

fn check_stratovirt_status(test_state: Rc<RefCell<TestState>>) {
    let ret = test_state
        .borrow()
        .qmp("{\"execute\": \"qmp_capabilities\"}");
    assert_eq!(*ret.get("return").unwrap(), json!({}));
}

fn init_device_step(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    tests: Vec<[usize; 8]>,
) {
    for elem in tests {
        let mut vqs: Vec<Rc<RefCell<TestVirtQueue>>> = Vec::new();
        for j in elem.iter() {
            match j {
                1 => blk.borrow_mut().reset(),
                2 => blk.borrow().set_acknowledge(),
                3 => blk.borrow().set_driver(),
                4 => blk.borrow_mut().negotiate_features(1 << VIRTIO_F_VERSION_1),
                5 => blk.borrow_mut().set_features_ok(),
                7 => {
                    blk.borrow_mut().pci_dev.enable_msix(None);
                    blk.borrow_mut()
                        .setup_msix_configuration_vector(alloc.clone(), 0);
                    vqs = blk
                        .borrow_mut()
                        .init_virtqueue(test_state.clone(), alloc.clone(), 1);
                    ()
                }
                8 => {
                    blk.borrow().set_driver_ok();
                }
                9 => blk.borrow().set_status(128),
                _ => continue,
            }
        }

        // Try to send write and read request to StratoVirt, ignore
        // the interrupt from device.
        if vqs.len() > 0 {
            let (_, _) = add_request(
                test_state.clone(),
                alloc.clone(),
                vqs[0].clone(),
                VIRTIO_BLK_T_OUT,
                0,
            );
            blk.borrow().virtqueue_notify(vqs[0].clone());

            let (_, _) = add_request(
                test_state.clone(),
                alloc.clone(),
                vqs[0].clone(),
                VIRTIO_BLK_T_IN,
                0,
            );
            blk.borrow().virtqueue_notify(vqs[0].clone());
        }

        check_stratovirt_status(test_state.clone());
    }
}

fn check_req_result(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    vq: Rc<RefCell<TestVirtQueue>>,
    addr: u64,
    timeout_us: u64,
) {
    let status = blk
        .borrow()
        .req_result(test_state.clone(), addr, timeout_us);
    assert!(!blk.borrow().queue_was_notified(vq));
    assert_eq!(status, VIRTIO_BLK_S_OK);
}

fn check_queue(blk: Rc<RefCell<TestVirtioPciDev>>, desc: u64, avail: u64, used: u64) {
    let bar = blk.borrow().bar;
    let common_base = blk.borrow().common_base as u64;
    let reqs = [
        (offset_of!(VirtioPciCommonCfg, queue_desc_lo), desc),
        (offset_of!(VirtioPciCommonCfg, queue_desc_hi), desc >> 32),
        (offset_of!(VirtioPciCommonCfg, queue_avail_lo), avail),
        (offset_of!(VirtioPciCommonCfg, queue_avail_hi), avail >> 32),
        (offset_of!(VirtioPciCommonCfg, queue_used_lo), used),
        (offset_of!(VirtioPciCommonCfg, queue_used_hi), used >> 32),
    ];
    for (offset, value) in reqs {
        let addr = blk
            .borrow()
            .pci_dev
            .io_readl(bar, common_base as u64 + offset as u64);
        assert_eq!(addr, value as u32);
    }
}

fn do_event_idx_with_flag(flag: u16) {
    let (blk, test_state, alloc, image_path) = set_up();

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1 | 1 << VIRTIO_RING_F_EVENT_IDX,
        1,
    );

    let (free_head, mut req_addr) = add_request(
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        VIRTIO_BLK_T_OUT,
        0,
    );
    vqs[0].borrow().set_used_event(test_state.clone(), 1);
    blk.borrow().virtqueue_notify(vqs[0].clone());
    blk.borrow().poll_used_elem(
        test_state.clone(),
        vqs[0].clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );

    let status = test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET);
    assert_eq!(status, VIRTIO_BLK_S_OK);

    // DEFAULT_IO_REQS write requests:
    //   Write "TEST" to sector 0 to DEFAULT_IO_REQS.
    //let mut req_addr = 0_u64;
    for i in 1..DEFAULT_IO_REQS {
        (_, req_addr) = add_request(
            test_state.clone(),
            alloc.clone(),
            vqs[0].clone(),
            VIRTIO_BLK_T_OUT,
            i,
        );
    }

    // Set avail->used_event to DEFAULT_IO_REQS which the rigth value is DEFAULT_IO_REQS - 1,
    // it will not get the interrupt which means event index feature works.
    vqs[0]
        .borrow()
        .set_used_event(test_state.clone(), DEFAULT_IO_REQS as u16);
    blk.borrow().virtqueue_notify(vqs[0].clone());
    check_req_result(
        blk.clone(),
        test_state.clone(),
        vqs[0].clone(),
        req_addr + REQ_STATUS_OFFSET,
        TIMEOUT_US,
    );

    // Create two write requests, the avail->used_event will be the update to the right value.
    // It will get the interrupt from device.
    let mut free_head = 0_u32;
    for i in DEFAULT_IO_REQS..DEFAULT_IO_REQS * 2 {
        (free_head, _) = add_request(
            test_state.clone(),
            alloc.clone(),
            vqs[0].clone(),
            VIRTIO_BLK_T_OUT,
            i,
        );
    }

    // Set flag to avail->flag.
    test_state.borrow().writew(vqs[0].borrow().avail, flag);
    blk.borrow().virtqueue_notify(vqs[0].clone());
    blk.borrow().poll_used_elem(
        test_state.clone(),
        vqs[0].clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );

    // Read the content in sector DEFAULT_IO_REQS * 2 - 1.
    virtio_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        DEFAULT_IO_REQS * 2 - 1,
    );

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Feature Test.
/// Driver don't enable feature, and failed to do the I/O request.
/// TestStep:
///   1. Init device: no virtio feature negotiation.
///   2. Do the I/O request.
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   1/3/4: success.
///   2: device can't handle the io request.
#[test]
fn virtio_feature_none() {
    let (blk, test_state, alloc, image_path) = set_up();

    let vqs = blk
        .borrow_mut()
        .init_device(test_state.clone(), alloc.clone(), 0, 1);

    let mut req_addr = 0_u64;
    for i in 0..DEFAULT_IO_REQS {
        (_, req_addr) = add_request(
            test_state.clone(),
            alloc.clone(),
            vqs[0].clone(),
            VIRTIO_BLK_T_OUT,
            i,
        );
    }
    blk.borrow().virtqueue_notify(vqs[0].clone());

    let status = test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET);
    assert_eq!(status, 0xff);

    check_stratovirt_status(test_state.clone());

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Feature Test.
/// Driver just enable VIRTIO_F_VERSION_1 feature, and succeed to do the I/O request.
/// TestStep:
///   1. Init device.
///   2. Do the I/O request:
///     1) avail->flags with VRING_AVAIL_F_NO_INTERRUPT;
///     2) avail->flags with not VRING_AVAIL_F_NO_INTERRUPT;
///   3. For different avail->flags:
///     1) check the request status, it has been handled.
///     2) it will get the interrupt from device.
///   4. Destroy device.
/// Expect:
///   1/2/3/4: success.
#[test]
fn virtio_feature_vertion_1() {
    let (blk, test_state, alloc, image_path) = set_up();

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    // 1) avail->flags with VRING_AVAIL_F_NO_INTERRUPT(1).
    vqs[0]
        .borrow()
        .set_avail_flags(test_state.clone(), VRING_AVAIL_F_NO_INTERRUPT);
    let mut free_head = 0_u32;
    let mut req_addr = 0_u64;
    for i in 0..DEFAULT_IO_REQS {
        (free_head, req_addr) = add_request(
            test_state.clone(),
            alloc.clone(),
            vqs[0].clone(),
            VIRTIO_BLK_T_OUT,
            i,
        );
    }
    assert!(!blk.borrow().queue_was_notified(vqs[0].clone()));
    blk.borrow().virtqueue_notify(vqs[0].clone());

    // need be changed.
    blk.borrow().poll_used_elem(
        test_state.clone(),
        vqs[0].clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        false,
    );

    assert!(!blk.borrow().queue_was_notified(vqs[0].clone()));
    let status = test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET);
    assert_eq!(status, VIRTIO_BLK_S_OK);

    // 2) avail->flags with no VRING_AVAIL_F_NO_INTERRUPT.
    vqs[0].borrow().set_avail_flags(test_state.clone(), 0);
    virtio_write(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        DEFAULT_IO_REQS,
    );
    virtio_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        DEFAULT_IO_REQS,
    );

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Driver just enable VIRTIO_F_VERSION_1|VIRTIO_RING_F_INDIRECT_DESC feature,
/// and succeed to do the I/O request.
/// TestStep:
///   1. Init device.
///   2. Do the I/O request(indirect and  indirect + normal).
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtio_feature_indirect() {
    let (blk, test_state, alloc, image_path) = set_up();

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1 | 1 << VIRTIO_RING_F_INDIRECT_DESC,
        1,
    );

    let mut free_head = 0_u32;
    let mut req_addr = 0_u64;
    for i in 0..DEFAULT_IO_REQS {
        let mut blk_req = TestVirtBlkReq::new(VIRTIO_BLK_T_OUT, 1, i, REQ_DATA_LEN as usize);
        blk_req.data.push_str("TEST");
        req_addr = virtio_request(test_state.clone(), alloc.clone(), blk_req);
        free_head = vqs[0]
            .borrow_mut()
            .add(test_state.clone(), req_addr, 8, false);
        let offset = free_head as u64 * VRING_DESC_SIZE + offset_of!(VringDesc, flags) as u64;
        test_state
            .borrow()
            .writew(vqs[0].borrow().desc + offset as u64, VRING_DESC_F_NEXT);
        test_state.borrow().writew(
            vqs[0].borrow().desc + offset as u64 + 2,
            free_head as u16 + 1,
        );
        let mut indirect_req = TestVringIndirectDesc::new();
        indirect_req.setup(alloc.clone(), test_state.clone(), 2);
        indirect_req.add_desc(test_state.clone(), req_addr + 8, 520, false);
        indirect_req.add_desc(test_state.clone(), req_addr + REQ_STATUS_OFFSET, 1, true);
        vqs[0]
            .borrow_mut()
            .add_indirect(test_state.clone(), indirect_req, true);
    }
    blk.borrow().virtqueue_notify(vqs[0].clone());
    blk.borrow().poll_used_elem(
        test_state.clone(),
        vqs[0].clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );
    let status = test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET);
    assert_eq!(status, VIRTIO_BLK_S_OK);

    let blk_req = TestVirtBlkReq::new(VIRTIO_BLK_T_IN, 1, 0, REQ_DATA_LEN as usize);
    let req_addr = virtio_request(test_state.clone(), alloc.clone(), blk_req);
    free_head = vqs[0]
        .borrow_mut()
        .add(test_state.clone(), req_addr, 8, false);
    let offset = free_head as u64 * VRING_DESC_SIZE + offset_of!(VringDesc, flags) as u64;
    test_state
        .borrow()
        .writew(vqs[0].borrow().desc + offset as u64, VRING_DESC_F_NEXT);
    test_state.borrow().writew(
        vqs[0].borrow().desc + offset as u64 + 2,
        free_head as u16 + 1,
    );
    let mut indirect_req = TestVringIndirectDesc::new();
    indirect_req.setup(alloc.clone(), test_state.clone(), 2);
    indirect_req.add_desc(test_state.clone(), req_addr + 8, 8, false);
    indirect_req.add_desc(
        test_state.clone(),
        req_addr + REQ_ADDR_LEN as u64,
        513,
        true,
    );
    vqs[0]
        .borrow_mut()
        .add_indirect(test_state.clone(), indirect_req, true);
    blk.borrow()
        .kick_virtqueue(test_state.clone(), vqs[0].clone());
    blk.borrow().poll_used_elem(
        test_state.clone(),
        vqs[0].clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );

    let status = test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET);
    assert_eq!(status, VIRTIO_BLK_S_OK);

    assert_eq!(
        String::from_utf8(
            test_state
                .borrow()
                .memread(req_addr + REQ_ADDR_LEN as u64, 4)
        )
        .unwrap(),
        "TEST"
    );

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Driver just enable VIRTIO_F_VERSION_1|VIRTIO_RING_F_EVENT_IDX feature,
/// and succeed to do the I/O request.
/// TestStep:
///   1. Init device with VIRTIO_F_VERSION_1|VIRTIO_RING_F_EVENT_IDX feature.
///   2. Do the I/O request:
///     1) create 5 request, and modify avail->used_event to 5.
///     2) If the event idx works, we will not get the interrupt from device.
///     3) create 5 request, and use the right avail->used_event.
///     4) we will get the interrupt from device.
///     5) read the sector 10 to check the write content, which is same as write.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtio_feature_event_idx() {
    do_event_idx_with_flag(0);
}

/// Driver just enable these featues:
///     VIRTIO_F_VERSION_1 | VIRTIO_RING_F_INDIRECT_DESC | VIRTIO_RING_F_EVENT_IDX
/// and succeed to do the I/O request(normal + indirect) which has opened the event idx.
/// TestStep:
///   1. Init device.
///   2. Do the I/O request(indirect and  indirect + normal).
///     1) create 5 request(with indirect), and modify avail->used_event to 5.
///     2) If the event idx works, we will not get the interrupt from device.
///     3) create 5 request, and use the right avail->used_event.
///     4) we will get the interrupt from device.
///     5) read the sector 10 to check the write content, which is same as write.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtio_feature_indirect_and_event_idx() {
    let (blk, test_state, alloc, image_path) = set_up();

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1 | 1 << VIRTIO_RING_F_INDIRECT_DESC | 1 << VIRTIO_RING_F_EVENT_IDX,
        1,
    );

    send_one_request(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
    );

    // Test write.
    let mut blk_req = TestVirtBlkReq::new(VIRTIO_BLK_T_OUT, 1, 0, REQ_DATA_LEN as usize);
    blk_req.data.push_str("TEST");
    let req_addr = virtio_request(test_state.clone(), alloc.clone(), blk_req);
    let free_head = vqs[0]
        .borrow_mut()
        .add(test_state.clone(), req_addr, REQ_ADDR_LEN, false);
    let offset = free_head as u64 * VRING_DESC_SIZE + offset_of!(VringDesc, flags) as u64;
    test_state
        .borrow()
        .writew(vqs[0].borrow().desc + offset as u64, VRING_DESC_F_NEXT);
    test_state.borrow().writew(
        vqs[0].borrow().desc + offset as u64 + 2,
        free_head as u16 + 1,
    );
    // 2 desc elems in indirect desc table.
    let mut indirect_req = TestVringIndirectDesc::new();
    indirect_req.setup(alloc.clone(), test_state.clone(), 2);
    indirect_req.add_desc(
        test_state.clone(),
        req_addr + REQ_ADDR_LEN as u64,
        REQ_DATA_LEN,
        false,
    );
    indirect_req.add_desc(test_state.clone(), req_addr + REQ_STATUS_OFFSET, 1, true);
    vqs[0]
        .borrow_mut()
        .add_indirect(test_state.clone(), indirect_req, true);

    let mut req_addr = 0_u64;
    for i in 2..DEFAULT_IO_REQS {
        (_, req_addr) = add_request(
            test_state.clone(),
            alloc.clone(),
            vqs[0].clone(),
            VIRTIO_BLK_T_OUT,
            i,
        );
    }

    // Set avail->used_event to DEFAULT_IO_REQS which the rigth value is DEFAULT_IO_REQS - 1,
    // it will not get the interrupt which means event index feature works.
    vqs[0]
        .borrow()
        .set_used_event(test_state.clone(), DEFAULT_IO_REQS as u16);
    blk.borrow().virtqueue_notify(vqs[0].clone());
    check_req_result(
        blk.clone(),
        test_state.clone(),
        vqs[0].clone(),
        req_addr + REQ_STATUS_OFFSET,
        TIMEOUT_US,
    );
    assert_eq!(
        vqs[0].borrow().get_avail_event(test_state.clone()),
        DEFAULT_IO_REQS as u16
    );

    // Create two write requests, the avail->used_event will be the update to the right value.
    // It will get the interrupt from device.
    let mut free_head = 0_u32;
    for i in DEFAULT_IO_REQS..DEFAULT_IO_REQS * 2 {
        (free_head, _) = add_request(
            test_state.clone(),
            alloc.clone(),
            vqs[0].clone(),
            VIRTIO_BLK_T_OUT,
            i,
        );
    }

    blk.borrow().virtqueue_notify(vqs[0].clone());
    blk.borrow().poll_used_elem(
        test_state.clone(),
        vqs[0].clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );

    // Read the content in sector DEFAULT_IO_REQS * 2 - 1.
    virtio_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        DEFAULT_IO_REQS * 2 - 1,
    );

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Setting abnormal status in device initialization.
/// TestStep:
///   1. Init device.
///     1) set device status: special status and random status.
///     2) ACKNOWLEDGE -> DRIVER -> DRIVER -> negotiate_features -> FEATURES_OK
///        -> setup_virtqueue -> DRIVER_OK.
///   2. Do the I/O request.
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   1/2: success or failure.
///   3/4: success.
#[test]
fn virtio_init_device_abnormal_status() {
    let (blk, test_state, alloc, image_path) = set_up();

    // Test some special status.
    let status = [31, 0, 2, 16, 31, 0, 1, 16, 31, 0, 7, 16, 31, 64, 128];
    for i in 0..status.len() {
        blk.borrow().set_status(status[i]);
        if i % 4 == 0 {
            blk.borrow_mut().negotiate_features(1 << VIRTIO_F_VERSION_1);
        }
        if i % 7 == 0 {
            blk.borrow_mut().pci_dev.enable_msix(None);
            blk.borrow_mut()
                .setup_msix_configuration_vector(alloc.clone(), 0);
            blk.borrow_mut()
                .init_virtqueue(test_state.clone(), alloc.clone(), 1);
        }
    }

    // Test 16 times of random status in [0, 0xff).
    let mut rng = rand::thread_rng();
    for i in 0..16 {
        blk.borrow().set_status(rng.gen_range(0..0xff));
        if i % 4 == 0 {
            blk.borrow_mut().negotiate_features(1 << VIRTIO_F_VERSION_1);
        }
        if i % 7 == 0 {
            blk.borrow_mut().pci_dev.enable_msix(None);
            blk.borrow_mut()
                .setup_msix_configuration_vector(alloc.clone(), 0);
            blk.borrow_mut()
                .init_virtqueue(test_state.clone(), alloc.clone(), 1);
        }
    }

    blk.borrow_mut().set_acknowledge();
    blk.borrow_mut().set_driver();
    blk.borrow_mut().negotiate_features(1 << VIRTIO_F_VERSION_1);
    blk.borrow_mut().set_features_ok();
    blk.borrow_mut().pci_dev.enable_msix(None);
    blk.borrow_mut()
        .setup_msix_configuration_vector(alloc.clone(), 0);
    let vqs = blk
        .borrow_mut()
        .init_virtqueue(test_state.clone(), alloc.clone(), 1);
    blk.borrow_mut().set_driver_ok();

    // 2. Do the I/O request.
    for i in 0..DEFAULT_IO_REQS {
        add_request(
            test_state.clone(),
            alloc.clone(),
            vqs[0].clone(),
            VIRTIO_BLK_T_OUT,
            i,
        );
    }
    blk.borrow().virtqueue_notify(vqs[0].clone());

    // 3. Send qmp to StratoVirt.
    check_stratovirt_status(test_state.clone());

    // 4. Destroy device.
    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Setting abnormal feature in device initialization.
/// TestStep:
///   1. Init device.
///     negotiate unsupport features:
///       1) 1 << 63;
///       2) 1 << 63 | 1 << VIRTIO_F_VERSION_1;
///   2. Do the I/O request.
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   1/2: success or failure.
///   3/4: success.
#[test]
fn virtio_init_device_abnormal_features() {
    for i in 0..2 {
        let (blk, test_state, alloc, image_path) = set_up();

        // 1. Init device.
        blk.borrow_mut().reset();
        blk.borrow_mut().set_acknowledge();
        blk.borrow_mut().set_driver();
        // Set unsupported feature 1 << 63 or (1 << 63 | 1 << VIRTIO_F_VERSION_1).
        let mut features = 1 << 63;
        if i == 0 {
            features |= 1 << VIRTIO_F_VERSION_1;
        }
        blk.borrow_mut().negotiate_features(features);
        blk.borrow_mut().set_features_ok();
        blk.borrow_mut().pci_dev.enable_msix(None);
        blk.borrow_mut()
            .setup_msix_configuration_vector(alloc.clone(), 0);
        let vqs = blk
            .borrow_mut()
            .init_virtqueue(test_state.clone(), alloc.clone(), 1);
        blk.borrow_mut().set_driver_ok();

        // 2. Do the I/O request.
        if i == 0 {
            virtio_write(
                blk.clone(),
                test_state.clone(),
                alloc.clone(),
                vqs[0].clone(),
                0,
            );
            virtio_read(
                blk.clone(),
                test_state.clone(),
                alloc.clone(),
                vqs[0].clone(),
                0,
            );
        } else {
            for i in 0..DEFAULT_IO_REQS {
                add_request(
                    test_state.clone(),
                    alloc.clone(),
                    vqs[0].clone(),
                    VIRTIO_BLK_T_OUT,
                    i,
                );
            }
            blk.borrow().virtqueue_notify(vqs[0].clone());
        }

        // 3. Send qmp to StratoVirt.
        check_stratovirt_status(test_state.clone());

        // 4. Destroy device.
        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs,
            image_path.clone(),
        );
    }
}

/// Setting abnormal vring info in device initialization.
/// TestStep:
///   1. Init device with abnormal steps:
///    1) use invalid value to select queue(not enable multi-queue):
///     2, u16::MAX
///    2) set invalid queue size:
///     0, 255, 1<<15, u16::MAX
///    3) set address overlap in desc/avail/used;
///    4) set not aligned desc/avail/used address;
///    5) set invalid desc/avail/used address:
///     0, 1 << 48, u64::MAX
///    6) set 0 to enable vq;
///    7) check if the writed queue info is right.
///   2. Do the I/O request.
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   1/2: success or failure.
///   3/4: success.
#[test]
fn virtio_init_device_abnormal_vring_info() {
    // (err_type, value, ack, device_status)
    let reqs = [
        (0, u16::MAX as u64, 0, 0),
        (0, 2, 0, 0),
        (1, 0_u64, 0xff, 0),
        (1, 255, 0xff, 0),
        (1, 1 << 15, 0xff, 0),
        (1, u16::MAX as u64, 0xff, 0),
        (2, 0, 0xff, 0),
        (3, 0, 0xff, 0),
        (4, 0, 0xff, 0),
        (5, 0, 0xff, 0),
        (6, 0, 0xff, 0),
        (6, 1 << 48, 0xff, 0),
        (6, u64::MAX, 0xff, 0),
        (7, 0, 0xff, 0),
        (7, 1 << 48, 0xff, 0),
        (7, u64::MAX, 0xff, 0),
        (8, 0, 0xff, 0),
        (8, 1 << 48, 0xff, 0),
        (8, u64::MAX, 0xff, 0),
        (9, 0, 0xff, 0),
        (10, 1, 0, 0),
    ];

    for (err_type, value, ack, device_status) in reqs {
        let (blk, test_state, alloc, image_path) = set_up();

        // 1. Init device.
        blk.borrow_mut().reset();
        assert_eq!(blk.borrow().get_generation(), 0);
        blk.borrow_mut().set_acknowledge();
        blk.borrow_mut().set_driver();
        blk.borrow_mut().negotiate_features(1 << VIRTIO_F_VERSION_1);
        blk.borrow_mut().set_features_ok();
        blk.borrow_mut().pci_dev.enable_msix(None);
        blk.borrow_mut()
            .setup_msix_configuration_vector(alloc.clone(), 0);

        let mut vqs = Vec::new();
        let vq = Rc::new(RefCell::new(TestVirtQueue::new()));
        let features = blk.borrow().get_guest_features();
        // Set invalid value to select queue.
        if err_type == 0 {
            let q_select = blk.borrow().get_queue_select();
            assert_ne!(q_select, value as u16);
            blk.borrow().queue_select(value as u16);
        }

        let queue_size = blk.borrow().get_queue_size() as u32;

        // Set invalid queue size.
        if err_type == 1 {
            blk.borrow().set_queue_size(value as u16);
            assert_eq!(blk.borrow().get_queue_size(), value as u16);
        }

        vq.borrow_mut().index = 0;
        vq.borrow_mut().size = queue_size;
        vq.borrow_mut().free_head = 0;
        vq.borrow_mut().num_free = queue_size;
        vq.borrow_mut().align = VIRTIO_PCI_VRING_ALIGN;
        vq.borrow_mut().indirect = (features & (1 << VIRTIO_RING_F_INDIRECT_DESC)) != 0;
        vq.borrow_mut().event = (features & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;

        let addr = alloc
            .borrow_mut()
            .alloc(get_vring_size(queue_size, VIRTIO_PCI_VRING_ALIGN) as u64);

        vq.borrow_mut().desc = addr;
        let avail = addr + (queue_size * size_of::<VringDesc>() as u32) as u64 + 16;
        vq.borrow_mut().avail = avail;
        let used = (avail
            + (size_of::<u16>() as u32 * (3 + queue_size)) as u64
            + VIRTIO_PCI_VRING_ALIGN as u64
            - 1)
            & !(VIRTIO_PCI_VRING_ALIGN as u64 - 1) + 16;
        vq.borrow_mut().used = used + 16;

        match err_type {
            2 => {
                // Test desc and avail address overlap.
                vq.borrow_mut().desc = addr + 16 + 1;
            }
            3 => {
                // TEST desc not aligned
                vq.borrow_mut().desc = addr + 1;
            }
            4 => {
                // TEST avail not aligned.
                vq.borrow_mut().avail = avail + 1;
            }
            5 => {
                // TEST used not aligned.
                vq.borrow_mut().used = used + 1;
            }
            6 => {
                // TEST invalid desc address.
                if value != u64::MAX {
                    vq.borrow_mut().desc = value;
                }
            }
            7 => {
                // TEST invalie avail address.
                if value != u64::MAX {
                    vq.borrow_mut().avail = value;
                }
            }
            8 => {
                // TEST invalie used address.
                if value != u64::MAX {
                    vq.borrow_mut().used = value;
                }
            }
            _ => (),
        }

        let mut desc = vq.borrow().desc;
        let mut avail = vq.borrow().avail;
        let mut used = vq.borrow().used;
        if queue_size > 0 {
            vq.borrow().vring_init(test_state.clone());
        }
        // TEST invalid desc address.
        if err_type == 6 && value == u64::MAX {
            desc = value;
        }
        // TEST invalid avail address.
        if err_type == 7 && value == u64::MAX {
            avail = value;
        }
        // TEST invalid used address.
        if err_type == 8 && value == u64::MAX {
            used = value;
        }
        blk.borrow().activate_queue(desc, avail, used);
        // TEST if the writed queue info is right.
        if err_type == 10 {
            check_queue(blk.clone(), desc, avail, used);
        }

        let notify_off = blk.borrow().pci_dev.io_readw(
            blk.borrow().bar,
            blk.borrow().common_base as u64
                + offset_of!(VirtioPciCommonCfg, queue_notify_off) as u64,
        );
        vq.borrow_mut().queue_notify_off = blk.borrow().notify_base as u64
            + notify_off as u64 * blk.borrow().notify_off_multiplier as u64;

        let offset = offset_of!(VirtioPciCommonCfg, queue_enable) as u64;
        // TEST enable vq with 0
        if err_type == 9 {
            blk.borrow().pci_dev.io_writew(
                blk.borrow().bar,
                blk.borrow().common_base as u64 + offset,
                0,
            );
        } else {
            blk.borrow().pci_dev.io_writew(
                blk.borrow().bar,
                blk.borrow().common_base as u64
                    + offset_of!(VirtioPciCommonCfg, queue_enable) as u64,
                1,
            );
            if err_type == 10 {
                let status = blk
                    .borrow()
                    .pci_dev
                    .io_readw(blk.borrow().bar, blk.borrow().common_base as u64 + offset);
                assert_eq!(status, 1);
            }
        }

        blk.borrow()
            .setup_virtqueue_intr(1, alloc.clone(), vq.clone());
        vqs.push(vq);

        blk.clone().borrow_mut().set_driver_ok();

        // 2. Do the I/O request.
        let mut req_addr: u64 = 0;
        if queue_size > 0 {
            (_, req_addr) = add_request(
                test_state.clone(),
                alloc.clone(),
                vqs[0].clone(),
                VIRTIO_BLK_T_OUT,
                0,
            );
        }
        blk.borrow().virtqueue_notify(vqs[0].clone());
        assert_eq!(test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET), ack);
        assert_eq!(
            blk.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET,
            device_status
        );

        // 3. Send qmp to StratoVirt.
        check_stratovirt_status(test_state.clone());

        // ecover the addr for free.
        vqs[0].borrow_mut().desc = addr;

        // 4. Destroy device.
        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs,
            image_path.clone(),
        );
    }
}

/// Init device out of order test 1.
/// TestStep:
///   1. Abnormal init device.
///		1.1->1.3->1.2->1.4->1.5->1.6->1.7->1.8
///		1.1->1.2->1.4->1.3->1.5->1.6->1.7->1.8
///		1.1->1.2->1.3->1.5->1.4->1.6->1.7->1.8
///		1.1->1.2->1.3->1.4->1.6->1.5->1.7->1.8
///		1.1->1.2->1.3->1.4->1.7->1.6->1.5->1.8
///	  2. Noraml init device.
///	  3. Write and read.
///   4. Destroy device.
/// Expect:
///   1/2: success or failed, stratovirt process status is normal.
///   3/4: success.
#[test]
fn virtio_init_device_out_of_order_1() {
    let (blk, test_state, alloc, image_path) = set_up();

    let tests = vec![
        [1, 3, 2, 4, 5, 6, 7, 8],
        [1, 2, 4, 3, 5, 6, 7, 8],
        [1, 2, 3, 5, 4, 6, 7, 8],
        [1, 2, 3, 4, 6, 5, 7, 8],
        [1, 2, 3, 4, 7, 6, 5, 8],
    ];

    init_device_step(blk.clone(), test_state.clone(), alloc.clone(), tests);

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    virtio_write(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );
    virtio_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Init device out of order test 2.
/// TestStep:
///   1. Abnormal init device.
///		1.1->1.2->1.3->1.4->1.8->1.6->1.7->1.5
///		1.1->1.3->1.4->1.5->1.6->1.7->1.8
///		1.1->1.2->1.4->1.5->1.6->1.7->1.8
///		1.1->1.2->1.3->1.4->1.6->1.7->1.8
///		1.1->1.2->1.3->1.4->1.5->1.6->1.8
///	  2. Noraml init device.
///	  3. Write and read.
///   4. Destroy device.
/// Expect:
///   1/2: success or failed, stratovirt process status is normal.
///   3/4: success.
#[test]
fn virtio_init_device_out_of_order_2() {
    let (blk, test_state, alloc, image_path) = set_up();

    let tests = vec![
        [1, 2, 3, 4, 8, 6, 7, 5],
        [1, 3, 4, 5, 6, 7, 8, 0],
        [1, 2, 4, 5, 6, 7, 8, 0],
        [1, 2, 3, 4, 6, 7, 8, 0],
        [1, 2, 3, 4, 5, 6, 8, 0],
    ];

    init_device_step(blk.clone(), test_state.clone(), alloc.clone(), tests);

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    virtio_write(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );
    virtio_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Init device out of order test 3.
/// TestStep:
///   1. Abnormal init device.
///		1.1->1.2->1.3->1.4->1.5->1.6->1.7
///		1.1->1.2->1.3->1.4->1.9
///		1.1->1.2->1.3->1.5->1.8
///		1.1->1.2->1.3->1.4->1.9(FAILED)->normal init process
///		1.1->1.2->1.3->1.4->1.9(FAILED)->1.2->1.3->1.4->1.5->1.6->1.7->1.8
///	  2. Noraml init device.
///	  3. Write and read.
///   4. Destroy device.
/// Expect:
///   1/2: success or failed, stratovirt process status is normal.
///   3/4: success.
#[test]
fn virtio_init_device_out_of_order_3() {
    let (blk, test_state, alloc, image_path) = set_up();

    let tests = vec![
        [1, 2, 3, 4, 5, 6, 7, 0],
        [1, 2, 3, 4, 9, 0, 0, 0],
        [1, 2, 3, 5, 8, 0, 0, 0],
        [1, 2, 3, 4, 9, 0, 0, 0],
        [1, 2, 3, 4, 5, 6, 7, 8],
        [1, 2, 3, 4, 9, 0, 0, 0],
        [2, 3, 4, 5, 6, 7, 8, 0],
    ];

    init_device_step(blk.clone(), test_state.clone(), alloc.clone(), tests);

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    virtio_write(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );
    virtio_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Repeat the initialization operation.
/// TestStep:
///   1. Init device.
///     reset -> reset -> ACKNOWLEDGE -> ACKNOWLEDGE -> DRIVER -> DRIVER ->
///     negotiate_features -> FEATURES_OK -> FEATURES_OK -> setup_virtqueue ->
///     DRIVER_OK.
///   2. Do the I/O request.
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   1/2: success or failed, stratovirt process status is normal.
///   3/4: success.
#[test]
fn virtio_init_device_repeat() {
    let (blk, test_state, alloc, image_path) = set_up();

    // Reset virtio device twice.
    blk.borrow_mut().reset();
    blk.borrow_mut().reset();
    // Set ACKNOWLEDGE twice.
    blk.borrow_mut().set_acknowledge();
    blk.borrow_mut().set_acknowledge();
    // Set DRIVER twice.
    blk.borrow_mut().set_driver();
    blk.borrow_mut().set_driver();

    let features = blk.borrow().get_device_features()
        | 1 << VIRTIO_RING_F_INDIRECT_DESC
        | 1 << VIRTIO_RING_F_EVENT_IDX;
    blk.borrow_mut().negotiate_features(features);
    // Set FEATURES_OK twice.
    blk.borrow_mut().set_features_ok();
    blk.borrow_mut().set_features_ok();

    let capability = blk.borrow().config_readq(0);
    assert_eq!(capability, TEST_IMAGE_SIZE / 512);

    blk.borrow_mut().pci_dev.enable_msix(None);
    blk.borrow_mut()
        .setup_msix_configuration_vector(alloc.clone(), 0);

    let vqs = blk
        .borrow_mut()
        .init_virtqueue(test_state.clone(), alloc.clone(), 1);
    blk.borrow_mut().set_driver_ok();

    virtio_write(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );
    virtio_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Setting abnormal desc addr in IO request.
/// TestStep:
///   1. Init device.
///   2. Do the I/O request with abnormal desc[i]->addr:
///     0, address unaligned, 0x5000, u64::MAX
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   2: success or failure.
///   1/3/4: success.
#[test]
fn virtio_io_abnormal_desc_addr() {
    // (addr, ack, device_status)
    let reqs = [
        (0, 0xff, VIRTIO_CONFIG_S_NEEDS_RESET),
        (1, 0x2, 0),
        (0x5000, 0xff, VIRTIO_CONFIG_S_NEEDS_RESET),
        (u64::MAX, 0xff, VIRTIO_CONFIG_S_NEEDS_RESET),
    ];
    for (mut addr, ack, device_status) in reqs {
        let (blk, test_state, alloc, image_path) = set_up();

        let vqs = blk.borrow_mut().init_device(
            test_state.clone(),
            alloc.clone(),
            1 << VIRTIO_F_VERSION_1,
            1,
        );

        let (_, req_addr) = add_request(
            test_state.clone(),
            alloc.clone(),
            vqs[0].clone(),
            VIRTIO_BLK_T_OUT,
            0,
        );
        if addr == 1 {
            addr += req_addr;
        }
        test_state.borrow().writeq(vqs[0].borrow().desc, addr);
        blk.borrow().virtqueue_notify(vqs[0].clone());

        assert_eq!(test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET), ack);
        assert_eq!(
            blk.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET,
            device_status
        );

        check_stratovirt_status(test_state.clone());

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs,
            image_path.clone(),
        );
    }
}

/// Setting abnormal desc length in IO request.
/// TestStep:
///   1. Init device.
///   2. Do the I/O request with abnormal desc[i]->len:
///     1) 0 with 1 request 3 desc elems;
///     2) 0x5000 with 1 request 3 desc elems;
///     3) u32::MAX with 1 request 3 desc elems;
///     4) total length of all desc is bigger than (1 << 32):
///         ((1 << 32) / 64) with indirect request which has 65 desc elems;
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   2: success or failure.
///   1/3/4: success.
#[test]
fn virtio_io_abnormal_desc_len() {
    // (length, num of IO, ack, device_status)
    let reqs = [
        (0, 1, 0xff, VIRTIO_CONFIG_S_NEEDS_RESET),
        (0x5000, 1, VIRTIO_BLK_S_IOERR, 0),
        (u32::MAX, 1, 0xff, VIRTIO_CONFIG_S_NEEDS_RESET),
        (1 << 26, 65, 0xff, VIRTIO_CONFIG_S_NEEDS_RESET),
    ];
    for (length, io_num, ack, device_status) in reqs {
        let (blk, test_state, alloc, image_path) = set_up();

        let vqs = blk.borrow_mut().init_device(
            test_state.clone(),
            alloc.clone(),
            1 << VIRTIO_F_VERSION_1,
            1,
        );

        let req_addr: u64;
        if io_num <= 1 {
            (_, req_addr) = add_request(
                test_state.clone(),
                alloc.clone(),
                vqs[0].clone(),
                VIRTIO_BLK_T_OUT,
                0,
            );
            test_state.borrow().writel(vqs[0].borrow().desc + 8, length);
        } else {
            let mut blk_req = TestVirtBlkReq::new(VIRTIO_BLK_T_OUT, 1, 0, REQ_DATA_LEN as usize);
            blk_req.data.push_str("TEST");
            req_addr = virtio_request(test_state.clone(), alloc.clone(), blk_req);
            let mut indirect_req = TestVringIndirectDesc::new();
            indirect_req.setup(alloc.clone(), test_state.clone(), io_num);
            for _ in 0..io_num {
                indirect_req.add_desc(test_state.clone(), req_addr, length, true);
            }
            let free_head =
                vqs[0]
                    .borrow_mut()
                    .add_indirect(test_state.clone(), indirect_req, true);
            vqs[0].borrow().update_avail(test_state.clone(), free_head);
        }
        blk.borrow().virtqueue_notify(vqs[0].clone());

        test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET);
        assert_eq!(test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET), ack);
        assert_eq!(
            blk.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET,
            device_status
        );

        check_stratovirt_status(test_state.clone());

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs,
            image_path.clone(),
        );
    }
}

/// Setting abnormal desc flag in IO request, testcase 1.
/// TestStep:
///   1. Init device, not negotiate INDIRECT_DESC feature.
///   2. Do the I/O request with abnormal desc[i]->flags:
///      1) add VRING_DESC_F_INDIRECT to flags
///      2) add invalid value 16 to flags
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   2: success or failure.
///   1/3/4: success.
#[test]
fn virtio_io_abnormal_desc_flags_1() {
    // (flag, ack, device_status)
    let reqs = [
        (VRING_DESC_F_INDIRECT, 0xff, VIRTIO_CONFIG_S_NEEDS_RESET),
        (16, 0, 0),
    ];
    for (flag, ack, device_status) in reqs {
        let (blk, test_state, alloc, image_path) = set_up();

        let vqs = blk.borrow_mut().init_device(
            test_state.clone(),
            alloc.clone(),
            1 << VIRTIO_F_VERSION_1,
            1,
        );

        let (_, req_addr) = add_request(
            test_state.clone(),
            alloc.clone(),
            vqs[0].clone(),
            VIRTIO_BLK_T_OUT,
            0,
        );

        // Add VRING_DESC_F_INDIRECT or 16 to desc[0]->flags;
        let flags = test_state.borrow().readw(vqs[0].borrow().desc + 12) | flag;
        test_state.borrow().writew(vqs[0].borrow().desc + 12, flags);
        blk.borrow().virtqueue_notify(vqs[0].clone());

        assert_eq!(test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET), ack);
        assert_eq!(
            blk.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET,
            device_status
        );
        check_stratovirt_status(test_state.clone());

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs,
            image_path.clone(),
        );
    }
}

/// Setting abnormal desc flag in IO request, testcase 2.
/// TestStep:
///   1. Init device, negotiate INDIRECT_DESC feature.
///   2. Do the I/O request with abnormal desc[i]->flags:
///      add VRING_DESC_F_INDIRECT to flags in indirect desc table.
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   2: success or failure.
///   1/3/4: success.
#[test]
fn virtio_io_abnormal_desc_flags_2() {
    let (blk, test_state, alloc, image_path) = set_up();

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1 | 1 << VIRTIO_RING_F_INDIRECT_DESC,
        1,
    );

    let mut blk_req = TestVirtBlkReq::new(VIRTIO_BLK_T_OUT, 1, 0, REQ_DATA_LEN as usize);
    blk_req.data.push_str("TEST");
    let req_addr = virtio_request(test_state.clone(), alloc.clone(), blk_req);
    let free_head = vqs[0]
        .borrow_mut()
        .add(test_state.clone(), req_addr, REQ_ADDR_LEN, false);
    let offset = free_head as u64 * VRING_DESC_SIZE + offset_of!(VringDesc, flags) as u64;
    test_state
        .borrow()
        .writew(vqs[0].borrow().desc + offset as u64, VRING_DESC_F_NEXT);
    test_state.borrow().writew(
        vqs[0].borrow().desc + offset as u64 + 2,
        free_head as u16 + 1,
    );
    let mut indirect_req = TestVringIndirectDesc::new();
    indirect_req.setup(alloc.clone(), test_state.clone(), 2);
    indirect_req.add_desc(
        test_state.clone(),
        req_addr + REQ_ADDR_LEN as u64,
        REQ_DATA_LEN,
        false,
    );
    indirect_req.add_desc(test_state.clone(), req_addr + REQ_STATUS_OFFSET, 1, true);
    indirect_req.set_desc_flag(test_state.clone(), 0, VRING_DESC_F_INDIRECT);
    vqs[0]
        .borrow_mut()
        .add_indirect(test_state.clone(), indirect_req, true);

    blk.borrow().virtqueue_notify(vqs[0].clone());

    assert_eq!(
        test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET),
        0xff
    );
    assert!(blk.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET > 0);
    check_stratovirt_status(test_state.clone());

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Setting abnormal desc flag in IO request, testcase 3.
/// TestStep:
///   1. Init device, negotiate INDIRECT_DESC feature.
///   2. Do the I/O request with abnormal desc[i]->flags:
///      add VRING_DESC_F_INDIRECT | VRING_DESC_F_WRITE to flags in indirect desc table,
///      and the device will ignore the VRING_DESC_F_WRITE flag.
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   2: success or failure.
///   1/3/4: success.
#[test]
fn virtio_io_abnormal_desc_flags_3() {
    // (flag, ack, device_status)
    let reqs = [
        (VRING_DESC_F_WRITE, 0, 0),
        (VRING_DESC_F_NEXT, 0xff, VIRTIO_CONFIG_S_NEEDS_RESET),
    ];
    for (flag, ack, device_status) in reqs {
        let (blk, test_state, alloc, image_path) = set_up();

        let vqs = blk.borrow_mut().init_device(
            test_state.clone(),
            alloc.clone(),
            1 << VIRTIO_F_VERSION_1 | 1 << VIRTIO_RING_F_INDIRECT_DESC,
            1,
        );

        let mut blk_req = TestVirtBlkReq::new(VIRTIO_BLK_T_OUT, 1, 0, REQ_DATA_LEN as usize);
        blk_req.data.push_str("TEST");
        let req_addr = virtio_request(test_state.clone(), alloc.clone(), blk_req);
        let free_head = vqs[0]
            .borrow_mut()
            .add(test_state.clone(), req_addr, 8, false);
        //vqs[0].borrow().set_desc_flag(free_head, VRING_DESC_F_NEXT);
        let offset = free_head as u64 * VRING_DESC_SIZE + offset_of!(VringDesc, flags) as u64;
        test_state
            .borrow()
            .writew(vqs[0].borrow().desc + offset as u64, VRING_DESC_F_NEXT);
        test_state.borrow().writew(
            vqs[0].borrow().desc + offset as u64 + 2,
            free_head as u16 + 1,
        );
        let mut indirect_req = TestVringIndirectDesc::new();
        indirect_req.setup(alloc.clone(), test_state.clone(), 2);
        indirect_req.add_desc(test_state.clone(), req_addr + 8, 520, false);
        indirect_req.add_desc(test_state.clone(), req_addr + REQ_STATUS_OFFSET, 1, true);
        vqs[0]
            .borrow_mut()
            .add_indirect(test_state.clone(), indirect_req, true);

        // Add VRING_DESC_F_WRITE or VRING_DESC_F_NEXT to desc[0]->flags;
        let addr = vqs[0].borrow().desc + 16_u64 * (free_head + 1) as u64 + 12;
        let flags = test_state.borrow().readw(addr) | flag;
        test_state.borrow().writew(addr, flags);
        blk.borrow().virtqueue_notify(vqs[0].clone());
        if flag == VRING_DESC_F_WRITE {
            blk.borrow().poll_used_elem(
                test_state.clone(),
                vqs[0].clone(),
                free_head,
                TIMEOUT_US,
                &mut None,
                true,
            );
        }
        assert_eq!(test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET), ack);
        assert_eq!(
            blk.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET,
            device_status
        );

        check_stratovirt_status(test_state.clone());

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs,
            image_path.clone(),
        );
    }
}

/// Setting abnormal desc next in IO request.
/// TestStep:
///   1. Init device.
///   2. Do the I/O request with abnormal desc[i]->next:
///     1) point to the wrong place in the queue_size;
///     2) create an circuit;
///     3) point to the place beyond the queue_size;
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   2: success or failure.
///   1/3/4: success.
#[test]
fn virtio_io_abnormal_desc_next() {
    // (next, ack, device_status)
    let reqs = [
        (0, 0xff, VIRTIO_CONFIG_S_NEEDS_RESET),
        (16, 0xff, VIRTIO_CONFIG_S_NEEDS_RESET),
        (u16::MAX, 0xff, VIRTIO_CONFIG_S_NEEDS_RESET),
    ];
    for (next, ack, device_status) in reqs {
        let (blk, test_state, alloc, image_path) = set_up();

        let vqs = blk.borrow_mut().init_device(
            test_state.clone(),
            alloc.clone(),
            1 << VIRTIO_F_VERSION_1,
            1,
        );

        // It will create a write request with 3 desc elems:
        //  desc[0]: addr, len, flags(NEXT), next(0)
        //  desc[1]: addr, len, flags(NEXT), next(1)
        //  desc[2]: addr, len, flags(WRITE), next
        let (_, req_addr) = add_request(
            test_state.clone(),
            alloc.clone(),
            vqs[0].clone(),
            VIRTIO_BLK_T_OUT,
            0,
        );

        assert_eq!(test_state.borrow().readw(vqs[0].borrow().desc + 14), 1);
        // desc[1]->next = next;
        test_state
            .borrow()
            .writew(vqs[0].borrow().desc + 16 + 14, next);
        blk.borrow().virtqueue_notify(vqs[0].clone());

        assert_eq!(test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET), ack);
        assert_eq!(
            blk.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET,
            device_status
        );

        check_stratovirt_status(test_state.clone());

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs,
            image_path.clone(),
        );
    }
}

/// Setting desc elems in abnormal place in IO request.
/// TestStep:
///   1. Init device.
///   2. Do the I/O request with writable desc elem before
///      readable desc elem.
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   2: success or failure.
///   1/3/4: success.
#[test]
fn virtio_io_abnormal_desc_elem_place() {
    let (blk, test_state, alloc, image_path) = set_up();

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    // It will create a read request with 3 desc elems:
    //  desc[0]: addr, len, flags(NEXT), next(0)
    //  desc[1]: addr, len, flags(NEXT|WRITE), next(1)
    //  desc[2]: addr, len, flags(WRITE), next
    let (_, req_addr) = add_request(
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        VIRTIO_BLK_T_IN,
        0,
    );

    // The address of desc[2]->flag.
    assert_eq!(VRING_DESC_SIZE, 16);
    let addr = vqs[0].borrow().desc + VRING_DESC_SIZE * 2 + 12;
    assert_eq!(test_state.borrow().readw(addr), VRING_DESC_F_WRITE);
    // desc[2]->flag = 0.
    test_state.borrow().writew(addr, 0);
    blk.borrow().virtqueue_notify(vqs[0].clone());

    assert_eq!(
        test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET),
        0xff
    );
    assert!(blk.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET > 0);

    check_stratovirt_status(test_state.clone());

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Setting (queue_size + 1) indirect desc elems in IO request.
/// TestStep:
///   1. Init device with INDIRECT feature.
///   2. Do the I/O request with (queue_size + 1) desc elems in
///      indirect desc table.
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   1/3/4: success.
///   2: success or failure.
#[test]
fn virtio_io_abnormal_indirect_desc_elem_num() {
    let (blk, test_state, alloc, image_path) = set_up();

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    let queue_size = vqs[0].borrow().size as usize;

    let mut blk_req = TestVirtBlkReq::new(VIRTIO_BLK_T_OUT, 1, 0, 2 * queue_size);
    blk_req.data.push_str("TEST");
    let req_addr = virtio_request(test_state.clone(), alloc.clone(), blk_req);
    let free_head = vqs[0]
        .borrow_mut()
        .add(test_state.clone(), req_addr, REQ_ADDR_LEN, false);
    let offset = free_head as u64 * VRING_DESC_SIZE + offset_of!(VringDesc, flags) as u64;
    test_state
        .borrow()
        .writew(vqs[0].borrow().desc + offset as u64, VRING_DESC_F_NEXT);
    test_state.borrow().writew(
        vqs[0].borrow().desc + offset as u64 + 2,
        free_head as u16 + 1,
    );
    let mut indirect_req = TestVringIndirectDesc::new();
    indirect_req.setup(alloc.clone(), test_state.clone(), queue_size as u16 + 1);
    for i in 0..queue_size {
        indirect_req.add_desc(test_state.clone(), req_addr + 16 + 2 * i as u64, 2, false);
    }
    indirect_req.add_desc(
        test_state.clone(),
        req_addr + 16 * 2 * queue_size as u64,
        1,
        true,
    );
    vqs[0]
        .borrow_mut()
        .add_indirect(test_state.clone(), indirect_req, true);
    blk.borrow().virtqueue_notify(vqs[0].clone());

    assert_eq!(
        test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET),
        0xff
    );
    blk.borrow().poll_used_elem(
        test_state.clone(),
        vqs[0].clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );

    check_stratovirt_status(test_state.clone());

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Setting invalid flags to avail->flag in IO request.
/// TestStep:
///   1. Init device with EVENT_IDX feature.
///   2. Do the I/O request with avail->flags:
///     1) invalid value: 2;
///     2) VRING_AVAIL_F_NO_INTERRUPT with EVENT_IDX feature;
///     3) VRING_AVAIL_F_NO_INTERRUPT | 2 with EVENT_IDX feature;
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtio_io_abnormal_avail_flags() {
    let flags = [
        VRING_AVAIL_F_NO_INTERRUPT,
        2,
        VRING_AVAIL_F_NO_INTERRUPT | 2,
    ];
    for flag in flags {
        do_event_idx_with_flag(flag);
    }
}

/// Setting invalid idx to avail->idx in IO request.
/// TestStep:
///   1. Init device.
///   2. Do the I/O request with avail->idx:
///     1) assign 16 to avail->idx, but do not add req to desc;
///     2) assign u16::MAX to avail->idx, which is bigger than queue size;
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   2: success or failure.
///   1/3/4: success.
#[test]
fn virtio_io_abnormal_avail_idx() {
    let idxs = [16, u16::MAX];
    for idx in idxs {
        let (blk, test_state, alloc, image_path) = set_up();

        let vqs = blk.borrow_mut().init_device(
            test_state.clone(),
            alloc.clone(),
            1 << VIRTIO_F_VERSION_1,
            1,
        );

        for i in 1..DEFAULT_IO_REQS {
            add_request(
                test_state.clone(),
                alloc.clone(),
                vqs[0].clone(),
                VIRTIO_BLK_T_OUT,
                i,
            );
        }

        // Set flag to avail->idx.
        test_state.borrow().writew(vqs[0].borrow().avail + 2, idx);
        blk.borrow().virtqueue_notify(vqs[0].clone());

        check_stratovirt_status(test_state.clone());

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs,
            image_path.clone(),
        );
    }
}

/// Setting invalid desc_idx to avail->ring[i] in IO request.
/// TestStep:
///   1. Init device.
///   2. Do the I/O request with avail->ring[i]:
///     1) assign u16::MAX to avail->ring[i], which is bigger than queue size;
///     2) avail->ring[i..j] point to the same desc index;
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   2: success or failure.
///   1/3/4: success.
#[test]
fn virtio_io_abnormal_avail_ring() {
    // (ring[i], ack, device_status)
    let reqs = [(u16::MAX, 0xff, VIRTIO_CONFIG_S_NEEDS_RESET), (0, 0xff, 0)];
    for (value, ack, device_status) in reqs {
        let (blk, test_state, alloc, image_path) = set_up();

        let vqs = blk.borrow_mut().init_device(
            test_state.clone(),
            alloc.clone(),
            1 << VIRTIO_F_VERSION_1,
            1,
        );

        let mut req_addr = 0_u64;
        for i in 0..DEFAULT_IO_REQS {
            (_, req_addr) = add_request(
                test_state.clone(),
                alloc.clone(),
                vqs[0].clone(),
                VIRTIO_BLK_T_OUT,
                i,
            );
        }

        // Set value to avail->ring[DEFAULT_IO_REQS - 1].
        test_state
            .borrow()
            .writew(vqs[0].borrow().avail + 4 + 2 * (DEFAULT_IO_REQS - 1), value);
        blk.borrow().virtqueue_notify(vqs[0].clone());

        assert_eq!(test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET), ack);
        assert_eq!(
            blk.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET,
            device_status
        );

        check_stratovirt_status(test_state.clone());

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs,
            image_path.clone(),
        );
    }
}

/// Setting invalid value to avail->used_event in IO request.
/// TestStep:
///   1. Init device with or with not EVENT_IDX feature.
///   2. Do the I/O request with avail->used_event:
///     1) without EVENT_IDX, set valud to used_event.
///     2) with EVENT_IDX, set u16::MAX to used_event.
///     3) with EVENT_IDX, do not modify used_event.
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   2: success or failure.
///   1/3/4: success.
#[test]
fn virtio_io_abnormal_used_event() {
    // (feature, used_event, ack, device_status)
    let reqs = [
        (VIRTIO_F_VERSION_1, DEFAULT_IO_REQS as u16 - 1, 0, 0),
        (VIRTIO_RING_F_EVENT_IDX, u16::MAX, 0, 0),
        (VIRTIO_RING_F_EVENT_IDX, 0, 0, 0),
    ];
    for (feature, used_event, ack, device_status) in reqs {
        let (blk, test_state, alloc, image_path) = set_up();

        let vqs = blk.borrow_mut().init_device(
            test_state.clone(),
            alloc.clone(),
            1 << VIRTIO_F_VERSION_1 | 1 << feature,
            1,
        );

        send_one_request(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs[0].clone(),
        );

        let mut free_head = 0_u32;
        let mut req_addr = 0_u64;
        for i in 1..DEFAULT_IO_REQS {
            (free_head, req_addr) = add_request(
                test_state.clone(),
                alloc.clone(),
                vqs[0].clone(),
                VIRTIO_BLK_T_OUT,
                i,
            );
        }

        // Set used_event to avail->used_event.
        vqs[0]
            .borrow()
            .set_used_event(test_state.clone(), used_event);
        blk.borrow().virtqueue_notify(vqs[0].clone());

        if feature == VIRTIO_RING_F_EVENT_IDX {
            check_req_result(
                blk.clone(),
                test_state.clone(),
                vqs[0].clone(),
                req_addr + REQ_STATUS_OFFSET,
                TIMEOUT_US,
            );
        } else {
            blk.borrow().poll_used_elem(
                test_state.clone(),
                vqs[0].clone(),
                free_head,
                TIMEOUT_US,
                &mut None,
                true,
            );
        }

        assert_eq!(test_state.borrow().readb(req_addr + REQ_STATUS_OFFSET), ack);
        assert_eq!(
            blk.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET,
            device_status
        );

        check_stratovirt_status(test_state.clone());

        tear_down(
            blk.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs,
            image_path.clone(),
        );
    }
}

/// Setting invalid value to used->idx in IO request.
/// TestStep:
///   1. Init device;
///   2. Do the I/O request with avail->used_event = u16::MAX;
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtio_io_abnormal_used_idx() {
    let (blk, test_state, alloc, image_path) = set_up();

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    let mut free_head = 0_u32;
    for i in 0..DEFAULT_IO_REQS {
        (free_head, _) = add_request(
            test_state.clone(),
            alloc.clone(),
            vqs[0].clone(),
            VIRTIO_BLK_T_OUT,
            i,
        );
    }

    // Set u16::MAX to used->idx.
    test_state
        .borrow()
        .writew(vqs[0].borrow().used + 2, u16::MAX);
    blk.borrow().virtqueue_notify(vqs[0].clone());
    blk.borrow().poll_used_elem(
        test_state.clone(),
        vqs[0].clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Virtio test step out of order, testcase 1.
/// TestStep:
///   1. Init device.
///   2. Do the I/O request(normal io in desc).
///   3. Init device.
///   4. Do the I/O request(normal io in desc).
///   5. Send qmp to StratoVirt.
///   6. Destroy device.
/// Expect:
///   1/2/5/6: success.
///   3/4: success or failure.
#[test]
fn virtio_test_out_of_order_1() {
    let (blk, test_state, alloc, image_path) = set_up();

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    virtio_write(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );
    virtio_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    virtio_write(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );
    virtio_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );

    check_stratovirt_status(test_state.clone());

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Virtio test step out of order, testcase 2.
/// TestStep:
///   1. Init device.
///   2. Destroy device.
///   3. Init device.
///   4. Do the I/O request(normal io in desc).
///   5. Destroy device.
/// Expect:
///   1/2/3/4/5: success.
#[test]
fn virtio_test_out_of_order_2() {
    let (blk, test_state, alloc, image_path) = set_up();
    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );

    let (blk, test_state, alloc, image_path) = set_up();
    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    virtio_write(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );
    virtio_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );

    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        image_path.clone(),
    );
}

/// Virtio test step repeat.
/// TestStep:
///   1. Init device.
///   2. Init device.
///   3. Do the I/O request(normal io in desc).
///   4. Do the I/O request(normal io in desc).
///   5. Send qmp to StratoVirt.
///   6. Destroy device.
///   7. Destroy device.
/// Expect:
///   1/2/3/4/5/6/7: success.
#[test]
fn virtio_test_repeat() {
    let (blk, test_state, alloc, image_path) = set_up();

    blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    virtio_write(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );
    virtio_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        0,
    );
    virtio_write(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        DEFAULT_IO_REQS,
    );
    virtio_read(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs[0].clone(),
        DEFAULT_IO_REQS * 2 - 1,
    );

    check_stratovirt_status(test_state.clone());

    blk.borrow_mut().destroy_device(alloc.clone(), vqs.clone());
    blk.borrow_mut().destroy_device(alloc.clone(), vqs.clone());
    tear_down(
        blk.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs.clone(),
        image_path.clone(),
    );
}
