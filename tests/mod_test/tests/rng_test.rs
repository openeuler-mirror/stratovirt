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

use mod_test::libdriver::malloc::GuestAllocator;
use mod_test::libdriver::virtio::{
    TestVirtQueue, TestVringDescEntry, VirtioDeviceOps, VIRTIO_F_VERSION_1,
};
use mod_test::libdriver::virtio_pci_modern::TestVirtioPciDev;
use mod_test::libdriver::virtio_rng::create_rng;
use mod_test::libtest::TestState;

use std::cell::RefCell;
use std::collections::HashSet;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

const TIMEOUT_US: u64 = 10 * 1000 * 1000;
const RANDOM_FILE: &str = "/dev/random";
const RNG_DATA_BYTES: u64 = 64;
const THRESHOLD: usize = 10;
const DEFAULT_RNG_REQS: u64 = 6;

fn get_random_file() -> String {
    let random_file: String = RANDOM_FILE.to_string();
    let path = Path::new(&random_file);
    if path.exists() && path.metadata().unwrap().file_type().is_char_device() {
        return random_file;
    }

    panic!("Failed to get random file.");
}

// Check if the distinct random numbers are greater than the THRESHOLD.
fn random_num_check(data: Vec<u8>) -> bool {
    let mut rand_set: HashSet<u8> = HashSet::new();

    for num in data.iter() {
        if *num != 0 {
            rand_set.insert(*num);

            if rand_set.len() > THRESHOLD {
                return true;
            }
        }
    }

    false
}

// Read RNG_DATA_BYTES bytes from virtio-rng device, and
// perform DEFAULT_RNG_REQS reqs.
fn virtio_rng_read_batch(
    rng: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    virtqueue: Rc<RefCell<TestVirtQueue>>,
    bytes: u64,
) -> Vec<u8> {
    let mut free_head = 0_u32;
    let mut req_addr = 0_u64;
    let mut len = Some(0);

    for _i in 0..DEFAULT_RNG_REQS {
        req_addr = alloc.borrow_mut().alloc(bytes);
        free_head = virtqueue
            .borrow_mut()
            .add(test_state.clone(), req_addr, bytes as u32, true);
    }

    rng.borrow()
        .kick_virtqueue(test_state.clone(), virtqueue.clone());
    rng.borrow().poll_used_elem(
        test_state.clone(),
        virtqueue.clone(),
        free_head,
        TIMEOUT_US,
        &mut len,
        true,
    );

    assert!(len.unwrap() >= 1);
    assert!(len.unwrap() as u64 <= bytes);

    test_state.borrow().memread(req_addr, RNG_DATA_BYTES)
}

// Read RNG_DATA_BYTES*DEFAULT_RNG_REQS bytes from virtio-rng device.
fn virtio_rng_read_chained(
    rng: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    virtqueue: Rc<RefCell<TestVirtQueue>>,
    bytes: u64,
) -> Vec<u8> {
    let req_addr = alloc.borrow_mut().alloc(bytes * DEFAULT_RNG_REQS);
    let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(DEFAULT_RNG_REQS as usize);
    let mut len = Some(0);

    for i in 0..DEFAULT_RNG_REQS {
        data_entries.push(TestVringDescEntry {
            data: req_addr + i * bytes,
            len: bytes as u32,
            write: true,
        });
    }

    let free_head = virtqueue
        .borrow_mut()
        .add_chained(test_state.clone(), data_entries);

    rng.borrow()
        .kick_virtqueue(test_state.clone(), virtqueue.clone());
    rng.borrow().poll_used_elem(
        test_state.clone(),
        virtqueue.clone(),
        free_head,
        TIMEOUT_US,
        &mut len,
        true,
    );

    assert!(len.unwrap() >= 1);
    assert!(len.unwrap() as u64 <= bytes * DEFAULT_RNG_REQS);

    test_state.borrow().memread(req_addr, RNG_DATA_BYTES)
}

fn tear_down(
    rng: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vqs: Vec<Rc<RefCell<TestVirtQueue>>>,
) {
    rng.borrow_mut().destroy_device(alloc.clone(), vqs);
    test_state.borrow_mut().stop();
}

/// Rng device read random numbers function test.
/// TestStep:
///   1. Init device.
///   2. Do the I/O request, check random numbers.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn rng_read() {
    let max_bytes = 1024;
    let period = 1000;

    let random_file = get_random_file();
    let (rng, test_state, alloc) = create_rng(random_file, max_bytes, period);

    let virtqueues = rng.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    let mut data = virtio_rng_read_chained(
        rng.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        RNG_DATA_BYTES,
    );
    assert!(random_num_check(data));

    data = virtio_rng_read_chained(
        rng.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        RNG_DATA_BYTES,
    );
    assert!(random_num_check(data));

    tear_down(rng.clone(), test_state.clone(), alloc.clone(), virtqueues);
}

/// Rng device batch read random numbers function test.
/// TestStep:
///   1. Init device.
///   2. Do the I/O request, check random numbers.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn rng_read_batch() {
    let max_bytes = 1024;
    let period = 1000;

    let random_file = get_random_file();
    let (rng, test_state, alloc) = create_rng(random_file, max_bytes, period);

    let virtqueues = rng.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    let mut data = virtio_rng_read_batch(
        rng.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        RNG_DATA_BYTES,
    );
    assert!(random_num_check(data));

    data = virtio_rng_read_batch(
        rng.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        RNG_DATA_BYTES,
    );
    assert!(random_num_check(data));

    tear_down(rng.clone(), test_state.clone(), alloc.clone(), virtqueues);
}

/// Rng device rate limit random numbers reading test.
/// TestStep:
///   1. Init device with rate limit 64 bytes/sec.
///   2. Do the I/O request, check random numbers.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn rng_limited_rate() {
    let max_bytes = 64;
    let period = 1000;

    let random_file = get_random_file();
    let (rng, test_state, alloc) = create_rng(random_file, max_bytes, period);

    let virtqueues = rng.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    let data = virtio_rng_read_chained(
        rng.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        RNG_DATA_BYTES,
    );
    assert!(random_num_check(data));

    let req_addr = alloc.borrow_mut().alloc(RNG_DATA_BYTES * DEFAULT_RNG_REQS);
    let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(DEFAULT_RNG_REQS as usize);

    for i in 0..DEFAULT_RNG_REQS {
        data_entries.push(TestVringDescEntry {
            data: req_addr + i * RNG_DATA_BYTES,
            len: RNG_DATA_BYTES as u32,
            write: true,
        });
    }

    let free_head = virtqueues[0]
        .borrow_mut()
        .add_chained(test_state.clone(), data_entries);
    rng.borrow()
        .kick_virtqueue(test_state.clone(), virtqueues[0].clone());
    assert!(!random_num_check(
        test_state.borrow().memread(req_addr, RNG_DATA_BYTES)
    ));

    let time_out = Instant::now() + Duration::from_micros(TIMEOUT_US);
    loop {
        test_state.borrow().clock_step();
        if rng.borrow().queue_was_notified(virtqueues[0].clone())
            && virtqueues[0].borrow_mut().get_buf(test_state.clone())
        {
            assert!(virtqueues[0].borrow().desc_len.contains_key(&free_head));
            break;
        }
        assert!(Instant::now() <= time_out);
    }

    assert!(random_num_check(test_state.borrow().memread(
        req_addr + (DEFAULT_RNG_REQS - 1) * RNG_DATA_BYTES,
        RNG_DATA_BYTES
    )));

    tear_down(rng.clone(), test_state.clone(), alloc.clone(), virtqueues);
}

/// Rng device read a large number of random numbers test.
/// TestStep:
///   1. Init device.
///   2. Do the I/O request, check random numbers.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn rng_read_with_max() {
    let max_bytes = 1000000000;
    let period = 1000;
    let max_bytes_read = 2048000;

    let random_file = get_random_file();
    let (rng, test_state, alloc) = create_rng(random_file, max_bytes, period);

    let virtqueues = rng.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    let mut data = virtio_rng_read_chained(
        rng.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        max_bytes_read,
    );
    assert!(random_num_check(data));

    data = virtio_rng_read_chained(
        rng.clone(),
        test_state.clone(),
        alloc.clone(),
        virtqueues[0].clone(),
        max_bytes_read,
    );
    assert!(random_num_check(data));

    tear_down(rng.clone(), test_state.clone(), alloc.clone(), virtqueues);
}

/// Rng device read/write config space.
/// TestStep:
///   1. Init device.
///   2. Read/write rng device config space.
///   3. Destroy device.
/// Expect:
///   1/3: success, 2: failed.
#[test]
fn rng_rw_config() {
    let max_bytes = 1024;
    let period = 1000;

    let random_file = get_random_file();
    let (rng, test_state, alloc) = create_rng(random_file, max_bytes, period);

    let virtqueues = rng.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    let config = rng.borrow().config_readq(0);
    assert_eq!(config, 0);

    rng.borrow().config_writeq(0, 0xff);
    let config = rng.borrow().config_readq(0);
    assert_ne!(config, 0xff);

    tear_down(rng.clone(), test_state.clone(), alloc.clone(), virtqueues);
}
