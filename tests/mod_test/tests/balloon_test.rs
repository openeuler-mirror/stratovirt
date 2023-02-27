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

use mod_test::libdriver::machine::TestStdMachine;
use mod_test::libdriver::malloc::GuestAllocator;
use mod_test::libdriver::virtio::{TestVirtQueue, TestVringDescEntry, VirtioDeviceOps};
use mod_test::libdriver::virtio_pci_modern::{TestVirtioPciDev, VirtioPciCommonCfg};
use mod_test::libtest::{test_init, TestState};
use serde_json::json;
use std::cell::RefCell;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::process::Command;
use std::rc::Rc;
use std::{thread, time};
use util::offset_of;

const BALLOON_F_DEFLATE_ON_OOM_TEST: u32 = 2;
const BALLOON_F_PRPORTING_TEST: u32 = 5;
const BALLOON_F_VERSION1_TEST: u64 = 32;
const PAGE_SIZE_UNIT: u64 = 4096;
const TIMEOUT_US: u64 = 15 * 1000 * 1000;
const MBSIZE: u64 = 1024 * 1024;

fn read_lines(filename: String) -> io::Lines<BufReader<File>> {
    let file = File::open(filename).unwrap();
    return io::BufReader::new(file).lines();
}

fn get_hugesize() -> u64 {
    let mut free_page = 0_u64;
    let lines = read_lines("/proc/meminfo".to_string());
    for line in lines {
        if let Ok(info) = line {
            if info.starts_with("HugePages_Free:") {
                let free: Vec<&str> = info.split(":").collect();
                free_page = free[1].trim().parse::<u64>().unwrap();
            }
            if info.starts_with("Hugepagesize:") {
                let huges: Vec<&str> = info.split(":").collect();
                let sizes: Vec<&str> = huges[1].trim().split(" ").collect();
                let size = sizes[0].trim().parse::<u64>().unwrap();
                return free_page * size;
            }
        }
    }
    0_u64
}

pub struct VirtioBalloonTest {
    pub device: Rc<RefCell<TestVirtioPciDev>>,
    pub state: Rc<RefCell<TestState>>,
    pub allocator: Rc<RefCell<GuestAllocator>>,
    pub inf_queue: Rc<RefCell<TestVirtQueue>>,
    pub def_queue: Rc<RefCell<TestVirtQueue>>,
    pub fpr_queue: Option<Rc<RefCell<TestVirtQueue>>>,
}

impl VirtioBalloonTest {
    pub fn new(memsize: u64, page_size: u64, shared: bool, fpr: bool, huge: bool) -> Self {
        let pci_slot: u8 = 0x4;
        let mut extra_args: Vec<&str> = Vec::new();
        let mut fpr_switch = String::from("false");
        let mem_path = format!("-mem-path /tmp/stratovirt/hugepages");

        let mut args: Vec<&str> = "-machine".split(' ').collect();
        if shared {
            args.push("virt,mem-share=on");
        } else {
            args.push("virt");
        }
        extra_args.append(&mut args);

        let mem_args = format!("-m {}", memsize);
        args = mem_args[..].split(' ').collect();
        extra_args.append(&mut args);

        if huge {
            args = mem_path[..].split(' ').collect();
            extra_args.append(&mut args);
        }

        if fpr {
            fpr_switch = String::from("true");
        }
        let dev_args = format!(
            "-device {},id=drv0,bus=pcie.0,addr={}.0,free-page-reporting={}",
            "virtio-balloon-pci", pci_slot, fpr_switch
        );
        args = dev_args[..].split(' ').collect();
        extra_args.append(&mut args);

        let test_state = Rc::new(RefCell::new(test_init(extra_args)));
        let machine = TestStdMachine::new_bymem(test_state.clone(), memsize * MBSIZE, page_size);
        let allocator = machine.allocator.clone();

        let dev = Rc::new(RefCell::new(TestVirtioPciDev::new(machine.pci_bus.clone())));
        dev.borrow_mut().init(pci_slot, 0);

        let features = dev.borrow_mut().get_device_features();
        let inf_queue;
        let def_queue;
        let mut fpr_queue = None;
        if fpr {
            let ques =
                dev.borrow_mut()
                    .init_device(test_state.clone(), allocator.clone(), features, 3);
            inf_queue = ques[0].clone();
            def_queue = ques[1].clone();
            fpr_queue = Some(ques[2].clone());
        } else {
            let ques =
                dev.borrow_mut()
                    .init_device(test_state.clone(), allocator.clone(), features, 2);
            inf_queue = ques[0].clone();
            def_queue = ques[1].clone();
        }

        VirtioBalloonTest {
            device: dev,
            state: test_state,
            allocator,
            inf_queue,
            def_queue,
            fpr_queue,
        }
    }
}

fn inflate_fun(shared: bool) {
    let page_num = 255_i32;
    let mut idx = 0_i32;
    let balloon = VirtioBalloonTest::new(1024, PAGE_SIZE_UNIT, shared, false, false);

    let free_page = balloon
        .allocator
        .borrow_mut()
        .alloc(page_num as u64 * PAGE_SIZE_UNIT);
    let pfn = (free_page >> 12) as u32;
    let pfn_addr = balloon.allocator.borrow_mut().alloc(PAGE_SIZE_UNIT);
    while idx < page_num {
        balloon
            .state
            .borrow_mut()
            .writeb(free_page + PAGE_SIZE_UNIT * idx as u64, 1);
        idx += 1;
    }
    // balloon Illegal addresses
    balloon.state.borrow_mut().writel(pfn_addr, pfn - 1024);
    let free_head = balloon
        .inf_queue
        .borrow_mut()
        .add(balloon.state.clone(), pfn_addr, 4, false);
    balloon
        .device
        .borrow_mut()
        .kick_virtqueue(balloon.state.clone(), balloon.inf_queue.clone());
    balloon.device.borrow_mut().poll_used_elem(
        balloon.state.clone(),
        balloon.inf_queue.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        false,
    );

    // begin balloon addresses
    let mut loop_num = page_num - 1;
    let mut msg = Vec::new();

    while loop_num >= 0 {
        balloon
            .state
            .borrow_mut()
            .writel(pfn_addr + 4 * loop_num as u64, pfn + loop_num as u32);
        let entry = TestVringDescEntry {
            data: pfn_addr + (loop_num as u64 * 4),
            len: 4,
            write: false,
        };
        msg.push(entry);
        loop_num -= 1;
    }
    let free_head = balloon
        .inf_queue
        .borrow_mut()
        .add_chained(balloon.state.clone(), msg);
    balloon
        .device
        .borrow_mut()
        .kick_virtqueue(balloon.state.clone(), balloon.inf_queue.clone());
    balloon.device.borrow_mut().poll_used_elem(
        balloon.state.clone(),
        balloon.inf_queue.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        false,
    );
    balloon.state.borrow_mut().stop();
}

fn balloon_fun(shared: bool, huge: bool) {
    let page_num = 255_u32;
    let mut idx = 0_u32;
    let balloon = VirtioBalloonTest::new(1024, PAGE_SIZE_UNIT, shared, false, huge);

    let free_page = balloon
        .allocator
        .borrow_mut()
        .alloc(page_num as u64 * PAGE_SIZE_UNIT);
    let pfn = (free_page >> 12) as u32;
    let pfn_addr = balloon.allocator.borrow_mut().alloc(PAGE_SIZE_UNIT);
    while idx < page_num {
        balloon
            .state
            .borrow_mut()
            .writel(pfn_addr + 4 * idx as u64, pfn + idx);
        balloon
            .state
            .borrow_mut()
            .writeb(free_page + PAGE_SIZE_UNIT * idx as u64, 1);
        idx += 1;
    }

    // begin inflate addresses
    let mut loop_num = 0_u32;
    let mut msg = Vec::new();

    while loop_num < page_num {
        let entry = TestVringDescEntry {
            data: pfn_addr + (loop_num as u64 * 4),
            len: 4,
            write: false,
        };
        msg.push(entry);
        loop_num += 1;
    }
    let free_head = balloon
        .inf_queue
        .borrow_mut()
        .add_chained(balloon.state.clone(), msg);
    balloon
        .device
        .borrow_mut()
        .kick_virtqueue(balloon.state.clone(), balloon.inf_queue.clone());
    balloon.device.borrow_mut().poll_used_elem(
        balloon.state.clone(),
        balloon.inf_queue.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        false,
    );
    // begin deflate addresses
    let mut loop_num = 0_u32;
    let mut msg = Vec::new();

    while loop_num < page_num {
        let entry = TestVringDescEntry {
            data: pfn_addr + (loop_num as u64 * 4),
            len: 4,
            write: false,
        };
        msg.push(entry);
        loop_num += 1;
    }
    let free_head = balloon
        .def_queue
        .borrow_mut()
        .add_chained(balloon.state.clone(), msg);
    balloon
        .device
        .borrow_mut()
        .kick_virtqueue(balloon.state.clone(), balloon.def_queue.clone());
    balloon.device.borrow_mut().poll_used_elem(
        balloon.state.clone(),
        balloon.def_queue.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        false,
    );

    // begin deflate Illegal addresses
    balloon.state.borrow_mut().writel(pfn_addr, pfn - 1024);
    let free_head = balloon
        .def_queue
        .borrow_mut()
        .add(balloon.state.clone(), pfn_addr, 4, false);
    balloon
        .device
        .borrow_mut()
        .kick_virtqueue(balloon.state.clone(), balloon.def_queue.clone());
    balloon.device.borrow_mut().poll_used_elem(
        balloon.state.clone(),
        balloon.def_queue.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        false,
    );

    balloon.state.borrow_mut().stop();
}

/// balloon device inflate test
/// TestStep:
///     1.Init device
///     2.Populate the inflate queue with illegal addresses
///     3.Populate the inflate queue with legal addresses
/// Expect:
///     1.Success
///     2.There are no exceptions in the process
///     3.Memory need by addr
#[test]
fn balloon_inflate_001() {
    inflate_fun(false);
}
/// balloon device inflate test
/// TestStep:
///     1.Init device
///     2.Populate the inflate queue with illegal addresses
///     3.Populate the inflate queue with legal addresses
/// Expect:
///     1.Success
///     2.There are no exceptions in the process
///     3.memory released by addr
#[test]
fn balloon_inflate_002() {
    inflate_fun(true);
}

fn create_huge_mem_path() {
    let _output = Command::new("rm")
        .arg("-rf")
        .arg("/tmp/stratovirt/hugepages")
        .output()
        .expect("Failed to rm dir");

    let _output = Command::new("mkdir")
        .arg("-p")
        .arg("/tmp/stratovirt/hugepages")
        .output()
        .expect("Failed to mkdir dir");

    let _output = Command::new("mount")
        .arg("-t")
        .arg("hugetlbfs")
        .arg("hugetlbfs")
        .arg("/tmp/stratovirt/hugepages")
        .output()
        .expect("Failed to mount dir");

    let _output = Command::new("sysctl")
        .arg("vm.nr_hugepages=1024")
        .output()
        .expect("Failed to set count hugepages");
}

fn clean_huge_mem_path() {
    let _output = Command::new("umount")
        .arg("/tmp/stratovirt/hugepages")
        .output()
        .expect("Failed to mount dir");
}

/// balloon device deflate and inflate test
/// TestStep:
///     1.Init device
///     2.Populate the inflate queue with illegal addresses
///     3.Populate the inflate queue with legal addresses
///     4.Populate the deflate queue with legal addresses
/// Expect:
///     1.Success
///     2.There are no exceptions in the process
///     3.Memory re by addr
///     4.Free memory
#[test]
fn balloon_fun_001() {
    balloon_fun(false, false);
}

/// balloon device deflate and inflate test
/// TestStep:
///     1.Init device
///     2.Populate the inflate queue with illegal addresses
///     3.Populate the inflate queue with legal addresses
///     4.Populate the deflate queue with legal addresses
/// Expect:
///     1.Success
///     2.There are no exceptions in the process
///     3.Memory reallocte by addr
///     4.Free memory
#[test]
fn balloon_fun_002() {
    balloon_fun(true, false);
}

/// TestStep:
///     1.Init device
///     2.Populate the inflate queue with illegal addresses
///     3.Populate the inflate queue with legal addresses
///     4.Populate the deflate queue with legal addresses
/// Expect:
///     1.Success
///     2.There are no exceptions in the process
///     3.Memory reallocte by addr
///     4.Free memory
#[test]
fn balloon_huge_fun_001() {
    create_huge_mem_path();
    let size_kb = get_hugesize();
    if size_kb < 1024 * 1024 {
        clean_huge_mem_path();
        return;
    }
    balloon_fun(false, true);
    balloon_fun(true, true);
    clean_huge_mem_path();
}

/// balloon device features config test
/// TestStep:
///     1.Init device
///     2.set guest feature 0xFFFFFFFFFFFFFFFF
/// Expect:
///     1.Success
///     2.guest feature equel device feature
#[test]
fn balloon_feature_001() {
    let pci_slot: u8 = 0x4;
    let pci_fn: u8 = 0x0;
    let mut extra_args: Vec<&str> = Vec::new();

    let mut args: Vec<&str> = "-machine virt".split(' ').collect();
    extra_args.append(&mut args);

    let mem_args = format!("-m {}", 128);
    args = mem_args[..].split(' ').collect();
    extra_args.append(&mut args);

    let dev_args = format!(
        "-device {},id=drv0,bus=pcie.{},addr={}.0",
        "virtio-balloon-pci", pci_fn, pci_slot
    );
    args = dev_args[..].split(' ').collect();
    extra_args.append(&mut args);

    let test_state = Rc::new(RefCell::new(test_init(extra_args)));
    let machine = TestStdMachine::new_bymem(test_state.clone(), 128 * MBSIZE, PAGE_SIZE_UNIT);
    let allocator = machine.allocator.clone();

    let dev = Rc::new(RefCell::new(TestVirtioPciDev::new(machine.pci_bus.clone())));
    dev.borrow_mut().init(pci_slot, pci_fn);

    dev.borrow_mut().pci_dev.enable_msix(None);
    dev.borrow_mut()
        .setup_msix_configuration_vector(allocator.clone(), 0);

    let features = dev.borrow_mut().get_device_features();

    dev.borrow_mut().set_guest_features(0xFFFFFFFFFFFFFFFF);
    let features_guest = dev.borrow_mut().get_guest_features();
    assert_eq!(features, features_guest);

    test_state.borrow_mut().stop();
}

/// balloon device features config test
/// TestStep:
///     1.Init device
///     2.get device feature
/// Expect:
///     1.Success
///     2.feature OK
#[test]
fn balloon_feature_002() {
    let pci_slot: u8 = 0x4;
    let pci_fn: u8 = 0x0;
    let mut extra_args: Vec<&str> = Vec::new();

    let mut args: Vec<&str> = "-machine virt".split(' ').collect();
    extra_args.append(&mut args);

    let mem_args = format!("-m {}", 128);
    args = mem_args[..].split(' ').collect();
    extra_args.append(&mut args);

    let pci_args = format!(
        "-device {},id=drv0,bus=pcie.{},addr={}.0,deflate-on-oom=true,free-page-reporting=true",
        "virtio-balloon-pci", pci_fn, pci_slot
    );
    args = pci_args[..].split(' ').collect();
    extra_args.append(&mut args);

    let test_state = Rc::new(RefCell::new(test_init(extra_args)));
    let machine = TestStdMachine::new_bymem(test_state.clone(), 128 * MBSIZE, PAGE_SIZE_UNIT);
    let allocator = machine.allocator.clone();

    let dev = Rc::new(RefCell::new(TestVirtioPciDev::new(machine.pci_bus.clone())));
    dev.borrow_mut().init(pci_slot, pci_fn);

    dev.borrow_mut().pci_dev.enable_msix(None);
    dev.borrow_mut()
        .setup_msix_configuration_vector(allocator.clone(), 0);

    let features = dev.borrow_mut().get_device_features();

    assert_eq!(
        features,
        1u64 << BALLOON_F_VERSION1_TEST
            | 1u64 << BALLOON_F_PRPORTING_TEST
            | 1u64 << BALLOON_F_DEFLATE_ON_OOM_TEST
    );

    dev.borrow_mut()
        .set_guest_features(1u64 << BALLOON_F_VERSION1_TEST);
    let features_guest = dev.borrow_mut().get_guest_features();
    assert_eq!(1u64 << BALLOON_F_VERSION1_TEST, features_guest);

    test_state.borrow_mut().stop();
}

fn balloon_fpr_fun(shared: bool) {
    let page_num = 255_u32;
    let mut idx = 0_u32;
    let balloon = VirtioBalloonTest::new(1024, PAGE_SIZE_UNIT, shared, true, false);

    let free_page = balloon
        .allocator
        .borrow_mut()
        .alloc(page_num as u64 * PAGE_SIZE_UNIT);
    let pfn = (free_page >> 12) as u32;
    let pfn_addr = balloon.allocator.borrow_mut().alloc(PAGE_SIZE_UNIT);
    while idx < page_num {
        balloon
            .state
            .borrow_mut()
            .writel(pfn_addr + 4 * idx as u64, pfn + idx);
        balloon
            .state
            .borrow_mut()
            .writeb(free_page + PAGE_SIZE_UNIT * idx as u64, 1);
        idx += 1;
    }
    // balloon Illegal addresses
    balloon.state.borrow_mut().writel(pfn_addr, pfn - 1024);
    let fpr = balloon.fpr_queue.unwrap();
    let free_head = fpr
        .borrow_mut()
        .add(balloon.state.clone(), pfn_addr, 4, true);
    balloon
        .device
        .borrow_mut()
        .kick_virtqueue(balloon.state.clone(), fpr.clone());
    balloon.device.borrow_mut().poll_used_elem(
        balloon.state.clone(),
        fpr.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        false,
    );

    // begin fpr addresses
    let mut loop_num = 0_u32;
    let mut msg = Vec::new();

    while loop_num < page_num {
        let entry = TestVringDescEntry {
            data: pfn_addr + (loop_num as u64 * 4),
            len: 4,
            write: true,
        };
        msg.push(entry);
        loop_num += 1;
    }
    let free_head = fpr.borrow_mut().add_chained(balloon.state.clone(), msg);
    balloon
        .device
        .borrow_mut()
        .kick_virtqueue(balloon.state.clone(), fpr.clone());
    balloon.device.borrow_mut().poll_used_elem(
        balloon.state.clone(),
        fpr.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        false,
    );

    balloon.state.borrow_mut().stop();
}

/// balloon device fpr features test
/// TestStep:
///     1.Init device
///     2.Populate the fpr queue with illegal addresses
///     3.Populate the fpr queue with legal addresses
/// Expect:
///     1.Success
///     2.There are no exceptions in the process
///     3.Free memory
#[test]
fn balloon_fpr_001() {
    balloon_fpr_fun(true);
}

/// balloon device fpr features test
/// TestStep:
///     1.Init device
///     2.Populate the fpr queue with illegal addresses
///     3.Populate the fpr queue with legal addresses
/// Expect:
///     1.Success
///     2.There are no exceptions in the process
///     3.Free memory
#[test]
fn balloon_fpr_002() {
    balloon_fpr_fun(false);
}

struct VirtioBalloonConfig {
    /// The target page numbers of balloon device.
    pub num_pages: u32,
    /// Number of pages we've actually got in balloon device.
    pub actual: u32,
}

#[test]
fn query() {
    let balloon = VirtioBalloonTest::new(2048, PAGE_SIZE_UNIT, false, false, false);
    let ret = balloon
        .state
        .borrow_mut()
        .qmp("{\"execute\": \"query-balloon\"}");

    assert_eq!(
        *ret.get("return").unwrap(),
        json!({"actual": 2147483648 as u64})
    );

    balloon.state.borrow_mut().stop();
}

/// balloon device qmp config test
/// TestStep:
///     1.Init device
///     2.qmp config page 512M
///     3.qmp query result 512M
/// Expect:
///     1/2/3.Success
#[test]
fn balloon_config_001() {
    let balloon = VirtioBalloonTest::new(1024, PAGE_SIZE_UNIT, false, false, false);

    balloon
        .state
        .borrow_mut()
        .qmp("{\"execute\": \"balloon\", \"arguments\": {\"value\": 536870912}}");
    let ret = balloon.state.borrow_mut().qmp_read();
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    let num_pages = balloon
        .device
        .borrow_mut()
        .config_readl(offset_of!(VirtioBalloonConfig, num_pages) as u64);
    assert_eq!(num_pages, 131072);
    let actual = balloon
        .device
        .borrow_mut()
        .config_readl(offset_of!(VirtioBalloonConfig, actual) as u64);
    assert_eq!(actual, 0);
    balloon
        .device
        .borrow_mut()
        .config_writel(offset_of!(VirtioBalloonConfig, actual) as u64, 131072);
    let actual = balloon
        .device
        .borrow_mut()
        .config_readl(offset_of!(VirtioBalloonConfig, actual) as u64);
    assert_eq!(actual, 131072);
    let _actual = balloon
        .device
        .borrow_mut()
        .config_readl((offset_of!(VirtioBalloonConfig, actual) + 8) as u64);
    let ten_millis = time::Duration::from_millis(10);
    thread::sleep(ten_millis);
    let ret = balloon.state.borrow_mut().qmp_read();
    assert_eq!(
        *ret.get("data").unwrap(),
        json!({"actual": 536870912 as u64})
    );

    balloon
        .state
        .borrow_mut()
        .qmp("{\"execute\": \"balloon\", \"arguments\": {\"value\": 1610612736}}");
    let num_pages = balloon
        .device
        .borrow_mut()
        .config_readl(offset_of!(VirtioBalloonConfig, num_pages) as u64);
    assert_eq!(num_pages, 0);
    balloon.state.borrow_mut().stop();
}

/// balloon device qmp config test
/// TestStep:
///     1.Init device
///     2.qmp config page 512M
///     3.qmp query result 512M
/// Expect:
///     1/2/3.Success
#[test]
fn balloon_config_002() {
    let size_kb = get_hugesize();
    if size_kb < 1024 * 1024 {
        return;
    }
    let balloon = VirtioBalloonTest::new(1024, PAGE_SIZE_UNIT, false, false, true);

    balloon
        .state
        .borrow_mut()
        .qmp("{\"execute\": \"balloon\", \"arguments\": {\"value\": 536870912}}");
    let ret = balloon.state.borrow_mut().qmp_read();
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    let num_pages = balloon
        .device
        .borrow_mut()
        .config_readl(offset_of!(VirtioBalloonConfig, num_pages) as u64);
    assert_eq!(num_pages, 131072);
    let actual = balloon
        .device
        .borrow_mut()
        .config_readl(offset_of!(VirtioBalloonConfig, actual) as u64);
    assert_eq!(actual, 0);
    balloon
        .device
        .borrow_mut()
        .config_writel(offset_of!(VirtioBalloonConfig, actual) as u64, 131072);
    let actual = balloon
        .device
        .borrow_mut()
        .config_readl(offset_of!(VirtioBalloonConfig, actual) as u64);
    assert_eq!(actual, 131072);
    let _actual = balloon
        .device
        .borrow_mut()
        .config_readl((offset_of!(VirtioBalloonConfig, actual) + 8) as u64);
    let ten_millis = time::Duration::from_millis(10);
    thread::sleep(ten_millis);
    let ret = balloon.state.borrow_mut().qmp_read();
    assert_eq!(
        *ret.get("data").unwrap(),
        json!({"actual": 536870912 as u64})
    );

    balloon
        .state
        .borrow_mut()
        .qmp("{\"execute\": \"balloon\", \"arguments\": {\"value\": 1610612736}}");
    let num_pages = balloon
        .device
        .borrow_mut()
        .config_readl(offset_of!(VirtioBalloonConfig, num_pages) as u64);
    assert_eq!(num_pages, 0);
    balloon.state.borrow_mut().stop();
}

/// balloon device deactive config test
/// TestStep:
///     1.Init device
///     2.guest write queue disable
/// Expect:
///     1/2.Success
#[test]
fn balloon_deactive_001() {
    let balloon = VirtioBalloonTest::new(1024, PAGE_SIZE_UNIT, false, false, false);

    let bar = balloon.device.borrow().bar;
    let common_base = balloon.device.borrow().common_base as u64;

    balloon.device.borrow().pci_dev.io_writel(
        bar,
        common_base + offset_of!(VirtioPciCommonCfg, queue_enable) as u64,
        0,
    );

    let ten_millis = time::Duration::from_millis(10);
    thread::sleep(ten_millis);

    let ret = balloon
        .state
        .borrow_mut()
        .qmp("{\"execute\": \"query-balloon\"}");
    assert_eq!(
        *ret.get("return").unwrap(),
        json!({"actual": 1073741824 as u64})
    );
    balloon.state.borrow_mut().stop();
}
