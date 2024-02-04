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
use std::fs::{remove_file, File};
use std::io::{self, BufRead, BufReader};
use std::process::Command;
use std::rc::Rc;
use std::{thread, time};

use serde_json::json;

use mod_test::libdriver::machine::TestStdMachine;
use mod_test::libdriver::malloc::GuestAllocator;
use mod_test::libdriver::virtio::{TestVirtQueue, TestVringDescEntry, VirtioDeviceOps};
use mod_test::libdriver::virtio_pci_modern::{TestVirtioPciDev, VirtioPciCommonCfg};
use mod_test::libtest::{test_init, TestState, MACHINE_TYPE_ARG};
use util::{byte_code::ByteCode, offset_of};

const BALLOON_F_DEFLATE_ON_OOM_TEST: u32 = 2;
const BALLOON_F_PRPORTING_TEST: u32 = 5;
const BALLOON_F_VERSION1_TEST: u64 = 32;
const PAGE_SIZE_UNIT: u64 = 4096;
const TIMEOUT_US: u64 = 15 * 1000 * 1000;
const MBSIZE: u64 = 1024 * 1024;
const MEM_BUFFER_PERCENT_DEFAULT: u32 = 50;
const MONITOR_INTERVAL_SECOND_DEFAULT: u32 = 10;
const ADDRESS_BASE: u64 = 0x4000_0000;

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
    pub auto_queue: Option<Rc<RefCell<TestVirtQueue>>>,
}

pub struct BalloonTestCfg {
    pub fpr: bool,
    pub auto_balloon: bool,
    pub percent: u32,
    pub interval: u32,
}

impl VirtioBalloonTest {
    pub fn new(
        memsize: u64,
        page_size: u64,
        shared: bool,
        huge: bool,
        cfg: BalloonTestCfg,
    ) -> Self {
        let pci_slot: u8 = 0x4;
        let mut extra_args: Vec<&str> = Vec::new();
        let mut fpr_switch = String::from("false");
        let mut auto_switch = String::from("false");
        let mem_path = format!("-mem-path /tmp/stratovirt/hugepages");

        let mut machine_args = MACHINE_TYPE_ARG.to_string();
        if shared {
            machine_args.push_str(",mem-share=on");
        }
        let mut args: Vec<&str> = machine_args.split(' ').collect();
        extra_args.append(&mut args);

        let mem_args = format!("-m {}", memsize);
        args = mem_args[..].split(' ').collect();
        extra_args.append(&mut args);

        if huge {
            args = mem_path[..].split(' ').collect();
            extra_args.append(&mut args);
        }

        if cfg.fpr {
            fpr_switch = String::from("true");
        }
        if cfg.auto_balloon {
            auto_switch = String::from("true");
        }
        let dev_args = format!(
            "-device virtio-balloon-pci,id=drv0,bus=pcie.0,addr={}.0,free-page-reporting={},auto-balloon={},membuf-percent={},monitor-interval={}",
            pci_slot, fpr_switch, auto_switch, cfg.percent, cfg.interval
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
        let mut auto_queue = None;
        let mut que_num = 2_usize;
        let mut idx = 2_usize;
        if cfg.fpr {
            que_num += 1;
        }
        if cfg.auto_balloon {
            que_num += 1;
        }
        let ques =
            dev.borrow_mut()
                .init_device(test_state.clone(), allocator.clone(), features, que_num);
        inf_queue = ques[0].clone();
        def_queue = ques[1].clone();
        if cfg.fpr {
            fpr_queue = Some(ques[idx].clone());
            idx += 1;
        }
        if cfg.auto_balloon {
            auto_queue = Some(ques[idx].clone());
        }

        VirtioBalloonTest {
            device: dev,
            state: test_state,
            allocator,
            inf_queue,
            def_queue,
            fpr_queue,
            auto_queue,
        }
    }

    pub fn numa_node_new() -> Self {
        let mut args: Vec<&str> = Vec::new();
        let mut extra_args: Vec<&str> = MACHINE_TYPE_ARG.split(' ').collect();
        args.append(&mut extra_args);

        let cpu = 8;
        let cpu_args = format!(
            "-smp {},sockets=1,cores=4,threads=2 -cpu host,pmu=on -m 2G",
            cpu
        );
        let mut extra_args = cpu_args.split(' ').collect();
        args.append(&mut extra_args);
        extra_args = "-object memory-backend-file,size=1G,id=mem0,host-nodes=0-1,policy=bind,share=on,mem-path=test.fd"
            .split(' ')
            .collect();
        args.append(&mut extra_args);
        extra_args =
            "-object memory-backend-memfd,size=1G,id=mem1,host-nodes=0-1,policy=bind,mem-prealloc=true"
                .split(' ')
                .collect();
        args.append(&mut extra_args);
        extra_args = "-numa node,nodeid=0,cpus=0-3,memdev=mem0"
            .split(' ')
            .collect();
        args.append(&mut extra_args);
        extra_args = "-numa node,nodeid=1,cpus=4-7,memdev=mem1"
            .split(' ')
            .collect();
        args.append(&mut extra_args);
        extra_args = "-numa dist,src=0,dst=1,val=30".split(' ').collect();
        args.append(&mut extra_args);
        extra_args = "-numa dist,src=1,dst=0,val=30".split(' ').collect();
        args.append(&mut extra_args);

        extra_args = "-device virtio-balloon-pci,id=drv0,bus=pcie.0,addr=0x4.0"
            .split(' ')
            .collect();
        args.append(&mut extra_args);

        let test_state = Rc::new(RefCell::new(test_init(args)));
        let machine = TestStdMachine::new_bymem(test_state.clone(), 2 * MBSIZE, 4096);
        let allocator = machine.allocator.clone();

        let dev = Rc::new(RefCell::new(TestVirtioPciDev::new(machine.pci_bus.clone())));
        dev.borrow_mut().init(4, 0);

        let features = dev.borrow_mut().get_device_features();
        let inf_queue;
        let def_queue;

        let ques = dev
            .borrow_mut()
            .init_device(test_state.clone(), allocator.clone(), features, 2);
        inf_queue = ques[0].clone();
        def_queue = ques[1].clone();

        VirtioBalloonTest {
            device: dev,
            state: test_state,
            allocator,
            inf_queue,
            def_queue,
            fpr_queue: None,
            auto_queue: None,
        }
    }
}

fn inflate_fun(shared: bool) {
    let page_num = 255_i32;
    let mut idx = 0_i32;
    let cfg = BalloonTestCfg {
        fpr: false,
        auto_balloon: false,
        percent: 0,
        interval: 0,
    };
    let balloon = VirtioBalloonTest::new(1024, PAGE_SIZE_UNIT, shared, false, cfg);

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
    let cfg = BalloonTestCfg {
        fpr: false,
        auto_balloon: false,
        percent: 0,
        interval: 0,
    };
    let balloon = VirtioBalloonTest::new(1024, PAGE_SIZE_UNIT, shared, huge, cfg);

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
///     2.guest feature equal device feature
#[test]
fn balloon_feature_001() {
    let pci_slot: u8 = 0x4;
    let pci_fn: u8 = 0x0;
    let mut extra_args: Vec<&str> = Vec::new();

    let mut args: Vec<&str> = MACHINE_TYPE_ARG.split(' ').collect();
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

    let mut args: Vec<&str> = MACHINE_TYPE_ARG.split(' ').collect();
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
    let cfg = BalloonTestCfg {
        fpr: true,
        auto_balloon: false,
        percent: 0,
        interval: 0,
    };
    let balloon = VirtioBalloonTest::new(1024, PAGE_SIZE_UNIT, shared, false, cfg);

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
    pub _reserved: u32,
    pub _reserved1: u32,
    /// Buffer percent is a percentage of memory actually needed by
    /// the applications and services running inside the virtual machine.
    /// This parameter takes effect only when VIRTIO_BALLOON_F_MESSAGE_VQ is supported.
    /// Recommended value range: [20, 80] and default is 50.
    pub membuf_percent: u32,
    /// Monitor interval host wants to adjust VM memory size.
    /// Recommended value range: [5, 300] and default is 10.
    pub monitor_interval: u32,
}

#[test]
fn query() {
    let cfg = BalloonTestCfg {
        fpr: false,
        auto_balloon: false,
        percent: 0,
        interval: 0,
    };
    let balloon = VirtioBalloonTest::new(2048, PAGE_SIZE_UNIT, false, false, cfg);
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
    let cfg = BalloonTestCfg {
        fpr: false,
        auto_balloon: false,
        percent: 0,
        interval: 0,
    };
    let balloon = VirtioBalloonTest::new(1024, PAGE_SIZE_UNIT, false, false, cfg);

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
    let cfg = BalloonTestCfg {
        fpr: false,
        auto_balloon: false,
        percent: 0,
        interval: 0,
    };
    let balloon = VirtioBalloonTest::new(1024, PAGE_SIZE_UNIT, false, true, cfg);

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
    let cfg = BalloonTestCfg {
        fpr: false,
        auto_balloon: false,
        percent: 0,
        interval: 0,
    };
    let balloon = VirtioBalloonTest::new(1024, PAGE_SIZE_UNIT, false, false, cfg);

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

#[derive(Clone, Copy, Default)]
#[repr(packed(1))]
struct BalloonStat {
    _tag: u16,
    _val: u64,
}
impl ByteCode for BalloonStat {}
/// balloon device deactive config test
/// TestStep:
///     1.Init device
///     2.geust send msg to host by auto balloon
/// Expect:
///     1/2.Success
#[test]
fn auto_balloon_test_001() {
    let cfg = BalloonTestCfg {
        fpr: false,
        auto_balloon: true,
        percent: MEM_BUFFER_PERCENT_DEFAULT,
        interval: MONITOR_INTERVAL_SECOND_DEFAULT,
    };
    let balloon = VirtioBalloonTest::new(1024, PAGE_SIZE_UNIT, false, false, cfg);

    let num_pages = balloon
        .device
        .borrow_mut()
        .config_readl(offset_of!(VirtioBalloonConfig, num_pages) as u64);
    assert_eq!(num_pages, 0);
    let percent = balloon
        .device
        .borrow_mut()
        .config_readl(offset_of!(VirtioBalloonConfig, membuf_percent) as u64);
    assert_eq!(percent, MEM_BUFFER_PERCENT_DEFAULT);
    let interval = balloon
        .device
        .borrow_mut()
        .config_readl(offset_of!(VirtioBalloonConfig, monitor_interval) as u64);
    assert_eq!(interval, MONITOR_INTERVAL_SECOND_DEFAULT);

    let stat = BalloonStat {
        _tag: 0,
        _val: 131070,
    };
    let msg_addr = balloon.allocator.borrow_mut().alloc(PAGE_SIZE_UNIT);
    balloon
        .state
        .borrow_mut()
        .memwrite(msg_addr, &stat.as_bytes());

    let auto_queue = balloon.auto_queue.unwrap();

    let free_head = auto_queue.borrow_mut().add(
        balloon.state.clone(),
        msg_addr,
        std::mem::size_of::<BalloonStat>() as u32,
        false,
    );
    balloon
        .device
        .borrow_mut()
        .kick_virtqueue(balloon.state.clone(), auto_queue.clone());
    balloon.device.borrow_mut().poll_used_elem(
        balloon.state.clone(),
        auto_queue.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        false,
    );
    let num_pages = balloon
        .device
        .borrow_mut()
        .config_readl(offset_of!(VirtioBalloonConfig, num_pages) as u64);
    assert_eq!(num_pages, 131070);
    balloon
        .device
        .borrow_mut()
        .config_writel(offset_of!(VirtioBalloonConfig, actual) as u64, 131070);
    let actual = balloon
        .device
        .borrow_mut()
        .config_readl(offset_of!(VirtioBalloonConfig, actual) as u64);
    assert_eq!(actual, 131070);
}

#[test]
/// balloon device deactive config test
/// TestStep:
///     1.Init device
///     2.geust send msg to host by auto balloon
/// Expect:
///     1/2.Success
fn balloon_numa1() {
    let page_num = 255_u32;
    let mut idx = 0_u32;
    let balloon = VirtioBalloonTest::numa_node_new();

    let free_page = 0x4000_0000 + ADDRESS_BASE - 100 * PAGE_SIZE_UNIT;
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

    balloon.state.borrow_mut().stop();
    remove_file("test.fd").unwrap();
}
