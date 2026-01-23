// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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
use std::env;
use std::fs;
use std::path::Path;
use std::rc::Rc;
use std::string::String;

use regex::Regex;

use devices::misc::pvpanic::{PVPANIC_BSOD, PVPANIC_CRASHLOADED, PVPANIC_PANICKED};
use devices::pci::config::{
    PCI_CLASS_SYSTEM_OTHER, PCI_DEVICE_ID_REDHAT_PVPANIC, PCI_SUBDEVICE_ID_QEMU,
    PCI_VENDOR_ID_REDHAT, PCI_VENDOR_ID_REDHAT_QUMRANET,
};
use mod_test::{
    libdriver::{machine::TestStdMachine, malloc::GuestAllocator, pci::*},
    libtest::{test_init, TestState},
};

const TMP_LOG_PATH: &str = "/tmp/pvpanic-mst";
const BUS_NUM: u8 = 0;
const ADDR: u8 = 7;
const DEFAULT_SUPPORTED_FEATURE: u8 = (PVPANIC_PANICKED | PVPANIC_CRASHLOADED | PVPANIC_BSOD) as u8;
const MEM_SIZE: u64 = 2048; // 2GB
const PAGE_SIZE: u64 = 4096;
const PVPANIC_U64: u64 = 8;

struct LogCfg {
    pub enable_log: bool,
    pub suffix: String,
}

impl Default for LogCfg {
    fn default() -> Self {
        LogCfg {
            enable_log: false,
            suffix: String::default(),
        }
    }
}

#[derive(Clone, Copy)]
struct PvPanicDevCfg {
    pub bus_num: u8,
    pub addr: u8,
    pub supported_features: u8,
}

impl Default for PvPanicDevCfg {
    fn default() -> Self {
        Self {
            bus_num: BUS_NUM,
            addr: ADDR,
            supported_features: DEFAULT_SUPPORTED_FEATURE,
        }
    }
}

impl PvPanicDevCfg {
    fn fmt_pvpanic_deves(&self) -> String {
        format!(
            "-device pvpanic,id=pvpanic_pci,bus=pcie.{},addr=0x{},supported-features={}",
            &self.bus_num, &self.addr, &self.supported_features,
        )
    }
}

struct PvPanicTest {
    pub state: Rc<RefCell<TestState>>,
    pub allocator: Rc<RefCell<GuestAllocator>>,
    pub pvpanic_pci_dev: Rc<RefCell<TestPciDev>>,
}

impl PvPanicTest {
    fn new(log_cfg: LogCfg, memsize: u64, page_size: u64, shared: bool, prealloc: bool) -> Self {
        let mut test_machine_args: Vec<&str> = Vec::new();

        let mut args: Vec<&str> = "-machine".split(' ').collect();
        if shared {
            args.push("virt,mem-share=on");
        } else {
            args.push("virt");
        }
        if prealloc {
            args.push("-mem-prealloc");
        }
        test_machine_args.append(&mut args);

        let mem_args = format!("-m {}", memsize);
        args = mem_args[..].split(' ').collect();
        test_machine_args.append(&mut args);

        let log_path;
        if log_cfg.enable_log {
            log_path = format!("-D {}{}.log", TMP_LOG_PATH, log_cfg.suffix);
            args = log_path[..].split(' ').collect();
            test_machine_args.append(&mut args);
        }

        let cfg = PvPanicDevCfg::default();
        let pvpanic_str = cfg.fmt_pvpanic_deves();
        args = pvpanic_str[..].split(' ').collect();
        test_machine_args.append(&mut args);

        let test_state = Rc::new(RefCell::new(test_init(test_machine_args)));
        let machine: TestStdMachine =
            TestStdMachine::new_bymem(test_state.clone(), memsize * 1024 * 1024, page_size);
        let allocator = machine.allocator.clone();

        let mut pvpanic_pci_dev = TestPciDev::new(machine.pci_bus.clone());
        let devfn = cfg.addr << 3;
        pvpanic_pci_dev.devfn = devfn;

        pvpanic_pci_dev.set_bus_num(cfg.bus_num);
        pvpanic_pci_dev.enable();

        PvPanicTest {
            state: test_state,
            allocator,
            pvpanic_pci_dev: Rc::new(RefCell::new(pvpanic_pci_dev)),
        }
    }
}

fn remove_specific_type_file(regex_str: &str, path_str: &str) -> bool {
    let type_regex = Regex::new(regex_str).unwrap();
    let path = Path::new(path_str);
    let mut remove_flag = false;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                if type_regex.is_match(file_name) {
                    match std::fs::remove_file(path) {
                        Ok(_) => remove_flag = true,
                        Err(e) => assert!(false, "{}", e),
                    }
                }
            }
        }
    }

    remove_flag
}

/// PvPanic device read config space.
/// TestStep:
///   1. Init device.
///   2. Read PvPanic device config space.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn test_pvpanic_read_config() {
    let log_cfg = LogCfg::default();
    let pvpanic_test = PvPanicTest::new(log_cfg, MEM_SIZE, PAGE_SIZE, false, false);
    let read_config_params: [(u8, u16); 5] = [
        (PCI_VENDOR_ID, PCI_VENDOR_ID_REDHAT),
        (PCI_DEVICE_ID, PCI_DEVICE_ID_REDHAT_PVPANIC),
        (PCI_SUB_CLASS_DEVICE, PCI_CLASS_SYSTEM_OTHER),
        (PCI_SUBSYSTEM_VENDOR_ID, PCI_VENDOR_ID_REDHAT_QUMRANET),
        (PCI_SUBSYSTEM_ID, PCI_SUBDEVICE_ID_QEMU),
    ];

    for &(offset, expected_content) in read_config_params.iter() {
        let info = pvpanic_test.pvpanic_pci_dev.borrow().config_readw(offset);
        assert_eq!(info, expected_content);
    }

    pvpanic_test.state.borrow_mut().stop();
}

/// PvPanic device read supported features.
/// TestStep:
///   1. Init device.
///   2. Read supported features of PvPanic to emulate front-end driver.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn test_pvpanic_read_supported_features() {
    let log_cfg = LogCfg::default();
    let pvpanic_test = PvPanicTest::new(log_cfg, MEM_SIZE, PAGE_SIZE, false, false);

    let bar_addr = pvpanic_test.pvpanic_pci_dev.borrow().io_map(0);
    let start = bar_addr;

    let info = pvpanic_test.state.borrow().readb(start);
    assert_eq!(info, DEFAULT_SUPPORTED_FEATURE);

    pvpanic_test.state.borrow_mut().stop();
}

/// PvPanic device write events.
/// TestStep:
///   1. Init device.
///   2. Write 3 types of events to PvPanic bar0 with offset 0 to emulate front-end driver and check device behaviors via log.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn test_pvpanic_write_events() {
    let tmp_log_path = format!("{}write_events.log", TMP_LOG_PATH);
    if Path::new(tmp_log_path.as_str()).exists() {
        fs::remove_file(tmp_log_path.as_str()).unwrap();
    }

    let log_cfg = LogCfg {
        enable_log: true,
        suffix: String::from("write_events"),
    };
    let pvpanic_test = PvPanicTest::new(log_cfg, MEM_SIZE, PAGE_SIZE, false, false);

    let bar_addr = pvpanic_test.pvpanic_pci_dev.borrow().io_map(0);
    let start = bar_addr;

    let write_test_params: [(u64, &str); 3] = [
        (PVPANIC_PANICKED, "pvpanic: panicked event"),
        (PVPANIC_CRASHLOADED, "pvpanic: crashloaded event"),
        (
            u64::from(!DEFAULT_SUPPORTED_FEATURE),
            "pvpanic: unknown event",
        ),
    ];

    for &(data, expected_log_content) in write_test_params.iter() {
        pvpanic_test.state.borrow().writeq(start, data);
        let tmp_log_content = std::fs::read_to_string(tmp_log_path.as_str()).unwrap();

        assert!(tmp_log_content.contains(expected_log_content));
    }

    pvpanic_test.state.borrow_mut().stop();
    match fs::remove_file(tmp_log_path.as_str()) {
        Ok(_) => {}
        Err(e) => assert!(false, "{}", e),
    }
}

/// PvPanic device init dump file.
/// TestStep:
///   1. Init device.
///   2. Write 0 to PvPanic bar0 with offset 1 * 8 to emulate front-end driver and check prepared dump file.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn test_pvpanic_init_dump_file() {
    // If there is any existing dump file, clean them up first.
    remove_specific_type_file(r"^.+\.dmp$", "./");

    let log_cfg = LogCfg::default();
    let pvpanic_test = PvPanicTest::new(log_cfg, MEM_SIZE, PAGE_SIZE, false, false);

    let bar_addr = pvpanic_test.pvpanic_pci_dev.borrow().io_map(0);
    let start = bar_addr;

    pvpanic_test
        .state
        .borrow()
        .writeq(start + PVPANIC_U64, 0_u64);

    let file_exists = remove_specific_type_file(r"^.+\.dmp$", "./");
    assert!(file_exists);

    pvpanic_test.state.borrow_mut().stop();
}

/// PvPanic device write buffer address.
/// TestStep:
///   1. Init device.
///   2. Write a buffer address(GPA) to PvPanic bar0 with offset 2 * 8 to emulate front-end driver and check device behaviors.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn test_pvpanic_write_buffer_address() {
    // set env
    env::set_var("STRATOVIRT_LOG_LEVEL", "debug");

    let tmp_log_path = format!("{}write_buffer_address.log", TMP_LOG_PATH);
    if Path::new(tmp_log_path.as_str()).exists() {
        fs::remove_file(tmp_log_path.as_str()).unwrap();
    }

    let log_cfg = LogCfg {
        enable_log: true,
        suffix: String::from("write_buffer_address"),
    };
    let pvpanic_test = PvPanicTest::new(log_cfg, MEM_SIZE, PAGE_SIZE, false, false);

    let bar_addr = pvpanic_test.pvpanic_pci_dev.borrow().io_map(0);
    let start = bar_addr;

    // prepare a guest buffer with some content, and get the corresponding GPA of it
    let content = "test write buffer address(GPA)";
    let addr = pvpanic_test.allocator.borrow_mut().alloc(PAGE_SIZE);

    pvpanic_test
        .state
        .borrow_mut()
        .memwrite(addr, content.as_bytes());

    let ret = pvpanic_test
        .state
        .borrow_mut()
        .memread(addr, content.len() as u64);
    assert_eq!(content, String::from_utf8(ret.clone()).unwrap());

    pvpanic_test
        .state
        .borrow()
        .writeq(start + PVPANIC_U64, 0_u64);

    pvpanic_test
        .state
        .borrow()
        .writeq(start + 2 * PVPANIC_U64, addr);

    // depends on the log level debug
    let tmp_log_content = std::fs::read_to_string(tmp_log_path.as_str()).unwrap();
    assert!(tmp_log_content.contains("pvpanic: buffer GPA is 0x"));

    pvpanic_test.state.borrow_mut().stop();
    match fs::remove_file(tmp_log_path.as_str()) {
        Ok(_) => {}
        Err(e) => assert!(false, "{}", e),
    }
}

/// PvPanic device write buffer size.
/// TestStep:
///   1. Init device.
///   2. Write 0 to PvPanic bar0 with offset 1 * 8 to prepare dump file.
///   3. Write a prepared buffer address(GPA) to PvPanic bar0 with offset 2 * 8
///   4. Write the corresponding buffer size to PvPanic bar0 with offset 3 * 8 to emulate front-end driver and check device behaviors via dump file.
///   5. Destroy device.
/// Expect:
///   1/2/3/4/5: success.
#[test]
fn test_pvpanic_write_buffer_size() {
    let log_cfg = LogCfg::default();
    let pvpanic_test = PvPanicTest::new(log_cfg, MEM_SIZE, PAGE_SIZE, false, false);

    let bar_addr = pvpanic_test.pvpanic_pci_dev.borrow().io_map(0);
    let start = bar_addr;

    pvpanic_test
        .state
        .borrow()
        .writeq(start + PVPANIC_U64, 77_u64);

    // prepare a guest buffer with some content, and get the corresponding GPA of it
    let content = "test write buffer size";
    let addr = pvpanic_test.allocator.borrow_mut().alloc(PAGE_SIZE);

    pvpanic_test
        .state
        .borrow_mut()
        .memwrite(addr, content.as_bytes());

    let ret = pvpanic_test
        .state
        .borrow_mut()
        .memread(addr, content.len() as u64);
    assert_eq!(content, String::from_utf8(ret.clone()).unwrap());

    pvpanic_test
        .state
        .borrow()
        .writeq(start + 2 * PVPANIC_U64, addr);

    pvpanic_test
        .state
        .borrow()
        .writeq(start + 3 * PVPANIC_U64, content.len() as u64);

    let type_regex = Regex::new(r"^.*_77\.dmp$").unwrap();
    let path = Path::new("./");
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                if type_regex.is_match(file_name) {
                    let tmp_dump_path = format!("./{}", file_name);
                    let tmp_dump_content = std::fs::read_to_string(&tmp_dump_path).unwrap();
                    assert!(tmp_dump_content.contains("test write buffer size"));
                    match std::fs::remove_file(path) {
                        Ok(_) => {}
                        Err(e) => assert!(false, "{}", e),
                    }
                    break;
                }
            }
        }
    }
}
