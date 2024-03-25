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
use std::fs;
use std::path::Path;
use std::rc::Rc;

use devices::pci::config::{
    PCI_CLASS_SYSTEM_OTHER, PCI_DEVICE_ID_REDHAT_PVPANIC, PCI_SUBDEVICE_ID_QEMU,
    PCI_VENDOR_ID_REDHAT, PCI_VENDOR_ID_REDHAT_QUMRANET,
};
use machine_manager::config::{PVPANIC_CRASHLOADED, PVPANIC_PANICKED};
use mod_test::{
    libdriver::{machine::TestStdMachine, pci::*},
    libtest::{test_init, TestState, MACHINE_TYPE_ARG},
};

const TMP_LOG_PATH: &str = "/tmp/pvpanic-mst.log";
const BUS_NUM: u8 = 0;
const ADDR: u8 = 7;
const DEFAULT_SUPPORTED_FEATURE: u8 = (PVPANIC_PANICKED | PVPANIC_CRASHLOADED) as u8;

#[derive(Clone, Copy)]
struct PvPanicDevCfg {
    bus_num: u8,
    addr: u8,
    supported_features: u8,
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
    fn init(&self, enable_log: bool) -> (Rc<RefCell<TestPciDev>>, Rc<RefCell<TestState>>) {
        let mut test_machine_args: Vec<&str> = Vec::new();

        let mut args: Vec<&str> = MACHINE_TYPE_ARG.split(' ').collect();
        test_machine_args.append(&mut args);

        if enable_log {
            let mut args: Vec<&str> = vec!["-D", TMP_LOG_PATH];
            test_machine_args.append(&mut args);
        }

        let pvpanic_str = fmt_pvpanic_deves(self.clone());
        args = pvpanic_str[..].split(' ').collect();
        test_machine_args.append(&mut args);

        let test_state = Rc::new(RefCell::new(test_init(test_machine_args)));
        let machine = Rc::new(RefCell::new(TestStdMachine::new(test_state.clone())));

        let mut pvpanic_pci_dev = TestPciDev::new(machine.clone().borrow().pci_bus.clone());
        let devfn = self.addr << 3;
        pvpanic_pci_dev.devfn = devfn;

        pvpanic_pci_dev.set_bus_num(self.bus_num);
        pvpanic_pci_dev.enable();

        (Rc::new(RefCell::new(pvpanic_pci_dev)), test_state)
    }
}

fn fmt_pvpanic_deves(cfg: PvPanicDevCfg) -> String {
    format!(
        "-device pvpanic,id=pvpanic_pci,bus=pcie.{},addr=0x{},supported-features={}",
        cfg.bus_num, cfg.addr, cfg.supported_features,
    )
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
    let cfg = PvPanicDevCfg::default();

    let (pvpanic_pci_dev, test_state) = cfg.init(false);

    let info = pvpanic_pci_dev.borrow().config_readw(PCI_VENDOR_ID);
    assert_eq!(info, PCI_VENDOR_ID_REDHAT);

    let info = pvpanic_pci_dev.borrow().config_readw(PCI_DEVICE_ID);
    assert_eq!(info, PCI_DEVICE_ID_REDHAT_PVPANIC);

    let info = pvpanic_pci_dev.borrow().config_readw(PCI_SUB_CLASS_DEVICE);
    assert_eq!(info, PCI_CLASS_SYSTEM_OTHER);

    let info = pvpanic_pci_dev
        .borrow()
        .config_readw(PCI_SUBSYSTEM_VENDOR_ID);
    assert_eq!(info, PCI_VENDOR_ID_REDHAT_QUMRANET);

    let info = pvpanic_pci_dev.borrow().config_readw(PCI_SUBSYSTEM_ID);
    assert_eq!(info, PCI_SUBDEVICE_ID_QEMU);

    test_state.borrow_mut().stop();
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
    let cfg = PvPanicDevCfg::default();

    let (pvpanic_pci_dev, test_state) = cfg.init(false);

    let bar_addr = pvpanic_pci_dev.borrow().io_map(0);

    let start = bar_addr;

    let info = test_state.borrow().readb(start);
    assert_eq!(info, DEFAULT_SUPPORTED_FEATURE);

    test_state.borrow_mut().stop();
}

/// PvPanic device write events.
/// TestStep:
///   1. Init device.
///   2. Write 3 types of events to PvPanic bar0 to emulate front-end driver and check device behaviors via log.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn test_pvpanic_write_events() {
    let cfg = PvPanicDevCfg::default();

    if Path::new(TMP_LOG_PATH).exists() {
        fs::remove_file(TMP_LOG_PATH).unwrap();
    }

    let (pvpanic_pci_dev, test_state) = cfg.init(true);

    let bar_addr = pvpanic_pci_dev.borrow().io_map(0);
    let start = bar_addr;
    let tmp_log_path = String::from(TMP_LOG_PATH);
    let write_test_params: [(u8, &str); 3] = [
        (PVPANIC_PANICKED as u8, "pvpanic: panicked event"),
        (PVPANIC_CRASHLOADED as u8, "pvpanic: crashloaded event"),
        (!DEFAULT_SUPPORTED_FEATURE, "pvpanic: unknown event"),
    ];

    for &(data, expected_log_content) in write_test_params.iter() {
        test_state.borrow().writeb(start, data);
        let tmp_log_content = std::fs::read_to_string(&tmp_log_path).unwrap();

        assert!(tmp_log_content.contains(expected_log_content));
    }

    test_state.borrow_mut().stop();
    match fs::remove_file(TMP_LOG_PATH) {
        Ok(_) => {}
        Err(e) => assert!(false, "{}", e),
    }
}
