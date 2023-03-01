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
use mod_test::libdriver::pci::*;
use mod_test::libdriver::pci_bus::{PciBusOps, TestPciBus};
use mod_test::libdriver::virtio::{TestVirtQueue, VirtioDeviceOps, VIRTIO_F_VERSION_1};
use mod_test::libdriver::virtio_block::{
    add_blk_request, virtio_blk_defalut_feature, virtio_blk_read, virtio_blk_write,
    VIRTIO_BLK_T_OUT,
};
use mod_test::libdriver::virtio_pci_modern::TestVirtioPciDev;
use mod_test::libtest::{test_init, TestState};
use mod_test::utils::{cleanup_img, create_img, read_le_u16, TEST_IMAGE_SIZE};

use serde_json::json;
use std::cell::RefCell;
use std::rc::Rc;
use std::{thread, time};

const VIRTIO_PCI_VENDOR: u16 = 0x1af4;
const BLK_DEVICE_ID: u16 = 0x1042;
const MAX_DEVICE_NUM_IN_MULTIFUNC: u8 = 248;
const MAX_DEVICE_NUM: u8 = 32;
const TIMEOUT_S: u64 = 5;

#[derive(Clone, Copy)]
struct DemoDev {
    bar_num: u8,
    bar_size: u64,
    bus_num: u8,
    dev_num: u8,
}

fn fmt_demo_deves(cfg: DemoDev, num: u8) -> String {
    // let mut dev_str = format!("-device pcie-root-port,port=0x0,addr=0x1.0x0,bus=pcie.0,id=pcie.{}", cfg.bus_num);
    let mut dev_str: String = String::new();

    for i in 1..num + 1 {
        let tmp = format!(
            "-device pcie-demo-dev,addr=0x{:x},bus=pcie.{},id=demo{},bar_num={},bar_size={}",
            cfg.dev_num + i - 1,
            cfg.bus_num,
            i,
            cfg.bar_num,
            cfg.bar_size
        );
        let sep = match i {
            1 => "",
            _ => " ",
        };
        dev_str = format!("{}{}{}", dev_str, sep, tmp);
    }

    dev_str
}

fn init_demo_dev(cfg: DemoDev, dev_num: u8) -> (Rc<RefCell<TestPciDev>>, Rc<RefCell<TestState>>) {
    let mut demo_dev_args: Vec<&str> = Vec::new();

    let mut args: Vec<&str> = "-machine virt -D /tmp/oscar.log".split(' ').collect();
    demo_dev_args.append(&mut args);

    let demo_str = fmt_demo_deves(cfg.clone(), dev_num);
    args = demo_str[..].split(' ').collect();
    demo_dev_args.append(&mut args);

    let test_state = Rc::new(RefCell::new(test_init(demo_dev_args)));
    let machine = Rc::new(RefCell::new(TestStdMachine::new(test_state.clone())));
    let _allocator = machine.borrow().allocator.clone();

    let mut pci_dev = TestPciDev::new(machine.clone().borrow().pci_bus.clone());
    let devfn = cfg.dev_num << 3;
    pci_dev.devfn = devfn;

    pci_dev.set_bus_num(cfg.bus_num);
    pci_dev.enable();

    (Rc::new(RefCell::new(pci_dev)), test_state)
}

#[derive(Default, Clone)]
pub struct MsixVector {
    pub msix_entry: u16,
    pub msix_addr: u64,
    pub msix_data: u32,
}

impl MsixVector {
    fn new(entry: u16, alloc: Rc<RefCell<GuestAllocator>>) -> Self {
        Self {
            msix_entry: entry,
            msix_addr: alloc.borrow_mut().alloc(4),
            msix_data: 0x12345678,
        }
    }
}

pub struct RootPort {
    pub rp_dev: TestPciDev,
    pub rp_misx_vector: MsixVector,
}

impl RootPort {
    fn new(
        machine: Rc<RefCell<TestStdMachine>>,
        alloc: Rc<RefCell<GuestAllocator>>,
        bus_num: u8,
        devfn: u8,
    ) -> Self {
        let mut root_port = TestPciDev::new(machine.clone().borrow().pci_bus.clone());
        root_port.set_bus_num(bus_num);
        root_port.devfn = devfn;
        assert_eq!(root_port.config_readw(PCI_SUB_CLASS_DEVICE), 0x0604);

        root_port.enable();
        root_port.enable_msix(None);
        let root_port_msix = MsixVector::new(0, alloc.clone());
        root_port.set_msix_vector(
            root_port_msix.msix_entry,
            root_port_msix.msix_addr,
            root_port_msix.msix_data,
        );

        Self {
            rp_dev: root_port,
            rp_misx_vector: root_port_msix,
        }
    }
}

fn build_root_port_args(root_port_nums: u8) -> Vec<String> {
    if root_port_nums == 0 {
        return Vec::new();
    }
    let mut multifunc = false;
    if root_port_nums > 32 {
        multifunc = true;
    }

    let mut root_port_args: Vec<String> = Vec::with_capacity(root_port_nums.try_into().unwrap());
    let mut addr = 1;
    let mut func = 0;
    for bus in 1..=root_port_nums {
        let mut arg = format!(
            "-device pcie-root-port,port=0x0,chassis=1,bus=pcie.0,addr={:#x}.{},id=pcie.{}",
            addr, func, bus
        );

        if func == 0 && multifunc {
            arg.push_str(",multifunction=on");
        }

        if multifunc {
            addr = bus / 8 + 1;
            func += 1;
            func = func % 8;
        } else {
            addr += 1;
            func = 0;
        }

        root_port_args.push(arg);
    }

    root_port_args
}

fn build_blk_args(
    blk_nums: u8,
    attach_in_rp: bool,
    multifunc: bool,
) -> Vec<(String, u8, u8, u8, u8, bool)> {
    if multifunc {
        assert!(blk_nums < MAX_DEVICE_NUM_IN_MULTIFUNC);
    } else {
        assert!(blk_nums < MAX_DEVICE_NUM);
    }

    let mut blk_args: Vec<(String, u8, u8, u8, u8, bool)> =
        Vec::with_capacity(blk_nums.try_into().unwrap());
    let mut slot = 0;
    let mut func = 0;
    let mut nums = 0;
    let mut bus = 0;

    if attach_in_rp {
        bus = 1;
    } else {
        slot = 1;
    }

    while nums < blk_nums {
        if multifunc {
            if func % 8 == 0 {
                blk_args.push((String::from("virtio-blk-pci"), nums, bus, slot, func, true));
            } else {
                blk_args.push((String::from("virtio-blk-pci"), nums, bus, slot, func, false));
            }
            func += 1;
            slot += func / 8
        } else {
            blk_args.push((String::from("virtio-blk-pci"), nums, bus, slot, func, false));
            bus += 1;
        }
        nums += 1;
    }

    blk_args
}

fn build_blk_driver_args(blk_nums: u8) -> (Vec<String>, Vec<String>) {
    let mut driver_args: Vec<String> = Vec::new();
    let mut image_paths: Vec<String> = Vec::new();

    for i in 0..blk_nums {
        let image_path = create_img(TEST_IMAGE_SIZE, 1);
        image_paths.push(image_path.clone());
        let driver_arg_str = format!(
            "-drive if=none,id=drive-{},file={},format=raw,direct=false",
            i, image_path
        );
        driver_args.push(driver_arg_str.clone());
    }

    (driver_args, image_paths)
}

fn build_hotplug_blk_cmd(
    hotplug_blk_id: u8,
    hotplug_image_path: String,
    bus_num: u8,
    slot: u8,
    func: u8,
) -> (String, String) {
    let add_blk_command = format!(
        "{{\"execute\": \"blockdev-add\", \
        \"arguments\": {{\"node-name\": \"drive-{}\", \"file\": {{\"driver\": \
        \"file\", \"filename\": \"{}\"}}, \"cache\": {{\"direct\": true}}, \
        \"read-only\": false}}}}",
        hotplug_blk_id, hotplug_image_path
    );

    let add_device_command = format!(
        "{{\"execute\":\"device_add\", \
        \"arguments\": {{\"id\":\"blk-{}\", \"driver\":\"virtio-blk-pci\", \
        \"drive\": \"drive-{}\", \"addr\":\"{:#x}.{:#x}\", \"bus\": \"pcie.{}\"}}}}",
        hotplug_blk_id, hotplug_blk_id, slot, func, bus_num
    );

    (add_blk_command, add_device_command)
}

fn build_hotunplug_blk_cmd(unplug_blk_id: u8) -> (String, String) {
    let delete_device_command = format!(
        "{{\"execute\": \"device_del\",\
        \"arguments\": {{\"id\":\"blk-{}\"}}}}",
        unplug_blk_id
    );

    let delete_blk_command = format!(
        "{{\"execute\": \"blockdev-del\",\
        \"arguments\": {{\"node-name\":\"drive-{}\"}}}}",
        unplug_blk_id
    );

    (delete_device_command, delete_blk_command)
}

fn build_all_device_args(
    root_port_nums: u8,
    pci_device_param: Vec<(String, u8, u8, u8, u8, bool)>,
) -> Vec<String> {
    let mut device_args: Vec<String> = Vec::new();
    let mut root_port_args = build_root_port_args(root_port_nums);
    if root_port_args.len() != 0 {
        device_args.append(&mut root_port_args);
    }

    for i in 0..pci_device_param.len() {
        let mut device_arg_str = format!(
            "-device {},id=blk-{},drive=drive-{},bus=pcie.{},addr={}.{}",
            pci_device_param.get(i).unwrap().0,
            pci_device_param.get(i).unwrap().1,
            pci_device_param.get(i).unwrap().1,
            pci_device_param.get(i).unwrap().2,
            pci_device_param.get(i).unwrap().3,
            pci_device_param.get(i).unwrap().4,
        );

        if pci_device_param.get(i).unwrap().5 {
            let multi_func_arg = String::from(",multifunction=on");
            device_arg_str.push_str(&multi_func_arg);
        }
        device_args.push(device_arg_str.clone());
    }

    device_args
}

fn create_blk(
    machine: Rc<RefCell<TestStdMachine>>,
    bus_num: u8,
    pci_slot: u8,
    pci_fn: u8,
) -> Rc<RefCell<TestVirtioPciDev>> {
    let virtio_blk = Rc::new(RefCell::new(TestVirtioPciDev::new(
        machine.clone().borrow().pci_bus.clone(),
    )));
    virtio_blk.borrow_mut().pci_dev.set_bus_num(bus_num);
    virtio_blk.borrow_mut().init(pci_slot, pci_fn);
    virtio_blk
}

fn create_machine(
    root_port_nums: u8,
    device_args: Vec<String>,
    driver_args: Vec<String>,
    other_args: Option<Vec<String>>,
) -> (
    Rc<RefCell<TestState>>,
    Rc<RefCell<TestStdMachine>>,
    Rc<RefCell<GuestAllocator>>,
) {
    let mut extra_args: Vec<&str> = Vec::new();

    let mut args: Vec<&str> = "-machine virt".split(' ').collect();
    extra_args.append(&mut args);

    for device_arg in device_args.iter() {
        let mut arg = device_arg[..].split(' ').collect();
        extra_args.append(&mut arg);
    }

    for driver_arg in driver_args.iter() {
        let mut arg = driver_arg[..].split(' ').collect();
        extra_args.append(&mut arg);
    }

    let mut args: Vec<String> = Vec::new();
    if other_args.is_some() {
        args = other_args.unwrap();
    }
    for other_arg in args.iter() {
        let mut arg = other_arg[..].split(' ').collect();
        extra_args.append(&mut arg);
    }

    let test_state = Rc::new(RefCell::new(test_init(extra_args)));
    let machine = Rc::new(RefCell::new(TestStdMachine::new(test_state.clone())));
    machine
        .borrow()
        .pci_bus
        .borrow()
        .pci_auto_bus_scan(root_port_nums as u8);
    let allocator = machine.borrow().allocator.clone();

    (test_state, machine, allocator)
}

fn set_up(
    root_port_nums: u8,
    blk_nums: u8,
    attach_in_rp: bool,
    multifunc: bool,
) -> (
    Rc<RefCell<TestState>>,
    Rc<RefCell<TestStdMachine>>,
    Rc<RefCell<GuestAllocator>>,
    Vec<String>,
) {
    let device_args = build_all_device_args(
        root_port_nums,
        build_blk_args(blk_nums, attach_in_rp, multifunc),
    );
    let (blk_driver_args, image_paths) = build_blk_driver_args(blk_nums);
    let (test_state, machine, alloc) =
        create_machine(root_port_nums, device_args, blk_driver_args, None);
    (test_state, machine, alloc, image_paths)
}

fn tear_down(
    blk: Option<Rc<RefCell<TestVirtioPciDev>>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vqs: Option<Vec<Rc<RefCell<TestVirtQueue>>>>,
    image_paths: Option<Vec<String>>,
) {
    if blk.is_some() {
        blk.clone().unwrap().borrow_mut().reset();
        blk.clone().unwrap().borrow_mut().pci_dev.disable_msix();
    }
    if vqs.is_some() {
        blk.clone()
            .unwrap()
            .borrow_mut()
            .destroy_device(alloc.clone(), vqs.unwrap());
    }

    test_state.borrow_mut().stop();
    if let Some(img_paths) = image_paths {
        img_paths.iter().enumerate().for_each(|(_i, image_path)| {
            cleanup_img(image_path.to_string());
        })
    }
}

fn validate_config_value_2byte(
    pci_bus: Rc<RefCell<TestPciBus>>,
    bus_num: u8,
    devfn: u8,
    offset: u8,
    expected_value: u16,
    mask: u16,
) {
    let config_value = pci_bus.borrow().config_readw(bus_num, devfn, offset);
    assert_eq!(config_value & mask, expected_value);
}

fn validate_config_perm_1byte(
    pci_dev: TestPciDev,
    offset: u8,
    expected_value: u8,
    writed_value: u8,
    mask: u8,
) {
    let config_value =
        pci_dev
            .pci_bus
            .borrow()
            .config_readb(pci_dev.bus_num, pci_dev.devfn, offset);
    assert_eq!(config_value & mask, expected_value);

    pci_dev
        .pci_bus
        .borrow()
        .config_writeb(pci_dev.bus_num, pci_dev.devfn, offset, writed_value);

    let config_value =
        pci_dev
            .pci_bus
            .borrow()
            .config_readb(pci_dev.bus_num, pci_dev.devfn, offset);
    assert_eq!(config_value & mask, expected_value);
}

fn validate_config_perm_2byte(
    pci_dev: TestPciDev,
    offset: u8,
    expected_value: u16,
    writed_value: u16,
    mask: u16,
) {
    pci_dev
        .pci_bus
        .borrow()
        .config_writew(pci_dev.bus_num, pci_dev.devfn, offset, writed_value);
    let config_value =
        pci_dev
            .pci_bus
            .borrow()
            .config_readw(pci_dev.bus_num, pci_dev.devfn, offset);
    assert_eq!(config_value & mask, expected_value);
}

fn validate_config_perm_4byte(
    pci_dev: TestPciDev,
    offset: u8,
    expected_value: u32,
    writed_value: u32,
    mask: u32,
) {
    let config_value =
        pci_dev
            .pci_bus
            .borrow()
            .config_readl(pci_dev.bus_num, pci_dev.devfn, offset);
    assert_eq!(config_value & mask, expected_value);

    pci_dev
        .pci_bus
        .borrow()
        .config_writel(pci_dev.bus_num, pci_dev.devfn, offset, writed_value);

    let config_value =
        pci_dev
            .pci_bus
            .borrow()
            .config_readl(pci_dev.bus_num, pci_dev.devfn, offset);
    assert_eq!(config_value & mask, expected_value);
}

fn get_slot_ctl_val(root_port: Rc<RefCell<RootPort>>) -> (u16, u8) {
    let rp_borrowed = root_port.borrow();
    let exp_cap_addr = rp_borrowed.rp_dev.find_capability(0x10, 0);
    let slot_ctl = rp_borrowed
        .rp_dev
        .config_readw(exp_cap_addr + PCI_EXP_SLTCTL);

    (slot_ctl, exp_cap_addr)
}

fn power_on_device(root_port: Rc<RefCell<RootPort>>) {
    let (slot_ctl, addr) = get_slot_ctl_val(root_port.clone());

    let mask = PCI_EXP_SLTCTL_PIC | PCI_EXP_SLTCTL_PCC;
    root_port.borrow().rp_dev.config_writew(
        addr + PCI_EXP_SLTCTL,
        (slot_ctl & !mask) | PCI_EXP_SLTCTL_PWR_IND_ON | PCI_EXP_SLTCTL_PWR_ON,
    );
}

fn power_off_device(root_port: Rc<RefCell<RootPort>>) {
    let (slot_ctl, addr) = get_slot_ctl_val(root_port.clone());

    let mask = PCI_EXP_SLTCTL_PIC | PCI_EXP_SLTCTL_PCC;
    root_port.borrow().rp_dev.config_writew(
        addr + PCI_EXP_SLTCTL,
        (slot_ctl & !mask) | PCI_EXP_SLTCTL_PWR_IND_OFF | PCI_EXP_SLTCTL_PWR_OFF,
    );
}

fn power_indicator_blink(root_port: Rc<RefCell<RootPort>>) {
    let (slot_ctl, addr) = get_slot_ctl_val(root_port.clone());

    let mask = PCI_EXP_SLTCTL_PIC;
    root_port.borrow().rp_dev.config_writew(
        addr + PCI_EXP_SLTCTL,
        (slot_ctl & !mask) | PCI_EXP_SLTCTL_PWR_IND_BLINK,
    );
}

fn power_indicator_off(root_port: Rc<RefCell<RootPort>>) {
    let (slot_ctl, addr) = get_slot_ctl_val(root_port.clone());

    let mask = PCI_EXP_SLTCTL_PIC;
    root_port.borrow().rp_dev.config_writew(
        addr + PCI_EXP_SLTCTL,
        (slot_ctl & !mask) | PCI_EXP_SLTCTL_PWR_IND_OFF,
    );
}

fn validate_blk_io_success(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
) {
    let features = virtio_blk_defalut_feature(blk.clone());
    let virtqueues = blk
        .borrow_mut()
        .init_device(test_state.clone(), alloc.clone(), features, 1);

    validate_std_blk_io(
        blk.clone(),
        test_state.clone(),
        virtqueues.clone(),
        alloc.clone(),
    );

    blk.borrow_mut().pci_dev.disable_msix();
    blk.borrow()
        .cleanup_virtqueue(alloc, virtqueues[0].borrow().desc);
}

fn simple_blk_io_req(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    virtqueue: Rc<RefCell<TestVirtQueue>>,
    alloc: Rc<RefCell<GuestAllocator>>,
) -> u32 {
    let (free_head, _req_addr) = add_blk_request(
        test_state.clone(),
        alloc.clone(),
        virtqueue.clone(),
        VIRTIO_BLK_T_OUT,
        0,
        false,
    );
    blk.borrow().virtqueue_notify(virtqueue.clone());

    free_head
}

fn wait_msix_timeout(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    virtqueue: Rc<RefCell<TestVirtQueue>>,
    timeout_us: u64,
) -> bool {
    let start_time = time::Instant::now();
    let timeout_us = time::Duration::from_micros(timeout_us);

    loop {
        if blk.borrow().queue_was_notified(virtqueue.clone()) {
            return false;
        }

        if time::Instant::now() - start_time > timeout_us {
            return true;
        }
    }
}

fn validate_std_blk_io(
    blk: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    virtqueues: Vec<Rc<RefCell<TestVirtQueue>>>,
    alloc: Rc<RefCell<GuestAllocator>>,
) {
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
}

fn wait_root_port_intr(root_port: Rc<RefCell<RootPort>>) -> bool {
    let start_time = time::Instant::now();
    let timeout_us = time::Duration::from_secs(TIMEOUT_S);
    let rp_borrowed = root_port.borrow();
    loop {
        if rp_borrowed.rp_dev.has_msix(
            rp_borrowed.rp_misx_vector.msix_addr,
            rp_borrowed.rp_misx_vector.msix_data,
        ) {
            return true;
        }
        if (time::Instant::now() - start_time) >= timeout_us {
            return false;
        }
    }
}

fn wait_cci_set(root_port: Rc<RefCell<RootPort>>) -> bool {
    let start_time = time::Instant::now();
    let timeout_us = time::Duration::from_secs(TIMEOUT_S);
    let rp_borrowed = root_port.borrow();
    let cci_mask = PCI_EXP_SLTSTA_CC;
    let cap_exp_addr = root_port.borrow().rp_dev.find_capability(PCI_CAP_ID_EXP, 0);

    loop {
        if rp_borrowed
            .rp_dev
            .config_readw(cap_exp_addr + PCI_EXP_SLTSTA)
            & cci_mask
            == 1
        {
            return true;
        }
        if (time::Instant::now() - start_time) >= timeout_us {
            return false;
        }
    }
}

fn lookup_all_cap_addr(cap_id: u8, pci_dev: TestPciDev) -> Vec<u8> {
    let mut addr = pci_dev.config_readb(PCI_CAPABILITY_LIST);
    let mut cap_addrs: Vec<u8> = Vec::new();
    loop {
        let cap = pci_dev.config_readb(addr);
        if cap == cap_id {
            cap_addrs.push(addr);
        }

        addr = pci_dev.config_readb(addr + PCI_CAP_LIST_NEXT);
        if addr == 0 {
            break;
        }
    }
    cap_addrs
}

fn get_msix_flag(pci_dev: TestPciDev) -> u16 {
    let addr = pci_dev.find_capability(PCI_CAP_ID_MSIX, 0);
    assert_ne!(addr, 0);
    let old_value = pci_dev.config_readw(addr + PCI_MSIX_MSG_CTL);
    old_value
}

fn set_msix_enable(pci_dev: TestPciDev) {
    let addr = pci_dev.find_capability(PCI_CAP_ID_MSIX, 0);
    let old_value = get_msix_flag(pci_dev.clone());
    pci_dev.config_writew(addr + PCI_MSIX_MSG_CTL, old_value | PCI_MSIX_MSG_CTL_ENABLE);
}

fn set_msix_disable(pci_dev: TestPciDev) {
    let addr = pci_dev.find_capability(PCI_CAP_ID_MSIX, 0);
    let old_value = get_msix_flag(pci_dev.clone());
    pci_dev.config_writew(
        addr + PCI_MSIX_MSG_CTL,
        old_value & !PCI_MSIX_MSG_CTL_ENABLE,
    );
}

fn mask_msix_global(pci_dev: TestPciDev) {
    let addr = pci_dev.find_capability(PCI_CAP_ID_MSIX, 0);
    let old_value = get_msix_flag(pci_dev.clone());
    pci_dev.config_writew(
        addr + PCI_MSIX_MSG_CTL,
        old_value | PCI_MSIX_MSG_CTL_MASKALL,
    );
}

fn unmask_msix_global(pci_dev: TestPciDev) {
    let addr = pci_dev.find_capability(PCI_CAP_ID_MSIX, 0);
    let old_value = get_msix_flag(pci_dev.clone());
    pci_dev.config_writew(
        addr + PCI_MSIX_MSG_CTL,
        old_value & !PCI_MSIX_MSG_CTL_MASKALL,
    );
}

fn mask_msix_vector(pci_dev: TestPciDev, vector: u16) {
    let offset: u64 = pci_dev.msix_table_off + (vector * PCI_MSIX_ENTRY_SIZE) as u64;

    let vector_mask = pci_dev.io_readl(
        pci_dev.msix_table_bar,
        offset + PCI_MSIX_ENTRY_VECTOR_CTRL as u64,
    );

    pci_dev.io_writel(
        pci_dev.msix_table_bar,
        offset + PCI_MSIX_ENTRY_VECTOR_CTRL as u64,
        vector_mask | PCI_MSIX_ENTRY_CTRL_MASKBIT,
    );
}

fn unmask_msix_vector(pci_dev: TestPciDev, vector: u16) {
    let offset: u64 = pci_dev.msix_table_off + (vector * PCI_MSIX_ENTRY_SIZE) as u64;

    let vector_control = pci_dev.io_readl(
        pci_dev.msix_table_bar,
        offset + PCI_MSIX_ENTRY_VECTOR_CTRL as u64,
    );

    pci_dev.io_writel(
        pci_dev.msix_table_bar,
        offset + PCI_MSIX_ENTRY_VECTOR_CTRL as u64,
        vector_control & !PCI_MSIX_ENTRY_CTRL_MASKBIT,
    );
}

fn hotplug_blk(
    test_state: Rc<RefCell<TestState>>,
    root_port: Rc<RefCell<RootPort>>,
    image_paths: &mut Vec<String>,
    hotplug_blk_id: u8,
    bus: u8,
    slot: u8,
    func: u8,
) {
    let hotplug_image_path = create_img(TEST_IMAGE_SIZE, 1);
    image_paths.push(hotplug_image_path.clone());

    // Hotplug a block device whose bdf is 2:0:0.
    let (add_blk_command, add_device_command) =
        build_hotplug_blk_cmd(hotplug_blk_id, hotplug_image_path.clone(), bus, slot, func);
    let ret = test_state.borrow().qmp(&add_blk_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    let ret = test_state.borrow().qmp(&add_device_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    // Verify the vendor id for the virtio block device hotplugged.
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        bus,
        slot << 3 | func,
        PCI_VENDOR_ID,
        VIRTIO_PCI_VENDOR,
        0xFFFF,
    );

    assert!(
        wait_root_port_intr(root_port.clone()),
        "Wait for interrupt of root port timeout"
    );
    power_on_device(root_port.clone());
}

fn hotunplug_blk(
    test_state: Rc<RefCell<TestState>>,
    blk: Rc<RefCell<TestVirtioPciDev>>,
    root_port: Rc<RefCell<RootPort>>,
    hotunplug_blk_id: u8,
) {
    // Hotunplug the virtio block device.
    let (delete_device_command, delete_blk_command) = build_hotunplug_blk_cmd(hotunplug_blk_id);
    let ret = test_state.borrow().qmp(&delete_device_command);

    assert!(
        wait_root_port_intr(root_port.clone()),
        "Wait for interrupt of root port timeout"
    );

    power_off_device(root_port.clone());

    assert_eq!(*ret.get("return").unwrap(), json!({}));
    test_state.borrow().wait_qmp_event();

    let ret = test_state.borrow().qmp(&delete_blk_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    wait_cci_set(root_port.clone());

    // Verify the vendor id for the virtio block device.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        0xFFFF,
        0xFFFF,
    );
}

/// Query the config of the device which has attached the bus.
#[test]
fn test_pci_device_discovery_001() {
    let blk_nums = 1;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(blk_nums, root_port_nums, true, false);

    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);

    // Verify the vendor id for non-existent devices.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        1,
        1 << 3 | 0,
        PCI_VENDOR_ID,
        0xFFFF,
        0xFFFF,
    );

    // Verify the vendor id for the virtio block device.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        VIRTIO_PCI_VENDOR,
        0xFFFF,
    );

    // Verify the device id for the virtio block device.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_DEVICE_ID,
        BLK_DEVICE_ID,
        0xFFFF,
    );

    tear_down(Some(blk), test_state, alloc, None, Some(image_paths));
}

/// Hotunplug the device which has attached the bus and hotplug another block device.
#[test]
fn test_pci_device_discovery_002() {
    let blk_nums = 1;
    let root_port_nums = 2;
    let (test_state, machine, alloc, mut image_paths) =
        set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:1:0.
    let root_port = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));

    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);

    // Verify the vendor id for the virtio block device.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        VIRTIO_PCI_VENDOR,
        0xFFFF,
    );

    // Hotplug a block device whose id is 0.
    hotunplug_blk(test_state.clone(), blk.clone(), root_port.clone(), 0);

    // Hotplug a block device whose id is 1 and bdf is 2:0:0.
    hotplug_blk(
        test_state.clone(),
        root_port.clone(),
        &mut image_paths,
        1,
        2,
        0,
        0,
    );

    // Create a block device whose bdf is 2:0:0.
    let blk = create_blk(machine.clone(), 2, 0, 0);
    // Verify the vendor id for the virtio block device hotplugged.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        VIRTIO_PCI_VENDOR,
        0xFFFF,
    );

    tear_down(Some(blk), test_state, alloc, None, Some(image_paths));
}

/// Repeat hotplug the same device and query the related ecam space(vendor id).
#[test]
fn test_pci_device_discovery_003() {
    let blk_nums = 1;
    let root_port_nums = 1;
    let (test_state, machine, alloc, mut image_paths) =
        set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:1:0.
    let root_port = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));

    // Verify the vendor id for the virtio block device hotplugged.
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port_nums,
        0,
        PCI_VENDOR_ID,
        VIRTIO_PCI_VENDOR,
        0xFFFF,
    );

    let blk_id = 1;
    let hotplug_image_path = create_img(TEST_IMAGE_SIZE, 1);
    image_paths.push(hotplug_image_path.clone());

    // Hotplug a block device whose bdf is 1:0:0.
    let (add_blk_command, add_device_command) =
        build_hotplug_blk_cmd(blk_id, hotplug_image_path.clone(), 1, 0, 0);
    let ret = test_state.borrow().qmp(&add_blk_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));
    let ret = test_state.borrow().qmp(&add_device_command);
    assert!(!(*ret.get("error").unwrap()).is_null());

    // Verify the vendor id for the virtio block device hotplugged.
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port_nums,
        0,
        PCI_VENDOR_ID,
        VIRTIO_PCI_VENDOR,
        0xFFFF,
    );

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Hotplug and hotunplug the same device.
#[test]
fn test_pci_device_discovery_004() {
    let blk_nums = 0;
    let root_port_nums = 1;
    let (test_state, machine, alloc, mut image_paths) =
        set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:1:0.
    let root_port = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));

    let blk_id = 0;
    let hotplug_image_path = create_img(TEST_IMAGE_SIZE, 1);
    image_paths.push(hotplug_image_path.clone());

    // Hotplug a block device whose id is 0 and bdf is 1:0:0.
    hotplug_blk(
        test_state.clone(),
        root_port.clone(),
        &mut image_paths,
        blk_id,
        1,
        0,
        0,
    );

    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);

    // Hotunplug the virtio block device whose id is 0.
    hotunplug_blk(test_state.clone(), blk.clone(), root_port.clone(), blk_id);

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Check the permission and initial value of type0 pci device's configuration space.
#[test]
fn test_pci_type0_config() {
    let blk_nums = 1;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);

    // Verify that the vendor id of type0 device is read-only.
    validate_config_perm_2byte(
        blk.borrow().pci_dev.clone(),
        PCI_VENDOR_ID,
        VIRTIO_PCI_VENDOR,
        0x1234,
        0xFFFF,
    );
    // Verify that the device id of type0 device is read-only.
    validate_config_perm_2byte(
        blk.borrow().pci_dev.clone(),
        PCI_DEVICE_ID,
        BLK_DEVICE_ID,
        0x1234,
        0xFFFF,
    );

    // verify that the lower three bits of the command register of type0 device is readable and writable.
    validate_config_perm_2byte(blk.borrow().pci_dev.clone(), PCI_COMMAND, 0x4, 0x4, 0x7);

    // verify that the interrupt status of the status register of type0 device is read-only.
    let intr_status = blk.borrow().pci_dev.pci_bus.borrow().config_readw(
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_STATUS,
    ) & PCI_STATUS_INTERRUPT;
    validate_config_perm_2byte(
        blk.borrow().pci_dev.clone(),
        PCI_STATUS,
        intr_status,
        !intr_status,
        PCI_STATUS_INTERRUPT,
    );

    // verify that the capabilities list of the status register of type0 device is read-only.
    let cap_list = blk.borrow().pci_dev.pci_bus.borrow().config_readw(
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_STATUS,
    ) & PCI_STATUS_CAP_LIST;
    validate_config_perm_2byte(
        blk.borrow().pci_dev.clone(),
        PCI_STATUS,
        cap_list,
        !cap_list,
        PCI_STATUS_CAP_LIST,
    );

    // verify that the revision id of type0 device is read-only.
    let revision_id = blk.borrow().pci_dev.pci_bus.borrow().config_readb(
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_REVISION_ID,
    );
    validate_config_perm_1byte(
        blk.borrow().pci_dev.clone(),
        PCI_REVISION_ID,
        1,
        !revision_id,
        0xff,
    );

    let sub_class = blk.borrow().pci_dev.pci_bus.borrow().config_readb(
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_SUB_CLASS_DEVICE,
    );
    // verify that the sub class id of type0 device is read-only.
    validate_config_perm_1byte(
        blk.borrow().pci_dev.clone(),
        PCI_SUB_CLASS_DEVICE,
        sub_class,
        !sub_class,
        0xFF,
    );

    // verify that the header type of type0 device is read-only.
    let header_type = blk.borrow().pci_dev.pci_bus.borrow().config_readb(
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_HEADER_TYPE,
    );
    validate_config_perm_1byte(
        blk.borrow().pci_dev.clone(),
        PCI_HEADER_TYPE,
        header_type,
        !header_type,
        0xff,
    );

    // verify that the capabilities pointer of type0 device is read-only.
    let cap_pointer = blk.borrow().pci_dev.pci_bus.borrow().config_readb(
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_CAPABILITY_LIST,
    );
    validate_config_perm_1byte(
        blk.borrow().pci_dev.clone(),
        PCI_CAPABILITY_LIST,
        cap_pointer,
        !cap_pointer,
        0xFF,
    );

    // verify that the sub vendor id of type0 device is read-only.
    let sub_vender_id = blk.borrow().pci_dev.pci_bus.borrow().config_readw(
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_SUBSYSTEM_VENDOR_ID,
    );
    validate_config_perm_2byte(
        blk.borrow().pci_dev.clone(),
        PCI_SUBSYSTEM_VENDOR_ID,
        sub_vender_id,
        !sub_vender_id,
        0xFFFF,
    );
    // verify that the sub system id of type0 device is read-only.
    let sub_system_id = blk.borrow().pci_dev.pci_bus.borrow().config_readw(
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_SUBSYSTEM_ID,
    );
    validate_config_perm_2byte(
        blk.borrow().pci_dev.clone(),
        PCI_SUBSYSTEM_ID,
        sub_system_id,
        !sub_system_id,
        0xFFFF,
    );

    tear_down(Some(blk), test_state, alloc, None, Some(image_paths));
}

/// Check the permission and initial value of type1 pci device's configuration space.
#[test]
fn test_pci_type1_config() {
    let blk_nums = 0;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:1:0.
    let root_port = RootPort::new(machine.clone(), alloc.clone(), 0, 1 << 3 | 0);

    assert_eq!(root_port.rp_dev.config_readb(PCI_PRIMARY_BUS), 0);
    assert_ne!(root_port.rp_dev.config_readb(PCI_SECONDARY_BUS), 0);
    assert_ne!(root_port.rp_dev.config_readb(PCI_SUBORDINATE_BUS), 0);

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

#[test]
fn test_pci_type1_reset() {
    let blk_nums = 1;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:1:0.
    let root_port = RootPort::new(machine.clone(), alloc.clone(), 0, 1 << 3 | 0);

    let command = root_port.rp_dev.config_readw(PCI_COMMAND);
    let cmd_memory = command & PCI_COMMAND_MEMORY as u16;

    // Bitwise inversion of memory space enable.
    let write_cmd = command | (command & (!PCI_COMMAND_MEMORY as u16)) | !cmd_memory;
    root_port.rp_dev.config_writew(PCI_COMMAND, write_cmd);
    let old_command = root_port.rp_dev.config_readw(PCI_COMMAND);
    assert_ne!(old_command, write_cmd);

    root_port
        .rp_dev
        .config_writeb(PCI_BRIDGE_CONTROL, BRIDGE_CTL_SEC_BUS_RESET);

    // Sleep three seconds to wait root port reset second bus.
    let sleep_s = time::Duration::from_secs(3);
    thread::sleep(sleep_s);

    let new_command = root_port.rp_dev.config_readw(PCI_COMMAND);
    // verify that the block device is reset.
    assert_ne!(old_command, new_command);

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Verify that out-of-bounds access to the configuration space
#[test]
fn test_out_boundry_config_access() {
    let blk_nums = 0;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    let devfn = 1 << 3 | 1;
    let addr = machine.borrow().pci_bus.borrow().ecam_alloc_ptr
        + ((0 as u32) << 20 | (devfn as u32) << 12 | 0 as u32) as u64
        - 1;

    let write_value = u16::max_value();
    let buf = write_value.to_le_bytes();
    test_state.borrow().memwrite(addr, &buf);

    let mut buf: &[u8] = &test_state.borrow().memread(addr, 2)[0..2];
    let read_value = read_le_u16(&mut buf);
    assert_ne!(write_value, read_value);

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Verify that out-of-size access to the configuration space
#[test]
fn test_out_size_config_access() {
    let blk_nums = 0;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:1:0.
    let root_port = RootPort::new(machine.clone(), alloc.clone(), 0, 1 << 3 | 0);

    let vendor_device_id = root_port.rp_dev.config_readl(PCI_VENDOR_ID);
    let command_status = root_port.rp_dev.config_readl(PCI_COMMAND);
    let value = root_port.rp_dev.config_readq(0);
    assert_ne!(
        value,
        (vendor_device_id as u64) << 32 | command_status as u64
    );

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Verify that out-of-bounds access to the msix bar space.
#[test]
fn test_out_boundry_msix_access() {
    let blk_nums = 0;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:1:0.
    let root_port = RootPort::new(machine.clone(), alloc.clone(), 0, 1 << 3 | 0);

    // Out-of-bounds access to the msix table.
    let write_value = u32::max_value();
    root_port.rp_dev.io_writel(
        root_port.rp_dev.msix_table_bar,
        PCI_MSIX_ENTRY_VECTOR_CTRL + 2,
        write_value,
    );
    let read_value = root_port.rp_dev.io_readl(
        root_port.rp_dev.msix_table_bar,
        PCI_MSIX_ENTRY_VECTOR_CTRL + 2,
    );
    assert_ne!(write_value, read_value);

    // Out-of-bounds access to the msix pba.
    let _read_value = root_port
        .rp_dev
        .io_readq(root_port.rp_dev.msix_table_bar, 4);

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

#[test]
fn test_repeat_io_map_bar() {
    let blk_nums = 1;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);

    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );
    // Verify that the function of the block device is normal.
    validate_std_blk_io(blk.clone(), test_state.clone(), vqs.clone(), alloc.clone());

    let old_feature = blk.borrow().get_guest_features();
    let old_bar_addr = blk.borrow().bar;

    // IO map the bar of virtio block device again.
    let bar_idx = blk.borrow().bar_idx;
    let bar_addr = blk.borrow().pci_dev.io_map(bar_idx);
    blk.borrow_mut().bar = bar_addr;
    // Verify that the configuration of virtio block can be read normally.
    assert_eq!(blk.borrow().get_guest_features(), old_feature);
    // Verify that the common config bar of virtio block has changed.
    assert_ne!(blk.borrow().bar, old_bar_addr);

    // Verify that the function of the block device is normal.
    validate_std_blk_io(blk.clone(), test_state.clone(), vqs.clone(), alloc.clone());

    tear_down(Some(blk), test_state, alloc, Some(vqs), Some(image_paths));
}

#[test]
fn test_pci_type0_msix_config() {
    let blk_nums = 1;
    let root_port_nums = 0;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, false, false);
    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 0, 1, 0);

    // Verify that there is only one msix capability addr of the type0 pci device.
    let blk_cap_msix_addrs = lookup_all_cap_addr(PCI_CAP_ID_MSIX, blk.borrow().pci_dev.clone());
    assert_eq!(blk_cap_msix_addrs.len(), 1);

    // Verify that the table size of msix is read-only.
    let table_size = blk
        .borrow()
        .pci_dev
        .config_readw(blk_cap_msix_addrs[0] + PCI_MSIX_MSG_CTL)
        & PCI_MSIX_MSG_CTL_TSIZE;
    validate_config_perm_2byte(
        blk.borrow().pci_dev.clone(),
        blk_cap_msix_addrs[0] + PCI_MSIX_MSG_CTL,
        table_size,
        !table_size,
        PCI_MSIX_MSG_CTL_TSIZE,
    );

    // Verify that the table size of msix is read-only.
    let msix_table = blk
        .borrow()
        .pci_dev
        .config_readl(blk_cap_msix_addrs[0] + PCI_MSIX_TABLE);
    let msix_table_bir = msix_table & PCI_MSIX_TABLE_BIR;
    // Verify that the bir of table of the type0 pci device is less than or equal to 5.
    assert!(msix_table_bir <= 5);
    // Verify that the msix table of the type0 pci device is read-only.
    validate_config_perm_4byte(
        blk.borrow().pci_dev.clone(),
        blk_cap_msix_addrs[0] + PCI_MSIX_TABLE,
        msix_table,
        !msix_table,
        0xFFFFFFFF,
    );

    let msix_pba = blk
        .borrow()
        .pci_dev
        .config_readl(blk_cap_msix_addrs[0] + PCI_MSIX_PBA);
    let msix_pba_bir = msix_pba & PCI_MSIX_PBA_BIR;
    // Verify that the bir of pba of the type0 pci device is less than or equal to 5.
    assert!(msix_pba_bir <= 5);
    // Verify that the msix pba of the type0 pci device is read-only.
    validate_config_perm_4byte(
        blk.borrow().pci_dev.clone(),
        blk_cap_msix_addrs[0] + PCI_MSIX_PBA,
        msix_pba,
        !msix_pba,
        0xFFFFFFFF,
    );

    tear_down(Some(blk), test_state, alloc, None, Some(image_paths));
}

/// Test whether the Function Mask bit in the control register for MSI-X works well,
/// which means that when it's set, msix pends notification, and starts to notify as
/// soon as the mask bit is cleared by the OS.
#[test]
fn test_pci_msix_global_ctl() {
    let blk_nums = 1;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);
    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    set_msix_disable(blk.borrow().pci_dev.clone());
    let mut free_head = simple_blk_io_req(
        blk.clone(),
        test_state.clone(),
        vqs[0].clone(),
        alloc.clone(),
    );
    // Verify that the os can not receive msix interrupt when msix is disabled.
    assert!(wait_msix_timeout(blk.clone(), vqs[0].clone(), TIMEOUT_S));

    set_msix_enable(blk.borrow().pci_dev.clone());
    // Verify that the os can receive msix interrupt when msix is enabled.
    assert!(!wait_msix_timeout(blk.clone(), vqs[0].clone(), TIMEOUT_S));
    blk.borrow().poll_used_elem(
        test_state.clone(),
        vqs[0].clone(),
        free_head,
        TIMEOUT_S,
        &mut None,
        false,
    );

    mask_msix_global(blk.borrow().pci_dev.clone());

    free_head = simple_blk_io_req(
        blk.clone(),
        test_state.clone(),
        vqs[0].clone(),
        alloc.clone(),
    );
    // Verify that the os can not receive msix interrupt when the function of vectors is masked.
    assert!(wait_msix_timeout(blk.clone(), vqs[0].clone(), TIMEOUT_S));

    unmask_msix_global(blk.borrow().pci_dev.clone());
    // Verify that the os can receive msix interrupt when the function of vectors is unmasked.
    assert!(!wait_msix_timeout(blk.clone(), vqs[0].clone(), TIMEOUT_S));
    blk.borrow().poll_used_elem(
        test_state.clone(),
        vqs[0].clone(),
        free_head,
        TIMEOUT_S,
        &mut None,
        false,
    );

    tear_down(Some(blk), test_state, alloc, Some(vqs), Some(image_paths));
}

/// Test whether the Mask bit in the vector register in msix table works well,
/// which means that when it's set, msix pends notification of the related vecotr,
/// and starts to notify as soon as the mask bit is cleared by the OS.
#[test]
fn test_pci_msix_local_ctl() {
    let blk_nums = 1;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);
    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    mask_msix_vector(blk.borrow().pci_dev.clone(), 1);
    let free_head = simple_blk_io_req(
        blk.clone(),
        test_state.clone(),
        vqs[0].clone(),
        alloc.clone(),
    );
    // Verify that the os can not receive msix interrupt when the vectors of virtqueue is masked.
    assert!(wait_msix_timeout(blk.clone(), vqs[0].clone(), TIMEOUT_S));

    unmask_msix_vector(blk.borrow().pci_dev.clone(), 1);
    // Verify that the os canreceive msix interrupt when the vectors of virtqueue is unmasked.
    assert!(!wait_msix_timeout(blk.clone(), vqs[0].clone(), TIMEOUT_S));
    blk.borrow().poll_used_elem(
        test_state.clone(),
        vqs[0].clone(),
        free_head,
        TIMEOUT_S,
        &mut None,
        false,
    );

    tear_down(Some(blk), test_state, alloc, Some(vqs), Some(image_paths));
}

#[test]
fn test_alloc_abnormal_vector() {
    let blk_nums = 1;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);

    // 1. Init device.
    blk.borrow_mut().reset();
    blk.borrow_mut().set_acknowledge();
    blk.borrow_mut().set_driver();
    blk.borrow_mut().negotiate_features(1 << VIRTIO_F_VERSION_1);
    blk.borrow_mut().set_features_ok();
    blk.borrow_mut().pci_dev.enable_msix(None);
    blk.borrow_mut()
        .setup_msix_configuration_vector(alloc.clone(), 0);

    let queue_num = blk.borrow().get_queue_nums();

    let virtqueue = blk
        .borrow()
        .setup_virtqueue(test_state.clone(), alloc.clone(), 0 as u16);
    blk.borrow()
        .setup_virtqueue_intr((queue_num + 2) as u16, alloc.clone(), virtqueue.clone());
    blk.borrow().set_driver_ok();

    let _free_head = simple_blk_io_req(
        blk.clone(),
        test_state.clone(),
        virtqueue.clone(),
        alloc.clone(),
    );
    // Verify that the os can not receive msix interrupt when the vectors of virtqueue is .
    assert!(wait_msix_timeout(blk.clone(), virtqueue.clone(), TIMEOUT_S));

    blk.borrow_mut()
        .cleanup_virtqueue(alloc.clone(), virtqueue.borrow().desc);
    tear_down(Some(blk), test_state, alloc, None, Some(image_paths));
}

/// Basic hotplug testcase.
#[test]
fn test_pci_hotplug_001() {
    let blk_nums = 0;
    let root_port_nums = 1;
    let (test_state, machine, alloc, mut image_paths) =
        set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:2:0.
    let root_port = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));

    // Hotplug a block device whose id is 1 and bdf is 1:0:0.
    hotplug_blk(
        test_state.clone(),
        root_port.clone(),
        &mut image_paths,
        0,
        1,
        0,
        0,
    );

    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);
    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );

    validate_std_blk_io(blk.clone(), test_state.clone(), vqs.clone(), alloc.clone());

    tear_down(Some(blk), test_state, alloc, Some(vqs), Some(image_paths));
}

/// Hotplug two devices at the same time.
#[test]
fn test_pci_hotplug_002() {
    let blk_nums = 0;
    let root_port_nums = 2;
    let (test_state, machine, alloc, mut image_paths) =
        set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:1:0.
    let root_port_1 = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));

    // Create a root port whose bdf is 0:2:0.
    let root_port_2 = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        2 << 3 | 0,
    )));

    // Hotplug a block device whose id is 1 and bdf is 1:0:0.
    hotplug_blk(
        test_state.clone(),
        root_port_1.clone(),
        &mut image_paths,
        1,
        1,
        0,
        0,
    );
    let blk_1 = create_blk(machine.clone(), 1, 0, 0);

    // Hotplug a block device whose id is 2 and bdf is 2:0:0.
    hotplug_blk(
        test_state.clone(),
        root_port_2.clone(),
        &mut image_paths,
        2,
        2,
        0,
        0,
    );
    let blk_2 = create_blk(machine.clone(), 2, 0, 0);

    validate_blk_io_success(blk_1.clone(), test_state.clone(), alloc.clone());
    validate_blk_io_success(blk_2.clone(), test_state.clone(), alloc.clone());

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Hotplug the device in non-zero slot.
#[test]
fn test_pci_hotplug_003() {
    let blk_nums = 0;
    let root_port_nums = 1;
    let (test_state, _machine, alloc, mut image_paths) =
        set_up(root_port_nums, blk_nums, true, false);

    let hotplug_image_path = create_img(TEST_IMAGE_SIZE, 1);
    image_paths.push(hotplug_image_path.clone());

    // Hotplug a block device whose id is 0, bdf is 1:1:0.
    let (add_blk_command, add_device_command) =
        build_hotplug_blk_cmd(0, hotplug_image_path.clone(), 1, 1, 0);
    let ret = test_state.borrow().qmp(&add_blk_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));
    // Verify that hotpluging the device in non-zero slot will fail.
    let ret = test_state.borrow().qmp(&add_device_command);
    assert!(!(*ret.get("error").unwrap()).is_null());

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Hotplug the device in the bus 0.
#[test]
fn test_pci_hotplug_004() {
    let blk_nums = 0;
    let root_port_nums = 0;
    let (test_state, _machine, alloc, mut image_paths) =
        set_up(root_port_nums, blk_nums, true, false);

    let hotplug_image_path = create_img(TEST_IMAGE_SIZE, 1);
    image_paths.push(hotplug_image_path.clone());

    let hotplug_blk_id = 1;
    let (add_blk_command, add_device_command) =
        build_hotplug_blk_cmd(hotplug_blk_id, hotplug_image_path.clone(), 0, 1, 0);
    let ret = test_state.borrow().qmp(&add_blk_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));
    let ret = test_state.borrow().qmp(&add_device_command);
    assert!(!(*ret.get("error").unwrap()).is_null());

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Hotplug a device which dosn't have the backend file.
#[test]
fn test_pci_hotplug_005() {
    let blk_nums = 0;
    let root_port_nums = 1;
    let (test_state, _machine, alloc, mut image_paths) =
        set_up(root_port_nums, blk_nums, true, false);

    let hotplug_image_path = create_img(TEST_IMAGE_SIZE, 1);
    image_paths.push(hotplug_image_path.clone());

    let hotplug_blk_id = 0;
    let (add_blk_command, add_device_command) =
        build_hotplug_blk_cmd(hotplug_blk_id, String::from(""), 1, 0, 0);

    let ret = test_state.borrow().qmp(&add_blk_command);
    assert!(!(*ret.get("error").unwrap()).is_null());
    let ret = test_state.borrow().qmp(&add_device_command);
    assert!(!(*ret.get("error").unwrap()).is_null());

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Hotplug a device which dosn't have the backend file.
#[test]
fn test_pci_hotplug_006() {
    let blk_nums = 0;
    let root_port_nums = 1;
    let (test_state, _machine, alloc, mut image_paths) =
        set_up(root_port_nums, blk_nums, true, false);

    let hotplug_image_path = create_img(TEST_IMAGE_SIZE, 1);
    image_paths.push(hotplug_image_path.clone());

    let hotplug_blk_id = 0;
    let (add_blk_command, add_device_command) =
        build_hotplug_blk_cmd(hotplug_blk_id, hotplug_image_path, 2, 0, 0);

    let ret = test_state.borrow().qmp(&add_blk_command);

    assert_eq!(*ret.get("return").unwrap(), json!({}));
    let ret = test_state.borrow().qmp(&add_device_command);
    assert!(!(*ret.get("error").unwrap()).is_null());

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Basic hotunplug testcase.
#[test]
fn test_pci_hotunplug_001() {
    let blk_nums = 1;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create root port whose  bdf is 0:1:0.
    let root_port = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));

    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);

    // Hotunplug the block device whose bdf is 1:0:0.
    hotunplug_blk(test_state.clone(), blk.clone(), root_port.clone(), 0);

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Hotunplug a device that does not exist.
#[test]
fn test_pci_hotunplug_002() {
    let blk_nums = 0;
    let root_port_nums = 1;
    let (test_state, _machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Hotunplug a device that does not exist.
    let (delete_device_command, delete_blk_command) = build_hotunplug_blk_cmd(0);
    let ret = test_state.borrow().qmp(&delete_device_command);
    assert!(!(*ret.get("error").unwrap()).is_null());
    let ret = test_state.borrow().qmp(&delete_blk_command);
    assert!(!(*ret.get("error").unwrap()).is_null());

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Hotunplug a device but power indicator of root port is abnormal.
#[test]
fn test_pci_hotunplug_003() {
    let blk_nums = 1;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:2:0.
    let root_port = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));

    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);

    let unplug_blk_id = 0;
    // Hotunplug the block device attaching the root port.
    let (delete_device_command, delete_blk_command) = build_hotunplug_blk_cmd(unplug_blk_id);
    let ret = test_state.borrow().qmp(&delete_device_command);
    assert!(
        wait_root_port_intr(root_port.clone()),
        "Wait for interrupt of root port timeout"
    );
    // The block device will not be unplugged when it is power on.
    power_on_device(root_port.clone());
    assert_eq!(*ret.get("return").unwrap(), json!({}));
    let ret = test_state.borrow().qmp(&delete_blk_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    // Verify the vendor id for the virtio block device is correct.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        VIRTIO_PCI_VENDOR,
        0xFFFF,
    );

    let (delete_device_command, delete_blk_command) = build_hotunplug_blk_cmd(unplug_blk_id);
    let ret = test_state.borrow().qmp(&delete_device_command);
    assert!(
        wait_root_port_intr(root_port.clone()),
        "Wait for interrupt of root port timeout"
    );
    // The block device will not be unplugged when indicator of power is blinking.
    power_indicator_blink(root_port.clone());
    assert_eq!(*ret.get("return").unwrap(), json!({}));
    let ret = test_state.borrow().qmp(&delete_blk_command);
    assert!(!(*ret.get("error").unwrap()).is_null());

    // Verify the vendor id for the virtio block device.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        VIRTIO_PCI_VENDOR,
        0xFFFF,
    );

    let (delete_device_command, _delete_blk_command) = build_hotunplug_blk_cmd(unplug_blk_id);
    let ret = test_state.borrow().qmp(&delete_device_command);
    assert!(!(*ret.get("error").unwrap()).is_null());

    // The block device will be unplugged when indicator of power and slot is power off.
    power_off_device(root_port.clone());
    test_state.borrow().wait_qmp_event();

    // Verify the vendor id for the virtio block device.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        0xFFFF,
        0xFFFF,
    );

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Hotunplug two device at the same time.
#[test]
fn test_pci_hotunplug_004() {
    let blk_nums = 2;
    let root_port_nums = 2;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create root port whose bdf is 0:1:0.
    let root_port_1 = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));

    // Create root port whose bdf is 0:2:0.
    let root_port_2 = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        2 << 3 | 0,
    )));

    // Create a block device whose bdf is 1:0:0.
    let blk_1 = create_blk(machine.clone(), 1, 0, 0);

    // Create a block device whose bdf is 2:0:0.
    let blk_2 = create_blk(machine.clone(), 2, 0, 0);

    let unplug_blk_id = 0;
    let (delete_device_command, delete_blk_command_1) = build_hotunplug_blk_cmd(unplug_blk_id);
    let ret = test_state.borrow().qmp(&delete_device_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    let unplug_blk_id = 1;
    let (delete_device_command, delete_blk_command_2) = build_hotunplug_blk_cmd(unplug_blk_id);
    let ret = test_state.borrow().qmp(&delete_device_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    assert!(
        wait_root_port_intr(root_port_1.clone()),
        "Wait for interrupt of root port timeout"
    );

    assert!(
        wait_root_port_intr(root_port_2.clone()),
        "Wait for interrupt of root port timeout"
    );

    power_off_device(root_port_1.clone());
    test_state.borrow().wait_qmp_event();

    power_off_device(root_port_2.clone());
    test_state.borrow().wait_qmp_event();

    // The block device will be unplugged when indicator of power and slot is power off.
    let ret = test_state.borrow().qmp(&delete_blk_command_1);
    assert_eq!(*ret.get("return").unwrap(), json!({}));
    // The block device will be unplugged when indicator of power and slot is power off.
    let ret = test_state.borrow().qmp(&delete_blk_command_2);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    // Verify the vendor id for the virtio block device.
    validate_config_value_2byte(
        blk_1.borrow().pci_dev.pci_bus.clone(),
        blk_1.borrow().pci_dev.bus_num,
        blk_1.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        0xFFFF,
        0xFFFF,
    );

    // Verify the vendor id for the virtio block device.
    validate_config_value_2byte(
        blk_2.borrow().pci_dev.pci_bus.clone(),
        blk_2.borrow().pci_dev.bus_num,
        blk_2.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        0xFFFF,
        0xFFFF,
    );

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Repeate hotunplug the same device.
#[test]
fn test_pci_hotunplug_005() {
    let blk_nums = 1;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create root port whose bdf is 0:1:0.
    let root_port = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));

    let blk = create_blk(machine.clone(), 1, 0, 0);

    // Hotplug the block device whose id is 0 and bdf is 1:0:0.
    hotunplug_blk(test_state.clone(), blk.clone(), root_port.clone(), 0);

    let (delete_device_command, _delete_blk_command) = build_hotunplug_blk_cmd(0);
    let ret = test_state.borrow().qmp(&delete_device_command);
    assert!(!(*ret.get("error").unwrap()).is_null());

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Hotunplug the device attaching the host bus
#[test]
fn test_pci_hotunplug_006() {
    let blk_nums = 1;
    let root_port_nums = 0;
    let (test_state, _machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, false, false);

    let unplug_blk_id = 0;
    let (delete_device_command, _delete_blk_command) = build_hotunplug_blk_cmd(unplug_blk_id);
    let ret = test_state.borrow().qmp(&delete_device_command);
    assert!(!(*ret.get("error").unwrap()).is_null());

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Guest sets PIC/PCC twice during hotunplug, the device ignores the 2nd write to speed up hotunplug.
#[test]
fn test_pci_hotunplug_007() {
    let blk_nums = 1;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:2:0.
    let root_port = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));

    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);

    let unplug_blk_id = 0;
    // Hotunplug the block device attaching the root port.
    let (delete_device_command, _delete_blk_command) = build_hotunplug_blk_cmd(unplug_blk_id);
    let _ret = test_state.borrow().qmp(&delete_device_command);
    assert!(
        wait_root_port_intr(root_port.clone()),
        "Wait for interrupt of root port timeout"
    );

    // The block device will be unplugged when indicator of power and slot is power off.
    power_off_device(root_port.clone());
    // Trigger a 2nd write to PIC/PCC, which will be ignored by the device, and causes no harm.
    power_off_device(root_port.clone());

    test_state.borrow().wait_qmp_event();

    // Verify the vendor id for the virtio block device.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        0xFFFF,
        0xFFFF,
    );

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Hotplug and hotunplug in sequence.
#[test]
fn test_pci_hotplug_combine_001() {
    let blk_nums = 0;
    let root_port_nums = 1;
    let (test_state, machine, alloc, mut image_paths) =
        set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:2:0.
    let root_port = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));

    let hotplug_blk_id = 0;
    let hotplug_image_path = create_img(TEST_IMAGE_SIZE, 1);
    image_paths.push(hotplug_image_path.clone());

    // Hotplug a block device whose bdf is 1:0:0.
    let (add_blk_command, add_device_command) =
        build_hotplug_blk_cmd(hotplug_blk_id, hotplug_image_path.clone(), 1, 0, 0);
    let ret = test_state.borrow().qmp(&add_blk_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));
    let ret = test_state.borrow().qmp(&add_device_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    assert!(
        wait_root_port_intr(root_port.clone()),
        "Wait for interrupt of root port timeout"
    );
    power_on_device(root_port.clone());

    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);
    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );
    // Verify that the function of the block device is normal.
    validate_std_blk_io(blk.clone(), test_state.clone(), vqs.clone(), alloc.clone());

    let (delete_device_command, delete_blk_command) = build_hotunplug_blk_cmd(hotplug_blk_id);
    let ret = test_state.borrow().qmp(&delete_device_command);
    assert!(
        wait_root_port_intr(root_port.clone()),
        "Wait for interrupt of root port timeout"
    );
    power_off_device(root_port.clone());

    assert_eq!(*ret.get("return").unwrap(), json!({}));
    test_state.borrow().wait_qmp_event();
    let ret = test_state.borrow().qmp(&delete_blk_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    // Verify the vendor id for the virtio block device.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        0xFFFF,
        0xFFFF,
    );

    let hotplug_blk_id = 1;
    let hotplug_image_path = create_img(TEST_IMAGE_SIZE, 1);
    image_paths.push(hotplug_image_path.clone());

    // Hotplug a block device whose bdf is 1:0:0.
    let (add_blk_command, add_device_command) =
        build_hotplug_blk_cmd(hotplug_blk_id, hotplug_image_path.clone(), 1, 0, 0);
    let ret = test_state.borrow().qmp(&add_blk_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));
    let ret = test_state.borrow().qmp(&add_device_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    assert!(
        wait_root_port_intr(root_port.clone()),
        "Wait for interrupt of root port timeout"
    );
    power_on_device(root_port.clone());

    // Verify the virtio block device has been plugged.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        VIRTIO_PCI_VENDOR,
        0xFFFF,
    );

    let blk = create_blk(machine.clone(), 1, 0, 0);
    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );
    // Verify that the function of the block device is normal.
    validate_std_blk_io(blk.clone(), test_state.clone(), vqs.clone(), alloc.clone());

    let (delete_device_command, delete_blk_command) = build_hotunplug_blk_cmd(hotplug_blk_id);
    let ret = test_state.borrow().qmp(&delete_device_command);
    assert!(
        wait_root_port_intr(root_port.clone()),
        "Wait for interrupt of root port timeout"
    );
    power_off_device(root_port.clone());

    assert_eq!(*ret.get("return").unwrap(), json!({}));
    test_state.borrow().wait_qmp_event();
    let ret = test_state.borrow().qmp(&delete_blk_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    // Verify that the virtio block device has been unplugged.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        0xFFFF,
        0xFFFF,
    );

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Hotunplugging during hotplugging.
#[test]
fn test_pci_hotplug_combine_002() {
    let blk_nums = 0;
    let root_port_nums = 1;
    let (test_state, machine, alloc, mut image_paths) =
        set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:1:0.
    let root_port = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));

    let hotplug_blk_id = 0;
    // Hotplug a block device whose id is 0 and bdf is 1:0:0.
    hotplug_blk(
        test_state.clone(),
        root_port.clone(),
        &mut image_paths,
        hotplug_blk_id,
        1,
        0,
        0,
    );
    power_indicator_off(root_port.clone());

    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);

    validate_blk_io_success(blk.clone(), test_state.clone(), alloc.clone());

    // Hotplug the block device whose id is 0 and bdf is 1:0:0.
    let (delete_device_command, delete_blk_command) = build_hotunplug_blk_cmd(0);
    let ret = test_state.borrow().qmp(&delete_device_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    assert!(
        wait_root_port_intr(root_port.clone()),
        "Wait for interrupt of root port timeout"
    );
    power_indicator_blink(root_port.clone());

    let ret = test_state.borrow().qmp(&delete_blk_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    // Verify the virtio block device has not been unplugged.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        VIRTIO_PCI_VENDOR,
        0xFFFF,
    );

    let (delete_device_command, delete_blk_command) = build_hotunplug_blk_cmd(hotplug_blk_id);
    let ret = test_state.borrow().qmp(&delete_device_command);
    assert!(!(*ret.get("error").unwrap()).is_null());

    assert!(
        wait_root_port_intr(root_port.clone()),
        "Wait for interrupt of root port timeout"
    );
    power_off_device(root_port.clone());
    test_state.borrow().wait_qmp_event();

    let ret = test_state.borrow().qmp(&delete_blk_command);
    assert!(!(*ret.get("error").unwrap()).is_null());

    // Verify that the virtio block device has been unplugged.
    validate_config_value_2byte(
        blk.borrow().pci_dev.pci_bus.clone(),
        blk.borrow().pci_dev.bus_num,
        blk.borrow().pci_dev.devfn,
        PCI_VENDOR_ID,
        0xFFFF,
        0xFFFF,
    );

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// Hotplugging during hotunpluging.
#[test]
fn test_pci_hotplug_combine_003() {
    let blk_nums = 1;
    let root_port_nums = 1;
    let (test_state, machine, alloc, mut image_paths) =
        set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:1:0.
    let root_port = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));

    let hotunplug_blk_id = 0;
    // Hotunplug the block device attaching the root port;
    let (delete_device_command, delete_blk_command) = build_hotunplug_blk_cmd(hotunplug_blk_id);
    let ret = test_state.borrow().qmp(&delete_device_command);
    assert!(
        wait_root_port_intr(root_port.clone()),
        "Wait for interrupt of root port timeout"
    );
    assert_eq!(*ret.get("return").unwrap(), json!({}));
    let ret = test_state.borrow().qmp(&delete_blk_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    let hotplug_image_path = create_img(TEST_IMAGE_SIZE, 1);
    image_paths.push(hotplug_image_path.clone());

    // Hotplug a block device whose bdf is 1:0:0.
    let (add_blk_command, add_device_command) =
        build_hotplug_blk_cmd(hotunplug_blk_id, hotplug_image_path.clone(), 1, 0, 0);
    let ret = test_state.borrow().qmp(&add_blk_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));
    let ret = test_state.borrow().qmp(&add_device_command);
    assert!(!(*ret.get("error").unwrap()).is_null());

    power_off_device(root_port.clone());
    test_state.borrow().wait_qmp_event();

    let hotplug_image_path = create_img(TEST_IMAGE_SIZE, 1);
    image_paths.push(hotplug_image_path.clone());
    // Hotplug a block device whose bdf is 1:0:0.
    let (add_blk_command, add_device_command) =
        build_hotplug_blk_cmd(hotunplug_blk_id, hotplug_image_path.clone(), 1, 0, 0);
    let ret = test_state.borrow().qmp(&add_blk_command);
    assert!(!(*ret.get("error").unwrap()).is_null());
    let ret = test_state.borrow().qmp(&add_device_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));
    let blk = create_blk(machine.clone(), 1, 0, 0);
    let vqs = blk.borrow_mut().init_device(
        test_state.clone(),
        alloc.clone(),
        1 << VIRTIO_F_VERSION_1,
        1,
    );
    // Verify that the function of the block device is normal.
    validate_std_blk_io(blk.clone(), test_state.clone(), vqs.clone(), alloc.clone());

    tear_down(Some(blk), test_state, alloc, Some(vqs), Some(image_paths));
}

/// Validate express capability of the root port.
#[test]
fn test_pci_root_port_exp_cap() {
    let blk_nums = 0;
    let root_port_nums = 1;
    let (test_state, machine, alloc, mut image_paths) =
        set_up(root_port_nums, blk_nums, true, false);
    let nlw_range: Vec<u16> = [1, 2, 4, 8, 16, 32].to_vec();
    let cls_range: Vec<u16> = [1, 2, 3, 4, 5, 6, 7].to_vec();

    // Create a root port whose bdf is 0:1:0.
    let root_port = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));

    let cap_exp_addr = root_port.borrow().rp_dev.find_capability(PCI_CAP_ID_EXP, 0);

    let negotiated_link_width_mask = PCI_EXP_LNKSTA_NLW;
    let negotiated_link_width = (root_port
        .borrow()
        .rp_dev
        .config_readw(cap_exp_addr + PCI_EXP_LNKSTA)
        & negotiated_link_width_mask)
        >> 4;
    assert!(nlw_range.binary_search(&negotiated_link_width).is_ok());

    let current_link_speed_mask = PCI_EXP_LNKSTA_CLS;
    let current_link_speed = root_port
        .borrow()
        .rp_dev
        .config_readw(cap_exp_addr + PCI_EXP_LNKSTA)
        & current_link_speed_mask;
    assert!(cls_range.binary_search(&current_link_speed).is_ok());

    let dllla_mask = PCI_EXP_LNKSTA_DLLLA;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_LNKSTA,
        0,
        dllla_mask,
    );

    let abp_mask = PCI_EXP_SLTSTA_ABP;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_SLTSTA,
        0,
        abp_mask,
    );

    let pds_mask = PCI_EXP_SLTSTA_PDS;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_SLTSTA,
        0,
        pds_mask,
    );

    let pdc_mask = PCI_EXP_SLTSTA_PDC;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_SLTSTA,
        0,
        pdc_mask,
    );

    let pcc_mask = PCI_EXP_SLTCTL_PCC;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_SLTCTL,
        PCI_EXP_SLTCTL_PCC,
        pcc_mask,
    );

    let hotplug_blk_id = 0;
    // Hotplug a block device whose id is 0 and bdf is 1:0:0.
    hotplug_blk(
        test_state.clone(),
        root_port.clone(),
        &mut image_paths,
        hotplug_blk_id,
        1,
        0,
        0,
    );
    // Create a block device whose bdf is 1:0:0.
    let blk = create_blk(machine.clone(), 1, 0, 0);

    let nlw_mask = PCI_EXP_LNKSTA_NLW;
    let negotiated_link_width = (root_port.borrow().rp_dev.pci_bus.borrow().config_readw(
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_LNKSTA,
    ) & nlw_mask)
        >> 4;
    assert!(nlw_range.binary_search(&negotiated_link_width).is_ok());

    let cls_mask = PCI_EXP_LNKSTA_CLS;
    let current_link_speed = root_port.borrow().rp_dev.pci_bus.borrow().config_readw(
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_LNKSTA,
    ) & cls_mask;
    assert!(cls_range.binary_search(&current_link_speed).is_ok());

    let dllla_mask = PCI_EXP_LNKSTA_DLLLA;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_LNKSTA,
        PCI_EXP_LNKSTA_DLLLA,
        dllla_mask,
    );

    let abp_mask = PCI_EXP_SLTSTA_ABP;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_SLTSTA,
        PCI_EXP_SLTSTA_ABP,
        abp_mask,
    );

    let pds_mask = PCI_EXP_SLTSTA_PDS;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_SLTSTA,
        PCI_EXP_SLTSTA_PDS,
        pds_mask,
    );

    let pdc_mask = PCI_EXP_SLTSTA_PDC;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_SLTSTA,
        PCI_EXP_SLTSTA_PDC,
        pdc_mask,
    );

    let pcc_mask = PCI_EXP_SLTCTL_PCC;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_SLTCTL,
        0,
        pcc_mask,
    );

    // Hotplug the block device whose id is 0 and bdf is 1:0:0.
    hotunplug_blk(
        test_state.clone(),
        blk.clone(),
        root_port.clone(),
        hotplug_blk_id,
    );

    let dllla_mask = PCI_EXP_LNKSTA_DLLLA;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_LNKSTA,
        0,
        dllla_mask,
    );

    let abp_mask = PCI_EXP_SLTSTA_ABP;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_SLTSTA,
        PCI_EXP_SLTSTA_ABP,
        abp_mask,
    );

    let pds_mask = PCI_EXP_SLTSTA_PDS;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_SLTSTA,
        0,
        pds_mask,
    );

    let pdc_mask = PCI_EXP_SLTSTA_PDC;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_SLTSTA,
        PCI_EXP_SLTSTA_PDC,
        pdc_mask,
    );

    let pcc_mask = PCI_EXP_SLTCTL_PCC;
    validate_config_value_2byte(
        root_port.borrow().rp_dev.pci_bus.clone(),
        root_port.borrow().rp_dev.bus_num,
        root_port.borrow().rp_dev.devfn,
        cap_exp_addr + PCI_EXP_SLTCTL,
        PCI_EXP_SLTCTL_PCC,
        pcc_mask,
    );

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// r/w demo dev's mmio
#[test]
fn test_pci_combine_000() {
    let cfg = DemoDev {
        bar_num: 3,
        bar_size: 0x100_0000, //16MB
        bus_num: 0,
        dev_num: 5,
    };

    let (pci_dev, test_state) = init_demo_dev(cfg, 1);

    let bar_addr = pci_dev.borrow().io_map(0);

    let start = bar_addr;

    test_state.borrow().writeb(start, 5);
    let out = test_state.borrow().readb(start);

    assert!(out == 10); // just multiply it with 2.
    test_state.borrow().writeb(start + 2, 7);
    let out = test_state.borrow().readb(start + 2);
    assert!(out == 14); // just multiply it with 2.

    test_state.borrow_mut().stop();
}

/// change memory enabled during r/w demo dev's mmio
#[test]
fn test_pci_combine_001() {
    let cfg = DemoDev {
        bar_num: 3,
        bar_size: 0x100_0000, //16MB
        bus_num: 0,
        dev_num: 5,
    };

    let (pci_dev, test_state) = init_demo_dev(cfg, 1);
    let dev_locked = pci_dev.borrow();

    let bar_addr = dev_locked.io_map(1);

    // set memory enabled = 0
    let mut val = dev_locked.config_readw(PCI_COMMAND);
    val &= !(PCI_COMMAND_MEMORY as u16);
    dev_locked.config_writew(PCI_COMMAND, val);

    // mmio r/w stops working.
    test_state.borrow().writeb(bar_addr, 5);
    let out = test_state.borrow().readb(bar_addr);
    assert_ne!(out, 10);

    // set memory enabled = 1
    val |= PCI_COMMAND_MEMORY as u16;
    dev_locked.config_writew(PCI_COMMAND, val);

    // mmio r/w gets back to work.
    test_state.borrow().writeb(bar_addr, 5);
    let out = test_state.borrow().readb(bar_addr);
    assert_eq!(out, 0);

    drop(dev_locked);

    test_state.borrow_mut().stop();
}

/// r/w mmio during hotunplug
#[test]
fn test_pci_combine_002() {
    let blk_nums = 1;
    let root_port_nums = 1;
    let (test_state, machine, alloc, image_paths) = set_up(root_port_nums, blk_nums, true, false);

    // Create a root port whose bdf is 0:1:0.
    let root_port = Rc::new(RefCell::new(RootPort::new(
        machine.clone(),
        alloc.clone(),
        0,
        1 << 3 | 0,
    )));
    let blk = Rc::new(RefCell::new(TestVirtioPciDev::new(
        machine.borrow().pci_bus.clone(),
    )));
    blk.borrow_mut().pci_dev.bus_num = 1;
    blk.borrow_mut().init(0, 0);
    let bar_addr = blk.borrow().bar;

    let (delete_device_command, delete_blk_command) = build_hotunplug_blk_cmd(0);
    let ret = test_state.borrow().qmp(&delete_device_command);

    // r/w mmio during hotunplug
    test_state.borrow().writeb(bar_addr, 5);
    assert!(test_state.borrow().readb(bar_addr) == 5);

    assert!(
        wait_root_port_intr(root_port.clone()),
        "Wait for interrupt of root port timeout"
    );
    power_off_device(root_port.clone());

    // r/w mmio during hotunplug
    test_state.borrow().writeb(bar_addr, 5);
    assert!(test_state.borrow().readb(bar_addr) != 5);

    assert_eq!(*ret.get("return").unwrap(), json!({}));
    test_state.borrow().qmp_read();
    let ret = test_state.borrow().qmp(&delete_blk_command);
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    validate_config_value_2byte(
        machine.borrow().pci_bus.clone(),
        root_port_nums,
        0,
        PCI_VENDOR_ID,
        0xFFFF,
        0xFFFF,
    );
    // r/w mmio during hotunplug
    test_state.borrow().writeb(bar_addr, 5);
    assert!(test_state.borrow().readb(bar_addr) != 5);

    tear_down(None, test_state, alloc, None, Some(image_paths));
}

/// too large bar space
#[test]
fn test_pci_combine_003() {
    let mut cfg = DemoDev {
        bar_num: 3,
        bar_size: 0x100_0000, //16MB
        bus_num: 0,
        dev_num: 5,
    };

    let (pci_dev, _) = init_demo_dev(cfg, 1);
    let bar_addr = pci_dev.borrow().io_map(0);
    // the mmio space is 78MB, bar1 got over bounded
    assert!(bar_addr != INVALID_BAR_ADDR);

    cfg.bar_size = 0x1000_0000; //2GB
    let (pci_dev, _) = init_demo_dev(cfg, 1);
    let bar_addr = pci_dev.borrow().io_map(0);

    assert!(bar_addr == INVALID_BAR_ADDR);
}
