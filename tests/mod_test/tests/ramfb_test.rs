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

use mod_test::libdriver::fwcfg::{bios_args, FwCfgDmaAccess};
use mod_test::libdriver::machine::TestStdMachine;
use mod_test::libdriver::malloc::GuestAllocator;
use mod_test::libtest::{test_init, TestState};
use mod_test::utils::{swap_u32, swap_u64};

use std::cell::RefCell;
use std::fs;
use std::mem;
use std::path::Path;
use std::rc::Rc;

const FRAMEBUFFER_SIZE: u64 = 3 * 1024 * 1024;
const RAMFB_FORMAT: u32 = 0x34325258;
const HORIZONTAL_RESOLUTION: u32 = 800;
const VERTICAL_RESOLUTION: u32 = 600;
const RAMFB_BPP: u32 = 4;
const ABNORMAL_FB_BASE: u64 = 0x60000001;

#[repr(C, packed(1))]
#[derive(Default)]
struct RamfbConfig {
    address: u64,
    fourcc: u32,
    flags: u32,
    width: u32,
    height: u32,
    stride: u32,
}

impl RamfbConfig {
    fn new(base: u64) -> Self {
        RamfbConfig {
            address: base,
            fourcc: RAMFB_FORMAT,
            flags: 0,
            width: HORIZONTAL_RESOLUTION,
            height: VERTICAL_RESOLUTION,
            stride: RAMFB_BPP * HORIZONTAL_RESOLUTION,
        }
    }

    fn write_to_file(
        &self,
        allocator: &mut GuestAllocator,
        test_state: &TestState,
        file_name: &str,
    ) {
        let ramfb_config_addr = allocator.alloc(mem::size_of::<RamfbConfig>() as u64);
        test_state.writeq(ramfb_config_addr, swap_u64(self.address));
        test_state.writel(ramfb_config_addr + 8, swap_u32(self.fourcc));
        test_state.writel(ramfb_config_addr + 12, swap_u32(self.flags));
        test_state.writel(ramfb_config_addr + 16, swap_u32(self.width));
        test_state.writel(ramfb_config_addr + 20, swap_u32(self.height));
        test_state.writel(ramfb_config_addr + 24, swap_u32(self.stride));

        let access = allocator.alloc(mem::size_of::<FwCfgDmaAccess>() as u64);
        test_state.fw_cfg_write_file(
            allocator,
            file_name,
            access,
            ramfb_config_addr,
            mem::size_of::<RamfbConfig>() as u32,
        );
    }
}

#[test]
fn test_basic() {
    let mut args: Vec<&str> = Vec::new();
    bios_args(&mut args);
    let ramfb_args = String::from("-device ramfb,id=ramfb1");
    args.append(&mut ramfb_args[..].split(' ').collect());
    let log_path = "/tmp/ramfb_test_basic.log";
    let log_args = format!("-D {}", log_path);
    args.append(&mut log_args[..].split(' ').collect());

    if Path::new(log_path).exists() {
        fs::remove_file(log_path).unwrap();
    }
    let test_state = Rc::new(RefCell::new(test_init(args)));
    let machine = TestStdMachine::new(test_state.clone());
    let allocator = machine.allocator.clone();

    let file_name = "etc/ramfb";
    let framebuffer_base = allocator.borrow_mut().alloc(FRAMEBUFFER_SIZE);

    let mut file_contents = String::from("");
    match fs::File::create(log_path) {
        Ok(_) => {}
        Err(e) => assert!(false, "{}", e),
    }

    let ramfb_config = RamfbConfig::new(framebuffer_base);
    ramfb_config.write_to_file(&mut allocator.borrow_mut(), &test_state.borrow(), file_name);

    match fs::read_to_string(log_path) {
        Ok(contents) => file_contents = contents,
        Err(e) => assert!(false, "{}", e),
    }
    assert!(
        file_contents
            .find("ERROR: Failed to create image of ramfb!")
            .is_none(),
        "Failed to create image!"
    );
    assert!(file_contents.find("ERROR").is_none(), "Unexpected error!");

    match fs::remove_file(log_path) {
        Ok(_) => {}
        Err(e) => assert!(false, "{}", e),
    }
    test_state.borrow_mut().stop();
}

#[test]
fn test_abnormal_param() {
    let mut args: Vec<&str> = Vec::new();
    bios_args(&mut args);
    let ramfb_args = String::from("-device ramfb,id=ramfb1");
    args.append(&mut ramfb_args[..].split(' ').collect());
    let log_path = "/tmp/ramfb_test_abnormal.log";
    let log_args = format!("-D {}", log_path);
    args.append(&mut log_args[..].split(' ').collect());

    if Path::new(log_path).exists() {
        fs::remove_file(log_path).unwrap();
    }
    let test_state = Rc::new(RefCell::new(test_init(args)));
    let machine = TestStdMachine::new(test_state.clone());
    let allocator = machine.allocator.clone();

    let file_name = "etc/ramfb";
    let framebuffer_base = allocator.borrow_mut().alloc(FRAMEBUFFER_SIZE);
    let mut file_contents = String::from("");

    match fs::File::create(log_path) {
        Ok(_) => {}
        Err(e) => assert!(false, "{}", e),
    }

    // Set frambuffer address is abnormal.
    let mut ramfb_config = RamfbConfig::new(ABNORMAL_FB_BASE);
    ramfb_config.write_to_file(&mut allocator.borrow_mut(), &test_state.borrow(), file_name);

    match fs::read_to_string(log_path) {
        Ok(contents) => file_contents = contents,
        Err(e) => assert!(false, "{}", e),
    }
    assert!(
        file_contents
            .find("ERROR: Failed to get the host address of the framebuffer")
            .is_some(),
        "Failed to check framebuffer address!"
    );

    // Set drm format is unsupported.
    ramfb_config.address = framebuffer_base;
    ramfb_config.fourcc = 0;
    ramfb_config.write_to_file(&mut allocator.borrow_mut(), &test_state.borrow(), file_name);

    match fs::read_to_string(log_path) {
        Ok(contents) => file_contents = contents,
        Err(e) => assert!(false, "{}", e),
    }
    assert!(
        file_contents
            .find("ERROR: Unsupported drm format")
            .is_some(),
        "Failed to check Fourcc!"
    );

    // Set width = 15, which is less than the minimum.
    ramfb_config.fourcc = RAMFB_FORMAT;
    ramfb_config.width = 15;
    ramfb_config.write_to_file(&mut allocator.borrow_mut(), &test_state.borrow(), file_name);

    match fs::read_to_string(log_path) {
        Ok(contents) => file_contents = contents,
        Err(e) => assert!(false, "{}", e),
    }
    let mut err_msg = format!(
        "ERROR: The resolution: {}x{} is unsupported",
        15, VERTICAL_RESOLUTION
    );
    assert!(
        file_contents.find(&err_msg).is_some(),
        "Failed to check min width!"
    );

    // Set width = 16001, which is exceeded the maximum.
    ramfb_config.width = 16001;
    ramfb_config.write_to_file(&mut allocator.borrow_mut(), &test_state.borrow(), file_name);

    match fs::read_to_string(log_path) {
        Ok(contents) => file_contents = contents,
        Err(e) => assert!(false, "{}", e),
    }
    err_msg = format!(
        "ERROR: The resolution: {}x{} is unsupported",
        16001, VERTICAL_RESOLUTION
    );
    assert!(
        file_contents.find(&err_msg).is_some(),
        "Failed to check max width!"
    );

    // Set height = 15, which is less than the minimum.
    ramfb_config.width = HORIZONTAL_RESOLUTION;
    ramfb_config.height = 15;
    ramfb_config.write_to_file(&mut allocator.borrow_mut(), &test_state.borrow(), file_name);

    match fs::read_to_string(log_path) {
        Ok(contents) => file_contents = contents,
        Err(e) => assert!(false, "{}", e),
    }
    err_msg = format!(
        "ERROR: The resolution: {}x{} is unsupported",
        HORIZONTAL_RESOLUTION, 15
    );
    assert!(
        file_contents.find(&err_msg).is_some(),
        "Failed to check min height!"
    );

    // Set height = 12001, which is exceeded the maximum.
    ramfb_config.height = 12001;
    ramfb_config.write_to_file(&mut allocator.borrow_mut(), &test_state.borrow(), file_name);

    match fs::read_to_string(log_path) {
        Ok(contents) => file_contents = contents,
        Err(e) => assert!(false, "{}", e),
    }
    err_msg = format!(
        "ERROR: The resolution: {}x{} is unsupported",
        HORIZONTAL_RESOLUTION, 12001
    );
    assert!(
        file_contents.find(&err_msg).is_some(),
        "Failed to check max height!"
    );

    match fs::remove_file(log_path) {
        Ok(_) => {}
        Err(e) => assert!(false, "{}", e),
    }
    test_state.borrow_mut().stop();
}
