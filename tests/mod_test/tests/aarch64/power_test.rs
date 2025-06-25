// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::borrow::BorrowMut;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use machine::aarch64::standard::{LayoutEntryType, MEM_LAYOUT};
use mod_test::libtest::{test_init, TestState, MACHINE_TYPE_ARG};

const POWER_ADDR_BASE: u64 = MEM_LAYOUT[LayoutEntryType::PowerDev as usize].0;
const POWER_REGS_SIZE: u64 = MEM_LAYOUT[LayoutEntryType::PowerDev as usize].1;

const REG_IDX_ACAD_ON: usize = 0;
const REG_IDX_BAT_DCAP: usize = 1;
const REG_IDX_BAT_FCAP: usize = 2;
const REG_IDX_BAT_DVOLT: usize = 3;
const REG_IDX_BAT_STATE: usize = 4;
const REG_IDX_BAT_PRATE: usize = 5;
const REG_IDX_BAT_RCAP: usize = 6;
const REG_IDX_BAT_PVOLT: usize = 7;

const ACPI_BATTERY_STATE_CHARGING: u32 = 0x2;

const ACAD_SYSFS_DIR: &str = "/sys/class/power_supply/Mains";
const BAT_SYSFS_DIR: &str = "/sys/class/power_supply/Battery";

const BAT_INFO: [(usize, &str, u32); 7] = [
    (REG_IDX_BAT_DCAP, "energy_full_design", 70020000),
    (REG_IDX_BAT_FCAP, "energy_full", 70020000),
    (REG_IDX_BAT_DVOLT, "voltage_max_design", 17600000),
    (REG_IDX_BAT_STATE, "online", 1),
    (REG_IDX_BAT_PRATE, "current_now", 0),
    (REG_IDX_BAT_RCAP, "energy_now", 67265880),
    (REG_IDX_BAT_PVOLT, "voltage_now", 13124000),
];

fn power_read_evt(ts: &TestState, off: u64) -> u32 {
    ts.readl(POWER_ADDR_BASE + off)
}

fn power_write_evt(ts: &TestState, off: u64, val: u32) {
    ts.writel(POWER_ADDR_BASE + off, val);
}

fn check_path(path: &str) -> bool {
    Path::new(path).exists()
}

fn create_fake_power_supply() {
    let test_dir = "/tmp/power_supply";
    let mains = &[test_dir, "/", "Mains"].concat();
    fs::create_dir_all(mains).unwrap();
    let mut file = fs::File::create(&[mains, "/", "online"].concat()).unwrap();
    file.write_all(b"1\n").unwrap();

    let battery = &[test_dir, "/Battery"].concat();
    fs::create_dir_all(battery).unwrap();

    for (_, name, value) in BAT_INFO {
        let mut file = fs::File::create(&[battery, "/", name].concat()).unwrap();
        file.write_all(&value.to_string().as_bytes()).unwrap();
        file.write_all(b"\n").unwrap();
    }

    // Try umount the remaining mount point.
    let _ = Command::new("umount")
        .arg("/sys/class/power_supply")
        .output();

    let _ = Command::new("mount")
        .arg("--bind")
        .arg(test_dir)
        .arg("/sys/class/power_supply")
        .output()
        .expect("Failed to mount power_supply");
}

fn power_prepare_env() {
    if !check_path(&[ACAD_SYSFS_DIR, "online"].concat()) {
        create_fake_power_supply();
        return;
    }

    for val in BAT_INFO {
        if !check_path(&[BAT_SYSFS_DIR, val.1].concat()) {
            create_fake_power_supply();
            return;
        }
    }
}

fn power_args(base_args: &mut Vec<&str>) {
    let mut args: Vec<&str> = MACHINE_TYPE_ARG.split(' ').collect();
    base_args.append(&mut args);
    args = "-battery".split(' ').collect();
    base_args.append(&mut args);
    args = "-drive file=/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw,if=pflash,unit=0,readonly=true"
        .split(' ')
        .collect();
    base_args.append(&mut args);
}

fn set_up() -> TestState {
    power_prepare_env();

    let mut args: Vec<&str> = Vec::new();
    power_args(&mut args);
    test_init(args)
}

fn tear_down() {
    let _ = Command::new("umount")
        .arg("/sys/class/power_supply")
        .output()
        .unwrap();

    let test_dir = "/tmp/power_supply";
    if check_path(&test_dir) {
        fs::remove_dir_all(test_dir).unwrap();
    }
}

/// Test the base function for the power device.
///
/// Steps
/// 1. Read power event.
/// 2. Write event which will not modify the value.
/// 3. Read abnormal event.
#[test]
fn test_rw_event() {
    let mut ts = set_up();

    // 1. normal read and check the power event.
    for (id, _, val) in BAT_INFO {
        let pos = id * 4;
        let event = power_read_evt(&ts, pos as u64);
        if id == REG_IDX_BAT_STATE {
            assert_eq!(event, ACPI_BATTERY_STATE_CHARGING);
        } else {
            assert_eq!(event, val / 1000);
        }
    }

    // 2. normal write event.
    let pos = 4 * REG_IDX_BAT_DCAP as u64;
    power_write_evt(&ts, pos, u32::MAX);
    let event = power_read_evt(&ts, pos);
    assert_eq!(event, 70020);

    // 3. abnormal read event.
    let event = power_read_evt(&ts, POWER_REGS_SIZE);
    assert_eq!(event, 0);

    ts.stop();
    tear_down();
}

/// Test the register/unregister timer for the power device.
///
/// Steps
/// 1. Send qmp command "stop".
/// 2. Modify Mains/online value from 1 -> 2.
/// 3. Send qmp command "cont".
/// 4. Read and check value.
#[test]
fn test_stop_resume() {
    let mut ts = set_up();

    ts.qmp("{\"execute\": \"stop\"}");
    ts.qmp_read();

    // Write 2 to online.
    fs::write("/sys/class/power_supply/Mains/online", "2\n").unwrap();

    ts.qmp("{\"execute\": \"cont\"}");
    ts.qmp_read();

    // The timer triggered every 5s, set clock after 6s.
    ts.borrow_mut().clock_step_ns(6_000_000_000);

    // Read and check the value.
    let event = power_read_evt(&ts, REG_IDX_ACAD_ON as u64);
    assert_eq!(event, 2);

    ts.stop();
    tear_down();
}
