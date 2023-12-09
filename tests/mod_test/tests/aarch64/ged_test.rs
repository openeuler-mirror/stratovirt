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

use machine::aarch64::standard::{LayoutEntryType, MEM_LAYOUT};
use mod_test::libtest::{test_init, TestState, MACHINE_TYPE_ARG};

pub const GED_ADDR_BASE: u64 = MEM_LAYOUT[LayoutEntryType::Ged as usize].0;
const ADD_ADDRESS: u64 = 1;

fn ged_read_evt(ts: &TestState) -> u32 {
    ts.readl(GED_ADDR_BASE)
}

fn ged_read_abnormal(ts: &TestState) -> u32 {
    ts.readl(GED_ADDR_BASE + ADD_ADDRESS)
}

fn ged_write_evt(ts: &TestState, val: u32) {
    ts.writel(GED_ADDR_BASE, val);
}

fn ged_args(base_args: &mut Vec<&str>) {
    let mut args: Vec<&str> = MACHINE_TYPE_ARG.split(' ').collect();
    base_args.append(&mut args);
    args = "-no-shutdown".split(' ').collect();
    base_args.append(&mut args);
    args = "-drive file=/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw,if=pflash,unit=0,readonly=true"
        .split(' ')
        .collect();
    base_args.append(&mut args);
}

fn set_up() -> TestState {
    let mut args: Vec<&str> = Vec::new();
    ged_args(&mut args);
    test_init(args)
}

/// Test the read and write functions of a ged device.
///
/// Steps
/// 1. Send qmp command "system_powerdown".
/// 2. Read ged event.
/// 3. Read abnormal address, except 0.
/// 4. Write event and read, excepy 0 because ged can't write.
#[test]
fn test_shutdown() {
    let mut ts = set_up();

    ts.qmp("{\"execute\": \"system_powerdown\"}");

    let event = ged_read_evt(&ts);
    assert_eq!(event, 1);

    let addr = ged_read_abnormal(&ts);
    assert_eq!(addr, 0);

    ged_write_evt(&ts, 1);
    let event = ged_read_evt(&ts);
    assert_eq!(event, 0);

    ts.stop();
}

/// Verify that the restart function is normal.
///
/// Steps
/// 1. Send qmp command "system_powerdown" and "system_reset" to achieve "reboot".
/// 2. Read ged event.
/// 3. Send qmp command "query-status" to get the status of vm, except "running".
#[test]
fn test_reboot() {
    let mut ts = set_up();

    ts.qmp("{\"execute\": \"system_powerdown\"}");
    ts.qmp_read();

    let event = ged_read_evt(&ts);
    assert_eq!(event, 1);

    ts.qmp("{\"execute\": \"system_reset\"}");
    ts.qmp_read();

    let value = ts.qmp("{\"execute\": \"query-status\"}");
    let status = value["return"]["status"].as_str().unwrap().to_string();
    assert_eq!(status, "running".to_string());

    ts.stop();
}
