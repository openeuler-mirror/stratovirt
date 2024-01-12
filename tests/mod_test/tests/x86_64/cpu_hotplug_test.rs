// Copyright (c) 2023 China Telecom Co.,Ltd. All rights reserved.
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

use std::borrow::BorrowMut;
use std::thread::sleep;
use std::time::Duration;

use serde_json::{json, Value};

use machine::x86_64::standard::{LayoutEntryType, MEM_LAYOUT};
use mod_test::libtest::{test_init, TestState, MACHINE_TYPE_ARG};

const GED_ADDR_BASE: u64 = MEM_LAYOUT[LayoutEntryType::GedMmio as usize].0;

fn ged_read_evt(ts: &TestState) -> u32 {
    ts.readl(GED_ADDR_BASE)
}

fn set_up(cpu: u8, max_cpus: Option<u8>) -> TestState {
    // Vm extra_args.
    let mut extra_args: Vec<&str> = Vec::new();
    let mut args: Vec<&str> = MACHINE_TYPE_ARG.split(' ').collect();
    extra_args.append(&mut args);

    let cpu_args = if let Some(max_cpus) = max_cpus {
        format!("-smp {},maxcpus={}", cpu, max_cpus)
    } else {
        format!("-smp {}", cpu)
    };
    args = cpu_args[..].split(' ').collect();
    extra_args.append(&mut args);

    let mem_args = format!("-m 512");
    args = mem_args[..].split(' ').collect();
    extra_args.append(&mut args);

    extra_args.push("-append");
    extra_args.push("root=/dev/vda panic=1");

    let uefi_drive =
        format!("-drive file=/usr/share/edk2/ovmf/OVMF_CODE.fd,if=pflash,unit=0,readonly=true");
    args = uefi_drive[..].split(' ').collect();
    extra_args.append(&mut args);

    let root_device = format!("-device pcie-root-port,port=0x0,addr=0x1.0x0,bus=pcie.0,id=pcie.1");
    args = root_device[..].split(' ').collect();
    extra_args.append(&mut args);

    args = "-disable-seccomp -daemonize".split(' ').collect();
    extra_args.append(&mut args);

    test_init(extra_args)
}

fn hotplug_cpu(test_state: &mut TestState, id: &str, cpu_id: u8) -> Value {
    test_state.borrow_mut().qmp(&format!(
        "{{\"execute\": \"device_add\",\"arguments\": {{ \"id\": \"{id}\", \"driver\": \"generic-x86-cpu\", \"cpu-id\": {cpu_id}}}}}"
    ))
}

fn hotunplug_cpu(test_state: &mut TestState, id: &str) -> Value {
    test_state.borrow_mut().qmp(&format!(
        "{{\"execute\": \"device_del\", \"arguments\": {{\"id\": \"{id}\"}}}}"
    ))
}

fn assert_response(result: Value, index: &str, expect: Option<String>) {
    if index == "return" {
        assert_eq!(*result.get("return").unwrap(), json!({}))
    } else {
        assert_eq!(
            result["error"]["desc"].as_str().unwrap().to_string(),
            expect.unwrap(),
        )
    }
}

/// Normal cpu hotplug.
/// TestStep:
///   1. Send id vcpu-1 and cpu-id 1 hotplug qmp command.
///   2. Read ged event, expect 16.
///   3. Destroy VM.
/// Expect:
///   1/2/3: success.
#[test]
fn normal_hotplug_cpu() {
    let mut ts = set_up(1, Some(2));

    let ret = hotplug_cpu(&mut ts, "vcpu-1", 1);
    assert_response(ret, "return", None);
    sleep(Duration::from_micros(200));

    let event = ged_read_evt(&ts);
    assert_eq!(event, 16);

    ts.borrow_mut().stop();
}

/// Normal cpu hotunplug.
/// TestStep:
///   1. Send id vcpu-1 and cpu-id 1 hotplug qmp command.
///   2. Send id vcpu-1 hotunplug qmp command.
///   3. Read ged event, expect 16.
///   4. Destroy VM.
/// Expect:
///   1/2/3/4: success.
#[test]
fn normal_hotunplug_cpu() {
    let mut ts = set_up(1, Some(2));

    // Hotplug vcpu-1.
    let ret = hotplug_cpu(&mut ts, "vcpu-1", 1);
    assert_response(ret, "return", None);
    ts.qmp_read();

    // Hotunplug vcpu-1.
    let ret = hotunplug_cpu(&mut ts, "vcpu-1");
    assert_response(ret, "return", None);

    let event = ged_read_evt(&ts);
    assert_eq!(event, 16);

    ts.borrow_mut().stop();
}

/// Hotplug cpu with an existed id.
/// TestStep:
///   1. Send id vcpu-1 and cpu-id 1 hotplug qmp command.
///   2. Send id vcpu-1 and cpu-id 2 hotplug qmp command.
///   3. Destroy VM.
/// Expect:
///   1/3: Success.
///   2: Failed.
#[test]
fn existed_id_hotplug_cpu() {
    let mut ts = set_up(1, Some(3));

    // Hotplug vcpu-1.
    let ret = hotplug_cpu(&mut ts, "vcpu-1", 1);
    assert_response(ret, "return", None);
    ts.qmp_read();

    // Hotplug vcpu-1.
    let ret = hotplug_cpu(&mut ts, "vcpu-1", 2);
    assert_response(
        ret,
        "error",
        Some("Device id vcpu-1 already existed.".to_string()),
    );

    ts.borrow_mut().stop();
}

/// Hotplug cpu with an existed cpu id.
/// TestStep:
///   1. Send id vcpu-1 and cpu-id 1 hotplug qmp command.
///   2. Send id vcpu-2 and cpu-id 1 hotplug qmp command.
///   3. Destroy VM.
/// Expect:
///   1/3: Success.
///   2: Failed.
#[test]
fn existed_cpuid_hotplug_cpu() {
    let mut ts = set_up(1, Some(3));

    let ret = hotplug_cpu(&mut ts, "vcpu-1", 1);
    assert_response(ret, "return", None);
    ts.qmp_read();

    let ret = hotplug_cpu(&mut ts, "vcpu-2", 1);
    assert_response(
        ret,
        "error",
        Some("Cpu-id 1 is running, device id is vcpu-1.".to_string()),
    );

    ts.borrow_mut().stop();
}

/// Hotplug cpu with empty id.
/// TestStep:
///   1. Send empty id and cpu-id 1 hotplug qmp command.
///   2. Destroy VM.
/// Expect:
///   2: Success.
///   1: Failed.
#[test]
fn empty_id_hotplug_cpu() {
    let mut ts = set_up(1, Some(2));

    let ret = hotplug_cpu(&mut ts, "", 1);
    assert_response(ret, "error", Some("Device id is empty".to_string()));

    ts.borrow_mut().stop();
}

/// Hotplug cpu with an overrange cpu id.
/// TestStep:
///   1. Send id vcpu-1 and cpu-id 1 hotplug qmp command.
///   2. Send id vcpu-2 and cpu-id 2 hotplug qmp command.
///   3. Destroy VM.
/// Expect:
///   1/3: Success.
///   2: Failed.
#[test]
fn overrange_hotplug_cpu() {
    let mut ts = set_up(1, Some(2));

    let ret = hotplug_cpu(&mut ts, "vcpu-1", 1);
    assert_response(ret, "return", None);
    ts.qmp_read();

    let ret = hotplug_cpu(&mut ts, "vcpu-2", 2);
    assert_response(ret, "error", Some("Max cpu-id is 1".to_string()));

    ts.borrow_mut().stop();
}

/// Hotplug cpu when max_cpus is not explicitly configured.
/// TestSetp:
///   1. Send id vcpu-1 and cpu-id 1 hotplug qmp command.
///   2. Destroy VM.
/// Expect:
///   2: Success.
///   1: Failed.
#[test]
fn without_config_max_cpus_hotplug_cpu() {
    let mut ts = set_up(1, None);

    let ret = hotplug_cpu(&mut ts, "vcpu-1", 1);
    assert_response(
        ret,
        "error",
        Some("There is no hotpluggable cpu-id for this VM.".to_string()),
    );

    ts.borrow_mut().stop();
}
