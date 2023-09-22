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

use std::cell::{RefCell, RefMut};
use std::rc::Rc;
use std::{fs::remove_file, fs::File, io::Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use devices::usb::xhci::xhci_trb::TRBCCode;
use mod_test::libdriver::usb::{
    TestUsbBuilder, TestXhciPciDevice, CONTROL_ENDPOINT_ID, PRIMARY_INTERRUPTER_ID,
};
use mod_test::libtest::TestState;

const UVC_FID: u8 = 1;
const UVC_HEADER_LEN: u8 = 2;
const VS_ENDPOINT_ID: u32 = 3;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Default)]
enum FmtType {
    #[default]
    Yuy2 = 0,
    Rgb565,
    Mjpg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceConfig {
    check_interval: u64,
    image_mode: String,
    force_frame_len: Option<u64>,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            check_interval: 10,
            image_mode: String::from("default"),
            force_frame_len: None,
        }
    }
}

struct TestCameraConfig {
    path: String,
    conf: DeviceConfig,
}

impl TestCameraConfig {
    fn new(name: &str) -> Self {
        let path = format!("/tmp/camera_config_{}.json", name);
        let mut config = Self {
            path,
            conf: DeviceConfig::default(),
        };
        config.write_config();
        config
    }

    fn write_config(&mut self) {
        let conf = serde_json::to_string(&self.conf).unwrap();
        let mut file = File::create(&self.path).unwrap();
        file.set_len(0).unwrap();
        file.write_all(conf.as_bytes()).unwrap();
        file.flush().unwrap();
    }
}

impl Drop for TestCameraConfig {
    fn drop(&mut self) {
        if let Err(e) = remove_file(&self.path) {
            println!("Failed to remove config, {:?}", e);
        }
    }
}

fn check_frame(
    xhci: &mut RefMut<TestXhciPciDevice>,
    slot_id: u32,
    format_idx: u8,
    frame_idx: u8,
    cnt: u32,
) {
    start_capture(xhci, slot_id, format_idx, frame_idx);
    // Check current setting.
    let cur = xhci.vs_get_cur(slot_id);
    assert_eq!(cur.bFormatIndex, format_idx);
    assert_eq!(cur.bFrameIndex, frame_idx);
    // Get frame.
    let fmt = format_index_to_fmt(format_idx);
    check_multi_frames(
        xhci,
        slot_id,
        &fmt,
        cur.dwMaxVideoFrameSize,
        cur.dwMaxPayloadTransferSize,
        cnt,
    );
    stop_capture(xhci, slot_id);
}

fn format_index_to_fmt(idx: u8) -> FmtType {
    if idx == 1 {
        FmtType::Yuy2
    } else if idx == 2 {
        FmtType::Mjpg
    } else {
        FmtType::Rgb565
    }
}

fn start_capture(xhci: &mut RefMut<TestXhciPciDevice>, slot_id: u32, fmt_idx: u8, frm_idx: u8) {
    xhci.vs_probe_control(slot_id, fmt_idx, frm_idx);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    xhci.vs_commit_control(slot_id, fmt_idx, frm_idx);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
}

fn stop_capture(xhci: &mut RefMut<TestXhciPciDevice>, slot_id: u32) {
    xhci.vs_clear_feature(slot_id);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
}

fn check_multi_frames(
    xhci: &mut RefMut<TestXhciPciDevice>,
    slot_id: u32,
    fmt: &FmtType,
    frame_len: u32,
    max_payload: u32,
    cnt: u32,
) {
    let mut fid = 0;
    for _ in 0..cnt {
        let payload_list = xhci.get_payload(
            slot_id,
            VS_ENDPOINT_ID,
            frame_len,
            UVC_HEADER_LEN as u32,
            max_payload,
        );
        for buf in &payload_list {
            assert_eq!(buf[0], UVC_HEADER_LEN);
            assert_eq!(buf[1] & UVC_FID, fid);
        }
        fid ^= UVC_FID;
        let frame = payload_to_frame(payload_list);
        check_frame_data(fmt, &frame);
    }
}

fn payload_to_frame(list: Vec<Vec<u8>>) -> Vec<u8> {
    let mut frame = Vec::new();
    for buf in list {
        frame.append(&mut buf[UVC_HEADER_LEN as usize..].to_vec())
    }
    frame
}

fn check_frame_data(fmt: &FmtType, data: &[u8]) {
    let sz = data.len();
    match fmt {
        FmtType::Yuy2 => {
            assert_eq!(sz % 4, 0);
            for i in 0..(sz / 4) {
                assert_eq!(data[4 * i..(4 * i + 4)], [82, 90, 82, 240]);
            }
        }
        FmtType::Rgb565 => {
            assert_eq!(sz % 4, 0);
            for i in 0..(sz / 4) {
                assert_eq!(data[4 * i..(4 * i + 4)], [0, 0, 255, 255]);
            }
        }
        FmtType::Mjpg => {
            assert_eq!(data[0..4], [0xff, 0xd8, 0xff, 0xe0]);
            let pos = data.len() - 2;
            assert_eq!(data[pos..], [0xff, 0xf9]);
        }
    }
}

fn qmp_cameradev_add(
    test_state: &Rc<RefCell<TestState>>,
    id: &str,
    driver: &str,
    path: &str,
) -> Value {
    let test_state = test_state.borrow_mut();
    let cmd: &str = r#"{"execute": "cameradev_add", "arguments": {"id": "ID", "driver": "DRIVER", "path": "PATH"}}"#;
    let cmd = cmd.replace("ID", id);
    let cmd = cmd.replace("DRIVER", driver);
    let cmd = cmd.replace("PATH", path);
    test_state.qmp(&cmd)
}

fn qmp_cameradev_del(test_state: &Rc<RefCell<TestState>>, id: &str) -> Value {
    let test_state = test_state.borrow_mut();
    let cmd = r#"{"execute": "cameradev_del", "arguments": {"id": "ID"}}"#;
    let cmd = cmd.replace("ID", id);
    test_state.qmp(&cmd)
}

fn qmp_plug_camera(test_state: &Rc<RefCell<TestState>>, id: &str, camdev: &str) -> Value {
    let test_state = test_state.borrow_mut();
    let cmd = r#"{"execute": "device_add", "arguments": {"id": "ID", "driver": "usb-camera", "cameradev": "CAMDEV"}}"#;
    let cmd = cmd.replace("ID", id);
    let cmd = cmd.replace("CAMDEV", &camdev);
    test_state.qmp(&cmd)
}

fn qmp_unplug_camera(test_state: &Rc<RefCell<TestState>>, id: &str) -> Value {
    let test_state = test_state.borrow_mut();
    let cmd = r#"{"execute": "device_del", "arguments": {"id": "ID"}}"#;
    let cmd = cmd.replace("ID", id);
    test_state.qmp(&cmd)
}

/// USB camera basic capture.
/// TestStep:
///   1. Init camera device.
///   2. Query control capabilities.
///   3. Start capture.
///   4. Check Frame data.
///   5. Stop capture.
/// Expect:
///   1/2/3/4/5: success.
#[test]
fn test_xhci_camera_basic() {
    let config = TestCameraConfig::new("test_xhci_camera_basic");
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_camera("cam", &config.path)
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();
    let port_id = 5; // super speed
    let slot_id = xhci.init_device(port_id);

    // Query control capabilities.
    let info = xhci.vs_get_info(slot_id);
    assert_eq!(info, 2 | 1);
    // Yuy2
    check_frame(&mut xhci, slot_id, 1, 2, 3);
    // Mjpg
    check_frame(&mut xhci, slot_id, 2, 2, 3);
    // Rgb
    check_frame(&mut xhci, slot_id, 3, 3, 3);

    test_state.borrow_mut().stop();
}

/// USB camera capture with invalid frame length.
/// TestStep:
///   1. Init camera device with invalid frame length.
///   2. Start capture.
///   3. Check Frame data.
///   4. Stop capture.
/// Expect:
///   1/2/3/4: success.
#[test]
fn test_xhci_camera_invalid_frame_len() {
    let mut config: TestCameraConfig = TestCameraConfig::new("test_xhci_camera_invalid_frame_len");
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_camera("cam", &config.path)
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .with_config("over_transfer_ring", true)
        .build();
    let mut xhci = xhci.borrow_mut();
    let port_id = 5; // super speed
    let slot_id = xhci.init_device(port_id);
    // Oversized frame.
    let len = 7680 * 4320;
    config.conf.force_frame_len = Some(len);
    config.write_config();
    start_capture(&mut xhci, slot_id, 1, 1);
    let cur = xhci.vs_get_cur(slot_id);
    // Get frame.
    let payload_list = xhci.get_payload(
        slot_id,
        VS_ENDPOINT_ID,
        len as u32,
        UVC_HEADER_LEN as u32,
        cur.dwMaxPayloadTransferSize,
    );
    for item in payload_list {
        assert_eq!(item[0], UVC_HEADER_LEN);
    }
    stop_capture(&mut xhci, slot_id);
    // Zero size frame.
    config.conf.force_frame_len = Some(0);
    config.write_config();
    start_capture(&mut xhci, slot_id, 1, 1);
    // Get frame.
    xhci.queue_indirect_td(slot_id, VS_ENDPOINT_ID, 10);
    xhci.doorbell_write(slot_id, VS_ENDPOINT_ID);
    // Wait enough time.
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());
    stop_capture(&mut xhci, slot_id);

    test_state.borrow_mut().stop();
}

/// USB camera capture with invalid frame index.
/// TestStep:
///   1. Init camera device.
///   2. Start capture with invalid frame index.
///   3. Reset endpoint.
///   4. Start capture.
///   5. Stop capture.
/// Expect:
///   1/3/4/5: success.
///   2: failure.
#[test]
fn test_xhci_camera_invalid_config() {
    let config = TestCameraConfig::new("test_xhci_camera_invalid_config");
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_camera("cam", &config.path)
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();
    let port_id = 5; // super speed
    let slot_id = xhci.init_device(port_id);

    start_capture(&mut xhci, slot_id, 1, 1);
    // Check current setting.
    let cur = xhci.vs_get_cur(slot_id);
    assert_eq!(cur.bFormatIndex, 1);
    assert_eq!(cur.bFrameIndex, 1);
    // Get frame.
    let fmt = format_index_to_fmt(1);
    check_multi_frames(
        &mut xhci,
        slot_id,
        &fmt,
        cur.dwMaxVideoFrameSize,
        cur.dwMaxPayloadTransferSize,
        2,
    );
    // Set invalid index.
    xhci.vs_probe_control(slot_id, 99, 99);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::StallError as u32);
    // Reset endpoint.
    xhci.reset_endpoint(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // Set invalid index.
    xhci.vs_commit_control(slot_id, 99, 99);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::StallError as u32);
    // Reset endpoint.
    xhci.reset_endpoint(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    check_multi_frames(
        &mut xhci,
        slot_id,
        &fmt,
        cur.dwMaxVideoFrameSize,
        cur.dwMaxPayloadTransferSize,
        2,
    );

    test_state.borrow_mut().stop();
}

/// USB camera capture multiple times.
/// TestStep:
///   1. Init camera device.
///   2. Start/Stop capture for multiple times.
/// Expect:
///   1/2: success.
#[test]
fn test_xhci_camera_repeat_openclose() {
    let config = TestCameraConfig::new("test_xhci_camera_repeat_openclose");
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_camera("cam", &config.path)
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();
    let port_id = 5; // super speed
    let slot_id = xhci.init_device(port_id);

    let cnt = 3;
    for _ in 0..cnt {
        check_frame(&mut xhci, slot_id, 1, 1, 3);
    }
    test_state.borrow_mut().stop();
}

/// USB camera capture with different config.
/// TestStep:
///   1. Init camera device.
///   2. Capture with different config.
/// Expect:
///   1/2: success.
#[test]
fn test_xhci_camera_repeat_config() {
    let config = TestCameraConfig::new("test_xhci_camera_repeat_config");
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_camera("cam", &config.path)
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();
    let port_id = 5; // super speed
    let slot_id = xhci.init_device(port_id);
    check_frame(&mut xhci, slot_id, 1, 1, 3);
    check_frame(&mut xhci, slot_id, 1, 2, 3);
    check_frame(&mut xhci, slot_id, 1, 3, 3);
    check_frame(&mut xhci, slot_id, 1, 4, 3);
    check_frame(&mut xhci, slot_id, 3, 2, 3);

    test_state.borrow_mut().stop();
}

/// USB camera capture with invalid control order.
/// TestStep:
///   1. Init camera device.
///   2. Capture with invalid control order.
/// Expect:
///   1/2: success.
#[test]
fn test_xhci_camera_invalid_control() {
    let config = TestCameraConfig::new("test_xhci_camera_invalid_control");
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_camera("cam", &config.path)
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();
    let port_id = 5; // super speed
    let slot_id = xhci.init_device(port_id);

    start_capture(&mut xhci, slot_id, 1, 1);
    let cur = xhci.vs_get_cur(slot_id);
    let fmt = format_index_to_fmt(1);
    let cnt = 2;
    for _ in 0..cnt {
        xhci.vs_probe_control(slot_id, 1, 1);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
    }
    for _ in 0..cnt {
        xhci.vs_commit_control(slot_id, 1, 1);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
    }

    check_multi_frames(
        &mut xhci,
        slot_id,
        &fmt,
        cur.dwMaxVideoFrameSize,
        cur.dwMaxPayloadTransferSize,
        2,
    );

    test_state.borrow_mut().stop();
}

/// USB camera hot plug/unplug.
/// TestStep:
///   1. Hot plug camera device.
///   2. Test camera start/stop capture.
///   3. Hot unplug device.
/// Expect:
///   1/2: success.
#[test]
fn test_xhci_camera_hotplug() {
    let config = TestCameraConfig::new("test_xhci_camera_hotplug");
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();
    qmp_cameradev_add(&test_state, "camdev0", "demo", &config.path);
    qmp_plug_camera(&test_state, "cam0", "camdev0");
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    let port_id = 5; // super speed
    xhci.device_config.insert(String::from("camera"), true);
    let slot_id = xhci.init_device(port_id);
    // Yuy2
    check_frame(&mut xhci, slot_id, 1, 4, 3);

    qmp_unplug_camera(&test_state, "cam0");
    qmp_cameradev_del(&test_state, "camdev0");
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    test_state.borrow_mut().stop();
}

/// USB camera hot plug/unplug with invalid config.
/// TestStep:
///   1. Hot plug camera device with invalid config.
///   2. Hot unplug camera device with invalid config.
/// Expect:
///   1/2: failure.
#[test]
fn test_xhci_camera_hotplug_invalid() {
    let (_, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_config("auto_run", true)
        .build();

    qmp_cameradev_add(&test_state, "camdev0", "v4l2", "/tmp/not-existed");
    // Invalid cameradev.
    let value = qmp_plug_camera(&test_state, "usbcam0", "camdev0");
    let desc = value["error"]["desc"].as_str().unwrap().to_string();
    assert_eq!(desc, "Failed to open v4l2 backend /tmp/not-existed.");
    // Invalid device id.
    let value = qmp_unplug_camera(&test_state.clone(), "usbcam0");
    let desc = value["error"]["desc"].as_str().unwrap().to_string();
    assert_eq!(desc, "Failed to detach device: id usbcam0 not found");
    // Invalid cameradev id.
    let value = qmp_cameradev_del(&test_state, "camdev1");
    let desc = value["error"]["desc"].as_str().unwrap().to_string();
    assert_eq!(desc, "no cameradev with id camdev1");

    test_state.borrow_mut().stop();
}
