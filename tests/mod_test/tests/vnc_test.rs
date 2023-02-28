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

use anyhow::Result;
use mod_test::{
    libdriver::vnc::{
        create_new_client, set_up, tear_down, DemoGpuConfig, EncodingType, InputConfig,
        RfbClientMessage, RfbPixelFormat, RfbServerMsg, TestAuthType, TestClientCut, UpdateState,
        KEYEVENTLIST, PIXMAN_A1, PIXMAN_A8B8G8R8, PIXMAN_R8G8B8, PIXMAN_X2R10G10B10, PIXMAN_YUY2,
        POINTEVENTLIST, TEST_CLIENT_RAND_MSG,
    },
    libtest::TestState,
};
use serde_json::Value;
use std::{cell::RefCell, rc::Rc};
use vmm_sys_util::epoll::EventSet;

fn qmp_query_vnc(test_state: Rc<RefCell<TestState>>) -> Value {
    let str = "{\"execute\": \"query-vnc\"}".to_string();
    test_state.borrow_mut().qmp(&str)
}

/// Brief:
/// 1. When received a framebuffer request from the client, the vnc server can
/// send the pixel which is changed to the client.
/// Preparation:
/// 1. Configure a demo pointer device and test GPU device.
/// 2. Start a VNC Server and listens on local ports.
/// 3. The demo gpu device create an image with size of 640 * 480 and sends it to VNC.
/// TestStep:
/// 1. VNC client connect to server.
/// 2. VNC client set pixel format Raw.
/// 3. VNC client send framebuffer request + Incremental
/// + The Demo GPU device changes the pixel and update image -> expect 1.
/// 4. The Demo GPU device changes the pixel and update image
/// + VNC client send framebuffer request + Incremental -> expect 1.
/// 5. VNC client set pixel format Raw.
/// 6. VNC client send framebuffer request + Incremental
/// + The Demo GPU device changes the pixel and update image -> expect 1.
/// ExpectOutput
/// 1. VNC client can receive image updates event, and the image format meets expectations.
#[test]
fn test_set_area_dirty() {
    let port: u16 = 0;
    let mut gpu_list: Vec<DemoGpuConfig> = vec![];
    let gpu_conf = DemoGpuConfig {
        pci_slot: 3,
        id: "demo-pci-gpu".to_string(),
    };
    gpu_list.push(gpu_conf);
    let input_conf = InputConfig {
        pci_slot: 4,
        id: "demo-pci-input".to_string(),
    };
    let (gpu_list, input, test_state) = set_up(gpu_list, input_conf, port);
    let demo_gpu = gpu_list[0].clone();

    let mut vnc_client = create_new_client(test_state.clone(), port).unwrap();
    assert!(vnc_client.connect(TestAuthType::VncAuthNone).is_ok());

    // Encoding -> Raw.
    // Demo update image -> VNC client send update request.
    assert!(vnc_client
        .test_setup_encodings(None, Some(EncodingType::EncodingRaw))
        .is_ok());
    let pf = RfbPixelFormat::new(32, 8, 0_u8, 1_u8, 255, 255, 255, 16, 8, 0);
    assert!(vnc_client.test_set_pixel_format(pf).is_ok());
    assert!(vnc_client
        .test_update_request(UpdateState::Incremental, 0, 0, 640 as u16, 480 as u16,)
        .is_ok());
    demo_gpu.borrow_mut().update_image_area(0, 0, 64, 64);
    demo_gpu.borrow_mut().set_area_dirty(0, 0, 64, 64);

    let res = vnc_client.test_recv_server_data(pf);
    assert!(res.is_ok());
    assert!(res
        .unwrap()
        .contains(&(RfbServerMsg::FramebufferUpdate, EncodingType::EncodingRaw)));

    // Encoding -> Raw
    // VNC client send update request -> Demo update image.
    demo_gpu.borrow_mut().update_image_area(0, 0, 64, 64);
    demo_gpu.borrow_mut().set_area_dirty(0, 0, 64, 64);
    assert!(vnc_client
        .test_update_request(UpdateState::Incremental, 0, 0, 640 as u16, 480 as u16,)
        .is_ok());

    let res = vnc_client.test_recv_server_data(pf);
    assert!(res.is_ok());
    assert!(res
        .unwrap()
        .contains(&(RfbServerMsg::FramebufferUpdate, EncodingType::EncodingRaw)));

    // Encoding -> Hextile.
    // Demo update image -> VNC client send update request.
    assert!(vnc_client
        .test_setup_encodings(None, Some(EncodingType::EncodingHextile))
        .is_ok());
    let pf = RfbPixelFormat::new(32, 8, 0_u8, 1_u8, 255, 255, 255, 16, 8, 0);
    assert!(vnc_client.test_set_pixel_format(pf).is_ok());
    assert!(vnc_client
        .test_update_request(UpdateState::Incremental, 0, 0, 640 as u16, 480 as u16,)
        .is_ok());
    demo_gpu.borrow_mut().update_image_area(0, 0, 64, 64);
    demo_gpu.borrow_mut().set_area_dirty(0, 0, 64, 64);

    let res = vnc_client.test_recv_server_data(pf);
    assert!(res.is_ok());
    assert!(res.unwrap().contains(&(
        RfbServerMsg::FramebufferUpdate,
        EncodingType::EncodingHextile
    )));

    assert!(vnc_client.disconnect().is_ok());

    tear_down(gpu_list, input, test_state);
}

/// Brief:
/// 1. When received a framebuffer request from the client, the vnc server can
/// send the pixel which is changed to the client.
/// Preparation:
/// 1. Configure a demo pointer device and test GPU device.
/// 2. Start a VNC Server and listens on local ports.
/// 3. The demo gpu device create an image with size of 640 * 480 and sends it to VNC.
/// TestStep:
/// 1. VNC client connect to server.
/// 2. VNC client set pixel format (Raw of Hextile).
/// 3. VNC client send framebuffer request + NotIncremental
/// + The Demo GPU device changes the pixel and update image -> expect 1.
/// ExpectOutput
/// 1. VNC client can receive image updates event, and the image format meets expectations.
#[test]
fn test_set_multiple_area_dirty() {
    let port: u16 = 8;
    let mut gpu_list: Vec<DemoGpuConfig> = vec![];
    let gpu_conf = DemoGpuConfig {
        pci_slot: 3,
        id: "demo-pci-gpu".to_string(),
    };
    gpu_list.push(gpu_conf);
    let input_conf = InputConfig {
        pci_slot: 4,
        id: "demo-pci-input".to_string(),
    };
    let (gpu_list, input, test_state) = set_up(gpu_list, input_conf, port);
    let demo_gpu = gpu_list[0].clone();
    let mut vnc_client = create_new_client(test_state.clone(), port).unwrap();
    assert!(vnc_client.connect(TestAuthType::VncAuthNone).is_ok());
    // Encoding -> Raw.
    // Multiple areas of image have been updated.
    // Demo update image -> VNC client send update request.
    assert!(vnc_client
        .test_setup_encodings(None, Some(EncodingType::EncodingRaw))
        .is_ok());
    let pf = RfbPixelFormat::new(32, 8, 0_u8, 1_u8, 255, 255, 255, 16, 8, 0);
    assert!(vnc_client.test_set_pixel_format(pf).is_ok());
    demo_gpu.borrow_mut().update_image_area(0, 0, 64, 64);
    demo_gpu.borrow_mut().update_image_area(72, 72, 109, 109);
    demo_gpu.borrow_mut().update_image_area(119, 120, 160, 160);
    demo_gpu.borrow_mut().set_area_dirty(0, 0, 640, 480);
    assert!(vnc_client
        .test_update_request(UpdateState::NotIncremental, 0, 0, 640 as u16, 480 as u16,)
        .is_ok());

    let res = vnc_client.test_recv_server_data(pf);
    assert!(res.is_ok());
    assert!(res
        .unwrap()
        .contains(&(RfbServerMsg::FramebufferUpdate, EncodingType::EncodingRaw)));

    // Encoding -> Hextile.
    // Multiple areas of image have been updated.
    // Demo update image -> VNC client send update request.
    assert!(vnc_client
        .test_setup_encodings(None, Some(EncodingType::EncodingHextile))
        .is_ok());
    let pf = RfbPixelFormat::new(32, 8, 0_u8, 1_u8, 255, 255, 255, 16, 8, 0);
    assert!(vnc_client.test_set_pixel_format(pf).is_ok());
    demo_gpu.borrow_mut().update_image_area(0, 0, 64, 64);
    demo_gpu.borrow_mut().update_image_area(72, 72, 109, 109);
    demo_gpu.borrow_mut().update_image_area(119, 120, 160, 160);
    demo_gpu.borrow_mut().set_area_dirty(0, 0, 640, 480);
    assert!(vnc_client
        .test_update_request(UpdateState::NotIncremental, 0, 0, 640 as u16, 480 as u16,)
        .is_ok());

    let res = vnc_client.test_recv_server_data(pf);
    assert!(res.is_ok());
    assert!(res.unwrap().contains(&(
        RfbServerMsg::FramebufferUpdate,
        EncodingType::EncodingHextile
    )));

    assert!(vnc_client.disconnect().is_ok());

    tear_down(gpu_list, input, test_state);
}

/// Brief:
/// 1. VNC Server can update cursor image.
/// Preparation:
/// 1. Configure a demo pointer device and test GPU device.
/// 2. Start a VNC Server and listens on local ports.
/// 3. The demo gpu device create an image with size of 640 * 480 and sends it to VNC.
/// TestStep:
/// 1. VNC client connect to server.
/// 2. VNC client setting feature of EncodingRichCursor.
/// 3. Demo GPU update the cursor image of VNC server -> expect 1.
/// 4. VNC client setting feature of EncodingAlphaCursor.
/// 5. Demo GPU update the cursor image of VNC server -> expect 1.
/// 6. VNC client setting feature of EncodingRichCursor.
/// 7. Demo GPU update the abnormal cursor image of VNC server -> expect 2.
/// 8. VNC client setting feature of EncodingAlphaCursor.
/// 9. Demo GPU update the abnormal cursor image of VNC server -> expect 2.
/// ExpectOutput:
/// 1. The client receives the cursor image, and the format meets expect.
/// 2. The state of VNC client and server are normal, and the next normal connection will not be effect.
#[test]
fn test_send_cursor_image() {
    let port: u16 = 1;
    let mut gpu_list: Vec<DemoGpuConfig> = vec![];
    let gpu_conf = DemoGpuConfig {
        pci_slot: 3,
        id: "demo-pci-gpu".to_string(),
    };
    gpu_list.push(gpu_conf);
    let input_conf = InputConfig {
        pci_slot: 4,
        id: "demo-pci-input".to_string(),
    };
    let (gpu_list, input, test_state) = set_up(gpu_list, input_conf, port);
    let demo_gpu = gpu_list[0].clone();

    let mut vnc_client = create_new_client(test_state.clone(), port).unwrap();
    assert!(vnc_client.connect(TestAuthType::VncAuthNone).is_ok());
    assert!(vnc_client
        .test_setup_encodings(Some(1), Some(EncodingType::EncodingRichCursor))
        .is_ok());
    let pf = RfbPixelFormat::new(32, 8, 0_u8, 1_u8, 255, 255, 255, 16, 8, 0);
    demo_gpu
        .borrow_mut()
        .replace_cursor(64, 64, 16, 16, 64 * 64 * 4);
    let res = vnc_client.test_recv_server_data(pf);
    assert!(res.is_ok());
    assert!(res.unwrap().contains(&(
        RfbServerMsg::FramebufferUpdate,
        EncodingType::EncodingRichCursor
    )));

    assert!(vnc_client
        .test_setup_encodings(Some(1), Some(EncodingType::EncodingAlphaCursor))
        .is_ok());
    demo_gpu
        .borrow_mut()
        .replace_cursor(64, 64, 16, 16, 64 * 64 * 4);
    let res = vnc_client.test_recv_server_data(pf);
    assert!(res.is_ok());
    assert!(res.unwrap().contains(&(
        RfbServerMsg::FramebufferUpdate,
        EncodingType::EncodingAlphaCursor
    )));

    assert!(vnc_client
        .test_setup_encodings(Some(1), Some(EncodingType::EncodingRichCursor))
        .is_ok());
    demo_gpu.borrow_mut().replace_cursor(64, 64, 16, 16, 0);
    assert!(vnc_client
        .test_setup_encodings(Some(1), Some(EncodingType::EncodingAlphaCursor))
        .is_ok());
    demo_gpu.borrow_mut().replace_cursor(64, 64, 16, 16, 0);
    assert!(vnc_client.disconnect().is_ok());

    let mut vnc_client = create_new_client(test_state.clone(), port).unwrap();
    assert!(vnc_client.connect(TestAuthType::VncAuthNone).is_ok());
    assert!(vnc_client.disconnect().is_ok());

    tear_down(gpu_list, input, test_state);
}

/// Brief:
/// When the surface size of VNC server is changed, server will inform
/// clients which has desktop_resize feature that the desktop size has been changed.
/// Preparation:
/// 1. Configure a demo pointer device and test GPU device.
/// 2. Start a VNC Server and listens on local ports.
/// 3. The demo gpu device create an image with size of 640 * 480 and sends it to VNC.
/// TestStep:
/// 1. VNC client connect to server.
/// 2. VNC client setting feature of EncodingDesktopresize.
/// 3. Demo GPU replace the surface of VNC server. -> expect 1.
/// 4. VNC client setting feature of Raw.
/// 5. Demo GPU replace the surface of VNC server. -> expect 2.
/// ExpectOutput
/// 1. VNC client received a desktop resize request from VNC server.
/// 2. VNC client not received any desktop resize request from VNC server.
#[test]
fn test_desktop_resize() {
    let port: u16 = 2;
    let mut gpu_list: Vec<DemoGpuConfig> = vec![];
    let gpu_conf = DemoGpuConfig {
        pci_slot: 3,
        id: "demo-pci-gpu".to_string(),
    };
    gpu_list.push(gpu_conf);
    let input_conf = InputConfig {
        pci_slot: 4,
        id: "demo-pci-input".to_string(),
    };
    let (gpu_list, input, test_state) = set_up(gpu_list, input_conf, port);
    let demo_gpu = gpu_list[0].clone();

    demo_gpu
        .borrow_mut()
        .replace_surface(640, 480, PIXMAN_A8B8G8R8);
    let mut vnc_client = create_new_client(test_state.clone(), port).unwrap();
    assert!(vnc_client.connect(TestAuthType::VncAuthNone).is_ok());
    assert!(vnc_client
        .test_setup_encodings(None, Some(EncodingType::EncodingDesktopresize))
        .is_ok());
    demo_gpu
        .borrow_mut()
        .replace_surface(1920, 1080, PIXMAN_A8B8G8R8);

    let pf = RfbPixelFormat::new(8, 8, 0_u8, 1_u8, 255, 255, 255, 16, 8, 0);
    let res = vnc_client.test_recv_server_data(pf);
    assert!(res.is_ok());
    assert!(res.unwrap().contains(&(
        RfbServerMsg::FramebufferUpdate,
        EncodingType::EncodingDesktopresize
    )));

    assert!(vnc_client
        .test_setup_encodings(None, Some(EncodingType::EncodingRaw))
        .is_ok());
    demo_gpu
        .borrow_mut()
        .replace_surface(640, 480, PIXMAN_A8B8G8R8);
    let pf = RfbPixelFormat::new(8, 8, 0_u8, 1_u8, 255, 255, 255, 16, 8, 0);
    let res = vnc_client.test_recv_server_data(pf);
    assert!(!res.unwrap().contains(&(
        RfbServerMsg::FramebufferUpdate,
        EncodingType::EncodingDesktopresize
    )));

    assert!(vnc_client.disconnect().is_ok());
    tear_down(gpu_list, input, test_state);
}

/// Brief:
/// The VNC server can receive image update request and return image data to client.
/// Preparation:
/// 1. Configure a demo pointer device and test GPU device.
/// 2. Start a VNC Server and listens on local ports.
/// 3. The demo gpu device create an image with size of 640 * 480 and sends it to VNC.
/// TestStep:
/// 1. VNC client connect to server.
/// 2. VNC client set pixel format.
/// 3. VNC client send framebuffer request + NotIncremental.
/// 4. VNC client check the image data from VNC server.
/// Situation:
///     1. Pixel format: Raw + bit_per_pixel=32 + true_color_flag=1 -> expect 1.
///     2. Pixel format: Raw + bit_per_pixel=16 + true_color_flag=1 -> expect 1.
///     3. Pixel format: Raw + bit_per_pixel=8 + true_color_flag=0. -> expect 2.
///     4. Pixel format: Hextile + bit_per_pixel=32 + true_color_flag=1 -> expect 1.
///     5. Pixel format: Hextile + bit_per_pixel=8 + true_color_flag=1 -> expect 1.
///     6. Pixel format: Hextile + bit_per_pixel=8 + true_color_flag=2 -> expect 2.
/// ExpectOutput:
/// 1. The image format meets expectations.
/// 2. The Image format meets expectations, VNC client receives the messages of set
///  color map information from VNC server.
#[test]
fn test_set_pixel_format() {
    let port: u16 = 3;
    let mut gpu_list: Vec<DemoGpuConfig> = vec![];
    let gpu_conf = DemoGpuConfig {
        pci_slot: 3,
        id: "demo-pci-gpu".to_string(),
    };
    gpu_list.push(gpu_conf);
    let input_conf = InputConfig {
        pci_slot: 4,
        id: "demo-pci-input".to_string(),
    };
    let (gpu_list, input, test_state) = set_up(gpu_list, input_conf, port);

    let mut vnc_client = create_new_client(test_state.clone(), port).unwrap();
    assert!(vnc_client.connect(TestAuthType::VncAuthNone).is_ok());
    assert!(vnc_client
        .test_setup_encodings(None, Some(EncodingType::EncodingRaw))
        .is_ok());
    assert!(vnc_client.stream_read_to_end().is_ok());

    // Raw + bit_per_pixel=32 + true_color_flag=1.
    let pf = RfbPixelFormat::new(32, 8, 0_u8, 1_u8, 255, 255, 255, 16, 8, 0);
    assert!(vnc_client.test_set_pixel_format(pf.clone()).is_ok());
    assert!(vnc_client
        .test_update_request(UpdateState::NotIncremental, 0, 0, 2560, 2048)
        .is_ok());
    let res = vnc_client.test_recv_server_data(pf);
    assert!(res.is_ok());
    assert!(res
        .unwrap()
        .contains(&(RfbServerMsg::FramebufferUpdate, EncodingType::EncodingRaw)));

    // Raw + bit_per_pixel=16 + true_color_flag=1.
    let pf = RfbPixelFormat::new(16, 8, 0_u8, 1_u8, 255, 255, 255, 16, 8, 0);
    assert!(vnc_client.test_set_pixel_format(pf.clone()).is_ok());
    assert!(vnc_client
        .test_update_request(UpdateState::NotIncremental, 0, 0, 2560, 2048)
        .is_ok());

    let res = vnc_client.test_recv_server_data(pf);
    assert!(res.is_ok());
    assert!(res
        .unwrap()
        .contains(&(RfbServerMsg::FramebufferUpdate, EncodingType::EncodingRaw)));

    // Raw + bit_per_pixel=8 + true_color_flag=0.
    let pf = RfbPixelFormat::new(8, 8, 0_u8, 0_u8, 255, 255, 255, 16, 8, 0);
    assert!(vnc_client.test_set_pixel_format(pf.clone()).is_ok());
    assert!(vnc_client
        .test_update_request(UpdateState::NotIncremental, 0, 0, 2560, 2048)
        .is_ok());

    let res = vnc_client.test_recv_server_data(pf.clone());
    assert!(res.is_ok());
    let res = res.unwrap();
    assert!(res.contains(&(RfbServerMsg::FramebufferUpdate, EncodingType::EncodingRaw)));
    assert!(res.contains(&(
        RfbServerMsg::SetColourMapEntries,
        EncodingType::EncodingInvalid
    )));

    // Hextile + bit_per_pixel=32 + true_color_flag=1.
    assert!(vnc_client
        .test_setup_encodings(None, Some(EncodingType::EncodingHextile))
        .is_ok());
    assert!(vnc_client.stream_read_to_end().is_ok());
    let pf = RfbPixelFormat::new(32, 8, 0_u8, 1_u8, 255, 255, 255, 16, 8, 0);
    assert!(vnc_client.test_set_pixel_format(pf.clone()).is_ok());
    assert!(vnc_client
        .test_update_request(UpdateState::NotIncremental, 0, 0, 2560, 2048)
        .is_ok());

    let res = vnc_client.test_recv_server_data(pf);
    assert!(res.is_ok());
    assert!(res.unwrap().contains(&(
        RfbServerMsg::FramebufferUpdate,
        EncodingType::EncodingHextile
    )));

    // Hextile + bit_per_pixel=8 + true_color_flag=1.
    assert!(vnc_client
        .test_setup_encodings(None, Some(EncodingType::EncodingHextile))
        .is_ok());
    assert!(vnc_client.stream_read_to_end().is_ok());
    let pf = RfbPixelFormat::new(8, 8, 0_u8, 1_u8, 255, 255, 255, 16, 8, 0);
    assert!(vnc_client.test_set_pixel_format(pf.clone()).is_ok());
    assert!(vnc_client
        .test_update_request(UpdateState::NotIncremental, 0, 0, 2560, 2048)
        .is_ok());
    let res = vnc_client.test_recv_server_data(pf);
    assert!(res.is_ok());
    assert!(res.unwrap().contains(&(
        RfbServerMsg::FramebufferUpdate,
        EncodingType::EncodingHextile
    )));

    // Hextile + bit_per_pixel=8 + true_color_flag=0.
    assert!(vnc_client
        .test_setup_encodings(None, Some(EncodingType::EncodingHextile))
        .is_ok());
    assert!(vnc_client.stream_read_to_end().is_ok());
    let pf = RfbPixelFormat::new(8, 8, 0_u8, 0_u8, 255, 255, 255, 16, 8, 0);
    assert!(vnc_client.test_set_pixel_format(pf.clone()).is_ok());
    assert!(vnc_client
        .test_update_request(UpdateState::NotIncremental, 0, 0, 2560, 2048)
        .is_ok());

    let res = vnc_client.test_recv_server_data(pf);
    assert!(res.is_ok());
    let res = res.unwrap();
    assert!(res.contains(&(
        RfbServerMsg::FramebufferUpdate,
        EncodingType::EncodingHextile
    )));
    assert!(res.contains(&(
        RfbServerMsg::SetColourMapEntries,
        EncodingType::EncodingInvalid
    )));
    assert!(vnc_client.disconnect().is_ok());

    tear_down(gpu_list, input, test_state);
}

/// Brief:
/// The VNC server can receive keyboard and pointer events.
/// Preparation:
/// 1. Configure a demo pointer device and test GPU device.
/// 2. Start a VNC Server and listens on local ports.
/// 3. The demo gpu device create an image with size of 640 * 480 and sends it to VNC.
/// TestStep
/// 1. VNC client connect to server.
/// 2. VNC client send key event -> expect 1.
/// 3. VNC client send pointer event -> expect 2.
/// ExpectOutput:
/// 1. VNC server received the keyboard event, the observed key value in demo keyboard device meets the expectation.
/// 2. VNC server received the pointer event, the observed coordinate in demo pointer device has been changed.
#[test]
fn test_vnc_kbd_mouse() {
    let port: u16 = 4;
    let mut gpu_list: Vec<DemoGpuConfig> = vec![];
    let gpu_conf = DemoGpuConfig {
        pci_slot: 3,
        id: "demo-pci-gpu".to_string(),
    };
    gpu_list.push(gpu_conf);
    let input_conf = InputConfig {
        pci_slot: 4,
        id: "demo-pci-input".to_string(),
    };
    let (gpu_list, input, test_state) = set_up(gpu_list, input_conf, port);
    let demo_gpu = gpu_list[0].clone();

    let mut vnc_client = create_new_client(test_state.clone(), port).unwrap();
    assert!(vnc_client.connect(TestAuthType::VncAuthNone).is_ok());
    // Key event.
    for &(name, keysym, keycode) in KEYEVENTLIST.iter() {
        assert!(vnc_client.test_key_event(0, keysym as u32).is_ok());
        let msg = input.borrow_mut().read_input_event();
        println!("key {:?}: {:?}", name, msg);
        assert_eq!(msg.keycode, keycode);
        assert_eq!(msg.down, 0);
        assert!(vnc_client.test_key_event(1, keysym as u32).is_ok());

        let msg = input.borrow_mut().read_input_event();
        println!("key {:?}: {:?}", name, msg);
        assert_eq!(msg.keycode, keycode);
        assert_eq!(msg.down, 1);
    }

    // Pointer event.
    let (button_mask, x, y) = POINTEVENTLIST[0];
    assert!(vnc_client.test_point_event(button_mask, x, y).is_ok());
    let mut old_msg = input.borrow_mut().read_input_event();
    for &(button_mask, x, y) in POINTEVENTLIST[1..].iter() {
        assert!(vnc_client.test_point_event(button_mask, x, y).is_ok());
        let msg = input.borrow_mut().read_input_event();
        // After sending the pointer event, the coordinate shoule be changed
        assert!(!(old_msg.button == msg.button && old_msg.x == msg.x && old_msg.y == msg.y));
        old_msg = msg;
        println!("msg: {:?}", msg);
    }
    assert!(vnc_client.disconnect().is_ok());
    demo_gpu.borrow_mut().deactive();
    tear_down(gpu_list, input, test_state);
}

/// Brief:
/// The display device can be switched through Ctl+Alt+Num on VNC client.
/// Preparation:
/// 1. Configure a demo pointer device and two test GPU device.
/// 2. Start a VNC Server and listens on local ports.
/// 3. First demo gpu device create an image with size of 640 * 480.
/// 4. Second demo gpu device create an image with size of 1920 * 1080.
/// TestStep:
/// 1. VNC client connect to server.
/// 2. VNC client setting feature of EncodingDesktopresize.
/// 3. VNC client send the key event of Ctl+Alt+Num -> expect 1.
/// ExpectOutput:
/// 1. The activate display device is be changed, and the VNC client receive the message of desktopresize.
#[test]
fn test_switch_display_device() {
    let port: u16 = 5;
    let mut gpu_list: Vec<DemoGpuConfig> = vec![];
    let gpu_conf = DemoGpuConfig {
        pci_slot: 3,
        id: "demo-pci-gpu_1".to_string(),
    };
    gpu_list.push(gpu_conf);
    let gpu_conf = DemoGpuConfig {
        pci_slot: 4,
        id: "demo-pci-gpu_2".to_string(),
    };
    gpu_list.push(gpu_conf);
    let input_conf = InputConfig {
        pci_slot: 5,
        id: "demo-pci-input".to_string(),
    };
    let (gpu_list, input, test_state) = set_up(gpu_list, input_conf, port);
    let demo_gpu_1 = gpu_list[0].clone();
    let demo_gpu_2 = gpu_list[1].clone();
    demo_gpu_1
        .borrow_mut()
        .replace_surface(640, 480, PIXMAN_A8B8G8R8);
    demo_gpu_2
        .borrow_mut()
        .replace_surface(1920, 1080, PIXMAN_A8B8G8R8);

    let mut vnc_client = create_new_client(test_state.clone(), port).unwrap();
    assert!(vnc_client.connect(TestAuthType::VncAuthNone).is_ok());
    assert!(vnc_client
        .test_setup_encodings(None, Some(EncodingType::EncodingDesktopresize))
        .is_ok());

    // Ctl + Alt + 2.
    assert!(vnc_client.test_key_event(1, 0xffe3).is_ok());
    assert!(vnc_client.test_key_event(1, 0xffe9).is_ok());
    assert!(vnc_client.test_key_event(1, 0x32).is_ok());

    let pf = RfbPixelFormat::new(8, 8, 0_u8, 1_u8, 255, 255, 255, 16, 8, 0);
    let res = vnc_client.test_recv_server_data(pf);
    assert!(res.is_ok());
    assert!(res.unwrap().contains(&(
        RfbServerMsg::FramebufferUpdate,
        EncodingType::EncodingDesktopresize
    )));

    tear_down(gpu_list, input, test_state);
}

/// Brief:
/// Test possible exceptions during image update.
/// Preparation:
/// 1. Configure a demo pointer device and test GPU device.
/// 2. Start a VNC Server and listens on local ports.
/// 3. The demo gpu device create an image with size of 640 * 480 and sends it to VNC.
/// TestStep:
/// 1. VNC client connect to server.
/// 2. Demo GPU do some operation.
/// Abnormal Situation:
///     1. The area to set dirty is out of range -> expect 1.
///     2. The image size exceeds value -> expect 1.
///     3. Switch different pixman formats -> expect 1.
/// ExpectOutput:
/// 1. The status of VNC server status is normal and can handle the next connect request.
#[test]
fn test_update_image_abnormal() {
    let port: u16 = 6;
    let mut gpu_list: Vec<DemoGpuConfig> = vec![];
    let gpu_conf = DemoGpuConfig {
        pci_slot: 3,
        id: "demo-pci-gpu".to_string(),
    };
    gpu_list.push(gpu_conf);
    let input_conf = InputConfig {
        pci_slot: 4,
        id: "demo-pci-input".to_string(),
    };
    let (gpu_list, input, test_state) = set_up(gpu_list, input_conf, port);
    let demo_gpu = gpu_list[0].clone();

    demo_gpu
        .borrow_mut()
        .replace_surface(640, 480, PIXMAN_A8B8G8R8);
    demo_gpu.borrow_mut().set_area_dirty(0, 0, 65535, 65535);
    demo_gpu
        .borrow_mut()
        .replace_surface(65535, 65535, PIXMAN_A8B8G8R8);
    demo_gpu
        .borrow_mut()
        .replace_surface(640, 480, PIXMAN_X2R10G10B10);
    demo_gpu
        .borrow_mut()
        .replace_surface(1080, 720, PIXMAN_R8G8B8);
    demo_gpu.borrow_mut().replace_surface(640, 480, PIXMAN_A1);
    demo_gpu
        .borrow_mut()
        .replace_surface(1080, 720, PIXMAN_YUY2);
    demo_gpu
        .borrow_mut()
        .replace_surface(640, 480, PIXMAN_A8B8G8R8);
    let mut vnc_client = create_new_client(test_state.clone(), port).unwrap();
    assert!(vnc_client.connect(TestAuthType::VncAuthNone).is_ok());
    let value = qmp_query_vnc(test_state.clone());
    let client_num = value["return"]["clients"].as_array().unwrap().len();
    assert!(client_num >= 1);
    assert!(vnc_client.disconnect().is_ok());
    tear_down(gpu_list, input, test_state);
}

fn test_rfb_version_abnormal(test_state: Rc<RefCell<TestState>>, port: u16) -> Result<()> {
    let mut buf: Vec<u8> = Vec::new();
    let mut vnc_client = create_new_client(test_state, port).unwrap();
    println!("Connect to server.");
    assert!(vnc_client.read_msg(&mut buf, 12).is_ok());
    assert_eq!(buf[..12].to_vec(), "RFB 003.008\n".as_bytes().to_vec());
    println!("Client Rfb version: RFB 003.010");
    assert!(vnc_client
        .write_msg(&"RFB 003.010\n".as_bytes().to_vec())
        .is_ok());
    buf.drain(..12);
    // VNC server closed connection.
    let res = vnc_client.epoll_wait(EventSet::READ_HANG_UP);
    assert!(res.is_ok());
    assert!(res.unwrap() > 0);
    assert_ne!(
        vnc_client.ready_events[0].events() & EventSet::READ_HANG_UP.bits(),
        0
    );
    assert!(vnc_client.disconnect().is_ok());

    Ok(())
}

fn test_unsupport_sec_type(test_state: Rc<RefCell<TestState>>, port: u16) -> Result<()> {
    let mut buf: Vec<u8> = Vec::new();
    let mut vnc_client = create_new_client(test_state, port).unwrap();
    println!("Connect to server.");
    assert!(vnc_client.read_msg(&mut buf, 12).is_ok());
    assert_eq!(buf[..12].to_vec(), "RFB 003.008\n".as_bytes().to_vec());
    assert!(vnc_client
        .write_msg(&"RFB 003.008\n".as_bytes().to_vec())
        .is_ok());
    buf.drain(..12);

    // Step 2: Auth num is 1.
    assert!(vnc_client.read_msg(&mut buf, 1).is_ok());
    let auth_num = buf[0];
    assert!(auth_num > 0);
    buf.drain(..1);
    assert!(vnc_client.read_msg(&mut buf, auth_num as usize).is_ok());
    buf.drain(..auth_num as usize);
    assert!(vnc_client
        .write_msg(&(TestAuthType::Invalid as u8).to_be_bytes().to_vec())
        .is_ok());
    // VNC server close the connection.
    let res = vnc_client.epoll_wait(EventSet::READ_HANG_UP);
    assert!(res.is_ok());
    assert!(res.unwrap() > 0);
    assert_ne!(
        vnc_client.ready_events[0].events() & EventSet::READ_HANG_UP.bits(),
        0
    );
    assert!(vnc_client.disconnect().is_ok());

    Ok(())
}

fn test_set_pixel_format_abnormal(test_state: Rc<RefCell<TestState>>, port: u16) -> Result<()> {
    let mut vnc_client = create_new_client(test_state, port).unwrap();
    assert!(vnc_client.connect(TestAuthType::VncAuthNone).is_ok());
    let pf = RfbPixelFormat::new(17, 8, 0_u8, 1_u8, 255, 255, 255, 16, 8, 0);
    assert!(vnc_client.test_set_pixel_format(pf.clone()).is_ok());

    // VNC server close the connection.
    let res = vnc_client.epoll_wait(EventSet::READ_HANG_UP)?;
    assert!(res > 0);
    assert_ne!(
        vnc_client.ready_events[0].events() & EventSet::READ_HANG_UP.bits(),
        0
    );

    assert!(vnc_client.disconnect().is_ok());
    Ok(())
}

fn test_set_encoding_abnormal(test_state: Rc<RefCell<TestState>>, port: u16) -> Result<()> {
    let mut vnc_client = create_new_client(test_state.clone(), port).unwrap();
    assert!(vnc_client.connect(TestAuthType::VncAuthNone).is_ok());
    assert!(vnc_client.test_setup_encodings(Some(100), None).is_ok());
    // Send a qmp to query vnc client state.
    let value = qmp_query_vnc(test_state.clone());
    let client_num = value["return"]["clients"].as_array().unwrap().len();
    assert_eq!(client_num, 1);
    assert!(vnc_client.disconnect().is_ok());
    Ok(())
}

fn test_client_cut_event(test_state: Rc<RefCell<TestState>>, port: u16) -> Result<()> {
    let mut vnc_client = create_new_client(test_state.clone(), port).unwrap();
    assert!(vnc_client.connect(TestAuthType::VncAuthNone).is_ok());
    let text = "Stratovirt".to_string();
    let client_cut = TestClientCut {
        event_type: RfbClientMessage::RfbClientCutText,
        pad0: 0,
        pad1: 0,
        length: text.len() as u32,
        text: text,
    };
    assert!(vnc_client.test_send_client_cut(client_cut).is_ok());
    // Send a qmp to query vnc client state.
    let value = qmp_query_vnc(test_state.clone());
    let client_num = value["return"]["clients"].as_array().unwrap().len();
    assert_eq!(client_num, 1);
    assert!(vnc_client.disconnect().is_ok());
    Ok(())
}

fn test_client_rand_bytes(test_state: Rc<RefCell<TestState>>, port: u16) -> Result<()> {
    let mut vnc_client = create_new_client(test_state, port).unwrap();
    assert!(vnc_client.connect(TestAuthType::VncAuthNone).is_ok());
    let mut buf = TEST_CLIENT_RAND_MSG;
    vnc_client.write_msg(&mut buf)?;
    assert!(vnc_client.disconnect().is_ok());
    Ok(())
}

/// Brief:
/// Test possible exceptions during RFB protocol connection.
/// Preparation:
/// 1. Configure a demo pointer device and test GPU device.
/// 2. Start a VNC Server and listens on local ports.
/// 3. The demo gpu device create an image with size of 640 * 480 and sends it to VNC.
/// TestStep:
/// 1. VNC client connect to server.
/// 2. VNC client set pixel format.
/// 3. VNC client send framebuffer request + NotIncremental.
/// 4. VNC client check the image data from VNC server.
/// Abnormal Situation:
///     1. Unsupport RFB version -> expect 1 + 2.
///     2. Unsupport security type -> expect 1 + 2.
///     3. The message of set pixel formal is abnormal -> expect 1 + 2.
///     4. Send the rand bytes from the client -> expect 2.
///     5. Send set encoding event: encoding number abnormal -> expect 2.
///     6. Unsupported event: Client cut event is not supported now -> expect 2.
/// ExpectOutput:
/// 1. VNC server close the connection.
/// 2. The status of VNC server status is normal and can handle the next connect request.
#[test]
fn test_rfb_abnormal() {
    let port: u16 = 7;
    let mut gpu_list: Vec<DemoGpuConfig> = vec![];
    let gpu_conf = DemoGpuConfig {
        pci_slot: 3,
        id: "demo-pci-gpu".to_string(),
    };
    gpu_list.push(gpu_conf);
    let input_conf = InputConfig {
        pci_slot: 4,
        id: "demo-pci-input".to_string(),
    };
    let (gpu_list, input, test_state) = set_up(gpu_list, input_conf, port);

    assert!(test_rfb_version_abnormal(test_state.clone(), port).is_ok());
    assert!(test_unsupport_sec_type(test_state.clone(), port).is_ok());
    assert!(test_set_pixel_format_abnormal(test_state.clone(), port).is_ok());
    assert!(test_set_encoding_abnormal(test_state.clone(), port).is_ok());
    assert!(test_client_cut_event(test_state.clone(), port).is_ok());
    assert!(test_client_rand_bytes(test_state.clone(), port).is_ok());

    let mut vnc_client = create_new_client(test_state.clone(), port).unwrap();
    assert!(vnc_client.connect(TestAuthType::VncAuthNone).is_ok());
    let value = qmp_query_vnc(test_state.clone());
    let client_num = value["return"]["clients"].as_array().unwrap().len();
    assert_eq!(client_num, 1);
    assert!(vnc_client.disconnect().is_ok());

    tear_down(gpu_list, input, test_state);
}
