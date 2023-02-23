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

use mod_test::libdriver::pci::{PCI_DEVICE_ID, PCI_VENDOR_ID};
use mod_test::libdriver::usb::{
    clear_iovec, qmp_send_key_event, qmp_send_multi_key_event, qmp_send_pointer_event, TestIovec,
    TestNormalTRB, TestUsbBuilder, CONTROL_ENDPOINT_ID, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN,
    HID_POINTER_LEN, KEYCODE_NUM1, KEYCODE_SPACE, PCI_CLASS_PI, PRIMARY_INTERRUPTER_ID,
    TD_TRB_LIMIT, XHCI_PCI_OPER_OFFSET, XHCI_PORTSC_OFFSET,
};
use usb::config::*;
use usb::usb::UsbDeviceRequest;
use usb::xhci::xhci_controller::{
    DwordOrder, XhciInputCtrlCtx, XhciSlotCtx, EP_RUNNING, SLOT_ADDRESSED,
};
use usb::xhci::xhci_regs::{
    XHCI_INTR_REG_ERSTBA_LO, XHCI_INTR_REG_ERSTSZ, XHCI_OPER_REG_CONFIG, XHCI_OPER_REG_USBSTS,
};
use usb::xhci::{TRBCCode, TRBType, TRB_SIZE};

#[test]
fn test_xhci_keyboard_basic() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    // Case 1
    // Space down
    qmp_send_key_event(test_state.borrow_mut(), KEYCODE_SPACE, true);
    let transfer_ptr = xhci.get_transfer_pointer(slot_id, HID_DEVICE_ENDPOINT_ID);
    let data_ptr = xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    assert_eq!(transfer_ptr, evt.ptr);
    let buf = xhci.get_transfer_data_direct(data_ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 44, 0, 0, 0, 0, 0]);
    // Space up
    qmp_send_key_event(test_state.borrow_mut(), KEYCODE_SPACE, false);
    let transfer_ptr = xhci.get_transfer_pointer(slot_id, HID_DEVICE_ENDPOINT_ID);
    let data_ptr = xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    assert_eq!(transfer_ptr, evt.ptr);
    let buf = xhci.get_transfer_data_direct(data_ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 0, 0, 0, 0, 0, 0]);

    // Case 2
    let key_list = vec![
        KEYCODE_NUM1,
        KEYCODE_NUM1 + 1,
        KEYCODE_NUM1 + 2,
        KEYCODE_NUM1 + 3,
    ];
    qmp_send_multi_key_event(test_state.clone(), &key_list, true);
    xhci.queue_multi_indirect_td(
        slot_id,
        HID_DEVICE_ENDPOINT_ID,
        HID_KEYBOARD_LEN,
        key_list.len(),
    );
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    // 1 2 3 4 down
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 30, 0, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 30, 31, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 30, 31, 32, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 30, 31, 32, 33, 0, 0]);
    // 1 2 3 4 Up
    qmp_send_multi_key_event(test_state.clone(), &key_list, false);
    xhci.queue_multi_indirect_td(
        slot_id,
        HID_DEVICE_ENDPOINT_ID,
        HID_KEYBOARD_LEN,
        key_list.len(),
    );
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 33, 31, 32, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 33, 32, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 33, 0, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 0, 0, 0, 0, 0, 0]);
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_direct() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    let key_list = vec![
        KEYCODE_NUM1,
        KEYCODE_NUM1 + 1,
        KEYCODE_NUM1 + 2,
        KEYCODE_NUM1 + 3,
    ];
    qmp_send_multi_key_event(test_state.clone(), &key_list, true);
    xhci.queue_multi_direct_td(
        slot_id,
        HID_DEVICE_ENDPOINT_ID,
        HID_KEYBOARD_LEN,
        key_list.len(),
    );
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    // 1 2 3 4 Down
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_direct(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 30, 0, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_direct(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 30, 31, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_direct(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 30, 31, 32, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_direct(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 30, 31, 32, 33, 0, 0]);
    // 1 2 3 4 Up
    qmp_send_multi_key_event(test_state.clone(), &key_list, false);
    xhci.queue_multi_direct_td(
        slot_id,
        HID_DEVICE_ENDPOINT_ID,
        HID_KEYBOARD_LEN,
        key_list.len(),
    );
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_direct(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 33, 31, 32, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_direct(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 33, 32, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_direct(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 33, 0, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_direct(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 0, 0, 0, 0, 0, 0]);
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_multi_trb() {
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    let key_list = vec![
        KEYCODE_NUM1,
        KEYCODE_NUM1 + 1,
        KEYCODE_NUM1 + 2,
        KEYCODE_NUM1 + 3,
    ];
    qmp_send_multi_key_event(test_state.clone(), &key_list, true);
    let mut io_list = Vec::new();
    for _ in 0..4 {
        let mut iovecs = Vec::new();
        let ptr = guest_allocator.borrow_mut().alloc(2);
        let iovec = TestIovec::new(ptr, 2, false);
        iovecs.push(iovec);
        let ptr = guest_allocator.borrow_mut().alloc(2);
        let iovec = TestIovec::new(ptr, 2, true);
        iovecs.push(iovec);
        let ptr = guest_allocator.borrow_mut().alloc(4);
        let iovec = TestIovec::new(ptr, 4, false);
        iovecs.push(iovec);
        xhci.queue_td_by_iovec(slot_id, HID_DEVICE_ENDPOINT_ID, &mut iovecs, true);
        io_list.push(iovecs);
    }
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    // 1 2 3 4 Down
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[0]);
    assert_eq!(buf, [0, 0, 30, 0, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[1]);
    assert_eq!(buf, [0, 0, 30, 31, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[2]);
    assert_eq!(buf, [0, 0, 30, 31, 32, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[3]);
    assert_eq!(buf, [0, 0, 30, 31, 32, 33, 0, 0]);
    // 1 2 3 4 Up
    qmp_send_multi_key_event(test_state.clone(), &key_list, false);
    let mut io_list = Vec::new();
    for _ in 0..4 {
        let mut iovecs = Vec::new();
        let ptr = guest_allocator.borrow_mut().alloc(2);
        let iovec = TestIovec::new(ptr, 2, false);
        iovecs.push(iovec);
        let ptr = guest_allocator.borrow_mut().alloc(2);
        let iovec = TestIovec::new(ptr, 2, true);
        iovecs.push(iovec);
        let ptr = guest_allocator.borrow_mut().alloc(4);
        let iovec = TestIovec::new(ptr, 4, false);
        iovecs.push(iovec);
        xhci.queue_td_by_iovec(slot_id, HID_DEVICE_ENDPOINT_ID, &mut iovecs, true);
        io_list.push(iovecs);
    }
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[0]);
    assert_eq!(buf, [0, 0, 33, 31, 32, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[1]);
    assert_eq!(buf, [0, 0, 33, 32, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[2]);
    assert_eq!(buf, [0, 0, 33, 0, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[3]);
    assert_eq!(buf, [0, 0, 0, 0, 0, 0, 0, 0]);
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_event_data() {
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    let key_list = vec![
        KEYCODE_NUM1,
        KEYCODE_NUM1 + 1,
        KEYCODE_NUM1 + 2,
        KEYCODE_NUM1 + 3,
    ];
    qmp_send_multi_key_event(test_state.clone(), &key_list, true);
    let mut io_list = Vec::new();
    for _ in 0..4 {
        let mut iovecs = Vec::new();
        let ptr = guest_allocator.borrow_mut().alloc(2);
        let iovec = TestIovec::new(ptr, 2, false);
        iovecs.push(iovec);
        let ptr = guest_allocator.borrow_mut().alloc(2);
        let iovec = TestIovec::new(ptr, 2, true);
        iovecs.push(iovec);
        let ptr = guest_allocator.borrow_mut().alloc(4);
        let iovec = TestIovec::new(ptr, 4, false);
        iovecs.push(iovec);
        // Event Data TRB
        let mut iovec = TestIovec::new(0xff00ff00ff00ff00, 0, false);
        iovec.event_data = true;
        iovecs.push(iovec);
        xhci.queue_td_by_iovec(slot_id, HID_DEVICE_ENDPOINT_ID, &mut iovecs, true);
        io_list.push(iovecs);
    }
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    // 1 2 3 4 Down
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    assert_eq!(evt.length, 8);
    assert_eq!(evt.ptr, 0xff00ff00ff00ff00);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[0]);
    assert_eq!(buf, [0, 0, 30, 0, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    assert_eq!(evt.length, 8);
    assert_eq!(evt.ptr, 0xff00ff00ff00ff00);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[1]);
    assert_eq!(buf, [0, 0, 30, 31, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    assert_eq!(evt.length, 8);
    assert_eq!(evt.ptr, 0xff00ff00ff00ff00);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[2]);
    assert_eq!(buf, [0, 0, 30, 31, 32, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    assert_eq!(evt.length, 8);
    assert_eq!(evt.ptr, 0xff00ff00ff00ff00);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[3]);
    assert_eq!(buf, [0, 0, 30, 31, 32, 33, 0, 0]);
    // 1 2 3 4 Up
    qmp_send_multi_key_event(test_state.clone(), &key_list, false);
    let mut io_list = Vec::new();
    for _ in 0..4 {
        let mut iovecs = Vec::new();
        let ptr = guest_allocator.borrow_mut().alloc(2);
        let iovec = TestIovec::new(ptr, 2, true);
        iovecs.push(iovec);
        let ptr = guest_allocator.borrow_mut().alloc(2);
        let iovec = TestIovec::new(ptr, 2, false);
        iovecs.push(iovec);
        let ptr = guest_allocator.borrow_mut().alloc(4);
        let iovec = TestIovec::new(ptr, 4, false);
        iovecs.push(iovec);
        // Event Data TRB
        let mut iovec = TestIovec::new(0xff00ff00ff00ff00, 0, false);
        iovec.event_data = true;
        iovecs.push(iovec);
        xhci.queue_td_by_iovec(slot_id, HID_DEVICE_ENDPOINT_ID, &mut iovecs, true);
        io_list.push(iovecs);
    }
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    assert_eq!(evt.length, 8);
    assert_eq!(evt.ptr, 0xff00ff00ff00ff00);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[0]);
    assert_eq!(buf, [0, 0, 33, 31, 32, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    assert_eq!(evt.length, 8);
    assert_eq!(evt.ptr, 0xff00ff00ff00ff00);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[1]);
    assert_eq!(buf, [0, 0, 33, 32, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    assert_eq!(evt.length, 8);
    assert_eq!(evt.ptr, 0xff00ff00ff00ff00);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[2]);
    assert_eq!(buf, [0, 0, 33, 0, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    assert_eq!(evt.length, 8);
    assert_eq!(evt.ptr, 0xff00ff00ff00ff00);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[3]);
    assert_eq!(buf, [0, 0, 0, 0, 0, 0, 0, 0]);
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_over_hid_buffer() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    const HID_BUFFER_SIZE: u32 = 16;
    let event_cnt = 20;
    // 1 -> 0 down / up
    for i in 0..(event_cnt / 2) {
        qmp_send_key_event(test_state.borrow_mut(), 2 + i, true);
        qmp_send_key_event(test_state.borrow_mut(), 2 + i, false);
    }
    xhci.queue_multi_indirect_td(
        slot_id,
        HID_DEVICE_ENDPOINT_ID,
        HID_KEYBOARD_LEN,
        event_cnt as usize,
    );
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    for i in 0..event_cnt {
        if i < HID_BUFFER_SIZE {
            let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
            assert_eq!(evt.ccode, TRBCCode::Success as u32);
            let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
            if i % 2 == 0 {
                assert_eq!(buf, [0, 0, 30 + i as u8 / 2, 0, 0, 0, 0, 0]);
            } else {
                assert_eq!(buf, [0, 0, 0, 0, 0, 0, 0, 0]);
            }
        } else {
            // event lost.
            assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());
        }
    }
    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_over_ring_limit() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    let org_ptr = xhci.get_transfer_pointer(slot_id, HID_DEVICE_ENDPOINT_ID);
    // Fake ring length.
    let transfer_limit = 32;
    let test_cnt = 3;
    for i in 0..test_cnt {
        for _ in 0..(transfer_limit / 2) {
            qmp_send_key_event(test_state.borrow_mut(), KEYCODE_SPACE, true);
            xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN);
            qmp_send_key_event(test_state.borrow_mut(), KEYCODE_SPACE, false);
            xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN);
            xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
            let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
            assert_eq!(evt.ccode, TRBCCode::Success as u32);
            let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
            assert_eq!(buf, [0, 0, 44, 0, 0, 0, 0, 0]);
            let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
            assert_eq!(evt.ccode, TRBCCode::Success as u32);
            let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
            assert_eq!(buf, [0, 0, 0, 0, 0, 0, 0, 0]);
        }
        if i == 0 {
            // Fake link new addrress.
            xhci.queue_link_trb(
                slot_id,
                HID_DEVICE_ENDPOINT_ID,
                org_ptr + TRB_SIZE as u64 * 64,
                false,
            );
        } else if i == 1 {
            // Goto the origin address.
            xhci.queue_link_trb(slot_id, HID_DEVICE_ENDPOINT_ID, org_ptr, true);
        } else {
            xhci.queue_link_trb(slot_id, HID_DEVICE_ENDPOINT_ID, org_ptr, true);
            let ptr = xhci.get_transfer_pointer(slot_id, HID_DEVICE_ENDPOINT_ID);
            assert_eq!(org_ptr, ptr);
        }
    }
    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_reorder() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    xhci.queue_multi_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN, 4);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());
    let key_list = vec![
        KEYCODE_NUM1,
        KEYCODE_NUM1 + 1,
        KEYCODE_NUM1 + 2,
        KEYCODE_NUM1 + 3,
    ];
    qmp_send_multi_key_event(test_state.clone(), &key_list, true);
    // 1 2 3 4 Down
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 30, 0, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 30, 31, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 30, 31, 32, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 30, 31, 32, 33, 0, 0]);
    // 1 2 3 4 Up
    let key_list = vec![
        KEYCODE_NUM1,
        KEYCODE_NUM1 + 1,
        KEYCODE_NUM1 + 2,
        KEYCODE_NUM1 + 3,
    ];
    qmp_send_multi_key_event(test_state.clone(), &key_list[0..2], false);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());
    xhci.queue_multi_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN, 2);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    xhci.queue_multi_indirect_td(
        slot_id,
        HID_DEVICE_ENDPOINT_ID,
        HID_KEYBOARD_LEN,
        key_list.len() - 2,
    );
    qmp_send_multi_key_event(test_state.clone(), &key_list[2..], false);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 33, 31, 32, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 33, 32, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 33, 0, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 0, 0, 0, 0, 0, 0]);
    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_remote_wakeup() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    // U0 -> U3
    // NOTE: write PLS field should set LWS field.
    xhci.port_regs_write(
        port_id,
        XHCI_PORTSC_OFFSET,
        PORTSC_LWS | PLS_U3 << PORTSC_PLS_SHIFT,
    );
    let portsc = xhci.port_regs_read(port_id, XHCI_PORTSC_OFFSET);
    assert!(portsc >> PORTSC_PLS_SHIFT & PLS_U3 == PLS_U3);

    // Set remote wakeup.
    xhci.set_feature(slot_id, USB_DEVICE_REMOTE_WAKEUP as u16);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    qmp_send_key_event(test_state.borrow_mut(), KEYCODE_SPACE, true);
    xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN);
    qmp_send_key_event(test_state.borrow_mut(), KEYCODE_SPACE, false);
    xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);

    // U3 -> U0
    xhci.port_regs_write(
        port_id,
        XHCI_PORTSC_OFFSET,
        PORTSC_LWS | PLS_U0 << PORTSC_PLS_SHIFT,
    );
    let portsc = xhci.port_regs_read(port_id, XHCI_PORTSC_OFFSET);
    assert!(portsc >> PORTSC_PLS_SHIFT & PLS_U0 == PLS_U0);
    assert!(portsc & PORTSC_PLC == PORTSC_PLC);

    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    assert_eq!(evt.get_trb_type(), TRBType::ErPortStatusChange as u32);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 44, 0, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 0, 0, 0, 0, 0, 0]);
    test_state.borrow_mut().stop();
}

// Abnormal
#[test]
fn test_xhci_keyboard_invalid_value() {
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    // Case 1: invalid code
    qmp_send_key_event(test_state.borrow_mut(), 0, true);
    xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
    assert_eq!(buf, [0, 0, 0, 0, 0, 0, 0, 0]);

    // Case 2: invalid cycle bit
    qmp_send_key_event(test_state.borrow_mut(), 2, true);
    let mut trb = TestNormalTRB::default();
    let ptr = guest_allocator.borrow_mut().alloc(8);
    trb.set_pointer(ptr);
    trb.set_ioc_flag(true);
    trb.set_trb_type(TRBType::TrNormal as u32);
    trb.force_cycle = true;
    trb.set_trb_transfer_length(8);
    xhci.queue_trb(slot_id, HID_DEVICE_ENDPOINT_ID, &mut trb);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());
    // clean td
    xhci.stop_endpoint(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let old_ptr = xhci.get_transfer_pointer(slot_id, HID_DEVICE_ENDPOINT_ID);
    xhci.set_tr_dequeue(old_ptr + 0x20, slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    // Case 3: invalid down length.
    const KEY_LIMIT: u32 = 6;
    let key_len = 10;
    for i in 0..key_len {
        qmp_send_key_event(test_state.borrow_mut(), 2 + i, true);
        xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN);
        xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        if i >= KEY_LIMIT {
            // rollover
            let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
            assert_eq!(buf, [0, 0, 1, 1, 1, 1, 1, 1]);
        }
    }
    for i in (0..key_len).rev() {
        qmp_send_key_event(test_state.borrow_mut(), 2 + i, false);
        xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN);
        xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        if i == 0 {
            let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
            assert_eq!(buf, [0, 0, 0, 0, 0, 0, 0, 0]);
        }
    }

    // Case 4: length over 8 when IDT = 1.
    qmp_send_key_event(test_state.borrow_mut(), 2, true);
    let mut trb = TestNormalTRB::default();
    trb.set_ioc_flag(true);
    trb.set_isp_flag(true);
    trb.set_idt_flag(true);
    trb.set_trb_type(TRBType::TrNormal as u32);
    trb.set_trb_transfer_length(10);
    xhci.queue_trb(slot_id, HID_DEVICE_ENDPOINT_ID, &mut trb);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::TrbError as u32);
    // clean up key event.
    qmp_send_key_event(test_state.borrow_mut(), 2, false);
    xhci.queue_multi_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN, 2);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_invalid_buffer() {
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    // over limit
    qmp_send_key_event(test_state.borrow_mut(), 2, true);
    qmp_send_key_event(test_state.borrow_mut(), 3, true);
    let mut io_list = Vec::new();
    for _ in 0..2 {
        let mut iovecs = Vec::new();
        let ptr = guest_allocator.borrow_mut().alloc(5);
        let iovec = TestIovec::new(ptr, 5, false);
        iovecs.push(iovec);
        let ptr = guest_allocator.borrow_mut().alloc(2);
        let iovec = TestIovec::new(ptr, 2, true);
        iovecs.push(iovec);
        let ptr = guest_allocator.borrow_mut().alloc(4);
        let iovec = TestIovec::new(ptr, 4, false);
        iovecs.push(iovec);
        xhci.queue_td_by_iovec(slot_id, HID_DEVICE_ENDPOINT_ID, &mut iovecs, true);
        // NOTE: ensure the memory is zero.
        clear_iovec(test_state.borrow_mut(), &iovecs);
        io_list.push(iovecs);
    }
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[0]);
    assert_eq!(buf, [0, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[1]);
    assert_eq!(buf, [0, 0, 30, 31, 0, 0, 0, 0, 0, 0, 0]);
    // less buffer.
    qmp_send_key_event(test_state.borrow_mut(), 2, false);
    qmp_send_key_event(test_state.borrow_mut(), 3, false);
    let mut io_list = Vec::new();
    for _ in 0..2 {
        let mut iovecs = Vec::new();
        let ptr = guest_allocator.borrow_mut().alloc(2);
        let iovec = TestIovec::new(ptr, 2, true);
        iovecs.push(iovec);
        let ptr = guest_allocator.borrow_mut().alloc(2);
        let iovec = TestIovec::new(ptr, 2, false);
        iovecs.push(iovec);
        let ptr = guest_allocator.borrow_mut().alloc(2);
        let iovec = TestIovec::new(ptr, 2, false);
        iovecs.push(iovec);
        xhci.queue_td_by_iovec(slot_id, HID_DEVICE_ENDPOINT_ID, &mut iovecs, true);
        // NOTE: ensure the memory is zero.
        clear_iovec(test_state.borrow_mut(), &iovecs);
        io_list.push(iovecs);
    }
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[0]);
    assert_eq!(buf, [0, 0, 31, 0, 0, 0]);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_by_iovec(&io_list[1]);
    assert_eq!(buf, [0, 0, 0, 0, 0, 0]);

    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_over_transfer_ring() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .with_config("over_transfer_ring", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    qmp_send_key_event(test_state.borrow_mut(), 2, true);
    qmp_send_key_event(test_state.borrow_mut(), 3, true);
    xhci.queue_multi_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN, 2);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // link trb overlimit by setting next trb to itself.
    let ptr = xhci.get_transfer_pointer(slot_id, HID_DEVICE_ENDPOINT_ID);
    xhci.queue_link_trb(slot_id, HID_DEVICE_ENDPOINT_ID, ptr, false);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    // Host Controller Error
    let status = xhci.oper_regs_read(XHCI_OPER_REG_USBSTS as u64);
    assert!(status & USB_STS_HCE == USB_STS_HCE);

    xhci.reset_controller(true);
    let slot_id = xhci.init_device(port_id);
    // Invalid iovec over td limit.
    let trb_limit = TD_TRB_LIMIT;
    let mut iovecs = vec![TestIovec::new(0, 1, true); trb_limit as usize];
    xhci.queue_td_by_iovec(slot_id, HID_DEVICE_ENDPOINT_ID, &mut iovecs, false);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    // Host Controller Error
    let status = xhci.oper_regs_read(XHCI_OPER_REG_USBSTS as u64);
    assert!(status & USB_STS_HCE == USB_STS_HCE);

    xhci.reset_controller(true);
    let slot_id = xhci.init_device(port_id);
    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_over_event_ring() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();
    // reset event ring.
    let evt_ring_sz = 16;
    xhci.init_event_ring(0, 1, evt_ring_sz);
    xhci.init_msix();
    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    // only one trb left in event ring it will report ring full error.
    for i in 0..evt_ring_sz - 1 {
        qmp_send_key_event(test_state.borrow_mut(), 2 + i, true);
    }
    xhci.queue_multi_indirect_td(
        slot_id,
        HID_DEVICE_ENDPOINT_ID,
        HID_KEYBOARD_LEN,
        evt_ring_sz as usize - 1,
    );
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    // NOTE: the last event is lost for the current implementation.
    for _ in 0..evt_ring_sz - 2 {
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
    }
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::EventRingFullError as u32);

    for i in 0..evt_ring_sz {
        qmp_send_key_event(test_state.borrow_mut(), 2 + i, false);
    }

    xhci.queue_multi_indirect_td(
        slot_id,
        HID_DEVICE_ENDPOINT_ID,
        HID_KEYBOARD_LEN,
        evt_ring_sz as usize,
    );

    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let status = xhci.oper_regs_read(XHCI_OPER_REG_USBSTS as u64);
    assert!(status & USB_STS_HCE == USB_STS_HCE);

    xhci.reset_controller(true);
    let slot_id = xhci.init_device(port_id);
    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_invalid_doorbell() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("command_auto_doorbell", true)
        .with_config("auto_run", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    qmp_send_key_event(test_state.borrow_mut(), 2, true);
    qmp_send_key_event(test_state.borrow_mut(), 3, true);
    xhci.queue_indirect_td(slot_id, 2, HID_KEYBOARD_LEN);
    xhci.queue_indirect_td(0, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());
    xhci.queue_multi_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN, 2);
    xhci.doorbell_write(slot_id, 0xff);
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());
    xhci.doorbell_write(0xff, HID_DEVICE_ENDPOINT_ID);
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());

    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    qmp_send_key_event(test_state.borrow_mut(), 2, false);
    qmp_send_key_event(test_state.borrow_mut(), 3, false);
    xhci.queue_indirect_td(2, 2, HID_KEYBOARD_LEN);
    xhci.queue_indirect_td(0, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());
    xhci.queue_multi_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN, 2);
    xhci.doorbell_write(0, 0);
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());
    xhci.doorbell_write(0, HID_DEVICE_ENDPOINT_ID);
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());

    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

// Init
#[test]
fn test_xhci_keyboard_controller_init_invalid_register() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    // Case 1: write value to pci config.
    xhci.read_pci_config();
    // write vendor id.
    xhci.pci_dev.config_writew(PCI_VENDOR_ID, 0xf0ff);
    // write device id.
    xhci.pci_dev.config_writew(PCI_DEVICE_ID, 0xff0f);
    // write class code.
    // write invalid data.
    xhci.pci_dev.config_writel(PCI_CLASS_PI, 0xf0f0ffff);
    xhci.read_pci_config();

    // Case 2: write value to capability registers.
    xhci.read_capability();
    // write invalid data.
    xhci.pci_dev.io_writel(xhci.bar_addr, 0, 0xffffffff);
    xhci.read_capability();

    // Case 3: write invalid slot.
    xhci.pci_dev.io_writel(
        xhci.bar_addr,
        XHCI_PCI_OPER_OFFSET as u64 + XHCI_OPER_REG_CONFIG as u64,
        0xffff,
    );
    let config = xhci.pci_dev.io_readl(
        xhci.bar_addr,
        XHCI_PCI_OPER_OFFSET as u64 + XHCI_OPER_REG_CONFIG as u64,
    );
    assert_ne!(config, 0xffff);

    // Case 4: invalid oper
    xhci.pci_dev.io_writel(
        xhci.bar_addr,
        XHCI_PCI_OPER_OFFSET as u64 + XHCI_OPER_REG_USBSTS as u64,
        0xffff,
    );
    let status = xhci.pci_dev.io_readl(
        xhci.bar_addr,
        XHCI_PCI_OPER_OFFSET as u64 + XHCI_OPER_REG_USBSTS as u64,
    );
    assert_ne!(status, 0xffff);

    xhci.init_device_context_base_address_array_pointer();
    xhci.init_command_ring_dequeue_pointer();

    // Case 5: write invalid interrupter.
    xhci.interrupter_regs_write(0, XHCI_INTR_REG_ERSTSZ, 0);
    xhci.interrupter_regs_writeq(0, XHCI_INTR_REG_ERSTBA_LO, 0);

    // Case 6: invalid size
    xhci.init_event_ring(0, 1, 12);
    xhci.init_msix();
    xhci.run();
    xhci.no_op();
    // NOTE: no event now.
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());

    xhci.reset_controller(true);
    let port_id = 1;
    let slot_id = xhci.init_device(port_id);
    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_controller_init_miss_step() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    // Case 1: miss init command ring.
    xhci.read_pci_config();
    xhci.read_capability();
    xhci.init_max_device_slot_enabled();
    xhci.init_device_context_base_address_array_pointer();
    xhci.init_interrupter();
    xhci.run();

    let port_id = 1;
    // reset usb port
    xhci.reset_port(port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // enable slot
    xhci.enable_slot();
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());
    // Host Controller Error
    let status = xhci.oper_regs_read(XHCI_OPER_REG_USBSTS as u64);
    assert!(status & USB_STS_HCE == USB_STS_HCE);

    xhci.reset_controller(false);
    // Case 2: miss init dcbaap.
    xhci.read_pci_config();
    xhci.read_capability();
    xhci.init_max_device_slot_enabled();
    xhci.init_command_ring_dequeue_pointer();
    xhci.init_interrupter();
    xhci.run();
    // reset usb port
    xhci.reset_port(port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // enable slot
    xhci.enable_slot();
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let slot_id = evt.get_slot_id();
    // address device
    xhci.address_device(slot_id, false, port_id);
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());
    // Host Controller Error
    let status = xhci.oper_regs_read(XHCI_OPER_REG_USBSTS as u64);
    assert!(status & USB_STS_HCE == USB_STS_HCE);

    xhci.reset_controller(false);
    // Case 3: miss init interrupter.
    xhci.read_pci_config();
    xhci.read_capability();
    xhci.init_max_device_slot_enabled();
    xhci.init_command_ring_dequeue_pointer();
    xhci.run();
    // reset usb port
    xhci.reset_port(port_id);
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());
    // NOTE: no HCE now. only print error log.

    xhci.reset_controller(true);
    let slot_id = xhci.init_device(port_id);
    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_device_init_control_command() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .with_config("address_device_bsr", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    // no op
    let ptr = xhci.get_command_pointer();
    xhci.no_op();
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    assert_eq!(evt.ptr, ptr);

    let slot_id = xhci.init_device(port_id);

    let device_req = UsbDeviceRequest {
        request_type: USB_DEVICE_OUT_REQUEST,
        request: USB_REQUEST_SET_CONFIGURATION,
        value: 0,
        index: 0,
        length: 8,
    };
    // Setup Stage.
    let mut setup_trb = TestNormalTRB::generate_setup_td(&device_req);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut setup_trb);
    // Data Stage.
    let in_dir =
        device_req.request_type & USB_DIRECTION_DEVICE_TO_HOST == USB_DIRECTION_DEVICE_TO_HOST;
    let mut data_trb = TestNormalTRB::generate_data_td(0, device_req.length, in_dir);
    data_trb.set_idt_flag(true);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut data_trb);
    // Status Stage.
    let mut status_trb = TestNormalTRB::generate_status_td(false);
    status_trb.set_ch_flag(true);
    status_trb.set_ioc_flag(false);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut status_trb);
    // Event Data TRB.
    let mut event_data_trb = TestNormalTRB::generate_event_data_trb(0x1234);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut event_data_trb);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    assert_eq!(evt.ptr, 0x1234);

    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_device_init_control_command_invalid_order() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    // reset usb port
    xhci.reset_port(port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // enable slot
    xhci.enable_slot();
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let slot_id = evt.get_slot_id();
    // address device bsr = 0
    xhci.address_device(slot_id, false, port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let slot_ctx = xhci.get_slot_context(slot_id);
    assert_eq!(slot_ctx.get_slot_state(), SLOT_ADDRESSED);
    let ep0_ctx = xhci.get_endpoint_context(slot_id, CONTROL_ENDPOINT_ID);
    assert_eq!(ep0_ctx.get_ep_state(), EP_RUNNING);
    // get descriptor
    xhci.get_usb_descriptor(slot_id);
    // configure endpoint
    xhci.configure_endpoint(slot_id, false);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    // disable slot
    xhci.disable_slot(slot_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // reset endpoint after disable slot
    xhci.reset_endpoint(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::SlotNotEnabledError as u32);

    // set tr dequeue
    let old_ptr = xhci.get_transfer_pointer(slot_id, HID_DEVICE_ENDPOINT_ID);
    xhci.set_tr_dequeue(old_ptr, slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::SlotNotEnabledError as u32);

    // reset device
    xhci.reset_device(slot_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::SlotNotEnabledError as u32);
    // stop endpoint after reset device
    xhci.stop_endpoint(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::SlotNotEnabledError as u32);

    // enable slot
    xhci.enable_slot();
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // address device
    let slot_id = evt.get_slot_id();
    xhci.address_device(slot_id, false, port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // configure endpoint
    xhci.configure_endpoint(slot_id, false);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    // stop endpoint. invalid slot id in trb.
    let mut trb = TestNormalTRB::default();
    trb.set_slot_id(slot_id);
    trb.set_ep_id(2);
    trb.set_trb_type(TRBType::CrStopEndpoint as u32);
    xhci.queue_command(&mut trb);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::EpNotEnabledError as u32);
    // set tr dequeue.
    let mut trb = TestNormalTRB::default();
    trb.set_pointer(0xff00 | 1);
    trb.set_slot_id(slot_id);
    trb.set_ep_id(2);
    trb.set_trb_type(TRBType::CrSetTrDequeue as u32);
    xhci.queue_command(&mut trb);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::EpNotEnabledError as u32);
    // reset endpoint
    let mut trb = TestNormalTRB::default();
    trb.set_slot_id(slot_id);
    trb.set_ep_id(2);
    trb.set_trb_type(TRBType::CrResetEndpoint as u32);
    xhci.queue_command(&mut trb);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::EpNotEnabledError as u32);

    // stop endpoint.
    xhci.stop_endpoint(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // configure agian.
    xhci.configure_endpoint(slot_id, false);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_over_command_ring() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let org_ptr = xhci.get_command_pointer();
    // Fake ring length.
    let ring_len = 32;
    for _ in 0..ring_len - 1 {
        let ptr = xhci.get_command_pointer();
        xhci.no_op();
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        assert_eq!(evt.ptr, ptr);
    }
    xhci.queue_link_trb(0, 0, org_ptr, true);
    let ptr = xhci.get_command_pointer();
    assert_eq!(org_ptr, ptr);
    for _ in 0..ring_len - 1 {
        let ptr = xhci.get_command_pointer();
        xhci.no_op();
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        assert_eq!(evt.ptr, ptr);
    }
    let ptr = xhci.get_command_pointer();
    // link trb overlimit by setting next trb to itself.
    xhci.queue_link_trb(0, 0, ptr, false);
    xhci.doorbell_write(0, 0);
    // Host Controller Error
    let status = xhci.oper_regs_read(XHCI_OPER_REG_USBSTS as u64);
    assert!(status & USB_STS_HCE == USB_STS_HCE);

    xhci.reset_controller(true);
    let port_id = 1;
    let slot_id = xhci.init_device(port_id);
    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_device_init_invalid_value() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    // reset usb port
    xhci.reset_port(port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // enable slot
    xhci.enable_slot();
    xhci.doorbell_write(0, 0);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let slot_id = evt.get_slot_id();
    // Case 1: invalid value when address device
    // Invalid port id.
    xhci.address_device(slot_id, true, 0xff);
    xhci.doorbell_write(0, 0);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::TrbError as u32);
    xhci.address_device(slot_id, true, port_id + 1);
    xhci.doorbell_write(0, 0);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::TrbError as u32);
    // Invalid add flag.
    let input_ctx_addr = xhci.address_device(slot_id, true, port_id);
    let mut input_ctx = XhciInputCtrlCtx::default();
    input_ctx.add_flags |= 0xf0;
    xhci.mem_write_u32(input_ctx_addr, input_ctx.as_dwords());
    xhci.doorbell_write(0, 0);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::ParameterError as u32);
    // Invalid slot state.
    let input_ctx_addr = xhci.address_device(slot_id, false, port_id);
    let mut slot_ctx = XhciSlotCtx::default();
    slot_ctx.set_slot_state(SLOT_ADDRESSED);
    slot_ctx.set_context_entry(1);
    slot_ctx.set_port_number(port_id);
    xhci.mem_write_u32(input_ctx_addr + 0x20, slot_ctx.as_dwords());
    xhci.doorbell_write(0, 0);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::ContextStateError as u32);
    // correct
    xhci.address_device(slot_id, false, port_id);
    xhci.doorbell_write(0, 0);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // Case 2: invalid value when evaluate context
    // Invalid input context.
    let input_ctx_addr = xhci.evaluate_context(slot_id, 0x1234, 3, 128);
    let mut input_ctx = XhciInputCtrlCtx::default();
    input_ctx.drop_flags = 0xf;
    xhci.mem_write_u32(input_ctx_addr, input_ctx.as_dwords());
    xhci.doorbell_write(0, 0);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::TrbError as u32);
    // Invalid slot id.
    xhci.evaluate_context(slot_id + 1, 0x1234, 3, 128);
    xhci.doorbell_write(0, 0);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::SlotNotEnabledError as u32);
    // correct
    xhci.evaluate_context(slot_id, 0x1234, 0, 64);
    xhci.doorbell_write(0, 0);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // Case 3: invalid value when configure endpoint
    // DC when endpoint is not configured.
    xhci.configure_endpoint(slot_id, true);
    xhci.doorbell_write(0, 0);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::ContextStateError as u32);
    // Invalid input context.
    let input_ctx_addr = xhci.configure_endpoint(slot_id, false);
    let mut input_ctx = XhciInputCtrlCtx::default();
    input_ctx.add_flags = 0x2;
    xhci.mem_write_u32(input_ctx_addr, input_ctx.as_dwords());
    xhci.doorbell_write(0, 0);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::TrbError as u32);
    // correct
    xhci.configure_endpoint(slot_id, false);
    xhci.doorbell_write(0, 0);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    // Case 4: invalid command
    let mut trb = TestNormalTRB::default();
    trb.set_slot_id(0);
    xhci.queue_command(&mut trb);
    xhci.doorbell_write(0, 0);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::TrbError as u32);

    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_device_init_invalid_request() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    // reset usb port
    xhci.reset_port(port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // enable slot
    xhci.enable_slot();
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let slot_id = evt.get_slot_id();
    // address device
    xhci.address_device(slot_id, false, port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // get descriptor
    let device_req = UsbDeviceRequest {
        request_type: USB_DEVICE_IN_REQUEST,
        request: USB_REQUEST_GET_DESCRIPTOR,
        value: (USB_DT_CONFIGURATION as u16) << 8 | 6,
        index: 10,
        length: 10,
    };
    xhci.queue_device_reqeust(slot_id, &device_req);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    // Stall Error.
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::StallError as u32);
    // reset endpoint
    xhci.reset_endpoint(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // evaluate context
    xhci.evaluate_context(slot_id, 0x1234, 0, 64);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // SET_CONFIGURATION invalid value.
    // Inject invalid usb device request to let endpoint halted.
    let device_req = UsbDeviceRequest {
        request_type: USB_DEVICE_OUT_REQUEST,
        request: USB_REQUEST_SET_CONFIGURATION,
        value: 0xff,
        index: 2,
        length: 64,
    };
    xhci.queue_device_reqeust(slot_id, &device_req);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    // Stall Error.
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::StallError as u32);
    // reset endpoint
    xhci.reset_endpoint(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // configure endpoint
    xhci.configure_endpoint(slot_id, false);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // set report
    xhci.set_report(slot_id, 3);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_device_init_invalid_control() {
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    // reset usb port
    xhci.reset_port(port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // enable slot
    xhci.enable_slot();
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let slot_id = evt.get_slot_id();
    // address device
    xhci.address_device(slot_id, false, port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // get descriptor, invalid control value
    let device_req = UsbDeviceRequest {
        request_type: USB_DEVICE_IN_REQUEST,
        request: USB_REQUEST_GET_DESCRIPTOR,
        value: (USB_DT_CONFIGURATION as u16) << 8,
        index: 0,
        length: 64,
    };
    // Case 1: no SetUp Stage.
    // Data Stage.
    let ptr = guest_allocator.borrow_mut().alloc(device_req.length as u64);
    let in_dir =
        device_req.request_type & USB_DIRECTION_DEVICE_TO_HOST == USB_DIRECTION_DEVICE_TO_HOST;
    let mut data_trb = TestNormalTRB::generate_data_td(ptr, device_req.length, in_dir);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut data_trb);
    // Status Stage.
    let mut status_trb = TestNormalTRB::generate_status_td(false);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut status_trb);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::TrbError as u32);

    // Case 2: no Status Stage.
    // Setup Stage.
    let org_ptr = xhci.get_transfer_pointer(slot_id, CONTROL_ENDPOINT_ID);
    let mut setup_trb = TestNormalTRB::generate_setup_td(&device_req);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut setup_trb);
    // Data Stage.
    let ptr = guest_allocator.borrow_mut().alloc(device_req.length as u64);
    let in_dir =
        device_req.request_type & USB_DIRECTION_DEVICE_TO_HOST == USB_DIRECTION_DEVICE_TO_HOST;
    let mut data_trb = TestNormalTRB::generate_data_td(ptr, device_req.length, in_dir);
    data_trb.set_ch_flag(false);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut data_trb);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    // NOTE: no event for current implement now.
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());
    // clean up. rewrite tr dequeue.
    xhci.set_transfer_pointer(org_ptr, slot_id, CONTROL_ENDPOINT_ID);

    // Case 3: no IDT = 1. in SetUp TD
    // Setup Stage.
    let mut setup_trb = TestNormalTRB::generate_setup_td(&device_req);
    setup_trb.set_idt_flag(false);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut setup_trb);
    // Data Stage.
    let ptr = guest_allocator.borrow_mut().alloc(device_req.length as u64);
    let in_dir =
        device_req.request_type & USB_DIRECTION_DEVICE_TO_HOST == USB_DIRECTION_DEVICE_TO_HOST;
    let mut data_trb = TestNormalTRB::generate_data_td(ptr, device_req.length, in_dir);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut data_trb);
    // Status Stage.
    let mut status_trb = TestNormalTRB::generate_status_td(false);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut status_trb);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::TrbError as u32);

    // Case 4: invalid length in Setup TD
    // Setup Stage.
    let mut setup_trb = TestNormalTRB::generate_setup_td(&device_req);
    setup_trb.set_trb_transfer_length(11);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut setup_trb);
    // Data Stage.
    let ptr = guest_allocator.borrow_mut().alloc(device_req.length as u64);
    let in_dir =
        device_req.request_type & USB_DIRECTION_DEVICE_TO_HOST == USB_DIRECTION_DEVICE_TO_HOST;
    let mut data_trb = TestNormalTRB::generate_data_td(ptr, device_req.length, in_dir);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut data_trb);
    // Status Stage.
    let mut status_trb = TestNormalTRB::generate_status_td(false);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut status_trb);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::TrbError as u32);

    // Case 5: Data direction mismatch EP
    // Setup Stage.
    let mut setup_trb = TestNormalTRB::generate_setup_td(&device_req);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut setup_trb);
    // Data Stage.
    let ptr = guest_allocator.borrow_mut().alloc(device_req.length as u64);
    let in_dir =
        device_req.request_type & USB_DIRECTION_DEVICE_TO_HOST == USB_DIRECTION_DEVICE_TO_HOST;
    let mut data_trb = TestNormalTRB::generate_data_td(ptr, device_req.length, in_dir);
    data_trb.set_dir_flag(false);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut data_trb);
    // Status Stage.
    let mut status_trb = TestNormalTRB::generate_status_td(false);
    xhci.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut status_trb);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::TrbError as u32);

    // evaluate context
    xhci.evaluate_context(slot_id, 0x1234, 0, 64);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // configure endpoint
    xhci.configure_endpoint(slot_id, false);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_device_init_invalid_order() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    // reset usb port
    xhci.reset_port(port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // enable slot
    xhci.enable_slot();
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let slot_id = evt.get_slot_id();
    // Case 1: configure endpoint before address device
    xhci.configure_endpoint(slot_id, false);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::ContextStateError as u32);
    // address device
    xhci.address_device(slot_id, false, port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // configure endpoint
    xhci.configure_endpoint(slot_id, false);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // Case 2: address device after configure endpoint
    xhci.address_device(slot_id, false, port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // recover, configure again
    xhci.configure_endpoint(slot_id, false);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // Case 3: set tr dequeue when not stop.
    let old_ptr = xhci.get_transfer_pointer(slot_id, HID_DEVICE_ENDPOINT_ID);
    xhci.set_tr_dequeue(old_ptr, slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::ContextStateError as u32);

    xhci.test_keyboard_event(slot_id, test_state.clone());

    // disable slot
    xhci.disable_slot(slot_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // Case 4: stop endpoint after disable slot
    xhci.stop_endpoint(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::SlotNotEnabledError as u32);
    // Case 5: reset endpoint after disable slot
    xhci.reset_endpoint(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::SlotNotEnabledError as u32);
    // Case 6: disable slot again
    xhci.disable_slot(slot_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::SlotNotEnabledError as u32);
    // reenable
    // enable slot
    xhci.enable_slot();
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // address device
    let slot_id = evt.get_slot_id();
    xhci.address_device(slot_id, false, port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // configure endpoint
    xhci.configure_endpoint(slot_id, false);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_device_init_reset_device() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    // reset usb port
    xhci.reset_port(port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // enable slot
    xhci.enable_slot();
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let slot_id = evt.get_slot_id();
    //  Case 1: reset afer enable slot.
    xhci.reset_device(slot_id);
    let status = xhci.oper_regs_read(XHCI_OPER_REG_USBSTS as u64);
    assert!(status & USB_STS_HCE == USB_STS_HCE);

    xhci.reset_controller(true);
    let slot_id = xhci.init_device(port_id);
    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_device_init_multi_enable_slot() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);
    xhci.test_keyboard_event(slot_id, test_state.clone());

    let enable_limit = 64;
    for _ in 0..enable_limit - 1 {
        // enable slot
        xhci.enable_slot();
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        let slot_id = evt.get_slot_id();
        assert_ne!(slot_id, 0);
    }
    xhci.enable_slot();
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::NoSlotsError as u32);

    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_device_init_reconfigure_endpoint() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    let cnt = 3;
    for _ in 0..cnt {
        xhci.configure_endpoint(slot_id, true);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        xhci.configure_endpoint(slot_id, false);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
    }

    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_device_init_device_request_repeat() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    // reset usb port
    xhci.reset_port(port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // enable slot
    xhci.enable_slot();
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let slot_id = evt.get_slot_id();
    // address device
    xhci.address_device(slot_id, false, port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let cnt = 3;
    for i in 0..cnt {
        // get descriptor
        xhci.get_device_descriptor(slot_id);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
        xhci.get_config_descriptor(slot_id);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
        xhci.get_string_descriptor(slot_id, i);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
    }
    // configure endpoint
    xhci.configure_endpoint(slot_id, false);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    let cnt = 3;
    for _ in 0..cnt {
        // get status
        xhci.get_status(slot_id);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
        let buf = xhci.get_transfer_data_indirect(evt.ptr - TRB_SIZE as u64, 2);
        assert_eq!(buf, [0, 0]);
        // set configuration
        xhci.set_configuration(slot_id, 1);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        // get configuration
        xhci.get_configuration(slot_id);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
        let buf = xhci.get_transfer_data_indirect(evt.ptr - TRB_SIZE as u64, 2);
        assert_eq!(buf[0], 1);
        // Set remote wakeup.
        xhci.set_feature(slot_id, USB_DEVICE_REMOTE_WAKEUP as u16);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        // get status
        xhci.get_status(slot_id);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
        let buf = xhci.get_transfer_data_indirect(evt.ptr - TRB_SIZE as u64, 2);
        assert_eq!(buf, [2, 0]);
        // Clear remote wakeup.
        xhci.clear_feature(slot_id, USB_DEVICE_REMOTE_WAKEUP as u16);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        // Set interface.
        xhci.set_interface(slot_id, 0, 0);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        // Get interface.
        xhci.get_interface(slot_id, 0);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
        // set protocol
        xhci.set_protocol(slot_id, 1);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        //get protocol
        xhci.get_protocol(slot_id);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        // NOTE: set idle, not fully implemented yet.
        xhci.set_idle(slot_id, 0x3 << 8);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        // get idle
        xhci.get_idle(slot_id);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        // set report
        xhci.set_report(slot_id, 3);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        // get report
        xhci.get_report(slot_id);
        xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
    }

    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_device_init_device_miss_step() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    // reset usb port
    xhci.reset_port(port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // enable slot
    xhci.enable_slot();
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let slot_id = evt.get_slot_id();
    // address device
    xhci.address_device(slot_id, false, port_id);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    qmp_send_key_event(test_state.borrow_mut(), KEYCODE_SPACE, true);
    xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    // NOTE: not kick acually, just print error.
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());

    // configure endpoint
    xhci.configure_endpoint(slot_id, false);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    // clean
    xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_some());

    xhci.test_keyboard_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

// Tablet
#[test]
fn test_xhci_tablet_basic() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_tablet("tbt")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    let cnt = 10;
    for i in 0..cnt {
        qmp_send_pointer_event(test_state.borrow_mut(), i * 10, i * 20, i % 3);
        xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_POINTER_LEN);
    }
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);

    for i in 0..cnt {
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_POINTER_LEN);
        assert_eq!(
            buf,
            [
                i as u8 % 3,
                (i * 10) as u8,
                (i * 10 >> 8) as u8,
                (i * 20) as u8,
                (i * 20 >> 8) as u8,
                0
            ]
        );
    }

    for _ in 0..cnt {
        qmp_send_pointer_event(test_state.borrow_mut(), 10, 20, 0x8);
        xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_POINTER_LEN);
    }
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    for _ in 0..cnt {
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_POINTER_LEN);
        assert_eq!(buf, [0, 10, 0, 20, 0, 1]);
    }

    for _ in 0..cnt {
        qmp_send_pointer_event(test_state.borrow_mut(), 10, 20, 0x10);
        xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_POINTER_LEN);
    }
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    for _ in 0..cnt {
        let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_POINTER_LEN);
        assert_eq!(buf, [0, 10, 0, 20, 0, 255]);
    }
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_tablet_over_hid_buffer() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_tablet("tbt")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    const HID_BUFFER_SIZE: u32 = 16;
    let event_cnt = 20;
    for i in 0..event_cnt {
        qmp_send_pointer_event(test_state.borrow_mut(), i, i + 100, 0);
    }
    xhci.queue_multi_indirect_td(
        slot_id,
        HID_DEVICE_ENDPOINT_ID,
        HID_POINTER_LEN,
        event_cnt as usize,
    );
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    for i in 0..event_cnt as u32 {
        if i < HID_BUFFER_SIZE {
            let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
            assert_eq!(evt.ccode, TRBCCode::Success as u32);
            let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_POINTER_LEN);
            assert_eq!(buf, [0, i as u8, 0, (i + 100) as u8, 0, 0]);
        } else {
            // event lost.
            assert!(xhci.fetch_event(PRIMARY_INTERRUPTER_ID).is_none());
        }
    }
    xhci.test_pointer_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_tablet_over_ring_limit() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_tablet("tbt")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    let org_ptr = xhci.get_transfer_pointer(slot_id, HID_DEVICE_ENDPOINT_ID);
    // Fake ring length.
    let transfer_limit = 32;
    let test_cnt = 3;
    for i in 0..test_cnt {
        for _ in 0..transfer_limit {
            qmp_send_pointer_event(test_state.borrow_mut(), 50, 100, 0);
            xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_POINTER_LEN);
            xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
            let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
            assert_eq!(evt.ccode, TRBCCode::Success as u32);
            let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_POINTER_LEN);
            assert_eq!(buf, [0, 50, 0, 100, 0, 0]);
        }
        if i == 0 {
            // Fake link new addrress.
            xhci.queue_link_trb(
                slot_id,
                HID_DEVICE_ENDPOINT_ID,
                org_ptr + TRB_SIZE as u64 * 64,
                false,
            );
        } else if i == 1 {
            // Goto the origin address.
            xhci.queue_link_trb(slot_id, HID_DEVICE_ENDPOINT_ID, org_ptr, true);
        } else {
            xhci.queue_link_trb(slot_id, HID_DEVICE_ENDPOINT_ID, org_ptr, true);
            let ptr = xhci.get_transfer_pointer(slot_id, HID_DEVICE_ENDPOINT_ID);
            assert_eq!(org_ptr, ptr);
        }
    }
    xhci.test_pointer_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_tablet_invalid_value() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_tablet("tbt")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    qmp_send_pointer_event(test_state.borrow_mut(), 0xfffff, 0xfffff, 0xff);
    xhci.queue_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_POINTER_LEN);
    xhci.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr, HID_POINTER_LEN);
    assert_eq!(buf, [7, 255, 127, 255, 127, 0]);

    xhci.test_pointer_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_tablet_device_init_control_command() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_tablet("tbt")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .with_config("address_device_bsr", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    // no op
    let ptr = xhci.get_command_pointer();
    xhci.no_op();
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    assert_eq!(evt.ptr, ptr);

    let slot_id = xhci.init_device(port_id);

    // get report
    xhci.get_report(slot_id);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr - TRB_SIZE as u64, HID_POINTER_LEN);
    assert_eq!(buf, [0, 0, 0, 0, 0, 0]);

    xhci.test_pointer_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}

#[test]
fn test_xhci_keyboard_tablet_basic() {
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_keyboard("kbd")
        .with_usb_tablet("tbt")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    xhci.device_config.insert(String::from("keyboard"), true);
    xhci.device_config.insert(String::from("tablet"), false);
    let slot_id = xhci.init_device(port_id);
    xhci.test_keyboard_event(slot_id, test_state.clone());

    let port_id = 2;
    xhci.device_config.insert(String::from("keyboard"), false);
    xhci.device_config.insert(String::from("tablet"), true);
    let slot_id = xhci.init_device(port_id);
    xhci.test_pointer_event(slot_id, test_state.clone());
    test_state.borrow_mut().stop();
}
