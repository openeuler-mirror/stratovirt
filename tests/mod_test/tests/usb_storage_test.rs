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

use std::cell::RefMut;

use byteorder::{ByteOrder, LittleEndian};

use devices::usb::{
    config::{USB_INTERFACE_CLASS_IN_REQUEST, USB_INTERFACE_CLASS_OUT_REQUEST},
    storage::{
        UsbMsdCswStatus, CBW_FLAG_IN, CBW_FLAG_OUT, CBW_SIGNATURE, CBW_SIZE, CSW_SIGNATURE,
        CSW_SIZE, GET_MAX_LUN, MASS_STORAGE_RESET,
    },
    xhci::xhci_trb::{TRBCCode, TRB_SIZE},
    UsbDeviceRequest,
};
use mod_test::libdriver::usb::{
    TestIovec, TestUsbBuilder, TestXhciPciDevice, CONTROL_ENDPOINT_ID, PRIMARY_INTERRUPTER_ID,
    STORAGE_DEVICE_IN_ENDPOINT_ID, STORAGE_DEVICE_OUT_ENDPOINT_ID,
};
use mod_test::utils::{cleanup_img, create_img, TEST_IMAGE_SIZE};
use mod_test::{libdriver::malloc::GuestAllocator, utils::ImageType};

const READ_10: u8 = 0x28;
const WRITE_10: u8 = 0x2a;
const RESERVE: u8 = 0x16;

const CBW_ILLEGAL_SIZE: u8 = CBW_SIZE - 1;
const CSW_ILLEGAL_SIZE: u8 = CSW_SIZE - 1;

const DISK_SECTOR_SIZE: usize = 512;

struct Cbw {
    sig: u32,
    tag: u32,
    data_len: u32,
    flags: u8,
    lun: u8,
    cmd_len: u8,
    cmd: [u8; 16],
}

impl Cbw {
    fn new() -> Self {
        Cbw {
            sig: CBW_SIGNATURE,
            tag: 123456,
            data_len: 0,
            flags: 0,
            lun: 0,
            cmd_len: 0,
            cmd: [0; 16],
        }
    }
}

fn cbw_phase(
    cbw: Cbw,
    mut xhci: RefMut<TestXhciPciDevice>,
    mut guest_allocator: RefMut<GuestAllocator>,
    slot_id: u32,
    status: TRBCCode,
    len: u8,
) {
    let mut cbw_buf: [u8; CBW_SIZE as usize] = [0; CBW_SIZE as usize];
    LittleEndian::write_u32(&mut cbw_buf[0..4], cbw.sig);
    LittleEndian::write_u32(&mut cbw_buf[4..8], cbw.tag);
    LittleEndian::write_u32(&mut cbw_buf[8..12], cbw.data_len);
    cbw_buf[12] = cbw.flags;
    cbw_buf[13] = cbw.lun;
    cbw_buf[14] = cbw.cmd_len;
    for i in 0..16 {
        cbw_buf[15 + i] = cbw.cmd[i];
    }

    let mut iovecs = Vec::new();
    let ptr = guest_allocator.alloc(CBW_SIZE as u64);
    xhci.mem_write(ptr, &cbw_buf);

    let iovec = TestIovec::new(ptr, len as usize, false);
    iovecs.push(iovec);
    xhci.queue_td_by_iovec(slot_id, STORAGE_DEVICE_OUT_ENDPOINT_ID, &mut iovecs, false);
    xhci.doorbell_write(slot_id, STORAGE_DEVICE_OUT_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, status as u32);
}

fn data_phase(
    mut xhci: RefMut<TestXhciPciDevice>,
    mut guest_allocator: RefMut<GuestAllocator>,
    slot_id: u32,
    buf: &[u8],
    to_host: bool,
    if_success: bool,
) {
    let mut iovecs = Vec::new();
    let ptr = guest_allocator.alloc(buf.len() as u64);
    let iovec = TestIovec::new(ptr, buf.len() as usize, false);

    if !to_host {
        xhci.mem_write(ptr, &buf);
    }

    iovecs.push(iovec);

    if to_host {
        xhci.queue_td_by_iovec(slot_id, STORAGE_DEVICE_IN_ENDPOINT_ID, &mut iovecs, false);
        xhci.doorbell_write(slot_id, STORAGE_DEVICE_IN_ENDPOINT_ID);
    } else {
        xhci.queue_td_by_iovec(slot_id, STORAGE_DEVICE_OUT_ENDPOINT_ID, &mut iovecs, false);
        xhci.doorbell_write(slot_id, STORAGE_DEVICE_OUT_ENDPOINT_ID);
    }

    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    if if_success {
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
    } else {
        assert_ne!(evt.ccode, TRBCCode::Success as u32);
    }

    if to_host {
        let data_buf = xhci.mem_read(ptr, buf.len());
        assert_eq!(buf, data_buf);
    }
}

fn csw_phase(
    mut xhci: RefMut<TestXhciPciDevice>,
    mut guest_allocator: RefMut<GuestAllocator>,
    slot_id: u32,
    status: TRBCCode,
    len: u8,
    sig_check: bool,
) -> u64 {
    let mut iovecs = Vec::new();
    let ptr = guest_allocator.alloc(len as u64);

    let iovec = TestIovec::new(ptr, len as usize, false);
    iovecs.push(iovec);
    xhci.queue_td_by_iovec(slot_id, STORAGE_DEVICE_IN_ENDPOINT_ID, &mut iovecs, false);
    xhci.doorbell_write(slot_id, STORAGE_DEVICE_IN_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, status as u32);

    if sig_check {
        let buf = xhci.mem_read(ptr, len as usize);
        assert_eq!(CSW_SIGNATURE, LittleEndian::read_u32(&buf[0..4]));
    }

    ptr
}

/// USB storage device basic IO function test.
/// TestStep:
///   0. Init process.
///   1. CBW: write.
///   2. DataOut: data write from host to device.
///   3. CSW.
///   4. CBW: read.
///   5. DataIn: data read from device to host.
///   6. Csw.
///   7. Test ends. Destroy device.
/// Expect:
///   0/1/2/3/4/5/6/7: success.
#[test]
fn usb_storage_basic() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "disk")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();

    let port_id = 1;
    let slot_id = xhci.borrow_mut().init_device(port_id);

    // Test 1: CBW phase.
    let mut cbw = Cbw::new();
    cbw.data_len = 4;
    cbw.flags = CBW_FLAG_OUT;
    cbw.cmd_len = 10;
    cbw.cmd[0] = WRITE_10;
    cbw.cmd[8] = 1;
    cbw_phase(
        cbw,
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::Success,
        CBW_SIZE,
    );

    // Test 2: DataOut phase.
    let mut buf = "TEST".as_bytes().to_vec();
    buf.resize(DISK_SECTOR_SIZE, 0);
    data_phase(
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        &buf,
        false,
        true,
    );

    // Test 3: CSW phase.
    csw_phase(
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::Success,
        CSW_SIZE,
        true,
    );

    // Test 4: CBW phase.
    let mut cbw = Cbw::new();
    cbw.data_len = 4;
    cbw.flags = CBW_FLAG_IN;
    cbw.cmd_len = 10;
    cbw.cmd[0] = READ_10;
    cbw.cmd[8] = 1;
    cbw_phase(
        cbw,
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::Success,
        CBW_SIZE,
    );

    // Test 5: Datain phase.
    data_phase(
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        &buf,
        true,
        true,
    );

    // Test 6: CSW phase.
    csw_phase(
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::Success,
        CSW_SIZE,
        true,
    );

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}

/// USB storage device functional 'Reset' test.
/// TestStep:
///   0. Init process.
///   1. Reset.
///   2. Test ends. Destroy device.
/// Expect:
///   0/1/2: success.
#[test]
fn usb_storage_functional_reset() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "cdrom")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();

    let mut xhci = xhci.borrow_mut();
    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    let device_req = UsbDeviceRequest {
        request_type: USB_INTERFACE_CLASS_OUT_REQUEST,
        request: MASS_STORAGE_RESET,
        value: 0,
        index: 0,
        length: 0,
    };

    xhci.queue_device_request(slot_id, &device_req);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}

/// USB storage device functional 'Get Max Lun' test.
/// TestStep:
///   0. Init process.
///   1. Get Max Lun.
///   2. Send CBW whose lun is greater than 'MAX LUN'.
///   3. Test ends. Destroy device.
/// Expect:
///   0/1/3: success.
///   2: Stallerror.
#[test]
fn usb_storage_functional_get_max_lun() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "cdrom")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();

    let mut xhci = xhci.borrow_mut();
    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    let device_req = UsbDeviceRequest {
        request_type: USB_INTERFACE_CLASS_IN_REQUEST,
        request: GET_MAX_LUN,
        value: 0,
        index: 0,
        length: 1,
    };

    xhci.queue_device_request(slot_id, &device_req);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::Success as u32);
    let buf = xhci.get_transfer_data_indirect(evt.ptr - TRB_SIZE as u64, 1);

    assert_eq!(buf, [0]);

    // Test: lun > 0 CBW phase.
    let mut cbw = Cbw::new();
    cbw.data_len = 512;
    cbw.lun = 8;
    cbw.flags = CBW_FLAG_IN;
    cbw.cmd_len = 10;
    cbw.cmd[0] = READ_10;
    cbw.cmd[8] = 1;
    cbw_phase(
        cbw,
        xhci,
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::StallError,
        CBW_SIZE,
    );

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}

/// USB storage device illegal request test.
/// TestStep:
///   0. Init process.
///   1. Illegal request.
///   2. Test ends. Destroy device.
/// Expect:
///   0/2: success.
///   1: StallError.
#[test]
fn usb_storage_illegal_request() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, _) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "cdrom")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();

    let mut xhci = xhci.borrow_mut();
    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    let device_req = UsbDeviceRequest {
        request_type: 2,
        request: 210,
        value: 0,
        index: 0,
        length: 0,
    };

    xhci.queue_device_request(slot_id, &device_req);
    xhci.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::StallError as u32);

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}

/// USB storage device CBW signature test.
/// TestStep:
///   0. Init process.
///   1. CBW: the signature value is abnormal.
///   2. Test ends. Destroy device.
/// Expect:
///   0/2: success.
///   1: CBW StallError.
#[test]
fn usb_storage_cbw_signature() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "cdrom")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();

    let port_id = 1;
    let slot_id = xhci.borrow_mut().init_device(port_id);

    // Test 1: CBW phase.
    let mut cbw = Cbw::new();
    cbw.sig = 0x123456;

    cbw_phase(
        cbw,
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::StallError,
        CBW_SIZE,
    );

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}

/// USB storage device CBW illegal packet size test.
/// TestStep:
///   0. Init process.
///   1. CBW: the packet size is abnormal.
///   2. Test ends. Destroy device.
/// Expect:
///   0/2: success.
///   1: CBW StallError.
#[test]
fn usb_storage_cbw_illegal_size() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "cdrom")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();

    let port_id = 1;
    let slot_id = xhci.borrow_mut().init_device(port_id);

    // Test 1: CBW phase.
    let cbw = Cbw::new();
    cbw_phase(
        cbw,
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::StallError,
        CBW_ILLEGAL_SIZE,
    );

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}

/// USB storage device CSW illegal packet size test.
/// TestStep:
///   0. Init process.
///   1. CBW.
///   2. CSW: the packet size is abnormal.
///   3. Test ends. Destroy device.
/// Expect:
///   0/1/3: success.
///   2: CSW StallError.
#[test]
fn usb_storage_csw_illegal_size() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "cdrom")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();

    let port_id = 1;
    let slot_id = xhci.borrow_mut().init_device(port_id);

    // Test 1: CBW phase.
    let cbw = Cbw::new();
    cbw_phase(
        cbw,
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::Success,
        CBW_SIZE,
    );

    // Test 2: CSW phase.
    csw_phase(
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::StallError,
        CSW_ILLEGAL_SIZE,
        false,
    );

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}

/// USB storage device abnormal phase (CBW -> CSW) test, skip Data phase.
/// TestStep:
///   0. Init process.
///   1. CBW.
///   2. CSW.
///   3. Test ends. Destroy device.
/// Expect:
///   0/1/3: success.
///   2: CSW StallError.
#[test]
fn usb_storage_abnormal_phase_01() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "cdrom")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();

    let port_id = 1;
    let slot_id = xhci.borrow_mut().init_device(port_id);

    // Test 1: CBW phase.
    let mut cbw = Cbw::new();
    cbw.data_len = 512;
    cbw.flags = CBW_FLAG_IN;
    cbw.cmd_len = 10;
    cbw.cmd[0] = READ_10;
    cbw.cmd[8] = 1;
    cbw_phase(
        cbw,
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::Success,
        CBW_SIZE,
    );

    // Test 2: CSW phase.
    let ptr = csw_phase(
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::StallError,
        CSW_SIZE,
        false,
    );

    let buf = xhci.borrow_mut().mem_read(ptr, CSW_SIZE as usize);
    assert_ne!(CSW_SIGNATURE, LittleEndian::read_u32(&buf[0..4]));

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}

/// USB storage device abnormal phase (CBW -> CSW -> CSW) test.
/// TestStep:
///   0. Init process.
///   1. CBW.
///   2. CSW.
///   3. CSW.
///   4. Test ends. Destroy device.
/// Expect:
///   0/1/2/4: success.
///   3: CSW StallError.
#[test]
fn usb_storage_abnormal_phase_02() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "cdrom")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();

    let port_id = 1;
    let slot_id = xhci.borrow_mut().init_device(port_id);

    // Test 1: CBW phase.
    let cbw = Cbw::new();
    cbw_phase(
        cbw,
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::Success,
        CBW_SIZE,
    );

    // Test 2: CSW phase.
    csw_phase(
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::Success,
        CSW_SIZE,
        true,
    );

    // Test 3: CSW phase.
    csw_phase(
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::StallError,
        CSW_SIZE,
        false,
    );

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}

/// USB storage device abnormal phase (CBW -> CBW) test.
/// TestStep:
///   0. Init process.
///   1. CBW.
///   2. CBW.
///   3. Test ends. Destroy device.
/// Expect:
///   0/1/3: success.
///   2: CBW StallError.
#[test]
fn usb_storage_abnormal_phase_03() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "cdrom")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();

    let port_id = 1;
    let slot_id = xhci.borrow_mut().init_device(port_id);

    // Test 1: CBW phase.
    let mut cbw = Cbw::new();
    cbw.data_len = 512;
    cbw.flags = CBW_FLAG_IN;
    cbw.cmd_len = 10;
    cbw.cmd[0] = READ_10;
    cbw.cmd[8] = 1;
    cbw_phase(
        cbw,
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::Success,
        CBW_SIZE,
    );

    // Test 2: CBW phase.
    let mut cbw = Cbw::new();
    cbw.data_len = 512;
    cbw.flags = CBW_FLAG_IN;
    cbw.cmd_len = 10;
    cbw.cmd[0] = READ_10;
    cbw.cmd[8] = 1;
    cbw_phase(
        cbw,
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::StallError,
        CBW_SIZE,
    );

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}

/// USB storage device illegal scsi cdb test.
/// TestStep:
///   0. Init process.
///   1. CBW.
///   2. CSW.
///   3. Test ends. Destroy device.
/// Expect:
///   0/1/3: success.
///   2: CSW StallError.
#[test]
fn usb_storage_illegal_scsi_cdb() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "cdrom")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();

    let port_id = 1;
    let slot_id = xhci.borrow_mut().init_device(port_id);

    // Test 1: CBW phase.
    let mut cbw = Cbw::new();
    cbw.data_len = 512;
    cbw.flags = CBW_FLAG_IN;
    cbw.cmd_len = 10;
    cbw.cmd[0] = 0xff;
    cbw.cmd[8] = 1;
    cbw_phase(
        cbw,
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::Success,
        CBW_SIZE,
    );

    // Test 2: CSW phase.
    csw_phase(
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::StallError,
        CSW_SIZE,
        false,
    );

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}

/// USB storage device does not provide enough data buffer test.
/// TestStep:
///   0. Init process.
///   1. CBW: read.
///   2. DataIn: data read from device to host.
///   3. Test ends. Destroy device.
/// Expect:
///   0/1/3: success.
///   2: StallError.
#[test]
fn insufficient_data_buffer_test() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "cdrom")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();

    let port_id = 1;
    let slot_id = xhci.borrow_mut().init_device(port_id);

    // Test 1: CBW phase.
    let mut cbw = Cbw::new();
    cbw.data_len = 512; // 512 Bytes data buffer.
    cbw.flags = CBW_FLAG_IN;
    cbw.cmd_len = 10;
    cbw.cmd[0] = READ_10;
    cbw.cmd[8] = 1; // Need 1 logical sector(CD-ROM: 2048Bytes).
    cbw_phase(
        cbw,
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::Success,
        CBW_SIZE,
    );

    // Test 2: Datain phase.
    let buf = vec![0; 512]; // Provides 512 Bytes datain buffer.
    data_phase(
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        &buf,
        true,
        false,
    );

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}

/// USB storage device not supported scsi cdb test.
/// TestStep:
///   0. Init process.
///   1. CBW.
///   2. CSW.
///   3. Test ends. Destroy device.
/// Expect:
///   0/1/2/3: success.
///   2: CSW status = UsbMsdCswStatus::Failed.
#[test]
fn usb_storage_not_supported_scsi_cdb() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "cdrom")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();

    let port_id = 1;
    let slot_id = xhci.borrow_mut().init_device(port_id);

    // Test 1: CBW phase.
    let mut cbw = Cbw::new();
    cbw.flags = CBW_FLAG_IN;
    cbw.cmd_len = 10;
    cbw.cmd[0] = RESERVE;
    cbw_phase(
        cbw,
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::Success,
        CBW_SIZE,
    );

    // Test 2: CSW phase.
    let csw_addr = csw_phase(
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::Success,
        CSW_SIZE,
        true,
    );

    let buf = xhci.borrow_mut().mem_read(csw_addr, CSW_SIZE as usize);
    assert_eq!(UsbMsdCswStatus::Failed as u8, buf[12]);

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}

/// USB storage device CBW phase to invalid endpoint test.
/// TestStep:
///   0. Init process.
///   1. CBW: invalid endpoint(not Out endpoint).
///   2. Test ends. Destroy device.
/// Expect:
///   0/2: success.
///   1: CBW StallError.
#[test]
fn usb_storage_cbw_invalid_endpoint() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "cdrom")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();
    let mut xhci = xhci.borrow_mut();

    let port_id = 1;
    let slot_id = xhci.init_device(port_id);

    // Test 1: CBW phase.
    let cbw = Cbw::new();

    let mut cbw_buf: [u8; CBW_SIZE as usize] = [0; CBW_SIZE as usize];
    LittleEndian::write_u32(&mut cbw_buf[0..4], cbw.sig);

    let mut iovecs = Vec::new();
    let ptr = guest_allocator.borrow_mut().alloc(CBW_SIZE as u64);
    xhci.mem_write(ptr, &cbw_buf);

    let iovec = TestIovec::new(ptr, CBW_SIZE as usize, false);
    iovecs.push(iovec);
    xhci.queue_td_by_iovec(slot_id, STORAGE_DEVICE_IN_ENDPOINT_ID, &mut iovecs, false);
    xhci.doorbell_write(slot_id, STORAGE_DEVICE_IN_ENDPOINT_ID);
    let evt = xhci.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
    assert_eq!(evt.ccode, TRBCCode::StallError as u32);

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}

/// USB storage device CSW phase to invalid endpoint test.
/// TestStep:
///   0. Init process.
///   1. CBW.
///   2. CSW: invalid endpoint(not In endpoint).
///   3. Test ends. Destroy device.
/// Expect:
///   0/1/3: success.
///   2: CSW StallError.
#[test]
fn usb_storage_csw_invalid_endpoint() {
    let image_path = create_img(TEST_IMAGE_SIZE, 0, &ImageType::Raw);
    let (xhci, test_state, guest_allocator) = TestUsbBuilder::new()
        .with_xhci("xhci")
        .with_usb_storage(&image_path, "cdrom")
        .with_config("auto_run", true)
        .with_config("command_auto_doorbell", true)
        .build();

    let port_id = 1;
    let slot_id = xhci.borrow_mut().init_device(port_id);

    // Test 1: CBW phase.
    let cbw = Cbw::new();
    cbw_phase(
        cbw,
        xhci.borrow_mut(),
        guest_allocator.borrow_mut(),
        slot_id,
        TRBCCode::Success,
        CBW_SIZE,
    );

    // Test 2: CSW phase.
    let mut iovecs = Vec::new();
    let ptr = guest_allocator.borrow_mut().alloc(CSW_SIZE as u64);

    let iovec = TestIovec::new(ptr, CSW_SIZE as usize, false);
    iovecs.push(iovec);
    xhci.borrow_mut().queue_td_by_iovec(
        slot_id,
        STORAGE_DEVICE_OUT_ENDPOINT_ID,
        &mut iovecs,
        false,
    );
    xhci.borrow_mut()
        .doorbell_write(slot_id, STORAGE_DEVICE_OUT_ENDPOINT_ID);
    let evt = xhci
        .borrow_mut()
        .fetch_event(PRIMARY_INTERRUPTER_ID)
        .unwrap();
    assert_eq!(evt.ccode, TRBCCode::StallError as u32);

    test_state.borrow_mut().stop();
    cleanup_img(image_path);
}
