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

use serde_json::json;
use std::cell::RefCell;
use std::fs::{self, File};
use std::io::prelude::*;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::rc::Rc;
use std::time;

use mod_test::libdriver::malloc::GuestAllocator;
use mod_test::libdriver::virtio::{TestVirtQueue, VirtioDeviceOps};
use mod_test::libdriver::virtio_console::{create_console, ChardevType};
use mod_test::libdriver::virtio_pci_modern::TestVirtioPciDev;
use mod_test::libtest::TestState;

const TIMEOUT_US: u64 = 15 * 1000 * 1000;
const ROWS_DEFAULT: u16 = 0;
const COLS_DEFAULT: u16 = 0;
const EMERG_WR_DEFAULT: u32 = 0;
const VIRTIO_CONSOLE_F_SIZE: u64 = 0;
const VIRTIO_CONSOLE_F_MULTIPORT: u64 = 1;
const VIRTIO_CONSOLE_F_EMERG_WRITE: u64 = 2;
const BUFFER_LEN: usize = 96;

fn console_setup(
    console: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
) -> Vec<Rc<RefCell<TestVirtQueue>>> {
    let features = console.borrow().get_device_features();
    let vqs = console
        .borrow_mut()
        .init_device(test_state, alloc, features, 2);
    vqs
}

fn verify_output_data(test_state: Rc<RefCell<TestState>>, addr: u64, len: u32, test_data: &String) {
    let mut data_buf: Vec<u8> = Vec::with_capacity(len.try_into().unwrap());
    data_buf.append(
        test_state
            .borrow()
            .memread(addr, len.try_into().unwrap())
            .as_mut(),
    );
    let data = String::from_utf8(data_buf).unwrap();
    assert_eq!(data, *test_data);
}

fn verify_input_data(input: &mut dyn Read, test_data: &String) {
    let mut buffer = [0; BUFFER_LEN];
    match input.read(&mut buffer[0..test_data.len()]) {
        Ok(size) => {
            let response = String::from_utf8_lossy(&buffer[0..size]).to_string();
            assert_eq!(response, *test_data);
        }
        Err(e) => assert!(false, "Failed to read contents from socket: {}", e),
    }
}

fn get_pty_path(test_state: Rc<RefCell<TestState>>) -> String {
    let ret = test_state.borrow().qmp("{\"execute\": \"query-chardev\"}");
    if (*ret.get("return").unwrap()).as_array().unwrap().len() != 0
        && (*ret.get("return").unwrap())[0].get("filename").is_some()
    {
        let filename = (*ret.get("return").unwrap())[0]
            .get("filename")
            .unwrap()
            .to_string()
            .replace('"', "");
        let mut file_path: Vec<&str> = filename.split("pty:").collect();
        return file_path.pop().unwrap().to_string();
    } else {
        return String::from("");
    }
}

fn verify_pty_io(
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    console: Rc<RefCell<TestVirtioPciDev>>,
) {
    let vqs = console_setup(console.clone(), test_state.clone(), alloc.clone());
    let input_queue = vqs[0].clone();
    let output_queue = vqs[1].clone();

    let pty_path = get_pty_path(test_state.clone());
    assert_ne!(pty_path, String::from(""));

    let test_data = String::from("Test\n");
    let addr = alloc.borrow_mut().alloc(test_data.len() as u64);
    test_state.borrow().memwrite(addr, test_data.as_bytes());
    let free_head = output_queue.borrow_mut().add(
        test_state.clone(),
        addr,
        test_data.len().try_into().unwrap(),
        false,
    );

    console
        .borrow()
        .kick_virtqueue(test_state.clone(), output_queue.clone());
    console.borrow().poll_used_elem(
        test_state.clone(),
        output_queue.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        false,
    );

    let mut input: Option<File> = None;
    match File::open(&pty_path) {
        Ok(file) => input = Some(file),
        Err(e) => assert!(false, "{}", e),
    }

    verify_input_data(&mut input.unwrap(), &test_data);

    let addr = alloc.borrow_mut().alloc(test_data.len() as u64);
    let free_head = input_queue.borrow_mut().add(
        test_state.clone(),
        addr,
        test_data.len().try_into().unwrap(),
        true,
    );
    console
        .borrow()
        .kick_virtqueue(test_state.clone(), input_queue.clone());

    let mut output: Option<File> = None;
    match File::create(&pty_path) {
        Ok(file) => output = Some(file),
        Err(e) => assert!(false, "{}", e),
    }
    match output.unwrap().write(&test_data.as_bytes()) {
        Ok(_num) => {
            let start_time = time::Instant::now();
            let timeout_us = time::Duration::from_micros(TIMEOUT_US);
            loop {
                let mut len: Option<u32> = Some(0);
                console.borrow().poll_used_elem(
                    test_state.clone(),
                    input_queue.clone(),
                    free_head,
                    TIMEOUT_US,
                    &mut len,
                    false,
                );
                if len.unwrap() != 0 {
                    verify_output_data(test_state.clone(), addr, len.unwrap(), &test_data);
                    break;
                }
                assert!(time::Instant::now() - start_time < timeout_us);
            }
        }
        Err(e) => assert!(false, "Failed to write contents to socket: {}", e),
    }

    console.borrow_mut().destroy_device(alloc, vqs);
}

#[test]
fn console_rw_conifg() {
    let chardev = ChardevType::Pty;
    let pci_slot = 0x04;
    let pci_fn = 0x0;
    let (console, test_state, alloc) = create_console(chardev, pci_slot, pci_fn);

    assert_eq!(
        console.borrow().config_readw(0),
        ROWS_DEFAULT,
        "The rows of the console config is uncorrect or the testcase parament is out of date!"
    );

    assert_eq!(
        console.borrow().config_readw(2),
        COLS_DEFAULT,
        "The cols of the console config is uncorrect or the testcase parament is out of date!"
    );

    assert_eq!(
        console.borrow().config_readl(8),
        EMERG_WR_DEFAULT,
        "The emerg_wr of the console config is uncorrect or the testcase parament is out of date!"
    );

    console.borrow().config_writew(0, 1);
    assert_eq!(
        console.borrow().config_readw(0),
        ROWS_DEFAULT,
        "The console device doesn't support writing config. But config was written!"
    );

    verify_pty_io(test_state.clone(), alloc.clone(), console.clone());

    test_state.borrow_mut().stop();
}

#[test]
fn console_features_negotiate() {
    let chardev = ChardevType::Pty;
    let pci_slot = 0x04;
    let pci_fn = 0x0;
    let (console, test_state, alloc) = create_console(chardev, pci_slot, pci_fn);

    let mut features = console.borrow().get_device_features();
    features |= 1 << VIRTIO_CONSOLE_F_SIZE;
    console.borrow_mut().negotiate_features(features);
    console.borrow_mut().set_features_ok();
    assert_eq!(features, console.borrow_mut().get_guest_features());

    let unsupported_features = 1 << VIRTIO_CONSOLE_F_MULTIPORT;
    features |= unsupported_features;
    console.borrow_mut().negotiate_features(features);
    console.borrow_mut().set_features_ok();
    assert_ne!(features, console.borrow_mut().get_guest_features());
    assert_eq!(
        unsupported_features & console.borrow_mut().get_guest_features(),
        0
    );

    let unsupported_features = 1 << VIRTIO_CONSOLE_F_EMERG_WRITE;
    features |= unsupported_features;
    console.borrow_mut().negotiate_features(features);
    console.borrow_mut().set_features_ok();
    assert_ne!(features, console.borrow_mut().get_guest_features());
    assert_eq!(
        unsupported_features & console.borrow_mut().get_guest_features(),
        0
    );

    verify_pty_io(test_state.clone(), alloc.clone(), console.clone());

    test_state.borrow_mut().stop();
}

#[test]
fn console_pty_basic() {
    let pty = ChardevType::Pty;
    let pci_slot = 0x04;
    let pci_fn = 0x0;
    let (console, test_state, alloc) = create_console(pty, pci_slot, pci_fn);

    verify_pty_io(test_state.clone(), alloc.clone(), console.clone());

    test_state.borrow_mut().stop();
}

#[test]
fn console_socket_basic() {
    let socket_path = "/tmp/test-console0.sock";
    if Path::new(socket_path).exists() {
        fs::remove_file(socket_path).unwrap();
    }
    let socket = ChardevType::Socket {
        path: String::from(socket_path),
        server: true,
        nowait: true,
    };

    let pci_slot = 0x4;
    let pci_fn = 0x0;
    let (console, test_state, alloc) = create_console(socket, pci_slot, pci_fn);

    let vqs = console_setup(console.clone(), test_state.clone(), alloc.clone());
    let input_queue = vqs[0].clone();
    let output_queue = vqs[1].clone();

    let mut stream = UnixStream::connect(socket_path).expect("Couldn't connect socket");
    stream
        .set_nonblocking(true)
        .expect("Couldn't set nonblocking");

    let test_data = String::from("Test\n");
    let addr = alloc.borrow_mut().alloc(test_data.len() as u64);
    test_state.borrow().memwrite(addr, test_data.as_bytes());
    let free_head = output_queue.borrow_mut().add(
        test_state.clone(),
        addr,
        test_data.len().try_into().unwrap(),
        false,
    );

    console
        .borrow()
        .kick_virtqueue(test_state.clone(), output_queue.clone());
    console.borrow().poll_used_elem(
        test_state.clone(),
        output_queue.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        false,
    );

    verify_input_data(&mut stream, &test_data);

    let addr = alloc.borrow_mut().alloc(test_data.len() as u64);
    let free_head = input_queue.borrow_mut().add(
        test_state.clone(),
        addr,
        test_data.len().try_into().unwrap(),
        true,
    );
    console
        .borrow()
        .kick_virtqueue(test_state.clone(), input_queue.clone());

    match stream.write(&test_data.as_bytes()) {
        Ok(_num) => {
            let start_time = time::Instant::now();
            let timeout_us = time::Duration::from_micros(TIMEOUT_US);
            loop {
                let mut len: Option<u32> = Some(0);
                console.borrow().poll_used_elem(
                    test_state.clone(),
                    input_queue.clone(),
                    free_head,
                    TIMEOUT_US,
                    &mut len,
                    false,
                );
                if len.unwrap() != 0 {
                    verify_output_data(test_state.clone(), addr, len.unwrap(), &test_data);
                    break;
                }
                assert!(time::Instant::now() - start_time < timeout_us);
            }
        }
        Err(e) => assert!(false, "Failed to write contents to socket: {}", e),
    }

    stream
        .shutdown(Shutdown::Both)
        .expect("shutdown function failed");
    console.borrow_mut().destroy_device(alloc, vqs);
    test_state.borrow_mut().stop();
}

#[test]
fn console_parallel_req() {
    let socket_path = "/tmp/test-console1.sock";
    if Path::new(socket_path).exists() {
        fs::remove_file(socket_path).unwrap();
    }
    let socket = ChardevType::Socket {
        path: String::from(socket_path),
        server: true,
        nowait: true,
    };

    let pci_slot = 0x4;
    let pci_fn = 0x0;
    let (console, test_state, alloc) = create_console(socket, pci_slot, pci_fn);

    let vqs = console_setup(console.clone(), test_state.clone(), alloc.clone());
    let input_queue = vqs[0].clone();
    let output_queue = vqs[1].clone();

    let mut stream = UnixStream::connect(socket_path).expect("Couldn't connect socket");
    stream
        .set_nonblocking(true)
        .expect("Couldn't set nonblocking");

    let test_data = String::from("Test\n");
    let addr = alloc.borrow_mut().alloc(test_data.len() as u64);
    test_state.borrow().memwrite(addr, test_data.as_bytes());
    let free_head = output_queue.borrow_mut().add(
        test_state.clone(),
        addr,
        test_data.len().try_into().unwrap(),
        false,
    );

    console
        .borrow()
        .kick_virtqueue(test_state.clone(), output_queue.clone());
    let mut len: Option<u32> = Some(0);
    console.borrow().poll_used_elem(
        test_state.clone(),
        output_queue.clone(),
        free_head,
        TIMEOUT_US,
        &mut len,
        false,
    );

    let addr = alloc.borrow_mut().alloc(test_data.len() as u64);
    let free_head = input_queue.borrow_mut().add(
        test_state.clone(),
        addr,
        test_data.len().try_into().unwrap(),
        true,
    );
    console
        .borrow()
        .kick_virtqueue(test_state.clone(), input_queue.clone());

    verify_input_data(&mut stream, &test_data);

    match stream.write(&test_data.as_bytes()) {
        Ok(_num) => {
            let start_time = time::Instant::now();
            let timeout_us = time::Duration::from_micros(TIMEOUT_US);
            loop {
                let mut len: Option<u32> = Some(0);
                console.borrow().poll_used_elem(
                    test_state.clone(),
                    input_queue.clone(),
                    free_head,
                    TIMEOUT_US,
                    &mut len,
                    false,
                );
                if len.unwrap() != 0 {
                    verify_output_data(test_state.clone(), addr, len.unwrap(), &test_data);
                    break;
                }
                assert!(time::Instant::now() - start_time < timeout_us);
            }
        }
        Err(e) => assert!(false, "Failed to write contents to socket: {}", e),
    }

    let ret = test_state.borrow().qmp("{\"execute\": \"system_reset\"}");
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    console.borrow_mut().init(pci_slot, pci_fn);

    let vqs = console_setup(console.clone(), test_state.clone(), alloc.clone());
    let input_queue = vqs[0].clone();
    let output_queue = vqs[1].clone();

    let test_data = String::from("Test\n");
    let addr = alloc.borrow_mut().alloc(test_data.len() as u64);
    test_state.borrow().memwrite(addr, test_data.as_bytes());
    let free_head = output_queue.borrow_mut().add(
        test_state.clone(),
        addr,
        test_data.len().try_into().unwrap(),
        false,
    );

    console
        .borrow()
        .kick_virtqueue(test_state.clone(), output_queue.clone());
    console.borrow().poll_used_elem(
        test_state.clone(),
        output_queue.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        false,
    );

    verify_input_data(&mut stream, &test_data);

    let addr = alloc.borrow_mut().alloc(test_data.len() as u64);
    let free_head = input_queue.borrow_mut().add(
        test_state.clone(),
        addr,
        test_data.len().try_into().unwrap(),
        true,
    );
    console
        .borrow()
        .kick_virtqueue(test_state.clone(), input_queue.clone());

    match stream.write(&test_data.as_bytes()) {
        Ok(_num) => {
            let start_time = time::Instant::now();
            let timeout_us = time::Duration::from_micros(TIMEOUT_US);
            loop {
                let mut len: Option<u32> = Some(0);
                console.borrow().poll_used_elem(
                    test_state.clone(),
                    input_queue.clone(),
                    free_head,
                    TIMEOUT_US,
                    &mut len,
                    false,
                );
                if len.unwrap() != 0 {
                    verify_output_data(test_state.clone(), addr, len.unwrap(), &test_data);
                    break;
                }
                assert!(time::Instant::now() - start_time < timeout_us);
            }
        }
        Err(e) => assert!(false, "Failed to write contents to socket: {}", e),
    }

    stream
        .shutdown(Shutdown::Both)
        .expect("shutdown function failed");
    console.borrow_mut().destroy_device(alloc, vqs);
    test_state.borrow_mut().stop();
}
