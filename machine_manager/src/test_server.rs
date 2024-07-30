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

use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::prelude::AsRawFd;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use hex::FromHexError;
use vmm_sys_util::epoll::EventSet;

use crate::event_loop::EventLoop;
use crate::machine::{MachineTestInterface, IOTHREADS};
use crate::socket::SocketHandler;
use util::loop_context::{EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation};
use util::test_helper::{eoi_intx, get_test_clock, has_msix_msg, query_intx, set_test_clock};

pub struct TestSock {
    stream: UnixStream,
    controller: Arc<Mutex<dyn MachineTestInterface>>,
}

impl TestSock {
    pub fn new(path: &str, controller: Arc<Mutex<dyn MachineTestInterface>>) -> Self {
        let stream = match UnixStream::connect(path) {
            Ok(s) => s,
            Err(e) => {
                panic!("Failed to connect test socket: {}", e);
            }
        };
        TestSock { stream, controller }
    }

    pub fn get_stream_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}

impl EventNotifierHelper for TestSock {
    fn internal_notifiers(socket: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let socket_clone = socket.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, _| {
            let locked_socket = socket_clone.lock().unwrap();
            handle_test_cmd(locked_socket.get_stream_fd(), &locked_socket.controller);
            None
        });

        let mut notifiers = Vec::new();
        let handlers = vec![handler];
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddExclusion,
            socket.lock().unwrap().get_stream_fd(),
            None,
            EventSet::IN,
            handlers,
        ));
        notifiers
    }
}

fn get_min_timeout() -> i64 {
    let mut min_timeout = EventLoop::get_ctx(None).unwrap().timers_min_duration();

    for thread in IOTHREADS.lock().unwrap().iter() {
        let timeout = EventLoop::get_ctx(Some(&thread.id))
            .unwrap()
            .timers_min_duration();
        if timeout.is_some()
            && (min_timeout.is_none()
                || (min_timeout.is_some()
                    && timeout.as_ref().unwrap() < min_timeout.as_ref().unwrap()))
        {
            min_timeout = timeout;
        }
    }
    match min_timeout {
        Some(d) => {
            let timeout = d.as_nanos();
            if timeout >= i64::MAX as u128 {
                i64::MAX
            } else {
                timeout as i64
            }
        }
        None => -1,
    }
}

fn update_clock(target: u64) {
    let mut current = get_test_clock();
    while current < target {
        let timeout = get_min_timeout();
        let mut step = target.checked_sub(current).unwrap();
        if timeout != -1 && step > timeout as u64 {
            step = timeout as u64;
        }

        set_test_clock(current.checked_add(step).unwrap());
        EventLoop::get_ctx(None).unwrap().run_timers();
        for thread in IOTHREADS.lock().unwrap().iter() {
            EventLoop::get_ctx(Some(&thread.id)).unwrap().run_timers();
        }

        current = get_test_clock();
    }
}

fn handle_test_cmd(stream_fd: RawFd, controller: &Arc<Mutex<dyn MachineTestInterface>>) {
    let mut handler = SocketHandler::new(stream_fd);
    let msg = handler.get_line().unwrap().unwrap();

    let cmd: Vec<&str> = msg.split(' ').collect();
    assert!(!cmd.is_empty());
    match cmd[0] {
        "read" => {
            assert!(cmd.len() == 3);
            let addr = u64::from_str_radix(cmd[1].trim_start_matches("0x"), 16).unwrap();
            let size = usize::from_str_radix(cmd[2].trim_start_matches("0x"), 16).unwrap();
            let mut data = vec![0_u8; size];

            controller
                .lock()
                .unwrap()
                .mmio_read(addr, data.as_mut_slice());
            handler
                .send_str(format!("OK 0x{}", hex::encode(data).as_str()).as_str())
                .unwrap();
        }
        "readb" | "readw" | "readl" | "readq" => {
            assert!(cmd.len() == 2);
            let addr = u64::from_str_radix(cmd[1].trim_start_matches("0x"), 16).unwrap();
            let size = match cmd[0] {
                "readb" => 1,
                "readw" => 2,
                "readl" => 4,
                "readq" => 8,
                _ => unreachable!(),
            };
            let mut data = vec![0_u8; 8];

            controller
                .lock()
                .unwrap()
                .mmio_read(addr, data[..size].as_mut());
            data.reverse();

            handler
                .send_str(format!("OK 0x{}", hex::encode(data).as_str()).as_str())
                .unwrap();
        }
        "write" => {
            assert!(cmd.len() == 4);
            let addr = u64::from_str_radix(cmd[1].trim_start_matches("0x"), 16).unwrap();
            let size = usize::from_str_radix(cmd[2].trim_start_matches("0x"), 16).unwrap();
            let data_str = cmd[3].trim_start_matches("0x");
            let data = match hex::decode(data_str) {
                Ok(d) => d,
                Err(FromHexError::OddLength) => hex::decode(format!("0{}", data_str)).unwrap(),
                Err(e) => panic!("Unable to decode {} to hex: {}", data_str, e),
            };
            assert!(data.len() == size);

            controller.lock().unwrap().mmio_write(addr, data.as_slice());
            handler.send_str("OK").unwrap();
        }
        "writeb" | "writew" | "writel" | "writeq" => {
            assert!(cmd.len() == 3);
            let addr = u64::from_str_radix(cmd[1].trim_start_matches("0x"), 16).unwrap();
            let input_str = cmd[2].trim_start_matches("0x");
            let input = match hex::decode(input_str) {
                Ok(i) => i,
                Err(FromHexError::OddLength) => hex::decode(format!("0{}", input_str)).unwrap(),
                Err(e) => panic!("Unable to decode {} to hex: {}", input_str, e),
            };
            let size = match cmd[0] {
                "writeb" => 1,
                "writew" => 2,
                "writel" => 4,
                "writeq" => 8,
                _ => unreachable!(),
            };
            let mut data = vec![0_u8; size];
            data[size - input.len()..].copy_from_slice(input.as_slice());
            data.reverse();

            controller.lock().unwrap().mmio_write(addr, data.as_slice());
            handler.send_str("OK").unwrap();
        }
        "memset" => {
            assert!(cmd.len() == 4);
            let addr = u64::from_str_radix(cmd[1].trim_start_matches("0x"), 16).unwrap();
            let size = usize::from_str_radix(cmd[2].trim_start_matches("0x"), 16).unwrap();
            let pat = hex::decode(cmd[3].trim_start_matches("0x")).unwrap();
            let pat_size = pat.len();
            let mut data = vec![0_u8; size];
            for index in 0..data.len() {
                data[index] = pat[index % pat_size];
            }

            controller.lock().unwrap().mmio_write(addr, data.as_slice());
            handler.send_str("OK").unwrap();
        }
        "clock_step" => {
            assert!(cmd.len() < 3);
            let value = match cmd.len() {
                1 => get_min_timeout(),
                2 => cmd[1].parse::<i64>().unwrap(),
                _ => panic!("Too many arguments in clock_step command"),
            };
            let ns: u64 = std::cmp::max(value, 0) as u64;

            update_clock(get_test_clock().checked_add(ns).unwrap());
            handler
                .send_str(format!("OK {}", get_test_clock()).as_str())
                .unwrap();
        }
        "clock_set" => {
            assert!(cmd.len() == 2);
            let value = cmd[1].parse::<i64>().unwrap();
            let ns: u64 = std::cmp::max(value, 0) as u64;

            update_clock(ns);
            handler
                .send_str(format!("OK {}", get_test_clock()).as_str())
                .unwrap();
        }
        "query_msix" => {
            assert!(cmd.len() == 3);
            let addr = cmd[1].parse::<u64>().unwrap();
            let data = cmd[2].parse::<u32>().unwrap();
            match has_msix_msg(addr, data) {
                true => handler.send_str("OK TRUE".to_string().as_str()).unwrap(),
                false => handler.send_str("OK FALSE".to_string().as_str()).unwrap(),
            }
        }
        "query_intx" => {
            assert!(cmd.len() == 2);
            let irq = cmd[1].parse::<u32>().unwrap();
            match query_intx(irq) {
                true => handler.send_str("OK TRUE".to_string().as_str()).unwrap(),
                false => handler.send_str("OK FALSE".to_string().as_str()).unwrap(),
            }
        }
        "eoi_intx" => {
            assert!(cmd.len() == 2);
            let irq = cmd[1].parse::<u32>().unwrap();
            match eoi_intx(irq) {
                true => handler.send_str("OK TRUE".to_string().as_str()).unwrap(),
                false => handler.send_str("OK FALSE".to_string().as_str()).unwrap(),
            }
        }
        _ => {
            handler
                .send_str(format!("Unsupported command: {}", cmd[0]).as_str())
                .unwrap();
        }
    };
}
