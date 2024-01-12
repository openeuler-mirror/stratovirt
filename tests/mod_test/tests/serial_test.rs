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

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::prelude::*;
use std::mem::size_of;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::rc::Rc;
use std::{thread, time};

use byteorder::{ByteOrder, LittleEndian};

use mod_test::libdriver::machine::TestStdMachine;
use mod_test::libdriver::malloc::GuestAllocator;
use mod_test::libdriver::virtio::{TestVirtQueue, VirtioDeviceOps, VIRTIO_CONFIG_S_NEEDS_RESET};
use mod_test::libdriver::virtio_pci_modern::TestVirtioPciDev;
use mod_test::libtest::{test_init, TestState, MACHINE_TYPE_ARG};
use util::byte_code::ByteCode;

const TIMEOUT_US: u64 = 15 * 1000 * 1000;
const ROWS_DEFAULT: u16 = 0;
const COLS_DEFAULT: u16 = 0;
const EMERG_WR_DEFAULT: u32 = 0;
// Default 31 serial ports.
const DEFAULT_SERIAL_PORTS_NUMBER: u32 = 31;
const BUFFER_LEN: usize = 96;
// Each port has 2 virtqueues and there exist 2 control virtqueues.
const DEFAULT_SERIAL_VIRTQUEUES: usize = DEFAULT_SERIAL_PORTS_NUMBER as usize * 2 + 2;

const VIRTIO_CONSOLE_F_SIZE: u64 = 0;
const VIRTIO_CONSOLE_F_MULTIPORT: u64 = 1;
const VIRTIO_CONSOLE_F_EMERG_WRITE: u64 = 2;

const VIRTIO_CONSOLE_DEVICE_READY: u16 = 0;
const VIRTIO_CONSOLE_PORT_ADD: u16 = 1;
const VIRTIO_CONSOLE_PORT_READY: u16 = 3;
const VIRTIO_CONSOLE_CONSOLE_PORT: u16 = 4;
const VIRTIO_CONSOLE_PORT_OPEN: u16 = 6;
const VIRTIO_CONSOLE_PORT_NAME: u16 = 7;

const IN_CONTROL_QUEUE_ID: usize = 2;
const OUT_CONTROL_QUEUE_ID: usize = 3;

#[derive(Clone)]
enum ChardevType {
    Pty,
    Socket {
        path: String,
        server: bool,
        nowait: bool,
    },
}

#[derive(Clone)]
struct PortConfig {
    chardev_type: ChardevType,
    nr: u8,
    is_console: bool,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioConsoleControl {
    // Port number.
    id: u32,
    // The kind of control event.
    event: u16,
    // Extra information for event.
    value: u16,
}

impl VirtioConsoleControl {
    fn new(id: u32, event: u16, value: u16) -> Self {
        VirtioConsoleControl { id, event, value }
    }
}

impl ByteCode for VirtioConsoleControl {}

struct SerialTest {
    pub serial: Rc<RefCell<TestVirtioPciDev>>,
    pub state: Rc<RefCell<TestState>>,
    pub alloc: Rc<RefCell<GuestAllocator>>,
    vqs: Vec<Rc<RefCell<TestVirtQueue>>>,
    ports: HashMap<u8, bool>,
}

impl SerialTest {
    fn virtqueue_setup(&mut self, num_queues: usize) {
        let features = self.serial.borrow().get_device_features();
        self.vqs = self.serial.borrow_mut().init_device(
            self.state.clone(),
            self.alloc.clone(),
            features,
            num_queues,
        );
    }

    fn get_pty_path(&mut self) -> String {
        let ret = self.state.borrow().qmp("{\"execute\": \"query-chardev\"}");
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

    // Send control message by output control queue.
    fn out_control_event(&mut self, ctrl_msg: VirtioConsoleControl) {
        self.virtqueue_add_element(
            OUT_CONTROL_QUEUE_ID,
            Some(ctrl_msg.as_bytes()),
            size_of::<VirtioConsoleControl>() as u64,
        );
    }

    fn virtqueue_add_element(
        &mut self,
        queue_id: usize,
        data: Option<&[u8]>,
        buffer_len: u64,
    ) -> (u64, u32) {
        let queue = self.vqs[queue_id].clone();
        let addr = self.alloc.borrow_mut().alloc(buffer_len);
        let mut write = true;

        if let Some(buffer) = data {
            self.state.borrow().memwrite(addr, buffer);
            write = false;
        }
        let free_head = queue
            .borrow_mut()
            .add(self.state.clone(), addr, buffer_len as u32, write);

        self.serial
            .borrow()
            .kick_virtqueue(self.state.clone(), queue.clone());

        (addr, free_head)
    }

    // Fill a batch of buffers elements in queues[$queue_id].
    fn fill_buffer_in_vq(&mut self, queue_id: usize) -> (Vec<u32>, Vec<u64>) {
        // Note: limited by the MST framework, we only allocate 32 * 1K sized buffers. It's enough
        // for test.
        let mut buf_addrs = Vec::with_capacity(32);
        let mut free_heads = Vec::with_capacity(32);
        for _ in 0..32 {
            let (buf_addr, free_head) = self.virtqueue_add_element(queue_id, None, 1024);
            buf_addrs.push(buf_addr);
            free_heads.push(free_head);
        }

        (free_heads, buf_addrs)
    }

    // Init serial device.
    fn serial_init(&mut self) {
        let control_msg_len = size_of::<VirtioConsoleControl>();
        let mut in_msg = 0;

        // Init virtqueues.
        self.virtqueue_setup(DEFAULT_SERIAL_VIRTQUEUES);

        // Prepare control input buffer.
        let (free_heads, control_outs) = self.fill_buffer_in_vq(IN_CONTROL_QUEUE_ID);

        // Device ready.
        let ready_msg = VirtioConsoleControl::new(0, VIRTIO_CONSOLE_DEVICE_READY, 1);
        self.out_control_event(ready_msg);

        // Port add.
        self.serial.borrow().poll_used_elem(
            self.state.clone(),
            self.vqs[IN_CONTROL_QUEUE_ID].clone(),
            free_heads[in_msg],
            TIMEOUT_US,
            &mut None,
            true,
        );
        for _ in self.ports.iter() {
            let in_control_msg = self
                .state
                .borrow()
                .memread(control_outs[in_msg], control_msg_len as u64);
            in_msg += 1;
            assert_eq!(
                LittleEndian::read_u16(&in_control_msg[4..6]),
                VIRTIO_CONSOLE_PORT_ADD
            );
            assert_eq!(LittleEndian::read_u16(&in_control_msg[6..8]), 1);
        }

        // Port Ready.
        for port in self.ports.clone().iter() {
            let ready_msg = VirtioConsoleControl::new(*port.0 as u32, VIRTIO_CONSOLE_PORT_READY, 1);
            self.out_control_event(ready_msg);

            // If it's a console port.
            if *port.1 {
                let in_control_msg = self
                    .state
                    .borrow()
                    .memread(control_outs[in_msg], control_msg_len as u64);
                in_msg += 1;
                assert_eq!(
                    LittleEndian::read_u16(&in_control_msg[4..6]),
                    VIRTIO_CONSOLE_CONSOLE_PORT
                );
                assert_eq!(LittleEndian::read_u16(&in_control_msg[6..8]), 1);
            }

            // Port name.
            let in_control_msg = self
                .state
                .borrow()
                .memread(control_outs[in_msg], control_msg_len as u64);
            in_msg += 1;
            assert_eq!(
                LittleEndian::read_u16(&in_control_msg[4..6]),
                VIRTIO_CONSOLE_PORT_NAME
            );
            assert_eq!(LittleEndian::read_u16(&in_control_msg[6..8]), 1);

            // Virtconsole is default host connected.
            if *port.1 {
                let in_control_msg = self
                    .state
                    .borrow()
                    .memread(control_outs[in_msg], control_msg_len as u64);
                in_msg += 1;
                assert_eq!(
                    LittleEndian::read_u16(&in_control_msg[4..6]),
                    VIRTIO_CONSOLE_PORT_OPEN
                );
                assert_eq!(LittleEndian::read_u16(&in_control_msg[6..8]), 1);

                // driver -> device: port open.
                let open_msg: VirtioConsoleControl =
                    VirtioConsoleControl::new(*port.0 as u32, VIRTIO_CONSOLE_PORT_OPEN, 1);
                self.out_control_event(open_msg);
            }
        }
    }

    fn connect_pty_host(&mut self, new: bool) -> Option<File> {
        let pty_path = self.get_pty_path();
        assert_ne!(pty_path, String::from(""));

        let pty = match new {
            true => File::create(&pty_path),
            false => File::open(&pty_path),
        };

        // Connect pty host.
        let mut host: Option<File> = None;
        match pty {
            Ok(file) => host = Some(file),
            Err(e) => assert!(false, "{}", e),
        }

        host
    }

    fn connect_socket_host(&mut self, socket_path: &str) -> Option<UnixStream> {
        let stream = UnixStream::connect(socket_path).expect("Couldn't connect socket");
        stream
            .set_nonblocking(true)
            .expect("Couldn't set nonblocking");

        Some(stream)
    }

    fn verify_port_io(&mut self, port: PortConfig) {
        // queue[2]: control receiveq(host to guest).
        // queue[3]: control transmitq(guest to host).
        let input_queue_id = match port.nr {
            0 => 0,
            _ => 2 * port.nr + 2,
        } as usize;
        let output_queue_id = input_queue_id + 1;

        let mut stream = None;
        let mut host = None;

        // Connect Host.
        match port.chardev_type {
            ChardevType::Pty => {
                host = self.connect_pty_host(false);
            }
            ChardevType::Socket {
                ref path,
                server: _,
                nowait: _,
            } => {
                stream = self.connect_socket_host(&path);
            }
        }

        // Connect Guest.
        // driver -> device: port open.
        let open_msg: VirtioConsoleControl =
            VirtioConsoleControl::new(port.nr as u32, VIRTIO_CONSOLE_PORT_OPEN, 1);
        self.out_control_event(open_msg);

        // IO: Guest -> Host.
        let test_data = String::from("Test\n");
        let (_, free_head) = self.virtqueue_add_element(
            output_queue_id,
            Some(test_data.as_bytes()),
            test_data.len() as u64,
        );
        self.serial.borrow().poll_used_elem(
            self.state.clone(),
            self.vqs[output_queue_id].clone(),
            free_head,
            TIMEOUT_US,
            &mut None,
            false,
        );
        match port.chardev_type {
            ChardevType::Pty => {
                verify_input_data(&mut host.unwrap(), &test_data);
            }
            _ => {
                verify_input_data(&mut stream.as_ref().unwrap(), &test_data);
            }
        }

        // IO: Host -> Guest.
        let (addr, free_head) =
            self.virtqueue_add_element(input_queue_id, None, test_data.len() as u64);
        let result = match port.chardev_type {
            ChardevType::Pty => {
                let output = self.connect_pty_host(true);
                output.unwrap().write(&test_data.as_bytes())
            }
            _ => stream.as_ref().unwrap().write(&test_data.as_bytes()),
        };
        match result {
            Ok(_num) => {
                let start_time = time::Instant::now();
                let timeout_us = time::Duration::from_micros(TIMEOUT_US);
                loop {
                    let mut len: Option<u32> = Some(0);
                    self.serial.borrow().poll_used_elem(
                        self.state.clone(),
                        self.vqs[input_queue_id].clone(),
                        free_head,
                        TIMEOUT_US,
                        &mut len,
                        false,
                    );
                    if len.unwrap() != 0 {
                        verify_output_data(self.state.clone(), addr, len.unwrap(), &test_data);
                        break;
                    }
                    assert!(time::Instant::now() - start_time < timeout_us);
                }
            }
            Err(e) => assert!(false, "Failed to write contents to socket: {}", e),
        }

        // Clean.
        match port.chardev_type {
            ChardevType::Pty => {}
            _ => stream
                .unwrap()
                .shutdown(Shutdown::Both)
                .expect("shutdown function failed"),
        };
    }

    fn test_end(&mut self) {
        self.serial
            .borrow_mut()
            .destroy_device(self.alloc.clone(), self.vqs.clone());

        self.state.borrow_mut().stop();
    }
}

fn create_serial(ports_config: Vec<PortConfig>, pci_slot: u8, pci_fn: u8) -> SerialTest {
    let mut args: Vec<&str> = MACHINE_TYPE_ARG.split(' ').collect();
    let serial_pci_args = format!(
        "-device {},id=serial0,bus=pcie.0,addr={}.0",
        "virtio-serial-pci", pci_slot
    );
    let mut ports = HashMap::new();
    args.append(&mut serial_pci_args[..].split(' ').collect());

    let mut ports_args = String::new();
    for port in ports_config {
        let chardev_args = match port.chardev_type {
            ChardevType::Pty => format!("-chardev pty,id=charserial{}", port.nr),
            ChardevType::Socket {
                path,
                server,
                nowait,
            } => {
                let mut args = format!("-chardev socket,id=charserial{},path={}", port.nr, path);
                if server {
                    args.push_str(",server")
                }
                if nowait {
                    args.push_str(",nowait")
                }
                args
            }
        };
        ports_args.push_str(&chardev_args);

        let device_type = match port.is_console {
            true => "virtconsole",
            false => "virtserialport",
        };
        let port_args = format!(
            " -device {},chardev=charserial{},id=serialport{},nr={} ",
            device_type, port.nr, port.nr, port.nr
        );
        ports_args.push_str(&port_args);
        ports.insert(port.nr, port.is_console);
    }
    args.append(&mut ports_args.trim().split(' ').collect());

    let state = Rc::new(RefCell::new(test_init(args)));
    let machine = TestStdMachine::new(state.clone());
    let alloc = machine.allocator.clone();
    let serial = Rc::new(RefCell::new(TestVirtioPciDev::new(machine.pci_bus)));
    serial.borrow_mut().init(pci_slot, pci_fn);

    SerialTest {
        serial,
        state,
        alloc,
        vqs: Vec::new(),
        ports,
    }
}

fn verify_output_data(test_state: Rc<RefCell<TestState>>, addr: u64, len: u32, test_data: &String) {
    let mut data_buf: Vec<u8> = Vec::with_capacity(len as usize);
    data_buf.append(test_state.borrow().memread(addr, len as u64).as_mut());
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

/// Virtio serial pci device config space operation.
/// TestStep:
///   1. Init virtio serial device(1 virtconsole, pty backend chardev).
///   2. Read/write pci device config space.
///   3. IO function test.
///   4. Destroy device.
/// Expect:
///   1/2/3/4: success.
#[test]
fn serial_config_rw_conifg() {
    let port = PortConfig {
        chardev_type: ChardevType::Pty,
        nr: 0,
        is_console: true,
    };
    let pci_slot = 0x04;
    let pci_fn = 0x0;
    let mut st = create_serial(vec![port.clone()], pci_slot, pci_fn);

    // Cross boundary reading. Stratovirt should not be abnormal.
    st.serial.borrow().config_readl(32);

    // Read normally.
    assert_eq!(
        st.serial.borrow().config_readw(0),
        ROWS_DEFAULT,
        "The rows of the serial config is incorrect or the testcase parament is out of date!"
    );

    assert_eq!(
        st.serial.borrow().config_readw(2),
        COLS_DEFAULT,
        "The cols of the serial config is incorrect or the testcase parament is out of date!"
    );

    assert_eq!(
        st.serial.borrow().config_readl(4),
        DEFAULT_SERIAL_PORTS_NUMBER,
        "The max_nr_ports of the serial config is incorrect or the testcase parament is out of date!"
    );

    assert_eq!(
        st.serial.borrow().config_readl(8),
        EMERG_WR_DEFAULT,
        "The emerg_wr of the serial config is incorrect or the testcase parament is out of date!"
    );

    // Write config.
    st.serial.borrow().config_writew(0, 1);
    assert_eq!(
        st.serial.borrow().config_readw(0),
        ROWS_DEFAULT,
        "The serial device doesn't support writing config. But config was written!"
    );

    st.serial_init();
    st.verify_port_io(port);
    st.test_end();
}

/// Virtio serial pci device features negotiate operation.
/// TestStep:
///   1. Init virtio serial device(1 virtconsole, pty backend chardev).
///   2. Negotiate supported features(VIRTIO_CONSOLE_F_SIZE/VIRTIO_CONSOLE_F_MULTIPORT).
///   3. Negotiate unsupported feature(VIRTIO_CONSOLE_F_EMERG_WRITE).
///   4. IO function test.
///   5. Destroy device.
/// Expect:
///   1/2/4/5: success.
///   3: unsupported feature can't be negotiated.
#[test]
fn serial_features_negotiate() {
    let port = PortConfig {
        chardev_type: ChardevType::Pty,
        nr: 0,
        is_console: true,
    };
    let pci_slot = 0x04;
    let pci_fn = 0x0;
    let mut st = create_serial(vec![port.clone()], pci_slot, pci_fn);

    let mut features = st.serial.borrow().get_device_features();
    features |= 1 << VIRTIO_CONSOLE_F_SIZE | 1 << VIRTIO_CONSOLE_F_MULTIPORT;
    st.serial.borrow_mut().negotiate_features(features);
    st.serial.borrow_mut().set_features_ok();
    assert_eq!(features, st.serial.borrow_mut().get_guest_features());

    let unsupported_features = 1 << VIRTIO_CONSOLE_F_EMERG_WRITE;
    features |= unsupported_features;
    st.serial.borrow_mut().negotiate_features(features);
    st.serial.borrow_mut().set_features_ok();
    assert_ne!(features, st.serial.borrow_mut().get_guest_features());
    assert_eq!(
        unsupported_features & st.serial.borrow_mut().get_guest_features(),
        0
    );

    st.serial_init();
    st.verify_port_io(port);
    st.test_end();
}

/// Virtio serial pci device basic function(socket backend chardev).
/// TestStep:
///   1. Init virtio serial device(1 virtserialport, socket backend chardev).
///   2. IO function test.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtserialport_socket_basic() {
    let socket_path = "/tmp/test-virtserialport0.sock";
    if Path::new(socket_path).exists() {
        fs::remove_file(socket_path).unwrap();
    }
    let socket = ChardevType::Socket {
        path: String::from(socket_path),
        server: true,
        nowait: true,
    };
    let port = PortConfig {
        chardev_type: socket.clone(),
        nr: 1,
        is_console: false,
    };

    let pci_slot = 0x4;
    let pci_fn = 0x0;
    let mut st = create_serial(vec![port.clone()], pci_slot, pci_fn);

    st.serial_init();
    st.verify_port_io(port);
    st.test_end();
}

/// Virtio serial pci device basic function(pty backend chardev).
/// TestStep:
///   1. Init virtio serial device(1 virtserialport, pty backend chardev).
///   2. IO function test.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtserialport_pty_basic() {
    let port = PortConfig {
        chardev_type: ChardevType::Pty,
        nr: 1,
        is_console: false,
    };
    let pci_slot = 0x04;
    let pci_fn = 0x0;
    let mut st = create_serial(vec![port.clone()], pci_slot, pci_fn);

    st.serial_init();
    st.verify_port_io(port);
    st.test_end();
}

/// Virtio serial pci device error control message test.
/// TestStep:
///   1. Init virtio serial device(1 virtconsole, pty backend chardev).
///   2. Send out control message which has invalid event.
///   3. Send out control message which has non-existed port id.
///   4. Send out control message which size is illegal.
///   5. Destroy device.
/// Expect:
///   1/5: success.
///   2/3: Just discard this invalid msg. Nothing happened.
///   4: report virtio error.
#[test]
fn virtconsole_pty_err_out_control_msg() {
    let nr = 0;
    let port = PortConfig {
        chardev_type: ChardevType::Pty,
        nr,
        is_console: true,
    };
    let pci_slot = 0x04;
    let pci_fn = 0x0;
    let mut st = create_serial(vec![port.clone()], pci_slot, pci_fn);

    st.serial_init();

    // Error out control msg which has invalid event. Just discard this invalid msg. Nothing
    // happened.
    let invalid_event_msg = VirtioConsoleControl::new(nr as u32, VIRTIO_CONSOLE_PORT_NAME, 1);
    st.out_control_event(invalid_event_msg);

    // Error out control msg which has non-existed port id. Just discard this invalid msg. Nothing
    // happened.
    let invalid_event_msg = VirtioConsoleControl::new((nr + 5) as u32, VIRTIO_CONSOLE_PORT_OPEN, 1);
    st.out_control_event(invalid_event_msg);

    // Error out control msg which size is illegal.
    let error_control_msg = vec![0];
    st.virtqueue_add_element(OUT_CONTROL_QUEUE_ID, Some(&error_control_msg), 1);

    thread::sleep(time::Duration::from_secs(1));
    assert!(st.serial.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET != 0);

    // Send a random control message. Check stratovirt is working.
    let ready_msg = VirtioConsoleControl::new(0, VIRTIO_CONSOLE_DEVICE_READY, 1);
    st.out_control_event(ready_msg);

    st.test_end();
}

/// Virtio serial pci device invalid input control message buffer test.
/// TestStep:
///   1. Init virtio serial device(1 virtconsole, pty backend chardev).
///   2. Don't provide buffer in input_control_queue. Send a message which should response in
///      input_control_queue.
///   3. Provide 1 byte buffer in input_control_queue. Send a message which should response in
///      input_control_queue.
///   4. Destroy device.
/// Expect:
///   1/4: success.
///   2: Just discard this invalid msg. Nothing happened.
///   3: report virtio error.
#[test]
fn virtconsole_pty_invalid_in_control_buffer() {
    let port = PortConfig {
        chardev_type: ChardevType::Pty,
        nr: 0,
        is_console: true,
    };
    let pci_slot = 0x04;
    let pci_fn = 0x0;
    let mut st = create_serial(vec![port.clone()], pci_slot, pci_fn);

    // Init virtqueues.
    st.virtqueue_setup(DEFAULT_SERIAL_VIRTQUEUES);

    // No buffer in input_control_queue. Will discard all requests sent by input_control_queue.
    // Nothing else happened.
    let ready_msg = VirtioConsoleControl::new(0, VIRTIO_CONSOLE_DEVICE_READY, 1);
    st.out_control_event(ready_msg);

    // Provide size_of::<VirtioConsoleControl>() buffer for input_control_queue.
    st.virtqueue_add_element(
        IN_CONTROL_QUEUE_ID,
        None,
        size_of::<VirtioConsoleControl>() as u64,
    );

    // Error control msg: Guest is not ready. It will do nothing. Buffer in input_control_queue will
    // not be used.
    let ready_msg = VirtioConsoleControl::new(0, VIRTIO_CONSOLE_DEVICE_READY, 0);
    st.out_control_event(ready_msg);

    // Should response VIRTIO_CONSOLE_PORT_ADD msg when guest is ready. Buffer will be used.
    let ready_msg = VirtioConsoleControl::new(0, VIRTIO_CONSOLE_DEVICE_READY, 1);
    st.out_control_event(ready_msg);

    // Give only 1 byte for input control message which will result virtio error.
    st.virtqueue_add_element(IN_CONTROL_QUEUE_ID, None, 1);

    // Error control msg: Port is not ready. It will do nothing. Buffer in input_control_queue will
    // not be used.
    let ready_msg = VirtioConsoleControl::new(0, VIRTIO_CONSOLE_PORT_READY, 0);
    st.out_control_event(ready_msg);

    // Console is default host connected. Should response VIRTIO_CONSOLE_CONSOLE_PORT msg. 1 byte
    // Buffer will be used.
    let ready_msg = VirtioConsoleControl::new(0, VIRTIO_CONSOLE_PORT_READY, 1);
    st.out_control_event(ready_msg);

    // Little buffer for VIRTIO_CONSOLE_CONSOLE_PORT message.
    thread::sleep(time::Duration::from_secs(1));
    assert!(st.serial.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET != 0);

    st.test_end();
}

/// Virtio serial pci device IO test when host is not connected.
/// TestStep:
///   1. Init virtio serial device(1 virtserialport, socket backend chardev, don't connect in host).
///   2. IO test in this port.
///   3. IO test in virtqueues which have no port.
///   4. basic IO test.(port is connected)
///   5. Destroy device.
/// Expect:
///   1/4/5: success.
///   2/3: Just discard these requests. Nothing happened.
#[test]
fn virtserialport_socket_not_connect() {
    let nr = 1;
    let socket_path = "/tmp/test-virtserialport1.sock";
    if Path::new(socket_path).exists() {
        fs::remove_file(socket_path).unwrap();
    }
    let socket = ChardevType::Socket {
        path: String::from(socket_path),
        server: true,
        nowait: true,
    };
    let port = PortConfig {
        chardev_type: socket.clone(),
        nr,
        is_console: false,
    };

    let pci_slot = 0x4;
    let pci_fn = 0x0;
    let mut st = create_serial(vec![port.clone()], pci_slot, pci_fn);

    st.serial_init();

    // Requests will be discarded when host (port 1, output queue id: 5) is not connected. Nothing
    // happened.
    let test_data = String::from("Test\n");
    st.virtqueue_add_element(5, Some(test_data.as_bytes()), test_data.len() as u64);

    // Requests will be discarded when it is sent in virtqueue which has no port(port 2, output
    // queue id: 7). Nothing happened.
    let test_data = String::from("Test\n");
    st.virtqueue_add_element(7, Some(test_data.as_bytes()), test_data.len() as u64);

    // Virtio-serial is working normally after these steps.
    st.verify_port_io(port);
    st.test_end();
}
