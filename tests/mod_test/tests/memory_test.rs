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

use mod_test::{
    libdriver::{machine::TestStdMachine, malloc::GuestAllocator},
    libtest::{test_init, TestState},
};
use serde_json::{json, Value::String as JsonString};
use std::{cell::RefCell, fs::File, process::Command, rc::Rc, string::String};

pub struct MemoryTest {
    pub state: Rc<RefCell<TestState>>,
    pub alloctor: Rc<RefCell<GuestAllocator>>,
}

const MEM_SIZE: u64 = 2048; // 2GB
const PAGE_SIZE: u64 = 4096;
const ADDRESS_BASE: u64 = 0x4000_0000;
const ROM_DEV_PATH: &str = "rom_dev_file.fd";
const RAM_DEV_PATH: &str = "ram_dev_file.fd";

fn remove_file(path: String) {
    let _output = Command::new("rm").arg("-f").arg(path).output();
}

impl MemoryTest {
    pub fn new(
        memsize: u64,
        page_size: u64,
        shared: bool,
        prealloc: bool,
        hugepage_path: Option<String>,
        ram_file: Option<String>,
    ) -> Self {
        let mut extra_args: Vec<&str> = Vec::new();
        let mut args: Vec<&str> = "-machine".split(' ').collect();
        if shared {
            args.push("virt,mem-share=on");
        } else {
            args.push("virt");
        }
        if prealloc {
            args.push("-mem-prealloc");
        }
        extra_args.append(&mut args);

        let mem_args = format!("-m {}", memsize);
        args = mem_args[..].split(' ').collect();
        extra_args.append(&mut args);

        let mem_args;
        if let Some(file) = hugepage_path {
            mem_args = format!("-mem-path {:?}", file);
            args = mem_args[..].split(' ').collect();
            extra_args.append(&mut args);
        }

        let mem_args_path;
        if let Some(file) = ram_file {
            mem_args_path = format!("-mem-path {:?}", file);
            args = mem_args_path[..].split(' ').collect();
            extra_args.append(&mut args);
        }

        let test_state = Rc::new(RefCell::new(test_init(extra_args)));
        let machine =
            TestStdMachine::new_bymem(test_state.clone(), memsize * 1024 * 1024, page_size);
        let allocator = machine.allocator.clone();

        MemoryTest {
            state: test_state,
            alloctor: allocator,
        }
    }
}

fn ram_read_write(memory_test: &MemoryTest) {
    let str = "test memory read write";
    let addr = memory_test.alloctor.borrow_mut().alloc(PAGE_SIZE);

    memory_test
        .state
        .borrow_mut()
        .memwrite(addr, str.as_bytes());
    let ret = memory_test
        .state
        .borrow_mut()
        .memread(addr, str.len() as u64);
    assert_eq!(str, String::from_utf8(ret.clone()).unwrap());

    memory_test.state.borrow_mut().stop();
}

/// Ram read and write Test.
/// TestStep:
///   1. Start device.
///   2. Write some data("test memory read write") to the address.
///   3. Read data from the address and check it.
///   4. Destroy device.
/// Expect:
///   1/2/3/4: success.
#[test]
fn normal_ram_read_write() {
    ram_read_write(&MemoryTest::new(
        MEM_SIZE, PAGE_SIZE, false, false, None, None,
    ));
}

/// Io region read and write Test.
/// TestStep:
///   1. Add an io region.
///   2. Write some data([0x1u8; 8]) to the address.
///   3. Read data from the address and check it.
///   4. Write overflow.
///   5. Read overflow.
///   6. Destroy device.
/// Expect:
///   1/2/6: Success.
///   4/5: Failed
///   3: Got [0x2u8; 8]. The function of the device is to multiply the written value by 2.
#[test]
fn io_region_read_write() {
    let memory_test = MemoryTest::new(MEM_SIZE, PAGE_SIZE, false, false, None, None);
    let addr = 0x100_0000_0000; // 1TB

    // Add a dummy device by qmp. The function of the device is to multiply the written value by 2
    // through the write interface and save it, and read the saved value through the read interface.
    memory_test
        .state
        .borrow_mut()
        .qmp("{ \"execute\": \"update_region\", \"arguments\": { \"update_type\": \"add\", \"region_type\": \"io_region\", \"offset\": 1099511627776, \"size\": 4096, \"priority\": 99 }}");
    let data = [0x01u8; 8];
    memory_test.state.borrow_mut().memwrite(addr, &data);
    let ret = memory_test
        .state
        .borrow_mut()
        .memread(addr, std::mem::size_of::<u64>() as u64);
    assert_eq!(ret, [0x02u8; 8]);

    memory_test.state.borrow_mut().stop();
}

/// Read and write the overlapping region Test.
/// TestStep:
///   1. Write some data[0x1u8; 8] to the ram.
///   2. Read the data([0x1u8; 8]) from the address.
///   3. Add a region that overlaps the ram region.
///   4. Write some data[0x1u8; 8] the overlaps region.
///   5. Read data from the overlaps region.
/// Expect:
///   1/3/4: success.
///   2: Got [0x1u8; 8].
///   5: Got [0x2u8; 8]. We read the io region data witch has a higher priority.
#[test]
fn region_priority() {
    let memory_test = MemoryTest::new(MEM_SIZE, PAGE_SIZE, false, false, None, None);
    let addr = memory_test.alloctor.borrow_mut().alloc(PAGE_SIZE);
    let data = [0x01u8; 8];

    // Ram write and read.
    memory_test.state.borrow_mut().memwrite(addr, &data);
    let ret = memory_test
        .state
        .borrow_mut()
        .memread(addr, std::mem::size_of::<u64>() as u64);
    assert_eq!(ret, [0x01u8; 8]);

    // Add an overlapping region to write and read again.
    let qmp_cmd = format!("{{ \"execute\": \"update_region\", \"arguments\": {{ \"update_type\": \"add\", \"region_type\": \"io_region\", \"offset\": {}, \"size\": 4096, \"priority\": 99 }} }}", addr);
    memory_test.state.borrow_mut().qmp(&qmp_cmd);
    memory_test.state.borrow_mut().memwrite(addr, &data);
    let ret = memory_test
        .state
        .borrow_mut()
        .memread(addr, std::mem::size_of::<u64>() as u64);
    assert_eq!(ret, [0x02u8; 8]);
}

/// Some region update exception operations.
/// TestStep:
///   1. Add the wrong attribute.(add read only for ram_device)
///   2. Repeat adding region.
///   3. Delete a non-existent region
///   4. Add a region that extends beyond its father
/// Expect:
///   1: Success.
///   2/3: Failed.
#[test]
fn region_update_exception() {
    let memory_test = MemoryTest::new(MEM_SIZE, PAGE_SIZE, false, false, None, None);

    // Add read only attribute for io region.
    let ret = memory_test
        .state
        .borrow_mut()
        .qmp("{ \"execute\": \"update_region\", \"arguments\": { \"update_type\": \"add\", \"region_type\": \"io_region\", \"offset\": 2199023255552, \"size\": 4096, \"priority\": 100, \"read_only_mode\": true }}");
    assert_eq!(
        *ret.get("error").unwrap(),
        json!({"class": JsonString("GenericError".to_string()), "desc": JsonString("set_rom_device_romd failed".to_string())})
    );

    // Repeat adding region.
    let ret = memory_test
        .state
        .borrow_mut()
        .qmp("{ \"execute\": \"update_region\", \"arguments\": { \"update_type\": \"add\", \"region_type\": \"io_region\", \"offset\": 1099511627776, \"size\": 4096, \"priority\": 99 }}");
    assert_eq!(*ret.get("return").unwrap(), json!({}));
    let ret = memory_test
        .state
        .borrow_mut()
        .qmp("{ \"execute\": \"update_region\", \"arguments\": { \"update_type\": \"add\", \"region_type\": \"io_region\", \"offset\": 1099511627776, \"size\": 4096, \"priority\": 99 }}");
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    // Delete a non-existent region
    let ret = memory_test
        .state
        .borrow_mut()
        .qmp("{ \"execute\": \"update_region\", \"arguments\": { \"update_type\": \"delete\", \"region_type\": \"io_region\", \"offset\": 2199023255552, \"size\": 4096, \"priority\": 100 }}");
    assert_eq!(
        *ret.get("error").unwrap(),
        json!({"class": JsonString("GenericError".to_string()), "desc": JsonString("delete subregion failed".to_string())})
    );

    // Add a region that extends beyond its father
    let ret = memory_test
        .state
        .borrow_mut()
        .qmp("{ \"execute\": \"update_region\", \"arguments\": { \"update_type\": \"add\", \"region_type\": \"io_region\", \"offset\": 18446744073709551615, \"size\": 4096, \"priority\": 99 }}");
    assert_eq!(
        *ret.get("error").unwrap(),
        json!({"class": JsonString("GenericError".to_string()), "desc": JsonString("add subregion failed".to_string())})
    );

    memory_test.state.borrow_mut().stop();
}

/// Rom device region write Test.
/// TestStep:
///   1. Add a rom_device region with read_only_mode equals false.
///   2. Write some data([0x01u8; 8]) to the rom device.
///   3. Read data from the rom device and check it.
///   4. Write overflow test.
///   5. Read overflow test.
///   6. Add a rom_device region with read_only_mode equals true.
///   7. Write some data([0x01u8; 8]) to the rom device.
///   8. Read data from the rom device and check it.
/// Expect:
///   1/2/6/7: Success.
///   4/5: Failed.
///   3: Got [0x02u8; 8] from the device. The read and write behavior is the same as io region.
///   8: Got [0x00u8; 8] fro the device. The write opration does nothing, and read the original data.
#[test]
fn rom_device_region_readwrite() {
    let memory_test = MemoryTest::new(MEM_SIZE, PAGE_SIZE, false, false, None, None);
    let addr = 0x100_0000_0000; // 1TB

    // Add a dummy rom device by qmp. The function of the device is to multiply the written value by 2
    // through the write interface and save it, and read the saved value through the read interface.
    let file = File::create(&ROM_DEV_PATH).unwrap();
    file.set_len(PAGE_SIZE).unwrap();
    let qmp_str = format!(
        "{{ \"execute\": \"update_region\",
                        \"arguments\": {{ \"update_type\": \"add\",
                                        \"region_type\": \"rom_device_region\",
                                        \"offset\": 1099511627776,
                                        \"size\": 4096,
                                        \"priority\": 99,
                                        \"read_only_mode\": false,
                                        \"device_fd_path\": {:?} }} }}",
        ROM_DEV_PATH
    );
    memory_test.state.borrow_mut().qmp(&qmp_str);
    let data = [0x01u8; 8];
    memory_test.state.borrow_mut().memwrite(addr, &data);
    let ret = memory_test
        .state
        .borrow_mut()
        .memread(addr, std::mem::size_of::<u64>() as u64);
    assert_eq!(ret, [0x02u8; 8]);
    remove_file(ROM_DEV_PATH.to_string());

    // Write overflow
    memory_test
        .state
        .borrow_mut()
        .memwrite(addr + PAGE_SIZE - 1, &data);
    // Read overflow
    let ret = memory_test
        .state
        .borrow_mut()
        .memread(addr + PAGE_SIZE - 1, std::mem::size_of::<u64>() as u64);
    assert_eq!(ret, [0x00u8; 8]);

    // Add a dummy rom device by qmp. And set read only mode. The write operation is sent to the
    // device. The device can set the write mode to writable according to the device status during
    // the write operation, or directly return an error indicating that the write is not allowed.
    // The read operation is the same as that of IO region.
    let file = File::create(&ROM_DEV_PATH).unwrap();
    file.set_len(PAGE_SIZE).unwrap();
    let qmp_str = format!(
        "{{ \"execute\": \"update_region\",
                        \"arguments\": {{ \"update_type\": \"add\",
                                        \"region_type\": \"rom_device_region\",
                                        \"offset\": 1099511627776,
                                        \"size\": 4096,
                                        \"priority\": 99,
                                        \"read_only_mode\": true,
                                        \"device_fd_path\": {:?} }} }}",
        ROM_DEV_PATH
    );
    memory_test.state.borrow_mut().qmp(&qmp_str);
    let data = [0x01u8; 8];
    memory_test.state.borrow_mut().memwrite(addr, &data);
    let ret = memory_test
        .state
        .borrow_mut()
        .memread(addr, std::mem::size_of::<u64>() as u64);
    assert_eq!(ret, [0x00u8; 8]);
    remove_file(ROM_DEV_PATH.to_string());

    memory_test.state.borrow_mut().stop();
}

/// Ram device region write Test.
/// TestStep:
///   1. Start device.
///   2. Write some data([0x01u8; 8]) to the ram device.
///   3. Read data from the ram device and check it.
///   4. Write overflow.
///   5. Read overflow.
///   6. Destroy device.
/// Expect:
///   1/2/6: Success.
///   4/5: Failed.
///   3: Got [0x01u8; 8] from the device. The read and write behavior is the same as ram.
#[test]
fn ram_device_region_readwrite() {
    let memory_test = MemoryTest::new(MEM_SIZE, PAGE_SIZE, false, false, None, None);
    let addr = 0x100_0000_0000; // 1TB

    let file = File::create(&RAM_DEV_PATH).unwrap();
    file.set_len(PAGE_SIZE).unwrap();
    let qmp_str = format!(
        "{{ \"execute\": \"update_region\",
                        \"arguments\": {{ \"update_type\": \"add\",
                                        \"region_type\": \"ram_device_region\",
                                        \"offset\": 1099511627776,
                                        \"size\": 4096,
                                        \"priority\": 99,
                                        \"device_fd_path\": {:?} }} }}",
        RAM_DEV_PATH
    );
    memory_test.state.borrow_mut().qmp(&qmp_str);
    let data = [0x01u8; 8];
    memory_test.state.borrow_mut().memwrite(addr, &data);
    let ret = memory_test
        .state
        .borrow_mut()
        .memread(addr, std::mem::size_of::<u64>() as u64);
    assert_eq!(ret, [0x01u8; 8]);

    // Write overflow
    memory_test
        .state
        .borrow_mut()
        .memwrite(addr + PAGE_SIZE - 1, &data);
    // Read overflow
    let ret = memory_test
        .state
        .borrow_mut()
        .memread(addr + PAGE_SIZE - 1, std::mem::size_of::<u64>() as u64);
    assert_eq!(ret, [0x00u8; 8]);

    memory_test
        .state
        .borrow_mut()
        .qmp("{ \"execute\": \"update_region\", \"arguments\": { \"update_type\": \"delete\", \"region_type\": \"ram_device_region\", \"offset\": 1099511627776, \"size\": 4096, \"priority\": 99 }}");

    remove_file(RAM_DEV_PATH.to_string());

    memory_test.state.borrow_mut().stop();
}

/// Io region ioeventfd read and write Test.
/// TestStep:
///   1. Add an io region with ioeventfd(data: 1, size 8).
///   2. Write 1 to the ioeventfd.
///   3. Read data from the address and check it.
///   4. Write 2 to the ioeventfd.
///   5. Read data from the address and check it.
/// Expect:
///   1/2/4: success.
///   3: Got value 0.
///   5: Got value 4.
#[test]
fn io_region_ioeventfd() {
    let memory_test = MemoryTest::new(MEM_SIZE, PAGE_SIZE, false, false, None, None);
    let addr = 0x100_0000_0000; // 1TB

    memory_test
        .state
        .borrow_mut()
        .qmp("{ \"execute\": \"update_region\", \"arguments\": { \"update_type\": \"add\", \"region_type\": \"io_region\", \"offset\": 1099511627776, \"size\": 4096, \"priority\": 99, \"ioeventfd\": true, \"ioeventfd_data\": 1, \"ioeventfd_size\": 8 }}");
    memory_test.state.borrow_mut().writeq(addr, 1);
    let ret = memory_test
        .state
        .borrow_mut()
        .memread(addr, std::mem::size_of::<u64>() as u64);
    let cmp = [0x0u8; 8];
    assert_eq!(ret, cmp);

    memory_test.state.borrow_mut().writeq(addr, 2);
    let ret = memory_test
        .state
        .borrow_mut()
        .memread(addr, std::mem::size_of::<u64>() as u64);
    let mut cmp = [0x0u8; 8];
    cmp[0] = 4;
    assert_eq!(ret, cmp);

    memory_test.state.borrow_mut().stop();
}

/// Shared ram read and write Test.
/// TestStep:
///   1. Start device.
///   2. Write some data("test memory read write") to the address.
///   3. Read data from the address and check it.
///   4. Destroy device.
/// Expect:
///   1/2/3/4: success.
#[test]
fn shared_ram_read_write() {
    ram_read_write(&MemoryTest::new(
        MEM_SIZE, PAGE_SIZE, true, false, None, None,
    ));
}

/// Prealloc ram read and write Test.
/// TestStep:
///   1. Start device.
///   2. Write some data("test memory read write") to the address.
///   3. Read data from the address and check it.
///   4. Destroy device.
/// Expect:
///   1/2/3/4: success.
#[test]
fn prealloc_ram_read_write() {
    ram_read_write(&MemoryTest::new(
        MEM_SIZE, PAGE_SIZE, false, true, None, None,
    ));
}

/// Hugepage ram read and write Test.
/// TestStep:
///   1. Start device.
///   2. Write some data("test memory read write") to the address.
///   3. Read data from the address and check it.
///   4. Destroy device.
/// Expect:
///   1/2/3/4: success.
#[test]
fn hugepage_ram_read_write() {
    // crate hugetlbfs directory
    let _output = Command::new("rm")
        .arg("-rf")
        .arg("/tmp/stratovirt/hugepages")
        .output()
        .expect("Failed to rm directory");
    let _output = Command::new("mkdir")
        .arg("-p")
        .arg("/tmp/stratovirt/hugepages")
        .output()
        .expect("Failed to create directory");

    // mount hugetlbfs on a directory on host
    let output = Command::new("mount")
        .arg("-t")
        .arg("hugetlbfs")
        .arg("hugetlbfs")
        .arg("/tmp/stratovirt/hugepages")
        .output()
        .expect("Failed to mount hugetlbfs");
    assert!(output.status.success());

    // set the count of hugepages
    let output = Command::new("sysctl")
        .arg("vm.nr_hugepages=1024")
        .output()
        .expect("Failed to set the count of hugepages");
    assert!(output.status.success());

    ram_read_write(&MemoryTest::new(
        MEM_SIZE,
        PAGE_SIZE,
        false,
        false,
        Some("/tmp/stratovirt/hugepages".to_string()),
        None,
    ));

    // remove hugetlbfs
    let _output = Command::new("umount")
        .arg("/tmp/stratovirt/hugepages")
        .output()
        .expect("Failed to mount hugetlbfs");
    let _output = Command::new("rm")
        .arg("-rf")
        .arg("/tmp/stratovirt/hugepages")
        .output()
        .expect("Failed to rm directory");
}

/// File backend ram read and write Test.
/// TestStep:
///   1. Start device.
///   2. Write some data("test memory read write") to the address.
///   3. Read data from the address and check it.
///   4. Destroy device.
/// Expect:
///   1/2/3/4: success.
#[test]
fn filebackend_ram_read_write() {
    // crate hugetlbfs directory
    let _output = Command::new("rm")
        .arg("-rf")
        .arg("/tmp/stratovirt/dir")
        .output()
        .expect("Failed to rm directory");
    let _output = Command::new("mkdir")
        .arg("-p")
        .arg("/tmp/stratovirt/dir")
        .output()
        .expect("Failed to create directory");
    let _output = Command::new("touch")
        .arg("/tmp/stratovirt/dir/ram-file")
        .output()
        .expect("Failed to create directory");

    ram_read_write(&MemoryTest::new(
        MEM_SIZE,
        PAGE_SIZE,
        false,
        false,
        None,
        Some("/tmp/stratovirt/dir/ram-file".to_string()),
    ));
}

/// Ram read and write Test.
/// TestStep:
///   1. Start device.
///   2. Write some data("test memory read write") to the address.
///   3. Read data from the address and check it.
///   4. Destroy device.
/// Expect:
///   1/2/3/4: success.
#[test]
fn ram_readwrite_exception() {
    let str = "test memory read write";
    const SIZE: u64 = 22;
    let str_overflow = "test memory read write overflow";
    const SIZE_OVERFLOW: u64 = 31;
    let memory_test = MemoryTest::new(MEM_SIZE, PAGE_SIZE, false, false, None, None);
    let addr = 0x100_0000_0000; // 1TB

    // The start address is out of range.
    memory_test
        .state
        .borrow_mut()
        .memwrite(addr, str.as_bytes());
    let ret = memory_test.state.borrow_mut().memread(addr, SIZE);
    assert_eq!(ret, [0u8; SIZE as usize]);

    // The start address is in range, but the size is out of bounds.
    memory_test.state.borrow_mut().memwrite(
        MEM_SIZE * 1024 * 1024 - SIZE + ADDRESS_BASE,
        str_overflow.as_bytes(),
    );
    let ret = memory_test.state.borrow_mut().memread(addr, SIZE_OVERFLOW);
    assert_eq!(ret, [0u8; SIZE_OVERFLOW as usize]);

    memory_test.state.borrow_mut().stop();
}

/// Ram read and write Test.
/// TestStep:
///   1. Start device.
///   2. Write some data("test memory read write") to the address.
///      And the read/write will across numa.
///   3. Read data from the address and check it.
///   4. Destroy device.
/// Expect:
///   1/2/3/4: success.
#[test]
fn ram_readwrite_numa() {
    let mut args: Vec<&str> = Vec::new();
    let mut extra_args: Vec<&str> = "-machine virt".split(' ').collect();
    args.append(&mut extra_args);

    let cpu = 8;
    let cpu_args = format!(
        "-smp {},sockets=1,cores=4,threads=2 -cpu host,pmu=on -m 2G",
        cpu
    );
    let mut extra_args = cpu_args.split(' ').collect();
    args.append(&mut extra_args);
    extra_args = "-object memory-backend-ram,size=1G,id=mem0,host-nodes=0-1,policy=bind"
        .split(' ')
        .collect();
    args.append(&mut extra_args);
    extra_args = "-object memory-backend-ram,size=1G,id=mem1,host-nodes=0-1,policy=bind"
        .split(' ')
        .collect();
    args.append(&mut extra_args);
    extra_args = "-numa node,nodeid=0,cpus=0-3,memdev=mem0"
        .split(' ')
        .collect();
    args.append(&mut extra_args);
    extra_args = "-numa node,nodeid=1,cpus=4-7,memdev=mem1"
        .split(' ')
        .collect();
    args.append(&mut extra_args);
    extra_args = "-numa dist,src=0,dst=1,val=30".split(' ').collect();
    args.append(&mut extra_args);
    extra_args = "-numa dist,src=1,dst=0,val=30".split(' ').collect();
    args.append(&mut extra_args);

    let test_state = Rc::new(RefCell::new(test_init(args)));

    let str = "test memory read write";
    let start_base = ADDRESS_BASE + MEM_SIZE * 1024 * 1024 / 2 - 4;
    test_state.borrow_mut().memwrite(start_base, str.as_bytes());
    let ret = test_state
        .borrow_mut()
        .memread(start_base, str.len() as u64);
    assert_eq!(str, String::from_utf8(ret.clone()).unwrap());

    test_state.borrow_mut().stop();
}
