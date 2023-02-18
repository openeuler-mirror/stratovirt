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
use std::mem::size_of;
use std::rc::Rc;
use std::slice::from_raw_parts;
use std::{thread, time};

use rand::Rng;
use util::aio::{aio_probe, AioEngine};
use util::byte_code::ByteCode;
use util::offset_of;

use mod_test::libdriver::machine::TestStdMachine;
use mod_test::libdriver::malloc::GuestAllocator;
use mod_test::libdriver::virtio::{
    TestVirtQueue, TestVringDescEntry, VirtioDeviceOps, VIRTIO_CONFIG_S_NEEDS_RESET,
    VIRTIO_F_BAD_FEATURE, VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use mod_test::libdriver::virtio_pci_modern::TestVirtioPciDev;
use mod_test::libtest::{test_init, TestState};
use mod_test::utils::{cleanup_img, create_img, TEST_IMAGE_SIZE};

const TEST_VIRTIO_SCSI_CDB_SIZE: usize = 32;
const TEST_VIRTIO_SCSI_SENSE_SIZE: usize = 96;

/// According to Virtio Spec.
/// Max_channel should be 0.
/// Max_target should be less than or equal to 255.
const TEST_VIRTIO_SCSI_MAX_TARGET: u16 = 255;
/// Max_lun should be less than or equal to 16383 (2^14 - 1).
const TEST_VIRTIO_SCSI_MAX_LUN: u32 = 16383;

const TIMEOUT_US: u64 = 10 * 1000 * 1000;
const DEFAULT_SCSI_DESC_ELEM: usize = 3;

/// Default serial number of scsi device.
const DEFAULT_SCSI_SERIAL: &str = "123456";

const READ_10: u8 = 0x28;
const WRITE_10: u8 = 0x2a;
const TEST_UNIT_READY: u8 = 0x00;
const INQUIRY: u8 = 0x12;
const REPORT_LUNS: u8 = 0xa0;
const READ_CAPACITY_10: u8 = 0x25;
const MODE_SENSE: u8 = 0x1a;
const REQUEST_SENSE: u8 = 0x03;
const GET_CONFIGURATION: u8 = 0x46;
const READ_DISC_INFORMATION: u8 = 0x51;
const GET_EVENT_STATUS_NOTIFICATION: u8 = 0x4a;
const READ_TOC: u8 = 0x43;

const VIRTIO_SCSI_S_OK: u8 = 0;
const VIRTIO_SCSI_S_BAD_TARGET: u8 = 3;
const VIRTIO_SCSI_S_FAILURE: u8 = 9;

/// Mode page codes for mode sense/set.
const MODE_PAGE_CACHING: u8 = 0x08;
const MODE_PAGE_CAPABILITIES: u8 = 0x2a;
const MODE_PAGE_ALLS: u8 = 0x3f;

/// Basic length of fixed format sense data.
const TEST_SCSI_SENSE_LEN: u32 = 18;

const MODE_SENSE_LEN_DATA_LEN: u8 = 36;
const READ_DISC_INFORMATION_DATA_LEN: u8 = 34;
const GET_CONFIGURATION_DATA_LEN: u8 = 40;
const GET_EVENT_STATUS_NOTIFICATION_DATA_LEN: u8 = 8;
const REPORT_LUNS_DATA_LEN: u8 = 16;
const INQUIRY_TARGET_DATA_LEN: u8 = 36;
const READ_CAPACITY_10_DATA_LEN: u8 = 8;
const INQUIRY_DATA_LEN: u8 = 96;
const MODE_SENSE_PAGE_CACHE_LEN_DATA_LEN: u8 = 32;
const MODE_SENSE_PAGE_ALL_DATA_LEN: u8 = 44;
const INQUIRY_SUPPORTED_VPD_PAGES_DATA_LEN: u8 = 10;
const INQUIRY_UNIT_SERIAL_NUMBER_DATA_LEN: u8 = 254;
const INQUIRY_DEVICE_IDENTIFICATION_DATA_LEN: u8 = 254;
const INQUIRY_BLOCK_LIMITS_DATA_LEN: u8 = 64;
const INQUIRY_BLOCK_DEVICE_CHARACTERISTICS_DATA_LEN: u8 = 64;
const INQUIRY_LOGICAL_BLOCK_PROVISIONING_DATA_LEN: u8 = 8;
const INQUIRY_REFERRALS_DATA_LEN: u8 = 64;
const READ_TOC_DATA_LEN: u8 = 20;
const READ_TOC_MSF_DATA_LEN: u8 = 12;
const READ_TOC_FORMAT_DATA_LEN: u8 = 12;

struct VirtioScsiTest {
    cntlr: Rc<RefCell<TestVirtioPciDev>>,
    scsi_devices: Vec<ScsiDeviceConfig>,
    state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    queues: Vec<Rc<RefCell<TestVirtQueue>>>,
}

impl VirtioScsiTest {
    /// Init test case. It will create a virtio-scsi controller with a scsi device using given args.
    ///
    /// # Arguments
    ///
    /// * `scsi_type` - The type of the only scsi device. Supports Harddisk and CD-ROM.
    /// * `target`    - The given target id of the only scsi device.
    /// * `lun`       - The given lun id of the only scsi device.
    /// * `image_size`- The size of the backend image.
    /// * `iothread`  - If true, virtio-scsi controller will use iothread to process IO.
    ///
    /// # Return
    ///
    /// * `VirtioScsiTest`  - Basic object for most tests, including the virtio scsi controller,
    ///                     - the scsi device's config, the state of testcase, the memory management
    ///                     - structure and virtqueues of this controller.
    fn testcase_start_with_config(
        scsi_type: ScsiDeviceType,
        target: u8,
        lun: u16,
        image_size: u64,
        iothread: bool,
    ) -> VirtioScsiTest {
        let image_path = Rc::new(create_img(image_size, 1));

        let cntlrcfg = CntlrConfig {
            id: 0,
            use_iothread: iothread,
        };

        let readonly = if scsi_type == ScsiDeviceType::ScsiHd {
            false
        } else {
            true
        };
        let scsi_devices: Vec<ScsiDeviceConfig> = vec![ScsiDeviceConfig {
            cntlr_id: 0,
            device_type: scsi_type,
            image_path: image_path.clone(),
            target,
            lun,
            read_only: readonly,
            direct: false,
            aio: TestAioType::AioOff,
            serial: Some(DEFAULT_SCSI_SERIAL.to_string()),
        }];

        let (cntlr, state, alloc) = scsi_test_init(cntlrcfg, scsi_devices.clone());
        let features = virtio_scsi_defalut_feature(cntlr.clone());
        let queues = cntlr
            .borrow_mut()
            .init_device(state.clone(), alloc.clone(), features, 3);

        VirtioScsiTest {
            cntlr,
            scsi_devices,
            state,
            alloc,
            queues,
        }
    }

    fn general_testcase_run(scsi_type: ScsiDeviceType, target: u8, lun: u16) -> VirtioScsiTest {
        VirtioScsiTest::testcase_start_with_config(scsi_type, target, lun, TEST_IMAGE_SIZE, false)
    }

    // String is not end with "/0" in Rust, so we should add data_in_len parameter to control length
    // of the reading data.
    fn virtio_scsi_do_command(
        &mut self,
        req: TestVirtioScsiCmdReq,
        data_out: &Option<String>,
        resp: &mut TestVirtioScsiCmdResp,
        data_in: &mut Vec<u8>,
        data_in_len: u32,
    ) {
        assert!(data_in_len <= data_in.capacity() as u32);

        let virtqueue = &self.queues[2];
        let mut len = Some(0);
        let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(DEFAULT_SCSI_DESC_ELEM);

        // Request Header.
        let cmdreq_len = size_of::<TestVirtioScsiCmdReq>() as u64;
        let req_addr = self
            .alloc
            .borrow_mut()
            .alloc(cmdreq_len.try_into().unwrap());
        let req_bytes = req.as_bytes();
        self.state.borrow().memwrite(req_addr, req_bytes);

        data_entries.push(TestVringDescEntry {
            data: req_addr,
            len: cmdreq_len as u32,
            write: false,
        });

        // Data out.
        if let Some(data) = data_out {
            let out_len = data.len() as u32;
            let out_bytes = data.as_bytes().to_vec();
            let out_addr = self.alloc.borrow_mut().alloc(out_len.try_into().unwrap());
            self.state.borrow().memwrite(out_addr, out_bytes.as_slice());
            data_entries.push(TestVringDescEntry {
                data: out_addr,
                len: out_len,
                write: false,
            });
        }

        // Response.
        let cmdresp_len = size_of::<TestVirtioScsiCmdResp>() as u64;
        let resp_addr = self
            .alloc
            .borrow_mut()
            .alloc((cmdresp_len + data_in_len as u64).try_into().unwrap());
        let resp_bytes = resp.as_bytes();
        self.state.borrow().memwrite(resp_addr, resp_bytes);

        // Data in.
        data_entries.push(TestVringDescEntry {
            data: resp_addr,
            len: cmdresp_len as u32,
            write: true,
        });

        if data_in_len > 0 {
            data_entries.push(TestVringDescEntry {
                data: resp_addr + cmdresp_len,
                len: data_in_len,
                write: true,
            });
        }

        let free_head = virtqueue
            .borrow_mut()
            .add_chained(self.state.clone(), data_entries);

        self.cntlr
            .borrow()
            .kick_virtqueue(self.state.clone(), virtqueue.clone());
        self.cntlr.borrow().poll_used_elem(
            self.state.clone(),
            virtqueue.clone(),
            free_head,
            TIMEOUT_US,
            &mut len,
            true,
        );

        let resp_bytes_new = self.state.borrow().memread(resp_addr, cmdresp_len);
        let slice = unsafe {
            from_raw_parts(
                resp_bytes_new.as_ptr() as *const TestVirtioScsiCmdResp,
                size_of::<TestVirtioScsiCmdResp>(),
            )
        };
        *resp = slice[0].clone();

        if data_in_len > 0 {
            data_in.append(
                self.state
                    .borrow()
                    .memread(resp_addr + cmdresp_len, data_in_len as u64)
                    .as_mut(),
            );
        }
    }

    fn scsi_cdb_test(&mut self, cdb_test: CdbTest) -> Option<Vec<u8>> {
        let scsi_req = TestVirtioScsiCmdReq::new(cdb_test.target, cdb_test.lun, cdb_test.cdb);
        let mut scsi_resp = TestVirtioScsiCmdResp::default();
        let mut data_in = Vec::<u8>::with_capacity(cdb_test.data_in_length as usize);

        self.virtio_scsi_do_command(
            scsi_req,
            &cdb_test.data_out,
            &mut scsi_resp,
            &mut data_in,
            cdb_test.data_in_length,
        );

        assert_eq!(scsi_resp.response, cdb_test.expect_response);
        if let Some(result_vec) = cdb_test.expect_result_data {
            assert_eq!(result_vec, data_in);
        }
        if let Some(sense_vec) = cdb_test.expect_sense {
            assert_eq!(sense_vec, scsi_resp.sense);
        }

        if cdb_test.data_in_length != 0 {
            Some(data_in)
        } else {
            None
        }
    }

    fn testcase_tear_down(&mut self) {
        self.cntlr
            .borrow_mut()
            .destroy_device(self.alloc.clone(), self.queues.clone());
        self.state.borrow_mut().stop();
        for device in self.scsi_devices.iter() {
            cleanup_img(device.image_path.clone().to_string());
        }
    }

    // Basic IO function test.
    fn scsi_try_io(&mut self, target: u8, lun: u16, scsi_type: ScsiDeviceType) {
        // Test: scsi command: WRITE_10.
        // Write to LBA(logical block address) 0, transfer length 1 sector.
        // Test Result: Check if scsi command WRITE_10 was handled successfully for scsi harddisk and
        // was failure for scsi CD-ROM.
        let mut write_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
        write_cdb[0] = WRITE_10;
        write_cdb[8] = 0x1; // 1 sector.
        let data = vec![0x8; 512];
        let write_data = String::from_utf8(data).unwrap();
        let expect_response = if scsi_type == ScsiDeviceType::ScsiHd {
            VIRTIO_SCSI_S_OK
        } else {
            VIRTIO_SCSI_S_FAILURE
        };
        let cdb_test_args = CdbTest {
            cdb: write_cdb,
            target,
            lun,
            data_out: Some(write_data.clone()),
            data_in_length: 0,
            expect_response,
            expect_result_data: None,
            expect_sense: None,
        };
        self.scsi_cdb_test(cdb_test_args);

        // Test: scsi command: READ_10.
        // Read from LBA(logical block address) 0, transfer length 1.
        // Test Result: Check if scsi command READ_10 was handled successfully. And check the read data is
        // the right data which was sent in WRITE_10 test for scsi harddisk.
        let mut read_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
        read_cdb[0] = READ_10;
        read_cdb[8] = 0x1; // 1 sector.

        let (data_in_length, expect_result_data) = if scsi_type == ScsiDeviceType::ScsiHd {
            (write_data.len(), Some(write_data.into_bytes()))
        } else {
            (0, None)
        };

        let cdb_test_args = CdbTest {
            cdb: read_cdb,
            target,
            lun,
            data_out: None,
            data_in_length: data_in_length as u32, // Read 1 sector data.
            expect_response: VIRTIO_SCSI_S_OK,
            expect_result_data,
            expect_sense: None,
        };
        self.scsi_cdb_test(cdb_test_args);
    }
}

struct CdbTest {
    cdb: [u8; TEST_VIRTIO_SCSI_CDB_SIZE],
    target: u8,
    lun: u16,
    data_out: Option<String>,
    data_in_length: u32,
    expect_response: u8,
    expect_result_data: Option<Vec<u8>>,
    expect_sense: Option<[u8; TEST_VIRTIO_SCSI_SENSE_SIZE]>,
}

#[derive(Default)]
struct ScsiSense {
    /// Sense key.
    key: u8,
    /// Additional sense code.
    asc: u8,
    /// Additional sense code qualifier.
    ascq: u8,
}

const SCSI_SENSE_INVALID_OPCODE: ScsiSense = ScsiSense {
    key: 0x05,
    asc: 0x20,
    ascq: 0x00,
};

const SCSI_SENSE_INVALID_FIELD: ScsiSense = ScsiSense {
    key: 0x05,
    asc: 0x24,
    ascq: 0x00,
};

const SCSI_SENSE_LUN_NOT_SUPPORTED: ScsiSense = ScsiSense {
    key: 0x05,
    asc: 0x25,
    ascq: 0x00,
};

const SCSI_SENSE_NO_SENSE: ScsiSense = ScsiSense {
    key: 0,
    asc: 0,
    ascq: 0,
};

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
struct TestVirtioScsiCmdReq {
    lun: [u8; 8],
    tag: u64,
    task_attr: u8,
    prio: u8,
    crn: u8,
    cdb: [u8; TEST_VIRTIO_SCSI_CDB_SIZE],
}

impl TestVirtioScsiCmdReq {
    fn new(target: u8, lun: u16, cdb: [u8; TEST_VIRTIO_SCSI_CDB_SIZE]) -> Self {
        let mut req = TestVirtioScsiCmdReq::default();
        let mut target_lun = [0_u8; 8];
        target_lun[0] = 1;
        target_lun[1] = target;
        target_lun[2] = (lun >> 8) as u8 & 0xff;
        target_lun[3] = lun as u8 & 0xff;

        req.lun = target_lun;
        req.cdb = cdb;

        req
    }
}

impl ByteCode for TestVirtioScsiCmdReq {}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct TestVirtioScsiCmdResp {
    sense_len: u32,
    resid: u32,
    status_qualifier: u16,
    status: u8,
    response: u8,
    sense: [u8; TEST_VIRTIO_SCSI_SENSE_SIZE],
}

impl ByteCode for TestVirtioScsiCmdResp {}

impl Default for TestVirtioScsiCmdResp {
    fn default() -> Self {
        TestVirtioScsiCmdResp {
            sense_len: 0,
            resid: 0,
            status_qualifier: 0,
            status: 0,
            response: 0,
            sense: [0; TEST_VIRTIO_SCSI_SENSE_SIZE],
        }
    }
}

struct CntlrConfig {
    // Controller id.
    id: u8,
    // If true, use iothread.
    use_iothread: bool,
}

#[derive(PartialEq, Clone, Debug)]
enum ScsiDeviceType {
    // Scsi Harddisk.
    ScsiHd = 0,
    // Scsi CD-ROM/DVD-ROM.
    ScsiCd = 1,
}

impl std::fmt::Display for ScsiDeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ScsiDeviceType::ScsiHd => "scsi-hd",
                ScsiDeviceType::ScsiCd => "scsi-cd",
            }
        )
    }
}

#[derive(Clone, Debug, Copy)]
enum TestAioType {
    AioOff = 0,
    AioNative = 1,
    AioIOUring = 2,
}

impl std::fmt::Display for TestAioType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TestAioType::AioIOUring => "io_uring",
                TestAioType::AioNative => "native",
                TestAioType::AioOff => "off",
            }
        )
    }
}

#[derive(Clone, Debug)]
struct ScsiDeviceConfig {
    cntlr_id: u8,
    device_type: ScsiDeviceType,
    image_path: Rc<String>,
    target: u8,
    lun: u16,
    read_only: bool,
    direct: bool,
    aio: TestAioType,
    serial: Option<String>,
}

impl ScsiDeviceConfig {
    fn cmdline(&self) -> String {
        let serial_args = if let Some(serial) = &self.serial {
            format!(",serial={}", serial)
        } else {
            "".to_string()
        };

        let device_args = format!(
            "-device {},bus=scsi{}.0,scsi-id={},lun={},drive=drive-scsi0-0-{}-{},id=scsi0-0-{}-{}{}",
            self.device_type, self.cntlr_id, self.target, self.lun, self.target, self.lun, self.target,
            self.lun, serial_args,
        );

        let drive_args = format!(
            "-drive file={},id=drive-scsi0-0-{}-{},direct={},readonly={},aio={}",
            self.image_path, self.target, self.lun, self.direct, self.read_only, self.aio,
        );

        format!("{} {} ", device_args, drive_args)
    }
}

fn get_sense_bytes(sense: ScsiSense) -> [u8; TEST_VIRTIO_SCSI_SENSE_SIZE] {
    let mut bytes = [0; TEST_VIRTIO_SCSI_SENSE_SIZE];
    bytes[0] = 0x70; // Fixed. Current errors.
    bytes[2] = sense.key;
    bytes[7] = 10; // Fixed. sense length: 10;
    bytes[12] = sense.asc;
    bytes[13] = sense.ascq;

    bytes
}

pub fn virtio_scsi_defalut_feature(cntlr: Rc<RefCell<TestVirtioPciDev>>) -> u64 {
    let mut features = cntlr.borrow().get_device_features();
    features &=
        !(VIRTIO_F_BAD_FEATURE | 1 << VIRTIO_RING_F_INDIRECT_DESC | 1 << VIRTIO_RING_F_EVENT_IDX);

    features
}

fn scsi_test_init(
    controller: CntlrConfig,
    scsidevice: Vec<ScsiDeviceConfig>,
) -> (
    Rc<RefCell<TestVirtioPciDev>>,
    Rc<RefCell<TestState>>,
    Rc<RefCell<GuestAllocator>>,
) {
    let mut args: Vec<&str> = "-machine virt".split(' ').collect();

    let pci_fn = 0;
    let pci_slot = 0x4;

    let iothread_args = if controller.use_iothread {
        let mut iothread_args_vec: Vec<&str> = "-object iothread,id=iothread1".split(' ').collect();
        args.append(&mut iothread_args_vec);
        ",iothread=iothread1"
    } else {
        ""
    };

    let cntlr_args = format!(
        "-device virtio-scsi-pci,id=scsi{},bus=pcie.0,addr={}.0{}",
        controller.id, pci_slot, iothread_args
    );
    let mut cntlr_str_vec: Vec<&str> = cntlr_args[..].split(' ').collect();
    args.append(&mut cntlr_str_vec);

    let mut scsi_device_args = String::new();

    for device in scsidevice.iter() {
        let disk_args = device.cmdline();
        scsi_device_args.push_str(&disk_args);
    }

    let mut disk_args_vec: Vec<&str> = scsi_device_args.trim().split(' ').collect();
    args.append(&mut disk_args_vec);

    let test_state = Rc::new(RefCell::new(test_init(args)));
    let machine = TestStdMachine::new(test_state.clone());
    let allocator = machine.allocator.clone();

    let virtio_scsi = Rc::new(RefCell::new(TestVirtioPciDev::new(machine.pci_bus.clone())));
    virtio_scsi.borrow_mut().init(pci_slot, pci_fn);

    (virtio_scsi, test_state, allocator)
}

/// Virtio Scsi hard disk basic function test. target 31, lun 7.
/// TestStep:
///   0. Init process.
///   1. Traverse all possible targets from 0 to VIRTIO_SCSI_MAX_TARGET(255).
///      (using scsi command INQUIRY) (lun is always 0 in this traverse process).
///   2. Get all luns info in target 31.(using scsi command REPORT_LUNS)
///   3. Check if scsi device is OK.(using scsi command TEST_UNIT_READY)
///   4. Get the capacity of the disk.(using scsi command READ_CAPACITY_10)
///   5. Get the caching strategy of the disk.(using scsi command MODE_SENSE)
///   6. Get some other information of the disk.(using scsi command INQUITY)
///   7. Basic IO test.
///   8. Test ends. Destroy device.
/// Expect:
///   1. 1/2/3/4/5/6/7/8: success.
///   step 2. Response VIRTIO_SCSI_S_BAD_TARGET for INQUIRY command in target 0-30.
///           Response VIRTIO_SCSI_S_OK for INQUIRY command in target 31.
///   step 3. Reported lun is 7.
///   step 4. Response VIRTIO_SCSI_S_OK.
///   step 5. Get the right mode information of disk.
///   step 6. Get the right information of disk.
///   step 7. READ/WRITE is OK.
#[test]
fn scsi_hd_basic_test() {
    let target = 31;
    let lun = 7;
    let mut vst = VirtioScsiTest::general_testcase_run(ScsiDeviceType::ScsiHd, target, lun);

    // Test 1: scsi command: INQUIRY for scsi controller.
    // Traverse all possible targets from 0 to VIRTIO_SCSI_MAX_TARGET(255).
    // Note: stratovirt mst can only has 256 num free, so just traverse from 0 to 31.
    let mut inquiry_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    inquiry_cdb[0] = INQUIRY;
    inquiry_cdb[4] = INQUIRY_DATA_LEN;
    for i in 0..32 {
        // Test 1 Result: Only response 0 for target == 31. Otherwise response VIRTIO_SCSI_S_BAD_TARGET.
        let expect_result = if i == target as u16 {
            VIRTIO_SCSI_S_OK
        } else {
            VIRTIO_SCSI_S_BAD_TARGET
        };
        let cdb_test_args = CdbTest {
            cdb: inquiry_cdb,
            target: i as u8,
            lun: 0,
            data_out: None,
            data_in_length: INQUIRY_DATA_LEN as u32,
            expect_response: expect_result,
            expect_result_data: None,
            expect_sense: None,
        };
        vst.scsi_cdb_test(cdb_test_args);
    }

    // Test 2: scsi command: REPORT_LUNS.
    // Test 2 Result: Check if scsi command REPORT_LUNS was handled successfully.
    // And check the read data is the right lun information (target 31, lun 7).
    let mut report_luns_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    report_luns_cdb[0] = REPORT_LUNS;
    report_luns_cdb[9] = REPORT_LUNS_DATA_LEN;
    let mut expect_result_vec = vec![0_u8; REPORT_LUNS_DATA_LEN as usize];
    // REPORT_LUNS parameter data format.
    // Expect result: Only 1 lun and lun id is 7.
    // Bytes[0..3]: Lun list length (n-7).
    expect_result_vec[3] = 0x8;
    // Bytes[4..7]: Reserved.
    // Bytes[8..15]: Lun[first].
    expect_result_vec[9] = lun as u8;
    // Bytes[n-7..n]: Lun[last].

    let cdb_test_args = CdbTest {
        cdb: report_luns_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: REPORT_LUNS_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 3: scsi command: TESE_UNIT_READY.
    // Test 3 Result: Check if scsi command TESE_UNIT_READY was handled successfully.
    let mut test_unit_ready_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    test_unit_ready_cdb[0] = TEST_UNIT_READY;
    let cdb_test_args = CdbTest {
        cdb: test_unit_ready_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: 0,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 4: scsi command: READ_CAPACITY_10
    // Test 4 Result: Check if scsi command READ_CAPACITY_10 was handled successfully.
    // And the returned capacity is right.
    let mut read_capacity_10_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    read_capacity_10_cdb[0] = READ_CAPACITY_10;
    let cdb_test_args = CdbTest {
        cdb: read_capacity_10_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: READ_CAPACITY_10_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: None,
    };
    let data_in = vst.scsi_cdb_test(cdb_test_args);

    // Bytes[0-3]: Returned Logical Block Address(the logical block address of the last logical block).
    // Bytes[4-7]: Logical Block Length In Bytes.
    // Total size = (last logical block address + 1) * block length.
    assert_eq!(
        (u32::from_be_bytes(data_in.as_ref().unwrap()[0..4].try_into().unwrap()) as u64 + 1)
            * (u32::from_be_bytes(data_in.as_ref().unwrap()[4..8].try_into().unwrap()) as u64),
        TEST_IMAGE_SIZE
    );

    // Test 5: scsi command: MODE_SENSE.
    // Byte2: bits[0-5]: page code. bits[6-7]: page control.
    // Test 5.1 page code = MODE_PAGE_CACHING.
    // Test 5.1 Result: Check if scsi command MODE_SENSE was handled successfully.
    // And the returned mode data is right.
    let mut mode_sense_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    mode_sense_cdb[0] = MODE_SENSE;
    mode_sense_cdb[2] = MODE_PAGE_CACHING;
    mode_sense_cdb[4] = MODE_SENSE_PAGE_CACHE_LEN_DATA_LEN;
    let mut expect_result_vec = vec![0; MODE_SENSE_PAGE_CACHE_LEN_DATA_LEN as usize];
    // MODE_SENSE MODE_PAGE_CACHING(0x8) parameter data format.
    // Bytes[0-1]: Mode Data Length (n-1).
    expect_result_vec[0] = 0x1f;
    // Bytes[2]: Device Specific Parameter.
    // Bytes[3]: Block Descriptor Length.
    expect_result_vec[3] = 0x8;
    // Byte[4]: density code.
    // Bytes[5-7]: number of blocks.
    expect_result_vec[5] = 0x2;
    // Byte[8]: Reserved.
    // Byte[9-11]: Block Length.
    expect_result_vec[10] = 0x2;
    // Bytes[12]: page code.
    expect_result_vec[12] = 0x8;
    // Byte[13]: page length(0x12).
    expect_result_vec[13] = 0x12;
    // Byte[14]: IC/ABPF/CAP/DISC/SIZE/WCE/MF/RCD.
    expect_result_vec[14] = 0x4;
    // Bytes[15-31]: do not support now.

    let cdb_test_args = CdbTest {
        cdb: mode_sense_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: MODE_SENSE_PAGE_CACHE_LEN_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 5.2 page code = MODE_PAGE_ALLS.
    // Test 5.2 Result: Check if scsi command MODE_SENSE was handled successfully.
    // And the returned mode data is right.
    let mut mode_sense_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    mode_sense_cdb[0] = MODE_SENSE;
    mode_sense_cdb[2] = MODE_PAGE_ALLS;
    mode_sense_cdb[4] = MODE_SENSE_PAGE_ALL_DATA_LEN;
    let mut expect_result_vec = vec![0; MODE_SENSE_PAGE_ALL_DATA_LEN as usize];
    // MODE_SENSE MODE_PAGE_ALLS parameter data format.
    // Bytes[0-1]: Mode Data Length (n-1).
    expect_result_vec[0] = MODE_SENSE_PAGE_ALL_DATA_LEN - 1;
    // Bytes[2]: Device Specific Parameter.
    // Bytes[3]: Block Descriptor Length.
    expect_result_vec[3] = 0x8;
    // Byte[4]: density code.
    // Bytes[5-7]: number of blocks.
    expect_result_vec[5] = 0x2;
    // Byte[8]: Reserved.
    // Bytes[9-11]: Block Length.
    expect_result_vec[10] = 0x2;
    // Bytes[12-23]: MODE_PAGE_R_W_ERROR(0x1) parameter data format.
    //   Byte[12]: page code.
    expect_result_vec[12] = 0x1;
    //   Byte[13]: page length(0xa).
    expect_result_vec[13] = 0xa;
    //   Byte[14]: AWRE/ARRE/TB/RC/EER/PER/DTE/DCR
    expect_result_vec[14] = 0x80;
    //   Bytes[15-23]: do not support now.
    // Bytes[24-43]: MODE_PAGE_CACHING(0x8) parameter data format. See test 5.1.
    expect_result_vec[24] = 0x8;
    expect_result_vec[25] = 0x12;
    expect_result_vec[26] = 0x4;
    let cdb_test_args = CdbTest {
        cdb: mode_sense_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: MODE_SENSE_PAGE_ALL_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 6: scsi command: INQUIRY for scsi device.
    // Byte1 bit0: EVPD(enable vital product data).
    // Byte2: page code for vital product data.
    // Test 6.1 EVPD = 0: Inquiry basic information of this scsi device such as vendor
    // and product information.
    // Test 6.1 Result: Check if scsi command INQUIRY was handled successfully. And
    // it has product/vendor information.
    let mut inquiry_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    inquiry_cdb[0] = INQUIRY;
    inquiry_cdb[4] = INQUIRY_DATA_LEN;
    let cdb_test_args = CdbTest {
        cdb: inquiry_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: INQUIRY_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: None,
    };
    let data_in = vst.scsi_cdb_test(cdb_test_args);
    assert!(std::str::from_utf8(&data_in.unwrap())
        .unwrap()
        .contains("STRA"));

    // Test 6.2 EVPD = 1, byte_code = 0x00: Inquiry supported VPD Pages of this scsi device.
    // Test 6.2 Result: Check if scsi command INQUIRY was handled successfully. And the
    // returned supported VPD pages is right.
    let mut inquiry_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    inquiry_cdb[0] = INQUIRY;
    inquiry_cdb[1] = 0x1;
    inquiry_cdb[4] = INQUIRY_SUPPORTED_VPD_PAGES_DATA_LEN;
    let expect_result_vec = vec![0, 0, 0, 0x6, 0, 0x80, 0x83, 0xb0, 0xb1, 0xb2];
    let cdb_test_args = CdbTest {
        cdb: inquiry_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: INQUIRY_SUPPORTED_VPD_PAGES_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 6.3 EVPD = 1, byte_code = 0x80: Inquiry unit serial number.
    // Test 6.3 Result: Check if scsi command INQUIRY was handled successfully. And the
    // returned serial number is DEFAULT_SCSI_SERIAL.
    let mut inquiry_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    inquiry_cdb[0] = INQUIRY;
    inquiry_cdb[1] = 0x1;
    inquiry_cdb[2] = 0x80;
    inquiry_cdb[4] = INQUIRY_UNIT_SERIAL_NUMBER_DATA_LEN;
    let cdb_test_args = CdbTest {
        cdb: inquiry_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: INQUIRY_UNIT_SERIAL_NUMBER_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: None,
    };
    let data_in = vst.scsi_cdb_test(cdb_test_args);
    // Unit Serial Number starts from Byte 4.
    assert!(std::str::from_utf8(&data_in.unwrap()[4..])
        .unwrap()
        .contains(DEFAULT_SCSI_SERIAL));

    // Test 6.4 EVPD = 1, byte_code = 0x83: Inquiry scsi device identification.
    // Test 6.4 Result: Check if scsi command INQUIRY was handled successfully.
    // Note: Stratovirt does not reply anything usefully for scsi device identification now.
    let mut inquiry_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    inquiry_cdb[0] = INQUIRY;
    inquiry_cdb[1] = 0x1;
    inquiry_cdb[2] = 0x83;
    inquiry_cdb[4] = INQUIRY_DEVICE_IDENTIFICATION_DATA_LEN;
    let cdb_test_args = CdbTest {
        cdb: inquiry_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: INQUIRY_DEVICE_IDENTIFICATION_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: None,
    };
    let data_in = vst.scsi_cdb_test(cdb_test_args);
    assert!(data_in.as_ref().unwrap()[1] == 0x83);

    // Test 6.5 EVPD = 1, byte_code = 0xb0: Inquiry scsi block limits.
    // Test 6.5 Result: Check if scsi command INQUIRY was handled successfully.
    // Note: Stratovirt does not reply anything usefully for scsi block limits now.
    let mut inquiry_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    inquiry_cdb[0] = INQUIRY;
    inquiry_cdb[1] = 0x1;
    inquiry_cdb[2] = 0xb0;
    inquiry_cdb[4] = INQUIRY_BLOCK_LIMITS_DATA_LEN;
    let cdb_test_args = CdbTest {
        cdb: inquiry_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: INQUIRY_BLOCK_LIMITS_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: None,
    };
    let data_in = vst.scsi_cdb_test(cdb_test_args);
    assert!(data_in.as_ref().unwrap()[1] == 0xb0);
    assert!(data_in.unwrap()[3] == 64 - 4);

    // Test 6.6 EVPD = 1, byte_code = 0xb1: Inquiry block device characteristics.
    // Test 6.6 Result: Check if scsi command INQUIRY was handled successfully.
    let mut inquiry_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    inquiry_cdb[0] = INQUIRY;
    inquiry_cdb[1] = 0x1;
    inquiry_cdb[2] = 0xb1;
    inquiry_cdb[4] = INQUIRY_BLOCK_DEVICE_CHARACTERISTICS_DATA_LEN;
    // Byte0: bits[0-4]: Scsi device type.
    // Byte1: Page code.
    // Byte2: Reserved.
    // Byte3: page length(length - 4).
    let mut expect_result_vec = vec![0, 0xb1, 0, 0x3c];
    expect_result_vec.resize(INQUIRY_BLOCK_DEVICE_CHARACTERISTICS_DATA_LEN as usize, 0);
    let cdb_test_args = CdbTest {
        cdb: inquiry_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: INQUIRY_BLOCK_DEVICE_CHARACTERISTICS_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 6.7 EVPD = 1, byte_code = 0xb2: Inquiry Logical Block Provisioning.
    // Test 6.7 Result: Check if scsi command INQUIRY was handled successfully.
    let mut inquiry_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    inquiry_cdb[0] = INQUIRY;
    inquiry_cdb[1] = 0x1;
    inquiry_cdb[2] = 0xb2;
    inquiry_cdb[4] = INQUIRY_LOGICAL_BLOCK_PROVISIONING_DATA_LEN;
    // Byte0: bits[0-4]: Scsi device type.
    // Byte1: Page code.
    // Byte2: Reserved.
    // Byte3: page length(length - 4).
    // Byte4: Threshold exponent.
    // Byte5: LBPU(bit 7) / LBPWS / LBPWS10 / LBPRZ / ANC_SUP / DP.
    // Byte6: Threshold percentage / Provisioning Type.
    // Byte7: Threshold percentage.
    let expect_result_vec = vec![0, 0xb2, 0, 0x4, 0, 0x60, 0x1, 0];
    let cdb_test_args = CdbTest {
        cdb: inquiry_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: INQUIRY_LOGICAL_BLOCK_PROVISIONING_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 6.7 EVPD = 1, byte_code = 0xb3: Referrals VPD page.
    // Test 6.7 Result: Check if scsi command INQUIRY was failure.
    let mut inquiry_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    inquiry_cdb[0] = INQUIRY;
    inquiry_cdb[1] = 0x1;
    inquiry_cdb[2] = 0xb3;
    inquiry_cdb[4] = INQUIRY_REFERRALS_DATA_LEN;
    let expect_sense = get_sense_bytes(SCSI_SENSE_INVALID_FIELD);
    let cdb_test_args = CdbTest {
        cdb: inquiry_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: INQUIRY_REFERRALS_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: Some(expect_sense),
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 7: basic io test.
    vst.scsi_try_io(target, lun, ScsiDeviceType::ScsiHd);

    vst.testcase_tear_down();
}

/// Virtio Scsi CD-ROM basic function test. target 0, lun 7.
/// TestStep:
///   0. Init process.
///   1. Get the mode page capabilities.(Using scsi command MODE_SENSE)
///   2. Request if there exist errors.(Using scsi command REQUEST_SENSE)
///   3. Read the table of Content.(Using scsi command READ_TOC)
///   4. Read the disc information.(Using scsi command READ_DISC_INFORMATION)
///   5. Get configuration of the CD/DVD.(Using scsi command GET_CONFIGURATION)
///   6. Test CD/DVD's event status notification(Using scsi command GET_EVENT_STATUS_NOTIFICATION)
///   7. Basic IO test.
///   8. Test ends. Destroy device.
/// Note:
///   1. Do not test TEST_UNIT_READY/REPORT_LUNS/READ_CAPACITY_10 again. See test scsi_hd_basic.
/// Expect:
///   1. 1/2/3/4/5/6/7/8: success.
#[test]
fn scsi_cd_basic_test() {
    let target = 0;
    let lun = 7;
    let mut vst = VirtioScsiTest::general_testcase_run(ScsiDeviceType::ScsiCd, target, lun);

    // Test 1: scsi command: MODE_SENSE.
    // Test 1.1 page code = MODE_PAGE_CAPABILITIES.
    // Test 1.1 Result: Check if scsi command MODE_SENSE was handled successfully.
    // And the returned mode data is right.
    let mut mode_sense_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    mode_sense_cdb[0] = MODE_SENSE;
    mode_sense_cdb[2] = MODE_PAGE_CAPABILITIES;
    mode_sense_cdb[4] = MODE_SENSE_LEN_DATA_LEN;
    let mut expect_result_vec = vec![0; MODE_SENSE_LEN_DATA_LEN as usize];
    // MODE_SENSE MODE_PAGE_ALLS(0x2a) parameter data format.
    // Byte[0]: Mode Data Length (n-1).
    expect_result_vec[0] = MODE_SENSE_LEN_DATA_LEN - 1;
    // Bytes[1-3]: 0.
    // Byte[4]: PS/Reserved/Bits[0-5]: Page Code(0x2A).
    expect_result_vec[4] = 0x2a;
    // Byte[5]: Page Length(28).
    expect_result_vec[5] = 28;
    // Byte[6]: Reserved/Reserved/DVD-RAW Read(1)/DVD-R READ(1)/DVD-ROM READ(1)/
    //          Method 2/CD-RW Read(1)/CD-R Read(1).
    expect_result_vec[6] = 0x3b;
    // Byte[7]: Reserved/Reserved/DVD-RAW WRITE/DVD-R WRITE/Reserved/Test Write/
    //          CD-R/RW Write/CD-R Write.
    // Byte[8]: BUF/Multi Session(1)/Mode 2 Form 2(1)/Mode 2 Form 1(1)/Digital Port 2(1)/
    //          Digital Port 1(1)/Composite(1)/Audio Play(1).
    expect_result_vec[8] = 0x7f;
    // Byte[9]: Read Bar Code(1)/UPC(1)/ISRC(1)/C2 Pointers supported(1)/R-W Deinterleaved & corrected(1)/
    //          R-W supported(1)/CD-DA Stream is Accurate(1)/CD-DA Cmds supported(1).
    expect_result_vec[9] = 0xff;
    // Byte[10]: Bits[5-7]: Loading Mechanism Type(1)/Reserved/Eject(1)/Prevent Jumper(1)/
    //           Lock State/Lock(1).
    expect_result_vec[10] = 0x2d;
    // Byte[11]: Bits[6-7]: Reserved/R-W in Lead-in/Side Change Capable/SSS/Changer Supports Disc Present/
    //           Separate Channel Mute/Separate volume levels
    // Bytes[12-13]: Obsolete.
    // Bytes[14-15]: Number of Volume Levels Supported.
    expect_result_vec[15] = 0x2;
    // Bytes[16-17]: Buffer Size Supported.
    expect_result_vec[16] = 0x8;
    // Bytes[18-25]: Do not support now.
    let cdb_test_args = CdbTest {
        cdb: mode_sense_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: MODE_SENSE_LEN_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 2: scsi command: REQUEST_SENSE.
    // Test 2 Result: Check if scsi command REQUEST_SENSE was handled successfully.
    // And the returned sense is SCSI_SENSE_NO_SENSE.
    let mut request_sense_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    request_sense_cdb[0] = REQUEST_SENSE;
    request_sense_cdb[4] = TEST_SCSI_SENSE_LEN as u8;
    let cdb_test_args = CdbTest {
        cdb: request_sense_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: TEST_SCSI_SENSE_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: Some(get_sense_bytes(SCSI_SENSE_NO_SENSE)),
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 3: scsi command: READ_TOC.
    // Test 3.1:
    // Byte1 bit1: MSF = 0. Byte2 bits[0-3]: Format = 0;
    // Test 3.1 Result: Check if scsi command READ_TOC was handled successfully. And check the read data
    // is the same with the expect result.
    let mut read_toc_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    read_toc_cdb[0] = READ_TOC;
    read_toc_cdb[8] = READ_TOC_DATA_LEN;
    let mut expect_result_vec = vec![0; READ_TOC_DATA_LEN as usize];
    // Bytes[0-1]: TOC Data Length.
    expect_result_vec[1] = 0x12;
    // Byte[2]: First Track Number.
    expect_result_vec[2] = 1;
    // Byte[3]: Last Track Number.
    expect_result_vec[3] = 1;
    // Byte[4]: Reserved.
    // Byte[5]: Bits[5-7]: ADR, Bits[0-4]: CONTROL.
    expect_result_vec[5] = 0x14;
    // Byte[6]: Track Number.
    expect_result_vec[6] = 0x1;
    // Byte[7]: Reserved.
    // Bytes[8-11]: Track Start Address(LBA form = 000000h, MSF form = 00:00:02:00).
    // Byte[12]: Reserved.
    // Byte[13]: Bits[5-7]: ADR, Bits[0-4]: CONTROL.
    expect_result_vec[13] = 0x14;
    // Byte[14]: Track Number.
    expect_result_vec[14] = 0xaa;
    // Byte[15]: Reserved.
    // Bytes[16-19]: Track Start Address.
    expect_result_vec[17] = 2;
    let cdb_test_args = CdbTest {
        cdb: read_toc_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: READ_TOC_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 3.2: scsi command: READ_TOC.
    // Byte1 bit1: MSF = 1.
    // Byte2 bits[0-3]: Format = 0; (Format(Select specific returned data format)(CD: 0,1,2)).
    // Byte6: Track/Session Number.
    // Test 3.2 Result: Check if scsi command READ_TOC was handled successfully. And check the read data
    // is the same with the expect result.
    let mut read_toc_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    read_toc_cdb[0] = READ_TOC;
    read_toc_cdb[1] = 2;
    read_toc_cdb[6] = 0xaa;
    read_toc_cdb[8] = READ_TOC_MSF_DATA_LEN;
    // Bytes[0-1]: TOC Data Length.
    // Byte[2]: First Track Number.
    // Byte[3]: Last Track Number.
    // Byte[4]: Reserved.
    // Byte[5]: Bits[5-7]: ADR, Bits[0-4]: CONTROL.
    // Byte[6]: Track Number.
    // Byte[7]: Reserved.
    // Bytes[8-11]: Track Start Address(LBA form = 000000h, MSF form = 00:00:02:00).
    let expect_result_vec = vec![0, 0xa, 1, 1, 0, 0x14, 0xaa, 0, 0, 0x1d, 9, 0x2f];
    let cdb_test_args = CdbTest {
        cdb: read_toc_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: READ_TOC_MSF_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 3.3: scsi command: READ_TOC.
    // Byte1 bit1: MSF = 0.
    // Byte2 bits[0-3]: Format = 1; (Format(Select specific returned data format)(CD: 0,1,2)).
    // Byte6: Track/Session Number.
    // Test 3.3 Result: Check if scsi command READ_TOC was handled successfully. And check the read data
    // is the same with the expect result.
    let mut read_toc_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    read_toc_cdb[0] = READ_TOC;
    read_toc_cdb[2] = 1;
    read_toc_cdb[8] = READ_TOC_FORMAT_DATA_LEN;
    let expect_result_vec = vec![0, 0xa, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let cdb_test_args = CdbTest {
        cdb: read_toc_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: READ_TOC_FORMAT_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 4: scsi command: READ_DISC_INFORMATION.
    // Test 4 Result: Check if scsi command READ_DISC_INFORMATION was handled successfully. And check the read data
    // is the same with the expect result.
    let mut read_disc_information_cdb: [u8; TEST_VIRTIO_SCSI_CDB_SIZE] =
        [0; TEST_VIRTIO_SCSI_CDB_SIZE];
    read_disc_information_cdb[0] = READ_DISC_INFORMATION;
    read_disc_information_cdb[8] = READ_DISC_INFORMATION_DATA_LEN;
    // Bytes[0-1]: Disc Information Length(32).
    // Byte2: Disc Information Data Type(000b) | Erasable(0) | State of last Session(01b) | Disc Status(11b).
    // Byte3: Number of First Track on Disc.
    // Byte4: Number of Sessions.
    // Byte5: First Track Number in Last Session(Least Significant Byte).
    // Byte6: Last Track Number in Last Session(Last Significant Byte).
    // Byte7: DID_V | DBC_V | URU:Unrestricted Use Disc(1) | DAC_V | Reserved | Legacy | BG Format Status.
    // Byte8: Disc Type(00h: CD-DA or CD-ROM Disc).
    // Byte9: Number of sessions(Most Significant Byte).
    // Byte10: First Trace Number in Last Session(Most Significant Byte).
    // Byte11: Last Trace Number in Last Session(Most Significant Byte).
    // Bytes12-15: Disc Identification.
    // Bytes16-19: Last Session Lead-in Start Address.
    // Bytes20-23: Last Possible Lead-Out Start Address.
    // Bytes24-31: Disc Bar Code.
    // Byte32: Disc Application Code.
    // Byte33: Number of OPC Tables.(0)
    let mut expect_result_vec = vec![0, 0x20, 0xe, 1, 1, 1, 1, 0x20];
    expect_result_vec.resize(READ_DISC_INFORMATION_DATA_LEN as usize, 0);
    let cdb_test_args = CdbTest {
        cdb: read_disc_information_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: READ_DISC_INFORMATION_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 5: scsi command: GET_CONFIGURATION.
    // The size of test img is TEST_IMAGE_SIZE(64M), so it is a CD-ROM.
    // Test 5 Result: Check if scsi command GET_CONFIGURATION was handled successfully. And check the read data
    // is the same with the expect result.
    let mut get_configuration_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    get_configuration_cdb[0] = GET_CONFIGURATION;
    get_configuration_cdb[8] = GET_CONFIGURATION_DATA_LEN;
    let mut expect_result_vec = vec![0; GET_CONFIGURATION_DATA_LEN as usize];
    // Bytes[0-7]: Feature Header.
    // Bytes[0-3]: Data Length(36 = 40 - 4).
    expect_result_vec[3] = GET_CONFIGURATION_DATA_LEN - 4;
    // Bytes[4-5]: Reserved.
    // Bytes[6-7]: Current Profile.
    expect_result_vec[7] = 8;
    // Bytes[8-n]: Feature Descriptor(s):
    // Bytes[8-19]: Feature 0: Profile List Feature:
    // Bytes[8-9]: Feature code(0000h).
    // Byte[10]: Bits[6-7]: Reserved. Bits[2-5]: Version. Bit 1: Persistent. Bit 0: Current(1).
    expect_result_vec[10] = 3;
    // Byte[11]: Additional Length.
    expect_result_vec[11] = 8;
    // Byte[12-19]: Profile Descriptors.(2 descriptors: CD and DVD)
    // Byte[12-13]： Profile Number(CD).
    expect_result_vec[13] = 8;
    // Byte[14]: Bits[1-7]: Reserved. Bit 0: CurrentP.
    expect_result_vec[14] = 1;
    // Byte[15]: Reserved.
    // Byte[16-17]: Profile Number(DVD).
    expect_result_vec[17] = 0x10;
    // Byte[18]: Bits[1-7]: Reserved. Bit 0: CurrentP.
    // Byte[19]: Reserved.
    // Bytes[20-31]: Feature 1: Core Feature:
    // Bytes[20-21]: Feature Code(0001h).
    expect_result_vec[21] = 0x1;
    // Byte[22]: Bits[6-7]: Reserved. Bits[2-5]: Version(0010b). Bit 1: Persistent(1). Bit 0: Current(1).
    expect_result_vec[22] = 0xb;
    // Byte[23]: Additional Length(8).
    expect_result_vec[23] = 8;
    // Bytes[24-27]: Physical Interface Standard. (Scsi Family: 00000001h)
    expect_result_vec[27] = 1;
    // Byte[28]: Bits[2-7]: Reserved. Bit 1: INQ2. Bit 0: DBE(1).
    expect_result_vec[28] = 1;
    // Bytes[29-31]: Reserved.
    // Bytes[32-40]: Feature 2: Removable media feature:
    // Bytes[32-33]: Feature Code(0003h).
    expect_result_vec[33] = 3;
    // Byte[34]: Bits[6-7]: Reserved. Bit[2-5]: Version(0010b). Bit 1: Persistent(1). Bit 0: Current(1).
    expect_result_vec[34] = 0xb;
    // Byte[35]: Additional Length(4).
    expect_result_vec[35] = 4;
    // Byte[36]: Bits[5-7]: Loading Mechanism Type(001b). Bit4: Load(1). Bit 3: Eject(1). Bit 2: Pvnt Jmpr.
    //           Bit 1: DBML. Bit 0: Lock(1).
    expect_result_vec[36] = 0x39;
    // Byte[37-39]: Reserved.
    let cdb_test_args = CdbTest {
        cdb: get_configuration_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: GET_CONFIGURATION_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 6: scsi command: GET_EVENT_STATUS_NOTIFICATION.
    // Test 6 Result: Check if scsi command GET_EVENT_STATUS_NOTIFICATION was handled successfully. And check the read data
    // is the same with the expect result.
    let mut get_event_status_notification_cdb: [u8; TEST_VIRTIO_SCSI_CDB_SIZE] =
        [0; TEST_VIRTIO_SCSI_CDB_SIZE];
    get_event_status_notification_cdb[0] = GET_EVENT_STATUS_NOTIFICATION;
    get_event_status_notification_cdb[1] = 1;
    // Byte[4]: Notification Class Request.
    get_event_status_notification_cdb[4] = 0x10;
    get_event_status_notification_cdb[8] = GET_EVENT_STATUS_NOTIFICATION_DATA_LEN;
    // Bytes[0-3]: Event Header.
    // Bytes[4-n]: Event Descriptor.
    // Bytes[0-1]: Event Descriptor Length.
    // Byte2: Bit7: NEC(No Event Available). Bits[0-2]: Notification Class.
    // NEC = 1: The Drive supports none of the requested notification classes.
    // NEC = 0: At least one of the requested notification classes is supported.
    // Byte3: Supported Event Class.
    // Bytes[4-7]: Media Event Descriptor.
    // Byte4: Bits[4-7]: reserved. Bits[0-3]: Event Code.
    // Byte5: Media Status. Bits[2-7] reserved. Bit 1: Media Present. Bit 0: Door or Tray open.
    // Byte6: Start Slot.
    // Byte7: End Slot.
    let expect_result_vec = vec![0, 6, 4, 0x10, 0, 2, 0, 0];
    let cdb_test_args = CdbTest {
        cdb: get_event_status_notification_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: GET_EVENT_STATUS_NOTIFICATION_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 7: basic io test.
    vst.scsi_try_io(target, lun, ScsiDeviceType::ScsiCd);

    vst.testcase_tear_down();
}

/// Virtio Scsi target cdb test. Test some commands no matter it's right or wrong.
/// Target cdb means that the target has at least one lun but the lun id of cdb will not
/// be found in target's all luns' id.
/// Using command REPORT_LUNS/INQUIRY/REQUEST_SENSE/TEST_UNIT_READY as target cdb are supported.
/// Others are not supported now.
/// TestStep:
///   0. Init process.
///   1. Test scsi command REPORT_LUNS.
///   2. Test scsi command INQUIRY.
///   3. Test scsi command REQUEST_SENSE.
///   4. Test scsi command TESE_UNIT_READY.
///   5. Test other scsi command, e.g. READ_CAPACITY_10.
///   6. Destroy device.
/// Expect:
///   0/1/2/3/4/5/6: success.
#[test]
fn scsi_target_cdb_test() {
    let target = 15;
    let lun = 5;
    let req_lun = 3;
    let mut vst = VirtioScsiTest::general_testcase_run(ScsiDeviceType::ScsiCd, target, lun);

    // Test 1: scsi command: REPORT_LUNS.
    // Test 1 Result: Check if scsi command REPORT_LUNS was handled successfully.
    // And check the read data is the right lun information (target 15, lun 5).
    let mut report_luns_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    report_luns_cdb[0] = REPORT_LUNS;
    report_luns_cdb[9] = REPORT_LUNS_DATA_LEN;
    let expect_result_vec = vec![0, 0, 0, 8, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0];
    let cdb_test_args = CdbTest {
        cdb: report_luns_cdb,
        target,
        lun: req_lun,
        data_out: None,
        data_in_length: REPORT_LUNS_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 2: scsi command: INQUIRY.
    // Test 2.1: request lun id != 0. EVPD = 0. page code = 0.
    // Test 2.1 Result: Check if scsi command INQUIRY was handled successfully.
    // And check the read data is TYPE_NO_LUN.
    let mut inquiry_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    inquiry_cdb[0] = INQUIRY;
    inquiry_cdb[4] = INQUIRY_TARGET_DATA_LEN;
    // Byte[0]: TYPE_NO_LUN(0x7f): Scsi target device is not capable of supporting a peripheral
    // device connected to this logical unit.
    let mut expect_result_vec = vec![0x7f];
    expect_result_vec.resize(INQUIRY_TARGET_DATA_LEN as usize, 0);
    let cdb_test_args = CdbTest {
        cdb: inquiry_cdb,
        target,
        lun: req_lun,
        data_out: None,
        data_in_length: INQUIRY_TARGET_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 2.2: request lun id == 0. EVPD = 0. page code = 0.
    // Test 2.2 Result: Check if scsi command INQUIRY was handled successfully.
    // And check the read data is the right target inquiry information.
    let mut inquiry_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    inquiry_cdb[0] = INQUIRY;
    inquiry_cdb[4] = INQUIRY_TARGET_DATA_LEN;
    let mut expect_result_vec = vec![0; INQUIRY_TARGET_DATA_LEN as usize];
    // Byte0: Peripheral Qualifier/peripheral device type.
    expect_result_vec[0] = 0x3f;
    // Byte1：RMB.
    // Byte2: VERSION.
    expect_result_vec[2] = 0x5;
    // Byte3: NORMACA/HISUP/Response Data Format.
    expect_result_vec[3] = 0x12;
    // Byte4: Additional length(length - 5).
    expect_result_vec[4] = INQUIRY_TARGET_DATA_LEN - 5;
    // Byte5: SCCS/ACC/TPGS/3PC/RESERVED/PROTECT.
    // Byte6: ENCSERV/VS/MULTIP/ADDR16.
    // Byte7: WBUS16/SYNC/CMDQUE/VS.
    expect_result_vec[7] = 0x12;
    let cdb_test_args = CdbTest {
        cdb: inquiry_cdb,
        target,
        lun: 0,
        data_out: None,
        data_in_length: INQUIRY_TARGET_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: Some(expect_result_vec),
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 2.3: request lun id != 0. EVPD = 1. page code = 0.
    // Test 2.3 Result: Check if scsi command INQUIRY was handled successfully.
    // And check the read data is the right target inquiry information.
    let mut inquiry_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    inquiry_cdb[0] = INQUIRY;
    inquiry_cdb[1] = 0x1; // Byte1: bit0: EVPD (Enable Vital product bit).
    inquiry_cdb[4] = INQUIRY_TARGET_DATA_LEN;
    // Byte[3]: Page Length. Supported VPD page list in stratovirt only has 0x00 item.
    let mut expect_result_vec = vec![0, 0, 0, 1];
    expect_result_vec.resize(INQUIRY_TARGET_DATA_LEN as usize, 0);
    let cdb_test_args = CdbTest {
        cdb: inquiry_cdb,
        target,
        lun: req_lun,
        data_out: None,
        data_in_length: INQUIRY_TARGET_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 2.4: request lun id == 0. EVPD = 1. page code = 0x80.
    // Test 2.4 Result: Check if scsi command INQUIRY was handled successfully.
    // And check the sense data is SCSI_SENSE_INVALID_FIELD.
    let mut inquiry_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    inquiry_cdb[0] = INQUIRY;
    inquiry_cdb[1] = 0x1; // Byte1: bit0: EVPD (Enable Vital product bit).
    inquiry_cdb[2] = 0x80;
    inquiry_cdb[4] = INQUIRY_TARGET_DATA_LEN;
    let cdb_test_args = CdbTest {
        cdb: inquiry_cdb,
        target,
        lun: 0,
        data_out: None,
        data_in_length: INQUIRY_TARGET_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: Some(get_sense_bytes(SCSI_SENSE_INVALID_FIELD)),
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 2.5: request lun id != 0. EVPD = 0. page code = 0x80.
    // Test 2.5 Result: Check if scsi command INQUIRY was handled successfully.
    // And check the sense data is SCSI_SENSE_INVALID_FIELD.
    let mut inquiry_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    inquiry_cdb[0] = INQUIRY;
    inquiry_cdb[1] = 0x1; // Byte1: bit0: EVPD (Enable Vital product bit).
    inquiry_cdb[2] = 0x80;
    inquiry_cdb[4] = INQUIRY_TARGET_DATA_LEN;
    let cdb_test_args = CdbTest {
        cdb: inquiry_cdb,
        target,
        lun: req_lun,
        data_out: None,
        data_in_length: INQUIRY_TARGET_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: Some(get_sense_bytes(SCSI_SENSE_INVALID_FIELD)),
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 3: scsi command: REQUEST_SENSE.
    // Test 3.1 req_lun != 0;
    // Test 3.1 Result: Check if scsi command REQUEST_SENSE was handled successfully.
    // And check the sense data is SCSI_SENSE_LUN_NOT_SUPPORTED.
    let mut request_sense_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    request_sense_cdb[0] = REQUEST_SENSE;
    request_sense_cdb[4] = TEST_SCSI_SENSE_LEN as u8;
    let cdb_test_args = CdbTest {
        cdb: request_sense_cdb,
        target,
        lun: req_lun,
        data_out: None,
        data_in_length: TEST_SCSI_SENSE_LEN,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: Some(get_sense_bytes(SCSI_SENSE_LUN_NOT_SUPPORTED)),
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 3.2 req_lun == 0;
    // Just return.
    // Test 3.1 Result: Check if scsi command REQUEST_SENSE was handled successfully.
    let mut request_sense_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    request_sense_cdb[0] = REQUEST_SENSE;
    request_sense_cdb[4] = TEST_SCSI_SENSE_LEN as u8;
    let cdb_test_args = CdbTest {
        cdb: request_sense_cdb,
        target,
        lun: 0,
        data_out: None,
        data_in_length: TEST_SCSI_SENSE_LEN,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 4: scsi command: TESE_UNIT_READY.
    // Test 4 Result: Check if scsi command TESE_UNIT_READY was handled successfully.
    let mut test_unit_ready_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    test_unit_ready_cdb[0] = TEST_UNIT_READY;
    let cdb_test_args = CdbTest {
        cdb: test_unit_ready_cdb,
        target,
        lun: req_lun,
        data_out: None,
        data_in_length: 0,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: None,
    };
    vst.scsi_cdb_test(cdb_test_args);

    // TEST 5: other scsi command, eg: READ_CAPACITY_10.
    // Test 4 Result: Check if scsi command READ_CAPACITY_10 was handled successfully.
    // And check the sense data is SCSI_SENSE_INVALID_OPCODE.
    let mut read_capacity_10_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    read_capacity_10_cdb[0] = READ_CAPACITY_10;
    let cdb_test_args = CdbTest {
        cdb: read_capacity_10_cdb,
        target,
        lun: req_lun,
        data_out: None,
        data_in_length: READ_CAPACITY_10_DATA_LEN as u32,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: Some(get_sense_bytes(SCSI_SENSE_INVALID_OPCODE)),
    };
    vst.scsi_cdb_test(cdb_test_args);

    vst.testcase_tear_down();
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioScsiConfig {
    num_queues: u32,
    seg_max: u32,
    max_sectors: u32,
    cmd_per_lun: u32,
    event_info_size: u32,
    sense_size: u32,
    cdb_size: u32,
    max_channel: u16,
    max_target: u16,
    max_lun: u32,
}

/// Virtio Scsi pci device config Test.
/// Virtio spec requires that only cdb_size and sense size in virtio scsi pci device config
/// can be set from guest.
/// TestStep:
///   1. Init process.
///   2. For every parameter in VirtioScsiConfig, do check just like:
///      Read default value -> Set other value -> Read value again -> Check if value was setted successfully.
///   3. Destroy device.
/// Note:
///   1. sense size and cdb size can not be changed in stratovirt now. So, they are 0 now.
/// Expect:
///   1/2/3: success.
///   2: only sense_size and cdb_size are setted successfully.
#[test]
fn device_config_test() {
    let target = 0x0;
    let lun = 0x0;
    let mut vst = VirtioScsiTest::general_testcase_run(ScsiDeviceType::ScsiHd, target, lun);

    let mut num_queues = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, num_queues) as u64);
    assert_eq!(num_queues, 1);
    vst.cntlr
        .borrow()
        .config_writel(offset_of!(VirtioScsiConfig, num_queues) as u64, 5);
    num_queues = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, num_queues) as u64);
    assert_eq!(num_queues, 1);

    let mut seg_max = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, seg_max) as u64);
    assert_eq!(seg_max, 254);
    vst.cntlr
        .borrow()
        .config_writel(offset_of!(VirtioScsiConfig, seg_max) as u64, 126);
    seg_max = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, seg_max) as u64);
    assert_eq!(seg_max, 254);

    let mut max_sectors = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, max_sectors) as u64);
    assert_eq!(max_sectors, 0xFFFF_u32);
    vst.cntlr
        .borrow()
        .config_writel(offset_of!(VirtioScsiConfig, max_sectors) as u64, 0xFF_u32);
    max_sectors = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, max_sectors) as u64);
    assert_eq!(max_sectors, 0xFFFF_u32);

    let mut cmd_per_lun = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, cmd_per_lun) as u64);
    assert_eq!(cmd_per_lun, 128);
    vst.cntlr
        .borrow()
        .config_writel(offset_of!(VirtioScsiConfig, cmd_per_lun) as u64, 256);
    cmd_per_lun = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, cmd_per_lun) as u64);
    assert_eq!(cmd_per_lun, 128);

    let mut event_info_size = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, event_info_size) as u64);
    assert_eq!(event_info_size, 0);
    vst.cntlr
        .borrow()
        .config_writel(offset_of!(VirtioScsiConfig, event_info_size) as u64, 32);
    event_info_size = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, event_info_size) as u64);
    assert_eq!(event_info_size, 0);

    let mut sense_size = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, sense_size) as u64);
    assert_eq!(sense_size, 0);
    vst.cntlr.borrow().config_writel(
        offset_of!(VirtioScsiConfig, sense_size) as u64,
        TEST_VIRTIO_SCSI_SENSE_SIZE as u32 + 2,
    );
    sense_size = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, sense_size) as u64);
    assert_eq!(sense_size, 0);
    vst.cntlr.borrow().config_writel(
        offset_of!(VirtioScsiConfig, sense_size) as u64,
        TEST_VIRTIO_SCSI_SENSE_SIZE as u32,
    );
    sense_size = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, sense_size) as u64);
    assert_eq!(sense_size, 0);

    let mut cdb_size = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, cdb_size) as u64);
    assert_eq!(cdb_size, 0);
    vst.cntlr.borrow().config_writel(
        offset_of!(VirtioScsiConfig, cdb_size) as u64,
        TEST_VIRTIO_SCSI_CDB_SIZE as u32 + 3,
    );
    cdb_size = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, cdb_size) as u64);
    assert_eq!(cdb_size, 0);
    vst.cntlr.borrow().config_writel(
        offset_of!(VirtioScsiConfig, cdb_size) as u64,
        TEST_VIRTIO_SCSI_CDB_SIZE as u32,
    );
    cdb_size = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, cdb_size) as u64);
    assert_eq!(cdb_size, 0);

    let mut max_channel = vst
        .cntlr
        .borrow()
        .config_readw(offset_of!(VirtioScsiConfig, max_channel) as u64);
    assert_eq!(max_channel, 0);
    vst.cntlr
        .borrow()
        .config_writew(offset_of!(VirtioScsiConfig, max_channel) as u64, 126);
    max_channel = vst
        .cntlr
        .borrow()
        .config_readw(offset_of!(VirtioScsiConfig, max_channel) as u64);
    assert_eq!(max_channel, 0);

    let mut max_target = vst
        .cntlr
        .borrow()
        .config_readw(offset_of!(VirtioScsiConfig, max_target) as u64);
    assert_eq!(max_target, TEST_VIRTIO_SCSI_MAX_TARGET);
    vst.cntlr
        .borrow()
        .config_writew(offset_of!(VirtioScsiConfig, max_target) as u64, 126);
    max_target = vst
        .cntlr
        .borrow()
        .config_readw(offset_of!(VirtioScsiConfig, max_target) as u64);
    assert_eq!(max_target, TEST_VIRTIO_SCSI_MAX_TARGET);

    let mut max_lun = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, max_lun) as u64);
    assert_eq!(max_lun, TEST_VIRTIO_SCSI_MAX_LUN);
    vst.cntlr
        .borrow()
        .config_writel(offset_of!(VirtioScsiConfig, max_lun) as u64, 1024);
    max_lun = vst
        .cntlr
        .borrow()
        .config_readl(offset_of!(VirtioScsiConfig, max_lun) as u64);
    assert_eq!(max_lun, TEST_VIRTIO_SCSI_MAX_LUN);

    vst.testcase_tear_down();
}

/// Virtio Scsi I/O processing in iothread test.
/// TestStep:
///   1. Config iothread in scsi controller with a scsi harddisk. Init process.
///   2. Write Data / Read Data.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
///   2: The data read out from the disk is exactly the data written down.
#[test]
fn iothread_test() {
    let target = 0x1;
    let lun = 0x2;
    let mut vst = VirtioScsiTest::general_testcase_run(ScsiDeviceType::ScsiHd, target, lun);

    // Test: basic io test.
    vst.scsi_try_io(target, lun, ScsiDeviceType::ScsiHd);

    vst.testcase_tear_down();
}

/// Virtio Scsi I/O processing in different AIO model.
/// TestStep:
///   1. Config different AIO model in scsi disk. Init process.
///   2. Write Data / Read Data.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
///   2: The data read out from the disk is exactly the data written down.
#[test]
fn aio_model_test() {
    let cntlrcfg = CntlrConfig {
        id: 0,
        use_iothread: false,
    };
    let target = 0x1;
    let mut lun = 0x2;
    let mut device_vec: Vec<ScsiDeviceConfig> = Vec::new();

    if aio_probe(AioEngine::IoUring).is_ok() {
        // Scsi Disk 1. AIO io_uring. Direct false.
        let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 0));
        device_vec.push(ScsiDeviceConfig {
            cntlr_id: 0,
            device_type: ScsiDeviceType::ScsiHd,
            image_path: image_path.clone(),
            target: target,
            lun: lun,
            read_only: false,
            direct: false,
            aio: TestAioType::AioIOUring,
            serial: None,
        });

        // Scsi Disk 2. AIO io_uring. Direct true.
        lun += 1;
        let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 1));
        device_vec.push(ScsiDeviceConfig {
            cntlr_id: 0,
            device_type: ScsiDeviceType::ScsiHd,
            image_path: image_path.clone(),
            target: target,
            lun: lun,
            read_only: false,
            direct: true,
            aio: TestAioType::AioIOUring,
            serial: None,
        });
    }

    // Scsi Disk 3. AIO OFF. Direct true. This is not allowed.
    // Stratovirt will report "low performance expect when use sync io with direct on"

    //Scsi Disk 4. AIO OFF. Direct false.
    lun += 1;
    let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 0));
    device_vec.push(ScsiDeviceConfig {
        cntlr_id: 0,
        device_type: ScsiDeviceType::ScsiHd,
        image_path: image_path.clone(),
        target: target,
        lun: lun,
        read_only: false,
        direct: false,
        aio: TestAioType::AioOff,
        serial: None,
    });
    // Scsi Disk 5. AIO native. Direct false. This is not allowed.
    // Stratovirt will report "native aio type should be used with direct on"

    if aio_probe(AioEngine::Native).is_ok() {
        // Scsi Disk 6. AIO native. Direct true.
        lun += 1;
        let image_path = Rc::new(create_img(TEST_IMAGE_SIZE, 1));
        device_vec.push(ScsiDeviceConfig {
            cntlr_id: 0,
            device_type: ScsiDeviceType::ScsiHd,
            image_path: image_path.clone(),
            target: target,
            lun: lun,
            read_only: false,
            direct: true,
            aio: TestAioType::AioNative,
            serial: None,
        });
    }

    let (cntlr, state, alloc) = scsi_test_init(cntlrcfg, device_vec.clone());
    let features = virtio_scsi_defalut_feature(cntlr.clone());
    let queues = cntlr
        .borrow_mut()
        .init_device(state.clone(), alloc.clone(), features, 3);

    let mut vst = VirtioScsiTest {
        cntlr,
        scsi_devices: device_vec,
        state,
        alloc,
        queues,
    };

    for device in vst.scsi_devices.clone().iter() {
        // Test: basic io test.
        vst.scsi_try_io(device.target, device.lun, ScsiDeviceType::ScsiHd);
    }

    vst.testcase_tear_down();
}

/// Virtio Scsi random CDB test.
/// TestStep:
///   1. Init process.
///   2. Generate random u8 vector as CDB and send.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
///   2: Stratovirt will not crash.
#[test]
fn random_cdb_test() {
    let target = 0xff;
    let lun = 0xff;
    let mut vst = VirtioScsiTest::general_testcase_run(ScsiDeviceType::ScsiHd, target, lun);

    // Test: Generate random u8 array as cdb.
    let mut randcdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    let mut rng = rand::thread_rng();
    for i in 0..TEST_VIRTIO_SCSI_CDB_SIZE {
        randcdb[i] = rng.gen();
    }

    let scsi_req = TestVirtioScsiCmdReq::new(target, lun, randcdb);
    let mut scsi_resp = TestVirtioScsiCmdResp::default();
    let mut data_in = Vec::<u8>::with_capacity(512);
    vst.virtio_scsi_do_command(scsi_req, &None, &mut scsi_resp, &mut data_in, 0);

    // Test: the scsi device works normally.
    vst.scsi_try_io(target, lun, ScsiDeviceType::ScsiHd);

    vst.testcase_tear_down();
}

/// Virtio Scsi wrong size virtioscsirequest test.
/// TestStep:
///   1. Config virtio scsi controller with a scsi harddisk. Init process.
///   2. Send virtioscsirequest which is less than expect length.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
///   2: Report VIRTIO ERROR. Stratovirt will not crash.
#[test]
fn wrong_virtioscsirequest_test() {
    let target = 0xff;
    let lun = 0xff;
    let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(DEFAULT_SCSI_DESC_ELEM);
    let mut vst = VirtioScsiTest::general_testcase_run(ScsiDeviceType::ScsiHd, target, lun);

    // Error request.
    let error_req_size = size_of::<TestVirtioScsiCmdReq>() as u64 - 1;
    let req = vec![1; error_req_size as usize];
    let req_addr = vst
        .alloc
        .borrow_mut()
        .alloc(error_req_size.try_into().unwrap());
    vst.state.borrow().memwrite(req_addr, &req);

    data_entries.push(TestVringDescEntry {
        data: req_addr,
        len: error_req_size as u32,
        write: false,
    });

    // Response.
    let cmdresp_len = size_of::<TestVirtioScsiCmdResp>() as u64;
    let resp = TestVirtioScsiCmdResp::default();
    let resp_addr = vst
        .alloc
        .borrow_mut()
        .alloc(cmdresp_len.try_into().unwrap());
    let resp_bytes = resp.as_bytes();
    vst.state.borrow().memwrite(resp_addr, resp_bytes);

    data_entries.push(TestVringDescEntry {
        data: resp_addr,
        len: cmdresp_len as u32,
        write: false,
    });

    vst.queues[2]
        .borrow_mut()
        .add_chained(vst.state.clone(), data_entries);

    vst.cntlr
        .borrow()
        .kick_virtqueue(vst.state.clone(), vst.queues[2].clone());

    thread::sleep(time::Duration::from_secs(1));
    assert!(vst.cntlr.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET != 0);

    vst.testcase_tear_down();
}

/// Virtio Scsi wrong size virtioscsiresponse test.
/// TestStep:
///   1. Config virtio scsi controller with a scsi harddisk. Init process.
///   2. Send virtioscsiresponse which is less than expect length.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
///   2: Report VIRTIO ERROR. Stratovirt will not crash.
#[test]
fn wrong_size_virtioscsiresponse_test() {
    let target = 0xff;
    let lun = 0xff;
    let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(DEFAULT_SCSI_DESC_ELEM);
    let mut vst = VirtioScsiTest::general_testcase_run(ScsiDeviceType::ScsiHd, target, lun);

    // Request Header.
    let req_len = size_of::<TestVirtioScsiCmdReq>() as u64;
    let req = vec![1; req_len as usize];
    let req_addr = vst.alloc.borrow_mut().alloc(req_len.try_into().unwrap());
    vst.state.borrow().memwrite(req_addr, &req);
    data_entries.push(TestVringDescEntry {
        data: req_addr,
        len: req_len as u32,
        write: false,
    });

    // Response.
    let err_resp_len = size_of::<TestVirtioScsiCmdResp>() as u64 - 1;
    let resp = vec![1; err_resp_len as usize];
    let resp_addr = vst
        .alloc
        .borrow_mut()
        .alloc(err_resp_len.try_into().unwrap());
    vst.state.borrow().memwrite(resp_addr, &resp);
    data_entries.push(TestVringDescEntry {
        data: resp_addr,
        len: err_resp_len as u32,
        write: true,
    });

    vst.queues[2]
        .borrow_mut()
        .add_chained(vst.state.clone(), data_entries);
    vst.cntlr
        .borrow()
        .kick_virtqueue(vst.state.clone(), vst.queues[2].clone());

    thread::sleep(time::Duration::from_secs(1));
    assert!(vst.cntlr.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET != 0);

    vst.testcase_tear_down();
}

/// Virtio Scsi missing virtioscsirequest test.
/// TestStep:
///   1. Config virtio scsi controller with a scsi harddisk. Init process.
///   2. Do not send virtioscsirequest in virtqueue.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
///   2: Report VIRTIO ERROR. Stratovirt will not crash.
#[test]
fn missing_virtioscsirequest_test() {
    let target = 0xff;
    let lun = 0xff;
    let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(DEFAULT_SCSI_DESC_ELEM);
    let mut vst = VirtioScsiTest::general_testcase_run(ScsiDeviceType::ScsiHd, target, lun);

    // Response.
    let resp_len = size_of::<TestVirtioScsiCmdResp>() as u64;
    let resp = vec![1; resp_len as usize];
    let resp_addr = vst.alloc.borrow_mut().alloc(resp_len.try_into().unwrap());
    vst.state.borrow().memwrite(resp_addr, &resp);

    data_entries.push(TestVringDescEntry {
        data: resp_addr,
        len: resp_len as u32,
        write: true,
    });

    vst.queues[2]
        .borrow_mut()
        .add_chained(vst.state.clone(), data_entries);
    vst.cntlr
        .borrow()
        .kick_virtqueue(vst.state.clone(), vst.queues[2].clone());

    thread::sleep(time::Duration::from_secs(1));
    assert!(vst.cntlr.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET != 0);

    vst.testcase_tear_down();
}

/// Virtio Scsi missing virtioscsiresponse test.
/// TestStep:
///   1. Config virtio scsi controller with a scsi harddisk. Init process.
///   2. Do not send virtioscsiresponse in virtqueue.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
///   2: Report VIRTIO ERROR. Stratovirt will not crash.
#[test]
fn missing_virtioscsiresponse_test() {
    let target = 0xff;
    let lun = 0xff;
    let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(DEFAULT_SCSI_DESC_ELEM);
    let mut vst = VirtioScsiTest::general_testcase_run(ScsiDeviceType::ScsiHd, target, lun);

    // Request Header.
    let req_len = size_of::<TestVirtioScsiCmdReq>() as u64;
    let req = vec![1; req_len as usize];
    let req_addr = vst.alloc.borrow_mut().alloc(req_len.try_into().unwrap());
    vst.state.borrow().memwrite(req_addr, &req);

    data_entries.push(TestVringDescEntry {
        data: req_addr,
        len: req_len as u32,
        write: false,
    });

    vst.queues[2]
        .borrow_mut()
        .add_chained(vst.state.clone(), data_entries);
    vst.cntlr
        .borrow()
        .kick_virtqueue(vst.state.clone(), vst.queues[2].clone());

    thread::sleep(time::Duration::from_secs(1));
    assert!(vst.cntlr.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET != 0);

    vst.testcase_tear_down();
}

/// Virtio Scsi wrong lun in virtioscsiresponse test.
/// #[repr(C, packed)]
/// struct TestVirtioScsiCmdReq {
///     lun: [u8; 8],
///     tag: u64,
///     task_attr: u8,
///     prio: u8,
///     crn: u8,
///     cdb: [u8; TEST_VIRTIO_SCSI_CDB_SIZE],
/// }
/// TestStep:
///   1. Config virtio scsi controller with a scsi harddisk. Init process.
///   2. Send virtioscsirequest which has wrong lun parameter.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
///   2: Return no such target/lun. Stratovirt will not crash.
#[test]
fn wrong_lun_in_virtioscsirequest_test() {
    let target = 0xff;
    let lun = 0xff;
    let mut vst = VirtioScsiTest::general_testcase_run(ScsiDeviceType::ScsiHd, target, lun);

    let mut test_unit_ready_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    test_unit_ready_cdb[0] = TEST_UNIT_READY;
    let err_lun_scsi_req = TestVirtioScsiCmdReq {
        lun: [0; 8], // Error lun.
        tag: 0,
        task_attr: 0,
        prio: 0,
        crn: 0,
        cdb: test_unit_ready_cdb,
    };
    let mut scsi_resp = TestVirtioScsiCmdResp::default();
    vst.virtio_scsi_do_command(err_lun_scsi_req, &None, &mut scsi_resp, &mut Vec::new(), 0);

    assert!(scsi_resp.response == VIRTIO_SCSI_S_BAD_TARGET);

    vst.testcase_tear_down();
}

/// Send scsi-cd command to scsi-hd.
/// TestStep:
///   1. Config virtio scsi controller with a scsi harddisk. Init process.
///   2. Send scsi command which is used for scsi CD-ROM.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
///   2: Return not supported. Stratovirt will not crash.
#[test]
fn send_cd_command_to_hd_test() {
    let target = 3;
    let lun = 0;
    let mut vst = VirtioScsiTest::general_testcase_run(ScsiDeviceType::ScsiHd, target, lun);

    // Test 1: Scsi Command: MODE_SENSE
    let mut mode_sense_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    mode_sense_cdb[0] = MODE_SENSE;
    mode_sense_cdb[2] = MODE_PAGE_CAPABILITIES;
    mode_sense_cdb[4] = MODE_SENSE_LEN_DATA_LEN;

    let cdb_test_args = CdbTest {
        cdb: mode_sense_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: 0,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: Some(get_sense_bytes(SCSI_SENSE_INVALID_FIELD)),
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 2: scsi command: READ_DISC_INFORMATION.
    // Test 2 Result: Check if scsi command READ_DISC_INFORMATION was failure.
    let mut read_disc_information_cdb: [u8; TEST_VIRTIO_SCSI_CDB_SIZE] =
        [0; TEST_VIRTIO_SCSI_CDB_SIZE];
    read_disc_information_cdb[0] = READ_DISC_INFORMATION;
    read_disc_information_cdb[8] = READ_DISC_INFORMATION_DATA_LEN;
    let cdb_test_args = CdbTest {
        cdb: read_disc_information_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: 0,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: Some(get_sense_bytes(SCSI_SENSE_INVALID_FIELD)),
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 3: scsi command: GET_CONFIGURATION.
    // Test 3 Result: Check if scsi command GET_CONFIGURATION was failure.
    let mut get_configuration_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    get_configuration_cdb[0] = GET_CONFIGURATION;
    get_configuration_cdb[8] = GET_CONFIGURATION_DATA_LEN;
    let cdb_test_args = CdbTest {
        cdb: get_configuration_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: 0,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: Some(get_sense_bytes(SCSI_SENSE_INVALID_FIELD)),
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test 4: scsi command: GET_EVENT_STATUS_NOTIFICATION.
    // Test 4 Result: Check if scsi command GET_EVENT_STATUS_NOTIFICATION was failure.
    let mut get_event_status_notification_cdb: [u8; TEST_VIRTIO_SCSI_CDB_SIZE] =
        [0; TEST_VIRTIO_SCSI_CDB_SIZE];
    get_event_status_notification_cdb[0] = GET_EVENT_STATUS_NOTIFICATION;
    get_event_status_notification_cdb[1] = 1;
    get_event_status_notification_cdb[4] = 0x10;
    get_event_status_notification_cdb[8] = GET_EVENT_STATUS_NOTIFICATION_DATA_LEN;

    let cdb_test_args = CdbTest {
        cdb: get_configuration_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: 0,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: Some(get_sense_bytes(SCSI_SENSE_INVALID_FIELD)),
    };
    vst.scsi_cdb_test(cdb_test_args);

    vst.testcase_tear_down();
}

/// Virtio Scsi Wrong io request test.
/// TestStep:
///   1. Init process.
///   2. Send READ_10/WRITE_10 CDB.
///     2.1 READ_10/WRITE_10 transfer length is larger than disk size.
///     2.2 READ_10/WRITE_10 read/write offset is larget than disk size.
///   3. Wait for return value.
///   4. Destroy device.
/// Expect:
///   1/2/3/4: success.
///   2: Stratovirt will not crash.
///   3. Return error.
#[test]
fn wrong_io_test() {
    let target = 0xff;
    let lun = 0xff;
    let size = 1 * 1024; // Disk size: 1K.

    let mut vst =
        VirtioScsiTest::testcase_start_with_config(ScsiDeviceType::ScsiHd, target, lun, size, true);

    // Test1: scsi command: WRITE_10.
    // Write to LBA(logical block address) 0, transfer length 2KB and disk is 1KB size.
    // Test Result: Check if scsi command WRITE_10 was failure.
    let mut write_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    write_cdb[0] = WRITE_10;
    write_cdb[8] = (2048 / 512) as u8; // 2KB data.
    let data = vec![0x5; 2048]; // 2KB data.
    let write_data = String::from_utf8(data).unwrap();
    let cdb_test_args = CdbTest {
        cdb: write_cdb,
        target,
        lun,
        data_out: Some(write_data),
        data_in_length: 0,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: Some(get_sense_bytes(SCSI_SENSE_INVALID_OPCODE)),
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test2: scsi command: READ_10.
    // Read from LBA(logical block address) 0, transfer length 2KB and disk is 1KB size.
    // Test Result: Check if scsi command READ_10 was failure.
    let mut read_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    read_cdb[0] = READ_10;
    read_cdb[8] = (2048 / 512) as u8; // 2KB data.
    let cdb_test_args = CdbTest {
        cdb: read_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: 2048, // Read 2K data.
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: Some(get_sense_bytes(SCSI_SENSE_INVALID_OPCODE)),
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test3: scsi command: WRITE_10.
    // Write to LBA(logical block address) 2K, transfer length 1 secotr and disk is 1KB size.
    // Test Result: Check if scsi command WRITE_10 was failure.
    let mut write_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    write_cdb[0] = WRITE_10;
    write_cdb[5] = ((2 * 1024) & 0xff) as u8;
    write_cdb[4] = ((2 * 1024) >> 8 & 0xff) as u8;
    write_cdb[8] = 1; // 1 sector data.
    let data = vec![0x5; 512]; // 1 sector data.
    let write_data = String::from_utf8(data).unwrap();
    let cdb_test_args = CdbTest {
        cdb: write_cdb,
        target,
        lun,
        data_out: Some(write_data),
        data_in_length: 0,
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: Some(get_sense_bytes(SCSI_SENSE_INVALID_OPCODE)),
    };
    vst.scsi_cdb_test(cdb_test_args);

    // Test4: scsi command: READ_10.
    // Read from LBA(logical block address) 2K, transfer length 1 sector and disk is 1KB size.
    // Test Result: Check if scsi command READ_10 was failure.
    let mut read_cdb = [0_u8; TEST_VIRTIO_SCSI_CDB_SIZE];
    read_cdb[0] = READ_10;
    read_cdb[5] = ((2 * 1024) & 0xff) as u8;
    read_cdb[4] = ((2 * 1024) >> 8 & 0xff) as u8;
    read_cdb[8] = 1; // 1 sector data.
    let cdb_test_args = CdbTest {
        cdb: read_cdb,
        target,
        lun,
        data_out: None,
        data_in_length: 512, // 1 sector data.
        expect_response: VIRTIO_SCSI_S_OK,
        expect_result_data: None,
        expect_sense: Some(get_sense_bytes(SCSI_SENSE_INVALID_OPCODE)),
    };
    vst.scsi_cdb_test(cdb_test_args);

    vst.testcase_tear_down();
}
