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

use std::{
    cell::RefCell, env, mem::size_of, path::Path, process::Command, rc::Rc, slice::from_raw_parts,
};

use mod_test::libdriver::{
    machine::TestStdMachine,
    malloc::GuestAllocator,
    virtio::{
        TestVirtQueue, TestVringDescEntry, VirtioDeviceOps, VIRTIO_F_BAD_FEATURE,
        VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
    },
    virtio_pci_modern::TestVirtioPciDev,
    virtiofs::*,
};
use mod_test::libtest::{test_init, TestState, MACHINE_TYPE_ARG};
use mod_test::utils::get_rand_str;
use util::byte_code::ByteCode;
use util::offset_of;

const DEFAULT_FS_DESC_ELEM: usize = 4; // 4 elems: inheader/inbody/outheader/outbody.
const TIMEOUT_US: u64 = 10 * 1000 * 1000; // 10s timeout.
const PARENT_NODEID: u64 = 1; // parent dir nodeid.
const TEST_MEM_SIZE: u64 = 1024; // 1G mem size.
const TEST_PAGE_SIZE: u64 = 4096; // 4k page size.
const TEST_FILE_NAME: &str = "testfile";
const TEST_CHARDEV_NAME: &str = "testchar";
const DEFAULT_READ_SIZE: usize = 1024; // 1024 Bytes.
const DEFAULT_XATTR_SIZE: u32 = 1024; // 1024 Bytes.
const MAX_TAG_LENGTH: usize = 36; // Tag buffer's max length in pci device config.

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct VirtioFsConfig {
    tag: [u8; MAX_TAG_LENGTH],
    num_request_queues: u32,
}

struct VirtioFsTest {
    device: Rc<RefCell<TestVirtioPciDev>>,
    state: Rc<RefCell<TestState>>,
    allocator: Rc<RefCell<GuestAllocator>>,
    queues: Vec<Rc<RefCell<TestVirtQueue>>>,
}

fn env_prepare(temp: bool) -> (String, String, String) {
    let rng_name: String = get_rand_str(8);

    let dir = if temp { "/tmp" } else { "/var" };
    let virtiofs_test_dir = format!("{}/mst-virtiofs-{}", dir, rng_name);
    let virtiofs_shared_dir = format!("{}/{}", virtiofs_test_dir, "shared");
    let virtiofs_test_file = format!("{}/{}", virtiofs_shared_dir, TEST_FILE_NAME);
    let virtiofs_test_character_device = format!("{}/{}", virtiofs_shared_dir, TEST_CHARDEV_NAME);

    Command::new("mkdir")
        .arg("-p")
        .arg(virtiofs_shared_dir.clone())
        .output()
        .unwrap();

    Command::new("touch")
        .arg(virtiofs_test_file.clone())
        .output()
        .unwrap();

    Command::new("mknod")
        .arg(virtiofs_test_character_device.clone())
        .arg("c")
        .arg("1")
        .arg("1")
        .output()
        .unwrap();

    let output = Command::new("dd")
        .arg("if=/dev/zero")
        .arg(format!("of={}", virtiofs_test_file))
        .arg("bs=1M")
        .arg("count=10")
        .output()
        .unwrap();
    assert!(output.status.success());

    (virtiofs_test_dir, virtiofs_shared_dir, virtiofs_test_file)
}

fn env_clean(test_dir: String) {
    Command::new("rm").arg("-rf").arg(test_dir).spawn().unwrap();
}

fn virtio_fs_default_feature(dev: Rc<RefCell<TestVirtioPciDev>>) -> u64 {
    let mut features = dev.borrow().get_device_features();
    features &=
        !(VIRTIO_F_BAD_FEATURE | 1 << VIRTIO_RING_F_INDIRECT_DESC | 1 << VIRTIO_RING_F_EVENT_IDX);

    features
}

impl VirtioFsTest {
    fn new(memsize: u64, page_size: u64, virtiofs_sock: String) -> Self {
        let tag = "myfs";
        let pci_slot: u8 = 0x4;
        let pci_fn: u8 = 0x0;

        let mut args = format!("-D {},mem-share=on", MACHINE_TYPE_ARG);

        let mem_args = format!(" -m {}", memsize);
        args.push_str(&mem_args);
        let chardev_args = format!(
            " -chardev socket,id=virtio_fs,path={},server,nowait",
            virtiofs_sock
        );
        args.push_str(&chardev_args);
        let virtiofs_pci_args = format!(
            " -device vhost-user-fs-pci,id=device_id,chardev=virtio_fs,tag={},bus=pcie.0,addr=0x4",
            tag,
        );
        args.push_str(&virtiofs_pci_args);

        let args_vec: Vec<&str> = args.trim().split(' ').collect();
        let test_state = Rc::new(RefCell::new(test_init(args_vec)));
        let machine =
            TestStdMachine::new_bymem(test_state.clone(), memsize * 1024 * 1024, page_size);
        let allocator = machine.allocator.clone();
        let dev = Rc::new(RefCell::new(TestVirtioPciDev::new(machine.pci_bus.clone())));
        dev.borrow_mut().init(pci_slot, pci_fn);
        let features = virtio_fs_default_feature(dev.clone());
        let queues =
            dev.borrow_mut()
                .init_device(test_state.clone(), allocator.clone(), features, 2);

        VirtioFsTest {
            device: dev,
            state: test_state,
            allocator,
            queues,
        }
    }

    fn handle_request_member(
        &self,
        reqmember: Option<&[u8]>,
        data_entries: &mut Vec<TestVringDescEntry>,
        is_write: bool,
    ) -> Option<u64> {
        if let Some(member) = reqmember {
            let member_size = member.len() as u64;
            let member_addr = self.allocator.borrow_mut().alloc(member_size);
            self.state.borrow().memwrite(member_addr, &member);
            data_entries.push(TestVringDescEntry {
                data: member_addr,
                len: member_size as u32,
                write: is_write,
            });

            return Some(member_addr);
        }

        None
    }

    fn do_virtio_request(
        &self,
        fuseinheader: Option<&[u8]>,
        fuseinbody: Option<&[u8]>,
        fuseoutheader: Option<&[u8]>,
        fuseoutbody: Option<&[u8]>,
    ) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
        let mut data_entries: Vec<TestVringDescEntry> = Vec::with_capacity(DEFAULT_FS_DESC_ELEM);

        // FuseInHeader.
        let fuseinheader_addr = self.handle_request_member(fuseinheader, &mut data_entries, false);
        // FuseInBody.
        let fuseinbody_addr = self.handle_request_member(fuseinbody, &mut data_entries, false);
        // FuseOutHeader.
        let fuseoutheader_addr = self.handle_request_member(fuseoutheader, &mut data_entries, true);
        // FuseOutbody.
        let fuseoutbody_addr = self.handle_request_member(fuseoutbody, &mut data_entries, true);

        let free_head = self.queues[1]
            .clone()
            .borrow_mut()
            .add_chained(self.state.clone(), data_entries);

        // Kick.
        self.device
            .borrow_mut()
            .kick_virtqueue(self.state.clone(), self.queues[1].clone());

        // Wait for response.
        self.wait_for_response(free_head);

        (
            fuseinheader_addr,
            fuseinbody_addr,
            fuseoutheader_addr,
            fuseoutbody_addr,
        )
    }

    fn virtiofs_do_virtio_request(
        &self,
        fuseinheader: &[u8],
        fuseinbody: &[u8],
        fuseoutheader: &[u8],
        fuseoutbody: &[u8],
    ) -> (u64, u64) {
        let (_, _, fuseoutheader_addr, fuseoutbody_addr) = self.do_virtio_request(
            Some(fuseinheader),
            Some(fuseinbody),
            Some(fuseoutheader),
            Some(fuseoutbody),
        );

        (fuseoutheader_addr.unwrap(), fuseoutbody_addr.unwrap())
    }

    fn virtiofsd_start_with_config(
        dir_temp: bool,
        seccomp: Option<SeccompAction>,
        sandbox: Option<SandBoxMechanism>,
        modcaps: Option<&str>,
        rlimit_nofile: Option<u32>,
        xattr: bool,
    ) -> (String, String, String) {
        let binary_path = env::var("VIRTIOFSD_BINARY").unwrap();
        let (virtiofs_test_dir, virtiofs_shared_dir, virtiofs_test_file) = env_prepare(dir_temp);
        let virtiofs_sock = format!("{}/virtiofs.sock", virtiofs_shared_dir);

        let mut args = "--log-level info".to_string();
        if seccomp.is_some() {
            let seccomp_args = format!(" --seccomp {}", seccomp.unwrap());
            args.push_str(&seccomp_args);
        }
        if sandbox.is_some() {
            let sandbox_args = format!(" --sandbox {}", sandbox.unwrap());
            args.push_str(&sandbox_args);
        }
        if modcaps.is_some() {
            let modcaps_args = format!(" {}", modcaps.unwrap());
            args.push_str(&modcaps_args);
        }
        if rlimit_nofile.is_some() {
            let rlimit_args = format!(" --rlimit-nofile {}", rlimit_nofile.unwrap());
            args.push_str(&rlimit_args);
        }
        if xattr {
            args.push_str(" --xattr");
        }

        let args_vec: Vec<&str> = args.trim().split(' ').collect();

        Command::new(binary_path)
            .arg("--shared-dir")
            .arg(virtiofs_shared_dir)
            .arg("--socket-path")
            .arg(virtiofs_sock.clone())
            .args(args_vec)
            .spawn()
            .unwrap();

        // Wait totally 10s for that the vhost user fs socket is being created.
        let path = virtiofs_sock.clone();
        let sock_path = Path::new(&path);
        for _ in 0..100 {
            if sock_path.exists() {
                break;
            }
            // Query at 0.1s interval.
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        (virtiofs_test_dir, virtiofs_sock, virtiofs_test_file)
    }

    fn virtiofsd_start() -> (String, String, String) {
        VirtioFsTest::virtiofsd_start_with_config(true, None, None, None, None, false)
    }

    fn testcase_end(&self, test_dir: String) {
        self.testcase_check_and_end(None, test_dir.clone());
    }

    fn testcase_check_and_end(&self, absolute_virtiofs_sock: Option<String>, test_dir: String) {
        self.device
            .borrow_mut()
            .destroy_device(self.allocator.clone(), self.queues.clone());

        if let Some(path) = absolute_virtiofs_sock {
            let path_clone = path.clone();
            let sock_path = Path::new(&path_clone);
            assert_eq!(sock_path.exists(), true);
            self.state.borrow_mut().stop();
        } else {
            self.state.borrow_mut().stop();
        }

        env_clean(test_dir);
    }

    fn wait_for_response(&self, free_head: u32) {
        self.device.borrow().poll_used_elem(
            self.state.clone(),
            self.queues[1].clone(),
            free_head,
            TIMEOUT_US,
            &mut None,
            false,
        );
    }
}

fn read_obj<T: ByteCode>(test_state: Rc<RefCell<TestState>>, read_addr: u64) -> T {
    let read_len = size_of::<T>() as u64;
    let read_bytes = test_state.borrow().memread(read_addr, read_len);
    let slice = unsafe { from_raw_parts(read_bytes.as_ptr() as *const T, size_of::<T>()) };
    slice[0].clone()
}

fn fuse_init(fs: &VirtioFsTest) -> (FuseOutHeader, FuseInitOut) {
    let len = size_of::<FuseInHeader>() + size_of::<FuseInitIn>();
    let fuse_in_head = FuseInHeader::new(len as u32, FUSE_INIT, 0, 0, 0, 0, 0, 0);
    let fuse_init_in = FuseInitIn {
        major: FUSE_KERNEL_VERSION,
        minor: FUSE_KERNEL_MINOR_VERSION,
        max_readahead: TEST_MAX_READAHEAD,
        flags: TEST_FLAG,
    };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_init_out = FuseInitOut::default();
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_init_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_init_out.as_bytes(),
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    let init_out = read_obj::<FuseInitOut>(fs.state.clone(), outbodyaddr);

    (out_header, init_out)
}

fn fuse_destroy(fs: &VirtioFsTest) -> FuseOutHeader {
    let len = size_of::<FuseInHeader>();
    let fuse_in_head = FuseInHeader::new(len as u32, FUSE_DESTROY, 0, 0, 0, 0, 0, 0);
    let fuse_out_head = FuseOutHeader::default();
    let (_, _, outheaderaddr, _outbodyaddr) = fs.do_virtio_request(
        Some(&fuse_in_head.as_bytes()),
        None,
        Some(&fuse_out_head.as_bytes()),
        None,
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr.unwrap());

    out_header
}

fn fuse_lookup(fs: &VirtioFsTest, name: String) -> u64 {
    // The reason why add "1" is that there exists "\0" after string.
    let len = (size_of::<FuseInHeader>() + name.len() + 1) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_LOOKUP, 0, PARENT_NODEID, 0, 0, 0, 0);
    let fuse_lookup_in = FuseLookupIn { name };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_lookup_out = FuseEntryOut::default();
    let (_outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_lookup_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_lookup_out.as_bytes(),
    );

    let entry_out = read_obj::<FuseEntryOut>(fs.state.clone(), outbodyaddr);

    entry_out.nodeid
}

fn fuse_open(fs: &VirtioFsTest, nodeid: u64) -> u64 {
    let len = (size_of::<FuseInHeader>() + size_of::<FuseOpenIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_OPEN, 0, nodeid, 0, 0, 0, 0);
    let fuse_open_in = FuseOpenIn {
        flags: O_RDWR,
        unused: 0,
    };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_open_out = FuseOpenOut::default();
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_open_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_open_out.as_bytes(),
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);
    let openout = read_obj::<FuseOpenOut>(fs.state.clone(), outbodyaddr);

    openout.fh
}

fn fuse_open_dir(fs: &VirtioFsTest, nodeid: u64) -> u64 {
    let len = (size_of::<FuseInHeader>() + size_of::<FuseOpenIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_OPENDIR, 0, nodeid, 0, 0, 0, 0);
    let fuse_open_in = FuseOpenIn {
        flags: 0,
        unused: 0,
    };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_open_out = FuseOpenOut::default();
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_open_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_open_out.as_bytes(),
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);
    let openout = read_obj::<FuseOpenOut>(fs.state.clone(), outbodyaddr);

    openout.fh
}

// Note: Virtiofsd doesn't support illegal size message now, so trim will only support 0 until virtiofsd modification.
fn fuse_lseek(
    fs: &VirtioFsTest,
    nodeid: u64,
    fh: u64,
    trim: usize,
) -> (FuseOutHeader, FuseLseekOut) {
    let fuse_lseek_in = FuseLseekIn {
        fh,
        offset: 0,
        whence: SEEK_END,
        padding: 0,
    };
    let lseek_in_len = fuse_lseek_in.as_bytes().len();
    let trim_lseek_in_len = lseek_in_len - trim;
    let fuse_out_head = FuseOutHeader::default();
    let fuse_lseek_out = FuseLseekOut::default();
    let len = (size_of::<FuseInHeader>() + trim_lseek_in_len) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_LSEEK, 0, nodeid, 0, 0, 0, 0);
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_lseek_in.as_bytes()[0..lseek_in_len - trim],
        &fuse_out_head.as_bytes(),
        &fuse_lseek_out.as_bytes(),
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    let lseekout = read_obj::<FuseLseekOut>(fs.state.clone(), outbodyaddr);

    (out_header, lseekout)
}

fn fuse_getattr(fs: &VirtioFsTest, nodeid: u64, fh: u64) -> (FuseOutHeader, FuseAttrOut) {
    let len = (size_of::<FuseInHeader>() + size_of::<FuseGetAttrIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_GETATTR, 0, nodeid, 0, 0, 0, 0);
    let fuse_getattr_in = FuseGetAttrIn {
        getattr_flags: 0,
        dummy: 0,
        fh,
    };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_getattr_out = FuseAttrOut::default();
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_getattr_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_getattr_out.as_bytes(),
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    let attrout = read_obj::<FuseAttrOut>(fs.state.clone(), outbodyaddr);

    (out_header, attrout)
}

// Test situation: mount -t virtiofs myfs /mnt.
#[test]
fn mount_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) =
        VirtioFsTest::virtiofsd_start_with_config(
            true,
            Some(SeccompAction::Kill),
            Some(SandBoxMechanism::Namespace),
            Some("--modcaps=-LEASE:+KILL"),
            None,
            false,
        );

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock.clone());

    // basic function test.
    fuse_init(&fs);

    // kill process and clean env.
    fs.testcase_check_and_end(Some(virtiofs_sock), virtiofs_test_dir);
}

// Test situation: umount /mnt.
#[test]
fn umount_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) =
        VirtioFsTest::virtiofsd_start_with_config(
            true,
            Some(SeccompAction::None),
            Some(SandBoxMechanism::Chroot),
            Some("--modcaps=-LEASE:+KILL"),
            None,
            false,
        );

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);

    // mount.
    fuse_init(&fs);

    // unmout and check.
    let resp = fuse_destroy(&fs);
    assert_eq!(resp.error, 0);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

/// Test: mkdir /mnt/dir
#[test]
fn mkdir_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) =
        VirtioFsTest::virtiofsd_start_with_config(
            true,
            Some(SeccompAction::Log),
            None,
            None,
            Some(4096), // Test rlimit_nofile config. -rlimit_nofile 4096.
            false,
        );

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);
    fuse_init(&fs);

    // do request.
    let fuse_mkdir_in = FuseMkdirIn {
        mode: 0o777, // Directory right: 777.
        umask: 0,
        name: String::from("dir"),
    };
    let len = (size_of::<FuseInHeader>() + fuse_mkdir_in.len()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_MKDIR, 0, PARENT_NODEID, 0, 0, 0, 0);
    let fuse_out_head = FuseOutHeader::default();
    let fuse_mkdir_out = FuseEntryOut::default();
    let (outheaderaddr, _outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_mkdir_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_mkdir_out.as_bytes(),
    );

    // Check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);

    let mut linkpath = virtiofs_test_dir.clone();
    linkpath.push_str("/shared/dir");
    let linkpath_clone = linkpath.clone();
    let link_path = Path::new(&linkpath_clone);
    assert_eq!(link_path.is_dir(), true);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

/// Test: sync /mnt/testfile.
#[test]
fn sync_fun() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) =
        VirtioFsTest::virtiofsd_start_with_config(
            true,
            Some(SeccompAction::Trap),
            None,
            None,
            None,
            false,
        );

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);

    fuse_init(&fs);
    let nodeid = fuse_lookup(&fs, TEST_FILE_NAME.to_string());
    let fh = fuse_open(&fs, nodeid);

    // sync file.
    let len = (size_of::<FuseInHeader>() + size_of::<FuseFsyncIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_FSYNC, 0, nodeid, 0, 0, 0, 0);
    let fuse_fallocate_in = FuseFsyncIn {
        fh,
        fsync_flags: 0,
        padding: 0,
    };
    let fuse_out_head = FuseOutHeader::default();
    let (_, _, outheader, _outbodyaddr) = fs.do_virtio_request(
        Some(&fuse_in_head.as_bytes()),
        Some(&fuse_fallocate_in.as_bytes()),
        Some(&fuse_out_head.as_bytes()),
        None,
    );

    // Check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheader.unwrap());
    assert_eq!(out_header.error, 0);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

/// Test: sync /mnt
#[test]
fn syncdir_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);
    fuse_init(&fs);
    let fh = fuse_open_dir(&fs, PARENT_NODEID);

    // sync directory.
    let len = (size_of::<FuseInHeader>() + size_of::<FuseFsyncIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_FSYNCDIR, 0, PARENT_NODEID, 0, 0, 0, 0);
    let fuse_fallocate_in = FuseFsyncIn {
        fh,
        fsync_flags: 0,
        padding: 0,
    };
    let fuse_out_head = FuseOutHeader::default();
    let (_, _, outheader, _outbodyaddr) = fs.do_virtio_request(
        Some(&fuse_in_head.as_bytes()),
        Some(&fuse_fallocate_in.as_bytes()),
        Some(&fuse_out_head.as_bytes()),
        None,
    );

    // Check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheader.unwrap());
    assert_eq!(out_header.error, 0);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

#[test]
fn invalid_fuse_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);

    // generate fake fuse request and send it.
    let fake_fuse_in_body = [0];
    let fake_len = (size_of::<FuseInHeader>() + fake_fuse_in_body.len()) as u32;
    let fake_ops = 50; // No such fuse command.
    let fuse_in_head = FuseInHeader::new(fake_len, fake_ops, 0, 0, 0, 0, 0, 0);
    let fuse_out_head = FuseOutHeader::default();
    let fake_fuse_out_body = [0];
    let (outheaderaddr, _outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fake_fuse_in_body,
        &fuse_out_head.as_bytes(),
        &fake_fuse_out_body,
    );

    // Check returned error.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert!(out_header.error != 0);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

// Note: Virtiofsd does not support illegal size message, block this test case.
#[test]
#[ignore]
fn missing_fuseinbody_fuseoutbody_virtiorequest_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);

    // generate fake fuse request and send it.
    let len = (size_of::<FuseInHeader>() + size_of::<FuseInitIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_INIT, 0, 0, 0, 0, 0, 0);
    let fuse_out_head = FuseOutHeader::default();
    let (_, _, outheader, _outbodyaddr) = fs.do_virtio_request(
        Some(fuse_in_head.as_bytes()),
        None,
        Some(fuse_out_head.as_bytes()),
        None,
    );

    // Check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheader.unwrap());
    assert!(out_header.error != 0);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

#[test]
fn virtiofs_device_config_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);

    // get values from device config.
    let mut tag = [0; MAX_TAG_LENGTH];
    for i in 0..MAX_TAG_LENGTH {
        tag[i] = fs
            .device
            .borrow()
            .config_readb((offset_of!(VirtioFsConfig, tag) + i) as u64);
    }
    let num_request_queues = fs
        .device
        .borrow()
        .config_readl(offset_of!(VirtioFsConfig, num_request_queues) as u64);

    // set values to device config.
    for i in 0..MAX_TAG_LENGTH {
        fs.device
            .borrow()
            .config_writeb((offset_of!(VirtioFsConfig, tag) + i) as u64, 0x10);
    }
    fs.device
        .borrow()
        .config_writel(offset_of!(VirtioFsConfig, num_request_queues) as u64, 5);

    // get values from device config.
    let mut tag_new = [0; MAX_TAG_LENGTH];
    for i in 0..MAX_TAG_LENGTH {
        tag_new[i] = fs
            .device
            .borrow()
            .config_readb((offset_of!(VirtioFsConfig, tag) + i) as u64);
    }
    let num_request_queues_new = fs
        .device
        .borrow()
        .config_readl(offset_of!(VirtioFsConfig, num_request_queues) as u64);

    // Check config can not be changed.
    assert!(num_request_queues == num_request_queues_new);
    assert!(tag == tag_new);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

#[test]
fn ls_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);

    // init filesystem.
    fuse_init(&fs);

    // FUSE_OPENDIR.
    let fh = fuse_open_dir(&fs, PARENT_NODEID);

    // FUSE_READDIRPLUS.
    let len = (size_of::<FuseInHeader>() + size_of::<FuseReadIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_READDIRPLUS, 0, PARENT_NODEID, 0, 0, 0, 0);
    let fuse_read_in = FuseReadIn {
        fh,
        offset: 0,
        size: DEFAULT_READ_SIZE as u32,
        ..Default::default()
    };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_read_out = [0; DEFAULT_READ_SIZE];
    let (outheaderaddr, _outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_read_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_read_out,
    );
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);

    // FUSE_FORGET.
    let len = (size_of::<FuseInHeader>() + size_of::<FuseForgetIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_FORGET, 0, PARENT_NODEID, 0, 0, 0, 0);
    let fuse_read_in = FuseForgetIn { nlookup: 1 };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_forget_out = FuseForgetOut::default();
    let (outheaderaddr, _outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_read_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_forget_out.as_bytes(),
    );
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);

    // FUSE_READDIR.
    let len = (size_of::<FuseInHeader>() + size_of::<FuseReadIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_READDIR, 0, 1, 0, 0, 0, 0);
    let fuse_read_in = FuseReadIn {
        fh,
        offset: 0,
        size: DEFAULT_READ_SIZE as u32,
        ..Default::default()
    };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_read_out = [0_u8; DEFAULT_READ_SIZE];
    let (outheaderaddr, _outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_read_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_read_out,
    );
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);

    // FUSE_RELEASEDIR.
    let len = (size_of::<FuseInHeader>() + size_of::<FuseReleaseIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_RELEASEDIR, 0, 1, 0, 0, 0, 0);
    let fuse_read_in = FuseReleaseIn {
        fh,
        ..Default::default()
    };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_read_out = [0_u8; DEFAULT_READ_SIZE];
    let (outheaderaddr, _outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_read_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_read_out,
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

fn fuse_setattr(
    fs: &VirtioFsTest,
    nodeid: u64,
    fuse_setattr_in: FuseSetattrIn,
) -> (FuseOutHeader, FuseAttrOut) {
    let len = (size_of::<FuseInHeader>() + size_of::<FuseSetattrIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_SETATTR, 0, nodeid, 0, 0, 0, 0);
    let fuse_out_head = FuseOutHeader::default();
    let fuse_attr_out = FuseAttrOut::default();
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_setattr_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_attr_out.as_bytes(),
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    let attr_out = read_obj::<FuseAttrOut>(fs.state.clone(), outbodyaddr);

    (out_header, attr_out)
}

#[test]
fn setattr_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);

    // do init.
    fuse_init(&fs);

    // do lookup
    let nodeid = fuse_lookup(&fs, TEST_FILE_NAME.to_string());
    let fh = fuse_open(&fs, nodeid);

    // chmod 666 testfile
    let mut fuse_setattr_in = FuseSetattrIn::default();
    fuse_setattr_in.mode = 0o666; // file right: 666.
    fuse_setattr_in.valid = FATTR_MODE | FATTR_FH;
    fuse_setattr_in.fh = fh;
    let (out_header, _attr) = fuse_setattr(&fs, nodeid, fuse_setattr_in);
    assert_eq!(out_header.error, 0);

    let (_out_header, attr) = fuse_getattr(&fs, nodeid, fh);
    assert!(attr.attr.mode & 0o666 == 0o666);

    // chmod 777 testfile
    let mut fuse_setattr_in = FuseSetattrIn::default();
    fuse_setattr_in.mode = 0o777; // file right: 777.
    fuse_setattr_in.valid = FATTR_MODE;
    fuse_setattr_in.fh = fh;
    let (out_header, _attr) = fuse_setattr(&fs, nodeid, fuse_setattr_in);
    assert_eq!(out_header.error, 0);

    let (_out_header, attr) = fuse_getattr(&fs, nodeid, fh);
    assert!(attr.attr.mode & 0o777 == 0o777);

    // chown.
    let mut fuse_setattr_in = FuseSetattrIn::default();
    fuse_setattr_in.valid = FATTR_UID | FATTR_GID;
    fuse_setattr_in.fh = fh;
    fuse_setattr_in.uid = 100;
    fuse_setattr_in.gid = 200;
    let (out_header, _attr) = fuse_setattr(&fs, nodeid, fuse_setattr_in);
    assert_eq!(out_header.error, 0);

    let (_out_header, attr) = fuse_getattr(&fs, nodeid, fh);
    assert!(attr.attr.uid == 100);
    assert!(attr.attr.gid == 200);

    // truncate /mnt/testfile -s 1k
    let mut fuse_setattr_in = FuseSetattrIn::default();
    fuse_setattr_in.size = 1024; // 1k
    fuse_setattr_in.valid = FATTR_SIZE | FATTR_FH;
    fuse_setattr_in.fh = fh;
    let (out_header, _attr) = fuse_setattr(&fs, nodeid, fuse_setattr_in);
    assert_eq!(out_header.error, 0);

    let (_out_header, attr) = fuse_getattr(&fs, nodeid, fh);
    assert!(attr.attr.size == 1024);

    // truncate /mnt/testfile -s 2k
    let mut fuse_setattr_in = FuseSetattrIn::default();
    fuse_setattr_in.size = 2048; // 2k
    fuse_setattr_in.valid = FATTR_SIZE;
    fuse_setattr_in.fh = fh;
    let (out_header, _attr) = fuse_setattr(&fs, nodeid, fuse_setattr_in);
    assert_eq!(out_header.error, 0);

    let (_out_header, attr) = fuse_getattr(&fs, nodeid, fh);
    assert!(attr.attr.size == 2048);

    // touch -m -t 202301010000 test.c
    let mut fuse_setattr_in = FuseSetattrIn::default();
    fuse_setattr_in.mtime = 1672531200; // 2023.01.01 00:00
    fuse_setattr_in.valid = FATTR_MTIME;
    fuse_setattr_in.fh = fh;
    let (out_header, _attr) = fuse_setattr(&fs, nodeid, fuse_setattr_in);
    assert_eq!(out_header.error, 0);

    let (_out_header, attr) = fuse_getattr(&fs, nodeid, fh);
    assert!(attr.attr.mtime == 1672531200);

    // touch -a -t 202301010000 test.c
    let mut fuse_setattr_in = FuseSetattrIn::default();
    fuse_setattr_in.atime = 1672531200; // 2023.01.01 00:00
    fuse_setattr_in.valid = FATTR_ATIME | FATTR_FH;
    fuse_setattr_in.fh = fh;
    let (out_header, _attr) = fuse_setattr(&fs, nodeid, fuse_setattr_in);
    assert_eq!(out_header.error, 0);

    let (_out_header, attr) = fuse_getattr(&fs, nodeid, fh);
    assert!(attr.attr.atime == 1672531200);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

// unlink /mnt/testfile
#[test]
fn unlink_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);

    fuse_init(&fs);
    fuse_lookup(&fs, TEST_FILE_NAME.to_string());

    // unlink request.
    let len = (size_of::<FuseInHeader>() + TEST_FILE_NAME.len() + 1) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_UNLINK, 0, PARENT_NODEID, 0, 0, 0, 0);
    let fuse_unlink_in = FuseUnlinkrIn {
        name: String::from(TEST_FILE_NAME),
    };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_unlink_out = FuseEntryOut::default();
    let (outheaderaddr, _outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_unlink_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_unlink_out.as_bytes(),
    );

    // Check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);

    let mut linkpath = virtiofs_test_dir.clone();
    linkpath.push_str("/shared/testfile");
    let linkpath_clone = linkpath.clone();
    let link_path = Path::new(&linkpath_clone);
    assert_eq!(link_path.exists(), false);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

#[test]
fn rmdir_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    let mut dir = virtiofs_test_dir.clone();
    dir.push_str("/shared/dir");
    Command::new("mkdir")
        .arg("-p")
        .arg(dir.clone())
        .output()
        .unwrap();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);

    fuse_init(&fs);
    fuse_lookup(&fs, "dir".to_string());

    // rmdir request.
    let fuse_unlink_in = FuseUnlinkrIn {
        name: String::from("dir"),
    };
    let len = (size_of::<FuseInHeader>() + fuse_unlink_in.len()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_RMDIR, 0, PARENT_NODEID, 0, 0, 0, 0);
    let fuse_out_head = FuseOutHeader::default();
    let fuse_unlink_out = FuseEntryOut::default();
    let (outheaderaddr, _outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_unlink_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_unlink_out.as_bytes(),
    );

    // Check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);

    let mut linkpath = virtiofs_test_dir.clone();
    linkpath.push_str("/shared/dir");
    let linkpath_clone = linkpath.clone();
    let link_path = Path::new(&linkpath_clone);
    assert_eq!(link_path.exists(), false);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

#[test]
fn symlink_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);
    fuse_init(&fs);

    // do request.
    let linkname = "link".to_string();
    let len = (linkname.len() + size_of::<FuseInHeader>() + TEST_FILE_NAME.len() + 2) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_SYMLINK, 4, PARENT_NODEID, 0, 0, 0, 0);
    let fuse_init_in = FusesysmlinkIn {
        name: linkname.clone(),
        linkname: String::from(TEST_FILE_NAME),
    };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_init_out = FuseEntryOut::default();
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_init_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_init_out.as_bytes(),
    );

    // Check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);

    let entryout = read_obj::<FuseEntryOut>(fs.state.clone(), outbodyaddr);
    assert_eq!(entryout.attr.nlink, 1);

    let mut linkpath = virtiofs_test_dir.clone();
    linkpath.push_str("/shared/link");
    let linkpath_clone = linkpath.clone();
    let link_path = Path::new(&linkpath_clone);
    assert_eq!(link_path.is_symlink(), true);

    // Read link
    let node_id = fuse_lookup(&fs, linkname.clone());
    let len = size_of::<FuseInHeader>() as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_READLINK, 8, node_id, 0, 0, 0, 0);
    let fuse_out_head = FuseOutHeader::default();
    let fuse_read_link_out = [0_u8; 1024];
    let (_, _, outheader, outbodyaddr) = fs.do_virtio_request(
        Some(&fuse_in_head.as_bytes()),
        None,
        Some(&fuse_out_head.as_bytes()),
        Some(&fuse_read_link_out),
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheader.unwrap());
    assert_eq!(0, out_header.error);
    let fuse_read_link_out = fs.state.borrow().memread(outbodyaddr.unwrap(), 1024);
    let read_path = String::from_utf8(fuse_read_link_out);
    let mut read_path = read_path.unwrap();
    read_path.truncate(TEST_FILE_NAME.len());
    assert_eq!(TEST_FILE_NAME.to_string(), read_path);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

// fallocate -l 1024K /mnt/testfile
#[test]
fn fallocate_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);
    fuse_init(&fs);
    let nodeid = fuse_lookup(&fs, TEST_FILE_NAME.to_string());
    let fh = fuse_open(&fs, nodeid);

    // FUSE_FALLOCATE.
    let len = (size_of::<FuseInHeader>() + size_of::<FuseFallocateIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_FALLOCATE, 0, nodeid, 0, 0, 0, 0);
    let fuse_fallocate_in = FuseFallocateIn {
        fh,
        offset: 0,
        length: 1048576, // 1KB.
        mode: 0,
        padding: 0,
    };
    let fuse_out_head = FuseOutHeader::default();
    let (_, _, outheader, _outbodyaddr) = fs.do_virtio_request(
        Some(&fuse_in_head.as_bytes()),
        Some(&fuse_fallocate_in.as_bytes()),
        Some(&fuse_out_head.as_bytes()),
        None,
    );

    // Check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheader.unwrap());
    assert_eq!(out_header.error, 0);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

// Note: Virtiofsd does not support `GETLK` message, block this test case.
// fcntl() function test.
#[test]
#[ignore]
fn posix_file_lock_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);
    fuse_init(&fs);
    let nodeid = fuse_lookup(&fs, TEST_FILE_NAME.to_string());
    let fh = fuse_open(&fs, nodeid);

    // getlk write lock.
    let len = (size_of::<FuseInHeader>() + size_of::<FuseLkIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_GETLK, 0, nodeid, 0, 0, 0, 0);
    let fuse_lk_in = FuseLkIn {
        fh,
        owner: 0,
        lk: FuseFileLock {
            start: 0,
            end: 1,
            lock_type: F_WRLCK,
            pid: 1,
        },
        lk_flags: 0,
        padding: 0,
    };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_lk_out = FuseLkOut::default();
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_lk_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_lk_out.as_bytes(),
    );

    // Check file is unlock.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);
    let lkout = read_obj::<FuseLkOut>(fs.state.clone(), outbodyaddr);
    assert_eq!(lkout.lk.lock_type, F_UNLCK);

    // setlk write lock.
    let len = (size_of::<FuseInHeader>() + size_of::<FuseLkIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_SETLK, 0, nodeid, 0, 0, 0, 0);
    let fuse_lk_in = FuseLkIn {
        fh,
        owner: 0,
        lk: FuseFileLock {
            start: 0,
            end: 1,
            lock_type: F_WRLCK,
            pid: 1,
        },
        lk_flags: 0,
        padding: 0,
    };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_lk_out = FuseLkOut::default();
    let (outheaderaddr, _outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_lk_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_lk_out.as_bytes(),
    );

    // check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

#[test]
fn mknod_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);
    fuse_init(&fs);

    // FUSE_MKNOD.
    let fuse_mknod_in = FuseMknodIn {
        mode: 0o666, // right mode 666.
        rdev: 0,
        umask: 0,
        padding: 0,
        name: String::from("node"),
    };
    let len = (size_of::<FuseInHeader>() + fuse_mknod_in.len()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_MKNOD, 4, PARENT_NODEID, 0, 0, 0, 0);

    let fuse_out_head = FuseOutHeader::default();
    let fuse_init_out = FuseEntryOut::default();
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_mknod_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_init_out.as_bytes(),
    );

    // Check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);
    let entryout = read_obj::<FuseEntryOut>(fs.state.clone(), outbodyaddr);
    assert_eq!(entryout.attr.nlink, 1);

    let mut nodepath = virtiofs_test_dir.clone();
    nodepath.push_str("/shared/node");
    let nodepath_clone = nodepath.clone();
    let node_path = Path::new(&nodepath_clone);
    assert!(node_path.exists());

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

fn get_xattr(fs: &VirtioFsTest, name: String, nodeid: u64) -> (FuseOutHeader, String) {
    let len =
        (size_of::<FuseInHeader>() + offset_of!(FuseGetxattrIn, name) + name.len() + 1) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_GETXATTR, 0, nodeid, 0, 0, 0, 0);
    let fuse_in = FuseGetxattrIn {
        size: DEFAULT_XATTR_SIZE,
        padding: 0,
        name,
    };

    let fuse_out_head = FuseOutHeader::default();
    let fuse_out = [0_u8; DEFAULT_XATTR_SIZE as usize];
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_out,
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    let fuse_read_out = fs
        .state
        .borrow()
        .memread(outbodyaddr, DEFAULT_XATTR_SIZE as u64);
    let attr = String::from_utf8(fuse_read_out).unwrap();

    (out_header, attr)
}

fn flush_file(fs: &VirtioFsTest, nodeid: u64, fh: u64) {
    let len = (size_of::<FuseInHeader>() + size_of::<FuseFlushIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_FLUSH, 0, nodeid, 0, 0, 0, 0);
    let fuse_in = FuseFlushIn {
        fh,
        unused: 0,
        padding: 0,
        lock_owner: 0,
    };
    let fuse_out_head = FuseOutHeader::default();
    let (_, _, outheader, _) = fs.do_virtio_request(
        Some(&fuse_in_head.as_bytes()),
        Some(&fuse_in.as_bytes()),
        Some(&fuse_out_head.as_bytes()),
        None,
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheader.unwrap());
    assert_eq!(out_header.error, 0);
}

fn write_file(fs: &VirtioFsTest, nodeid: u64, fh: u64, write_buf: String) {
    let len = (size_of::<FuseInHeader>() + offset_of!(FuseWriteIn, write_buf) + write_buf.len() + 1)
        as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_WRITE, 0, nodeid, 0, 0, 0, 0);
    let fuse_write_in = FuseWriteIn::new(fh, 0, write_buf.clone());
    let fuse_out_head = FuseOutHeader::default();
    let fuse_write_out = FuseWriteOut::default();
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_write_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_write_out.as_bytes(),
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);

    let write_out = read_obj::<FuseWriteOut>(fs.state.clone(), outbodyaddr);
    assert_eq!(write_out.size, (write_buf.len() + 1) as u32);
}

fn release_file(fs: &VirtioFsTest, nodeid: u64, fh: u64) {
    let len = (size_of::<FuseInHeader>() + size_of::<FuseReleaseIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_RELEASE, 0, nodeid, 0, 0, 0, 0);
    let fuse_read_in = FuseReleaseIn {
        fh,
        flags: O_NONBLOCK | O_DIRECT,
        ..Default::default()
    };
    let fuse_out_head = FuseOutHeader::default();
    let (_, _, outheader, _) = fs.do_virtio_request(
        Some(&fuse_in_head.as_bytes()),
        Some(&fuse_read_in.as_bytes()),
        Some(&fuse_out_head.as_bytes()),
        None,
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheader.unwrap());
    assert_eq!(out_header.error, 0);
}

fn create_file(fs: &VirtioFsTest, name: String) -> (FuseOutHeader, FuseCreateOut) {
    let len = (size_of::<FuseInHeader>() + offset_of!(FuseCreateIn, name) + name.len() + 1) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_CREATE, 0, PARENT_NODEID, 0, 0, 0, 0);
    let fuse_in = FuseCreateIn {
        flags: O_CREAT | O_TRUNC | O_RDWR,
        mode: 0o777, // file right mode 777.
        umask: 0,
        padding: 0,
        name,
    };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_out = FuseCreateOut::default();
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_out.as_bytes(),
    );

    // Check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);
    let createout = read_obj::<FuseCreateOut>(fs.state.clone(), outbodyaddr);

    (out_header, createout)
}

#[test]
fn writefile_fun() {
    let file = "text.txt".to_string();
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);
    fuse_init(&fs);

    let (out_head, attr) = create_file(&fs, file);
    assert_eq!(out_head.error, 0);

    let mut nodepath = virtiofs_test_dir.clone();
    nodepath.push_str("/shared/text.txt");

    let nodepath_clone = nodepath.clone();
    let node_path = Path::new(&nodepath_clone);
    assert!(node_path.exists());

    flush_file(&fs, attr.create_out.nodeid, attr.open_out.fh);
    get_xattr(&fs, "security.selinux".to_string(), attr.create_out.nodeid);

    write_file(
        &fs,
        attr.create_out.nodeid,
        attr.open_out.fh,
        "12345".to_string(),
    );
    flush_file(&fs, attr.create_out.nodeid, attr.open_out.fh);

    release_file(&fs, attr.create_out.nodeid, attr.open_out.fh);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

fn read_file(fs: &VirtioFsTest, nodeid: u64, fh: u64) -> String {
    let len = (size_of::<FuseInHeader>() + size_of::<FuseReadIn>()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_READ, 0, nodeid, 0, 0, 0, 0);
    let fuse_in = FuseReadIn {
        fh,
        offset: 0,
        size: DEFAULT_READ_SIZE as u32,
        ..Default::default()
    };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_out = [0_u8; DEFAULT_READ_SIZE];
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_out,
    );

    // Check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(out_header.error, 0);
    let fuse_read_out = fs.state.borrow().memread(outbodyaddr, 5);
    let str = String::from_utf8(fuse_read_out).unwrap();

    str
}

#[test]
fn openfile_test() {
    let file = TEST_FILE_NAME.to_string();

    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);
    fuse_init(&fs);
    let nodeid = fuse_lookup(&fs, file.clone());

    // open/write/flush/close/open/read/close
    let fh = fuse_open(&fs, nodeid);
    let mut nodepath = virtiofs_test_dir.clone();
    nodepath.push_str("/shared/testfile");
    let nodepath_clone = nodepath.clone();
    let node_path = Path::new(&nodepath_clone);
    assert!(node_path.exists());
    write_file(&fs, nodeid, fh, "12345".to_string());
    flush_file(&fs, nodeid, fh);
    release_file(&fs, nodeid, fh);

    let fh = fuse_open(&fs, nodeid);
    let get_str = read_file(&fs, nodeid, fh);
    assert_eq!(get_str, "12345".to_string());
    release_file(&fs, nodeid, fh);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

#[test]
fn rename_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);
    fuse_init(&fs);

    // FUSE_RENAME. Rename testfile to file.
    fuse_lookup(&fs, TEST_FILE_NAME.to_string());
    let fuse_rename_in = FuseRenameIn {
        newdir: PARENT_NODEID,
        oldname: TEST_FILE_NAME.to_string(),
        newname: "file".to_string(),
    };
    let len = (size_of::<FuseInHeader>() + fuse_rename_in.len()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_RENAME, 0, PARENT_NODEID, 0, 0, 0, 0);
    let fuse_out_head = FuseOutHeader::default();
    let (_, _, outheader, _outbodyaddr) = fs.do_virtio_request(
        Some(&fuse_in_head.as_bytes()),
        Some(&fuse_rename_in.as_bytes()),
        Some(&fuse_out_head.as_bytes()),
        None,
    );

    // Check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheader.unwrap());
    assert_eq!(0, out_header.error);
    let path = virtiofs_test_dir.clone() + "/shared" + "/file";
    let path = Path::new(path.as_str());
    assert!(path.exists());

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

#[test]
fn link_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);
    fuse_init(&fs);

    // FUSE_LINK.
    let oldnodeid = fuse_lookup(&fs, TEST_FILE_NAME.to_string());

    let fuse_rename_in = FuseLinkIn {
        oldnodeid,
        newname: "file_link".to_string(),
    };
    let len = (size_of::<FuseInHeader>() + fuse_rename_in.len()) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_LINK, 0, PARENT_NODEID, 0, 0, 0, 0);
    let fuse_out_head = FuseOutHeader::default();
    let fuse_entry_out = FuseEntryOut::default();
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_rename_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_entry_out.as_bytes(),
    );

    // Check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_eq!(0, out_header.error);
    let entry_out = read_obj::<FuseEntryOut>(fs.state.clone(), outbodyaddr);
    // link a file will make its nlink count +1
    assert_eq!(2, entry_out.attr.nlink);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

#[test]
fn statfs_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);
    fuse_init(&fs);

    // do request.
    let len = size_of::<FuseInHeader>() as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_STATFS, 0, PARENT_NODEID, 0, 0, 0, 0);
    let fuse_out_head = FuseOutHeader::default();
    let fuse_statfs_out = FuseKstatfs::default();
    let (_, _, outheader, _outbodyaddr) = fs.do_virtio_request(
        Some(&fuse_in_head.as_bytes()),
        None,
        Some(&fuse_out_head.as_bytes()),
        Some(&fuse_statfs_out.as_bytes()),
    );

    // Check.
    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheader.unwrap());
    assert_eq!(0, out_header.error);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

#[test]
fn virtio_fs_fuse_ioctl_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);

    // init filesystem.
    fuse_init(&fs);

    // FUSE_LOOKUP.
    let nodeid = fuse_lookup(&fs, TEST_FILE_NAME.to_string());

    // FUSE_IOCTL.
    let len = size_of::<FuseInHeader>() as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_IOCTL, 0, nodeid, 0, 0, 0, 0);
    let fuse_out_head = FuseOutHeader::default();
    let (outheaderaddr, _outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &[0],
        &fuse_out_head.as_bytes(),
        &[0],
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_ne!(out_header.error, 0);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

#[test]
fn virtio_fs_fuse_abnormal_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);

    // init filesystem.
    fuse_init(&fs);

    // Unsupported message 0xff.
    let len = size_of::<FuseInHeader>() as u32;
    let fuse_in_head = FuseInHeader::new(len, 0xff, 0, 0, 0, 0, 0, 0);
    let fuse_out_head = FuseOutHeader::default();

    let (outheaderaddr, _outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &[0],
        &fuse_out_head.as_bytes(),
        &[0],
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
    assert_ne!(out_header.error, 0);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

// Read "\0" c string from buffer[start..] and return the end position's next in buffer.
fn read_cstring(buffer: Vec<u8>, start: usize) -> (Option<String>, usize) {
    let mut pos = start;

    for i in start..buffer.len() {
        if buffer[i] == b'\0' {
            pos = i;
            break;
        }
    }

    if pos == start {
        return (None, pos);
    }

    let cstring = String::from_utf8(buffer[start..pos].to_vec()).unwrap();

    (Some(cstring), pos + 1)
}

fn fuse_setxattr(fs: &VirtioFsTest, name: String, value: String, nodeid: u64) -> FuseOutHeader {
    // 8: offset_of!(name, FuseSetxattrIn).
    // 2: two "/0".
    let len = (size_of::<FuseInHeader>() + 8 + name.len() + value.len() + 2) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_SETXATTR, 4, nodeid, 0, 0, 0, 0);
    let fuse_setxattr_in = FuseSetxattrIn {
        size: value.len() as u32 + 1,
        flags: XATTR_CREATE,
        name,
        value,
    };
    let fuse_out_head = FuseOutHeader::default();
    let (_, _, outheader, _outbodyaddr) = fs.do_virtio_request(
        Some(&fuse_in_head.as_bytes()),
        Some(&fuse_setxattr_in.as_bytes()),
        Some(&fuse_out_head.as_bytes()),
        None,
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheader.unwrap());

    out_header
}

fn fuse_removexattr(fs: &VirtioFsTest, name: String, nodeid: u64) -> FuseOutHeader {
    let len = (size_of::<FuseInHeader>() + name.len() + 1) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_REMOVEXATTR, 0, nodeid, 0, 0, 0, 0);
    let fuse_removexattr_in = FuseRemoveXattrIn { name };
    let fuse_out_head = FuseOutHeader::default();
    let (_, _, outheader, _outbodyaddr) = fs.do_virtio_request(
        Some(&fuse_in_head.as_bytes()),
        Some(&fuse_removexattr_in.as_bytes()),
        Some(&fuse_out_head.as_bytes()),
        None,
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheader.unwrap());
    out_header
}

fn fuse_listxattr(fs: &VirtioFsTest, nodeid: u64) -> (FuseOutHeader, u64) {
    // 8: offset_of!(name, FuseGetxattrIn).
    let len = (size_of::<FuseInHeader>() + 8) as u32;
    let fuse_in_head = FuseInHeader::new(len, FUSE_LISTXATTR, 0, nodeid, 0, 0, 0, 0);
    let fuse_in = FuseGetxattrIn {
        size: DEFAULT_XATTR_SIZE,
        padding: 0,
        name: "".to_string(),
    };
    let fuse_out_head = FuseOutHeader::default();
    let fuse_out = [0_u8; DEFAULT_XATTR_SIZE as usize];
    let (outheaderaddr, outbodyaddr) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &fuse_in.as_bytes(),
        &fuse_out_head.as_bytes(),
        &fuse_out,
    );

    let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);

    (out_header, outbodyaddr)
}

// setfattr -n user.abc -v valtest testfile
// getfattr -n user.abc testfile
// getfattr testfile
// setfattr -x user.abc testfile
#[test]
fn regularfile_xattr_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) =
        VirtioFsTest::virtiofsd_start_with_config(false, None, None, None, None, true);

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);
    fuse_init(&fs);
    let nodeid = fuse_lookup(&fs, TEST_FILE_NAME.to_string());

    let testattr_name = "user.abc";
    let testattr_value = "valtest";

    // SETXATTR.
    let fuseout = fuse_setxattr(
        &fs,
        testattr_name.to_string(),
        testattr_value.to_string(),
        nodeid,
    );
    assert_eq!(fuseout.error, 0);

    // GETXATTR
    let (header, value) = get_xattr(&fs, testattr_name.to_string(), nodeid);
    assert_eq!(0, header.error);
    assert_eq!(value[0..testattr_value.len()], testattr_value.to_string());

    // LISTXATTR
    let (header, outbodyaddr) = fuse_listxattr(&fs, nodeid);
    assert_eq!(header.error, 0);
    let attr_list = fs
        .state
        .borrow()
        .memread(outbodyaddr, DEFAULT_XATTR_SIZE as u64);
    // The first attr is "security.selinux"
    let (_attr1, next1) = read_cstring(attr_list.clone(), 0);
    // The next attrs are what we set by FUSE_SETXATTR. Check it.
    let (attr2, _next2) = read_cstring(attr_list.clone(), next1);
    assert_eq!(attr2.unwrap(), testattr_name);

    // REMOVEXATTR
    let outheader = fuse_removexattr(&fs, testattr_name.to_string(), nodeid);
    assert_eq!(0, outheader.error);

    // GETXATTR
    // Xattr "user.abc" has been removed, should receive ERROR.
    let (header, _value) = get_xattr(&fs, testattr_name.to_string(), nodeid);
    assert_ne!(0, header.error);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

// setfattr -n user.abc -v valtest /mnt/testchar
// getfattr -n user.abc /mnt/testchar
// getfattr /mnt/testchar
// setfattr -x user.abc /mnt/testchar
#[test]
fn character_file_xattr_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) =
        VirtioFsTest::virtiofsd_start_with_config(false, None, None, None, None, true);

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);
    fuse_init(&fs);
    let nodeid = fuse_lookup(&fs, TEST_CHARDEV_NAME.to_string());

    let testattr_name = "user.abc";
    let testattr_value = "valtest";

    // SETXATTR.
    let fuseout = fuse_setxattr(
        &fs,
        testattr_name.to_string(),
        testattr_value.to_string(),
        nodeid,
    );
    // can not setxattr for character device.
    assert_ne!(fuseout.error, 0);

    // GETXATTR nothing.
    let (header, _value) = get_xattr(&fs, testattr_name.to_string(), nodeid);
    assert_ne!(0, header.error);

    // LISTXATTR
    let (header, _outbodyaddr) = fuse_listxattr(&fs, nodeid);
    assert_eq!(header.error, 0);

    // REMOVEXATTR
    let outheader = fuse_removexattr(&fs, testattr_name.to_string(), nodeid);
    assert_ne!(0, outheader.error);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

#[test]
fn virtio_fs_fuse_lseek_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);

    // init filesystem.
    fuse_init(&fs);

    // FUSE_LOOKUP.
    let nodeid = fuse_lookup(&fs, TEST_FILE_NAME.to_string());
    // FUSE_OPEN.
    let fh = fuse_open(&fs, nodeid);

    // FUSE_GETATTR.
    let (out_header, _attrout) = fuse_getattr(&fs, nodeid, fh);
    assert_eq!(out_header.error, 0);

    // FUSE_LSEEK.
    /*
        Block this test until virtiofsd support illegal size message.

        assert_ne!(fuse_lseek(&fs, nodeid, fh + 1, 1).0.error, 0);
    */
    assert_ne!(fuse_lseek(&fs, nodeid, fh + 1, 0).0.error, 0);
    assert_eq!(fuse_lseek(&fs, nodeid, fh, 0).0.error, 0);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

// Note: Virtiofsd doesn't support illegal size message now, so trim will only support 0 until virtiofsd modification.
fn fuse_batch_forget(fs: &VirtioFsTest, nodeid: u64, trim: usize) {
    let len =
        size_of::<FuseInHeader>() + size_of::<FuseBatchForgetIn>() + size_of::<FuseForgetDataIn>();
    let fuse_in_head = FuseInHeader::new(len as u32, FUSE_BATCH_FORGET, 0, 0, 0, 0, 0, 0);
    let fuse_batch_forget_in = FuseBatchForgetIn { count: 1, dummy: 0 };
    let fuse_forget_data_in = FuseForgetDataIn {
        ino: nodeid,
        nlookup: 1,
    };
    let data_bytes = [
        fuse_batch_forget_in.as_bytes(),
        fuse_forget_data_in.as_bytes(),
    ]
    .concat();
    let (_, _) = fs.virtiofs_do_virtio_request(
        &fuse_in_head.as_bytes(),
        &data_bytes[0..data_bytes.len() - trim],
        &[0],
        &[0],
    );
}

#[test]
fn virtio_fs_fuse_batch_forget_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);

    // init filesystem.
    fuse_init(&fs);

    // FUSE_LOOKUP.
    let nodeid = fuse_lookup(&fs, TEST_FILE_NAME.to_string());

    // FUSE_BATCH_FORGET.

    /*
        Block these two test until virtiofsd support illegal size message.

        // Incomplete FuseBatchForgetIn.
        fuse_batch_forget(&fs, nodeid, size_of::<FuseForgetDataIn>() + 1);
        // Incomplete FuseForgetDataIn.
        fuse_batch_forget(&fs, nodeid, size_of::<FuseForgetDataIn>() - 1);
    */

    // Normal test.
    fuse_batch_forget(&fs, nodeid, 0);

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}

// Note: Virtiofsd does not support `SETLK` and `SETLKW` message, block this test case.
// flock.
#[test]
#[ignore]
fn virtio_fs_fuse_setlkw_test() {
    // start virtiofsd process.
    let (virtiofs_test_dir, virtiofs_sock, _virtiofs_test_file) = VirtioFsTest::virtiofsd_start();

    // start vm.
    let fs = VirtioFsTest::new(TEST_MEM_SIZE, TEST_PAGE_SIZE, virtiofs_sock);

    // init filesystem.
    fuse_init(&fs);

    // FUSE_LOOKUP.
    let nodeid = fuse_lookup(&fs, TEST_FILE_NAME.to_string());
    // FUSE_OPEN.
    let fh = fuse_open(&fs, nodeid);

    let reqs = [
        //(req_type, lk_flags, lock_type, fh, error),
        (0, 1, 0, fh, 0),      // Normal F_RDLCK test.
        (0, 1, 1, fh, 0),      // Normal F_WDLCK test.
        (0, 1, 2, fh, 0),      // Normal F_UNLCK test.
        (0, 0, 1, fh, -95),    // Abnormal test with error -libc::EOPNOTSUPP.
        (0, 1, 0, fh + 1, -9), // Abnormal test with error -libc::EBADF.
        (0, 1, 0, fh + 1, -9), // Abnormal test with error -libc::EBADF.
        (1, 1, 0, fh, -22),    // Abnormal test with error -libc::EINVAL.
    ];

    // FUSE_SETLKW.
    for (req_type, lk_flags, lock_type, fh, error) in reqs {
        let len = size_of::<FuseInHeader>() + size_of::<FuseLkIn>();
        let fuse_in_head = FuseInHeader::new(len as u32, FUSE_SETLKW, 0, nodeid, 0, 0, 0, 0);
        let fuse_lk_in = FuseLkIn {
            fh,
            owner: 0,
            lk: FuseFileLock {
                start: 0,
                end: 1,
                lock_type,
                pid: 0,
            },
            lk_flags,
            padding: 0,
        };
        let fuse_out_head = FuseOutHeader::default();
        let mut fuse_lk_in_bytes = fuse_lk_in.as_bytes();
        if req_type == 1 {
            fuse_lk_in_bytes = &fuse_lk_in.as_bytes()[0..1];
        }

        let (outheaderaddr, _outbodyaddr) = fs.virtiofs_do_virtio_request(
            &fuse_in_head.as_bytes(),
            &fuse_lk_in_bytes,
            &fuse_out_head.as_bytes(),
            &[0],
        );

        let out_header = read_obj::<FuseOutHeader>(fs.state.clone(), outheaderaddr);
        assert_eq!(out_header.error, error);
    }

    // kill process and clean env.
    fs.testcase_end(virtiofs_test_dir);
}
