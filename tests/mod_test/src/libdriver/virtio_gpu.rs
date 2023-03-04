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

use super::{
    machine::TestStdMachine,
    malloc::GuestAllocator,
    pci::{PCIBarAddr, TestPciDev, PCI_VENDOR_ID},
    pci_bus::TestPciBus,
};
use crate::libdriver::virtio::{TestVirtQueue, TestVringDescEntry, VirtioDeviceOps};
use crate::libdriver::virtio_pci_modern::TestVirtioPciDev;
use crate::libtest::{test_init, TestState};

use std::{cell::RefCell, mem::size_of, rc::Rc, slice::from_raw_parts, vec};
use util::byte_code::ByteCode;
use virtio::{
    VIRTIO_GPU_CMD_GET_DISPLAY_INFO, VIRTIO_GPU_CMD_GET_EDID,
    VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING, VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
    VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING, VIRTIO_GPU_CMD_RESOURCE_FLUSH,
    VIRTIO_GPU_CMD_RESOURCE_UNREF, VIRTIO_GPU_CMD_SET_SCANOUT, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
    VIRTIO_GPU_CMD_UPDATE_CURSOR,
};

const TIMEOUT_US: u64 = 15 * 1000 * 1000;

pub const VIRTIO_GPU_MAX_SCANOUTS: usize = 16;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuCtrlHdr {
    pub hdr_type: u32,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub padding: u32,
}

impl ByteCode for VirtioGpuCtrlHdr {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuRect {
    pub x_coord: u32,
    pub y_coord: u32,
    pub width: u32,
    pub height: u32,
}

impl VirtioGpuRect {
    pub fn new(x_coord: u32, y_coord: u32, width: u32, height: u32) -> Self {
        Self {
            x_coord,
            y_coord,
            width,
            height,
        }
    }
}

impl ByteCode for VirtioGpuRect {}

#[derive(Default, Clone, Copy)]
pub struct VirtioGpuDisplayOne {
    pub rect: VirtioGpuRect,
    pub enabled: u32,
    pub flags: u32,
}

impl ByteCode for VirtioGpuDisplayOne {}

#[allow(unused)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuDisplayInfo {
    pub header: VirtioGpuCtrlHdr,
    pmodes: [VirtioGpuDisplayOne; VIRTIO_GPU_MAX_SCANOUTS],
}
impl ByteCode for VirtioGpuDisplayInfo {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuGetEdid {
    pub scanouts: u32,
    pub padding: u32,
}

impl VirtioGpuGetEdid {
    pub fn new(scanouts: u32) -> Self {
        Self {
            scanouts,
            padding: 0,
        }
    }
}

impl ByteCode for VirtioGpuGetEdid {}

#[allow(unused)]
#[derive(Clone, Copy)]
pub struct VirtioGpuRespEdid {
    pub header: VirtioGpuCtrlHdr,
    pub size: u32,
    pub padding: u32,
    pub edid: [u8; 1024],
}

impl Default for VirtioGpuRespEdid {
    fn default() -> Self {
        VirtioGpuRespEdid {
            header: VirtioGpuCtrlHdr::default(),
            size: 0,
            padding: 0,
            edid: [0; 1024],
        }
    }
}

impl ByteCode for VirtioGpuRespEdid {}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct VirtioGpuResourceCreate2d {
    pub resource_id: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
}

impl VirtioGpuResourceCreate2d {
    pub fn new(resource_id: u32, format: u32, width: u32, height: u32) -> Self {
        Self {
            resource_id,
            format,
            width,
            height,
        }
    }
}

impl ByteCode for VirtioGpuResourceCreate2d {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuResourceUnref {
    pub resource_id: u32,
    pub padding: u32,
}

impl VirtioGpuResourceUnref {
    pub fn new(resource_id: u32) -> Self {
        Self {
            resource_id,
            padding: 0,
        }
    }
}

impl ByteCode for VirtioGpuResourceUnref {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuSetScanout {
    pub rect: VirtioGpuRect,
    pub scanout_id: u32,
    pub resource_id: u32,
}

impl VirtioGpuSetScanout {
    pub fn new(rect: VirtioGpuRect, scanout_id: u32, resource_id: u32) -> Self {
        Self {
            rect,
            scanout_id,
            resource_id,
        }
    }
}

impl ByteCode for VirtioGpuSetScanout {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuResourceFlush {
    pub rect: VirtioGpuRect,
    pub resource_id: u32,
    pub padding: u32,
}

impl VirtioGpuResourceFlush {
    pub fn new(rect: VirtioGpuRect, resource_id: u32) -> Self {
        Self {
            rect,
            resource_id,
            padding: 0,
        }
    }
}

impl ByteCode for VirtioGpuResourceFlush {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuTransferToHost2d {
    pub rect: VirtioGpuRect,
    pub offset: u64,
    pub resource_id: u32,
    pub padding: u32,
}

impl VirtioGpuTransferToHost2d {
    pub fn new(rect: VirtioGpuRect, offset: u64, resource_id: u32) -> Self {
        Self {
            rect,
            offset,
            resource_id,
            padding: 0,
        }
    }
}

impl ByteCode for VirtioGpuTransferToHost2d {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuResourceAttachBacking {
    pub resource_id: u32,
    pub nr_entries: u32,
}

impl VirtioGpuResourceAttachBacking {
    pub fn new(resource_id: u32, nr_entries: u32) -> Self {
        Self {
            resource_id,
            nr_entries,
        }
    }
}

impl ByteCode for VirtioGpuResourceAttachBacking {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuMemEntry {
    pub addr: u64,
    pub length: u32,
    pub padding: u32,
}

impl VirtioGpuMemEntry {
    pub fn new(addr: u64, length: u32) -> Self {
        Self {
            addr,
            length,
            padding: 0,
        }
    }
}

impl ByteCode for VirtioGpuMemEntry {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuResourceDetachBacking {
    pub resource_id: u32,
    pub padding: u32,
}

impl VirtioGpuResourceDetachBacking {
    pub fn new(resource_id: u32) -> Self {
        Self {
            resource_id,
            padding: 0,
        }
    }
}

impl ByteCode for VirtioGpuResourceDetachBacking {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuCursorPos {
    pub scanout_id: u32,
    pub x_coord: u32,
    pub y_coord: u32,
    pub padding: u32,
}

impl ByteCode for VirtioGpuCursorPos {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuUpdateCursor {
    pub pos: VirtioGpuCursorPos,
    pub resource_id: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub padding: u32,
}

impl ByteCode for VirtioGpuUpdateCursor {}

#[derive(Debug, Clone, Copy)]
pub enum DpyEvent {
    QuerySurface = 0,
    QueryCursor = 1,
    GetSurface = 2,
    GetCursor = 3,
    Deactive = 4,
}

pub struct TestDemoDpyDevice {
    pub pci_dev: TestPciDev,
    pub bar_addr: PCIBarAddr,
    bar_idx: u8,
    allocator: Rc<RefCell<GuestAllocator>>,
}

pub struct TestVirtioGpu {
    pub device: Rc<RefCell<TestVirtioPciDev>>,
    pub allocator: Rc<RefCell<GuestAllocator>>,
    pub state: Rc<RefCell<TestState>>,
    pub ctrl_q: Rc<RefCell<TestVirtQueue>>,
    pub cursor_q: Rc<RefCell<TestVirtQueue>>,
}

impl TestDemoDpyDevice {
    pub fn new(pci_bus: Rc<RefCell<TestPciBus>>, allocator: Rc<RefCell<GuestAllocator>>) -> Self {
        Self {
            pci_dev: TestPciDev::new(pci_bus),
            bar_addr: 0,
            bar_idx: 0,
            allocator,
        }
    }

    pub fn deactive(&mut self) {
        let addr = self.allocator.borrow_mut().alloc(1);
        self.pci_dev
            .io_writeq(self.bar_addr, DpyEvent::Deactive as u64, addr);
    }

    pub fn query_surface(&mut self) -> u16 {
        let addr = self.allocator.borrow_mut().alloc(size_of::<u16>() as u64);
        let test_state = self.pci_dev.pci_bus.borrow_mut().test_state.clone();
        self.pci_dev
            .io_writeq(self.bar_addr, DpyEvent::QuerySurface as u64, addr);
        return test_state.borrow_mut().readw(addr);
    }

    pub fn query_cursor(&mut self) -> u16 {
        let addr = self.allocator.borrow_mut().alloc(size_of::<u16>() as u64);
        let test_state = self.pci_dev.pci_bus.borrow_mut().test_state.clone();
        self.pci_dev
            .io_writeq(self.bar_addr, DpyEvent::QueryCursor as u64, addr);
        return test_state.borrow_mut().readw(addr);
    }

    pub fn get_surface(&mut self, size: u64) -> Vec<u8> {
        let addr = self.allocator.borrow_mut().alloc(size_of::<u16>() as u64);
        let test_state = self.pci_dev.pci_bus.borrow_mut().test_state.clone();
        self.pci_dev
            .io_writeq(self.bar_addr, DpyEvent::GetSurface as u64, addr);
        return test_state.borrow_mut().memread(addr, size);
    }

    pub fn get_cursor(&mut self, size: u64) -> Vec<u8> {
        let addr = self.allocator.borrow_mut().alloc(size_of::<u16>() as u64);
        let test_state = self.pci_dev.pci_bus.borrow_mut().test_state.clone();
        self.pci_dev
            .io_writeq(self.bar_addr, DpyEvent::GetCursor as u64, addr);
        return test_state.borrow_mut().memread(addr, size);
    }

    pub fn set_devfn(&mut self, devfn: u8) {
        self.pci_dev.devfn = devfn;
    }

    pub fn find_pci_device(&mut self, devfn: u8) -> bool {
        self.set_devfn(devfn);
        if self.pci_dev.config_readw(PCI_VENDOR_ID) == 0xFFFF {
            return false;
        }
        true
    }

    pub fn init(&mut self, pci_slot: u8) {
        let devfn = pci_slot << 3;
        assert!(self.find_pci_device(devfn));

        self.pci_dev.enable();
        self.bar_addr = self.pci_dev.io_map(self.bar_idx);
    }
}

impl TestVirtioGpu {
    pub fn new(
        pci_bus: Rc<RefCell<TestPciBus>>,
        allocator: Rc<RefCell<GuestAllocator>>,
        state: Rc<RefCell<TestState>>,
    ) -> Self {
        Self {
            device: Rc::new(RefCell::new(TestVirtioPciDev::new(pci_bus))),
            allocator,
            state: state,
            ctrl_q: Rc::new(RefCell::new(TestVirtQueue::new())),
            cursor_q: Rc::new(RefCell::new(TestVirtQueue::new())),
        }
    }

    pub fn init(&mut self, pci_slot: u8, pci_fn: u8) {
        self.device.borrow_mut().init(pci_slot, pci_fn);
        self.device.borrow_mut().pci_dev.enable_msix(None);
        self.device
            .borrow_mut()
            .setup_msix_configuration_vector(self.allocator.clone(), 0);
        let features = self.device.borrow_mut().get_device_features();
        self.device.borrow_mut().negotiate_features(features);
        self.device.borrow_mut().set_features_ok();

        let ctrl_q =
            self.device
                .borrow_mut()
                .setup_virtqueue(self.state.clone(), self.allocator.clone(), 0);
        self.device
            .borrow_mut()
            .setup_virtqueue_intr(1, self.allocator.clone(), ctrl_q.clone());
        let cursor_q =
            self.device
                .borrow_mut()
                .setup_virtqueue(self.state.clone(), self.allocator.clone(), 1);
        self.device
            .borrow_mut()
            .setup_virtqueue_intr(2, self.allocator.clone(), cursor_q.clone());

        self.ctrl_q = ctrl_q.clone();
        self.cursor_q = cursor_q.clone();

        self.device.borrow_mut().set_driver_ok();
    }

    pub fn request_complete<T: ByteCode>(
        &mut self,
        ctrl_q: bool,
        hdr: &[u8],
        hdr_ctx: Option<&[u8]>,
        ctx: Option<&[u8]>,
        resp: Option<&mut T>,
    ) {
        let mut offset = 0;
        let mut vec = Vec::new();
        let hdr_len = hdr.len() as u64;
        let mut hdr_ctx_len = 0;
        if hdr_ctx.is_some() {
            hdr_ctx_len = hdr_ctx.as_ref().unwrap().len() as u64;
        }
        let mut ctx_len = 0;
        if ctx.is_some() {
            ctx_len = ctx.as_ref().unwrap().len() as u64;
        }
        let mut resp_len = 0;
        if resp.is_some() {
            resp_len = size_of::<T>() as u64;
        }

        let addr = self
            .allocator
            .borrow_mut()
            .alloc(hdr_len + hdr_ctx_len + ctx_len + resp_len);

        // write first
        self.state.borrow().memwrite(addr, hdr);

        let mut tmp = TestVringDescEntry::default();

        if hdr_ctx.is_some() {
            self.state
                .borrow()
                .memwrite(addr + hdr_len, hdr_ctx.unwrap());
            let mut tmp = TestVringDescEntry::default();
            tmp.data = addr;
            tmp.len = (hdr_len + hdr_ctx_len) as u32;
            tmp.write = false;
            vec.push(tmp);
            offset += hdr_len + hdr_ctx_len;
        } else {
            tmp.data = addr;
            tmp.len = hdr_len as u32;
            tmp.write = false;
            vec.push(tmp);
            offset += hdr_len;
        }

        if ctx.is_some() {
            self.state.borrow().memwrite(addr + offset, ctx.unwrap());
            let mut tmp = TestVringDescEntry::default();
            tmp.data = addr + offset;
            tmp.len = ctx_len as u32;
            tmp.write = false;
            vec.push(tmp);
            offset += ctx_len;
        }

        if resp.is_some() {
            self.state
                .borrow()
                .memwrite(addr + offset, resp.as_ref().unwrap().as_bytes());
            let mut tmp = TestVringDescEntry::default();
            tmp.data = addr + offset;
            tmp.len = resp_len as u32;
            tmp.write = true;
            vec.push(tmp);
        }

        if ctrl_q {
            let free_head = self
                .ctrl_q
                .borrow_mut()
                .add_chained(self.state.clone(), vec);

            self.device
                .borrow_mut()
                .kick_virtqueue(self.state.clone(), self.ctrl_q.clone());

            self.device.borrow_mut().poll_used_elem(
                self.state.clone(),
                self.ctrl_q.clone(),
                free_head,
                TIMEOUT_US,
                &mut None,
                true,
            );
        } else {
            let free_head = self
                .cursor_q
                .borrow_mut()
                .add_chained(self.state.clone(), vec);

            self.device
                .borrow_mut()
                .kick_virtqueue(self.state.clone(), self.cursor_q.clone());

            self.device.borrow_mut().poll_used_elem(
                self.state.clone(),
                self.cursor_q.clone(),
                free_head,
                TIMEOUT_US,
                &mut None,
                true,
            );
        }

        if resp.is_some() {
            let resp_bytes_new = self
                .state
                .borrow_mut()
                .memread(addr + hdr_len + hdr_ctx_len + ctx_len, resp_len);

            let slice =
                unsafe { from_raw_parts(resp_bytes_new.as_ptr() as *const T, size_of::<T>()) };

            *resp.unwrap() = slice[0].clone();
        }
    }
}

#[derive(Clone, Debug)]
pub struct GpuDevConfig {
    pub id: String,
    pub max_outputs: u32,
    pub edid: bool,
    pub xres: u32,
    pub yres: u32,
    pub max_hostmem: u64,
}

impl Default for GpuDevConfig {
    fn default() -> Self {
        Self {
            id: String::from("gpu"),
            max_outputs: 1,
            edid: true,
            xres: 1024,
            yres: 768,
            max_hostmem: 1024 * 1024 * 4,
        }
    }
}

pub fn set_up(
    gpu_conf: &GpuDevConfig,
) -> (Rc<RefCell<TestDemoDpyDevice>>, Rc<RefCell<TestVirtioGpu>>) {
    let gpu_pci_slot: u8 = 0x4;
    let gpu_pci_fn: u8 = 0x0;
    let dpy_pci_slot: u8 = 0x3;
    let dpy_pci_fn: u8 = 0x0;

    let mut args: Vec<String> = Vec::new();
    // vm args
    let vm_args = String::from("-machine virt");
    let vm_args: Vec<&str> = vm_args[..].split(' ').collect();
    let mut vm_args = vm_args.into_iter().map(|s| s.to_string()).collect();
    args.append(&mut vm_args);
    // log args
    let log_args = String::from("-D /tmp/virtio_gpu_test_log");
    let log_args: Vec<&str> = log_args[..].split(' ').collect();
    let mut log_args = log_args.into_iter().map(|s| s.to_string()).collect();
    args.append(&mut log_args);
    // virtio-gpu args
    let gpu_args = format!(
        "-device virtio-gpu-pci,id=drv0,bus=pcie.{},addr={}.0,max_hostmem={}",
        gpu_pci_fn, gpu_pci_slot, gpu_conf.max_hostmem
    );
    let gpu_args: Vec<&str> = gpu_args[..].split(' ').collect();
    let mut gpu_args = gpu_args.into_iter().map(|s| s.to_string()).collect();
    args.append(&mut gpu_args);
    // demo dpy device args
    let dpy_args = format!(
        "-device pcie-demo-dev,bus=pcie.{},addr={}.0,id=1,\
        bar_num=3,device_type=demo-display,bar_size=4096",
        dpy_pci_fn, dpy_pci_slot
    );
    let dpy_args: Vec<&str> = dpy_args[..].split(' ').collect();
    let mut dpy_args = dpy_args.into_iter().map(|s| s.to_string()).collect();
    args.append(&mut dpy_args);
    let args = args.iter().map(AsRef::as_ref).collect();

    let test_state = Rc::new(RefCell::new(test_init(args)));
    let machine = TestStdMachine::new_bymem(test_state.clone(), 1280 * 1024 * 1024, 4096);
    let allocator = machine.allocator.clone();

    let demo_dpy = Rc::new(RefCell::new(TestDemoDpyDevice::new(
        machine.pci_bus.clone(),
        allocator.clone(),
    )));
    demo_dpy.borrow_mut().init(dpy_pci_slot);

    let virtgpu = Rc::new(RefCell::new(TestVirtioGpu::new(
        machine.pci_bus.clone(),
        allocator.clone(),
        test_state.clone(),
    )));
    virtgpu.borrow_mut().init(gpu_pci_slot, gpu_pci_fn);

    (demo_dpy, virtgpu)
}

pub fn tear_down(dpy: Rc<RefCell<TestDemoDpyDevice>>, gpu: Rc<RefCell<TestVirtioGpu>>) {
    dpy.borrow_mut().deactive();
    gpu.borrow_mut().state.borrow_mut().stop();
}

// VIRTIO_GPU_CMD_GET_DISPLAY_INFO
pub fn get_display_info(gpu: &Rc<RefCell<TestVirtioGpu>>) -> VirtioGpuDisplayInfo {
    let mut hdr = VirtioGpuCtrlHdr::default();
    hdr.hdr_type = VIRTIO_GPU_CMD_GET_DISPLAY_INFO;

    let mut resp = VirtioGpuDisplayInfo::default();

    gpu.borrow_mut()
        .request_complete(true, hdr.as_bytes(), None, None, Some(&mut resp));
    return resp;
}

// VIRTIO_GPU_CMD_GET_EDID
pub fn get_edid(gpu: &Rc<RefCell<TestVirtioGpu>>, hdr_ctx: VirtioGpuGetEdid) -> VirtioGpuRespEdid {
    let mut hdr = VirtioGpuCtrlHdr::default();

    hdr.hdr_type = VIRTIO_GPU_CMD_GET_EDID;

    let mut resp = VirtioGpuRespEdid::default();

    gpu.borrow_mut().request_complete(
        true,
        hdr.as_bytes(),
        Some(hdr_ctx.as_bytes()),
        None,
        Some(&mut resp),
    );
    return resp;
}

pub fn current_curosr_check(dpy: &Rc<RefCell<TestDemoDpyDevice>>, local: &Vec<u8>) -> bool {
    let size = dpy.borrow_mut().query_cursor();
    if size as usize != local.len() {
        return false;
    }
    let remote = dpy.borrow_mut().get_cursor(size as u64);

    for (i, v) in remote.iter().enumerate() {
        if v != local.get(i).unwrap() {
            return false;
        }
    }
    true
}

pub fn current_surface_check(dpy: &Rc<RefCell<TestDemoDpyDevice>>, local: &Vec<u8>) -> bool {
    let size = dpy.borrow_mut().query_surface();
    if size as usize != local.len() {
        return false;
    }
    let remote = dpy.borrow_mut().get_surface(size as u64);

    for (i, v) in remote.iter().enumerate() {
        if v != local.get(i).unwrap() {
            return false;
        }
    }
    true
}

// VIRTIO_GPU_CMD_RESOURCE_CREATE_2D
pub fn resource_create(
    gpu: &Rc<RefCell<TestVirtioGpu>>,
    hdr_ctx: VirtioGpuResourceCreate2d,
) -> VirtioGpuCtrlHdr {
    let mut hdr = VirtioGpuCtrlHdr::default();

    hdr.hdr_type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D;

    let mut resp = VirtioGpuCtrlHdr::default();

    gpu.borrow_mut().request_complete(
        true,
        hdr.as_bytes(),
        Some(hdr_ctx.as_bytes()),
        None,
        Some(&mut resp),
    );
    return resp;
}

// VIRTIO_GPU_CMD_RESOURCE_UNREF
pub fn resource_unref(
    gpu: &Rc<RefCell<TestVirtioGpu>>,
    hdr_ctx: VirtioGpuResourceUnref,
) -> VirtioGpuCtrlHdr {
    let mut hdr = VirtioGpuCtrlHdr::default();

    hdr.hdr_type = VIRTIO_GPU_CMD_RESOURCE_UNREF;

    let mut resp = VirtioGpuCtrlHdr::default();

    gpu.borrow_mut().request_complete(
        true,
        hdr.as_bytes(),
        Some(hdr_ctx.as_bytes()),
        None,
        Some(&mut resp),
    );
    return resp;
}

// VIRTIO_GPU_CMD_RESOURCE_FLUSH
pub fn resource_flush(
    gpu: &Rc<RefCell<TestVirtioGpu>>,
    hdr_ctx: VirtioGpuResourceFlush,
) -> VirtioGpuCtrlHdr {
    let mut hdr = VirtioGpuCtrlHdr::default();

    hdr.hdr_type = VIRTIO_GPU_CMD_RESOURCE_FLUSH;

    let mut resp = VirtioGpuCtrlHdr::default();

    gpu.borrow_mut().request_complete(
        true,
        hdr.as_bytes(),
        Some(hdr_ctx.as_bytes()),
        None,
        Some(&mut resp),
    );
    return resp;
}

// VIRTIO_GPU_CMD_UPDATE_CURSOR
pub fn update_cursor(gpu: &Rc<RefCell<TestVirtioGpu>>, resource_id: u32, scanout_id: u32) {
    let mut hdr = VirtioGpuCtrlHdr::default();

    hdr.hdr_type = VIRTIO_GPU_CMD_UPDATE_CURSOR;

    let mut hdr_ctx = VirtioGpuUpdateCursor::default();

    hdr_ctx.pos.scanout_id = scanout_id;
    hdr_ctx.resource_id = resource_id;

    gpu.borrow_mut().request_complete::<VirtioGpuCtrlHdr>(
        false,
        hdr.as_bytes(),
        Some(hdr_ctx.as_bytes()),
        None,
        None,
    );
}

// VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING
pub fn resource_attach_backing(
    gpu: &Rc<RefCell<TestVirtioGpu>>,
    hdr_ctx: VirtioGpuResourceAttachBacking,
    ctxs: Vec<VirtioGpuMemEntry>,
) -> VirtioGpuCtrlHdr {
    let mut hdr = VirtioGpuCtrlHdr::default();

    hdr.hdr_type = VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING;

    let mut ctx: Vec<u8> = vec![];
    for i in ctxs {
        // let tmp = &i;
        // let mut tmp = tmp.as_bytes().to_vec();
        ctx.append(&mut i.as_bytes().to_vec());
    }

    let mut resp = VirtioGpuCtrlHdr::default();

    gpu.borrow_mut().request_complete(
        true,
        hdr.as_bytes(),
        Some(hdr_ctx.as_bytes()),
        Some(&ctx),
        Some(&mut resp),
    );
    return resp;
}

pub fn resource_attach_backing_with_invalid_ctx_len(
    gpu: &Rc<RefCell<TestVirtioGpu>>,
    hdr_ctx: VirtioGpuResourceAttachBacking,
) -> VirtioGpuCtrlHdr {
    let mut hdr = VirtioGpuCtrlHdr::default();

    hdr.hdr_type = VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING;

    let mut resp = VirtioGpuCtrlHdr::default();

    gpu.borrow_mut().request_complete(
        true,
        hdr.as_bytes(),
        Some(hdr_ctx.as_bytes()),
        None,
        Some(&mut resp),
    );
    return resp;
}

// VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING
pub fn resource_detach_backing(
    gpu: &Rc<RefCell<TestVirtioGpu>>,
    hdr_ctx: VirtioGpuResourceDetachBacking,
) -> VirtioGpuCtrlHdr {
    let mut hdr = VirtioGpuCtrlHdr::default();

    hdr.hdr_type = VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING;

    let mut resp = VirtioGpuCtrlHdr::default();

    gpu.borrow_mut().request_complete(
        true,
        hdr.as_bytes(),
        Some(hdr_ctx.as_bytes()),
        None,
        Some(&mut resp),
    );
    return resp;
}

// VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D
pub fn transfer_to_host(
    gpu: &Rc<RefCell<TestVirtioGpu>>,
    hdr_ctx: VirtioGpuTransferToHost2d,
) -> VirtioGpuCtrlHdr {
    let mut hdr = VirtioGpuCtrlHdr::default();
    hdr.hdr_type = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D;

    let mut resp = VirtioGpuCtrlHdr::default();

    gpu.borrow_mut().request_complete(
        true,
        hdr.as_bytes(),
        Some(hdr_ctx.as_bytes()),
        None,
        Some(&mut resp),
    );
    return resp;
}

// VIRTIO_GPU_CMD_SET_SCANOUT
pub fn set_scanout(
    gpu: &Rc<RefCell<TestVirtioGpu>>,
    hdr_ctx: VirtioGpuSetScanout,
) -> VirtioGpuCtrlHdr {
    let mut hdr = VirtioGpuCtrlHdr::default();

    hdr.hdr_type = VIRTIO_GPU_CMD_SET_SCANOUT;

    let mut resp = VirtioGpuCtrlHdr::default();

    gpu.borrow_mut().request_complete(
        true,
        hdr.as_bytes(),
        Some(hdr_ctx.as_bytes()),
        None,
        Some(&mut resp),
    );
    return resp;
}

pub fn invalid_cmd_test(gpu: &Rc<RefCell<TestVirtioGpu>>) -> VirtioGpuCtrlHdr {
    let mut hdr = VirtioGpuCtrlHdr::default();
    hdr.hdr_type = VIRTIO_GPU_CMD_GET_DISPLAY_INFO - 1;

    let mut resp = VirtioGpuCtrlHdr::default();

    gpu.borrow_mut()
        .request_complete(true, hdr.as_bytes(), None, None, Some(&mut resp));
    return resp;
}
