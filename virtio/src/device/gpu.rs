// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::slice::from_raw_parts_mut;
use std::sync::{Arc, Mutex, Weak};
use std::{ptr, vec};

use anyhow::{anyhow, bail, Context, Result};
use log::{error, info, warn};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use crate::{
    check_config_space_rw, gpa_hva_iovec_map, iov_discard_front, iov_to_buf, read_config_default,
    ElemIovec, Element, Queue, VirtioBase, VirtioDevice, VirtioDeviceQuirk, VirtioError,
    VirtioInterrupt, VirtioInterruptType, VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_RING_INDIRECT_DESC,
    VIRTIO_F_VERSION_1, VIRTIO_GPU_CMD_GET_DISPLAY_INFO, VIRTIO_GPU_CMD_GET_EDID,
    VIRTIO_GPU_CMD_MOVE_CURSOR, VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_2D, VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
    VIRTIO_GPU_CMD_RESOURCE_FLUSH, VIRTIO_GPU_CMD_RESOURCE_UNREF, VIRTIO_GPU_CMD_SET_SCANOUT,
    VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D, VIRTIO_GPU_CMD_UPDATE_CURSOR, VIRTIO_GPU_FLAG_FENCE,
    VIRTIO_GPU_F_EDID, VIRTIO_GPU_F_MONOCHROME, VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
    VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID,
    VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY, VIRTIO_GPU_RESP_ERR_UNSPEC, VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
    VIRTIO_GPU_RESP_OK_EDID, VIRTIO_GPU_RESP_OK_NODATA, VIRTIO_TYPE_GPU,
};
use address_space::{AddressSpace, FileBackend, GuestAddress};
use machine_manager::config::{GpuDevConfig, DEFAULT_VIRTQUEUE_SIZE, VIRTIO_GPU_MAX_OUTPUTS};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use migration_derive::ByteCode;
use ui::console::{
    console_close, console_init, display_cursor_define, display_graphic_update,
    display_replace_surface, display_set_major_screen, get_run_stage, set_run_stage, ConsoleType,
    DisplayConsole, DisplayMouse, DisplaySurface, HardWareOperations, VmRunningStage,
};
use ui::pixman::{
    create_pixman_image, get_image_data, get_image_format, get_image_height, get_image_stride,
    get_image_width, ref_pixman_image, unref_pixman_image,
};
use util::aio::{iov_from_buf_direct, iov_to_buf_direct, Iovec};
use util::byte_code::ByteCode;
use util::edid::EdidInfo;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::pixman::{
    pixman_format_bpp, pixman_format_code_t, pixman_image_set_destroy_function, pixman_image_t,
    pixman_region16_t, pixman_region_extents, pixman_region_fini, pixman_region_init,
    pixman_region_init_rect, pixman_region_intersect, pixman_region_translate,
    virtio_gpu_unref_resource_callback,
};

/// Number of virtqueues
const QUEUE_NUM_GPU: usize = 2;
/// Display changed event
const VIRTIO_GPU_EVENT_DISPLAY: u32 = 1 << 0;

/// The flag indicates that the frame buffer only used in windows.
const VIRTIO_GPU_RES_WIN_FRAMEBUF: u32 = 0x80000000;
/// The flag indicates that the frame buffer only used in special bios phase for windows.
const VIRTIO_GPU_RES_EFI_FRAMEBUF: u32 = 0x40000000;
const VIRTIO_GPU_RES_FRAMEBUF: u32 = VIRTIO_GPU_RES_WIN_FRAMEBUF | VIRTIO_GPU_RES_EFI_FRAMEBUF;

#[derive(Debug)]
struct GpuResource {
    resource_id: u32,
    width: u32,
    height: u32,
    format: u32,
    iov: Vec<Iovec>,
    scanouts_bitmask: u32,
    host_mem: u64,
    pixman_image: *mut pixman_image_t,
    monochrome_cursor: Vec<u8>,
}

impl Default for GpuResource {
    fn default() -> Self {
        GpuResource {
            resource_id: 0,
            width: 0,
            height: 0,
            format: 0,
            iov: Vec::new(),
            scanouts_bitmask: 0,
            host_mem: 0,
            pixman_image: ptr::null_mut(),
            monochrome_cursor: Vec::new(),
        }
    }
}

#[allow(unused)]
#[derive(Default, Clone, Copy)]
struct VirtioGpuOutputState {
    con_id: usize,
    width: u32,
    height: u32,
    x_coor: i32,
    y_coor: i32,
}

trait CtrlHdr {
    fn mut_ctrl_hdr(&mut self) -> &mut VirtioGpuCtrlHdr;
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct VirtioGpuCtrlHdr {
    hdr_type: u32,
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuCtrlHdr {}

impl CtrlHdr for VirtioGpuCtrlHdr {
    fn mut_ctrl_hdr(&mut self) -> &mut VirtioGpuCtrlHdr {
        self
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct VirtioGpuRect {
    x_coord: u32,
    y_coord: u32,
    width: u32,
    height: u32,
}

impl ByteCode for VirtioGpuRect {}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct VirtioGpuDisplayOne {
    rect: VirtioGpuRect,
    enabled: u32,
    flags: u32,
}

impl ByteCode for VirtioGpuDisplayOne {}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct VirtioGpuDisplayInfo {
    header: VirtioGpuCtrlHdr,
    pmodes: [VirtioGpuDisplayOne; VIRTIO_GPU_MAX_OUTPUTS],
}

impl ByteCode for VirtioGpuDisplayInfo {}

impl CtrlHdr for VirtioGpuDisplayInfo {
    fn mut_ctrl_hdr(&mut self) -> &mut VirtioGpuCtrlHdr {
        &mut self.header
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VirtioGpuGetEdid {
    scanouts: u32,
    padding: u32,
}
impl ByteCode for VirtioGpuGetEdid {}

#[repr(C)]
// data which transfer to frontend need padding
#[derive(Clone, Copy)]
struct VirtioGpuRespEdid {
    header: VirtioGpuCtrlHdr,
    size: u32,
    padding: u32,
    edid: [u8; 1024],
}

impl ByteCode for VirtioGpuRespEdid {}

impl CtrlHdr for VirtioGpuRespEdid {
    fn mut_ctrl_hdr(&mut self) -> &mut VirtioGpuCtrlHdr {
        &mut self.header
    }
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

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VirtioGpuResourceCreate2d {
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
}

impl ByteCode for VirtioGpuResourceCreate2d {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VirtioGpuResourceUnref {
    resource_id: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuResourceUnref {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VirtioGpuSetScanout {
    rect: VirtioGpuRect,
    scanout_id: u32,
    resource_id: u32,
}

impl ByteCode for VirtioGpuSetScanout {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VirtioGpuResourceFlush {
    rect: VirtioGpuRect,
    resource_id: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuResourceFlush {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VirtioGpuTransferToHost2d {
    rect: VirtioGpuRect,
    offset: u64,
    resource_id: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuTransferToHost2d {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VirtioGpuResourceAttachBacking {
    resource_id: u32,
    nr_entries: u32,
}

impl ByteCode for VirtioGpuResourceAttachBacking {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VirtioGpuMemEntry {
    addr: u64,
    length: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuMemEntry {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VirtioGpuResourceDetachBacking {
    resource_id: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuResourceDetachBacking {}

struct GpuOpts {
    /// Status of the emulated physical outputs.
    output_states: Arc<Mutex<[VirtioGpuOutputState; VIRTIO_GPU_MAX_OUTPUTS]>>,
    /// Config space of the GPU device.
    config_space: Arc<Mutex<VirtioGpuConfig>>,
    /// Callback to trigger interrupt.
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    /// Whether to use it in the bios phase.
    enable_bar0: bool,
}

impl HardWareOperations for GpuOpts {
    fn hw_update(&self, con: Arc<Mutex<DisplayConsole>>) {
        // Only in the Bios phase and configured with enable_bar0 feature and need to
        // use special modifications with edk2.
        if !self.enable_bar0 || get_run_stage() != VmRunningStage::Bios {
            return;
        }

        let locked_con = con.lock().unwrap();
        if locked_con.surface.is_none() {
            return;
        }
        let width = locked_con.width;
        let height = locked_con.height;
        trace::virtio_gpu_console_hw_update(locked_con.con_id, width, height);
        drop(locked_con);
        display_graphic_update(&Some(Arc::downgrade(&con)), 0, 0, width, height)
            .unwrap_or_else(|e| error!("Error occurs during graphic updating: {:?}", e));
    }

    fn hw_ui_info(&self, con: Arc<Mutex<DisplayConsole>>, width: u32, height: u32) {
        let con_id = con.lock().unwrap().con_id;

        // Update output size.
        for output_state in self.output_states.lock().unwrap().iter_mut() {
            if output_state.con_id == con_id {
                output_state.width = width;
                output_state.height = height;
                break;
            }
        }

        // Update events_read in config sapce.
        let mut config_space = self.config_space.lock().unwrap();
        config_space.events_read |= VIRTIO_GPU_EVENT_DISPLAY;

        if self.interrupt_cb.is_none() {
            return;
        }
        info!(
            "virtio-gpu receive resize request, con {} will be resize to {} {}.",
            con_id, width, height
        );
        let interrupt_cb = self.interrupt_cb.as_ref().unwrap();
        if let Err(e) = (interrupt_cb)(&VirtioInterruptType::Config, None, false) {
            error!(
                "{:?}. {:?}",
                VirtioError::InterruptTrigger("gpu", VirtioInterruptType::Config),
                e
            );
        }
    }
}

#[derive(Default, Clone)]
struct VirtioGpuRequest {
    header: VirtioGpuCtrlHdr,
    index: u16,
    out_iovec: Vec<Iovec>,
    out_len: u32,
    in_iovec: Vec<Iovec>,
    _in_len: u32,
}

impl VirtioGpuRequest {
    fn new(mem_space: &Arc<AddressSpace>, elem: &mut Element) -> Result<Self> {
        // Report errors for out_iovec invalid here, deal with in_iovec
        // error in cmd process.
        if elem.out_iovec.is_empty() {
            bail!(
                "Missed header for gpu request: out {} in {} desc num {}.",
                elem.out_iovec.len(),
                elem.in_iovec.len(),
                elem.desc_num
            );
        }

        let mut header = VirtioGpuCtrlHdr::default();
        iov_to_buf(mem_space, &elem.out_iovec, header.as_mut_bytes()).and_then(|size| {
            if size < size_of::<VirtioGpuCtrlHdr>() {
                bail!("Invalid header for gpu request: len {}.", size)
            }
            Ok(())
        })?;

        // Size of out_iovec is no less than size of VirtioGpuCtrlHdr, so
        // it is possible to get none back.
        let data_iovec =
            iov_discard_front(&mut elem.out_iovec, size_of::<VirtioGpuCtrlHdr>() as u64)
                .unwrap_or_default();

        let (out_len, out_iovec) = gpa_hva_iovec_map(data_iovec, mem_space)?;
        let (in_len, in_iovec) = gpa_hva_iovec_map(&elem.in_iovec, mem_space)?;

        // Note: in_iov and out_iov total len is no more than 1<<32, and
        // out_iov is more than 1, so in_len and out_len will not overflow.
        Ok(VirtioGpuRequest {
            header,
            index: elem.index,
            out_iovec,
            out_len: out_len as u32,
            in_iovec,
            _in_len: in_len as u32,
        })
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VirtioGpuCursorPos {
    scanout_id: u32,
    x_coord: u32,
    y_coord: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuCursorPos {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VirtioGpuUpdateCursor {
    pos: VirtioGpuCursorPos,
    resource_id: u32,
    hot_x: u32,
    hot_y: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuUpdateCursor {}

#[derive(Default)]
struct GpuScanout {
    con: Option<Weak<Mutex<DisplayConsole>>>,
    surface: Option<DisplaySurface>,
    mouse: Option<DisplayMouse>,
    width: u32,
    height: u32,
    x: u32,
    y: u32,
    resource_id: u32,
    cursor_visible: bool,
}

impl GpuScanout {
    fn clear(&mut self) {
        self.resource_id = 0;
        self.surface = None;
        self.width = 0;
        self.height = 0;
        self.cursor_visible = false;
    }
}

/// Control block of GPU IO.
struct GpuIoHandler {
    /// The virtqueue for for sending control commands.
    ctrl_queue: Arc<Mutex<Queue>>,
    /// The virtqueue for sending cursor updates.
    cursor_queue: Arc<Mutex<Queue>>,
    /// The address space to which the GPU device belongs.
    mem_space: Arc<AddressSpace>,
    /// Eventfd for control virtqueue.
    ctrl_queue_evt: Arc<EventFd>,
    /// Eventfd for cursor virtqueue.
    cursor_queue_evt: Arc<EventFd>,
    /// Callback to trigger an interrupt.
    interrupt_cb: Arc<VirtioInterrupt>,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Vector for resources.
    resources_list: Vec<GpuResource>,
    /// The bit mask of whether scanout is enabled or not.
    enable_output_bitmask: u32,
    /// The number of scanouts
    num_scanouts: u32,
    /// States of all output_states.
    output_states: Arc<Mutex<[VirtioGpuOutputState; VIRTIO_GPU_MAX_OUTPUTS]>>,
    /// Scanouts of gpu, mouse doesn't realize copy trait, so it is a vector.
    scanouts: Vec<GpuScanout>,
    /// Max host mem for resource.
    max_hostmem: u64,
    /// Current usage of host mem.
    used_hostmem: u64,
}

fn create_surface(
    scanout: &mut GpuScanout,
    info_set_scanout: VirtioGpuSetScanout,
    res: &GpuResource,
    pixman_format: pixman_format_code_t,
    pixman_stride: libc::c_int,
    res_data_offset: *mut u32,
) -> DisplaySurface {
    let mut surface = DisplaySurface::default();
    let rect = create_pixman_image(
        pixman_format,
        info_set_scanout.rect.width as i32,
        info_set_scanout.rect.height as i32,
        res_data_offset,
        pixman_stride,
    );
    ref_pixman_image(res.pixman_image);
    // SAFETY: The param of create operation for image has been checked.
    unsafe {
        pixman_image_set_destroy_function(
            rect,
            Some(virtio_gpu_unref_resource_callback),
            res.pixman_image.cast(),
        );
    }
    surface.format = pixman_format;
    surface.image = ref_pixman_image(rect);

    if !surface.image.is_null() {
        // Update surface in scanout.
        scanout.surface = Some(surface);
        unref_pixman_image(rect);
        display_replace_surface(&scanout.con, scanout.surface)
            .unwrap_or_else(|e| error!("Error occurs during surface switching: {:?}", e));
    }

    surface
}

// simple formats for fbcon/X use
const VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;
const VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: u32 = 2;
const VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM: u32 = 3;
const VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM: u32 = 4;
const VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM: u32 = 67;
const VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM: u32 = 68;
const VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM: u32 = 121;
const VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM: u32 = 134;
const VIRTIO_GPU_FORMAT_MONOCHROME: u32 = 500;
pub const VIRTIO_GPU_FORMAT_INVALID_UNORM: u32 = 135;
const VIRTIO_GPU_CURSOR_SIZE: usize = 64;

pub fn get_pixman_format(format: u32) -> Result<pixman_format_code_t> {
    match format {
        VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM => Ok(pixman_format_code_t::PIXMAN_a8r8g8b8),
        VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM => Ok(pixman_format_code_t::PIXMAN_x8r8g8b8),
        VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM => Ok(pixman_format_code_t::PIXMAN_b8g8r8a8),
        VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM => Ok(pixman_format_code_t::PIXMAN_b8g8r8x8),
        VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM => Ok(pixman_format_code_t::PIXMAN_a8b8g8r8),
        VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM => Ok(pixman_format_code_t::PIXMAN_r8g8b8x8),
        VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM => Ok(pixman_format_code_t::PIXMAN_r8g8b8a8),
        VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM => Ok(pixman_format_code_t::PIXMAN_x8b8g8r8),
        _ => {
            bail!("Unsupported pixman format")
        }
    }
}

// update curosr from monochrome source
// https://learn.microsoft.com/en-us/windows-hardware/drivers/display/drawing-monochrome-pointers
pub fn set_monochrome_cursor(cursor: &mut [u8], source: &[u8], width: usize, height: usize) {
    let pixels_num = width * height;
    let mask_value_size = pixels_num / 8;
    let and_mask_value = &source[0..mask_value_size];
    let xor_mask_value = &source[mask_value_size..mask_value_size * 2];
    // Bytes per line
    let bpl = VIRTIO_GPU_CURSOR_SIZE / 8;
    // Bytes per pixel for cursor img, which expected export in RGBA format
    let bpp = 4;

    for row in 0..VIRTIO_GPU_CURSOR_SIZE {
        for col in 0..bpl {
            for i in 0..8 {
                let cursor_index = (row * VIRTIO_GPU_CURSOR_SIZE + col * 8 + i) * bpp;

                if row >= height || col * bpl >= width {
                    cursor[cursor_index] = 0x00;
                    cursor[cursor_index + 1] = 0x00;
                    cursor[cursor_index + 2] = 0x00;
                    cursor[cursor_index + 3] = 0x00;
                    continue;
                }

                let mask_index: u8 = 0x80 >> i;
                let and_v = (and_mask_value[row * (width / 8) + col] & mask_index) != 0;
                let xor_v = (xor_mask_value[row * (width / 8) + col] & mask_index) != 0;

                if !and_v && !xor_v {
                    cursor[cursor_index] = 0x00;
                    cursor[cursor_index + 1] = 0x00;
                    cursor[cursor_index + 2] = 0x00;
                    cursor[cursor_index + 3] = 0xff;
                } else if !and_v && xor_v {
                    cursor[cursor_index] = 0xff;
                    cursor[cursor_index + 1] = 0xff;
                    cursor[cursor_index + 2] = 0xff;
                    cursor[cursor_index + 3] = 0xff;
                } else if and_v && !xor_v {
                    cursor[cursor_index] = 0x00;
                    cursor[cursor_index + 1] = 0x00;
                    cursor[cursor_index + 2] = 0x00;
                    cursor[cursor_index + 3] = 0x00;
                } else {
                    // for inverted, in graphic is hard to get background color, just make it black.
                    cursor[cursor_index] = 0x00;
                    cursor[cursor_index + 1] = 0x00;
                    cursor[cursor_index + 2] = 0x00;
                    cursor[cursor_index + 3] = 0xff;
                }
            }
        }
    }
}

pub fn cal_image_hostmem(format: u32, width: u32, height: u32) -> (Option<usize>, u32) {
    // Expected monochrome cursor is 8 pixel aligned.
    if format == VIRTIO_GPU_FORMAT_MONOCHROME {
        if width as usize > VIRTIO_GPU_CURSOR_SIZE
            || height as usize > VIRTIO_GPU_CURSOR_SIZE
            || width % 8 != 0
            || height % 8 != 0
        {
            error!(
                "GuestError: monochrome cursor use invalid size: {} {}.",
                width, height
            );
            (None, VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER)
        } else {
            let mem = (width * height / 8 * 2) as usize;
            (Some(mem), 0)
        }
    } else {
        let pixman_format = match get_pixman_format(format) {
            Ok(f) => f,
            Err(e) => {
                error!("GuestError: {:?}", e);
                return (None, VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER);
            }
        };
        let bpp = pixman_format_bpp(pixman_format as u32);
        let stride = ((width as u64 * bpp as u64 + 0x1f) >> 5) * (size_of::<u32>() as u64);
        match stride.checked_mul(height as u64) {
            None => {
                error!(
                    "stride * height is overflow: width {} height {} stride {} bpp {}",
                    width, height, stride, bpp,
                );
                (None, VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER)
            }
            Some(v) => (Some(v as usize), 0),
        }
    }
}

fn is_rect_in_resource(rect: &VirtioGpuRect, res: &GpuResource) -> bool {
    let x_in = rect
        .x_coord
        .checked_add(rect.width)
        .filter(|&sum| sum <= res.width)
        .is_some();
    let y_in = rect
        .y_coord
        .checked_add(rect.height)
        .filter(|&sum| sum <= res.height)
        .is_some();
    x_in && y_in
}

impl GpuIoHandler {
    fn change_run_stage(&self) -> Result<()> {
        if get_run_stage() == VmRunningStage::Bios && !self.scanouts.is_empty() {
            match &self.scanouts[0].con.as_ref().and_then(|c| c.upgrade()) {
                Some(con) => {
                    let dev_name = con.lock().unwrap().dev_name.clone();
                    display_set_major_screen(&dev_name)?;
                    set_run_stage(VmRunningStage::Os);
                }
                None => {}
            };
        }
        Ok(())
    }

    fn get_request<T: ByteCode>(&mut self, header: &VirtioGpuRequest, req: &mut T) -> Result<()> {
        iov_to_buf_direct(&header.out_iovec, 0, req.as_mut_bytes()).and_then(|size| {
            if size == size_of::<T>() {
                Ok(())
            } else {
                Err(anyhow!("Invalid header for gpu request: len {}.", size))
            }
        })
    }

    fn complete_one_request(&mut self, index: u16, len: u32) -> Result<()> {
        let mut queue_lock = self.ctrl_queue.lock().unwrap();

        queue_lock
            .vring
            .add_used(&self.mem_space, index, len)
            .with_context(|| {
                format!(
                    "Failed to add used ring(gpu ctrl), index {}, len {}",
                    index, len,
                )
            })?;

        if queue_lock
            .vring
            .should_notify(&self.mem_space, self.driver_features)
        {
            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue_lock), false)
                .with_context(|| "Failed to trigger interrupt(gpu ctrl)")?;
            trace::virtqueue_send_interrupt("Gpu", &*queue_lock as *const _ as u64);
        }

        Ok(())
    }

    fn send_response<T: ByteCode + CtrlHdr>(
        &mut self,
        req: &VirtioGpuRequest,
        resp: &mut T,
    ) -> Result<()> {
        if (req.header.flags & VIRTIO_GPU_FLAG_FENCE) != 0 {
            let header = resp.mut_ctrl_hdr();
            header.flags |= VIRTIO_GPU_FLAG_FENCE;
            header.fence_id = req.header.fence_id;
            header.ctx_id = req.header.ctx_id;
        }

        let len = iov_from_buf_direct(&req.in_iovec, resp.as_bytes())?;
        if len != size_of::<T>() {
            error!(
                "GuestError: An incomplete response will be used instead of the expected: expected \
                 length is {}, actual length is {}. \
                 Also, be aware that the virtual machine may suspended if response is too short to \
                 carry the necessary information.",
                 size_of::<T>(), len,
            );
        }
        self.complete_one_request(req.index, len as u32)
    }

    fn response_nodata(&mut self, resp_head_type: u32, req: &VirtioGpuRequest) -> Result<()> {
        let mut resp = VirtioGpuCtrlHdr {
            hdr_type: resp_head_type,
            ..Default::default()
        };
        self.send_response(req, &mut resp)
    }

    // Mask resource's scanout bit before disable a scanout.
    fn disable_scanout(&mut self, scanout_id: usize) {
        let resource_id = self.scanouts[scanout_id].resource_id;
        if resource_id == 0 {
            return;
        }

        if let Some(res_idx) = self.get_resource_idx(resource_id) {
            let res = &mut self.resources_list[res_idx];
            res.scanouts_bitmask &= !(1 << scanout_id);
        }

        // TODO: present 'Guest disabled display.' in surface.
        let scanout = &mut self.scanouts[scanout_id];
        display_replace_surface(&scanout.con, None)
            .unwrap_or_else(|e| error!("Error occurs during surface switching: {:?}", e));
        scanout.clear();
    }

    fn get_resource_idx(&self, resource_id: u32) -> Option<usize> {
        self.resources_list
            .iter()
            .position(|x| x.resource_id == resource_id)
    }

    fn get_backed_resource_idx(&self, res_id: u32, caller: &str) -> (Option<usize>, u32) {
        match self.get_resource_idx(res_id) {
            None => {
                error!(
                    "GuestError: The resource_id {} in {} request does not existed",
                    res_id, caller,
                );
                (None, VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID)
            }
            Some(res_idx) => {
                let res = &self.resources_list[res_idx];
                if res.iov.is_empty()
                    || (res.pixman_image.is_null() && res.monochrome_cursor.is_empty())
                {
                    error!(
                        "GuestError: The resource_id {} in {} request has no backing storage.",
                        res_id, caller,
                    );
                    (None, VIRTIO_GPU_RESP_ERR_UNSPEC)
                } else {
                    (Some(res_idx), 0)
                }
            }
        }
    }

    fn update_cursor_image(&mut self, info_cursor: &VirtioGpuUpdateCursor) {
        let (res_idx, error) =
            self.get_backed_resource_idx(info_cursor.resource_id, "cmd_update_cursor");
        if res_idx.is_none() {
            error!("Failed to update cursor image, errcode: {}", error);
            return;
        }

        let res = &self.resources_list[res_idx.unwrap()];
        let scanout = &mut self.scanouts[info_cursor.pos.scanout_id as usize];
        let mse = scanout.mouse.as_mut().unwrap();
        let mse_data_size = mse.data.len();

        if res.format == VIRTIO_GPU_FORMAT_MONOCHROME {
            set_monochrome_cursor(
                &mut mse.data,
                &res.monochrome_cursor,
                res.width as usize,
                res.height as usize,
            );
        } else {
            let res_width = get_image_width(res.pixman_image);
            let res_height = get_image_height(res.pixman_image);
            if res_width as u32 != mse.width || res_height as u32 != mse.height {
                return;
            }
            let res_data_ptr = get_image_data(res.pixman_image) as *mut u8;
            // SAFETY: the length of the source and dest pointers can be ensured to be same,
            // and equal to mse_data_size.
            unsafe {
                ptr::copy(res_data_ptr, mse.data.as_mut_ptr(), mse_data_size);
            }
        }

        // Windows front-end driver does not deliver data in format sequence.
        // So we fix it in back-end.
        // TODO: Fix front-end driver is a better solution.
        if res.format == VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM
            || res.format == VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM
        {
            let mut i = 0;
            while i < mse_data_size {
                mse.data.swap(i, i + 2);
                i += 4;
            }
        }
        scanout.cursor_visible = true;
    }

    fn update_cursor(&mut self, info_cursor: &VirtioGpuUpdateCursor, hdr_type: u32) -> Result<()> {
        let scanout = &mut self.scanouts[info_cursor.pos.scanout_id as usize];
        match &mut scanout.mouse {
            None => {
                let mouse = DisplayMouse::new(
                    VIRTIO_GPU_CURSOR_SIZE as u32,
                    VIRTIO_GPU_CURSOR_SIZE as u32,
                    info_cursor.hot_x,
                    info_cursor.hot_y,
                );
                scanout.mouse = Some(mouse);
            }
            Some(mouse) => {
                if hdr_type == VIRTIO_GPU_CMD_UPDATE_CURSOR {
                    mouse.hot_x = info_cursor.hot_x;
                    mouse.hot_y = info_cursor.hot_y;
                }
            }
        }

        if info_cursor.resource_id > 0 {
            self.update_cursor_image(info_cursor);
        }
        let scanout = &mut self.scanouts[info_cursor.pos.scanout_id as usize];
        display_cursor_define(&scanout.con, scanout.mouse.as_ref().unwrap())?;
        Ok(())
    }

    fn cmd_update_cursor(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_cursor = VirtioGpuUpdateCursor::default();
        self.get_request(req, &mut info_cursor)?;

        if info_cursor.pos.scanout_id >= self.num_scanouts {
            error!(
                "GuestError: The scanout id {} is out of range.",
                info_cursor.pos.scanout_id
            );
            return Ok(());
        }
        trace::virtio_gpu_update_cursor(
            info_cursor.pos.scanout_id,
            info_cursor.pos.x_coord,
            info_cursor.pos.y_coord,
            info_cursor.resource_id,
            if req.header.hdr_type == VIRTIO_GPU_CMD_MOVE_CURSOR {
                "move"
            } else {
                "update"
            },
        );

        let scanout = &mut self.scanouts[info_cursor.pos.scanout_id as usize];
        if req.header.hdr_type == VIRTIO_GPU_CMD_MOVE_CURSOR {
            if info_cursor.resource_id == 0 && scanout.cursor_visible && scanout.mouse.is_some() {
                let data = &mut scanout.mouse.as_mut().unwrap().data;
                // In order to improve performance, displaying cursor by virtio-gpu.
                // But we have to displaying it in guest img if virtio-gpu can't do display job.
                // In this case, to avoid overlapping displaying two cursor imgs, change
                // cursor (render by virtio-gpu) color to transparent.
                //
                // Only A or X byte in RGBA\X needs to be set.
                // We sure that the data is assembled in format like RGBA and the minimum unit
                // is byte, so there is no size end problem.
                //
                // TODO: How much impact does it have on performance?
                for (i, item) in data.iter_mut().enumerate() {
                    if i % 4 == 3 {
                        *item = 0_u8;
                    }
                }
                display_cursor_define(&scanout.con, scanout.mouse.as_ref().unwrap())?;
                scanout.cursor_visible = false;
            } else if info_cursor.resource_id > 0 && !scanout.cursor_visible {
                self.update_cursor(&info_cursor, VIRTIO_GPU_CMD_MOVE_CURSOR)?;
            }
        } else if req.header.hdr_type == VIRTIO_GPU_CMD_UPDATE_CURSOR {
            self.update_cursor(&info_cursor, VIRTIO_GPU_CMD_UPDATE_CURSOR)?;
        } else {
            bail!("Wrong header type for cursor queue");
        }

        Ok(())
    }

    fn cmd_get_display_info(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut display_info = VirtioGpuDisplayInfo::default();
        display_info.header.hdr_type = VIRTIO_GPU_RESP_OK_DISPLAY_INFO;

        let output_states_lock = self.output_states.lock().unwrap();
        for i in 0..self.num_scanouts {
            if (self.enable_output_bitmask & (1 << i)) != 0 {
                let i = i as usize;
                display_info.pmodes[i].enabled = 1;
                display_info.pmodes[i].rect.width = output_states_lock[i].width;
                display_info.pmodes[i].rect.height = output_states_lock[i].height;
                display_info.pmodes[i].flags = 0;
            }
        }
        drop(output_states_lock);
        info!("virtio-gpu get the display info {:?}", display_info);
        self.send_response(req, &mut display_info)
    }

    fn cmd_get_edid(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut edid_req = VirtioGpuGetEdid::default();
        self.change_run_stage()?;
        self.get_request(req, &mut edid_req)?;

        if edid_req.scanouts >= self.num_scanouts {
            error!(
                "GuestError: The scanouts {} of request exceeds the max_outputs {}.",
                edid_req.scanouts, self.num_scanouts
            );
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, req);
        }
        trace::virtio_gpu_get_edid(edid_req.scanouts);

        let mut edid_resp = VirtioGpuRespEdid::default();
        edid_resp.header.hdr_type = VIRTIO_GPU_RESP_OK_EDID;

        let output_states_lock = self.output_states.lock().unwrap();
        let mut edid_info = EdidInfo::new(
            "HWV",
            "STRA Monitor",
            100,
            output_states_lock[edid_req.scanouts as usize].width,
            output_states_lock[edid_req.scanouts as usize].height,
        );
        drop(output_states_lock);
        edid_info.edid_array_fulfill(&mut edid_resp.edid);
        edid_resp.size = edid_resp.edid.len() as u32;

        self.send_response(req, &mut edid_resp)
    }

    fn cmd_resource_create_2d(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_create_2d = VirtioGpuResourceCreate2d::default();
        self.get_request(req, &mut info_create_2d)?;
        trace::virtio_gpu_resource_create_2d(
            info_create_2d.resource_id,
            info_create_2d.format,
            info_create_2d.width,
            info_create_2d.height,
        );

        if info_create_2d.resource_id == 0 {
            error!("GuestError: resource id 0 is not allowed.");
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req);
        }

        if self.get_resource_idx(info_create_2d.resource_id).is_some() {
            error!(
                "GuestError: resource {} already exists.",
                info_create_2d.resource_id
            );
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req);
        }

        let mut res = GpuResource {
            width: info_create_2d.width,
            height: info_create_2d.height,
            format: info_create_2d.format,
            resource_id: info_create_2d.resource_id,
            ..Default::default()
        };

        let (mem, error) = cal_image_hostmem(res.format, res.width, res.height);
        if mem.is_none() {
            return self.response_nodata(error, req);
        }
        res.host_mem = mem.unwrap() as u64;

        if res
            .host_mem
            .checked_add(self.used_hostmem)
            .filter(|&sum| sum <= self.max_hostmem)
            .is_some()
        {
            if res.format == VIRTIO_GPU_FORMAT_MONOCHROME {
                res.monochrome_cursor = vec![0_u8; (res.width * res.height / 8 * 2) as usize];
            } else {
                res.pixman_image = create_pixman_image(
                    get_pixman_format(res.format).unwrap(),
                    info_create_2d.width as i32,
                    info_create_2d.height as i32,
                    ptr::null_mut(),
                    0,
                );
            }
        }

        if res.monochrome_cursor.is_empty() && res.pixman_image.is_null() {
            error!(
                "GuestError: Fail to create resource(id {}, width {}, height {}) on host.",
                res.resource_id, res.width, res.height
            );
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY, req);
        }

        self.used_hostmem += res.host_mem;
        self.resources_list.push(res);
        self.response_nodata(VIRTIO_GPU_RESP_OK_NODATA, req)
    }

    fn resource_destroy(&mut self, res_index: usize) {
        let scanouts_bitmask = self.resources_list[res_index].scanouts_bitmask;
        if scanouts_bitmask != 0 {
            for i in 0..self.num_scanouts {
                if (scanouts_bitmask & (1 << i)) != 0 {
                    self.disable_scanout(i as usize);
                }
            }
        }

        let res = &mut self.resources_list[res_index];
        unref_pixman_image(res.pixman_image);
        self.used_hostmem -= res.host_mem;
        self.resources_list.remove(res_index);
    }

    fn cmd_resource_unref(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_resource_unref = VirtioGpuResourceUnref::default();
        self.get_request(req, &mut info_resource_unref)?;
        trace::virtio_gpu_resource_unref(info_resource_unref.resource_id);

        if let Some(res_index) = self.get_resource_idx(info_resource_unref.resource_id) {
            self.resource_destroy(res_index);
            self.response_nodata(VIRTIO_GPU_RESP_OK_NODATA, req)
        } else {
            error!(
                "GuestError: illegal resource specified {}.",
                info_resource_unref.resource_id,
            );
            self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req)
        }
    }

    fn cmd_set_scanout(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_set_scanout = VirtioGpuSetScanout::default();
        self.get_request(req, &mut info_set_scanout)?;
        trace::virtio_gpu_set_scanout(
            info_set_scanout.scanout_id,
            info_set_scanout.resource_id,
            info_set_scanout.rect.width,
            info_set_scanout.rect.height,
            info_set_scanout.rect.x_coord,
            info_set_scanout.rect.y_coord,
        );

        if info_set_scanout.scanout_id >= self.num_scanouts {
            error!(
                "GuestError: The scanout id {} is out of range.",
                info_set_scanout.scanout_id
            );
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID, req);
        }

        if info_set_scanout.resource_id == 0 {
            // Set resource_id to 0 means disable the scanout.
            self.disable_scanout(info_set_scanout.scanout_id as usize);
            return self.response_nodata(VIRTIO_GPU_RESP_OK_NODATA, req);
        }

        // Check if resource is valid.
        let (res_idx, error) =
            self.get_backed_resource_idx(info_set_scanout.resource_id, "cmd_set_scanout");
        if res_idx.is_none() {
            return self.response_nodata(error, req);
        }

        let res = &mut self.resources_list[res_idx.unwrap()];
        if info_set_scanout.rect.width < 16
            || info_set_scanout.rect.height < 16
            || !is_rect_in_resource(&info_set_scanout.rect, res)
        {
            error!(
                "GuestError: The resource (id: {} width: {} height: {}) is outfit for scanout (id: {} width: {} height: {} x_coord: {} y_coord: {}).",
                res.resource_id,
                res.width,
                res.height,
                info_set_scanout.scanout_id,
                info_set_scanout.rect.width,
                info_set_scanout.rect.height,
                info_set_scanout.rect.x_coord,
                info_set_scanout.rect.y_coord,
            );
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, req);
        }

        let pixman_format = get_image_format(res.pixman_image);
        let bpp = (pixman_format_bpp(pixman_format as u32) as u32 + 8 - 1) / 8;
        let pixman_stride = get_image_stride(res.pixman_image);
        let offset = info_set_scanout.rect.x_coord * bpp
            + info_set_scanout.rect.y_coord * pixman_stride as u32;
        let res_data = if info_set_scanout.resource_id & VIRTIO_GPU_RES_FRAMEBUF != 0 {
            res.iov[0].iov_base as *mut u32
        } else {
            get_image_data(res.pixman_image)
        };
        // SAFETY: The offset is within the legal address.
        let res_data_offset = unsafe { res_data.offset(offset as isize) };

        // Create surface for the scanout.
        let scanout = &mut self.scanouts[info_set_scanout.scanout_id as usize];
        if scanout.surface.is_none()
            || get_image_data(scanout.surface.unwrap().image) != res_data_offset
            || scanout.width != info_set_scanout.rect.width
            || scanout.height != info_set_scanout.rect.height
        {
            let surface = create_surface(
                scanout,
                info_set_scanout,
                res,
                pixman_format,
                pixman_stride,
                res_data_offset,
            );
            if surface.image.is_null() {
                error!("HostError: surface image create failed, check pixman library.");
                return self.response_nodata(VIRTIO_GPU_RESP_ERR_UNSPEC, req);
            }
        }

        // Unlink old resource.
        let old_res_id = scanout.resource_id;
        if let Some(old_res_idx) = self.get_resource_idx(old_res_id) {
            let old_res = &mut self.resources_list[old_res_idx];
            old_res.scanouts_bitmask &= !(1 << info_set_scanout.scanout_id);
        }
        // Link new resource.
        let res = &mut self.resources_list[res_idx.unwrap()];
        res.scanouts_bitmask |= 1 << info_set_scanout.scanout_id;
        let scanout = &mut self.scanouts[info_set_scanout.scanout_id as usize];
        scanout.resource_id = info_set_scanout.resource_id;
        scanout.x = info_set_scanout.rect.x_coord;
        scanout.y = info_set_scanout.rect.y_coord;
        scanout.width = info_set_scanout.rect.width;
        scanout.height = info_set_scanout.rect.height;

        self.response_nodata(VIRTIO_GPU_RESP_OK_NODATA, req)
    }

    fn cmd_resource_flush(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_res_flush = VirtioGpuResourceFlush::default();
        self.get_request(req, &mut info_res_flush)?;
        trace::virtio_gpu_resource_flush(
            info_res_flush.resource_id,
            info_res_flush.rect.width,
            info_res_flush.rect.height,
            info_res_flush.rect.x_coord,
            info_res_flush.rect.y_coord,
        );

        let res_index = self.get_resource_idx(info_res_flush.resource_id);
        if res_index.is_none() {
            error!(
                "GuestError: The resource_id {} in resource flush request is not existed.",
                info_res_flush.resource_id
            );
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req);
        }

        let res = &self.resources_list[res_index.unwrap()];
        if !is_rect_in_resource(&info_res_flush.rect, res) {
            error!(
                "GuestError: The resource (id: {} width: {} height: {}) is outfit for flush rectangle (width: {} height: {} x_coord: {} y_coord: {}).",
                res.resource_id, res.width, res.height,
                info_res_flush.rect.width, info_res_flush.rect.height,
                info_res_flush.rect.x_coord, info_res_flush.rect.y_coord,
            );
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, req);
        }

        let mut flush_reg = pixman_region16_t::default();
        let flush_reg_ptr = &mut flush_reg as *mut pixman_region16_t;
        // SAFETY: rect information has been checked.
        unsafe {
            pixman_region_init_rect(
                flush_reg_ptr,
                info_res_flush.rect.x_coord as i32,
                info_res_flush.rect.y_coord as i32,
                info_res_flush.rect.width,
                info_res_flush.rect.height,
            );
        }

        for i in 0..self.num_scanouts {
            // Flushes any scanouts the resource is being used on.
            if res.scanouts_bitmask & (1 << i) == 0 {
                continue;
            }
            let scanout = &self.scanouts[i as usize];

            let mut rect_reg = pixman_region16_t::default();
            let mut final_reg = pixman_region16_t::default();
            let rect_reg_ptr = &mut rect_reg as *mut pixman_region16_t;
            let final_reg_ptr = &mut final_reg as *mut pixman_region16_t;
            // SAFETY: The pointer is not empty.
            unsafe {
                pixman_region_init(final_reg_ptr);
                pixman_region_init_rect(
                    rect_reg_ptr,
                    scanout.x as i32,
                    scanout.y as i32,
                    scanout.width,
                    scanout.height,
                );

                pixman_region_intersect(final_reg_ptr, flush_reg_ptr, rect_reg_ptr);
                pixman_region_translate(final_reg_ptr, -(scanout.x as i32), -(scanout.y as i32));
                let extents = pixman_region_extents(final_reg_ptr);
                display_graphic_update(
                    &scanout.con,
                    (*extents).x1 as i32,
                    (*extents).y1 as i32,
                    ((*extents).x2 - (*extents).x1) as i32,
                    ((*extents).y2 - (*extents).y1) as i32,
                )?;
                pixman_region_fini(rect_reg_ptr);
                pixman_region_fini(final_reg_ptr);
            }
        }

        // SAFETY: Tt can ensured that the pointer is not empty.
        unsafe {
            pixman_region_fini(flush_reg_ptr);
        }

        self.response_nodata(VIRTIO_GPU_RESP_OK_NODATA, req)
    }

    fn cmd_transfer_to_host_2d_params_check(
        &mut self,
        info_transfer: &VirtioGpuTransferToHost2d,
    ) -> (Option<usize>, u32) {
        let (res_idx, error) =
            self.get_backed_resource_idx(info_transfer.resource_id, "cmd_transfer_to_host_2d");
        if res_idx.is_none() {
            return (None, error);
        }

        let res = &self.resources_list[res_idx.unwrap()];
        if res.resource_id & VIRTIO_GPU_RES_FRAMEBUF != 0 {
            return (None, VIRTIO_GPU_RESP_OK_NODATA);
        }
        if !is_rect_in_resource(&info_transfer.rect, res) {
            error!(
                "GuestError: The resource (id: {} width: {} height: {}) is outfit for transfer rectangle (offset: {} width: {} height: {} x_coord: {} y_coord: {}).",
                res.resource_id,
                res.width,
                res.height,
                info_transfer.offset,
                info_transfer.rect.width,
                info_transfer.rect.height,
                info_transfer.rect.x_coord,
                info_transfer.rect.y_coord,
            );
            (None, VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER)
        } else {
            (res_idx, 0)
        }
    }

    fn cmd_transfer_to_host_2d_update_resource(
        &mut self,
        trans_info: &VirtioGpuTransferToHost2d,
        res_idx: usize,
    ) -> Result<()> {
        let res = &mut self.resources_list[res_idx];
        let pixman_format = get_image_format(res.pixman_image);
        let width = get_image_width(res.pixman_image) as u32;
        let bpp = (pixman_format_bpp(pixman_format as u32) as u32 + 8 - 1) / 8;
        let stride = get_image_stride(res.pixman_image) as u32;
        let data = get_image_data(res.pixman_image).cast() as *mut u8;

        if res.format == VIRTIO_GPU_FORMAT_MONOCHROME {
            let v = iov_to_buf_direct(&res.iov, 0, &mut res.monochrome_cursor)?;
            if v != res.monochrome_cursor.len() {
                error!("No enough data is copied for transfer_to_host_2d with monochrome");
            }
            return Ok(());
        }

        // When the dedicated area is continuous.
        if trans_info.rect.x_coord == 0 && trans_info.rect.width == width {
            let offset_dst = (trans_info.rect.y_coord * stride) as usize;
            let trans_size = (trans_info.rect.height * stride) as usize;
            // SAFETY: offset_dst and trans_size do not exceeds data size.
            let dst = unsafe { from_raw_parts_mut(data.add(offset_dst), trans_size) };
            iov_to_buf_direct(&res.iov, trans_info.offset, dst).map(|v| {
                if v < trans_size {
                    warn!("No enough data is copied for transfer_to_host_2d");
                }
                v
            })?;
            return Ok(());
        }

        // Otherwise transfer data line by line.
        let mut offset_src = trans_info.offset as usize;
        let mut offset_dst =
            (trans_info.rect.y_coord * stride + trans_info.rect.x_coord * bpp) as usize;
        let line_size = (trans_info.rect.width * bpp) as usize;
        for _ in 0..trans_info.rect.height {
            // SAFETY: offset_dst and line_size do not exceeds data size.
            let dst = unsafe { from_raw_parts_mut(data.add(offset_dst), line_size) };
            iov_to_buf_direct(&res.iov, offset_src as u64, dst).map(|v| {
                if v < line_size {
                    warn!("No enough data is copied for transfer_to_host_2d");
                }
                v
            })?;
            offset_src += stride as usize;
            offset_dst += stride as usize;
        }
        Ok(())
    }

    fn cmd_transfer_to_host_2d(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_transfer = VirtioGpuTransferToHost2d::default();
        self.get_request(req, &mut info_transfer)?;
        trace::virtio_gpu_xfer_toh_2d(info_transfer.resource_id);

        let (res_idx, error) = self.cmd_transfer_to_host_2d_params_check(&info_transfer);
        if res_idx.is_none() {
            return self.response_nodata(error, req);
        }

        self.cmd_transfer_to_host_2d_update_resource(&info_transfer, res_idx.unwrap())?;
        self.response_nodata(VIRTIO_GPU_RESP_OK_NODATA, req)
    }

    fn cmd_resource_attach_backing(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_attach_backing = VirtioGpuResourceAttachBacking::default();
        self.get_request(req, &mut info_attach_backing)?;
        trace::virtio_gpu_resource_attach_backing(info_attach_backing.resource_id);

        let res_idx = self.get_resource_idx(info_attach_backing.resource_id);
        if res_idx.is_none() {
            error!(
                "The resource_id {} in attach backing request request is not existed.",
                info_attach_backing.resource_id
            );
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req);
        }

        let res = &mut self.resources_list[res_idx.unwrap()];
        if !res.iov.is_empty() {
            error!(
                "GuestError: The resource_id {} in resource attach backing request already has iov.",
                info_attach_backing.resource_id
            );
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_UNSPEC, req);
        }

        if info_attach_backing.nr_entries > 16384 {
            error!(
                "GuestError: The nr_entries in resource attach backing request is too large ( {} > 16384).",
                info_attach_backing.nr_entries
            );
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_UNSPEC, req);
        }

        let entries = info_attach_backing.nr_entries;
        let ents_size = size_of::<VirtioGpuMemEntry>() as u64 * entries as u64;
        let head_size = size_of::<VirtioGpuResourceAttachBacking>() as u64;
        if (req.out_len as u64) < (ents_size + head_size) {
            error!(
                "GuestError: The nr_entries {} in resource attach backing request is larger than total len {}.",
                info_attach_backing.nr_entries, req.out_len,
            );
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_UNSPEC, req);
        }

        // Start reading and parsing.
        let mut ents = Vec::<VirtioGpuMemEntry>::new();
        // SAFETY: Upper limit of ents is 16384.
        ents.resize(entries as usize, VirtioGpuMemEntry::default());
        let ents_buf =
            // SAFETY: ents is guaranteed not be null and the range of ents_size has been limited.
            unsafe { from_raw_parts_mut(ents.as_mut_ptr() as *mut u8, ents_size as usize) };
        let v = iov_to_buf_direct(&req.out_iovec, head_size, ents_buf)?;
        if v as u64 != ents_size {
            error!(
                "Virtio-GPU: Load no enough ents buf when attach backing, {} vs {}",
                v, ents_size
            );
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_UNSPEC, req);
        }

        let mut elemiovec = Vec::with_capacity(ents.len());
        for ent in ents.iter() {
            elemiovec.push(ElemIovec {
                addr: GuestAddress(ent.addr),
                len: ent.length,
            });
        }
        match gpa_hva_iovec_map(&elemiovec, &self.mem_space) {
            Ok((_, iov)) => {
                res.iov = iov;
                self.response_nodata(VIRTIO_GPU_RESP_OK_NODATA, req)
            }
            Err(e) => {
                error!("Virtio-GPU: Map entry base failed, {:?}", e);
                self.response_nodata(VIRTIO_GPU_RESP_ERR_UNSPEC, req)
            }
        }
    }

    fn cmd_resource_detach_backing(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_detach_backing = VirtioGpuResourceDetachBacking::default();
        self.get_request(req, &mut info_detach_backing)?;
        trace::virtio_gpu_resource_detach_backing(info_detach_backing.resource_id);

        let (res_idx, error) = self.get_backed_resource_idx(
            info_detach_backing.resource_id,
            "cmd_resource_detach_backing",
        );
        if res_idx.is_none() {
            return self.response_nodata(error, req);
        }

        self.resources_list[res_idx.unwrap()].iov.clear();
        self.response_nodata(VIRTIO_GPU_RESP_OK_NODATA, req)
    }

    fn process_control_queue(&mut self, mut req_queue: Vec<VirtioGpuRequest>) -> Result<()> {
        for req in req_queue.iter_mut() {
            if let Err(e) = match req.header.hdr_type {
                VIRTIO_GPU_CMD_GET_DISPLAY_INFO => self.cmd_get_display_info(req),
                VIRTIO_GPU_CMD_RESOURCE_CREATE_2D => self.cmd_resource_create_2d(req),
                VIRTIO_GPU_CMD_RESOURCE_UNREF => self.cmd_resource_unref(req),
                VIRTIO_GPU_CMD_SET_SCANOUT => self.cmd_set_scanout(req),
                VIRTIO_GPU_CMD_RESOURCE_FLUSH => self.cmd_resource_flush(req),
                VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D => self.cmd_transfer_to_host_2d(req),
                VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING => self.cmd_resource_attach_backing(req),
                VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING => self.cmd_resource_detach_backing(req),
                VIRTIO_GPU_CMD_GET_EDID => self.cmd_get_edid(req),
                _ => {
                    error!(
                        "Failed to process unsupported command: {}",
                        req.header.hdr_type
                    );
                    self.response_nodata(VIRTIO_GPU_RESP_ERR_UNSPEC, req)
                }
            } {
                error!("Fail to handle GPU request, {:?}.", e);
            }
        }

        Ok(())
    }

    fn ctrl_queue_evt_handler(&mut self) -> Result<()> {
        let mut queue = self.ctrl_queue.lock().unwrap();
        let mut req_queue = Vec::new();

        loop {
            let mut elem = queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)?;
            if elem.desc_num == 0 {
                break;
            }

            match VirtioGpuRequest::new(&self.mem_space, &mut elem) {
                Ok(req) => {
                    req_queue.push(req);
                }
                Err(e) => {
                    error!(
                        "GuestError: Request will be ignored, because request header is incomplete and {:?}. \
                         Also, be aware that the virtual machine may suspended as response is not sent.",
                        e
                    );
                }
            }
        }
        drop(queue);

        self.process_control_queue(req_queue)?;
        Ok(())
    }

    fn cursor_queue_evt_handler(&mut self) -> Result<()> {
        let cursor_queue = self.cursor_queue.clone();
        let mut queue = cursor_queue.lock().unwrap();

        loop {
            let mut elem = queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)?;
            if elem.desc_num == 0 {
                break;
            }

            match VirtioGpuRequest::new(&self.mem_space, &mut elem) {
                Ok(req) => match self.cmd_update_cursor(&req) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Failed to handle gpu cursor cmd for {:?}.", e);
                    }
                },
                // Ignore the request has no effect, because we handle it later.
                Err(err) => {
                    error!("Failed to create GPU request, {:?}, just ignore it", err);
                }
            };

            queue
                .vring
                .add_used(&self.mem_space, elem.index, 0)
                .with_context(|| {
                    format!("Failed to add used ring(cursor), index {}", elem.index)
                })?;

            if queue
                .vring
                .should_notify(&self.mem_space, self.driver_features)
            {
                (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue), false)
                    .with_context(|| {
                        VirtioError::InterruptTrigger("gpu cursor", VirtioInterruptType::Vring)
                    })?;
                trace::virtqueue_send_interrupt("Cursor", &*queue as *const _ as u64);
            }
        }

        Ok(())
    }
}

impl Drop for GpuIoHandler {
    fn drop(&mut self) {
        while !self.resources_list.is_empty() {
            self.resource_destroy(0);
        }
    }
}

impl EventNotifierHelper for GpuIoHandler {
    fn internal_notifiers(handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let handler_raw = handler.lock().unwrap();
        let mut notifiers = Vec::new();

        // Register event notifier for ctrl_queue_evt.
        let handler_clone = handler.clone();
        let h: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            if let Err(e) = handler_clone.lock().unwrap().ctrl_queue_evt_handler() {
                error!("Failed to process ctrlq for virtio gpu, err: {:?}", e);
            }
            None
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            handler_raw.ctrl_queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![h],
        ));

        // Register event notifier for cursor_queue_evt.
        let handler_clone = handler.clone();
        let h: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            if let Err(e) = handler_clone.lock().unwrap().cursor_queue_evt_handler() {
                error!("Failed to process cursorq for virtio gpu, err: {:?}", e);
            }
            None
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            handler_raw.cursor_queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![h],
        ));

        notifiers
    }
}

#[derive(Clone, Copy, Debug, ByteCode)]
struct VirtioGpuConfig {
    events_read: u32,
    events_clear: u32,
    num_scanouts: u32,
    _reserved: u32,
}

/// GPU device structure.
#[derive(Default)]
pub struct Gpu {
    /// Virtio device base property.
    base: VirtioBase,
    /// Configuration of the GPU device.
    cfg: GpuDevConfig,
    /// Config space of the GPU device.
    config_space: Arc<Mutex<VirtioGpuConfig>>,
    /// Status of the emulated physical outputs.
    output_states: Arc<Mutex<[VirtioGpuOutputState; VIRTIO_GPU_MAX_OUTPUTS]>>,
    /// Each console corresponds to a display.
    consoles: Vec<Option<Weak<Mutex<DisplayConsole>>>>,
    /// bar0 file backend which is set by ohui server
    bar0_fb: Option<FileBackend>,
}

/// SAFETY: The raw pointer in rust doesn't impl Send, all write operations
/// to this memory will be locked. So implement Send safe.
unsafe impl Send for Gpu {}

impl Gpu {
    pub fn new(cfg: GpuDevConfig) -> Gpu {
        Self {
            base: VirtioBase::new(VIRTIO_TYPE_GPU, QUEUE_NUM_GPU, DEFAULT_VIRTQUEUE_SIZE),
            cfg,
            ..Default::default()
        }
    }

    pub fn set_bar0_fb(&mut self, fb: Option<FileBackend>) {
        if !self.cfg.enable_bar0 {
            self.bar0_fb = None;
            return;
        }
        self.bar0_fb = fb;
    }

    pub fn get_bar0_fb(&self) -> Option<FileBackend> {
        self.bar0_fb.as_ref().cloned()
    }

    fn build_device_config_space(&mut self) {
        let mut config_space = self.config_space.lock().unwrap();
        config_space.num_scanouts = self.cfg.max_outputs;
    }
}

impl VirtioDevice for Gpu {
    fn virtio_base(&self) -> &VirtioBase {
        &self.base
    }

    fn virtio_base_mut(&mut self) -> &mut VirtioBase {
        &mut self.base
    }

    fn device_quirk(&self) -> Option<VirtioDeviceQuirk> {
        if self.cfg.enable_bar0 {
            return Some(VirtioDeviceQuirk::VirtioGpuEnableBar0);
        }
        None
    }

    fn realize(&mut self) -> Result<()> {
        if self.cfg.max_outputs > VIRTIO_GPU_MAX_OUTPUTS as u32 {
            bail!(
                "Invalid max_outputs {} which is bigger than {}",
                self.cfg.max_outputs,
                VIRTIO_GPU_MAX_OUTPUTS
            );
        }

        let mut output_states = self.output_states.lock().unwrap();
        output_states[0].width = self.cfg.xres;
        output_states[0].height = self.cfg.yres;

        let gpu_opts = Arc::new(GpuOpts {
            output_states: self.output_states.clone(),
            config_space: self.config_space.clone(),
            interrupt_cb: None,
            enable_bar0: self.cfg.enable_bar0,
        });
        for i in 0..self.cfg.max_outputs {
            let dev_name = format!("virtio-gpu{}", i);
            let con = console_init(dev_name, ConsoleType::Graphic, gpu_opts.clone());
            let con_ref = con.as_ref().unwrap().upgrade().unwrap();
            output_states[i as usize].con_id = con_ref.lock().unwrap().con_id;
            self.consoles.push(con);
        }

        drop(output_states);

        self.init_config_features()?;

        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        self.base.device_features = 1u64 << VIRTIO_F_VERSION_1
            | 1u64 << VIRTIO_F_RING_INDIRECT_DESC
            | 1u64 << VIRTIO_F_RING_EVENT_IDX;
        if self.cfg.edid {
            self.base.device_features |= 1 << VIRTIO_GPU_F_EDID;
        }

        self.base.device_features |= 1 << VIRTIO_GPU_F_MONOCHROME;

        trace::virtio_gpu_init_config_features(self.base.device_features);
        self.build_device_config_space();
        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        for con in &self.consoles {
            console_close(con)?;
        }

        // TODO: support migration
        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        let config_space = self.config_space.lock().unwrap();
        read_config_default(config_space.as_bytes(), offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let mut config_space = self.config_space.lock().unwrap();
        check_config_space_rw(config_space.as_bytes(), offset, data)?;

        let mut config_cpy = *config_space;
        let config_cpy_slice = config_cpy.as_mut_bytes();

        config_cpy_slice[(offset as usize)..(offset as usize + data.len())].copy_from_slice(data);
        if config_cpy.events_clear != 0 {
            config_space.events_read &= !config_cpy.events_clear;
        }

        Ok(())
    }

    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let queues = &self.base.queues;
        if queues.len() != QUEUE_NUM_GPU {
            return Err(anyhow!(VirtioError::IncorrectQueueNum(
                QUEUE_NUM_GPU,
                queues.len()
            )));
        }

        let mut scanouts = vec![];
        let gpu_opts = Arc::new(GpuOpts {
            output_states: self.output_states.clone(),
            config_space: self.config_space.clone(),
            interrupt_cb: Some(interrupt_cb.clone()),
            enable_bar0: self.cfg.enable_bar0,
        });
        for con in &self.consoles {
            let con_ref = con.as_ref().unwrap().upgrade().unwrap();
            con_ref.lock().unwrap().dev_opts = gpu_opts.clone();

            let scanout = GpuScanout {
                con: con.clone(),
                ..Default::default()
            };
            scanouts.push(scanout);
        }

        let handler = GpuIoHandler {
            ctrl_queue: queues[0].clone(),
            cursor_queue: queues[1].clone(),
            mem_space,
            ctrl_queue_evt: queue_evts[0].clone(),
            cursor_queue_evt: queue_evts[1].clone(),
            interrupt_cb,
            driver_features: self.base.driver_features,
            resources_list: Vec::new(),
            enable_output_bitmask: 1,
            num_scanouts: self.cfg.max_outputs,
            output_states: self.output_states.clone(),
            scanouts,
            max_hostmem: self.cfg.max_hostmem,
            used_hostmem: 0,
        };

        let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler)));
        register_event_helper(notifiers, None, &mut self.base.deactivate_evts)?;
        info!("virtio-gpu has been activated");

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        if get_run_stage() == VmRunningStage::Os {
            display_set_major_screen("ramfb")?;
            set_run_stage(VmRunningStage::Bios);
        }

        let result = unregister_event_helper(None, &mut self.base.deactivate_evts);
        info!("virtio-gpu deactivate {:?}", result);
        result
    }
}
