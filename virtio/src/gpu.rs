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

use super::{
    Element, Queue, VirtioDevice, VirtioInterrupt, VirtioInterruptType, VIRTIO_F_RING_EVENT_IDX,
    VIRTIO_F_RING_INDIRECT_DESC, VIRTIO_F_VERSION_1, VIRTIO_GPU_CMD_GET_DISPLAY_INFO,
    VIRTIO_GPU_CMD_GET_EDID, VIRTIO_GPU_CMD_MOVE_CURSOR, VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_2D, VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
    VIRTIO_GPU_CMD_RESOURCE_FLUSH, VIRTIO_GPU_CMD_RESOURCE_UNREF, VIRTIO_GPU_CMD_SET_SCANOUT,
    VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D, VIRTIO_GPU_CMD_UPDATE_CURSOR, VIRTIO_GPU_FLAG_FENCE,
    VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
    VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID, VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY,
    VIRTIO_GPU_RESP_ERR_UNSPEC, VIRTIO_GPU_RESP_OK_DISPLAY_INFO, VIRTIO_GPU_RESP_OK_EDID,
    VIRTIO_GPU_RESP_OK_NODATA, VIRTIO_TYPE_GPU,
};
use crate::{iov_discard_front, iov_to_buf, VirtioError, VIRTIO_GPU_F_EDID};
use address_space::{AddressSpace, GuestAddress};
use anyhow::{anyhow, bail, Context, Result};
use log::{error, warn};
use machine_manager::config::{GpuDevConfig, DEFAULT_VIRTQUEUE_SIZE, VIRTIO_GPU_MAX_SCANOUTS};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use migration::{DeviceStateDesc, FieldDesc, MigrationManager};
use migration_derive::{ByteCode, Desc};
use std::io::Write;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::{ptr, vec};
use util::aio::{iov_discard_front_direct, iov_from_buf_direct, iov_to_buf_direct};
use util::byte_code::ByteCode;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::num_ops::read_u32;
use util::pixman::{
    pixman_format_bpp, pixman_format_code_t, pixman_image_create_bits, pixman_image_get_data,
    pixman_image_get_format, pixman_image_get_height, pixman_image_get_stride,
    pixman_image_get_width, pixman_image_ref, pixman_image_set_destroy_function, pixman_image_t,
    pixman_image_unref, pixman_region16_t, pixman_region_extents, pixman_region_fini,
    pixman_region_init, pixman_region_init_rect, pixman_region_intersect, pixman_region_translate,
    virtio_gpu_unref_resource_callback,
};
use util::{aio::Iovec, edid::EdidInfo};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};
use vnc::console::{
    console_close, console_init, display_cursor_define, display_graphic_update,
    display_replace_surface, DisplayMouse, DisplaySurface, HardWareOperations,
};

// number of virtqueues
const QUEUE_NUM_GPU: usize = 2;

// simple formats for fbcon/X use
const VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;
const VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: u32 = 2;
const VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM: u32 = 3;
const VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM: u32 = 4;
const VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM: u32 = 67;
const VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM: u32 = 68;
const VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM: u32 = 121;
const VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM: u32 = 134;

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
        }
    }
}

#[allow(unused)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuReqState {
    width: u32,
    height: u32,
    x_coor: i32,
    y_coor: i32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuCtrlHdr {
    hdr_type: u32,
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuCtrlHdr {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuRect {
    x_coord: u32,
    y_coord: u32,
    width: u32,
    height: u32,
}

impl ByteCode for VirtioGpuRect {}

#[derive(Default, Clone, Copy)]
pub struct VirtioGpuDisplayOne {
    rect: VirtioGpuRect,
    enabled: u32,
    flags: u32,
}

impl ByteCode for VirtioGpuDisplayOne {}

#[derive(Default, Clone, Copy)]
pub struct VirtioGpuDisplayInfo {
    header: VirtioGpuCtrlHdr,
    pmodes: [VirtioGpuDisplayOne; VIRTIO_GPU_MAX_SCANOUTS],
}
impl ByteCode for VirtioGpuDisplayInfo {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuGetEdid {
    scanouts: u32,
    padding: u32,
}
impl ByteCode for VirtioGpuGetEdid {}

#[allow(unused)]
// data which transfer to frontend need padding
#[derive(Clone, Copy)]
pub struct VirtioGpuRespEdid {
    header: VirtioGpuCtrlHdr,
    size: u32,
    padding: u32,
    edid: [u8; 1024],
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
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuResourceCreate2d {
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
}

impl ByteCode for VirtioGpuResourceCreate2d {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuResourceUnref {
    resource_id: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuResourceUnref {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuSetScanout {
    rect: VirtioGpuRect,
    scanout_id: u32,
    resource_id: u32,
}

impl ByteCode for VirtioGpuSetScanout {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuResourceFlush {
    rect: VirtioGpuRect,
    resource_id: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuResourceFlush {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuTransferToHost2d {
    rect: VirtioGpuRect,
    offset: u64,
    resource_id: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuTransferToHost2d {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuResourceAttachBacking {
    resource_id: u32,
    nr_entries: u32,
}

impl ByteCode for VirtioGpuResourceAttachBacking {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuMemEntry {
    addr: u64,
    length: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuMemEntry {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuResourceDetachBacking {
    resource_id: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuResourceDetachBacking {}

#[derive(Default)]
pub struct GpuOpts {}
impl HardWareOperations for GpuOpts {}

#[allow(unused)]
#[derive(Default, Clone)]
pub struct VirtioGpuRequest {
    header: VirtioGpuCtrlHdr,
    index: u16,
    out_iovec: Vec<Iovec>,
    out_len: u32,
    in_iovec: Vec<Iovec>,
    in_len: u32,
}

impl VirtioGpuRequest {
    fn new(mem_space: &Arc<AddressSpace>, elem: &Element) -> Result<Self> {
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

        // Note: in_iov and out_iov total len is no more than 1<<32, and
        // out_iov is more than 1, so in_len and out_len will not overflow.
        let mut request = VirtioGpuRequest {
            header,
            index: elem.index,
            out_iovec: Vec::with_capacity(elem.desc_num as usize),
            out_len: 0,
            in_iovec: Vec::with_capacity(elem.desc_num as usize),
            in_len: 0,
        };

        let mut out_iovec = elem.out_iovec.clone();
        // Size of out_iovec no less than sizeo of VirtioGpuCtrlHdr, so
        // it is possible to get none back.
        if let Some(data_iovec) =
            iov_discard_front(&mut out_iovec, size_of::<VirtioGpuCtrlHdr>() as u64)
        {
            for elem_iov in data_iovec {
                if let Some(hva) = mem_space.get_host_address(elem_iov.addr) {
                    let iov = Iovec {
                        iov_base: hva,
                        iov_len: u64::from(elem_iov.len),
                    };
                    request.out_iovec.push(iov);
                    request.out_len += elem_iov.len;
                } else {
                    bail!("Map desc base {:?} failed.", elem_iov.addr);
                }
            }
        }

        for elem_iov in elem.in_iovec.iter() {
            if let Some(hva) = mem_space.get_host_address(elem_iov.addr) {
                let iov = Iovec {
                    iov_base: hva,
                    iov_len: u64::from(elem_iov.len),
                };
                request.in_iovec.push(iov);
                request.in_len += elem_iov.len;
            } else {
                bail!("Map desc base {:?} failed.", elem_iov.addr);
            }
        }

        Ok(request)
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuCursorPos {
    scanout_id: u32,
    x_coord: u32,
    y_coord: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuCursorPos {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuUpdateCursor {
    pos: VirtioGpuCursorPos,
    resource_id: u32,
    hot_x: u32,
    hot_y: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuUpdateCursor {}

#[derive(Default)]
struct GpuScanout {
    con_id: Option<usize>,
    surface: Option<DisplaySurface>,
    mouse: Option<DisplayMouse>,
    width: u32,
    height: u32,
    x: u32,
    y: u32,
    resource_id: u32,
    // Unused with vnc backend, work in others.
    cursor: VirtioGpuUpdateCursor,
}

impl GpuScanout {
    fn clear(&mut self) {
        self.resource_id = 0;
        self.surface = None;
        self.width = 0;
        self.height = 0;
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
    /// Eventfd for contorl virtqueue.
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
    /// States of all request in scanout.
    req_states: [VirtioGpuReqState; VIRTIO_GPU_MAX_SCANOUTS],
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
    unsafe {
        let rect = pixman_image_create_bits(
            pixman_format,
            info_set_scanout.rect.width as i32,
            info_set_scanout.rect.height as i32,
            res_data_offset,
            pixman_stride,
        );
        pixman_image_ref(res.pixman_image);
        pixman_image_set_destroy_function(
            rect,
            Some(virtio_gpu_unref_resource_callback),
            res.pixman_image.cast(),
        );
        surface.format = pixman_image_get_format(rect);
        surface.image = pixman_image_ref(rect);
        if !surface.image.is_null() {
            // update surface in scanout.
            scanout.surface = Some(surface);
            pixman_image_unref(rect);
            display_replace_surface(scanout.con_id, scanout.surface);
        }
    };
    surface
}

fn get_pixman_format(format: u32) -> Result<pixman_format_code_t> {
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
            bail!("Unsupport pixman format")
        }
    }
}

fn get_image_hostmem(format: pixman_format_code_t, width: u32, height: u32) -> u64 {
    let bpp = pixman_format_bpp(format as u32);
    let stride = ((width as u64 * bpp as u64 + 0x1f) >> 5) * (size_of::<u32>() as u64);
    height as u64 * stride
}

fn is_rect_in_resouce(rect: &VirtioGpuRect, res: &GpuResource) -> bool {
    if rect
        .x_coord
        .checked_add(rect.width)
        .filter(|&sum| sum <= res.width)
        .is_some()
        && rect
            .y_coord
            .checked_add(rect.height)
            .filter(|&sum| sum <= res.height)
            .is_some()
    {
        return true;
    }
    false
}

// Mask resource's scanout bit before disable a scanout.
fn disable_scanout(scanout: &mut GpuScanout) {
    if scanout.resource_id == 0 {
        return;
    }
    // TODO: present 'Guest disabled display.' in surface.
    display_replace_surface(scanout.con_id, None);
    scanout.clear();
}

impl GpuIoHandler {
    fn get_request<T: ByteCode>(&mut self, header: &VirtioGpuRequest, req: &mut T) -> Result<()> {
        if header.out_len < size_of::<T>() as u32 {
            bail!("Invalid header for gpu request: len {}.", header.out_len)
        }

        iov_to_buf_direct(&header.out_iovec, req.as_mut_bytes()).and_then(|size| {
            if size == size_of::<T>() {
                Ok(())
            } else {
                bail!("Invalid header for gpu request: len {}.", size)
            }
        })
    }

    fn send_response<T: ByteCode>(&mut self, req: &VirtioGpuRequest, resp: &T) -> Result<()> {
        if let Err(e) = iov_from_buf_direct(&req.in_iovec, resp.as_bytes()).and_then(|size| {
            if size == size_of::<T>() {
                Ok(())
            } else {
                bail!(
                    "Failed to response gpu request, invalid reponse len {}.",
                    size
                );
            }
        }) {
            error!(
                "Failed to response gpu request, {:?}, may cause suspended.",
                e
            );
        }

        let mut queue_lock = self.ctrl_queue.lock().unwrap();
        if let Err(e) = queue_lock
            .vring
            .add_used(&self.mem_space, req.index, size_of::<T>() as u32)
        {
            bail!(
                "Failed to add used ring(gpu ctrl), index {}, len {} {:?}.",
                req.index,
                size_of::<T>() as u32,
                e,
            );
        }

        if queue_lock
            .vring
            .should_notify(&self.mem_space, self.driver_features)
        {
            if let Err(e) =
                (*self.interrupt_cb.as_ref())(&VirtioInterruptType::Vring, Some(&queue_lock), false)
            {
                error!("Failed to trigger interrupt(gpu ctrl), error is {:?}.", e);
            }
        }

        Ok(())
    }

    fn response_nodata(&mut self, resp_head_type: u32, req: &VirtioGpuRequest) -> Result<()> {
        let mut resp = VirtioGpuCtrlHdr {
            hdr_type: resp_head_type,
            ..Default::default()
        };

        if (req.header.flags & VIRTIO_GPU_FLAG_FENCE) != 0 {
            resp.flags |= VIRTIO_GPU_FLAG_FENCE;
            resp.fence_id = req.header.fence_id;
            resp.ctx_id = req.header.ctx_id;
        }

        self.send_response(req, &resp)
    }

    fn cmd_update_cursor(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_cursor = VirtioGpuUpdateCursor::default();
        self.get_request(req, &mut info_cursor)?;

        let scanout = &mut self.scanouts[info_cursor.pos.scanout_id as usize];
        if req.header.hdr_type == VIRTIO_GPU_CMD_MOVE_CURSOR {
            scanout.cursor.pos.x_coord = info_cursor.hot_x;
            scanout.cursor.pos.y_coord = info_cursor.hot_y;
        } else if req.header.hdr_type == VIRTIO_GPU_CMD_UPDATE_CURSOR {
            if scanout.mouse.is_none() {
                let tmp_mouse = DisplayMouse {
                    height: 64,
                    width: 64,
                    hot_x: info_cursor.hot_x,
                    hot_y: info_cursor.hot_y,
                    data: vec![0_u8; 64 * 64 * size_of::<u32>()],
                };
                scanout.mouse = Some(tmp_mouse);
            } else {
                let mut mse = scanout.mouse.as_mut().unwrap();
                mse.hot_x = info_cursor.hot_x;
                mse.hot_y = info_cursor.hot_y;
            }
            if info_cursor.resource_id != 0 {
                if let Some(res_index) = self
                    .resources_list
                    .iter()
                    .position(|x| x.resource_id == info_cursor.resource_id)
                {
                    let res = &self.resources_list[res_index];
                    unsafe {
                        let res_width = pixman_image_get_width(res.pixman_image);
                        let res_height = pixman_image_get_height(res.pixman_image);
                        let mse = scanout.mouse.as_mut().unwrap();

                        if res_width as u32 == mse.width && res_height as u32 == mse.height {
                            let pixels = mse.width * mse.height;
                            let mouse_data_size = pixels * (size_of::<u32>() as u32);
                            let mut con = vec![0u8; 64 * 64 * 4];
                            let res_data_ptr = pixman_image_get_data(res.pixman_image) as *mut u8;
                            ptr::copy(res_data_ptr, con.as_mut_ptr(), mouse_data_size as usize);
                            mse.data.clear();
                            mse.data.append(&mut con);
                        }
                    }
                }
            }
            if let Some(mouse) = &mut scanout.mouse {
                display_cursor_define(scanout.con_id, mouse);
            }
            scanout.cursor = info_cursor;
        } else {
            bail!("Wrong header type for cursor queue");
        }

        Ok(())
    }

    fn cmd_get_display_info(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut display_info = VirtioGpuDisplayInfo::default();
        display_info.header.hdr_type = VIRTIO_GPU_RESP_OK_DISPLAY_INFO;
        for i in 0..self.num_scanouts {
            if (self.enable_output_bitmask & (1 << i)) != 0 {
                let i = i as usize;
                display_info.pmodes[i].enabled = 1;
                display_info.pmodes[i].rect.width = self.req_states[i].width;
                display_info.pmodes[i].rect.height = self.req_states[i].height;
                display_info.pmodes[i].flags = 0;
            }
        }

        if (req.header.flags & VIRTIO_GPU_FLAG_FENCE) != 0 {
            display_info.header.flags |= VIRTIO_GPU_FLAG_FENCE;
            display_info.header.fence_id = req.header.fence_id;
            display_info.header.ctx_id = req.header.ctx_id;
        }
        self.send_response(req, &display_info)
    }

    fn cmd_get_edid(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut edid_req = VirtioGpuGetEdid::default();
        self.get_request(req, &mut edid_req)?;

        if edid_req.scanouts >= self.num_scanouts {
            error!(
                "GuestError: The scanouts {} of request exceeds the max_outputs {}.",
                edid_req.scanouts, self.num_scanouts
            );
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, req);
        }

        let mut edid_resp = VirtioGpuRespEdid::default();
        edid_resp.header.hdr_type = VIRTIO_GPU_RESP_OK_EDID;
        if (req.header.flags & VIRTIO_GPU_FLAG_FENCE) != 0 {
            edid_resp.header.flags |= VIRTIO_GPU_FLAG_FENCE;
            edid_resp.header.fence_id = req.header.fence_id;
            edid_resp.header.ctx_id = req.header.ctx_id;
        }

        let mut edid_info = EdidInfo::new(
            "HWV",
            "STRA Monitor",
            100,
            self.req_states[edid_req.scanouts as usize].width,
            self.req_states[edid_req.scanouts as usize].height,
        );
        edid_info.edid_array_fulfill(&mut edid_resp.edid.to_vec());
        edid_resp.size = edid_resp.edid.len() as u32;

        self.send_response(req, &edid_resp)?;

        Ok(())
    }

    fn cmd_resource_create_2d(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_create_2d = VirtioGpuResourceCreate2d::default();
        self.get_request(req, &mut info_create_2d)?;

        if info_create_2d.resource_id == 0 {
            error!("GuestError: resource id 0 is not allowed.");
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req);
        }

        if let Some(res) = self
            .resources_list
            .iter()
            .find(|&x| x.resource_id == info_create_2d.resource_id)
        {
            error!("GuestError: resource {} already exists.", res.resource_id);
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req);
        }

        let mut res = GpuResource {
            width: info_create_2d.width,
            height: info_create_2d.height,
            format: info_create_2d.format,
            resource_id: info_create_2d.resource_id,
            ..Default::default()
        };
        let pixman_format = match get_pixman_format(res.format) {
            Ok(f) => f,
            Err(e) => {
                error!("GuestError: {:?}.", e);
                return self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req);
            }
        };

        res.host_mem =
            get_image_hostmem(pixman_format, info_create_2d.width, info_create_2d.height);

        if res
            .host_mem
            .checked_add(self.used_hostmem)
            .filter(|&sum| sum <= self.max_hostmem)
            .is_some()
        {
            res.pixman_image = unsafe {
                pixman_image_create_bits(
                    pixman_format,
                    info_create_2d.width as i32,
                    info_create_2d.height as i32,
                    ptr::null_mut(),
                    0,
                )
            }
        }
        if res.pixman_image.is_null() {
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
        let res = &mut self.resources_list[res_index];

        if res.scanouts_bitmask == 0 {
            return;
        }

        for i in 0..self.num_scanouts {
            if (res.scanouts_bitmask & (1 << i)) != 0 {
                let scanout = &mut self.scanouts[i as usize];
                res.scanouts_bitmask &= !(1 << i);
                disable_scanout(scanout);
            }
        }

        unsafe {
            pixman_image_unref(res.pixman_image);
        }
        self.used_hostmem -= res.host_mem;
        res.iov.clear();
    }

    fn cmd_resource_unref(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_resource_unref = VirtioGpuResourceUnref::default();
        self.get_request(req, &mut info_resource_unref)?;

        if let Some(res_index) = self
            .resources_list
            .iter()
            .position(|x| x.resource_id == info_resource_unref.resource_id)
        {
            self.resource_destroy(res_index);
            self.resources_list.remove(res_index);
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

        if info_set_scanout.scanout_id >= self.num_scanouts {
            error!(
                "GuestError: The scanout id {} is out of range.",
                info_set_scanout.scanout_id
            );
            return self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID, req);
        }

        let scanout = &mut self.scanouts[info_set_scanout.scanout_id as usize];
        if info_set_scanout.resource_id == 0 {
            // Set resource_id to 0 means disable the scanout.
            if let Some(res_index) = self
                .resources_list
                .iter()
                .position(|x| x.resource_id == scanout.resource_id)
            {
                let res = &mut self.resources_list[res_index];
                res.scanouts_bitmask &= !(1 << info_set_scanout.scanout_id);
            }
            disable_scanout(scanout);
            return self.response_nodata(VIRTIO_GPU_RESP_OK_NODATA, req);
        }

        if let Some(res_index) = self
            .resources_list
            .iter()
            .position(|x| x.resource_id == info_set_scanout.resource_id)
        {
            let res = &self.resources_list[res_index];
            if info_set_scanout.rect.width < 16
                || info_set_scanout.rect.height < 16
                || !is_rect_in_resouce(&info_set_scanout.rect, res)
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

            let pixman_format = unsafe { pixman_image_get_format(res.pixman_image) };
            let bpp = (pixman_format_bpp(pixman_format as u32) as u32 + 8 - 1) / 8;
            let pixman_stride = unsafe { pixman_image_get_stride(res.pixman_image) };
            let offset = info_set_scanout.rect.x_coord * bpp
                + info_set_scanout.rect.y_coord * pixman_stride as u32;
            let res_data = unsafe { pixman_image_get_data(res.pixman_image) };
            let res_data_offset = unsafe { res_data.offset(offset as isize) };

            match scanout.surface {
                None => {
                    if create_surface(
                        scanout,
                        info_set_scanout,
                        res,
                        pixman_format,
                        pixman_stride,
                        res_data_offset,
                    )
                    .image
                    .is_null()
                    {
                        error!("HostError: surface image create failed, check pixman libary.");
                        return self.response_nodata(VIRTIO_GPU_RESP_ERR_UNSPEC, req);
                    }
                }
                Some(sur) => {
                    let scanout_data = unsafe { pixman_image_get_data(sur.image) };
                    if (res_data_offset != scanout_data
                        || scanout.width != info_set_scanout.rect.width
                        || scanout.height != info_set_scanout.rect.height)
                        && create_surface(
                            scanout,
                            info_set_scanout,
                            res,
                            pixman_format,
                            pixman_stride,
                            res_data_offset,
                        )
                        .image
                        .is_null()
                    {
                        error!("HostError: surface pixman image create failed, please check pixman libary.");
                        return self.response_nodata(VIRTIO_GPU_RESP_ERR_UNSPEC, req);
                    }
                }
            }

            if let Some(old_res_index) = self
                .resources_list
                .iter()
                .position(|x| x.resource_id == scanout.resource_id)
            {
                // Update old resource scanout bitmask.
                self.resources_list[old_res_index].scanouts_bitmask &=
                    !(1 << info_set_scanout.scanout_id);
            }
            // Update new resource scanout bitmask.
            self.resources_list[res_index].scanouts_bitmask |= 1 << info_set_scanout.scanout_id;
            // Update scanout configure.
            scanout.resource_id = info_set_scanout.resource_id;
            scanout.x = info_set_scanout.rect.x_coord;
            scanout.y = info_set_scanout.rect.y_coord;
            scanout.width = info_set_scanout.rect.width;
            scanout.height = info_set_scanout.rect.height;

            self.response_nodata(VIRTIO_GPU_RESP_OK_NODATA, req)
        } else {
            error!(
                "GuestError: The resource_id {} in set_scanout {} request is not existed.",
                info_set_scanout.resource_id, info_set_scanout.scanout_id
            );
            self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req)
        }
    }

    fn cmd_resource_flush(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_res_flush = VirtioGpuResourceFlush::default();
        self.get_request(req, &mut info_res_flush)?;

        if let Some(res_index) = self
            .resources_list
            .iter()
            .position(|x| x.resource_id == info_res_flush.resource_id)
        {
            let res = &self.resources_list[res_index];
            if !is_rect_in_resouce(&info_res_flush.rect, res) {
                error!(
                    "GuestError: The resource (id: {} width: {} height: {}) is outfit for flush rectangle (width: {} height: {} x_coord: {} y_coord: {}).",
                    res.resource_id, res.width, res.height,
                    info_res_flush.rect.width, info_res_flush.rect.height,
                    info_res_flush.rect.x_coord, info_res_flush.rect.y_coord,
                );
                return self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, req);
            }

            unsafe {
                let mut flush_reg = pixman_region16_t::default();
                let flush_reg_ptr: *mut pixman_region16_t =
                    &mut flush_reg as *mut pixman_region16_t;
                pixman_region_init_rect(
                    flush_reg_ptr,
                    info_res_flush.rect.x_coord as i32,
                    info_res_flush.rect.y_coord as i32,
                    info_res_flush.rect.width,
                    info_res_flush.rect.height,
                );
                for i in 0..self.num_scanouts {
                    // Flushes any scanouts the resource is being used on.
                    if res.scanouts_bitmask & (1 << i) != 0 {
                        let scanout = &self.scanouts[i as usize];
                        let mut rect_reg = pixman_region16_t::default();
                        let mut final_reg = pixman_region16_t::default();
                        let rect_reg_ptr: *mut pixman_region16_t =
                            &mut rect_reg as *mut pixman_region16_t;
                        let final_reg_ptr: *mut pixman_region16_t =
                            &mut final_reg as *mut pixman_region16_t;

                        pixman_region_init(final_reg_ptr);
                        pixman_region_init_rect(
                            rect_reg_ptr,
                            scanout.x as i32,
                            scanout.y as i32,
                            scanout.width,
                            scanout.height,
                        );
                        pixman_region_intersect(final_reg_ptr, flush_reg_ptr, rect_reg_ptr);
                        pixman_region_translate(
                            final_reg_ptr,
                            -(scanout.x as i32),
                            -(scanout.y as i32),
                        );
                        let extents = pixman_region_extents(final_reg_ptr);
                        display_graphic_update(
                            scanout.con_id,
                            (*extents).x1 as i32,
                            (*extents).y1 as i32,
                            ((*extents).x2 - (*extents).x1) as i32,
                            ((*extents).y2 - (*extents).y1) as i32,
                        );
                        pixman_region_fini(rect_reg_ptr);
                        pixman_region_fini(final_reg_ptr);
                    }
                }
                pixman_region_fini(flush_reg_ptr);
            }
            self.response_nodata(VIRTIO_GPU_RESP_OK_NODATA, req)
        } else {
            error!(
                "GuestError: The resource_id {} in resource flush request is not existed.",
                info_res_flush.resource_id
            );
            self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req)
        }
    }

    fn cmd_transfer_to_host_2d_params_check(
        &mut self,
        info_transfer: &VirtioGpuTransferToHost2d,
    ) -> u32 {
        let res_idx = self
            .resources_list
            .iter()
            .position(|x| x.resource_id == info_transfer.resource_id);

        if res_idx.is_none() {
            error!(
                "GuestError: The resource_id {} in transfer to host 2d request is not existed.",
                info_transfer.resource_id
            );
            return VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
        }

        let res = &self.resources_list[res_idx.unwrap()];
        if res.iov.is_empty() {
            error!(
                "GuestError: The resource_id {} in transfer to host 2d request don't have iov.",
                info_transfer.resource_id
            );
            return VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
        }

        if !is_rect_in_resouce(&info_transfer.rect, res) {
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
            return VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
        }

        0
    }

    fn cmd_transfer_to_host_2d_update_resource(
        &mut self,
        info_transfer: &VirtioGpuTransferToHost2d,
    ) {
        // SAFETY: unwrap is safe because it has been checked in params check.
        let res = self
            .resources_list
            .iter()
            .find(|&x| x.resource_id == info_transfer.resource_id)
            .unwrap();
        let pixman_format;
        let bpp;
        let stride;
        let data;
        unsafe {
            pixman_format = pixman_image_get_format(res.pixman_image);
            bpp = (pixman_format_bpp(pixman_format as u32) as u32 + 8 - 1) / 8;
            stride = pixman_image_get_stride(res.pixman_image);
            data = pixman_image_get_data(res.pixman_image);
        }
        let data_cast: *mut u8 = data.cast();
        let mut dst_ofs: usize = (info_transfer.rect.y_coord * stride as u32
            + info_transfer.rect.x_coord * bpp) as usize;
        // It can be considered that PARTIAL or complete image data is stored in
        // the res.iov[]. And info_transfer.offset is the offset from res.iov[0].base
        // to the start position of the resource we really want to update.
        let mut src_ofs: usize = info_transfer.offset as usize;
        // current iov's index
        let mut iov_idx: usize = 0;
        // current iov's offset
        let mut iov_ofs: usize = 0;
        let mut iov_len_sum: usize = 0;

        // move to correct iov
        loop {
            if iov_len_sum == src_ofs || iov_idx >= res.iov.len() {
                break;
            }

            if res.iov[iov_idx].iov_len as usize + iov_len_sum <= src_ofs {
                iov_len_sum += res.iov[iov_idx].iov_len as usize;
                iov_idx += 1;
            } else {
                iov_ofs = src_ofs - iov_len_sum;
                break;
            }
        }

        if iov_idx >= res.iov.len() {
            warn!("GuestWarn: the start pos of transfer data from guest is longer than resource's len.");
            return;
        }

        // We divide regions into that need to be copied and can be skipped.
        let src_cpy_section: usize = (info_transfer.rect.width * bpp) as usize;
        let src_expected: usize = info_transfer.offset as usize
            + ((info_transfer.rect.height - 1) * stride as u32) as usize
            + (info_transfer.rect.width * bpp) as usize;

        loop {
            if src_ofs >= src_expected || iov_idx >= res.iov.len() {
                break;
            }

            let iov_left = res.iov[iov_idx].iov_len as usize - iov_ofs;

            let pos = (src_ofs - info_transfer.offset as usize) % (stride as usize);
            if pos >= src_cpy_section {
                if pos + iov_left <= stride as usize {
                    src_ofs += iov_left;
                    dst_ofs += iov_left;
                    iov_idx += 1;
                    iov_ofs = 0;
                } else {
                    src_ofs += stride as usize - pos;
                    dst_ofs += stride as usize - pos;
                    iov_ofs += stride as usize - pos;
                }
            } else if pos + iov_left <= src_cpy_section {
                unsafe {
                    ptr::copy(
                        (res.iov[iov_idx].iov_base as *const u8).add(iov_ofs),
                        data_cast.add(dst_ofs),
                        iov_left,
                    );
                }
                src_ofs += iov_left;
                dst_ofs += iov_left;
                iov_idx += 1;
                iov_ofs = 0;
            } else {
                // pos + iov_left > src_cpy_section
                unsafe {
                    ptr::copy(
                        (res.iov[iov_idx].iov_base as *const u8).add(iov_ofs),
                        data_cast.add(dst_ofs),
                        src_cpy_section - pos,
                    );
                }
                src_ofs += src_cpy_section - pos;
                dst_ofs += src_cpy_section - pos;
                iov_ofs += src_cpy_section - pos;
            }
        }
    }

    fn cmd_transfer_to_host_2d(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_transfer = VirtioGpuTransferToHost2d::default();
        self.get_request(req, &mut info_transfer)?;

        let errcode = self.cmd_transfer_to_host_2d_params_check(&info_transfer);
        if errcode != 0 {
            return self.response_nodata(errcode, req);
        }

        self.cmd_transfer_to_host_2d_update_resource(&info_transfer);
        self.response_nodata(VIRTIO_GPU_RESP_OK_NODATA, req)
    }

    fn cmd_resource_attach_backing(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_attach_backing = VirtioGpuResourceAttachBacking::default();
        self.get_request(req, &mut info_attach_backing)?;

        if let Some(res_index) = self
            .resources_list
            .iter()
            .position(|x| x.resource_id == info_attach_backing.resource_id)
        {
            let res = &mut self.resources_list[res_index];
            if !res.iov.is_empty() {
                error!(
                    "GuestError: The resource_id {} in resource attach backing request allready has iov.",
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

            let esize =
                size_of::<VirtioGpuMemEntry>() as u64 * info_attach_backing.nr_entries as u64;
            if esize > req.out_len as u64 {
                error!(
                    "GuestError: The nr_entries {} in resource attach backing request is larger than total len {}.",
                    info_attach_backing.nr_entries, req.out_len,
                );
                return self.response_nodata(VIRTIO_GPU_RESP_ERR_UNSPEC, req);
            }

            let mut data_iovec = req.out_iovec.clone();
            // Move to entries part first.
            data_iovec = iov_discard_front_direct(
                &mut data_iovec,
                size_of::<VirtioGpuResourceAttachBacking>() as u64,
            )
            .unwrap()
            .to_vec();

            for i in 0..info_attach_backing.nr_entries {
                if i != 0 {
                    data_iovec = iov_discard_front_direct(
                        &mut data_iovec,
                        size_of::<VirtioGpuMemEntry>() as u64,
                    )
                    .unwrap()
                    .to_vec();
                }

                let mut entry = VirtioGpuMemEntry::default();
                if let Err(e) =
                    iov_to_buf_direct(&data_iovec, entry.as_mut_bytes()).and_then(|size| {
                        if size == size_of::<VirtioGpuMemEntry>() {
                            Ok(())
                        } else {
                            bail!(
                                "GuestError: Invalid size of gpu request data: len {}.",
                                size
                            );
                        }
                    })
                {
                    res.iov.clear();
                    error!("{:?}", e);
                    return self.response_nodata(VIRTIO_GPU_RESP_ERR_UNSPEC, req);
                }

                if let Some(iov_base) = self.mem_space.get_host_address(GuestAddress(entry.addr)) {
                    let iov_item = Iovec {
                        iov_base,
                        iov_len: entry.length as u64,
                    };
                    res.iov.push(iov_item);
                } else {
                    res.iov.clear();
                    error!("GuestError: Map desc base {:?} failed.", entry.addr);
                    return self.response_nodata(VIRTIO_GPU_RESP_ERR_UNSPEC, req);
                }
            }
            self.response_nodata(VIRTIO_GPU_RESP_OK_NODATA, req)
        } else {
            error!(
                "The resource_id {} in attach backing request request is not existed.",
                info_attach_backing.resource_id
            );
            self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req)
        }
    }

    fn cmd_resource_detach_backing(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let mut info_detach_backing = VirtioGpuResourceDetachBacking::default();
        self.get_request(req, &mut info_detach_backing)?;

        if let Some(res_index) = self
            .resources_list
            .iter()
            .position(|x| x.resource_id == info_detach_backing.resource_id)
        {
            let res = &mut self.resources_list[res_index];
            if res.iov.is_empty() {
                error!(
                    "GuestError: The resource_id {} in resource detach backing request don't have iov.",
                    info_detach_backing.resource_id
                );
                return self.response_nodata(VIRTIO_GPU_RESP_ERR_UNSPEC, req);
            }
            res.iov.clear();
            self.response_nodata(VIRTIO_GPU_RESP_OK_NODATA, req)
        } else {
            error!(
                "GuestError: The resource_id {} in detach backing request request is not existed.",
                info_detach_backing.resource_id
            );
            self.response_nodata(VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req)
        }
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
                _ => self.response_nodata(VIRTIO_GPU_RESP_ERR_UNSPEC, req),
            } {
                bail!("Fail to handle GPU request, {:?}.", e);
            }
        }

        Ok(())
    }

    fn ctrl_queue_evt_handler(&mut self) -> Result<()> {
        let mut queue = self.ctrl_queue.lock().unwrap();
        let mut req_queue = Vec::new();

        loop {
            let elem = queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)?;
            if elem.desc_num == 0 {
                break;
            }

            match VirtioGpuRequest::new(&self.mem_space, &elem) {
                Ok(req) => {
                    req_queue.push(req);
                }
                // TODO: Ignore this request may cause vnc suspended
                Err(e) => {
                    error!(
                        "GuestError: Failed to create GPU request, {:?}, just ignore it.",
                        e
                    );
                    queue
                        .vring
                        .add_used(&self.mem_space, elem.index, 0)
                        .with_context(|| "Failed to add used ring")?;
                    break;
                }
            }
        }

        drop(queue);
        self.process_control_queue(req_queue)
    }

    fn cursor_queue_evt_handler(&mut self) -> Result<()> {
        let cursor_queue = self.cursor_queue.clone();
        let mut queue = cursor_queue.lock().unwrap();

        loop {
            let elem = queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)?;
            if elem.desc_num == 0 {
                break;
            }

            match VirtioGpuRequest::new(&self.mem_space, &elem) {
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

            if let Err(e) = queue.vring.add_used(&self.mem_space, elem.index, 0) {
                bail!(
                    "Failed to add used ring(cursor), index {} {:?}",
                    elem.index,
                    e
                );
            }

            if queue
                .vring
                .should_notify(&self.mem_space, self.driver_features)
            {
                if let Err(e) =
                    (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue), false)
                {
                    error!("{:?}", e);
                    return Err(anyhow!(VirtioError::InterruptTrigger(
                        "gpu cursor",
                        VirtioInterruptType::Vring
                    )));
                }
            }
        }

        Ok(())
    }
}

impl Drop for GpuIoHandler {
    fn drop(&mut self) {
        for scanout in &self.scanouts {
            console_close(scanout.con_id);
        }

        while !self.resources_list.is_empty() {
            self.resource_destroy(0);
            self.resources_list.remove(0);
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
                error!("Failed to process queue for virtio gpu, err: {:?}", e,);
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
                error!("Failed to process queue for virtio gpu, err: {:?}", e,);
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
pub struct VirtioGpuConfig {
    events_read: u32,
    events_clear: u32,
    num_scanouts: u32,
    reserved: u32,
}

/// State of gpu device.
#[repr(C)]
#[derive(Clone, Copy, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct GpuState {
    /// Bitmask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Config space of the GPU device.
    config_space: VirtioGpuConfig,
}

/// GPU device structure.
#[derive(Default)]
pub struct Gpu {
    /// Configuration of the GPU device.
    cfg: GpuDevConfig,
    /// Status of the GPU device.
    state: GpuState,
    /// Callback to trigger interrupt.
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    /// Eventfd for device deactivate.
    deactivate_evts: Vec<RawFd>,
}

impl Gpu {
    pub fn new(cfg: GpuDevConfig) -> Gpu {
        Self {
            cfg,
            state: GpuState::default(),
            interrupt_cb: None,
            deactivate_evts: Vec::new(),
        }
    }

    fn build_device_config_space(&mut self) {
        self.state.config_space.num_scanouts = self.cfg.max_outputs;
        self.state.config_space.reserved = 0;
    }
}

impl VirtioDevice for Gpu {
    /// Realize virtio gpu device.
    fn realize(&mut self) -> Result<()> {
        if self.cfg.max_outputs > VIRTIO_GPU_MAX_SCANOUTS as u32 {
            bail!(
                "Invalid max_outputs {} which is bigger than {}",
                self.cfg.max_outputs,
                VIRTIO_GPU_MAX_SCANOUTS
            );
        }

        self.state.device_features = 1u64 << VIRTIO_F_VERSION_1;
        self.state.device_features |= 1u64 << VIRTIO_F_RING_EVENT_IDX;
        self.state.device_features |= 1u64 << VIRTIO_F_RING_INDIRECT_DESC;
        if self.cfg.edid {
            self.state.device_features |= 1 << VIRTIO_GPU_F_EDID;
        }

        self.build_device_config_space();

        Ok(())
    }

    /// Unrealize low level device.
    fn unrealize(&mut self) -> Result<()> {
        MigrationManager::unregister_device_instance(GpuState::descriptor(), &self.cfg.id);
        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_GPU
    }

    /// Get the count of virtio gpu queues.
    fn queue_num(&self) -> usize {
        QUEUE_NUM_GPU
    }

    /// Get the queue size of virtio gpu.
    fn queue_size(&self) -> u16 {
        DEFAULT_VIRTQUEUE_SIZE
    }

    /// Get device features from host.
    fn get_device_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.device_features, features_select)
    }

    /// Set driver features by guest.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        self.state.driver_features = self.checked_driver_features(page, value);
    }

    /// Get driver features by guest.
    fn get_driver_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.driver_features, features_select)
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config_slice = self.state.config_space.as_bytes();
        let config_len = config_slice.len() as u64;

        if offset
            .checked_add(data.len() as u64)
            .filter(|&end| end <= config_len)
            .is_none()
        {
            return Err(anyhow!(VirtioError::DevConfigOverflow(offset, config_len)));
        }

        let read_end: usize = offset as usize + data.len();
        data.write_all(&config_slice[offset as usize..read_end])?;

        Ok(())
    }

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let mut config_cpy = self.state.config_space;
        let config_cpy_slice = config_cpy.as_mut_bytes();
        let config_len = config_cpy_slice.len() as u64;

        if offset
            .checked_add(data.len() as u64)
            .filter(|&end| end <= config_len)
            .is_none()
        {
            return Err(anyhow!(VirtioError::DevConfigOverflow(offset, config_len)));
        }

        config_cpy_slice[(offset as usize)..(offset as usize + data.len())].copy_from_slice(data);
        if self.state.config_space.events_clear != 0 {
            self.state.config_space.events_read &= !config_cpy.events_clear;
        }

        Ok(())
    }

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<Queue>>],
        mut queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        if queues.len() != QUEUE_NUM_GPU {
            return Err(anyhow!(VirtioError::IncorrectQueueNum(
                QUEUE_NUM_GPU,
                queues.len()
            )));
        }

        self.interrupt_cb = Some(interrupt_cb.clone());
        let req_states = [VirtioGpuReqState::default(); VIRTIO_GPU_MAX_SCANOUTS];
        let mut scanouts = vec![];
        for _i in 0..VIRTIO_GPU_MAX_SCANOUTS {
            let mut scanout = GpuScanout::default();
            let gpu_opts = Rc::new(GpuOpts::default());
            scanout.con_id = console_init(gpu_opts);
            scanouts.push(scanout);
        }

        let mut handler = GpuIoHandler {
            ctrl_queue: queues[0].clone(),
            cursor_queue: queues[1].clone(),
            mem_space,
            ctrl_queue_evt: queue_evts.remove(0),
            cursor_queue_evt: queue_evts.remove(0),
            interrupt_cb,
            driver_features: self.state.driver_features,
            resources_list: Vec::new(),
            enable_output_bitmask: 1,
            num_scanouts: self.cfg.max_outputs,
            req_states,
            scanouts,
            max_hostmem: self.cfg.max_hostmem,
            used_hostmem: 0,
        };
        handler.req_states[0].width = self.cfg.xres;
        handler.req_states[0].height = self.cfg.yres;

        let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler)));
        register_event_helper(notifiers, None, &mut self.deactivate_evts)?;

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        unregister_event_helper(None, &mut self.deactivate_evts)
    }
}
