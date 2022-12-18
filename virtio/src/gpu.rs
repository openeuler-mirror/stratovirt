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
    Element, Queue, VirtioDevice, VirtioInterrupt, VirtioInterruptType, VIRTIO_F_VERSION_1,
    VIRTIO_TYPE_GPU,
};
use crate::VirtioError;
use address_space::{AddressSpace, GuestAddress};
use anyhow::{anyhow, bail, Context, Result};
use log::error;
use machine_manager::config::{GpuConfig, VIRTIO_GPU_MAX_SCANOUTS};
use machine_manager::event_loop::EventLoop;
use migration::{DeviceStateDesc, FieldDesc};
use migration_derive::{ByteCode, Desc};
use std::cmp;
use std::io::Write;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::{ptr, vec};
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
    console_init, display_cursor_define, display_graphic_update, display_replace_surface,
    DisplayMouse, DisplaySurface, HardWareOperations,
};

/// Number of virtqueues.
const QUEUE_NUM_GPU: usize = 2;
/// Size of each virtqueue.
const QUEUE_SIZE_GPU: u16 = 256;

/// Flags for virtio gpu base conf.
const VIRTIO_GPU_FLAG_VIRGL_ENABLED: u32 = 1;
#[allow(unused)]
const VIRTIO_GPU_FLAG_STATS_ENABLED: u32 = 2;
const VIRTIO_GPU_FLAG_EDID_ENABLED: u32 = 3;

/// Features which virtio gpu cmd can support
const VIRTIO_GPU_FLAG_FENCE: u32 = 1 << 0;

/// flag used to distinguish the cmd type and format VirtioGpuRequest
const VIRTIO_GPU_CMD_CTRL: u32 = 0;
const VIRTIO_GPU_CMD_CURSOR: u32 = 1;

/// virtio_gpu_ctrl_type: 2d commands.
const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const VIRTIO_GPU_CMD_RESOURCE_UNREF: u32 = 0x0102;
const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0103;
const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x0104;
const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
const VIRTIO_GPU_CMD_GET_CAPSET_INFO: u32 = 0x0108;
const VIRTIO_GPU_CMD_GET_CAPSET: u32 = 0x0109;
const VIRTIO_GPU_CMD_GET_EDID: u32 = 0x010a;
/// virtio_gpu_ctrl_type: cursor commands.
const VIRTIO_GPU_CMD_UPDATE_CURSOR: u32 = 0x0300;
const VIRTIO_GPU_CMD_MOVE_CURSOR: u32 = 0x0301;
/// virtio_gpu_ctrl_type: success responses.
const VIRTIO_GPU_RESP_OK_NODATA: u32 = 0x1100;
const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;
const VIRTIO_GPU_RESP_OK_EDID: u32 = 0x1104;
/// virtio_gpu_ctrl_type: error responses.
const VIRTIO_GPU_RESP_ERR_UNSPEC: u32 = 0x1200;
const VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
const VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
const VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
const VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;

/// simple formats for fbcon/X use
const VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;
const VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: u32 = 2;
const VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM: u32 = 3;
const VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM: u32 = 4;
const VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM: u32 = 67;
const VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM: u32 = 68;
const VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM: u32 = 121;
const VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM: u32 = 134;

#[derive(Clone, Copy, Debug, ByteCode)]
pub struct VirtioGpuConfig {
    events_read: u32,
    events_clear: u32,
    num_scanouts: u32,
    reserved: u32,
}

#[derive(Clone, Copy, Debug, ByteCode)]
pub struct VirtioGpuBaseConf {
    max_outputs: u32,
    flags: u32,
    xres: u32,
    yres: u32,
}

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

impl VirtioGpuCtrlHdr {
    fn is_valid(&self) -> bool {
        match self.hdr_type {
            VIRTIO_GPU_CMD_UPDATE_CURSOR
            | VIRTIO_GPU_CMD_MOVE_CURSOR
            | VIRTIO_GPU_CMD_GET_DISPLAY_INFO
            | VIRTIO_GPU_CMD_RESOURCE_CREATE_2D
            | VIRTIO_GPU_CMD_RESOURCE_UNREF
            | VIRTIO_GPU_CMD_SET_SCANOUT
            | VIRTIO_GPU_CMD_RESOURCE_FLUSH
            | VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D
            | VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING
            | VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING
            | VIRTIO_GPU_CMD_GET_CAPSET_INFO
            | VIRTIO_GPU_CMD_GET_CAPSET
            | VIRTIO_GPU_CMD_GET_EDID => true,
            _ => {
                error!("request type {} is not supported for GPU", self.hdr_type);
                false
            }
        }
    }
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
    header: VirtioGpuCtrlHdr,
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
    header: VirtioGpuCtrlHdr,
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
}

impl ByteCode for VirtioGpuResourceCreate2d {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuResourceUnref {
    header: VirtioGpuCtrlHdr,
    resource_id: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuResourceUnref {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuSetScanout {
    header: VirtioGpuCtrlHdr,
    rect: VirtioGpuRect,
    scanout_id: u32,
    resource_id: u32,
}

impl ByteCode for VirtioGpuSetScanout {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuResourceFlush {
    header: VirtioGpuCtrlHdr,
    rect: VirtioGpuRect,
    resource_id: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuResourceFlush {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuTransferToHost2d {
    header: VirtioGpuCtrlHdr,
    rect: VirtioGpuRect,
    offset: u64,
    resource_id: u32,
    padding: u32,
}

impl ByteCode for VirtioGpuTransferToHost2d {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VirtioGpuResourceAttachBacking {
    header: VirtioGpuCtrlHdr,
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
    header: VirtioGpuCtrlHdr,
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
    desc_num: u16,
    out_iovec: Vec<Iovec>,
    in_iovec: Vec<Iovec>,
    in_header: GuestAddress,
    out_header: GuestAddress,
}

impl VirtioGpuRequest {
    fn new(mem_space: &Arc<AddressSpace>, elem: &Element, cmd_type: u32) -> Result<Self> {
        if cmd_type != VIRTIO_GPU_CMD_CTRL && cmd_type != VIRTIO_GPU_CMD_CURSOR {
            bail!("unsupport GPU request: {} ", cmd_type);
        }

        if elem.out_iovec.is_empty()
            || (cmd_type == VIRTIO_GPU_CMD_CTRL && elem.in_iovec.is_empty())
            || (cmd_type == VIRTIO_GPU_CMD_CURSOR && !elem.in_iovec.is_empty())
        {
            bail!(
                "Missed header for GPU request: out {} in {} desc num {}",
                elem.out_iovec.len(),
                elem.in_iovec.len(),
                elem.desc_num
            );
        }

        let out_elem = elem.out_iovec.get(0).unwrap();
        if out_elem.len < size_of::<VirtioGpuCtrlHdr>() as u32 {
            bail!(
                "Invalid out header for GPU request: length {}",
                out_elem.len
            );
        }

        let out_header = mem_space
            .read_object::<VirtioGpuCtrlHdr>(out_elem.addr)
            .with_context(|| {
                anyhow!(VirtioError::ReadObjectErr(
                    "the GPU's request header",
                    out_elem.addr.0
                ))
            })?;
        if !out_header.is_valid() {
            bail!("Unsupported GPU request type");
        }

        let in_elem_addr = match cmd_type {
            VIRTIO_GPU_CMD_CTRL => {
                let in_elem = elem.in_iovec.last().unwrap();
                if in_elem.len < 1 {
                    bail!("Invalid in header for GPU request: length {}", in_elem.len)
                }
                in_elem.addr
            }
            VIRTIO_GPU_CMD_CURSOR => GuestAddress(0),
            _ => {
                bail!("unsupport GPU request: {}", cmd_type)
            }
        };

        let mut request = VirtioGpuRequest {
            header: out_header,
            index: elem.index,
            desc_num: elem.desc_num,
            out_iovec: Vec::with_capacity(elem.out_iovec.len()),
            in_iovec: Vec::with_capacity(elem.in_iovec.len()),
            in_header: in_elem_addr,
            out_header: out_elem.addr,
        };

        for (index, elem_iov) in elem.in_iovec.iter().enumerate() {
            if index == elem.in_iovec.len() - 1 {
                break;
            }
            if let Some(hva) = mem_space.get_host_address(elem_iov.addr) {
                let iov = Iovec {
                    iov_base: hva,
                    iov_len: u64::from(elem_iov.len),
                };
                request.in_iovec.push(iov);
            }
        }

        for (_index, elem_iov) in elem.out_iovec.iter().enumerate() {
            request.out_iovec.push(Iovec {
                iov_base: elem_iov.addr.0,
                iov_len: elem_iov.len as u64,
            });
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
    header: VirtioGpuCtrlHdr,
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
    /// The virtqueue for sending cursor updates
    cursor_queue: Arc<Mutex<Queue>>,
    /// The address space to which the GPU device belongs.
    mem_space: Arc<AddressSpace>,
    /// Eventfd for contorl virtqueue.
    ctrl_queue_evt: EventFd,
    /// Eventfd for cursor virtqueue.
    cursor_queue_evt: EventFd,
    /// Eventfd for device deactivate.
    deactivate_evt: RawFd,
    /// Callback to trigger an interrupt.
    interrupt_cb: Arc<VirtioInterrupt>,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Vector for resources.
    resources_list: Vec<GpuResource>,
    /// The bit mask of whether scanout is enabled or not.
    enable_output_bitmask: u32,
    /// Baisc Configure of GPU device.
    base_conf: VirtioGpuBaseConf,
    /// States of all request in scanout.
    req_states: [VirtioGpuReqState; VIRTIO_GPU_MAX_SCANOUTS],
    ///
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

impl GpuIoHandler {
    fn gpu_get_pixman_format(&mut self, format: u32) -> Result<pixman_format_code_t> {
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

    fn gpu_get_image_hostmem(
        &mut self,
        format: pixman_format_code_t,
        width: u32,
        height: u32,
    ) -> u64 {
        let bpp = pixman_format_bpp(format as u32);
        let stride = ((width as u64 * bpp as u64 + 0x1f) >> 5) * (size_of::<u32>() as u64);
        height as u64 * stride
    }

    fn gpu_clear_resource_iovs(&mut self, res_index: usize) {
        let res = &mut self.resources_list[res_index];
        res.iov.clear();
    }

    fn gpu_update_cursor(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let info_cursor = self
            .mem_space
            .read_object::<VirtioGpuUpdateCursor>(req.out_header)
            .with_context(|| {
                anyhow!(VirtioError::ReadObjectErr(
                    "the GPU's cursor request header",
                    req.out_header.0
                ))
            })?;

        let scanout = &mut self.scanouts[info_cursor.pos.scanout_id as usize];
        if info_cursor.header.hdr_type == VIRTIO_GPU_CMD_MOVE_CURSOR {
            scanout.cursor.pos.x_coord = info_cursor.hot_x;
            scanout.cursor.pos.y_coord = info_cursor.hot_y;
        } else if info_cursor.header.hdr_type == VIRTIO_GPU_CMD_UPDATE_CURSOR {
            if scanout.mouse.is_none() {
                let tmp_mouse = DisplayMouse {
                    height: 64,
                    width: 64,
                    hot_x: info_cursor.hot_x,
                    hot_y: info_cursor.hot_y,
                    data: vec![0_u8; 64 * 64 * size_of::<u32>() as usize],
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

                        if res_width as u32 == scanout.mouse.as_ref().unwrap().width
                            && res_height as u32 == scanout.mouse.as_ref().unwrap().height
                        {
                            let pixels = scanout.mouse.as_ref().unwrap().width
                                * scanout.mouse.as_ref().unwrap().height;
                            let mouse_data_size = pixels * (size_of::<u32>() as u32);
                            let mut con = vec![0u8; 64 * 64 * 4];
                            let res_data_ptr = pixman_image_get_data(res.pixman_image) as *mut u8;
                            ptr::copy(res_data_ptr, con.as_mut_ptr(), mouse_data_size as usize);
                            scanout.mouse.as_mut().unwrap().data.clear();
                            scanout.mouse.as_mut().unwrap().data.append(&mut con);
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

    fn gpu_response_nodata(
        &mut self,
        need_interrupt: &mut bool,
        resp_head_type: u32,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        let mut resp = VirtioGpuCtrlHdr {
            hdr_type: resp_head_type,
            ..Default::default()
        };

        if (req.header.flags & VIRTIO_GPU_FLAG_FENCE) != 0 {
            resp.flags |= VIRTIO_GPU_FLAG_FENCE;
            resp.fence_id = req.header.fence_id;
            resp.ctx_id = req.header.ctx_id;
        }

        self.mem_space
            .write_object(&resp, req.in_header)
            .with_context(|| "Fail to write nodata response")?;
        self.ctrl_queue
            .lock()
            .unwrap()
            .vring
            .add_used(
                &self.mem_space,
                req.index,
                size_of::<VirtioGpuCtrlHdr>() as u32,
            )
            .with_context(|| "Fail to add used elem for control queue")?;

        Ok(())
    }

    fn gpu_cmd_get_display_info(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        let mut display_info = VirtioGpuDisplayInfo::default();
        display_info.header.hdr_type = VIRTIO_GPU_RESP_OK_DISPLAY_INFO;
        for i in 0..self.base_conf.max_outputs {
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
        self.mem_space
            .write_object(&display_info, req.in_header)
            .with_context(|| "Fail to write displayinfo")?;
        self.ctrl_queue
            .lock()
            .unwrap()
            .vring
            .add_used(
                &self.mem_space,
                req.index,
                size_of::<VirtioGpuDisplayInfo>() as u32,
            )
            .with_context(|| "Fail to add used elem for control queue")?;

        Ok(())
    }

    fn gpu_cmd_get_edid(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        let mut edid_resp = VirtioGpuRespEdid::default();
        edid_resp.header.hdr_type = VIRTIO_GPU_RESP_OK_EDID;

        let edid_req = self
            .mem_space
            .read_object::<VirtioGpuGetEdid>(req.out_header)
            .with_context(|| {
                anyhow!(VirtioError::ReadObjectErr(
                    "the GPU's edid request header",
                    req.out_header.0
                ))
            })?;

        if edid_req.scanouts >= self.base_conf.max_outputs {
            error!(
                "The scanouts {} of request exceeds the max_outputs {}",
                edid_req.scanouts, self.base_conf.max_outputs
            );
            return self.gpu_response_nodata(
                need_interrupt,
                VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
                req,
            );
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

        if (req.header.flags & VIRTIO_GPU_FLAG_FENCE) != 0 {
            edid_resp.header.flags |= VIRTIO_GPU_FLAG_FENCE;
            edid_resp.header.fence_id = req.header.fence_id;
            edid_resp.header.ctx_id = req.header.ctx_id;
        }
        self.mem_space
            .write_object(&edid_resp, req.in_header)
            .with_context(|| "Fail to write displayinfo")?;
        self.ctrl_queue
            .lock()
            .unwrap()
            .vring
            .add_used(
                &self.mem_space,
                req.index,
                size_of::<VirtioGpuDisplayInfo>() as u32,
            )
            .with_context(|| "Fail to add used elem for control queue")?;

        Ok(())
    }

    fn gpu_cmd_resource_create_2d(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        let info_create_2d = self
            .mem_space
            .read_object::<VirtioGpuResourceCreate2d>(req.out_header)
            .with_context(|| {
                anyhow!(VirtioError::ReadObjectErr(
                    "the GPU's resource create 2d request header",
                    req.out_header.0,
                ))
            })?;
        if info_create_2d.resource_id == 0 {
            error!("The 0 value for resource_id is illegal");
            return self.gpu_response_nodata(
                need_interrupt,
                VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
                req,
            );
        }

        if let Some(res) = self
            .resources_list
            .iter()
            .find(|&x| x.resource_id == info_create_2d.resource_id)
        {
            error!("The resource_id {} is already existed", res.resource_id);
            return self.gpu_response_nodata(
                need_interrupt,
                VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
                req,
            );
        }

        let mut res = GpuResource {
            width: info_create_2d.width,
            height: info_create_2d.height,
            format: info_create_2d.format,
            resource_id: info_create_2d.resource_id,
            ..Default::default()
        };
        let pixman_format = self
            .gpu_get_pixman_format(res.format)
            .with_context(|| "Fail to parse guest format")?;
        res.host_mem =
            self.gpu_get_image_hostmem(pixman_format, info_create_2d.width, info_create_2d.height);
        if res.host_mem + self.used_hostmem < self.max_hostmem {
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
                "Fail to create resource(id {}, width {}, height {}) on host",
                res.resource_id, res.width, res.height
            );
            return self.gpu_response_nodata(
                need_interrupt,
                VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY,
                req,
            );
        }

        self.used_hostmem += res.host_mem;
        self.resources_list.push(res);
        self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req)
    }

    fn gpu_destroy_resoure(
        &mut self,
        res_id: u32,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        if let Some(res_index) = self
            .resources_list
            .iter()
            .position(|x| x.resource_id == res_id)
        {
            let res = &mut self.resources_list[res_index];
            if res.scanouts_bitmask != 0 {
                for i in 0..self.base_conf.max_outputs {
                    if (res.scanouts_bitmask & (1 << i)) != 0 {
                        let scanout = &mut self.scanouts[i as usize];
                        if scanout.resource_id != 0 {
                            // disable the scanout.
                            res.scanouts_bitmask &= !(1 << i);
                            display_replace_surface(scanout.con_id, None);
                            scanout.clear();
                        }
                    }
                }
            }
            unsafe {
                pixman_image_unref(res.pixman_image);
            }
            self.used_hostmem -= res.host_mem;
            self.gpu_clear_resource_iovs(res_index);
            self.resources_list.remove(res_index);
        } else {
            error!("The resource_id {} is not existed", res_id);
            return self.gpu_response_nodata(
                need_interrupt,
                VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
                req,
            );
        }

        Ok(())
    }

    fn gpu_cmd_resource_unref(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        let info_resource_unref = self
            .mem_space
            .read_object::<VirtioGpuResourceUnref>(req.out_header)
            .with_context(|| {
                anyhow!(VirtioError::ReadObjectErr(
                    "the GPU's resource unref request header",
                    req.out_header.0,
                ))
            })?;

        self.gpu_destroy_resoure(info_resource_unref.resource_id, need_interrupt, req)
            .with_context(|| "Fail to unref guest resource")?;
        self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req)
    }

    fn gpu_cmd_set_scanout(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        let info_set_scanout = self
            .mem_space
            .read_object::<VirtioGpuSetScanout>(req.out_header)
            .with_context(|| {
                anyhow!(VirtioError::ReadObjectErr(
                    "the GPU's set scanout request header",
                    req.out_header.0
                ))
            })?;

        if info_set_scanout.scanout_id >= self.base_conf.max_outputs {
            error!(
                "The scanout id {} is out of range",
                info_set_scanout.scanout_id
            );
            return self.gpu_response_nodata(
                need_interrupt,
                VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID,
                req,
            );
        }

        // TODO refactor to disable function
        let scanout = &mut self.scanouts[info_set_scanout.scanout_id as usize];
        if info_set_scanout.resource_id == 0 {
            // set resource_id to 0 means disable the scanout.
            if let Some(res_index) = self
                .resources_list
                .iter()
                .position(|x| x.resource_id == scanout.resource_id)
            {
                let res = &mut self.resources_list[res_index];
                res.scanouts_bitmask &= !(1 << info_set_scanout.scanout_id);
            }
            display_replace_surface(scanout.con_id, None);
            scanout.clear();
            return self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req);
        }

        if let Some(res_index) = self
            .resources_list
            .iter()
            .position(|x| x.resource_id == info_set_scanout.resource_id)
        {
            let res = &self.resources_list[res_index];
            if info_set_scanout.rect.x_coord > res.width
                || info_set_scanout.rect.y_coord > res.height
                || info_set_scanout.rect.width > res.width
                || info_set_scanout.rect.height > res.height
                || info_set_scanout.rect.width < 16
                || info_set_scanout.rect.height < 16
                || info_set_scanout.rect.width + info_set_scanout.rect.x_coord > res.width
                || info_set_scanout.rect.height + info_set_scanout.rect.y_coord > res.height
            {
                error!(
                    "The resource (id: {} width: {} height: {}) is outfit for scanout (id: {} width: {} height: {} x_coord: {} y_coord: {})",
                    res.resource_id,
                    res.width,
                    res.height,
                    info_set_scanout.scanout_id,
                    info_set_scanout.rect.width,
                    info_set_scanout.rect.height,
                    info_set_scanout.rect.x_coord,
                    info_set_scanout.rect.y_coord,
                );
                return self.gpu_response_nodata(
                    need_interrupt,
                    VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
                    req,
                );
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
                        return self.gpu_response_nodata(
                            need_interrupt,
                            VIRTIO_GPU_RESP_ERR_UNSPEC,
                            req,
                        );
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
                        return self.gpu_response_nodata(
                            need_interrupt,
                            VIRTIO_GPU_RESP_ERR_UNSPEC,
                            req,
                        );
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

            self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req)
        } else {
            error!(
                "The resource_id {} in set_scanout {} request is not existed",
                info_set_scanout.resource_id, info_set_scanout.scanout_id
            );
            self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req)
        }
    }

    fn gpu_cmd_resource_flush(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        let info_res_flush = self
            .mem_space
            .read_object::<VirtioGpuResourceFlush>(req.out_header)
            .with_context(|| {
                anyhow!(VirtioError::ReadObjectErr(
                    "the GPU's resource flush request header",
                    req.out_header.0,
                ))
            })?;

        if let Some(res_index) = self
            .resources_list
            .iter()
            .position(|x| x.resource_id == info_res_flush.resource_id)
        {
            let res = &self.resources_list[res_index];
            if info_res_flush.rect.x_coord > res.width
                || info_res_flush.rect.y_coord > res.height
                || info_res_flush.rect.width > res.width
                || info_res_flush.rect.height > res.height
                || info_res_flush.rect.width + info_res_flush.rect.x_coord > res.width
                || info_res_flush.rect.height + info_res_flush.rect.y_coord > res.height
            {
                error!(
                    "The resource (id: {} width: {} height: {}) is outfit for flush rectangle (width: {} height: {} x_coord: {} y_coord: {})",
                    res.resource_id, res.width, res.height,
                    info_res_flush.rect.width, info_res_flush.rect.height,
                    info_res_flush.rect.x_coord, info_res_flush.rect.y_coord,
                );
                return self.gpu_response_nodata(
                    need_interrupt,
                    VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
                    req,
                );
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
                for i in 0..self.base_conf.max_outputs {
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
            self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req)
        } else {
            error!(
                "The resource_id {} in resource flush request is not existed",
                info_res_flush.resource_id
            );
            self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req)
        }
    }

    fn gpu_cmd_transfer_to_host_2d(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        let info_transfer = self
            .mem_space
            .read_object::<VirtioGpuTransferToHost2d>(req.out_header)
            .with_context(|| {
                anyhow!(VirtioError::ReadObjectErr(
                    "the GPU's transfer to host 2d request header",
                    req.out_header.0,
                ))
            })?;

        if let Some(res_index) = self
            .resources_list
            .iter()
            .position(|x| x.resource_id == info_transfer.resource_id)
        {
            let res = &self.resources_list[res_index];
            if res.iov.is_empty() {
                error!(
                    "The resource_id {} in transfer to host 2d request don't have iov",
                    info_transfer.resource_id
                );
                return self.gpu_response_nodata(
                    need_interrupt,
                    VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
                    req,
                );
            }

            if info_transfer.rect.x_coord > res.width
                || info_transfer.rect.y_coord > res.height
                || info_transfer.rect.width > res.width
                || info_transfer.rect.height > res.height
                || info_transfer.rect.width + info_transfer.rect.x_coord > res.width
                || info_transfer.rect.height + info_transfer.rect.y_coord > res.height
            {
                error!(
                    "The resource (id: {} width: {} height: {}) is outfit for transfer rectangle (offset: {} width: {} height: {} x_coord: {} y_coord: {})",
                    res.resource_id,
                    res.width,
                    res.height,
                    info_transfer.offset,
                    info_transfer.rect.width,
                    info_transfer.rect.height,
                    info_transfer.rect.x_coord,
                    info_transfer.rect.y_coord,
                );
                return self.gpu_response_nodata(
                    need_interrupt,
                    VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
                    req,
                );
            }

            unsafe {
                let pixman_format = pixman_image_get_format(res.pixman_image);
                let bpp = (pixman_format_bpp(pixman_format as u32) as u32 + 8 - 1) / 8;
                let stride = pixman_image_get_stride(res.pixman_image);
                let height = pixman_image_get_height(res.pixman_image);
                let width = pixman_image_get_width(res.pixman_image);
                let data = pixman_image_get_data(res.pixman_image);
                let data_cast: *mut u8 = data.cast();

                let mut iovec_buf = Vec::new();
                for item in res.iov.iter() {
                    let mut dst = Vec::new();
                    let src = std::slice::from_raw_parts(
                        item.iov_base as *const u8,
                        item.iov_len as usize,
                    );
                    dst.resize(item.iov_len as usize, 0);
                    dst[0..item.iov_len as usize].copy_from_slice(src);
                    iovec_buf.append(&mut dst);
                }

                if info_transfer.offset != 0
                    || info_transfer.rect.x_coord != 0
                    || info_transfer.rect.y_coord != 0
                    || info_transfer.rect.width != width as u32
                {
                    for h in 0..info_transfer.rect.height {
                        let offset_iov = info_transfer.offset as u32 + stride as u32 * h;
                        let offset_data = (info_transfer.rect.y_coord + h) * stride as u32
                            + (info_transfer.rect.x_coord * bpp);
                        ptr::copy(
                            iovec_buf.as_ptr().offset(offset_iov as isize),
                            data_cast.offset(offset_data as isize),
                            info_transfer.rect.width as usize * bpp as usize,
                        );
                    }
                } else {
                    ptr::copy(
                        iovec_buf.as_ptr(),
                        data_cast,
                        stride as usize * height as usize,
                    );
                }
            }
            self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req)
        } else {
            error!(
                "The resource_id {} in transfer to host 2d request is not existed",
                info_transfer.resource_id
            );
            self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req)
        }
    }
    fn gpu_cmd_resource_attach_backing(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        let info_attach_backing = self
            .mem_space
            .read_object::<VirtioGpuResourceAttachBacking>(req.out_header)
            .with_context(|| {
                anyhow!(VirtioError::ReadObjectErr(
                    "the GPU's resource attach backing request header",
                    req.out_header.0,
                ))
            })?;

        if let Some(res_index) = self
            .resources_list
            .iter()
            .position(|x| x.resource_id == info_attach_backing.resource_id)
        {
            let res = &mut self.resources_list[res_index];
            if !res.iov.is_empty() {
                error!(
                    "The resource_id {} in resource attach backing request allready has iov",
                    info_attach_backing.resource_id
                );
                return self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_ERR_UNSPEC, req);
            }

            if info_attach_backing.nr_entries > 16384 {
                error!(
                    "The nr_entries in resource attach backing request is too large ( {} > 16384)",
                    info_attach_backing.nr_entries
                );
                return self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_ERR_UNSPEC, req);
            }

            let mut base_entry = req.out_iovec.get(0).unwrap();
            let mut offset = size_of::<VirtioGpuResourceAttachBacking>() as u64;
            let esize =
                size_of::<VirtioGpuMemEntry>() as u64 * info_attach_backing.nr_entries as u64;
            if base_entry.iov_len < offset + esize {
                if req.out_iovec.len() <= 1 || req.out_iovec.get(1).unwrap().iov_len < esize {
                    error!("The entries is not setted");
                    return self.gpu_response_nodata(
                        need_interrupt,
                        VIRTIO_GPU_RESP_ERR_UNSPEC,
                        req,
                    );
                }
                base_entry = req.out_iovec.get(1).unwrap();
                offset = 0;
            }

            for i in 0..info_attach_backing.nr_entries {
                let entry_addr =
                    base_entry.iov_base + offset + i as u64 * size_of::<VirtioGpuMemEntry>() as u64;
                let info_gpu_mem_entry = self
                    .mem_space
                    .read_object::<VirtioGpuMemEntry>(GuestAddress(entry_addr))
                    .with_context(|| {
                        anyhow!(VirtioError::ReadObjectErr(
                            "the GPU's resource attach backing request header",
                            req.out_header.0,
                        ))
                    })?;
                let iov_base = self
                    .mem_space
                    .get_host_address(GuestAddress(info_gpu_mem_entry.addr))
                    .with_context(|| "Fail to get gpu mem entry host addr")?;
                let iov_item = Iovec {
                    iov_base,
                    iov_len: info_gpu_mem_entry.length as u64,
                };
                res.iov.push(iov_item);
            }

            self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req)
        } else {
            error!(
                "The resource_id {} in attach backing request request is not existed",
                info_attach_backing.resource_id
            );
            self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req)
        }
    }
    fn gpu_cmd_resource_detach_backing(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        let info_detach_backing = self
            .mem_space
            .read_object::<VirtioGpuResourceDetachBacking>(req.out_header)
            .with_context(|| {
                anyhow!(VirtioError::ReadObjectErr(
                    "the GPU's resource detach backing request header",
                    req.out_header.0,
                ))
            })?;

        if let Some(res_index) = self
            .resources_list
            .iter()
            .position(|x| x.resource_id == info_detach_backing.resource_id)
        {
            let res = &mut self.resources_list[res_index];
            if res.iov.is_empty() {
                error!(
                    "The resource_id {} in resource detach backing request don't have iov",
                    info_detach_backing.resource_id
                );
                return self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_ERR_UNSPEC, req);
            }
            self.gpu_clear_resource_iovs(res_index);
            self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req)
        } else {
            error!(
                "The resource_id {} in detach backing request request is not existed",
                info_detach_backing.resource_id
            );
            self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, req)
        }
    }
    fn process_control_queue(&mut self, mut req_queue: Vec<VirtioGpuRequest>) -> Result<()> {
        for req in req_queue.iter_mut() {
            let mut need_interrupt = true;

            if let Err(e) = match req.header.hdr_type {
                VIRTIO_GPU_CMD_GET_DISPLAY_INFO => self
                    .gpu_cmd_get_display_info(&mut need_interrupt, req)
                    .with_context(|| "Fail to get display info"),
                VIRTIO_GPU_CMD_RESOURCE_CREATE_2D => self
                    .gpu_cmd_resource_create_2d(&mut need_interrupt, req)
                    .with_context(|| "Fail to create 2d resource"),
                VIRTIO_GPU_CMD_RESOURCE_UNREF => self
                    .gpu_cmd_resource_unref(&mut need_interrupt, req)
                    .with_context(|| "Fail to unref resource"),
                VIRTIO_GPU_CMD_SET_SCANOUT => self
                    .gpu_cmd_set_scanout(&mut need_interrupt, req)
                    .with_context(|| "Fail to set scanout"),
                VIRTIO_GPU_CMD_RESOURCE_FLUSH => self
                    .gpu_cmd_resource_flush(&mut need_interrupt, req)
                    .with_context(|| "Fail to flush resource"),
                VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D => self
                    .gpu_cmd_transfer_to_host_2d(&mut need_interrupt, req)
                    .with_context(|| "Fail to transfer fo host 2d resource"),
                VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING => self
                    .gpu_cmd_resource_attach_backing(&mut need_interrupt, req)
                    .with_context(|| "Fail to attach backing"),
                VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING => self
                    .gpu_cmd_resource_detach_backing(&mut need_interrupt, req)
                    .with_context(|| "Fail to detach backing"),
                VIRTIO_GPU_CMD_GET_EDID => self
                    .gpu_cmd_get_edid(&mut need_interrupt, req)
                    .with_context(|| "Fail to get edid info"),
                _ => self
                    .gpu_response_nodata(&mut need_interrupt, VIRTIO_GPU_RESP_ERR_UNSPEC, req)
                    .with_context(|| "Fail to get nodata response"),
            } {
                error!("Fail to handle GPU request, {:?}", e);
            }

            if need_interrupt {
                (self.interrupt_cb)(
                    &VirtioInterruptType::Vring,
                    Some(&self.ctrl_queue.lock().unwrap()),
                    false,
                )
                .with_context(|| {
                    anyhow!(VirtioError::InterruptTrigger(
                        "gpu",
                        VirtioInterruptType::Vring
                    ))
                })?;
            }
        }

        Ok(())
    }

    fn ctrl_queue_evt_handler(&mut self) -> Result<()> {
        let mut queue = self.ctrl_queue.lock().unwrap();
        if !queue.is_valid(&self.mem_space) {
            bail!("Failed to handle any request, the queue is not ready");
        }

        let mut req_queue = Vec::new();
        while let Ok(elem) = queue.vring.pop_avail(&self.mem_space, self.driver_features) {
            if elem.desc_num == 0 {
                break;
            }
            match VirtioGpuRequest::new(&self.mem_space, &elem, VIRTIO_GPU_CMD_CTRL) {
                Ok(req) => {
                    req_queue.push(req);
                }
                Err(e) => {
                    queue
                        .vring
                        .add_used(&self.mem_space, elem.index, 0)
                        .with_context(|| "Failed to add used ring")?;
                    error!("failed to create GPU request, {:?}", e);
                }
            }
        }
        drop(queue);
        self.process_control_queue(req_queue)
    }

    fn cursor_queue_evt_handler(&mut self) -> Result<()> {
        let cursor_queue = self.cursor_queue.clone();
        let mut queue = cursor_queue.lock().unwrap();
        if !queue.is_valid(&self.mem_space) {
            bail!("Failed to handle any request, the queue is not ready");
        }

        while let Ok(elem) = queue.vring.pop_avail(&self.mem_space, self.driver_features) {
            if elem.desc_num == 0 {
                break;
            }
            match VirtioGpuRequest::new(&self.mem_space, &elem, VIRTIO_GPU_CMD_CURSOR) {
                Ok(req) => {
                    self.gpu_update_cursor(&req)
                        .with_context(|| "Fail to update cursor")?;
                }
                Err(e) => {
                    error!("failed to create GPU request, {:?}", e);
                }
            }
            queue
                .vring
                .add_used(&self.mem_space, elem.index, 0)
                .with_context(|| "Failed to add used ring")?;

            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue), false).with_context(
                || {
                    anyhow!(VirtioError::InterruptTrigger(
                        "gpu",
                        VirtioInterruptType::Vring
                    ))
                },
            )?;
        }

        Ok(())
    }

    fn deactivate_evt_handler(&mut self) -> Vec<EventNotifier> {
        let notifiers = vec![
            EventNotifier::new(
                NotifierOperation::Delete,
                self.ctrl_queue_evt.as_raw_fd(),
                None,
                EventSet::IN,
                Vec::new(),
            ),
            EventNotifier::new(
                NotifierOperation::Delete,
                self.cursor_queue_evt.as_raw_fd(),
                None,
                EventSet::IN,
                Vec::new(),
            ),
            EventNotifier::new(
                NotifierOperation::Delete,
                self.deactivate_evt,
                None,
                EventSet::IN,
                Vec::new(),
            ),
        ];
        notifiers
    }
}

impl EventNotifierHelper for GpuIoHandler {
    fn internal_notifiers(gpu_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        // Register event notifier for deactivate_evt.
        let gpu_handler_clone = gpu_handler.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            Some(gpu_handler_clone.lock().unwrap().deactivate_evt_handler())
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            gpu_handler.lock().unwrap().deactivate_evt,
            None,
            EventSet::IN,
            vec![Arc::new(Mutex::new(handler))],
        ));

        // Register event notifier for ctrl_queue_evt.
        let gpu_handler_clone = gpu_handler.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            if let Err(e) = gpu_handler_clone.lock().unwrap().ctrl_queue_evt_handler() {
                error!("Failed to process queue for virtio gpu, err: {:?}", e,);
            }

            None
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            gpu_handler.lock().unwrap().ctrl_queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![Arc::new(Mutex::new(handler))],
        ));

        // Register event notifier for cursor_queue_evt.
        let gpu_handler_clone = gpu_handler.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            if let Err(e) = gpu_handler_clone.lock().unwrap().cursor_queue_evt_handler() {
                error!("Failed to process queue for virtio gpu, err: {:?}", e,);
            }

            None
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            gpu_handler.lock().unwrap().cursor_queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![Arc::new(Mutex::new(handler))],
        ));

        notifiers
    }
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
    config: VirtioGpuConfig,
    /// Baisc Configure of GPU device.
    base_conf: VirtioGpuBaseConf,
}

/// GPU device structure.
pub struct Gpu {
    /// Configuration of the GPU device.
    gpu_conf: GpuConfig,
    /// Status of the GPU device.
    state: GpuState,
    /// Callback to trigger interrupt.
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    /// Eventfd for device deactivate.
    deactivate_evt: EventFd,
}

impl Default for Gpu {
    fn default() -> Self {
        Gpu {
            gpu_conf: GpuConfig::default(),
            state: GpuState::default(),
            interrupt_cb: None,
            deactivate_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }
}

impl Gpu {
    pub fn new(gpu_conf: GpuConfig) -> Gpu {
        let mut state = GpuState::default();
        state.base_conf.xres = gpu_conf.xres;
        state.base_conf.yres = gpu_conf.yres;
        if gpu_conf.edid {
            state.base_conf.flags &= 1 << VIRTIO_GPU_FLAG_EDID_ENABLED;
        }
        state.base_conf.max_outputs = gpu_conf.max_outputs;
        state.device_features = 1u64 << VIRTIO_F_VERSION_1;
        Self {
            gpu_conf,
            state,
            interrupt_cb: None,
            deactivate_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }
}

impl VirtioDevice for Gpu {
    /// Realize virtio gpu device.
    fn realize(&mut self) -> Result<()> {
        if self.gpu_conf.max_outputs > VIRTIO_GPU_MAX_SCANOUTS as u32 {
            bail!(
                "Invalid max_outputs {} which is bigger than {}",
                self.gpu_conf.max_outputs,
                VIRTIO_GPU_MAX_SCANOUTS
            );
        }

        // Virgl is not supported.
        self.state.base_conf.flags &= !(1 << VIRTIO_GPU_FLAG_VIRGL_ENABLED);
        self.state.config.num_scanouts = self.state.base_conf.max_outputs;
        self.state.config.reserved = 0;

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
        QUEUE_SIZE_GPU
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
        let config_slice = self.state.config.as_bytes();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            return Err(anyhow!(VirtioError::DevConfigOverflow(offset, config_len)));
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])?;
        }
        Ok(())
    }

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let config_slice = self.state.config.as_mut_bytes();
        let config_len = config_slice.len();
        if offset as usize + data_len > config_len {
            return Err(anyhow!(VirtioError::DevConfigOverflow(
                offset,
                config_len as u64
            )));
        }

        config_slice[(offset as usize)..(offset as usize + data_len)].copy_from_slice(data);

        if self.state.config.events_clear != 0 {
            self.state.config.events_read &= !self.state.config.events_clear;
        }

        Ok(())
    }

    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<Queue>>],
        mut queue_evts: Vec<EventFd>,
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

        let mut gpu_handler = GpuIoHandler {
            ctrl_queue: queues[0].clone(),
            cursor_queue: queues[1].clone(),
            mem_space,
            ctrl_queue_evt: queue_evts.remove(0),
            cursor_queue_evt: queue_evts.remove(0),
            deactivate_evt: self.deactivate_evt.as_raw_fd(),
            interrupt_cb,
            driver_features: self.state.driver_features,
            resources_list: Vec::new(),
            enable_output_bitmask: 1,
            base_conf: self.state.base_conf,
            scanouts,
            req_states,
            max_hostmem: self.gpu_conf.max_hostmem,
            used_hostmem: 0,
        };
        gpu_handler.req_states[0].width = self.state.base_conf.xres;
        gpu_handler.req_states[0].height = self.state.base_conf.yres;

        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(gpu_handler))),
            None,
        )?;

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        self.deactivate_evt
            .write(1)
            .with_context(|| anyhow!(VirtioError::EventFdWrite))
    }
}
