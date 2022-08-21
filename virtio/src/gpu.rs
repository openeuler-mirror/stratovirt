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

use super::errors::{ErrorKind, Result, ResultExt};
use super::{
    Element, Queue, VirtioDevice, VirtioInterrupt, VirtioInterruptType, VIRTIO_F_VERSION_1,
    VIRTIO_TYPE_GPU,
};
use address_space::{AddressSpace, GuestAddress};
use error_chain::bail;
use log::{error, warn};
use machine_manager::config::{GpuConfig, VIRTIO_GPU_MAX_SCANOUTS};
use machine_manager::event_loop::EventLoop;
use migration::{DeviceStateDesc, FieldDesc};
use migration_derive::{ByteCode, Desc};
use std::cmp;
use std::io::Write;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::{ptr, vec};
use util::byte_code::ByteCode;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::num_ops::{read_u32, write_u32};
use util::pixman::{
    pixman_image_get_data, pixman_image_get_height, pixman_image_get_width, pixman_image_t,
};
use util::{aio::Iovec, edid::EdidInfo};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};
use vnc::{vnc_display_cursor, DisplayMouse, DisplaySurface};

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
const VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;

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

#[allow(unused)]
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
            .chain_err(|| ErrorKind::ReadObjectErr("the GPU's request header", out_elem.addr.0))?;
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

#[allow(unused)]
#[derive(Clone, Default)]
struct GpuScanout {
    surface: Option<DisplaySurface>,
    mouse: Option<DisplayMouse>,
    width: u32,
    height: u32,
    x: u32,
    y: u32,
    invalidate: i32,
    resource_id: u32,
    cursor: VirtioGpuUpdateCursor,
}

#[allow(unused)]
impl GpuScanout {
    fn clear(&mut self) {
        self.resource_id = 0;
        self.surface = None;
        self.width = 0;
        self.height = 0;
    }
}

/// Control block of GPU IO.
#[allow(unused)]
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

fn display_define_mouse(mouse: &mut Option<DisplayMouse>) {
    if let Some(mouse) = mouse {
        vnc_display_cursor(mouse);
    }
}

impl GpuIoHandler {
    fn gpu_update_cursor(&mut self, req: &VirtioGpuRequest) -> Result<()> {
        let info_cursor = self
            .mem_space
            .read_object::<VirtioGpuUpdateCursor>(req.out_header)
            .chain_err(|| {
                ErrorKind::ReadObjectErr("the GPU's cursor request header", req.out_header.0)
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
                    ..Default::default()
                };
                scanout.mouse = Some(tmp_mouse);
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
            display_define_mouse(&mut scanout.mouse);
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
            .chain_err(|| "Fail to write nodata response")?;
        self.ctrl_queue
            .lock()
            .unwrap()
            .vring
            .add_used(
                &self.mem_space,
                req.index,
                size_of::<VirtioGpuCtrlHdr>() as u32,
            )
            .chain_err(|| "Fail to add used elem for control queue")?;

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
            .chain_err(|| "Fail to write displayinfo")?;
        self.ctrl_queue
            .lock()
            .unwrap()
            .vring
            .add_used(
                &self.mem_space,
                req.index,
                size_of::<VirtioGpuDisplayInfo>() as u32,
            )
            .chain_err(|| "Fail to add used elem for control queue")?;

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
            .chain_err(|| {
                ErrorKind::ReadObjectErr("the GPU's edid request header", req.out_header.0)
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
            .chain_err(|| "Fail to write displayinfo")?;
        self.ctrl_queue
            .lock()
            .unwrap()
            .vring
            .add_used(
                &self.mem_space,
                req.index,
                size_of::<VirtioGpuDisplayInfo>() as u32,
            )
            .chain_err(|| "Fail to add used elem for control queue")?;

        Ok(())
    }

    fn gpu_cmd_resource_create_2d(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req)
    }

    fn gpu_cmd_resource_unref(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req)
    }

    fn gpu_cmd_set_scanout(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req)
    }

    fn gpu_cmd_resource_flush(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req)
    }

    fn gpu_cmd_transfer_to_host_2d(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req)
    }
    fn gpu_cmd_resource_attach_backing(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req)
    }
    fn gpu_cmd_resource_detach_backing(
        &mut self,
        need_interrupt: &mut bool,
        req: &VirtioGpuRequest,
    ) -> Result<()> {
        *need_interrupt = true;
        self.gpu_response_nodata(need_interrupt, VIRTIO_GPU_RESP_OK_NODATA, req)
    }
    fn process_control_queue(&mut self, mut req_queue: Vec<VirtioGpuRequest>) -> Result<()> {
        for req in req_queue.iter_mut() {
            let mut need_interrupt = true;

            if let Err(e) = match req.header.hdr_type {
                VIRTIO_GPU_CMD_GET_DISPLAY_INFO => self
                    .gpu_cmd_get_display_info(&mut need_interrupt, req)
                    .chain_err(|| "Fail to get display info"),
                VIRTIO_GPU_CMD_RESOURCE_CREATE_2D => self
                    .gpu_cmd_resource_create_2d(&mut need_interrupt, req)
                    .chain_err(|| "Fail to create 2d resource"),
                VIRTIO_GPU_CMD_RESOURCE_UNREF => self
                    .gpu_cmd_resource_unref(&mut need_interrupt, req)
                    .chain_err(|| "Fail to unref resource"),
                VIRTIO_GPU_CMD_SET_SCANOUT => self
                    .gpu_cmd_set_scanout(&mut need_interrupt, req)
                    .chain_err(|| "Fail to set scanout"),
                VIRTIO_GPU_CMD_RESOURCE_FLUSH => self
                    .gpu_cmd_resource_flush(&mut need_interrupt, req)
                    .chain_err(|| "Fail to flush resource"),
                VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D => self
                    .gpu_cmd_transfer_to_host_2d(&mut need_interrupt, req)
                    .chain_err(|| "Fail to transfer fo host 2d resource"),
                VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING => self
                    .gpu_cmd_resource_attach_backing(&mut need_interrupt, req)
                    .chain_err(|| "Fail to attach backing"),
                VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING => self
                    .gpu_cmd_resource_detach_backing(&mut need_interrupt, req)
                    .chain_err(|| "Fail to detach backing"),
                VIRTIO_GPU_CMD_GET_EDID => self
                    .gpu_cmd_get_edid(&mut need_interrupt, req)
                    .chain_err(|| "Fail to get edid info"),
                _ => self
                    .gpu_response_nodata(&mut need_interrupt, VIRTIO_GPU_RESP_ERR_UNSPEC, req)
                    .chain_err(|| "Fail to get nodata response"),
            } {
                error!("Fail to handle GPU request, {}", e);
            }

            if need_interrupt {
                (self.interrupt_cb)(
                    &VirtioInterruptType::Vring,
                    Some(&self.ctrl_queue.lock().unwrap()),
                )
                .chain_err(|| ErrorKind::InterruptTrigger("gpu", VirtioInterruptType::Vring))?;
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
            match VirtioGpuRequest::new(&self.mem_space, &elem, VIRTIO_GPU_CMD_CTRL) {
                Ok(req) => {
                    req_queue.push(req);
                }
                Err(e) => {
                    queue
                        .vring
                        .add_used(&self.mem_space, elem.index, 0)
                        .chain_err(|| "Failed to add used ring")?;
                    error!(
                        "failed to create GPU request, {}",
                        error_chain::ChainedError::display_chain(&e)
                    );
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
            match VirtioGpuRequest::new(&self.mem_space, &elem, VIRTIO_GPU_CMD_CURSOR) {
                Ok(req) => {
                    self.gpu_update_cursor(&req)
                        .chain_err(|| "Fail to update cursor")?;
                }
                Err(e) => {
                    error!(
                        "failed to create GPU request, {}",
                        error_chain::ChainedError::display_chain(&e)
                    );
                }
            }
            queue
                .vring
                .add_used(&self.mem_space, elem.index, 0)
                .chain_err(|| "Failed to add used ring")?;

            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue))
                .chain_err(|| ErrorKind::InterruptTrigger("gpu", VirtioInterruptType::Vring))?;
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
                error!(
                    "Failed to process queue for virtio gpu, err: {}",
                    error_chain::ChainedError::display_chain(&e),
                );
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
                error!(
                    "Failed to process queue for virtio gpu, err: {}",
                    error_chain::ChainedError::display_chain(&e),
                );
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
        let mut v = write_u32(value, page);
        let unrequested_features = v & !self.state.device_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request with unknown feature: {:x}", v);
            v &= !unrequested_features;
        }
        self.state.driver_features |= v;
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config_slice = self.state.config.as_bytes();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            return Err(ErrorKind::DevConfigOverflow(offset, config_len).into());
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
            return Err(ErrorKind::DevConfigOverflow(offset, config_len as u64).into());
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
            return Err(ErrorKind::IncorrectQueueNum(QUEUE_NUM_GPU, queues.len()).into());
        }

        self.interrupt_cb = Some(interrupt_cb.clone());
        let req_states = [VirtioGpuReqState::default(); VIRTIO_GPU_MAX_SCANOUTS];
        let mut scanouts = vec![];
        for _i in 0..VIRTIO_GPU_MAX_SCANOUTS {
            let scanout = GpuScanout::default();
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
            .chain_err(|| ErrorKind::EventFdWrite)
    }
}
