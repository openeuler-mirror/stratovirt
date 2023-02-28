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

// Demo GPU device is a simple pci device. Its purpose is to simulate the input of image
// to test the basic functions of VNC. During the initialization of device,
// it will register in the console. Users can write a rom address in the mmio
// configuration space of the device. The Demo GPU device can do corresponding
// operations by reading the commands. Currently, the supported operations are:
// Replace surface 、Update surface 、
// Set dirty for target area of the surface 、
// Update the cursor image.

use address_space::{AddressSpace, GuestAddress};
use anyhow::{bail, Result};
use byteorder::{ByteOrder, LittleEndian};
use log::info;
use std::{
    ptr,
    sync::{Arc, Mutex, Weak},
};
use util::pixman::pixman_format_code_t;
use vnc::{
    console::{
        console_close, console_init, display_cursor_define, display_graphic_update,
        display_replace_surface, DisplayConsole, DisplayMouse, DisplaySurface, HardWareOperations,
    },
    pixman::{
        create_pixman_image, get_image_data, get_image_format, get_image_stride, ref_pixman_image,
    },
};
pub const UPDATE_FACTOR: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];
use crate::demo_dev::DeviceTypeOperation;

#[derive(Debug)]
pub enum GpuEvent {
    ReplaceSurface = 0,
    ReplaceCursor = 1,
    GraphicUpdateArea = 2,
    GraphicUpdateDirty = 3,
    DeactiveEvent = 4,
}

impl From<u8> for GpuEvent {
    fn from(v: u8) -> Self {
        match v {
            0 => GpuEvent::ReplaceSurface,
            1 => GpuEvent::ReplaceCursor,
            2 => GpuEvent::GraphicUpdateArea,
            3 => GpuEvent::GraphicUpdateDirty,
            _ => GpuEvent::DeactiveEvent,
        }
    }
}

pub struct DemoGpu {
    sys_mem: Arc<AddressSpace>,
    con: Option<Weak<Mutex<DisplayConsole>>>,
    width: u32,
    height: u32,
    pub surface: Option<DisplaySurface>,
    mouse: Option<DisplayMouse>,
}
unsafe impl Send for DemoGpu {}

impl DemoGpu {
    pub fn new(sys_mem: Arc<AddressSpace>) -> Self {
        Self {
            sys_mem,
            con: None,
            width: 0,
            height: 0,
            surface: None,
            mouse: None,
        }
    }
}

impl DemoGpu {
    ///  Create a new surface, and replace the surface.
    pub fn hw_replace_surface(&mut self, width: u32, height: u32, format: u32) -> Result<()> {
        let pixman_format = match format {
            1 => pixman_format_code_t::PIXMAN_x2r10g10b10,
            2 => pixman_format_code_t::PIXMAN_r8g8b8,
            3 => pixman_format_code_t::PIXMAN_a1,
            4 => pixman_format_code_t::PIXMAN_yuy2,
            _ => pixman_format_code_t::PIXMAN_a8b8g8r8,
        };

        // Create Image.
        self.width = width;
        self.height = height;
        let image = create_pixman_image(
            pixman_format,
            self.width as i32,
            self.height as i32,
            ptr::null_mut(),
            self.width as i32 * 4,
        );
        let surface = DisplaySurface {
            format: get_image_format(image),
            image: ref_pixman_image(image),
        };
        self.surface = Some(surface);
        self.graphic_replace_surface()
    }

    /// Create a new cursor image, and update it.
    pub fn hw_replace_cursor(
        &mut self,
        width: u32,
        height: u32,
        hot_x: u32,
        hot_y: u32,
        mouse_data: u32,
    ) -> Result<()> {
        let mut mouse = DisplayMouse {
            width,
            height,
            hot_x,
            hot_y,
            data: vec![0_u8; mouse_data as usize],
        };
        display_cursor_define(&self.con, &mut mouse)?;
        self.mouse = Some(mouse);
        Ok(())
    }

    /// Change the pixels of the specified area in the image.
    pub fn update_image_area(&mut self, x: u32, y: u32, w: u32, h: u32) -> Result<()> {
        let image = self.surface.unwrap().image;
        let image_ptr = get_image_data(image) as *mut u8;
        let stride = get_image_stride(image);
        for i in y..y + h {
            let ptr = (image_ptr as usize + i as usize * stride as usize) as *mut u8;
            for j in x..x + w {
                let tmp_ptr = ptr as usize + 4 * j as usize;
                let rand_factor = (i * j) as usize;
                let len = UPDATE_FACTOR.len();
                unsafe {
                    // byte reverse by ^.
                    *(tmp_ptr as *mut u8) ^= UPDATE_FACTOR[rand_factor % len];
                    *((tmp_ptr + 1) as *mut u8) ^= UPDATE_FACTOR[(rand_factor + 1) % len];
                    *((tmp_ptr + 2) as *mut u8) ^= UPDATE_FACTOR[(rand_factor + 2) % len];
                    *((tmp_ptr + 3) as *mut u8) ^= UPDATE_FACTOR[(rand_factor + 3) % len];
                }
            }
        }
        self.graphic_update(x, y, w, h)
    }

    /// Set a area dirty.
    pub fn graphic_update(&mut self, x: u32, y: u32, w: u32, h: u32) -> Result<()> {
        display_graphic_update(&self.con, x as i32, y as i32, w as i32, h as i32)
    }

    /// Update the cursor image.
    pub fn graphic_cursor_define(&mut self) -> Result<()> {
        if let Some(mouse) = &mut self.mouse {
            display_cursor_define(&self.con, mouse)?;
        }
        Ok(())
    }

    /// Change surface in display.
    pub fn graphic_replace_surface(&mut self) -> Result<()> {
        display_replace_surface(&self.con, self.surface)
    }
}

impl DeviceTypeOperation for DemoGpu {
    fn read(&mut self, _data: &mut [u8], _addr: GuestAddress, _offset: u64) -> Result<()> {
        bail!("read is not support");
    }

    fn write(&mut self, data: &[u8], _addr: GuestAddress, _offset: u64) -> Result<()> {
        let mem_addr = LittleEndian::read_u64(data);
        // Event Type.
        let mut buf: Vec<u8> = vec![];
        self.sys_mem
            .read(&mut buf, address_space::GuestAddress(mem_addr), 21)?;
        let event_type = GpuEvent::from(buf[0]);
        let x = LittleEndian::read_u32(&buf[1..5]);
        let y = LittleEndian::read_u32(&buf[5..9]);
        let w = LittleEndian::read_u32(&buf[9..13]);
        let h = LittleEndian::read_u32(&buf[13..17]);
        let data_len = LittleEndian::read_u32(&buf[17..21]);
        info!(
            "GpuEvent: {:?}, x: {}, y: {}, w: {}, h: {}, data_len: {}",
            event_type, x, y, w, h, data_len
        );
        match event_type {
            GpuEvent::ReplaceSurface => self.hw_replace_surface(w, h, data_len),
            GpuEvent::ReplaceCursor => self.hw_replace_cursor(w, h, x, y, data_len),
            GpuEvent::GraphicUpdateArea => self.update_image_area(x, y, w, h),
            GpuEvent::GraphicUpdateDirty => self.graphic_update(x, y, w, h),
            _ => self.unrealize(),
        }
    }

    fn realize(&mut self) -> Result<()> {
        let con_opts = Arc::new(HwOpts {});
        self.con = console_init(con_opts);

        // Create Image.
        self.width = 640;
        self.height = 480;
        let image = create_pixman_image(
            pixman_format_code_t::PIXMAN_a8b8g8r8,
            self.width as i32,
            self.height as i32,
            ptr::null_mut(),
            self.width as i32 * 4,
        );
        let surface = DisplaySurface {
            format: get_image_format(image),
            image: ref_pixman_image(image),
        };
        self.surface = Some(surface);

        // Create image.
        let mouse = DisplayMouse {
            width: 64_u32,
            height: 64_u32,
            hot_x: 4_u32,
            hot_y: 4_u32,
            data: vec![0_u8; 64 * 64 * 4],
        };
        self.mouse = Some(mouse);
        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        let con = self.con.clone();
        console_close(&con)
    }
}

pub struct HwOpts {}
impl HardWareOperations for HwOpts {}
