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

// Demo Dpy device is a simple pci device. Its purpose is to simulate the display
// of image from GPU to test the basic functions of GPU. During the initialization
// of device, it will register in the console. Users can write different address in
// the bar space of the device, the Demo Dpy device can do corresponding operations.
// Currently, the supported operations are:
// Get surface size, Get cursor image size, Get Surface data, Get cursor image data.

use crate::demo_dev::DeviceTypeOperation;
use address_space::{AddressSpace, GuestAddress};
use anyhow::{bail, Ok, Result};
use byteorder::{ByteOrder, LittleEndian};
use log::error;
use once_cell::sync::Lazy;
use std::{
    ptr,
    sync::{Arc, Mutex},
};
use util::pixman::{pixman_format_bpp, pixman_image_get_stride, pixman_image_t};
use vnc::{
    console::{
        register_display, DisplayChangeListener, DisplayChangeListenerOperations, DisplayMouse,
        DisplaySurface,
    },
    pixman::{
        get_image_data, get_image_format, get_image_height, ref_pixman_image, unref_pixman_image,
    },
};

unsafe impl Send for Surface {}
unsafe impl Sync for Surface {}
pub struct Surface {
    pub pixman_image: *mut pixman_image_t,
    image: Vec<u8>,
    cursor: Vec<u8>,
}

impl Default for Surface {
    fn default() -> Self {
        Self {
            pixman_image: ptr::null_mut(),
            image: vec![],
            cursor: vec![],
        }
    }
}

pub static DISPLAY: Lazy<Mutex<Vec<Arc<Mutex<Surface>>>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub struct DemoDisplay {
    sys_mem: Arc<AddressSpace>,
}

impl DemoDisplay {
    pub fn new(sys_mem: Arc<AddressSpace>) -> Self {
        Self { sys_mem }
    }
}

#[derive(Default)]
pub struct DpyInterface {}

impl DisplayChangeListenerOperations for DpyInterface {
    fn dpy_switch(&self, surface: &DisplaySurface) {
        if DISPLAY.lock().unwrap().is_empty() {
            error!("Demo Display is empty, check initialize");
            return;
        }

        let ds_clone = DISPLAY.lock().unwrap()[0].clone();
        let mut ds = ds_clone.lock().unwrap();
        unref_pixman_image(ds.pixman_image);
        ds.pixman_image = ref_pixman_image(surface.image);

        let res_data_ptr = get_image_data(surface.image) as *mut u8;
        let height = get_image_height(surface.image);
        let stride;
        unsafe {
            stride = pixman_image_get_stride(surface.image);
        }

        let size = height * stride;

        let mut data: Vec<u8> = vec![0u8; size as usize];
        unsafe {
            ptr::copy(res_data_ptr, data.as_mut_ptr(), size as usize);
        }
        ds.image = data;
    }

    fn dpy_refresh(&self, _dcl: &Arc<Mutex<DisplayChangeListener>>) {}

    fn dpy_image_update(&self, x: i32, y: i32, w: i32, h: i32) {
        if DISPLAY.lock().unwrap().is_empty() {
            error!("Demo Display is empty, check initialize");
            return;
        }

        let ds_clone = DISPLAY.lock().unwrap()[0].clone();
        let mut ds = ds_clone.lock().unwrap();
        let res_data_ptr = get_image_data(ds.pixman_image) as *mut u8;

        let bpp = pixman_format_bpp(get_image_format(ds.pixman_image) as u32);
        let stride;
        unsafe {
            stride = pixman_image_get_stride(ds.pixman_image);
        }

        let mut i = 0;
        let mut offset = y * stride as i32 + x * bpp as i32 / 8;
        let count = w * bpp as i32 / 8;
        while i < h {
            error!(
                "update from {} to {}, before is {}",
                offset,
                offset + count,
                ds.image[offset as usize]
            );

            unsafe {
                ptr::copy(
                    res_data_ptr.add(offset as usize),
                    ds.image.as_mut_ptr().add(offset as usize),
                    count as usize,
                );
            }
            error!(
                "update from {} to {}, after is {}",
                offset,
                offset + count,
                ds.image[offset as usize]
            );
            offset += stride as i32;
            i += 1;
        }
    }

    fn dpy_cursor_update(&self, cursor: &mut DisplayMouse) {
        if DISPLAY.lock().unwrap().is_empty() {
            error!("Demo Display is empty, check initialize");
            return;
        }

        let ds_clone = DISPLAY.lock().unwrap()[0].clone();
        let mut ds = ds_clone.lock().unwrap();

        ds.cursor = cursor.data.clone();
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DpyEvent {
    QuerySurface = 0,
    QueryCursor = 1,
    GetSurface = 2,
    GetCursor = 3,
    Deactive = 4,
}

// Support at max 64 * 64 image which format is 4 bytes.
// 0x0 WO for surface size
// 0x1 WO for cursor size
// 0x2 WO, surface data
// 0x3 WO, cursor data
impl DeviceTypeOperation for DemoDisplay {
    fn read(&mut self, _data: &mut [u8], _addr: GuestAddress, _offset: u64) -> Result<()> {
        bail!("Read is not support");
    }

    fn write(&mut self, data: &[u8], _addr: GuestAddress, offset: u64) -> Result<()> {
        if DISPLAY.lock().unwrap().is_empty() {
            error!("Demo Display is empty, write after get image");
            return Ok(());
        }

        let ds_clone = DISPLAY.lock().unwrap()[0].clone();
        let ds = ds_clone.lock().unwrap();

        let mem_addr = LittleEndian::read_u64(data);
        let mut buf: Vec<u8> = vec![];

        match offset {
            0 => {
                buf.push(ds.image.len() as u8);
                buf.push((ds.image.len() as u16 >> 8) as u8);
            }
            1 => {
                buf.push(ds.cursor.len() as u8);
                buf.push((ds.cursor.len() as u16 >> 8) as u8);
            }
            2 => {
                buf = ds.image.clone();
            }
            3 => {
                buf = ds.cursor.clone();
            }
            _ => {
                return self.unrealize();
            }
        }
        return self.sys_mem.write(
            &mut buf.as_slice(),
            address_space::GuestAddress(mem_addr),
            buf.len() as u64,
        );
    }

    fn realize(&mut self) -> Result<()> {
        DISPLAY
            .lock()
            .unwrap()
            .push(Arc::new(Mutex::new(Surface::default())));
        let opts = Arc::new(DpyInterface::default());
        let dcl = Arc::new(Mutex::new(DisplayChangeListener::new(None, opts)));
        register_display(&dcl)?;
        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        if DISPLAY.lock().unwrap().is_empty() {
            error!("Demo Display is empty, write after get image");
            return Ok(());
        }
        DISPLAY.lock().unwrap().pop();
        Ok(())
    }
}
