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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::{Context, Result};
use drm_fourcc::DrmFourcc;
use log::error;

use super::fwcfg::{FwCfgOps, FwCfgWriteCallback};
use crate::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysBusDevType};
use crate::{Device, DeviceBase};
use acpi::AmlBuilder;
use address_space::{AddressSpace, GuestAddress};
use machine_manager::event_loop::EventLoop;
use ui::console::{
    console_init, display_graphic_update, display_replace_surface, ConsoleType, DisplayConsole,
    DisplaySurface, HardWareOperations,
};
use ui::input::{key_event, KEYCODE_RET};
use util::pixman::{pixman_format_bpp, pixman_format_code_t, pixman_image_create_bits};

const BYTES_PER_PIXELS: u32 = 8;
const WIDTH_MAX: u32 = 16_000;
const HEIGHT_MAX: u32 = 12_000;
const INSTALL_CHECK_INTERVEL_MS: u64 = 500;
const INSTALL_RELEASE_INTERVEL_MS: u64 = 200;
const INSTALL_PRESS_INTERVEL_MS: u64 = 100;

#[repr(packed)]
struct RamfbCfg {
    _addr: u64,
    _fourcc: u32,
    _flags: u32,
    _width: u32,
    _height: u32,
    _stride: u32,
}

#[derive(Clone)]
pub struct RamfbState {
    pub surface: Option<DisplaySurface>,
    pub con: Option<Weak<Mutex<DisplayConsole>>>,
    sys_mem: Arc<AddressSpace>,
    install: Arc<AtomicBool>,
}

// SAFETY: The type of image, the field of the struct DisplaySurface
// is the raw pointer. create_display_surface() method will create
// image object. The memory that the image pointer refers to is
// modified by guest OS and accessed by vnc. So implement Sync and
// Send is safe.
unsafe impl Sync for RamfbState {}
// SAFETY: The reason is same as above.
unsafe impl Send for RamfbState {}

impl RamfbState {
    pub fn new(sys_mem: Arc<AddressSpace>, install: bool) -> Self {
        let ramfb_opts = Arc::new(RamfbInterface {});
        let con = console_init("ramfb".to_string(), ConsoleType::Graphic, ramfb_opts);
        Self {
            surface: None,
            con,
            sys_mem,
            install: Arc::new(AtomicBool::new(install)),
        }
    }

    pub fn setup(&mut self, fw_cfg: &Arc<Mutex<dyn FwCfgOps>>) -> Result<()> {
        let mut locked_fw_cfg = fw_cfg.lock().unwrap();
        let ramfb_state_cb = self.clone();
        let cfg: Vec<u8> = [0; size_of::<RamfbCfg>()].to_vec();
        locked_fw_cfg
            .add_file_callback_entry(
                "etc/ramfb",
                cfg,
                None,
                Some(Arc::new(Mutex::new(ramfb_state_cb))),
                true,
            )
            .with_context(|| "Failed to set fwcfg")?;
        Ok(())
    }

    fn create_display_surface(
        &mut self,
        width: u32,
        height: u32,
        format: pixman_format_code_t,
        mut stride: u32,
        addr: u64,
    ) {
        if width < 16 || height < 16 || width > WIDTH_MAX || height > HEIGHT_MAX {
            error!("The resolution: {}x{} is unsupported.", width, height);
        }

        if stride == 0 {
            let linesize = width * pixman_format_bpp(format as u32) as u32 / BYTES_PER_PIXELS;
            stride = linesize;
        }

        let fb_addr = match self.sys_mem.addr_cache_init(GuestAddress(addr)) {
            Some((hva, len)) => {
                if len < stride as u64 {
                    error!("Insufficient contiguous memory length");
                    return;
                }
                hva
            }
            None => {
                error!("Failed to get the host address of the framebuffer");
                return;
            }
        };

        let mut ds = DisplaySurface {
            format,
            ..Default::default()
        };
        // SAFETY: pixman_image_create_bits() is C function. All
        // parameters passed of the function have been checked.
        // It returns a raw pointer.
        unsafe {
            ds.image = pixman_image_create_bits(
                format,
                width as i32,
                height as i32,
                fb_addr as *mut u32,
                stride as i32,
            );
        }

        if ds.image.is_null() {
            error!("Failed to create the surface of Ramfb!");
            return;
        }

        self.surface = Some(ds);

        set_press_event(self.install.clone(), fb_addr as *const u8);
    }

    fn reset_ramfb_state(&mut self) {
        self.surface = None;
    }
}

impl FwCfgWriteCallback for RamfbState {
    fn write_callback(&mut self, data: Vec<u8>, _start: u64, _len: usize) {
        if data.len() < 28 {
            error!("RamfbCfg data format is incorrect");
            return;
        }
        let addr = u64::from_be_bytes(
            data.as_slice()
                .split_at(size_of::<u64>())
                .0
                .try_into()
                .unwrap(),
        );
        let fourcc = u32::from_be_bytes(
            data.as_slice()[8..]
                .split_at(size_of::<u32>())
                .0
                .try_into()
                .unwrap(),
        );
        let width = u32::from_be_bytes(
            data.as_slice()[16..]
                .split_at(size_of::<u32>())
                .0
                .try_into()
                .unwrap(),
        );
        let height = u32::from_be_bytes(
            data.as_slice()[20..]
                .split_at(size_of::<u32>())
                .0
                .try_into()
                .unwrap(),
        );
        let stride = u32::from_be_bytes(
            data.as_slice()[24..]
                .split_at(size_of::<u32>())
                .0
                .try_into()
                .unwrap(),
        );

        let format: pixman_format_code_t = if fourcc == DrmFourcc::Xrgb8888 as u32 {
            pixman_format_code_t::PIXMAN_x8r8g8b8
        } else {
            error!("Unsupported drm format: {}", fourcc);
            return;
        };

        self.create_display_surface(width, height, format, stride, addr);
        display_replace_surface(&self.con, self.surface)
            .unwrap_or_else(|e| error!("Error occurs during surface switching: {:?}", e));
    }
}

pub struct RamfbInterface {}
impl HardWareOperations for RamfbInterface {
    fn hw_update(&self, con: Arc<Mutex<DisplayConsole>>) {
        let locked_con = con.lock().unwrap();
        let width = locked_con.width;
        let height = locked_con.height;
        drop(locked_con);
        display_graphic_update(&Some(Arc::downgrade(&con)), 0, 0, width, height)
            .unwrap_or_else(|e| error!("Error occurs during graphic updating: {:?}", e));
    }
}

pub struct Ramfb {
    base: SysBusDevBase,
    pub ramfb_state: RamfbState,
}

impl Ramfb {
    pub fn new(sys_mem: Arc<AddressSpace>, install: bool) -> Self {
        Ramfb {
            base: SysBusDevBase::new(SysBusDevType::Ramfb),
            ramfb_state: RamfbState::new(sys_mem, install),
        }
    }

    pub fn realize(self, sysbus: &mut SysBus) -> Result<()> {
        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_dynamic_device(&dev)?;
        Ok(())
    }
}

impl Device for Ramfb {
    fn device_base(&self) -> &DeviceBase {
        &self.base.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base.base
    }
}

impl SysBusDevOps for Ramfb {
    fn sysbusdev_base(&self) -> &SysBusDevBase {
        &self.base
    }

    fn sysbusdev_base_mut(&mut self) -> &mut SysBusDevBase {
        &mut self.base
    }

    fn read(&mut self, _data: &mut [u8], _base: GuestAddress, _offset: u64) -> bool {
        error!("Ramfb can not be read!");
        false
    }

    fn write(&mut self, _data: &[u8], _base: GuestAddress, _offset: u64) -> bool {
        error!("Ramfb can not be written!");
        false
    }

    fn reset(&mut self) -> Result<()> {
        self.ramfb_state.reset_ramfb_state();
        Ok(())
    }
}

impl AmlBuilder for Ramfb {
    fn aml_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

fn set_press_event(install: Arc<AtomicBool>, data: *const u8) {
    let black_screen =
        // SAFETY: data is the raw pointer of framebuffer. EDKII has malloc the memory of
        // the framebuffer. So dereference the data is safe.
        unsafe { !data.is_null() && *data == 0 && *data.offset(1) == 0 && *data.offset(2) == 0 };
    if install.load(Ordering::Acquire) && black_screen {
        let set_press_func = Box::new(move || {
            set_press_event(install.clone(), data);
        });
        let press_func = Box::new(move || {
            key_event(KEYCODE_RET, true)
                .unwrap_or_else(|e| error!("Ramfb couldn't press return key: {:?}", e));
        });
        let release_func = Box::new(move || {
            key_event(KEYCODE_RET, false)
                .unwrap_or_else(|e| error!("Ramfb couldn't release return key: {:?}.", e));
        });

        let ctx = EventLoop::get_ctx(None).unwrap();
        ctx.timer_add(
            set_press_func,
            Duration::from_millis(INSTALL_CHECK_INTERVEL_MS),
        );
        ctx.timer_add(press_func, Duration::from_millis(INSTALL_PRESS_INTERVEL_MS));
        ctx.timer_add(
            release_func,
            Duration::from_millis(INSTALL_RELEASE_INTERVEL_MS),
        );
    } else {
        install.store(false, Ordering::Release);
    }
}
