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

use anyhow::{Context, Ok, Result};
use clap::{ArgAction, Parser};
use drm_fourcc::DrmFourcc;
use log::error;
use serde::{Deserialize, Serialize};

use super::fwcfg::{FwCfgOps, FwCfgWriteCallback};
use crate::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysBusDevType};
use crate::{convert_bus_mut, Device, DeviceBase, MUT_SYS_BUS};
use acpi::AmlBuilder;
use address_space::{AddressAttr, AddressSpace, GuestAddress};
use machine_manager::config::valid_id;
use machine_manager::event_loop::EventLoop;
use migration::snapshot::RAMFB_SNAPSHOT_ID;
use migration::{DeviceStateDesc, MigrationError, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::DescSerde;
use ui::console::{
    console_init, display_graphic_update, display_replace_surface, ConsoleType, DisplayConsole,
    DisplaySurface, HardWareOperations,
};
use ui::input::{key_event, KEYCODE_RET};
use util::gen_base_func;
use util::pixman::{pixman_format_bpp, pixman_format_code_t, pixman_image_create_bits};

const BYTES_PER_PIXELS: u32 = 8;
const WIDTH_MAX: u32 = 16_000;
const HEIGHT_MAX: u32 = 12_000;
const INSTALL_CHECK_INTERVEL_MS: u64 = 500;
const INSTALL_RELEASE_INTERVEL_MS: u64 = 200;
const INSTALL_PRESS_INTERVEL_MS: u64 = 100;

#[derive(Parser, Debug, Clone)]
#[command(no_binary_name(true))]
pub struct RamfbConfig {
    #[arg(long, value_parser = ["ramfb"])]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long, default_value = "false", action = ArgAction::Append)]
    pub install: bool,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, DescSerde, Deserialize, Serialize)]
#[desc_version(current_version = "0.1.0")]
struct RamfbCfg {
    addr: u64,
    fourcc: u32,
    flags: u32,
    width: u32,
    height: u32,
    stride: u32,
}

#[derive(Clone)]
pub struct RamfbState {
    pub surface: Option<DisplaySurface>,
    pub con: Option<Weak<Mutex<DisplayConsole>>>,
    sys_mem: Arc<AddressSpace>,
    install: Arc<AtomicBool>,
    cfg: RamfbCfg,
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
            cfg: RamfbCfg::default(),
        }
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
            let linesize = width * u32::from(pixman_format_bpp(format as u32)) / BYTES_PER_PIXELS;
            stride = linesize;
        }

        let (fb_addr, fb_len) = match self
            .sys_mem
            .addr_cache_init(GuestAddress(addr), AddressAttr::Ram)
        {
            Some((hva, len)) => {
                let sf_len = u64::from(stride) * u64::from(height);
                if len < sf_len {
                    error!("Insufficient contiguous memory length");
                    return;
                }
                (hva, len)
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

        if fb_len >= 3 {
            // SAFETY: fb_addr is valid and length is enough.
            unsafe { set_press_event(self.install.clone(), fb_addr as *const u8) };
        }
    }

    fn replace_surface(&mut self) {
        let format: pixman_format_code_t = if self.cfg.fourcc == DrmFourcc::Xrgb8888 as u32 {
            pixman_format_code_t::PIXMAN_x8r8g8b8
        } else {
            error!("Unsupported drm format: {}", { self.cfg.fourcc });
            return;
        };

        self.create_display_surface(
            self.cfg.width,
            self.cfg.height,
            format,
            self.cfg.stride,
            self.cfg.addr,
        );
        display_replace_surface(&self.con, self.surface)
            .unwrap_or_else(|e| error!("Error occurs during surface switching: {:?}", e));
    }

    fn reset_ramfb_state(&mut self) {
        self.surface = None;
        self.cfg = RamfbCfg::default();
    }
}

impl FwCfgWriteCallback for RamfbState {
    fn write_callback(&mut self, data: Vec<u8>, _start: u64, _len: usize) {
        if data.len() < 28 {
            error!("RamfbCfg data format is incorrect");
            return;
        }
        self.cfg.addr = u64::from_be_bytes(
            data.as_slice()
                .split_at(size_of::<u64>())
                .0
                .try_into()
                .unwrap(),
        );
        self.cfg.fourcc = u32::from_be_bytes(
            data.as_slice()[8..]
                .split_at(size_of::<u32>())
                .0
                .try_into()
                .unwrap(),
        );
        self.cfg.width = u32::from_be_bytes(
            data.as_slice()[16..]
                .split_at(size_of::<u32>())
                .0
                .try_into()
                .unwrap(),
        );
        self.cfg.height = u32::from_be_bytes(
            data.as_slice()[20..]
                .split_at(size_of::<u32>())
                .0
                .try_into()
                .unwrap(),
        );
        self.cfg.stride = u32::from_be_bytes(
            data.as_slice()[24..]
                .split_at(size_of::<u32>())
                .0
                .try_into()
                .unwrap(),
        );

        self.replace_surface();
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
    ramfb_state: Arc<Mutex<RamfbState>>,
}

impl Ramfb {
    pub fn new(
        sys_mem: Arc<AddressSpace>,
        sysbus: &Arc<Mutex<SysBus>>,
        install: bool,
        fw_cfg: &Arc<Mutex<dyn FwCfgOps>>,
    ) -> Result<Self> {
        let mut ramfb = Ramfb {
            base: SysBusDevBase::new(SysBusDevType::Ramfb),
            ramfb_state: Arc::new(Mutex::new(RamfbState::new(sys_mem, install))),
        };

        let mut locked_fw_cfg = fw_cfg.lock().unwrap();
        let cfg: Vec<u8> = [0; size_of::<RamfbCfg>()].to_vec();
        locked_fw_cfg
            .add_file_callback_entry(
                "etc/ramfb",
                cfg,
                None,
                Some(ramfb.ramfb_state.clone()),
                true,
            )
            .with_context(|| "Failed to set fwcfg")?;

        ramfb.set_parent_bus(sysbus.clone());
        Ok(ramfb)
    }
}

impl Device for Ramfb {
    gen_base_func!(device_base, device_base_mut, DeviceBase, base.base);

    fn reset(&mut self, _reset_child_device: bool) -> Result<()> {
        self.ramfb_state.lock().unwrap().reset_ramfb_state();
        Ok(())
    }

    fn realize(self) -> Result<Arc<Mutex<Self>>> {
        let parent_bus = self.parent_bus().unwrap().upgrade().unwrap();
        MUT_SYS_BUS!(parent_bus, locked_bus, sysbus);
        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_device(&dev)?;

        MigrationManager::register_device_instance(
            RamfbCfg::descriptor(),
            dev.clone(),
            RAMFB_SNAPSHOT_ID,
        );

        Ok(dev)
    }
}

impl SysBusDevOps for Ramfb {
    gen_base_func!(sysbusdev_base, sysbusdev_base_mut, SysBusDevBase, base);

    fn read(&mut self, _data: &mut [u8], _base: GuestAddress, _offset: u64) -> bool {
        error!("Ramfb can not be read!");
        false
    }

    fn write(&mut self, _data: &[u8], _base: GuestAddress, _offset: u64) -> bool {
        error!("Ramfb can not be written!");
        false
    }
}

impl AmlBuilder for Ramfb {
    fn aml_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl MigrationHook for Ramfb {}

impl StateTransfer for Ramfb {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let state_locked = self.ramfb_state.lock().unwrap();

        Ok(serde_json::to_vec(&state_locked.cfg)?)
    }

    fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
        let cfg: RamfbCfg = serde_json::from_slice(state)
            .with_context(|| MigrationError::FromBytesError("RamfbCfg"))?;
        let mut ramfb_state = self.ramfb_state.lock().unwrap();
        ramfb_state.cfg = cfg;
        ramfb_state.replace_surface();

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&RamfbCfg::descriptor().name).unwrap_or(!0)
    }
}

/// # Safety
///
/// The length of data must not less than 3.
unsafe fn set_press_event(install: Arc<AtomicBool>, data: *const u8) {
    let black_screen =
        // SAFETY: caller promises data is valid.
        unsafe { !data.is_null() && *data == 0 && *data.offset(1) == 0 && *data.offset(2) == 0 };
    if install.load(Ordering::Acquire) && black_screen {
        let set_press_func = Box::new(move || {
            // SAFETY: caller promises data is valid.
            unsafe { set_press_event(install.clone(), data) };
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

#[cfg(test)]
mod tests {
    use super::*;
    use machine_manager::config::str_slip_to_clap;

    #[test]
    fn test_ramfb_config_cmdline_parser() {
        // Test1: install.
        let ramfb_cmd1 = "ramfb,id=ramfb0,install=true";
        let ramfb_config =
            RamfbConfig::try_parse_from(str_slip_to_clap(ramfb_cmd1, true, false)).unwrap();
        assert_eq!(ramfb_config.id, "ramfb0");
        assert_eq!(ramfb_config.install, true);

        // Test2: Default.
        let ramfb_cmd2 = "ramfb,id=ramfb0";
        let ramfb_config =
            RamfbConfig::try_parse_from(str_slip_to_clap(ramfb_cmd2, true, false)).unwrap();
        assert_eq!(ramfb_config.install, false);
    }
}
