// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use clap::{ArgAction, Parser};
use ui::input::{
    register_mt_handler, unregister_mt_handler, MultiTouchAbsData, MultiTouchEventKind,
    MultitouchOps,
};

use crate::VirtioBase;
use crate::VirtioDevice;
use crate::VirtioInterrupt;
use crate::{EvdevConfig, Input, InputIoHandler};
use address_space::AddressSpace;
use machine_manager::config::{get_pci_df, parse_bool, valid_id};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use util::evdev::*;
use util::loop_context::EventNotifierHelper;
use util::num_ops::str_to_num;
use vmm_sys_util::eventfd::EventFd;

#[derive(Parser, Debug, Clone, Default)]
#[command(no_binary_name(true))]
pub struct MultitouchConfig {
    #[arg(long, value_parser = ["virtio-multitouch-device", "virtio-multitouch-pci"])]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub bus: Option<String>,
    #[arg(long, value_parser=get_pci_df)]
    pub addr: Option<(u8, u8)>,
    #[arg(long, value_parser=parse_bool, action = ArgAction::Append)]
    pub multifunction: Option<bool>,
    #[arg(long, value_parser = valid_id)]
    pub serial: Option<String>,
    #[arg(long, default_value = "0x7FFF",  value_parser = str_to_num::<u16>)]
    pub x: u16,
    #[arg(long, default_value = "0x7FFF", value_parser = str_to_num::<u16>)]
    pub y: u16,
}

pub const ABS_MT_TOUCH_MAJOR_MAX: u32 = 0x1;
pub const ABS_MT_TOUCH_MINOR_MAX: u32 = 0x1;
pub const ABS_MT_TRACKING_ID_MAX: u32 = 0x9;
pub const ABS_MT_PRESSURE_MAX: u32 = 0x64;

pub struct Multitouch {
    device: Input,
    x_max: u32,
    y_max: u32,
}

impl Multitouch {
    pub fn new(option: MultitouchConfig) -> Self {
        // set vendor,product,version to 0 to avoid conflict
        // with a physical device.
        let mut evdev_cfg = EvdevConfig::new_with_id(EvdevId {
            bustype: BUS_VIRTUAL,
            vendor: 0_u16,
            product: 0_u16,
            version: 0_u16,
        });
        evdev_cfg.name = String::from("StratoVirt Virtio Multitouch")
            .as_bytes()
            .to_vec();
        evdev_cfg.serial = option.serial.unwrap_or_default().as_bytes().to_vec();

        evdev_cfg.properties = *EvdevBuf::new().set_bit(INPUT_PROP_DIRECT as usize);

        let abs_bits = *EvdevBuf::new()
            .set_bit(ABS_X as usize)
            .set_bit(ABS_Y as usize)
            .set_bit(ABS_MT_SLOT as usize)
            .set_bit(ABS_MT_TOUCH_MAJOR as usize)
            .set_bit(ABS_MT_TOUCH_MINOR as usize)
            .set_bit(ABS_MT_POSITION_X as usize)
            .set_bit(ABS_MT_POSITION_Y as usize)
            .set_bit(ABS_MT_TRACKING_ID as usize)
            .set_bit(ABS_MT_PRESSURE as usize);

        // Only support BTN_TOUCH for multitouch screen.
        // For future touchpad support, should add more BTN_*.
        let key_bits = *EvdevBuf::new().set_bit(BTN_TOUCH as usize);

        evdev_cfg.event_supported = EvdevBufHelper::new()
            .push(EV_ABS, abs_bits)
            .push(EV_KEY, key_bits)
            .to_raw();

        evdev_cfg.abs_info = AbsinfoHelper::new()
            .push(ABS_X, InputAbsInfo::new(0, option.x as u32))
            .push(ABS_Y, InputAbsInfo::new(0, option.y as u32))
            .push(ABS_MT_SLOT, InputAbsInfo::new(0, ABS_MT_TRACKING_ID_MAX))
            .push(
                ABS_MT_TOUCH_MAJOR,
                InputAbsInfo::new(0, ABS_MT_TOUCH_MAJOR_MAX),
            )
            .push(
                ABS_MT_TOUCH_MINOR,
                InputAbsInfo::new(0, ABS_MT_TOUCH_MINOR_MAX),
            )
            .push(ABS_MT_POSITION_X, InputAbsInfo::new(0, option.x as u32))
            .push(ABS_MT_POSITION_Y, InputAbsInfo::new(0, option.y as u32))
            .push(
                ABS_MT_TRACKING_ID,
                InputAbsInfo::new(0, ABS_MT_TRACKING_ID_MAX),
            )
            .push(ABS_MT_PRESSURE, InputAbsInfo::new(0, ABS_MT_PRESSURE_MAX))
            .to_raw();

        Self {
            device: Input::new_with_cfg(evdev_cfg),
            x_max: option.x as u32,
            y_max: option.y as u32,
        }
    }
}

impl VirtioDevice for Multitouch {
    fn virtio_base(&self) -> &VirtioBase {
        self.device.virtio_base()
    }

    fn virtio_base_mut(&mut self) -> &mut VirtioBase {
        self.device.virtio_base_mut()
    }
    fn init_config_features(&mut self) -> Result<()> {
        Ok(())
    }

    fn realize(&mut self) -> Result<()> {
        self.device.realize()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        self.device.read_config(offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        self.device.write_config(offset, data)
    }

    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let handler = Arc::new(Mutex::new(self.device.create_io_handler(
            mem_space,
            interrupt_cb,
            queue_evts,
        )?));
        register_mt_handler(
            handler.clone(),
            self.x_max as i32,
            self.y_max as i32,
            ABS_MT_TRACKING_ID_MAX,
        )?;

        register_event_helper(
            EventNotifierHelper::internal_notifiers(handler),
            None,
            &mut self.device.deactivate_evts,
        )
        .with_context(|| "Failed to register mt input handler to Mainloop")?;
        self.virtio_base_mut().broken.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        unregister_event_helper(None, &mut self.device.deactivate_evts)?;
        unregister_mt_handler();
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        unregister_mt_handler();
        Ok(())
    }
}

impl MultitouchOps for InputIoHandler {
    fn send_event(&mut self, mtt_evt: &MultiTouchAbsData) -> Result<()> {
        match mtt_evt.kind {
            MultiTouchEventKind::BEGIN | MultiTouchEventKind::UPDATE => {
                let evts = [
                    InputEvent::new(EV_ABS as u16, ABS_MT_SLOT as u16, mtt_evt.slot),
                    InputEvent::new(
                        EV_ABS as u16,
                        ABS_MT_TRACKING_ID as u16,
                        mtt_evt.tracking_id,
                    ),
                    InputEvent::new(EV_ABS as u16, ABS_MT_POSITION_X as u16, mtt_evt.x),
                    InputEvent::new(EV_ABS as u16, ABS_MT_POSITION_Y as u16, mtt_evt.y),
                    InputEvent::new(EV_ABS as u16, ABS_MT_TOUCH_MAJOR as u16, mtt_evt.major),
                    InputEvent::new(EV_ABS as u16, ABS_MT_TOUCH_MINOR as u16, mtt_evt.minor),
                ];

                for evt in &evts {
                    if !self.send_event(evt) {
                        unregister_mt_handler();
                        bail!("Failed to inject multitouch event");
                    }
                }
            }
            MultiTouchEventKind::END => {
                let evts = [
                    InputEvent::new(EV_ABS as u16, ABS_MT_SLOT as u16, mtt_evt.slot),
                    InputEvent::new(EV_ABS as u16, ABS_MT_TRACKING_ID as u16, -1),
                ];

                for evt in &evts {
                    if !self.send_event(evt) {
                        unregister_mt_handler();
                        bail!("Failed to inject multitouch event");
                    }
                }
            }
        }

        Ok(())
    }

    fn send_sync(&mut self) -> Result<()> {
        let evt = InputEvent::new(EV_SYN, SYN_REPORT, 0);
        if self.send_event(&evt) {
            Ok(())
        } else {
            unregister_mt_handler();
            bail!("Failed to send multitouch sync event");
        }
    }
}
