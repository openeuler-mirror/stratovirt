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
    MultitouchOps, MultitouchType,
};

use crate::{
    virtio_has_feature, VirtioBase, VirtioDevice, VirtioInterrupt, VIRTIO_INPUT_F_MTT_SCREEN,
    VIRTIO_INPUT_F_MTT_TOUCHPAD,
};
use crate::{EvdevConfig, Input, InputIoHandler};
use address_space::AddressSpace;
use machine_manager::config::{get_pci_df, parse_bool, valid_id};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use util::evdev::*;
use util::loop_context::EventNotifierHelper;
use util::num_ops::str_to_num;
use vmm_sys_util::eventfd::EventFd;

struct MultitouchAbsInfo {
    slot_max: u32,
    touch_major_max: u32,
    touch_minor_max: u32,
    tracking_id_max: u32,
    pressure_max: u32,
    x_res: u32,
    y_res: u32,
}

const MT_ABS_INFO: [MultitouchAbsInfo; 2] = [
    // touchscreen
    MultitouchAbsInfo {
        slot_max: 0x9,
        touch_major_max: 0x1,
        touch_minor_max: 0x1,
        tracking_id_max: 0x9,
        pressure_max: 0x64,
        x_res: 0,
        y_res: 0,
    },
    // touchpad
    MultitouchAbsInfo {
        // three fingers
        slot_max: 0x2,
        touch_major_max: 0xff,
        touch_minor_max: 0xff,
        tracking_id_max: 0xffff,
        pressure_max: 0xff,
        x_res: 31,
        y_res: 29,
    },
];

pub fn touchtype_parser(touchtype: &str) -> Result<MultitouchType> {
    match touchtype {
        "screen" => Ok(MultitouchType::Screen),
        "pad" => Ok(MultitouchType::Pad),
        _ => bail!("Wrong type: {:?}, only supports: screen, pad", touchtype),
    }
}

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
    #[arg(long, default_value = "screen", value_parser = touchtype_parser)]
    pub touchtype: MultitouchType,
}

pub struct Multitouch {
    device: Input,
    x_max: u32,
    y_max: u32,
    slot_max: u32,
    touchtype: MultitouchType,
}

impl Multitouch {
    fn init_event_supported(evdev_cfg: &mut EvdevConfig, touchtype: MultitouchType) {
        let mut key_bits = *EvdevBuf::new().set_bit(BTN_TOUCH as usize);
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

        match touchtype {
            MultitouchType::Screen => {
                evdev_cfg.event_supported = EvdevBufHelper::new()
                    .push(EV_ABS, abs_bits)
                    .push(EV_KEY, key_bits)
                    .to_raw();
            }
            MultitouchType::Pad => {
                key_bits.set_bit(BTN_LEFT as usize);
                let msc_bits = *EvdevBuf::new().set_bit(MSC_TIMESTAMP as usize);
                evdev_cfg.event_supported = EvdevBufHelper::new()
                    .push(EV_ABS, abs_bits)
                    .push(EV_KEY, key_bits)
                    .push(EV_MSC, msc_bits)
                    .to_raw();
            }
        }
    }

    fn init_properties(evdev_cfg: &mut EvdevConfig, touchtype: MultitouchType) {
        match touchtype {
            MultitouchType::Screen => {
                evdev_cfg.properties = *EvdevBuf::new().set_bit(INPUT_PROP_DIRECT as usize);
            }
            MultitouchType::Pad => {
                evdev_cfg.properties = *EvdevBuf::new()
                    .set_bit(INPUT_PROP_POINTER as usize)
                    .set_bit(INPUT_PROP_BUTTONPAD as usize);
            }
        }
    }

    fn init_abs_info(evdev_cfg: &mut EvdevConfig, option: &MultitouchConfig) {
        let device_config = &MT_ABS_INFO[Into::<usize>::into(option.touchtype)];

        evdev_cfg.abs_info = AbsinfoHelper::new()
            .push(
                ABS_X,
                InputAbsInfo::new(0, option.x as u32, device_config.x_res),
            )
            .push(
                ABS_Y,
                InputAbsInfo::new(0, option.y as u32, device_config.y_res),
            )
            .push(ABS_MT_SLOT, InputAbsInfo::new(0, device_config.slot_max, 0))
            .push(
                ABS_MT_TOUCH_MAJOR,
                InputAbsInfo::new(0, device_config.touch_major_max, 0),
            )
            .push(
                ABS_MT_TOUCH_MINOR,
                InputAbsInfo::new(0, device_config.touch_minor_max, 0),
            )
            .push(
                ABS_MT_POSITION_X,
                InputAbsInfo::new(0, option.x as u32, device_config.x_res),
            )
            .push(
                ABS_MT_POSITION_Y,
                InputAbsInfo::new(0, option.y as u32, device_config.y_res),
            )
            .push(
                ABS_MT_TRACKING_ID,
                InputAbsInfo::new(0, device_config.tracking_id_max, 0),
            )
            .push(
                ABS_MT_PRESSURE,
                InputAbsInfo::new(0, device_config.pressure_max, 0),
            )
            .to_raw();
    }

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
        evdev_cfg.serial = option
            .serial
            .clone()
            .unwrap_or_default()
            .as_bytes()
            .to_vec();

        Self::init_event_supported(&mut evdev_cfg, option.touchtype);
        Self::init_properties(&mut evdev_cfg, option.touchtype);
        Self::init_abs_info(&mut evdev_cfg, &option);
        let slot_max = MT_ABS_INFO[Into::<usize>::into(option.touchtype)].slot_max;

        Self {
            device: Input::new_with_cfg(evdev_cfg),
            x_max: option.x as u32,
            y_max: option.y as u32,
            slot_max,
            touchtype: option.touchtype,
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
        self.virtio_base_mut().device_features |=
            1 << VIRTIO_INPUT_F_MTT_TOUCHPAD | 1 << VIRTIO_INPUT_F_MTT_SCREEN;
        Ok(())
    }

    fn realize(&mut self) -> Result<()> {
        self.device.realize()?;
        self.init_config_features()
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
        if self.touchtype == MultitouchType::Pad
            && !virtio_has_feature(
                self.device.virtio_base().driver_features,
                VIRTIO_INPUT_F_MTT_TOUCHPAD,
            )
        {
            bail!("the guest driver didn't initialize the device as touchpad");
        }

        let handler = Arc::new(Mutex::new(self.device.create_io_handler(
            mem_space,
            interrupt_cb,
            queue_evts,
            Some(self.touchtype),
        )?));
        register_mt_handler(
            handler.clone(),
            self.x_max as i32,
            self.y_max as i32,
            self.slot_max,
            self.touchtype,
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
        unregister_mt_handler(self.touchtype);
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        unregister_mt_handler(self.touchtype);
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
                        unregister_mt_handler(self.get_mt_type().unwrap());
                        bail!(
                            "Failed to inject multitouch {:?} event",
                            self.get_mt_type().unwrap()
                        );
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
                        unregister_mt_handler(self.get_mt_type().unwrap());
                        bail!(
                            "Failed to inject multitouch {:?} event",
                            self.get_mt_type().unwrap()
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn send_raw_event(&mut self, evt: &InputEvent) -> Result<()> {
        if !self.send_event(evt) {
            unregister_mt_handler(self.get_mt_type().unwrap());
            bail!(
                "Failed to send raw input event to multitouch {:?} dev",
                self.get_mt_type().unwrap()
            );
        }
        Ok(())
    }

    fn send_sync(&mut self) -> Result<()> {
        let evt = InputEvent::new(EV_SYN, SYN_REPORT, 0);
        if !self.send_event(&evt) {
            unregister_mt_handler(self.get_mt_type().unwrap());
            bail!(
                "Failed to send multitouch sync event for multitouch {:?} dev",
                self.get_mt_type().unwrap()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use machine_manager::config::str_slip_to_clap;

    #[test]
    fn test_touchpad_cmdline_parser() {
        // Test device parameters are all right.
        let touchpad_cmd =
            "virtio-multitouch-pci,id=touchpad,bus=pcie.0,addr=0xb,x=12000,y=8000,touchtype=pad";
        let touchpad_config =
            MultitouchConfig::try_parse_from(str_slip_to_clap(touchpad_cmd, true, false)).unwrap();
        assert_eq!(touchpad_config.id, "touchpad");
        assert_eq!(touchpad_config.touchtype, MultitouchType::Pad);
        assert_eq!(touchpad_config.x, 12000);
        assert_eq!(touchpad_config.y, 8000);

        // Test device parameters are illegal value.
        let touchpad_cmd = "virtio-multitouch-pci,id=touchpad,bus=pcie.0,addr=0xb,x=12000,y=8000,touchtype=touchpad";
        let result = MultitouchConfig::try_parse_from(str_slip_to_clap(touchpad_cmd, true, false));
        assert!(result.is_err());
    }

    #[test]
    fn test_touchpad_info_init() {
        let touchpad_cmd =
            "virtio-multitouch-pci,id=touchpad,bus=pcie.0,addr=0xb,x=12000,y=8000,touchtype=pad";
        let touchpad_config =
            MultitouchConfig::try_parse_from(str_slip_to_clap(touchpad_cmd, true, false)).unwrap();
        let touchpad_info = Multitouch::new(touchpad_config);
        assert_eq!(touchpad_info.touchtype, MultitouchType::Pad);
        assert_eq!(touchpad_info.x_max, 12000);
        assert_eq!(touchpad_info.y_max, 8000);
    }
}
