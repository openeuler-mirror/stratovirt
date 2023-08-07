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

use std::os::unix::prelude::AsRawFd;
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use log::error;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use crate::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysRes};
use crate::{Device, DeviceBase};
use acpi::{
    AcpiError, AmlActiveLevel, AmlAddressSpaceType, AmlAnd, AmlBuilder, AmlDevice, AmlEdgeLevel,
    AmlEqual, AmlExtendedInterrupt, AmlField, AmlFieldAccessType, AmlFieldLockRule, AmlFieldUnit,
    AmlFieldUpdateRule, AmlIf, AmlIntShare, AmlInteger, AmlLocal, AmlMethod, AmlName, AmlNameDecl,
    AmlNotify, AmlOpRegion, AmlResTemplate, AmlResourceUsage, AmlScopeBuilder, AmlStore, AmlString,
    INTERRUPT_PPIS_COUNT, INTERRUPT_SGIS_COUNT,
};
use address_space::GuestAddress;
use machine_manager::event;
use machine_manager::event_loop::EventLoop;
use machine_manager::qmp::QmpChannel;
use util::loop_context::{read_fd, EventNotifier, NotifierOperation};
use util::{loop_context::NotifierCallback, num_ops::write_data_u32};

#[derive(Clone, Copy)]
pub enum AcpiEvent {
    Nothing = 0,
    PowerDown = 1,
    AcadSt = 2,
    BatteryInf = 4,
    BatterySt = 8,
}

const AML_GED_EVT_REG: &str = "EREG";
const AML_GED_EVT_SEL: &str = "ESEL";

#[derive(Clone)]
pub struct Ged {
    base: SysBusDevBase,
    notification_type: Arc<AtomicU32>,
    battery_present: bool,
}

impl Default for Ged {
    fn default() -> Self {
        Self {
            base: SysBusDevBase::default(),
            notification_type: Arc::new(AtomicU32::new(AcpiEvent::Nothing as u32)),
            battery_present: false,
        }
    }
}

impl Ged {
    pub fn realize(
        mut self,
        sysbus: &mut SysBus,
        power_button: Arc<EventFd>,
        battery_present: bool,
        region_base: u64,
        region_size: u64,
    ) -> Result<Arc<Mutex<Ged>>> {
        self.base.interrupt_evt = Some(Arc::new(EventFd::new(libc::EFD_NONBLOCK)?));
        self.set_sys_resource(sysbus, region_base, region_size)
            .with_context(|| AcpiError::Alignment(region_size.try_into().unwrap()))?;
        self.battery_present = battery_present;

        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_device(&dev, region_base, region_size, "Ged")?;

        let ged = dev.lock().unwrap();
        ged.register_acpi_powerdown_event(power_button)
            .with_context(|| "Failed to register ACPI powerdown event.")?;
        Ok(dev.clone())
    }

    fn register_acpi_powerdown_event(&self, power_button: Arc<EventFd>) -> Result<()> {
        let power_down_fd = power_button.as_raw_fd();
        let ged_clone = self.clone();
        let power_down_handler: Rc<NotifierCallback> = Rc::new(move |_, _| {
            read_fd(power_down_fd);
            ged_clone
                .notification_type
                .store(AcpiEvent::PowerDown as u32, Ordering::SeqCst);
            ged_clone.inject_interrupt();
            if QmpChannel::is_connected() {
                event!(Powerdown);
            }
            None
        });

        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            power_down_fd,
            None,
            EventSet::IN,
            vec![power_down_handler],
        );

        EventLoop::update_event(vec![notifier], None)
            .with_context(|| "Failed to register powerdown notifier.")?;
        Ok(())
    }

    pub fn inject_acpi_event(&self, evt: AcpiEvent) {
        self.notification_type
            .fetch_or(evt as u32, Ordering::SeqCst);
        self.inject_interrupt();
    }

    fn inject_interrupt(&self) {
        if let Some(evt_fd) = self.interrupt_evt() {
            evt_fd
                .write(1)
                .unwrap_or_else(|e| error!("ged: failed to write interrupt eventfd ({:?}).", e));
        }
    }
}

impl Device for Ged {
    fn device_base(&self) -> &DeviceBase {
        &self.base.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base.base
    }
}

impl SysBusDevOps for Ged {
    fn sysbusdev_base(&self) -> &SysBusDevBase {
        &self.base
    }

    fn sysbusdev_base_mut(&mut self) -> &mut SysBusDevBase {
        &mut self.base
    }

    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        if offset != 0 {
            return false;
        }
        let value = self
            .notification_type
            .swap(AcpiEvent::Nothing as u32, Ordering::SeqCst);
        write_data_u32(data, value)
    }

    fn write(&mut self, _data: &[u8], _base: GuestAddress, _offset: u64) -> bool {
        true
    }

    fn get_sys_resource(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.base.res)
    }
}

impl AmlBuilder for Ged {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut acpi_dev = AmlDevice::new("\\_SB.GED");
        acpi_dev.append_child(AmlNameDecl::new("_HID", AmlString("ACPI0013".to_string())));
        acpi_dev.append_child(AmlNameDecl::new("_UID", AmlString("GED".to_string())));

        let mut res = AmlResTemplate::new();

        // SPI start at interrupt number 32 on aarch64 platform.
        let irq_base = INTERRUPT_PPIS_COUNT + INTERRUPT_SGIS_COUNT;
        res.append_child(AmlExtendedInterrupt::new(
            AmlResourceUsage::Consumer,
            AmlEdgeLevel::Edge,
            AmlActiveLevel::High,
            AmlIntShare::Exclusive,
            vec![self.base.res.irq as u32 + irq_base],
        ));
        acpi_dev.append_child(AmlNameDecl::new("_CRS", res));

        acpi_dev.append_child(AmlOpRegion::new(
            "EREG",
            AmlAddressSpaceType::SystemMemory,
            self.base.res.region_base,
            self.base.res.region_size,
        ));

        let mut field = AmlField::new(
            AML_GED_EVT_REG,
            AmlFieldAccessType::DWord,
            AmlFieldLockRule::NoLock,
            AmlFieldUpdateRule::WriteAsZeros,
        );

        let element = AmlFieldUnit::new(Some(AML_GED_EVT_SEL), 32);
        field.append_child(element);
        acpi_dev.append_child(field);

        let mut method = AmlMethod::new("_EVT", 1, true);
        let store = AmlStore::new(AmlName(AML_GED_EVT_SEL.to_string()), AmlLocal(0));
        method.append_child(store);

        struct PowerDevEvent(AcpiEvent, &'static str, u64);
        let events: [PowerDevEvent; 4] = [
            PowerDevEvent(AcpiEvent::PowerDown, "PWRB", 0x80),
            PowerDevEvent(AcpiEvent::AcadSt, "ACAD", 0x80),
            PowerDevEvent(AcpiEvent::BatteryInf, "BAT0", 0x81),
            PowerDevEvent(AcpiEvent::BatterySt, "BAT0", 0x80),
        ];

        for event in events.into_iter() {
            let evt = event.0 as u64;
            let dev = event.1;
            let notify = event.2;

            if !self.battery_present
                && (evt > AcpiEvent::PowerDown as u64 && evt <= AcpiEvent::BatterySt as u64)
            {
                break;
            }

            let mut if_scope = AmlIf::new(AmlEqual::new(
                AmlAnd::new(AmlLocal(0), AmlInteger(evt), AmlLocal(1)),
                AmlInteger(evt),
            ));
            if_scope.append_child(AmlNotify::new(AmlName(dev.to_string()), AmlInteger(notify)));
            method.append_child(if_scope);
        }

        acpi_dev.append_child(method);

        acpi_dev.aml_bytes()
    }
}

pub fn acpi_dsdt_add_power_button() -> AmlDevice {
    let mut acpi_dev = AmlDevice::new("PWRB");
    acpi_dev.append_child(AmlNameDecl::new("_HID", AmlString("PNP0C0C".to_string())));
    acpi_dev.append_child(AmlNameDecl::new("_UID", AmlInteger(1)));

    acpi_dev
}
