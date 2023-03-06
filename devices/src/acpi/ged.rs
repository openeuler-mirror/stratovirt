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

use acpi::{AcpiError, AmlFieldAccessType, AmlFieldLockRule, AmlFieldUpdateRule};
use address_space::GuestAddress;
use anyhow::{anyhow, Context, Result};
use log::error;
use machine_manager::event;
use machine_manager::event_loop::EventLoop;
use machine_manager::qmp::QmpChannel;
use std::os::unix::prelude::AsRawFd;
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, Ordering};
use sysbus::{SysBus, SysBusDevOps, SysRes};
use util::loop_context::{read_fd, EventNotifier, NotifierOperation};
use util::{loop_context::NotifierCallback, num_ops::write_data_u32};
use vmm_sys_util::epoll::EventSet;

use acpi::{
    AmlActiveLevel, AmlAddressSpaceType, AmlAnd, AmlBuilder, AmlDevice, AmlEdgeLevel, AmlEqual,
    AmlExtendedInterrupt, AmlField, AmlFieldUnit, AmlIf, AmlIntShare, AmlInteger, AmlLocal,
    AmlMethod, AmlName, AmlNameDecl, AmlNotify, AmlOpRegion, AmlResTemplate, AmlResourceUsage,
    AmlScopeBuilder, AmlStore, AmlString, INTERRUPT_PPIS_COUNT, INTERRUPT_SGIS_COUNT,
};

use std::sync::{Arc, Mutex};

use vmm_sys_util::eventfd::EventFd;

#[derive(Clone, Copy)]
enum AcpiEvent {
    Nothing = 0,
    PowerDown = 1,
}

const AML_GED_EVT_REG: &str = "EREG";
const AML_GED_EVT_SEL: &str = "ESEL";

#[derive(Clone)]
pub struct Ged {
    interrupt_evt: Arc<Option<EventFd>>,
    notification_type: Arc<AtomicU32>,
    /// System resource.
    res: SysRes,
}

impl Default for Ged {
    fn default() -> Self {
        Self {
            interrupt_evt: Arc::new(None),
            notification_type: Arc::new(AtomicU32::new(AcpiEvent::Nothing as u32)),
            res: SysRes::default(),
        }
    }
}

impl Ged {
    pub fn realize(
        mut self,
        sysbus: &mut SysBus,
        power_button: Arc<EventFd>,
        region_base: u64,
        region_size: u64,
    ) -> Result<()> {
        self.interrupt_evt = Arc::new(Some(EventFd::new(libc::EFD_NONBLOCK)?));
        self.set_sys_resource(sysbus, region_base, region_size)
            .with_context(|| anyhow!(AcpiError::Alignment(region_size.try_into().unwrap())))?;

        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_device(&dev, region_base, region_size)?;

        let ged = dev.lock().unwrap();
        ged.register_acpi_powerdown_event(power_button)
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

    fn inject_interrupt(&self) {
        if let Some(evt_fd) = self.interrupt_evt() {
            evt_fd
                .write(1)
                .unwrap_or_else(|e| error!("ged: failed to write interrupt eventfd ({}).", e));
            return;
        }
        error!("ged: failed to get interrupt event fd.");
    }
}

impl SysBusDevOps for Ged {
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

    fn interrupt_evt(&self) -> Option<&EventFd> {
        self.interrupt_evt.as_ref().as_ref()
    }

    fn get_sys_resource(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.res)
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
            vec![self.res.irq as u32 + irq_base],
        ));
        acpi_dev.append_child(AmlNameDecl::new("_CRS", res));

        acpi_dev.append_child(AmlOpRegion::new(
            "EREG",
            AmlAddressSpaceType::SystemMemory,
            self.res.region_base,
            self.res.region_size,
        ));

        let mut field = AmlField::new(
            AML_GED_EVT_REG,
            AmlFieldAccessType::DWord,
            AmlFieldLockRule::NoLock,
            AmlFieldUpdateRule::WriteAsZeros,
        );

        let elemt = AmlFieldUnit::new(Some(AML_GED_EVT_SEL), 32);
        field.append_child(elemt);
        acpi_dev.append_child(field);

        let mut method = AmlMethod::new("_EVT", 1, true);
        let store = AmlStore::new(AmlName(AML_GED_EVT_SEL.to_string()), AmlLocal(0));
        method.append_child(store);
        let mut if_scope = AmlIf::new(AmlEqual::new(
            AmlAnd::new(AmlLocal(0), AmlInteger(1), AmlLocal(0)),
            AmlInteger(1),
        ));
        if_scope.append_child(AmlNotify::new(
            AmlName("PWRB".to_string()),
            AmlInteger(0x80),
        ));
        method.append_child(if_scope);
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
