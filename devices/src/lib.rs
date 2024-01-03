// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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

//! Interfaces for simulating various devices.
//!
//! This crate simulates:
//! - interrupt controller (aarch64)
//! - legacy devices, such as serial devices

pub mod acpi;
#[cfg(feature = "usb_camera")]
pub mod camera_backend;
pub mod interrupt_controller;
pub mod legacy;
pub mod misc;
pub mod pci;
pub mod scsi;
pub mod smbios;
pub mod sysbus;
pub mod usb;

#[cfg(target_arch = "aarch64")]
pub use interrupt_controller::{
    GICDevice, GICVersion, GICv2, GICv2Access, GICv3, GICv3Access, GICv3ItsAccess, GICv3ItsState,
    GICv3State, GicRedistRegion, ICGICConfig, ICGICv2Config, ICGICv3Config, InterruptController,
    InterruptError as IntCtrlErrs, GIC_IRQ_INTERNAL, GIC_IRQ_MAX,
};
pub use interrupt_controller::{IrqManager, IrqState, LineIrqManager, MsiIrqManager, TriggerMode};
pub use legacy::error::LegacyError as LegacyErrs;
pub use scsi::bus as ScsiBus;
pub use scsi::disk as ScsiDisk;

#[derive(Clone, Default)]
pub struct DeviceBase {
    /// Name of this device
    pub id: String,
    /// Whether it supports hot-plug/hot-unplug.
    pub hotpluggable: bool,
}

impl DeviceBase {
    pub fn new(id: String, hotpluggable: bool) -> Self {
        DeviceBase { id, hotpluggable }
    }
}

pub trait Device {
    fn device_base(&self) -> &DeviceBase;

    fn device_base_mut(&mut self) -> &mut DeviceBase;

    /// Get device name.
    fn name(&self) -> String {
        self.device_base().id.clone()
    }

    /// Query whether it supports hot-plug/hot-unplug.
    fn hotpluggable(&self) -> bool {
        self.device_base().hotpluggable
    }
}
