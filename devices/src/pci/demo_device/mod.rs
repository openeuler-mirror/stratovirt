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

/// DemoDev is a demo PCIe device, that can have device properties configurable, eg.
/// bar num, max msix vector num, etc.
/// It can have 0-6 bars, if set, msix always lives in bar 0, data handling in bar 1.
/// 1. its functionality is to read and write data for the guest, meanwhile, do a little
///    mathmetic logic(multiply data[0] with 2) with the write op.
/// 2. After r/w, it sends back a msix interrupt to the guest, which means that it has also
///    msix capability. We assume msix bar is in bar 0.
/// 3. Finally, it supports hotplug/hotunplug.
/// As that it has device memory, it means it has a bar space, we assume the
/// bar size is 4KB in bar 1.
/// As that it has device memory, it means it has a bar space other than the msix one.(
/// therotically they can share the same bar as well).
///
/// Note: developers can also add yourself mmio r/w ops for this device by changing the
/// callback fn write_data_internal_func(), using trait to expand this function is recommended.
///
/// The example cmdline for the device is:
///     "-device pcie-demo-dev,addr=0x5,bus=pcie.0,id=demo0,bar_num=3,bar_size=4096"
pub mod base_device;
pub mod dpy_device;
pub mod gpu_device;
pub mod kbd_pointer_device;

use std::{
    sync::Mutex,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Weak,
    },
};

use anyhow::{bail, Result};
use clap::Parser;
use log::error;

use crate::pci::demo_device::{
    dpy_device::DemoDisplay, gpu_device::DemoGpu, kbd_pointer_device::DemoKbdMouse,
};
use crate::pci::{
    config::{
        PciConfig, RegionType, DEVICE_ID, HEADER_TYPE, HEADER_TYPE_ENDPOINT,
        PCIE_CONFIG_SPACE_SIZE, SUB_CLASS_CODE, VENDOR_ID,
    },
    init_msix, le_write_u16, PciBus, PciDevOps,
};
use crate::pci::{demo_device::base_device::BaseDevice, PciDevBase};
use crate::{Device, DeviceBase};
use address_space::{AddressSpace, GuestAddress, Region, RegionOps};
use machine_manager::config::{get_pci_df, valid_id};
use util::gen_base_func;

/// Config struct for `demo_dev`.
/// Contains demo_dev device's attr.
#[derive(Parser, Debug, Clone)]
#[command(no_binary_name(true))]
pub struct DemoDevConfig {
    #[arg(long, value_parser = ["pcie-demo-dev"])]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub bus: String,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: (u8, u8),
    // Different device implementations can be configured based on this parameter
    #[arg(long, alias = "device_type")]
    pub device_type: Option<String>,
    #[arg(long, alias = "bar_num", default_value = "0")]
    pub bar_num: u8,
    // Every bar has the same size just for simplification.
    #[arg(long, alias = "bar_size", default_value = "0")]
    pub bar_size: u64,
}

pub struct DemoDev {
    base: PciDevBase,
    cmd_cfg: DemoDevConfig,
    mem_region: Region,
    dev_id: Arc<AtomicU16>,
    device: Arc<Mutex<dyn DeviceTypeOperation>>,
}

impl DemoDev {
    pub fn new(
        cfg: DemoDevConfig,
        devfn: u8,
        sys_mem: Arc<AddressSpace>,
        parent_bus: Weak<Mutex<PciBus>>,
    ) -> Self {
        // You can choose different device function based on the parameter of device_type.
        let device_type = cfg.device_type.clone().unwrap_or_default();
        let device: Arc<Mutex<dyn DeviceTypeOperation>> = match device_type.as_str() {
            "demo-gpu" => Arc::new(Mutex::new(DemoGpu::new(sys_mem, cfg.id.clone()))),
            "demo-input" => Arc::new(Mutex::new(DemoKbdMouse::new(sys_mem))),
            "demo-display" => Arc::new(Mutex::new(DemoDisplay::new(sys_mem))),
            _ => Arc::new(Mutex::new(BaseDevice::new())),
        };
        DemoDev {
            base: PciDevBase {
                base: DeviceBase::new(cfg.id.clone(), false, Some(parent_bus.clone())),
                config: PciConfig::new(PCIE_CONFIG_SPACE_SIZE, cfg.bar_num),
                devfn,
                parent_bus,
            },
            cmd_cfg: cfg,
            mem_region: Region::init_container_region(u32::MAX as u64, "DemoDev"),
            dev_id: Arc::new(AtomicU16::new(0)),
            device,
        }
    }

    fn init_pci_config(&mut self) -> Result<()> {
        self.init_write_mask(false)?;
        self.init_write_clear_mask(false)?;

        let config = &mut self.base.config.config;
        le_write_u16(config, DEVICE_ID as usize, DEVICE_ID_DEMO)?;
        le_write_u16(config, VENDOR_ID as usize, VENDOR_ID_DEMO)?;
        le_write_u16(config, SUB_CLASS_CODE as usize, CLASS_CODE_DEMO)?;
        config[HEADER_TYPE as usize] = HEADER_TYPE_ENDPOINT;

        Ok(())
    }

    fn attach_to_parent_bus(self) -> Result<()> {
        let parent_bus = self.base.parent_bus.upgrade().unwrap();
        let mut locked_parent_bus = parent_bus.lock().unwrap();
        if locked_parent_bus.devices.get(&self.base.devfn).is_some() {
            bail!("device already existed");
        }
        let devfn = self.base.devfn;
        let demo_pci_dev = Arc::new(Mutex::new(self));
        locked_parent_bus.devices.insert(devfn, demo_pci_dev);

        Ok(())
    }

    fn register_data_handling_bar(&mut self) -> Result<()> {
        let device = self.device.clone();
        let write_ops = move |data: &[u8], addr: GuestAddress, offset: u64| -> bool {
            device
                .lock()
                .unwrap()
                .write(data, addr, offset)
                .unwrap_or_else(|e| error!("Some error occur in writing: {:?}", e));
            true
        };

        let device = self.device.clone();
        let read_ops = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
            device
                .lock()
                .unwrap()
                .read(data, addr, offset)
                .unwrap_or_else(|e| error!("Some error occur in reading: {:?}", e));
            true
        };

        let region_ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };

        let region = Region::init_io_region(self.cmd_cfg.bar_size, region_ops, "DemoRegion");

        self.mem_region.add_subregion(region, 0)?;
        self.base.config.register_bar(
            0,
            self.mem_region.clone(),
            RegionType::Mem64Bit,
            false,
            (self.cmd_cfg.bar_size * self.cmd_cfg.bar_num as u64).next_power_of_two(),
        )?;

        Ok(())
    }
}

// reference to https://pci-ids.ucw.cz/read/PC?restrict=1
// "DEAD BEEF" seems will not be used for a long time.
const VENDOR_ID_DEMO: u16 = 0xDEAD;
const DEVICE_ID_DEMO: u16 = 0xBEEF;
// reference to https://pci-ids.ucw.cz/read/PD/
const CLASS_CODE_DEMO: u16 = 0xEE;

impl Device for DemoDev {
    gen_base_func!(device_base, device_base_mut, DeviceBase, base.base);
}

impl PciDevOps for DemoDev {
    gen_base_func!(pci_base, pci_base_mut, PciDevBase, base);

    /// Realize PCI/PCIe device.
    fn realize(mut self) -> Result<()> {
        self.init_pci_config()?;
        if self.cmd_cfg.bar_num > 0 {
            init_msix(&mut self.base, 0, 1, self.dev_id.clone(), None, None)?;
        }

        self.register_data_handling_bar()?;
        self.device.lock().unwrap().realize()?;

        self.attach_to_parent_bus()?;
        Ok(())
    }

    /// Unrealize PCI/PCIe device.
    fn unrealize(&mut self) -> Result<()> {
        self.device.lock().unwrap().unrealize()
    }

    /// write the pci configuration space
    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let parent_bus = self.base.parent_bus.upgrade().unwrap();
        let parent_bus_locked = parent_bus.lock().unwrap();

        self.base.config.write(
            offset,
            data,
            self.dev_id.load(Ordering::Acquire),
            #[cfg(target_arch = "x86_64")]
            None,
            Some(&parent_bus_locked.mem_region),
        );
    }

    /// Reset device
    fn reset(&mut self, _reset_child_device: bool) -> Result<()> {
        self.base.config.reset_common_regs()
    }
}

pub trait DeviceTypeOperation: Send {
    fn read(&mut self, data: &mut [u8], addr: GuestAddress, offset: u64) -> Result<()>;
    fn write(&mut self, data: &[u8], addr: GuestAddress, offset: u64) -> Result<()>;
    fn realize(&mut self) -> Result<()>;
    fn unrealize(&mut self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use machine_manager::config::str_slip_to_clap;
    #[test]
    fn test_parse_demo_dev() {
        // Test1: Right.
        let demo_cmd1 = "pcie-demo-dev,bus=pcie.0,addr=0x4,id=test_0,device_type=demo-gpu,bar_num=3,bar_size=4096";
        let result = DemoDevConfig::try_parse_from(str_slip_to_clap(demo_cmd1, true, false));
        assert!(result.is_ok());
        let demo_cfg = result.unwrap();
        assert_eq!(demo_cfg.id, "test_0".to_string());
        assert_eq!(demo_cfg.device_type, Some("demo-gpu".to_string()));
        assert_eq!(demo_cfg.bar_num, 3);
        assert_eq!(demo_cfg.bar_size, 4096);

        // Test2: Default bar_num/bar_size.
        let demo_cmd2 = "pcie-demo-dev,bus=pcie.0,addr=4.0,id=test_0,device_type=demo-gpu";
        let result = DemoDevConfig::try_parse_from(str_slip_to_clap(demo_cmd2, true, false));
        assert!(result.is_ok());
        let demo_cfg = result.unwrap();
        assert_eq!(demo_cfg.bar_num, 0);
        assert_eq!(demo_cfg.bar_size, 0);
    }
}
