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

/// DemoDev is a demo PCIe device, that has 2 bars, 1 for msix, 1 for data handling.
/// 1. its functionality is to print heximal values that the guest writes,
///    and do nothing if the guest reads its device memory.
/// 2. After printing, it sends back a msix interrupt to the guest, which
/// means that it has also msix capability. We assume msix bar is in bar 0.
/// 3. Finally, it supports hotplug/hotunplug.
/// As that it has device memory, it means it has a bar space, we assume the
/// bar size is 4KB in bar 1.
///
/// The cmdline for the device is: -device pcie-demo-dev,addr=0x5,bus=pcie.0,id=demo0
use std::{
    sync::Mutex,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Weak,
    },
};

use address_space::Region;
use anyhow::Ok;
use machine_manager::config::DemoDevConfig;

use crate::{
    config::{
        PciConfig, RegionType, DEVICE_ID, HEADER_TYPE, HEADER_TYPE_ENDPOINT,
        PCIE_CONFIG_SPACE_SIZE, SUB_CLASS_CODE, VENDOR_ID,
    },
    init_msix, le_write_u16, PciBus, PciDevOps,
};
pub use anyhow::{bail, Result};

pub struct DemoDev {
    name: String,
    cmd_cfg: DemoDevConfig,
    config: PciConfig,
    mem_region: Region,
    devfn: u8,
    parent_bus: Weak<Mutex<PciBus>>,
    dev_id: Arc<AtomicU16>,
}

impl DemoDev {
    pub fn new(cfg: DemoDevConfig, devfn: u8, parent_bus: Weak<Mutex<PciBus>>) -> Self {
        DemoDev {
            name: cfg.id.clone(),
            cmd_cfg: cfg.clone(),
            config: PciConfig::new(PCIE_CONFIG_SPACE_SIZE, cfg.bar_num),
            mem_region: Region::init_container_region(u64::max_value() >> 10),
            devfn,
            parent_bus,
            dev_id: Arc::new(AtomicU16::new(0)),
        }
    }
}

// reference to https://pci-ids.ucw.cz/read/PC?restrict=1
// "DEAD BEEF" seems will not be used for a long time.
const VENDOR_ID_DEMO: u16 = 0xDEAD;
const DEVICE_ID_DEMO: u16 = 0xBEEF;
// reference to https://pci-ids.ucw.cz/read/PD/
const CLASS_CODE_DEMO: u16 = 0xEE;

impl PciDevOps for DemoDev {
    fn init_write_mask(&mut self) -> Result<()> {
        self.config.init_common_write_mask()
    }

    fn init_write_clear_mask(&mut self) -> Result<()> {
        self.config.init_common_write_clear_mask()
    }

    fn realize(mut self) -> Result<()> {
        self.init_write_mask()?;
        self.init_write_clear_mask()?;

        let config = &mut self.config.config;
        le_write_u16(config, DEVICE_ID as usize, DEVICE_ID_DEMO)?;
        le_write_u16(config, VENDOR_ID as usize, VENDOR_ID_DEMO)?;
        le_write_u16(config, SUB_CLASS_CODE as usize, CLASS_CODE_DEMO)?;
        config[HEADER_TYPE as usize] = HEADER_TYPE_ENDPOINT;

        let region_size = self
            .cmd_cfg
            .bar_size
            .checked_mul(self.cmd_cfg.bar_num as u64);
        if region_size.is_none() {
            bail!(
                "bar size overflow with 0x{:x} * 0x{:x}",
                self.cmd_cfg.bar_size,
                self.cmd_cfg.bar_num
            );
        }
        let region_size = region_size.unwrap();
        let region = Region::init_container_region(region_size as u64);
        self.config.register_bar(
            1,
            region,
            RegionType::Mem64Bit,
            false,
            self.cmd_cfg.bar_size as u64,
        )?;
        init_msix(
            0,
            1,
            &mut self.config,
            self.dev_id.clone(),
            &self.name,
            None,
            None,
        )?;

        let parent_bus = self.parent_bus.upgrade().unwrap();
        let mut locked_parent_bus = parent_bus.lock().unwrap();
        if locked_parent_bus.devices.get(&self.devfn).is_some() {
            bail!("device already existed");
        }
        let devfn = self.devfn;
        let demo_pci_dev = Arc::new(Mutex::new(self));
        locked_parent_bus.devices.insert(devfn, demo_pci_dev);

        Ok(())
    }

    /// Unrealize PCI/PCIe device.
    fn unrealize(&mut self) -> Result<()> {
        bail!("Unrealize of the demo device is not implemented yet");
    }

    /// read the pci configuration space
    fn read_config(&mut self, offset: usize, data: &mut [u8]) {
        self.config.read(offset, data);
    }

    /// write the pci configuration space
    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let parent_bus = self.parent_bus.upgrade().unwrap();
        let locked_parent_bus = parent_bus.lock().unwrap();

        self.config.write(
            offset,
            data,
            self.dev_id.load(Ordering::Acquire),
            #[cfg(target_arch = "x86_64")]
            None,
            Some(&locked_parent_bus.mem_region),
        );
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    /// Reset device
    fn reset(&mut self, _reset_child_device: bool) -> Result<()> {
        self.config.reset_common_regs()
    }

    /// Get device devfn
    fn devfn(&self) -> Option<u8> {
        Some(self.devfn)
    }
}
