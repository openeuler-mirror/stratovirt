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

use std::sync::{Arc, Mutex, Weak};

use address_space::Region;
use error_chain::ChainedError;

use super::config::{
    PciConfig, PcieDevType, BAR_0, CLASS_CODE_PCI_BRIDGE, COMMAND, COMMAND_IO_SPACE,
    COMMAND_MEMORY_SPACE, DEVICE_ID, HEADER_TYPE, HEADER_TYPE_BRIDGE, HEADER_TYPE_MULTIFUNC,
    IO_BASE, MEMORY_BASE, PCIE_CONFIG_SPACE_SIZE, PREF_MEMORY_BASE, PREF_MEMORY_LIMIT,
    PREF_MEM_RANGE_64BIT, REG_SIZE, SUB_CLASS_CODE, VENDOR_ID,
};
use crate::bus::PciBus;
use crate::errors::{Result, ResultExt};
use crate::msix::init_msix;
use crate::{le_read_u16, le_write_u16, ranges_overlap, PciDevOps};

const VENDOR_ID_RP: u16 = 0x1b36;
const DEVICE_ID_RP: u16 = 0x000c;

pub struct RootPort {
    name: String,
    devfn: u8,
    port_num: u8,
    config: PciConfig,
    parent_bus: Weak<Mutex<PciBus>>,
    sec_bus: Arc<Mutex<PciBus>>,
    #[cfg(target_arch = "x86_64")]
    io_region: Region,
    mem_region: Region,
    dev_id: u16,
}

impl RootPort {
    /// Construct a new pcie root port.
    ///
    /// # Arguments
    ///
    /// * `name` - Root port name.
    /// * `devfn` - Device number << 3 | Function number.
    /// * `port_num` - Root port number.
    /// * `parent_bus` - Weak reference to the parent bus.
    #[allow(dead_code)]
    pub fn new(name: String, devfn: u8, port_num: u8, parent_bus: Weak<Mutex<PciBus>>) -> Self {
        #[cfg(target_arch = "x86_64")]
        let io_region = Region::init_container_region(1 << 16);
        let mem_region = Region::init_container_region(u64::max_value());
        let sec_bus = Arc::new(Mutex::new(PciBus::new(
            name.clone(),
            #[cfg(target_arch = "x86_64")]
            io_region.clone(),
            mem_region.clone(),
        )));

        Self {
            name,
            devfn,
            port_num,
            config: PciConfig::new(PCIE_CONFIG_SPACE_SIZE, 2),
            parent_bus,
            sec_bus,
            #[cfg(target_arch = "x86_64")]
            io_region,
            mem_region,
            dev_id: 0,
        }
    }
}

impl PciDevOps for RootPort {
    fn init_write_mask(&mut self) -> Result<()> {
        self.config.init_common_write_mask()?;
        self.config.init_bridge_write_mask()
    }

    fn init_write_clear_mask(&mut self) -> Result<()> {
        self.config.init_common_write_clear_mask()?;
        self.config.init_bridge_write_clear_mask()
    }

    fn realize(mut self) -> Result<()> {
        self.init_write_mask()?;
        self.init_write_clear_mask()?;

        let config_space = &mut self.config.config;
        le_write_u16(config_space, VENDOR_ID as usize, VENDOR_ID_RP)?;
        le_write_u16(config_space, DEVICE_ID as usize, DEVICE_ID_RP)?;
        le_write_u16(config_space, SUB_CLASS_CODE as usize, CLASS_CODE_PCI_BRIDGE)?;
        config_space[HEADER_TYPE as usize] = HEADER_TYPE_BRIDGE | HEADER_TYPE_MULTIFUNC;
        config_space[PREF_MEMORY_BASE as usize] = PREF_MEM_RANGE_64BIT;
        config_space[PREF_MEMORY_LIMIT as usize] = PREF_MEM_RANGE_64BIT;
        self.config
            .add_pcie_cap(self.devfn, self.port_num, PcieDevType::RootPort as u8)?;
        #[cfg(target_arch = "aarch64")]
        {
            self.dev_id = self.set_dev_id(0, self.devfn);
            init_msix(0, 1, &mut self.config, self.dev_id)?;
        }
        #[cfg(target_arch = "x86_64")]
        init_msix(0, 1, &mut self.config, 0)?;

        let parent_bus = self.parent_bus.upgrade().unwrap();
        let mut locked_parent_bus = parent_bus.lock().unwrap();
        #[cfg(target_arch = "x86_64")]
        locked_parent_bus
            .io_region
            .add_subregion(self.sec_bus.lock().unwrap().io_region.clone(), 0)
            .chain_err(|| "Failed to register subregion in I/O space.")?;
        locked_parent_bus
            .mem_region
            .add_subregion(self.sec_bus.lock().unwrap().mem_region.clone(), 0)
            .chain_err(|| "Failed to register subregion in memory space.")?;

        let root_port = Arc::new(Mutex::new(self));
        #[allow(unused_mut)]
        let mut locked_root_port = root_port.lock().unwrap();
        locked_root_port.sec_bus.lock().unwrap().parent_bridge =
            Some(Arc::downgrade(&root_port) as Weak<Mutex<dyn PciDevOps>>);
        locked_parent_bus
            .child_buses
            .push(locked_root_port.sec_bus.clone());
        locked_parent_bus
            .devices
            .insert(locked_root_port.devfn, root_port.clone());

        Ok(())
    }

    fn read_config(&self, offset: usize, data: &mut [u8]) {
        let size = data.len();
        if offset + size > PCIE_CONFIG_SPACE_SIZE || size > 4 {
            error!(
                "Failed to read pcie config space at offset {} with data size {}",
                offset, size
            );
            return;
        }

        self.config.read(offset, data);
    }

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let size = data.len();
        let end = offset + size;
        if end > PCIE_CONFIG_SPACE_SIZE || size > 4 {
            error!(
                "Failed to write pcie config space at offset {} with data size {}",
                offset, size
            );
            return;
        }

        self.config.write(offset, data, self.dev_id);
        if ranges_overlap(offset, end, COMMAND as usize, (COMMAND + 1) as usize)
            || ranges_overlap(offset, end, BAR_0 as usize, BAR_0 as usize + REG_SIZE * 2)
        {
            if let Err(e) = self.config.update_bar_mapping(
                #[cfg(target_arch = "x86_64")]
                &self.io_region,
                &self.mem_region,
            ) {
                error!("{}", e.display_chain());
            }
        }
        if ranges_overlap(offset, end, COMMAND as usize, (COMMAND + 1) as usize)
            || ranges_overlap(offset, end, IO_BASE as usize, (IO_BASE + 2) as usize)
            || ranges_overlap(
                offset,
                end,
                MEMORY_BASE as usize,
                (MEMORY_BASE + 20) as usize,
            )
        {
            let command: u16 = le_read_u16(&self.config.config, COMMAND as usize).unwrap();
            if command & COMMAND_IO_SPACE != 0 {
                #[cfg(target_arch = "x86_64")]
                if let Err(e) = self
                    .parent_bus
                    .upgrade()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .io_region
                    .add_subregion(self.io_region.clone(), 0)
                    .chain_err(|| "Failed to add IO container region.")
                {
                    error!("{}", e.display_chain());
                }
            }
            if command & COMMAND_MEMORY_SPACE != 0 {
                if let Err(e) = self
                    .parent_bus
                    .upgrade()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .mem_region
                    .add_subregion(self.mem_region.clone(), 0)
                    .chain_err(|| "Failed to add memory container region.")
                {
                    error!("{}", e.display_chain());
                }
            }
        }
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}
