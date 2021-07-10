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

const PCI_NUM_BARS: u8 = 6;
const PCI_ROM_SLOT: u8 = 6;

struct MsixTable {
    table_bar: u8,
    table_offset: u64,
    table_size: u64,
}

struct VfioMsixInfo {
    // Table bar, table offset and table size info.
    table: MsixTable,
    // Msix enteries.
    enteries: u16,
    // Vfio device irq info
    #[allow(dead_code)]
    vfio_irq: HashMap<u32, VfioIrq>,
}

struct VfioBar {
    vfio_region: VfioRegion,
    region_type: RegionType,
    size: u64,
}

struct GsiMsiRoute {
    irq_fd: Option<EventFd>,
    gsi: i32,
}

/// VfioPciDevice is a VFIO PCI device. It implements PciDevOps trait for a PCI device.
/// And it is bound to a VFIO device.
pub struct VfioPciDevice {
    pci_config: PciConfig,
    config_size: u64,
    // Offset of pci config space region within vfio device fd.
    config_offset: u64,
    // Vfio device which is bound to.
    vfio_device: Arc<VfioDevice>,
    // Cache of MSI-X setup.
    msix_info: Option<VfioMsixInfo>,
    // Bars information without ROM.
    vfio_bars: Arc<Mutex<Vec<VfioBar>>>,
    // Maintains a list of GSI with irqfds that are registered to kvm.
    gsi_msi_routes: Arc<Mutex<Vec<GsiMsiRoute>>>,
    devfn: u8,
    dev_id: u16,
    name: String,
    parent_bus: Weak<Mutex<PciBus>>,
}

impl VfioPciDevice {
    /// New a VFIO PCI device structure for the vfio device created by VMM.
    pub fn new(
        path: &Path,
        container: Arc<VfioContainer>,
        devfn: u8,
        name: String,
        parent_bus: Weak<Mutex<PciBus>>,
    ) -> PciResult<Self> {
        Ok(VfioPciDevice {
            // Unknown PCI or PCIe type here, allocate enough space to match the two types.
            pci_config: PciConfig::new(PCIE_CONFIG_SPACE_SIZE, PCI_NUM_BARS),
            config_size: 0,
            config_offset: 0,
            vfio_device: Arc::new(
                VfioDevice::new(container, path).chain_err(|| "Failed to new vfio device")?,
            ),
            msix_info: None,
            vfio_bars: Arc::new(Mutex::new(Vec::with_capacity(PCI_NUM_BARS as usize))),
            gsi_msi_routes: Arc::new(Mutex::new(Vec::new())),
            devfn,
            dev_id: 0,
            name,
            parent_bus,
        })
    }
}

impl PciDevOps for VfioPciDevice {
    fn init_write_mask(&mut self) -> PciResult<()> {
        self.pci_config.init_common_write_mask()
    }

    fn init_write_clear_mask(&mut self) -> PciResult<()> {
        self.pci_config.init_common_write_clear_mask()
    }

    fn realize(mut self) -> PciResult<()> {
        self.init_write_mask()?;
        self.init_write_clear_mask()?;
        self.vfio_device
            .reset()
            .chain_err(|| "Failed to reset vfio device")?;

        self.get_pci_config()
            .chain_err(|| "Failed to get vfio device pci config space")?;
        self.pci_config_reset()
            .chain_err(|| "Failed to reset vfio device pci config space")?;

        #[cfg(target_arch = "aarch64")]
        {
            let bus_num = self
                .parent_bus
                .upgrade()
                .unwrap()
                .lock()
                .unwrap()
                .number(SECONDARY_BUS_NUM as usize);
            self.dev_id = self.set_dev_id(bus_num, self.devfn);
        }

        self.msix_info = Some(
            self.get_msix_info()
                .chain_err(|| "Failed to get MSI-X info")?,
        );
        self.vfio_bars = Arc::new(Mutex::new(
            self.bar_region_info()
                .chain_err(|| "Fail to get bar region info")?,
        ));
        self.register_bars().chain_err(|| "Fail to register bars")?;

        let devfn = self.devfn;
        let dev = Arc::new(Mutex::new(self));
        let pci_bus = dev.lock().unwrap().parent_bus.upgrade().unwrap();
        let mut locked_pci_bus = pci_bus.lock().unwrap();
        let pci_device = locked_pci_bus.devices.get(&devfn);
        if pci_device.is_none() {
            locked_pci_bus.devices.insert(devfn, dev);
        } else {
            bail!(
                "Devfn {:?} has been used by {:?}",
                &devfn,
                pci_device.unwrap().lock().unwrap().name()
            );
        }

        Ok(())
    }

    /// Read pci data from pci config if it emulate, otherwise read from vfio device.
    fn read_config(&self, offset: usize, data: &mut [u8]) {
        let size = data.len();
        let end = offset + size;
        if end > (self.config_size as usize) || size > 4 {
            error!(
                "Failed to read pci config space at offset {} with data size {}",
                offset, size
            );
            return;
        }

        if offset >= (BAR_0 as usize) && offset < (BAR_5 as usize) + REG_SIZE {
            self.pci_config.read(offset, data);
            return;
        }

        if let Err(e) = self
            .vfio_device
            .read_region(data, self.config_offset, offset as u64)
        {
            error!("Failed to read device pci config, error is {}", e);
            return;
        }
        for (i, data) in data.iter_mut().enumerate().take(size) {
            if i + offset == 0x3d {
                // Clear INIx
                *data &= 0;
            } else if i + offset == 0x0e {
                // Clear multi-function
                *data &= 0x7f;
            }
        }
    }

    /// Write data to pci config and vfio device at the same time
    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let size = data.len();
        let end = offset + size;
        if end > (self.config_size as usize) || size > 4 {
            error!(
                "Failed to write pci config space at offset {} with data size {}",
                offset, size
            );
            return;
        }

        // Let vfio device filter data to write.
        if let Err(e) = self
            .vfio_device
            .write_region(data, self.config_offset, offset as u64)
        {
            error!("Failed to write device pci config, error is {}", e);
            return;
        }

        let mut cap_offset = 0;
        if let Some(msix) = &self.pci_config.msix {
            cap_offset = msix.lock().unwrap().msix_cap_offset as usize;
        }

        if ranges_overlap(offset, end, COMMAND as usize, COMMAND as usize + 4) {
            self.pci_config.write(offset, data, self.dev_id);

            if le_read_u32(&self.pci_config.config, offset).unwrap() & COMMAND_MEMORY_SPACE as u32
                != 0
            {
                let parent_bus = self.parent_bus.upgrade().unwrap();
                let locked_parent_bus = parent_bus.lock().unwrap();
                if let Err(e) = self.pci_config.update_bar_mapping(
                    #[cfg(target_arch = "x86_64")]
                    &locked_parent_bus.io_region,
                    &locked_parent_bus.mem_region,
                ) {
                    error!("Failed to update bar, error is {}", e.display_chain());
                    return;
                }
                drop(locked_parent_bus);

                if let Err(e) = self.setup_bars_mmap() {
                    error!("Failed to map bar regions, error is {}", e.display_chain());
                    return;
                }
            }
        } else if ranges_overlap(offset, end, BAR_0 as usize, (BAR_5 as usize) + REG_SIZE) {
            self.pci_config.write(offset, data, self.dev_id);

            if size == 4 && LittleEndian::read_u32(data) != 0xffff_ffff {
                let parent_bus = self.parent_bus.upgrade().unwrap();
                let locked_parent_bus = parent_bus.lock().unwrap();
                if let Err(e) = self.pci_config.update_bar_mapping(
                    #[cfg(target_arch = "x86_64")]
                    &locked_parent_bus.io_region,
                    &locked_parent_bus.mem_region,
                ) {
                    error!("Failed to update bar, error is {}", e.display_chain());
                    return;
                }
            }
        } else if ranges_overlap(offset, end, cap_offset, cap_offset + MSIX_CAP_SIZE as usize) {
            let was_enable = is_msix_enabled(cap_offset, &self.pci_config.config);
            self.pci_config.write(offset, data, self.dev_id);
            let is_enable = is_msix_enabled(cap_offset, &self.pci_config.config);

            if !was_enable && is_enable {
                if let Err(e) = self.vfio_enable_msix() {
                    error!("Failed to enable MSI-X, error is {}", e.display_chain());
                    return;
                }
            } else if was_enable && !is_enable {
                if let Err(e) = self.vfio_disable_msix() {
                    error!("Failed to disable MSI-X, error is {}", e.display_chain());
                    return;
                }
            }
        } else {
            self.pci_config.write(offset, data, self.dev_id);
        }
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}
