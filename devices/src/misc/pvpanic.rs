// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::{
    convert::TryInto,
    fs::{metadata, read_dir, remove_file, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
    atomic::{AtomicBool, AtomicU16, Ordering},
    Arc, Mutex, Weak,
    },
    time::SystemTime,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};

use crate::pci::config::{
    RegionType, CLASS_PI, DEVICE_ID, HEADER_TYPE, PCI_CLASS_SYSTEM_OTHER, PCI_CONFIG_SPACE_SIZE,
    PCI_DEVICE_ID_REDHAT_PVPANIC, PCI_SUBDEVICE_ID_QEMU, PCI_VENDOR_ID_REDHAT,
    PCI_VENDOR_ID_REDHAT_QUMRANET, REVISION_ID, SUBSYSTEM_ID, SUBSYSTEM_VENDOR_ID, SUB_CLASS_CODE,
    VENDOR_ID,
};
use crate::pci::{le_write_u16, PciBus, PciConfig, PciDevBase, PciDevOps, PciState};
use crate::{convert_bus_mut, convert_bus_ref, Bus, Device, DeviceBase, MUT_PCI_BUS, PCI_BUS};
use address_space::{AddressAttr, AddressSpace, GuestAddress, Region, RegionOps};
use machine_manager::config::{get_pci_df, valid_id};
use migration::{DeviceStateDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::DescSerde;
use util::gen_base_func;
use util::time::{get_format_time, gettime};

const PVPANIC_PCI_REVISION_ID: u8 = 1;
const PVPANIC_PCI_VENDOR_ID: u16 = PCI_VENDOR_ID_REDHAT_QUMRANET;

const PVPANIC_REG_BAR_SIZE: u64 = 0x20;
const PVPANIC_EVENT_OFFSET: u64 = 0;
const PVPANIC_DUMP_FILE_INIT_OFFSET: u64 = 8;
const PVPANIC_BUFFER_ADDRESS_OFFSET: u64 = 16;
const PVPANIC_BUFFER_SIZE_OFFSET: u64 = 24;

pub const PVPANIC_PANICKED: u64 = 1 << 0;
pub const PVPANIC_CRASHLOADED: u64 = 1 << 1;
pub const PVPANIC_BSOD: u64 = 1 << 2;

const PVPANIC_MAX_DMP_FILES: usize = 10;
const PVPANIC_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10MB

#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct PvpanicDevConfig {
    #[arg(long, value_parser = ["pvpanic"])]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub bus: String,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: (u8, u8),
    #[arg(
        long,
        alias = "supported-features",
        default_value = "3",
        value_parser = valid_supported_features
    )]
    pub supported_features: u64,
    #[arg(long, alias = "dumpfile-path", default_value = "./", value_parser = valid_dumpfolder_path)]
    pub dump_folder_path: String,
}

fn valid_supported_features(f: &str) -> Result<u64> {
    let features = f.parse::<u64>()?;
    let supported_features =
        match features & !(PVPANIC_PANICKED | PVPANIC_CRASHLOADED | PVPANIC_BSOD) {
            0 => {
                if (features & PVPANIC_BSOD) != 0 && (features & PVPANIC_CRASHLOADED) == 0 {
                    bail!("pvpanic: BSOD cannot be enabled without enabling CRASHLOADED.");
                }
                features
            }
        _ => bail!("Unsupported pvpanic device features {}", features),
    };
    Ok(supported_features)
}

fn valid_dumpfolder_path(f: &str) -> Result<String> {
    let path = Path::new(f);
    let dump_folder_path = match std::fs::metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() {
                warn!("pvpanic: dump file path configuration error: not a directory.");
            }
            f.to_string()
        }
        Err(e) => {
            warn!("pvpanic: dump file path configuration error: {}", e);
            f.to_string()
        }
    };
    Ok(dump_folder_path)
}

pub struct PvPanicState {
    pub(crate) supported_features: u64,
    pub sys_mem: Arc<AddressSpace>,
    pub guest_physical_address: GuestAddress,
    pub dump_folder_path: String,
    pub dump_file_path: Option<String>,
    pub dump_file: Option<File>,
    pub current_dump_file_size: u64,
    pub file_size_limit_violation: bool,
    pub sys_mem_read_error: bool,
}

impl PvPanicState {
    fn new(supported_features: u64, sys_mem: Arc<AddressSpace>, dump_folder_path: String) -> Self {
        Self {
            supported_features,
            sys_mem,
            guest_physical_address: GuestAddress(0),
            dump_folder_path,
            dump_file_path: None,
            dump_file: None,
            current_dump_file_size: 0_u64,
            file_size_limit_violation: false,
            sys_mem_read_error: false,
        }
    }

    fn clear_current_folder(&mut self) -> bool {
        let mut file_count: usize = 0;
        let mut unremovable_file_count: usize = 0;
        if let Ok(entries) = read_dir(&self.dump_folder_path) {
            let mut dmp_files: Vec<(SystemTime, PathBuf)> = entries
                .filter_map(|entry| {
                    entry.ok().and_then(|e| {
                        let path = e.path();
                        if path.extension().is_some_and(|ext| ext == "dmp") {
                            metadata(&path)
                                .and_then(|metadata| metadata.created().map(|time| (time, path)))
                                .ok()
                        } else {
                            None
                        }
                    })
                })
                .collect();

            dmp_files.sort_by_key(|(time, _)| *time);

            while dmp_files.len() >= PVPANIC_MAX_DMP_FILES
                || dmp_files.len() + unremovable_file_count >= PVPANIC_MAX_DMP_FILES
            {
                let (_, path) = dmp_files.remove(0);
                if let Err(e) = remove_file(&path) {
                    unremovable_file_count += 1;
                    error!(
                        "pvpanic: failed to remove old dump file {}: {:?}",
                        path.display(),
                        e
                    );
                }
                if dmp_files.is_empty() {
                    break;
                }
            }
            file_count = dmp_files.len() + unremovable_file_count;
        } else {
            warn!(
                "pvpanic: failed to read directory {}",
                &self.dump_folder_path
            );
        }

        file_count <= PVPANIC_MAX_DMP_FILES
    }

    fn handle_write_event(&mut self, data: &[u8]) -> Result<()> {
        let event = u64::from(data[0]);
        if (event & !(PVPANIC_PANICKED | PVPANIC_CRASHLOADED)) != 0 {
            error!("pvpanic: unknown event 0x{:X}", event);
        }

        if (event & PVPANIC_PANICKED) == PVPANIC_PANICKED
            && (self.supported_features & PVPANIC_PANICKED) == PVPANIC_PANICKED
        {
            hisysevent::STRATOVIRT_PVPANIC("PANICKED".to_string());
            info!("pvpanic: panicked event");
        }

        if (event & PVPANIC_CRASHLOADED) == PVPANIC_CRASHLOADED
            && (self.supported_features & PVPANIC_CRASHLOADED) == PVPANIC_CRASHLOADED
        {
            hisysevent::STRATOVIRT_PVPANIC("CRASHLOADED".to_string());
            info!("pvpanic: crashloaded event");
        }

        Ok(())
    }

    fn handle_init_dump_file(&mut self, data: &[u8]) -> Result<()> {
        if (self.supported_features & PVPANIC_BSOD) == 0 {
            error!("pvpanic: try to init dump file without enabling BSOD feature");
            return Ok(());
        }

        if !self.clear_current_folder() {
            warn!("pvpanic: try to clear current folder failed");
            self.dump_file = None;
            self.current_dump_file_size = 0_u64;
            self.file_size_limit_violation = false;
            return Ok(());
        }

        let tag_data: [u8; 8] = match data.try_into() {
            Ok(temp_data) => temp_data,
            Err(_) => {
                error!("pvpanic: tag slice sent by init_dump_file command is not 8 bytes long");
                [0; 8]
            }
        };
        let tag = u64::from_le_bytes(tag_data);

        let (sec, _nsec) = gettime().unwrap_or_else(|e| {
            error!("pvpanic: get system time secs error: {:?}", e);
            (0, 0)
        });
        let format_time = get_format_time(sec);

        let sys_time_now = format!(
            "{:02}{:02}{:02}-{:02}{:02}{:02}",
            format_time[0] % 100,
            format_time[1],
            format_time[2],
            format_time[3],
            format_time[4],
            format_time[5]
        );

        let mut dump_path = PathBuf::from(&self.dump_folder_path);
        dump_path.push(sys_time_now.as_str());
        if tag != 0 {
            dump_path.push(format!("_{}", tag));
        }
        dump_path.set_extension("dmp");

        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(dump_path.clone())
        {
            Ok(file) => {
                self.dump_file_path = Some(String::from(dump_path.to_str().unwrap()));
                self.dump_file = Some(file);
            }
            Err(e) => {
                error!(
                    "pvpanic: Failed to append open potential dump file {} : {:?}",
                    dump_path.display(),
                    e
                );
                self.dump_file = None;
            }
        }

        self.current_dump_file_size = 0_u64;
        self.file_size_limit_violation = false;

        Ok(())
    }

    fn handle_write_buffer_address(&mut self, data: &[u8]) -> Result<()> {
        if (self.supported_features & PVPANIC_BSOD) == 0 {
            error!("pvpanic: try to write buffer address without enabling BSOD feature");
            return Ok(());
        }

        if self.dump_file.is_none() {
            error!("pvpanic: try to write buffer address without init dump file first");
            return Ok(());
        }

        let addr_data: [u8; 8] = match data.try_into() {
            Ok(temp_data) => temp_data,
            Err(_) => {
                error!("pvpanic: Slice is not 8 bytes long");
                return Ok(());
            }
        };
        let addr = u64::from_le_bytes(addr_data);
        self.guest_physical_address = GuestAddress(addr);
        debug!("pvpanic: buffer GPA is 0x{:X}", addr);

        Ok(())
    }

    fn handle_write_buffer_size(&mut self, data: &[u8]) -> Result<()> {
        if (self.supported_features & PVPANIC_BSOD) == 0 {
            error!("pvpanic: try to write buffer size without enabling BSOD feature");
            return Ok(());
        }

        if (self.supported_features & PVPANIC_CRASHLOADED) == PVPANIC_CRASHLOADED
            && self.dump_file.is_some()
        {
            let buffer_length_data: [u8; 8] = match data.try_into() {
                Ok(temp_data) => temp_data,
                Err(_) => {
                    error!("pvpanic: Slice is not 8 bytes long");
                    return Ok(());
                }
            };
            let buffer_length = u64::from_le_bytes(buffer_length_data);

            let mut_file = self.dump_file.as_mut().unwrap();

            if self.current_dump_file_size + buffer_length > PVPANIC_MAX_FILE_SIZE {
                if !self.file_size_limit_violation {
                    error!(
                        "pvpanic: current dump file size {}, buffer length {}, exceeds the maximum allowed size {}",
                        self.current_dump_file_size,
                        buffer_length,
                        PVPANIC_MAX_FILE_SIZE
                    );
                    self.file_size_limit_violation = true;
                }
                return Ok(());
            }

            match self.sys_mem.read(
                mut_file,
                self.guest_physical_address,
                buffer_length,
                AddressAttr::Ram,
            ) {
                Ok(_) => {}
                Err(e) => {
                    if !self.sys_mem_read_error {
                        error!("pvpanic: Failed to write data to file: {:?}", e);
                        self.sys_mem_read_error = true;
                    }
                    return Ok(());
                }
            }

            match mut_file.flush() {
                Ok(_) => {}
                Err(e) => {
                    error!("pvpanic: Failed to flush data to file: {:?}", e);
                }
            }

            self.current_dump_file_size += buffer_length;
        }

        Ok(())
    }

    fn close_file(&mut self) -> Result<()> {
        if self.dump_file.is_some() {
            self.dump_file_path = None;
            self.dump_file = None;
        }

        Ok(())
    }

    pub fn get_state(&self) -> PvPanicDevState {
        let pvpanic_state = PvPanicDevState {
            supported_features: self.supported_features,
            guest_physical_address: self.guest_physical_address.0,
            dump_folder_path: self.dump_folder_path.clone(),
            dump_file_path: self
                .dump_file_path
                .is_some()
                .then(|| self.dump_file_path.as_ref().unwrap().clone()),
            current_dump_file_size: self.current_dump_file_size,
            file_size_limit_violation: self.file_size_limit_violation.into(),
            sys_mem_read_error: self.sys_mem_read_error.into(),
        };

        pvpanic_state
    }

    pub fn set_state(&mut self, pvpanic_dev_state: &PvPanicDevState) {
        self.supported_features = pvpanic_dev_state.supported_features;
        self.guest_physical_address = GuestAddress(pvpanic_dev_state.guest_physical_address);

        // set dump folder path
        self.dump_folder_path = pvpanic_dev_state.dump_folder_path.clone();

        // set dump file path, and open the file if config says so
        match &pvpanic_dev_state.dump_file_path {
            Some(path) => {
                self.dump_file_path = Some(path.clone());
                self.dump_file = File::open(path)
                    .inspect_err(|e| {
                        error!("Failed to open file {}: {:?}", path, e);
                    })
                    .ok();
            }
            None => {
                self.dump_file_path = None;
                self.dump_file = None;
            }
        }

        self.current_dump_file_size = pvpanic_dev_state.current_dump_file_size;
        self.file_size_limit_violation = matches!(pvpanic_dev_state.file_size_limit_violation, 1);
        self.sys_mem_read_error = matches!(pvpanic_dev_state.sys_mem_read_error, 1);
    }
}

#[derive(Clone, Deserialize, Serialize, DescSerde)]
#[desc_version(current_version = "0.1.0")]
struct PvPanicPciDevState {
    pci_state: PciState,
    dev_id: u16,
    dev_state: PvPanicDevState,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PvPanicDevState {
    supported_features: u64,
    pub guest_physical_address: u64,
    pub dump_folder_path: String,
    pub dump_file_path: Option<String>,
    pub current_dump_file_size: u64,
    pub file_size_limit_violation: u8,
    pub sys_mem_read_error: u8,
}

pub struct PvPanicPci {
    base: PciDevBase,
    dev_id: AtomicU16,
    pub pvpanic: Arc<Mutex<PvPanicState>>,
}

impl PvPanicPci {
    pub fn new(
        config: &PvpanicDevConfig,
        devfn: u8,
        parent_bus: Weak<Mutex<dyn Bus>>,
        sys_mem: Arc<AddressSpace>,
    ) -> Self {
        Self {
            base: PciDevBase {
                base: DeviceBase::new(config.id.clone(), false, Some(parent_bus)),
                config: PciConfig::new(devfn, PCI_CONFIG_SPACE_SIZE, 1),
                devfn,
                bme: Arc::new(AtomicBool::new(false)),
            },
            dev_id: AtomicU16::new(0),
            pvpanic: Arc::new(Mutex::new(PvPanicState::new(
                config.supported_features,
                sys_mem,
                config.dump_folder_path.clone(),
            ))),
        }
    }

    fn register_bar(&mut self) -> Result<()> {
        let cloned_pvpanic_read = self.pvpanic.clone();
        let bar0_read = Arc::new(
            move |data: &mut [u8], _: GuestAddress, offset: u64| -> bool {
                debug!(
                    "pvpanic: read bar0 called event {} with offset {}",
                    cloned_pvpanic_read.lock().unwrap().supported_features,
                    offset
                );
                if offset != PVPANIC_EVENT_OFFSET {
                    error!("pvpanic: wrong offset {} with bar0 read request", offset);
                    return false;
                }
                data[0] = cloned_pvpanic_read.lock().unwrap().supported_features as u8;
                true
            },
        );

        let cloned_pvpanic_write = self.pvpanic.clone();

        let bar0_write = Arc::new(move |data: &[u8], _: GuestAddress, offset: u64| -> bool {
            match offset {
                PVPANIC_EVENT_OFFSET => {
                    matches!(
                        cloned_pvpanic_write
                            .lock()
                            .unwrap()
                            .handle_write_event(data),
                        Ok(())
                    )
                }
                PVPANIC_DUMP_FILE_INIT_OFFSET => {
                    matches!(
                        cloned_pvpanic_write
                            .lock()
                            .unwrap()
                            .handle_init_dump_file(data),
                        Ok(())
                    )
                }
                PVPANIC_BUFFER_ADDRESS_OFFSET => {
                    matches!(
                        cloned_pvpanic_write
                            .lock()
                            .unwrap()
                            .handle_write_buffer_address(data),
                        Ok(())
                    )
                }
                PVPANIC_BUFFER_SIZE_OFFSET => {
                    matches!(
                        cloned_pvpanic_write
                            .lock()
                            .unwrap()
                            .handle_write_buffer_size(data),
                        Ok(())
                    )
                }
                _ => {
                    error!("pvpanic: wrong offset from front end driver");
                    false
                }
            }
        });

        let bar0_region_ops = RegionOps {
            read: bar0_read,
            write: bar0_write,
        };

        let mut bar_region =
            Region::init_io_region(PVPANIC_REG_BAR_SIZE, bar0_region_ops, "PvPanic");
        bar_region.set_access_size(8);

        self.base.config.register_bar(
            0,
            bar_region,
            RegionType::Mem64Bit,
            false,
            PVPANIC_REG_BAR_SIZE,
        )
    }
}

impl Device for PvPanicPci {
    gen_base_func!(device_base, device_base_mut, DeviceBase, base.base);

    fn reset(&mut self, _reset_child_device: bool) -> Result<()> {
        let mut locked_pvpanic = self.pvpanic.lock().unwrap();
        locked_pvpanic.sys_mem_read_error = false;
        locked_pvpanic.close_file()
    }

    fn realize(mut self) -> Result<Arc<Mutex<Self>>> {
        self.init_write_mask(false)?;
        self.init_write_clear_mask(false)?;
        le_write_u16(
            &mut self.base.config.config,
            VENDOR_ID as usize,
            PCI_VENDOR_ID_REDHAT,
        )?;

        le_write_u16(
            &mut self.base.config.config,
            DEVICE_ID as usize,
            PCI_DEVICE_ID_REDHAT_PVPANIC,
        )?;

        self.base.config.config[REVISION_ID] = PVPANIC_PCI_REVISION_ID;

        le_write_u16(
            &mut self.base.config.config,
            SUB_CLASS_CODE as usize,
            PCI_CLASS_SYSTEM_OTHER,
        )?;

        le_write_u16(
            &mut self.base.config.config,
            SUBSYSTEM_VENDOR_ID,
            PVPANIC_PCI_VENDOR_ID,
        )?;

        le_write_u16(
            &mut self.base.config.config,
            SUBSYSTEM_ID,
            PCI_SUBDEVICE_ID_QEMU,
        )?;

        self.base.config.config[CLASS_PI as usize] = 0x00;

        self.base.config.config[HEADER_TYPE as usize] = 0x00;

        self.register_bar()
            .with_context(|| "pvpanic: device register bar failed")?;

        let device_name = self.name();

        // Attach to the PCI bus.
        let devfn = self.base.devfn;
        let dev = Arc::new(Mutex::new(self));
        let bus = dev.lock().unwrap().parent_bus().unwrap().upgrade().unwrap();
        MUT_PCI_BUS!(bus, locked_bus, pci_bus);
        let device_id = pci_bus.generate_dev_id(devfn);
        dev.lock()
            .unwrap()
            .dev_id
            .store(device_id, Ordering::Release);
        locked_bus.attach_child(u64::from(devfn), dev.clone())?;

        MigrationManager::register_device_instance(
            PvPanicPciDevState::descriptor(),
            dev.clone(),
            &device_name,
        );

        Ok(dev)
    }

    fn unrealize(&mut self) -> Result<()> {
        MigrationManager::unregister_device_instance(
            PvPanicPciDevState::descriptor(),
            &self.name(),
        );

        let mut locked_pvpanic = self.pvpanic.lock().unwrap();
        locked_pvpanic.close_file()
    }
}

impl PciDevOps for PvPanicPci {
    gen_base_func!(pci_base, pci_base_mut, PciDevBase, base);

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let parent_bus = self.parent_bus().unwrap().upgrade().unwrap();
        PCI_BUS!(parent_bus, locked_bus, pci_bus);

        self.base.config.write(
            offset,
            data,
            self.dev_id.load(Ordering::Acquire),
            #[cfg(target_arch = "x86_64")]
            Some(&pci_bus.io_region),
            Some(&pci_bus.mem_region),
        );
    }
}

impl StateTransfer for PvPanicPci {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let state = PvPanicPciDevState {
            pci_state: self.base.get_pci_state(),
            dev_id: self.dev_id.load(Ordering::Acquire),
            dev_state: self.pvpanic.lock().unwrap().get_state(),
        };

        Ok(serde_json::to_vec(&state)?)
    }

    fn set_state_mut(&mut self, state: &[u8], _version: u32) -> Result<()> {
        let pvpanic_pci_state: PvPanicPciDevState = serde_json::from_slice(state)
            .with_context(|| migration::error::MigrationError::FromBytesError("PVPANIC"))?;

        self.dev_id
            .store(pvpanic_pci_state.dev_id, Ordering::Release);
        self.base.set_pci_state(&pvpanic_pci_state.pci_state);
        self.pvpanic
            .lock()
            .unwrap()
            .set_state(&pvpanic_pci_state.dev_state);

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&PvPanicPciDevState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for PvPanicPci {
    fn resume(&mut self) -> Result<()> {
        let parent_bus = self.parent_bus().unwrap().upgrade().unwrap();
        PCI_BUS!(parent_bus, locked_bus, pci_bus);
        if let Err(e) = self.base.config.update_bar_mapping(
            #[cfg(target_arch = "x86_64")]
            Some(&pci_bus.io_region),
            Some(&pci_bus.mem_region),
        ) {
            bail!("Failed to update bar, error is {:?}", e);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::{host::tests::create_pci_host, le_read_u16, PciHost};
    use crate::{convert_bus_ref, convert_device_mut, PCI_BUS};
    use machine_manager::config::str_slip_to_clap;

    /// Convert from Arc<Mutex<dyn Device>> to &mut PvPanicPci.
    #[macro_export]
    macro_rules! MUT_PVPANIC_PCI {
        ($trait_device:expr, $lock_device: ident, $struct_device: ident) => {
            convert_device_mut!($trait_device, $lock_device, $struct_device, PvPanicPci);
        };
    }

    fn init_pvpanic_dev(devfn: u8, supported_features: u64, dev_id: &str) -> Arc<Mutex<PciHost>> {
        let pci_host = create_pci_host();
        let locked_pci_host = pci_host.lock().unwrap();
        let root_bus = Arc::downgrade(&locked_pci_host.child_bus().unwrap());

        let config = PvpanicDevConfig {
            id: dev_id.to_string(),
            supported_features,
            classtype: "".to_string(),
            bus: "pcie.0".to_string(),
            addr: (3, 0),
        };
        let pvpanic_dev = PvPanicPci::new(&config, devfn, root_bus);
        assert_eq!(pvpanic_dev.base.base.id, "pvpanic_test".to_string());

        pvpanic_dev.realize().unwrap();
        drop(locked_pci_host);

        pci_host
    }

    fn get_pvpanic_dev(devfn: u8, supported_features: u64, dev_id: &str) -> Arc<Mutex<dyn Device>> {
        let pci_host = init_pvpanic_dev(devfn, supported_features, dev_id);
        let root_bus = pci_host.lock().unwrap().child_bus().unwrap();
        PCI_BUS!(root_bus, locked_bus, pci_bus);
        pci_bus.get_device(0, devfn).unwrap()
    }

    #[test]
    fn test_pvpanic_cmdline_parser() {
        // Test1: supported-features Right.
        let cmdline = "pvpanic,id=pvpanic0,bus=pcie.0,addr=0x7,supported-features=0";
        let result = PvpanicDevConfig::try_parse_from(str_slip_to_clap(cmdline, true, false));
        assert_eq!(result.unwrap().supported_features, 0);

        // Test2: supported-features Default value.
        let cmdline = "pvpanic,id=pvpanic0,bus=pcie.0,addr=0x7";
        let result = PvpanicDevConfig::try_parse_from(str_slip_to_clap(cmdline, true, false));
        assert_eq!(result.unwrap().supported_features, 3);

        // Test3: supported-features Illegal value.
        let cmdline = "pvpanic,id=pvpanic0,bus=pcie.0,addr=0x7,supported-features=4";
        let result = PvpanicDevConfig::try_parse_from(str_slip_to_clap(cmdline, true, false));
        assert!(result.is_err());
    }

    #[test]
    fn test_pvpanic_attached() {
        let pci_host = init_pvpanic_dev(7, PVPANIC_PANICKED | PVPANIC_CRASHLOADED, "pvpanic_test");
        let root_bus = pci_host.lock().unwrap().child_bus().unwrap();
        PCI_BUS!(root_bus, locked_bus, pci_bus);
        let pvpanic_dev = pci_bus.get_device(0, 7);
        drop(locked_bus);
        assert!(pvpanic_dev.is_some());
        assert_eq!(
            pvpanic_dev.unwrap().lock().unwrap().name(),
            "pvpanic_test".to_string()
        );

        let info = PciBus::find_attached_bus(&root_bus, "pvpanic_test");
        assert!(info.is_some());
        let (bus, dev) = info.unwrap();
        assert_eq!(bus.lock().unwrap().name(), "pcie.0");
        assert_eq!(dev.lock().unwrap().name(), "pvpanic_test");
    }

    #[test]
    fn test_pvpanic_config() {
        let pvpanic_dev =
            get_pvpanic_dev(7, PVPANIC_PANICKED | PVPANIC_CRASHLOADED, "pvpanic_test");
        MUT_PVPANIC_PCI!(pvpanic_dev, locked_dev, pvpanic);

        let read_config_params: [(u8, u16); 5] = [
            (VENDOR_ID, PCI_VENDOR_ID_REDHAT),
            (DEVICE_ID, PCI_DEVICE_ID_REDHAT_PVPANIC),
            (SUB_CLASS_CODE, PCI_CLASS_SYSTEM_OTHER),
            (SUBSYSTEM_VENDOR_ID as u8, PVPANIC_PCI_VENDOR_ID),
            (SUBSYSTEM_ID as u8, PCI_SUBDEVICE_ID_QEMU),
        ];

        for &(offset, expected_content) in read_config_params.iter() {
            let info = le_read_u16(&pvpanic.pci_base_mut().config.config, offset as usize)
                .unwrap_or_else(|_| 0);
            assert_eq!(info, expected_content);
        }
    }

    #[test]
    fn test_pvpanic_read_features() {
        let pvpanic_dev =
            get_pvpanic_dev(7, PVPANIC_PANICKED | PVPANIC_CRASHLOADED, "pvpanic_test");
        MUT_PVPANIC_PCI!(pvpanic_dev, locked_dev, pvpanic);

        // test read supported_features
        let mut data_read = [0xffu8; 1];
        let result = &pvpanic.pci_base_mut().config.bars[0]
            .region
            .as_ref()
            .unwrap()
            .read(&mut data_read.as_mut(), GuestAddress(0), 0, 1);
        assert!(result.is_ok());
        assert_eq!(
            data_read.to_vec(),
            vec![PVPANIC_PANICKED as u8 | PVPANIC_CRASHLOADED as u8]
        );
    }

    #[test]
    fn test_pvpanic_write_events() {
        let pvpanic_dev =
            get_pvpanic_dev(7, PVPANIC_PANICKED | PVPANIC_CRASHLOADED, "pvpanic_test");
        MUT_PVPANIC_PCI!(pvpanic_dev, locked_dev, pvpanic);

        // test write events
        let write_event_params: [u64; 3] = [
            PVPANIC_PANICKED,
            PVPANIC_CRASHLOADED,
            (!(PVPANIC_PANICKED | PVPANIC_CRASHLOADED)),
        ];

        for &param in write_event_params.iter() {
            let data_write = param.to_le_bytes();
            let count = data_write.len() as u64;
            let result = &pvpanic.pci_base_mut().config.bars[0]
                .region
                .as_ref()
                .unwrap()
                .write(&mut data_write.as_ref(), GuestAddress(0), 0, count);
            assert!(result.is_ok());
        }
    }
}
