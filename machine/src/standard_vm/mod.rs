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

#[allow(dead_code)]
#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::StdMachine;
use machine_manager::event_loop::EventLoop;
use util::loop_context::{EventNotifier, NotifierCallback, NotifierOperation};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;
#[cfg(target_arch = "x86_64")]
pub use x86_64::StdMachine;

#[allow(clippy::upper_case_acronyms)]
pub mod errors {
    error_chain! {
        links {
            AddressSpace(address_space::errors::Error, address_space::errors::ErrorKind);
            Cpu(cpu::errors::Error, cpu::errors::ErrorKind);
            Legacy(devices::LegacyErrs::Error, devices::LegacyErrs::ErrorKind);
            PciErr(pci::errors::Error, pci::errors::ErrorKind);
            Acpi(acpi::errors::Error, acpi::errors::ErrorKind);
            MachineManager(machine_manager::config::errors::Error, machine_manager::config::errors::ErrorKind);
        }
        foreign_links{
            Io(std::io::Error);
        }
        errors {
            InitPCIeHostErr {
                display("Failed to init PCIe host.")
            }
            OpenFileErr(path: String) {
                display("Failed to open file: {}.", path)
            }
            InitPflashErr {
                display("Failed to init pflash device.")
            }
            RlzPflashErr {
                display("Failed to realize pflash device.")
            }
        }
    }
}

use std::mem::size_of;
use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::os::unix::prelude::AsRawFd;
use std::sync::{Arc, Condvar, Mutex};

use crate::errors::Result as MachineResult;
use crate::MachineOps;
#[cfg(target_arch = "x86_64")]
use acpi::AcpiGenericAddress;
use acpi::{
    AcpiRsdp, AcpiTable, AmlBuilder, TableLoader, ACPI_RSDP_FILE, ACPI_TABLE_FILE,
    ACPI_TABLE_LOADER_FILE, TABLE_CHECKSUM_OFFSET,
};
use cpu::{CpuTopology, CPU};
use devices::legacy::FwCfgOps;
use error_chain::ChainedError;
use errors::{Result, ResultExt};
use machine_manager::config::{
    get_pci_df, BlkDevConfig, ConfigCheck, DriveConfig, PciBdf, VmConfig,
};
use machine_manager::machine::{DeviceInterface, KvmVmState};
use machine_manager::qmp::{qmp_schema, QmpChannel, Response};
use pci::hotplug::{handle_plug, handle_unplug_request};
use pci::PciBus;
use util::byte_code::ByteCode;
use virtio::{qmp_balloon, qmp_query_balloon, Block};

#[cfg(target_arch = "aarch64")]
use aarch64::{LayoutEntryType, MEM_LAYOUT};
#[cfg(target_arch = "x86_64")]
use x86_64::{LayoutEntryType, MEM_LAYOUT};

#[cfg(target_arch = "x86_64")]
use self::x86_64::ich9_lpc::SLEEP_CTRL_OFFSET;

trait StdMachineOps: AcpiBuilder {
    fn init_pci_host(&self) -> Result<()>;

    /// Build all ACPI tables and RSDP, and add them to FwCfg as file entries.
    ///
    /// # Arguments
    ///
    /// `fw_cfg` - FwCfgOps trait object.
    fn build_acpi_tables(&self, fw_cfg: &Arc<Mutex<dyn FwCfgOps>>) -> Result<()>
    where
        Self: Sized,
    {
        let mut loader = TableLoader::new();
        let acpi_tables = Arc::new(Mutex::new(Vec::new()));
        loader.add_alloc_entry(ACPI_TABLE_FILE, acpi_tables.clone(), 64_u32, false)?;

        let mut xsdt_entries = Vec::new();

        let dsdt_addr = self
            .build_dsdt_table(&acpi_tables, &mut loader)
            .chain_err(|| "Failed to build ACPI DSDT table")?;
        let fadt_addr = Self::build_fadt_table(&acpi_tables, &mut loader, dsdt_addr)
            .chain_err(|| "Failed to build ACPI FADT table")?;
        xsdt_entries.push(fadt_addr);

        let madt_addr = self
            .build_madt_table(&acpi_tables, &mut loader)
            .chain_err(|| "Failed to build ACPI MADT table")?;
        xsdt_entries.push(madt_addr);

        let mcfg_addr = Self::build_mcfg_table(&acpi_tables, &mut loader)
            .chain_err(|| "Failed to build ACPI MCFG table")?;
        xsdt_entries.push(mcfg_addr);

        let xsdt_addr = Self::build_xsdt_table(&acpi_tables, &mut loader, xsdt_entries)?;

        let mut locked_fw_cfg = fw_cfg.lock().unwrap();
        Self::build_rsdp(
            &mut loader,
            &mut *locked_fw_cfg as &mut dyn FwCfgOps,
            xsdt_addr,
        )
        .chain_err(|| "Failed to build ACPI RSDP")?;

        locked_fw_cfg
            .add_file_entry(ACPI_TABLE_LOADER_FILE, loader.cmd_entries())
            .chain_err(|| "Failed to add ACPI table loader file entry")?;
        locked_fw_cfg
            .add_file_entry(ACPI_TABLE_FILE, acpi_tables.lock().unwrap().to_vec())
            .chain_err(|| "Failed to add ACPI-tables file entry")?;

        Ok(())
    }

    fn add_fwcfg_device(&mut self) -> Result<Arc<Mutex<dyn FwCfgOps>>> {
        bail!("Not implemented");
    }

    fn get_vm_state(&self) -> &Arc<(Mutex<KvmVmState>, Condvar)>;

    fn get_cpu_topo(&self) -> &CpuTopology;

    fn get_cpus(&self) -> &Vec<Arc<CPU>>;

    fn get_vm_config(&self) -> &Mutex<VmConfig>;

    /// Register event notifier for reset of standard machine.
    ///
    /// # Arguments
    ///
    /// * `reset_req` - Eventfd of the reset request.
    /// * `clone_vm` - Reference of the StdMachine.
    fn register_reset_event(
        &self,
        reset_req: &EventFd,
        clone_vm: Arc<Mutex<StdMachine>>,
    ) -> MachineResult<()> {
        let reset_req = reset_req.try_clone().unwrap();
        let reset_req_fd = reset_req.as_raw_fd();
        let reset_req_handler: Arc<Mutex<Box<NotifierCallback>>> =
            Arc::new(Mutex::new(Box::new(move |_, _| {
                let _ret = reset_req.read().unwrap();
                if let Err(e) = StdMachine::handle_reset_request(&clone_vm) {
                    error!(
                        "Fail to reboot standard VM, {}",
                        error_chain::ChainedError::display_chain(&e)
                    );
                }

                None
            })));
        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            reset_req_fd,
            None,
            EventSet::IN,
            vec![reset_req_handler],
        );
        EventLoop::update_event(vec![notifier], None)
            .chain_err(|| "Failed to register event notifier.")?;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn register_acpi_shutdown_event(
        &self,
        shutdown_req: &EventFd,
        clone_vm: Arc<Mutex<StdMachine>>,
    ) -> MachineResult<()> {
        let shutdown_req = shutdown_req.try_clone().unwrap();
        let shutdown_req_fd = shutdown_req.as_raw_fd();
        let shutdown_req_handler: Arc<Mutex<Box<NotifierCallback>>> =
            Arc::new(Mutex::new(Box::new(move |_, _| {
                let _ret = shutdown_req.read().unwrap();
                StdMachine::handle_shutdown_request(&clone_vm);
                let notifiers = vec![EventNotifier::new(
                    NotifierOperation::Delete,
                    shutdown_req_fd,
                    None,
                    EventSet::IN,
                    Vec::new(),
                )];
                Some(notifiers)
            })));
        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            shutdown_req_fd,
            None,
            EventSet::IN,
            vec![shutdown_req_handler],
        );
        EventLoop::update_event(vec![notifier], None)
            .chain_err(|| "Failed to register event notifier.")?;
        Ok(())
    }
}

/// Trait that helps to build ACPI tables.
/// Standard machine struct should at least implement `build_dsdt_table`, `build_madt_table`
/// and `build_mcfg_table` function.
trait AcpiBuilder {
    /// Build ACPI DSDT table, returns the offset of ACPI DSDT table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `loader` - ACPI table loader.
    fn build_dsdt_table(
        &self,
        _acpi_data: &Arc<Mutex<Vec<u8>>>,
        _loader: &mut TableLoader,
    ) -> Result<u64> {
        bail!("Not implemented");
    }

    /// Build ACPI MADT table, returns the offset of ACPI MADT table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `loader` - ACPI table loader.
    fn build_madt_table(
        &self,
        _acpi_data: &Arc<Mutex<Vec<u8>>>,
        _loader: &mut TableLoader,
    ) -> Result<u64> {
        bail!("Not implemented");
    }

    /// Build ACPI MCFG table, returns the offset of ACPI MCFG table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `loader` - ACPI table loader.
    fn build_mcfg_table(acpi_data: &Arc<Mutex<Vec<u8>>>, loader: &mut TableLoader) -> Result<u64>
    where
        Self: Sized,
    {
        let mut mcfg = AcpiTable::new(*b"MCFG", 1, *b"STRATO", *b"VIRTMCFG", 1);
        let ecam_addr: u64 = MEM_LAYOUT[LayoutEntryType::PcieEcam as usize].0;
        // Bits 20~28 (totally 9 bits) in PCIE ECAM represents bus number.
        let bus_number_mask = (1 << 9) - 1;
        let max_nr_bus = (MEM_LAYOUT[LayoutEntryType::PcieEcam as usize].1 >> 20) & bus_number_mask;

        // Reserved
        mcfg.append_child(&[0_u8; 8]);
        // Base address of PCIE ECAM
        mcfg.append_child(ecam_addr.as_bytes());
        // PCI Segment Group Number
        mcfg.append_child(0_u16.as_bytes());
        // Start Bus Number and End Bus Number
        mcfg.append_child(&[0_u8, (max_nr_bus - 1) as u8]);
        // Reserved
        mcfg.append_child(&[0_u8; 4]);

        let mut acpi_data_locked = acpi_data.lock().unwrap();
        let mcfg_begin = acpi_data_locked.len() as u32;
        acpi_data_locked.extend(mcfg.aml_bytes());
        let mcfg_end = acpi_data_locked.len() as u32;
        drop(acpi_data_locked);

        loader.add_cksum_entry(
            ACPI_TABLE_FILE,
            mcfg_begin + TABLE_CHECKSUM_OFFSET,
            mcfg_begin,
            mcfg_end - mcfg_begin,
        )?;
        Ok(mcfg_begin as u64)
    }

    /// Build ACPI FADT table, returns the offset of ACPI FADT table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `loader` - ACPI table loader.
    /// `dsdt_addr` - Offset of ACPI DSDT table in `acpi_data`.
    fn build_fadt_table(
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
        dsdt_addr: u64,
    ) -> Result<u64>
    where
        Self: Sized,
    {
        let mut fadt = AcpiTable::new(*b"FACP", 6, *b"STRATO", *b"VIRTFSCP", 1);

        fadt.set_table_len(208_usize);
        // PM_TMR_BLK bit, offset is 76.
        #[cfg(target_arch = "x86_64")]
        fadt.set_field(76, 0x608);
        // FADT flag: disable HW_REDUCED_ACPI bit.
        fadt.set_field(112, 1 << 10 | 1 << 8);
        // FADT minor revision
        fadt.set_field(131, 3);
        // X_PM_TMR_BLK bit, offset is 208.
        #[cfg(target_arch = "x86_64")]
        fadt.append_child(&AcpiGenericAddress::new_io_address(0x608_u32).aml_bytes());
        // FADT table size is fixed.
        fadt.set_table_len(276_usize);

        #[cfg(target_arch = "x86_64")]
        {
            // Sleep control register, offset is 244.
            fadt.set_field(244, 0x01_u8);
            fadt.set_field(245, 0x08_u8);
            fadt.set_field(248, SLEEP_CTRL_OFFSET as u64);
            // Sleep status tegister, offset is 256.
            fadt.set_field(256, 0x01_u8);
            fadt.set_field(257, 0x08_u8);
            fadt.set_field(260, SLEEP_CTRL_OFFSET as u64);
        }

        let mut locked_acpi_data = acpi_data.lock().unwrap();
        let fadt_begin = locked_acpi_data.len() as u32;
        locked_acpi_data.extend(fadt.aml_bytes());
        let fadt_end = locked_acpi_data.len() as u32;
        drop(locked_acpi_data);

        // xDSDT address field's offset in FADT.
        let xdsdt_offset = 140_u32;
        // Size of xDSDT address.
        let xdsdt_size = 8_u8;
        loader.add_pointer_entry(
            ACPI_TABLE_FILE,
            fadt_begin + xdsdt_offset,
            xdsdt_size,
            ACPI_TABLE_FILE,
            dsdt_addr as u32,
        )?;

        loader.add_cksum_entry(
            ACPI_TABLE_FILE,
            fadt_begin + TABLE_CHECKSUM_OFFSET,
            fadt_begin,
            fadt_end - fadt_begin,
        )?;

        Ok(fadt_begin as u64)
    }

    /// Build ACPI XSDT table, returns the offset of ACPI XSDT table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `loader` - ACPI table loader.
    /// `xsdt_entries` - Offset of table entries in `acpi_data`, such as FADT, MADT, MCFG table.
    fn build_xsdt_table(
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
        xsdt_entries: Vec<u64>,
    ) -> Result<u64>
    where
        Self: Sized,
    {
        let mut xsdt = AcpiTable::new(*b"XSDT", 1, *b"STRATO", *b"VIRTXSDT", 1);

        xsdt.set_table_len(xsdt.table_len() + size_of::<u64>() * xsdt_entries.len());

        let mut locked_acpi_data = acpi_data.lock().unwrap();
        let xsdt_begin = locked_acpi_data.len() as u32;
        locked_acpi_data.extend(xsdt.aml_bytes());
        let xsdt_end = locked_acpi_data.len() as u32;
        drop(locked_acpi_data);

        // Offset of table entries in XSDT.
        let mut entry_offset = 36_u32;
        // Size of each entry.
        let entry_size = size_of::<u64>() as u8;
        for entry in xsdt_entries {
            loader.add_pointer_entry(
                ACPI_TABLE_FILE,
                xsdt_begin + entry_offset,
                entry_size,
                ACPI_TABLE_FILE,
                entry as u32,
            )?;
            entry_offset += u32::from(entry_size);
        }

        loader.add_cksum_entry(
            ACPI_TABLE_FILE,
            xsdt_begin + TABLE_CHECKSUM_OFFSET,
            xsdt_begin,
            xsdt_end - xsdt_begin,
        )?;

        Ok(xsdt_begin as u64)
    }

    /// Build ACPI RSDP and add it to FwCfg as file-entry.
    ///
    /// # Arguments
    ///
    /// `loader` - ACPI table loader.
    /// `fw_cfg`: FwCfgOps trait object.
    /// `xsdt_addr` - Offset of ACPI XSDT table in `acpi_data`.
    fn build_rsdp(loader: &mut TableLoader, fw_cfg: &mut dyn FwCfgOps, xsdt_addr: u64) -> Result<()>
    where
        Self: Sized,
    {
        let rsdp = AcpiRsdp::new(*b"STRATO");
        let rsdp_data = Arc::new(Mutex::new(rsdp.aml_bytes().to_vec()));

        loader.add_alloc_entry(ACPI_RSDP_FILE, rsdp_data.clone(), 16, true)?;

        let xsdt_offset = 24_u32;
        let xsdt_size = 8_u8;
        loader.add_pointer_entry(
            ACPI_RSDP_FILE,
            xsdt_offset,
            xsdt_size,
            ACPI_TABLE_FILE,
            xsdt_addr as u32,
        )?;

        let cksum_offset = 8_u32;
        let exd_cksum_offset = 32_u32;
        loader.add_cksum_entry(ACPI_RSDP_FILE, cksum_offset, 0, 20)?;
        loader.add_cksum_entry(ACPI_RSDP_FILE, exd_cksum_offset, 0, 36)?;

        fw_cfg.add_file_entry(ACPI_RSDP_FILE, rsdp_data.lock().unwrap().to_vec())?;

        Ok(())
    }
}

fn get_device_bdf(bus: Option<String>, addr: Option<String>) -> Result<PciBdf> {
    let mut pci_bdf = PciBdf {
        bus: bus.unwrap_or_else(|| String::from("pcie.0")),
        addr: (0, 0),
    };
    let addr = addr.unwrap_or_else(|| String::from("0x0"));
    pci_bdf.addr = get_pci_df(&addr).chain_err(|| "Failed to get device num or function num")?;
    Ok(pci_bdf)
}

impl StdMachine {
    fn plug_virtio_pci_blk(
        &mut self,
        pci_bdf: &PciBdf,
        args: &qmp_schema::DeviceAddArgument,
    ) -> Result<()> {
        let multifunction = args.multifunction.unwrap_or(false);
        let drive = if let Some(drv) = &args.drive {
            drv
        } else {
            bail!("Drive not set");
        };

        let blk = if let Some(conf) = self.get_vm_config().lock().unwrap().drives.get(drive) {
            let dev = BlkDevConfig {
                id: conf.id.clone(),
                path_on_host: conf.path_on_host.clone(),
                read_only: conf.read_only,
                direct: conf.direct,
                serial_num: args.serial_num.clone(),
                iothread: args.iothread.clone(),
                iops: conf.iops,
            };
            dev.check()?;
            Arc::new(Mutex::new(Block::new(dev)))
        } else {
            bail!("Drive not found");
        };

        self.add_virtio_pci_device(&args.id, pci_bdf, blk, multifunction)
            .chain_err(|| "Failed to add virtio pci device")
    }

    fn plug_vfio_pci_device(
        &mut self,
        bdf: &PciBdf,
        args: &qmp_schema::DeviceAddArgument,
    ) -> Result<()> {
        if args.host.is_none() {
            bail!("Option \"host\" not provided.");
        }

        if let Err(e) = self.create_vfio_pci_device(
            &args.id,
            bdf,
            args.host.as_ref().unwrap(),
            args.multifunction.map_or(false, |m| m),
        ) {
            error!("{}", e.display_chain());
            bail!("Failed to plug vfio-pci device.");
        }
        Ok(())
    }
}

impl DeviceInterface for StdMachine {
    fn query_status(&self) -> Response {
        let vm_state = self.get_vm_state();
        let vmstate = vm_state.deref().0.lock().unwrap();
        let qmp_state = match *vmstate {
            KvmVmState::Running => qmp_schema::StatusInfo {
                singlestep: false,
                running: true,
                status: qmp_schema::RunState::running,
            },
            KvmVmState::Paused => qmp_schema::StatusInfo {
                singlestep: false,
                running: true,
                status: qmp_schema::RunState::paused,
            },
            _ => Default::default(),
        };

        Response::create_response(serde_json::to_value(&qmp_state).unwrap(), None)
    }

    fn query_cpus(&self) -> Response {
        let mut cpu_vec: Vec<serde_json::Value> = Vec::new();
        let cpu_topo = self.get_cpu_topo();
        let cpus = self.get_cpus();
        for cpu_index in 0..cpu_topo.max_cpus {
            if cpu_topo.get_mask(cpu_index as usize) == 1 {
                let thread_id = cpus[cpu_index as usize].tid();
                let (socketid, coreid, threadid) = cpu_topo.get_topo(cpu_index as usize);
                let cpu_instance = qmp_schema::CpuInstanceProperties {
                    node_id: None,
                    socket_id: Some(socketid as isize),
                    core_id: Some(coreid as isize),
                    thread_id: Some(threadid as isize),
                };
                let cpu_info = qmp_schema::CpuInfo::x86 {
                    current: true,
                    qom_path: String::from("/machine/unattached/device[")
                        + &cpu_index.to_string()
                        + &"]".to_string(),
                    halted: false,
                    props: Some(cpu_instance),
                    CPU: cpu_index as isize,
                    thread_id: thread_id as isize,
                    x86: qmp_schema::CpuInfoX86 {},
                };
                cpu_vec.push(serde_json::to_value(cpu_info).unwrap());
            }
        }
        Response::create_response(cpu_vec.into(), None)
    }

    fn query_hotpluggable_cpus(&self) -> Response {
        Response::create_empty_response()
    }

    fn balloon(&self, value: u64) -> Response {
        if qmp_balloon(value) {
            return Response::create_empty_response();
        }
        Response::create_error_response(
            qmp_schema::QmpErrorClass::DeviceNotActive(
                "No balloon device has been activated".to_string(),
            ),
            None,
        )
    }

    fn query_balloon(&self) -> Response {
        if let Some(actual) = qmp_query_balloon() {
            let ret = qmp_schema::BalloonInfo { actual };
            return Response::create_response(serde_json::to_value(&ret).unwrap(), None);
        }
        Response::create_error_response(
            qmp_schema::QmpErrorClass::DeviceNotActive(
                "No balloon device has been activated".to_string(),
            ),
            None,
        )
    }

    fn device_add(&mut self, args: Box<qmp_schema::DeviceAddArgument>) -> Response {
        if let Err(e) = self.check_device_id_existed(&args.id) {
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            );
        }

        // Use args.bus.clone() and args.addr.clone() because args borrowed in the following process.
        let pci_bdf = match get_device_bdf(args.bus.clone(), args.addr.clone()) {
            Ok(bdf) => bdf,
            Err(e) => {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        };

        let driver = args.driver.as_str();
        match driver {
            "virtio-blk-pci" => {
                if let Err(e) = self.plug_virtio_pci_blk(&pci_bdf, args.as_ref()) {
                    let err_str = format!("Failed to add virtio pci blk: {}", e.to_string());
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(err_str),
                        None,
                    );
                }
            }
            "vfio-pci" => {
                if let Err(e) = self.plug_vfio_pci_device(&pci_bdf, args.as_ref()) {
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                        None,
                    );
                }
            }
            _ => {
                let err_str = format!("Failed to add device: Driver {} is not support", driver);
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(err_str),
                    None,
                );
            }
        }

        // It's safe to call get_pci_host().unwrap() because it has been checked before.
        let locked_pci_host = self.get_pci_host().unwrap().lock().unwrap();
        if let Some((bus, dev)) = PciBus::find_attached_bus(&locked_pci_host.root_bus, &args.id) {
            match handle_plug(&bus, &dev) {
                Ok(()) => Response::create_empty_response(),
                Err(e) => {
                    if let Err(e) = PciBus::detach_device(&bus, &dev) {
                        error!("{}", e.display_chain());
                        error!("Failed to detach device");
                    }
                    let err_str = format!("Failed to plug device: {}", e.to_string());
                    Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(err_str),
                        None,
                    )
                }
            }
        } else {
            Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(
                    "Failed to add device: Bus not found".to_string(),
                ),
                None,
            )
        }
    }

    fn device_del(&mut self, device_id: String) -> Response {
        let pci_host = match self.get_pci_host() {
            Ok(host) => host,
            Err(e) => {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        };

        let locked_pci_host = pci_host.lock().unwrap();
        if let Some((bus, dev)) = PciBus::find_attached_bus(&locked_pci_host.root_bus, &device_id) {
            match handle_unplug_request(&bus, &dev) {
                Ok(()) => Response::create_empty_response(),
                Err(e) => Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                ),
            }
        } else {
            let err_str = format!("Failed to remove device: id {} not found", &device_id);
            Response::create_error_response(qmp_schema::QmpErrorClass::GenericError(err_str), None)
        }
    }

    fn blockdev_add(
        &self,
        node_name: String,
        file: qmp_schema::FileOptions,
        cache: Option<qmp_schema::CacheOptions>,
        read_only: Option<bool>,
        iops: Option<u64>,
    ) -> Response {
        let read_only = read_only.unwrap_or(false);
        let direct = if let Some(cache) = cache {
            cache.direct.unwrap_or(true)
        } else {
            true
        };
        let config = DriveConfig {
            id: node_name,
            path_on_host: file.filename,
            read_only,
            direct,
            iops,
        };

        if let Err(e) = config.check() {
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            );
        }
        // Check whether path is valid after configuration check
        if let Err(e) = config.check_path() {
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            );
        }
        match self
            .get_vm_config()
            .lock()
            .unwrap()
            .add_drive_with_config(config)
        {
            Ok(()) => Response::create_empty_response(),
            Err(e) => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            ),
        }
    }

    fn blockdev_del(&self, node_name: String) -> Response {
        match self
            .get_vm_config()
            .lock()
            .unwrap()
            .del_drive_by_id(&node_name)
        {
            Ok(()) => Response::create_empty_response(),
            Err(e) => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            ),
        }
    }

    fn netdev_add(&self, _id: String, _if_name: Option<String>, _fds: Option<String>) -> Response {
        Response::create_empty_response()
    }

    fn getfd(&self, fd_name: String, if_fd: Option<RawFd>) -> Response {
        if let Some(fd) = if_fd {
            QmpChannel::set_fd(fd_name, fd);
            Response::create_empty_response()
        } else {
            let err_resp =
                qmp_schema::QmpErrorClass::GenericError("Invalid SCM message".to_string());
            Response::create_error_response(err_resp, None)
        }
    }
}
