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

pub mod syscall;

#[cfg(target_arch = "aarch64")]
pub use crate::aarch64::standard::StdMachine;
pub use crate::error::MachineError;
#[cfg(target_arch = "x86_64")]
pub use crate::x86_64::standard::StdMachine;

use std::mem::size_of;
use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::os::unix::prelude::AsRawFd;
use std::rc::Rc;
use std::string::String;
use std::sync::{Arc, Mutex};
use std::u64;

use anyhow::{bail, Context, Result};
use log::error;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

#[cfg(target_arch = "aarch64")]
use crate::aarch64::standard::{LayoutEntryType, MEM_LAYOUT};
#[cfg(target_arch = "x86_64")]
use crate::x86_64::ich9_lpc::{
    PM_CTRL_OFFSET, PM_EVENT_OFFSET, RST_CTRL_OFFSET, SLEEP_CTRL_OFFSET,
};
#[cfg(target_arch = "x86_64")]
use crate::x86_64::standard::{LayoutEntryType, MEM_LAYOUT};
use crate::MachineOps;
#[cfg(target_arch = "x86_64")]
use acpi::AcpiGenericAddress;
use acpi::{
    AcpiRsdp, AcpiTable, AmlBuilder, TableLoader, ACPI_RSDP_FILE, ACPI_TABLE_FILE,
    ACPI_TABLE_LOADER_FILE, TABLE_CHECKSUM_OFFSET,
};
use address_space::{
    AddressRange, FileBackend, GuestAddress, HostMemMapping, Region, RegionIoEventFd, RegionOps,
};
use block_backend::{qcow2::QCOW2_LIST, BlockStatus};
#[cfg(target_arch = "x86_64")]
use devices::acpi::cpu_controller::CpuController;
use devices::legacy::FwCfgOps;
use devices::pci::hotplug::{handle_plug, handle_unplug_pci_request};
use devices::pci::PciBus;
#[cfg(feature = "usb_camera")]
use machine_manager::config::get_cameradev_config;
#[cfg(feature = "windows_emu_pid")]
use machine_manager::config::VmConfig;
use machine_manager::config::{
    get_chardev_config, get_netdev_config, memory_unit_conversion, ConfigCheck, DiskFormat,
    DriveConfig, ExBool, NumaNode, NumaNodes, M,
};
use machine_manager::event_loop::EventLoop;
use machine_manager::machine::{
    DeviceInterface, MachineAddressInterface, MachineLifecycle, VmState,
};
use machine_manager::qmp::qmp_schema::{BlockDevAddArgument, UpdateRegionArgument};
use machine_manager::qmp::{qmp_channel::QmpChannel, qmp_response::Response, qmp_schema};
#[cfg(feature = "gtk")]
use ui::gtk::qmp_query_display_image;
use ui::input::{input_button, input_move_abs, input_point_sync, key_event, Axis};
#[cfg(feature = "vnc")]
use ui::vnc::qmp_query_vnc;
use util::aio::{AioEngine, WriteZeroesState};
use util::byte_code::ByteCode;
use util::loop_context::{read_fd, EventNotifier, NotifierCallback, NotifierOperation};
use virtio::{qmp_balloon, qmp_query_balloon};

const MAX_REGION_SIZE: u64 = 65536;

pub(crate) trait StdMachineOps: AcpiBuilder + MachineOps {
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

        let facs_addr = Self::build_facs_table(&acpi_tables)
            .with_context(|| "Failed to build ACPI FACS table")?;

        let dsdt_addr = self
            .build_dsdt_table(&acpi_tables, &mut loader)
            .with_context(|| "Failed to build ACPI DSDT table")?;
        let fadt_addr = Self::build_fadt_table(&acpi_tables, &mut loader, facs_addr, dsdt_addr)
            .with_context(|| "Failed to build ACPI FADT table")?;
        xsdt_entries.push(fadt_addr);

        let madt_addr = self
            .build_madt_table(&acpi_tables, &mut loader)
            .with_context(|| "Failed to build ACPI MADT table")?;
        xsdt_entries.push(madt_addr);

        #[cfg(target_arch = "aarch64")]
        {
            let gtdt_addr = self
                .build_gtdt_table(&acpi_tables, &mut loader)
                .with_context(|| "Failed to build ACPI GTDT table")?;
            xsdt_entries.push(gtdt_addr);

            let dbg2_addr = self
                .build_dbg2_table(&acpi_tables, &mut loader)
                .with_context(|| "Failed to build ACPI DBG2 table")?;
            xsdt_entries.push(dbg2_addr);

            let iort_addr = self
                .build_iort_table(&acpi_tables, &mut loader)
                .with_context(|| "Failed to build ACPI IORT table")?;
            xsdt_entries.push(iort_addr);

            let spcr_addr = self
                .build_spcr_table(&acpi_tables, &mut loader)
                .with_context(|| "Failed to build ACPI SPCR table")?;
            xsdt_entries.push(spcr_addr);
        }

        let mcfg_addr = Self::build_mcfg_table(&acpi_tables, &mut loader)
            .with_context(|| "Failed to build ACPI MCFG table")?;
        xsdt_entries.push(mcfg_addr);

        if let Some(numa_nodes) = self.get_numa_nodes() {
            let srat_addr = self
                .build_srat_table(&acpi_tables, &mut loader)
                .with_context(|| "Failed to build ACPI SRAT table")?;
            xsdt_entries.push(srat_addr);

            let slit_addr = Self::build_slit_table(numa_nodes, &acpi_tables, &mut loader)
                .with_context(|| "Failed to build ACPI SLIT table")?;
            xsdt_entries.push(slit_addr);
        }

        #[cfg(target_arch = "aarch64")]
        {
            let pptt_addr = self
                .build_pptt_table(&acpi_tables, &mut loader)
                .with_context(|| "Failed to build ACPI PPTT table")?;
            xsdt_entries.push(pptt_addr);
        }

        let xsdt_addr = Self::build_xsdt_table(&acpi_tables, &mut loader, xsdt_entries)?;

        let mut locked_fw_cfg = fw_cfg.lock().unwrap();
        Self::build_rsdp(
            &mut loader,
            &mut *locked_fw_cfg as &mut dyn FwCfgOps,
            xsdt_addr,
        )
        .with_context(|| "Failed to build ACPI RSDP")?;

        locked_fw_cfg
            .add_file_entry(ACPI_TABLE_LOADER_FILE, loader.cmd_entries())
            .with_context(|| "Failed to add ACPI table loader file entry")?;
        locked_fw_cfg
            .add_file_entry(ACPI_TABLE_FILE, acpi_tables.lock().unwrap().to_vec())
            .with_context(|| "Failed to add ACPI-tables file entry")?;

        Ok(())
    }

    fn add_fwcfg_device(
        &mut self,
        _nr_cpus: u8,
        #[cfg(target_arch = "x86_64")] _max_cpus: u8,
    ) -> Result<Option<Arc<Mutex<dyn FwCfgOps>>>> {
        bail!("Not implemented");
    }

    /// Get cpu controller.
    #[cfg(target_arch = "x86_64")]
    fn get_cpu_controller(&self) -> &Arc<Mutex<CpuController>>;

    /// Add new vcpu device.
    ///
    /// # Arguments
    ///
    /// * `clone_vm` - Reference of the StdMachine.
    #[cfg(target_arch = "x86_64")]
    fn add_vcpu_device(&mut self, clone_vm: Arc<Mutex<StdMachine>>) -> Result<()>;

    /// Register event notifier for hotplug vcpu event.
    ///
    /// # Arguments
    ///
    /// * `resize_req` - Eventfd of the cpu hotplug request.
    /// * `clone_vm`  - Reference of the StdMachine.
    #[cfg(target_arch = "x86_64")]
    fn register_hotplug_vcpu_event(
        &self,
        hotplug_req: Arc<EventFd>,
        clone_vm: Arc<Mutex<StdMachine>>,
    ) -> Result<()> {
        let hotplug_req_fd = hotplug_req.as_raw_fd();
        let hotplug_req_handler: Rc<NotifierCallback> = Rc::new(move |_, _| {
            read_fd(hotplug_req_fd);
            if let Err(e) = StdMachine::handle_hotplug_vcpu_request(&clone_vm) {
                error!("Fail to hotplug vcpu, {}", e);
            }
            None
        });
        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            hotplug_req_fd,
            None,
            EventSet::IN,
            vec![hotplug_req_handler],
        );
        EventLoop::update_event(vec![notifier], None)
            .with_context(|| "Failed to register event notifier.")
    }

    /// Remove vcpu device.
    ///
    /// # Arguments
    ///
    /// * `vcpu_id` - The id number of vcpu.
    #[cfg(target_arch = "x86_64")]
    fn remove_vcpu_device(&mut self, vcpu_id: u8) -> Result<()>;

    /// Find cpu id by device id.
    ///
    /// # Arguments
    ///
    /// * `device_id` - The name of vcpu device.
    #[cfg(target_arch = "x86_64")]
    fn find_cpu_id_by_device_id(&mut self, device_id: &str) -> Option<u8>;

    /// Register event notifier for reset of standard machine.
    ///
    /// # Arguments
    ///
    /// * `reset_req` - Eventfd of the reset request.
    /// * `clone_vm` - Reference of the StdMachine.
    fn register_reset_event(
        &self,
        reset_req: Arc<EventFd>,
        clone_vm: Arc<Mutex<StdMachine>>,
    ) -> Result<()> {
        let reset_req_fd = reset_req.as_raw_fd();
        let reset_req_handler: Rc<NotifierCallback> = Rc::new(move |_, _| {
            read_fd(reset_req_fd);
            if let Err(e) = StdMachine::handle_reset_request(&clone_vm) {
                error!("Fail to reboot standard VM, {:?}", e);
            }

            None
        });
        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            reset_req_fd,
            None,
            EventSet::IN,
            vec![reset_req_handler],
        );
        EventLoop::update_event(vec![notifier], None)
            .with_context(|| "Failed to register event notifier.")
    }

    fn register_pause_event(
        &self,
        pause_req: Arc<EventFd>,
        clone_vm: Arc<Mutex<StdMachine>>,
    ) -> Result<()> {
        let pause_req_fd = pause_req.as_raw_fd();
        let pause_req_handler: Rc<NotifierCallback> = Rc::new(move |_, _| {
            let _ret = pause_req.read();
            if !clone_vm.lock().unwrap().pause() {
                error!("VM pause failed");
            }
            None
        });

        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            pause_req_fd,
            None,
            EventSet::IN,
            vec![pause_req_handler],
        );
        EventLoop::update_event(vec![notifier], None)
            .with_context(|| "Failed to register event notifier.")
    }

    fn register_resume_event(
        &self,
        resume_req: Arc<EventFd>,
        clone_vm: Arc<Mutex<StdMachine>>,
    ) -> Result<()> {
        let resume_req_fd = resume_req.as_raw_fd();
        let resume_req_handler: Rc<NotifierCallback> = Rc::new(move |_, _| {
            let _ret = resume_req.read();
            if !clone_vm.lock().unwrap().resume() {
                error!("VM resume failed!");
            }
            None
        });

        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            resume_req_fd,
            None,
            EventSet::IN,
            vec![resume_req_handler],
        );
        EventLoop::update_event(vec![notifier], None)
            .with_context(|| "Failed to register event notifier.")
    }

    fn register_shutdown_event(
        &self,
        shutdown_req: Arc<EventFd>,
        clone_vm: Arc<Mutex<StdMachine>>,
    ) -> Result<()> {
        use util::loop_context::gen_delete_notifiers;

        let shutdown_req_fd = shutdown_req.as_raw_fd();
        let shutdown_req_handler: Rc<NotifierCallback> = Rc::new(move |_, _| {
            let _ret = shutdown_req.read();
            if StdMachine::handle_destroy_request(&clone_vm).is_ok() {
                Some(gen_delete_notifiers(&[shutdown_req_fd]))
            } else {
                None
            }
        });
        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            shutdown_req_fd,
            None,
            EventSet::IN,
            vec![shutdown_req_handler],
        );
        EventLoop::update_event(vec![notifier], None)
            .with_context(|| "Failed to register event notifier.")
    }
}

/// Trait that helps to build ACPI tables.
/// Standard machine struct should at least implement `build_dsdt_table`, `build_madt_table`
/// and `build_mcfg_table` function.
pub(crate) trait AcpiBuilder {
    /// Add ACPI table to the end of table loader, returns the offset of ACPI table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `loader` - ACPI table loader.
    /// `table` - ACPI table.
    fn add_table_to_loader(
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
        table: &AcpiTable,
    ) -> Result<u64> {
        let mut locked_acpi_data = acpi_data.lock().unwrap();
        let table_begin = locked_acpi_data.len() as u32;
        locked_acpi_data.extend(table.aml_bytes());
        let table_end = locked_acpi_data.len() as u32;
        // Drop the lock of acpi_data to avoid dead-lock when adding entry to
        // TableLoader, because TableLoader also needs to acquire this lock.
        drop(locked_acpi_data);

        loader.add_cksum_entry(
            ACPI_TABLE_FILE,
            table_begin + TABLE_CHECKSUM_OFFSET,
            table_begin,
            table_end - table_begin,
        )?;

        Ok(table_begin as u64)
    }

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

    /// Build ACPI GTDT table, returns the offset of ACPI GTDT table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `loader` - ACPI table loader.
    #[cfg(target_arch = "aarch64")]
    fn build_gtdt_table(
        &self,
        _acpi_data: &Arc<Mutex<Vec<u8>>>,
        _loader: &mut TableLoader,
    ) -> Result<u64>
    where
        Self: Sized,
    {
        Ok(0)
    }

    /// Build ACPI DBG2 table, returns the offset of ACPI DBG2 table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `loader` - ACPI table loader.
    #[cfg(target_arch = "aarch64")]
    fn build_dbg2_table(
        &self,
        _acpi_data: &Arc<Mutex<Vec<u8>>>,
        _loader: &mut TableLoader,
    ) -> Result<u64>
    where
        Self: Sized,
    {
        bail!("Not implemented");
    }

    /// Build ACPI IORT table, returns the offset of ACPI IORT table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `loader` - ACPI table loader.
    #[cfg(target_arch = "aarch64")]
    fn build_iort_table(
        &self,
        _acpi_data: &Arc<Mutex<Vec<u8>>>,
        _loader: &mut TableLoader,
    ) -> Result<u64>
    where
        Self: Sized,
    {
        Ok(0)
    }

    /// Build ACPI SPCR table, returns the offset of ACPI SPCR table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `loader` - ACPI table loader.
    #[cfg(target_arch = "aarch64")]
    fn build_spcr_table(
        &self,
        _acpi_data: &Arc<Mutex<Vec<u8>>>,
        _loader: &mut TableLoader,
    ) -> Result<u64>
    where
        Self: Sized,
    {
        Ok(0)
    }

    /// Build ACPI PPTT table, returns the offset of ACPI PPTT table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `Loader` - ACPI table loader.
    #[cfg(target_arch = "aarch64")]
    fn build_pptt_table(
        &self,
        _acpi_data: &Arc<Mutex<Vec<u8>>>,
        _loader: &mut TableLoader,
    ) -> Result<u64>
    where
        Self: Sized,
    {
        Ok(0)
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
        // Bits 20~28 (totally 9 bits) in PCIE ECAM represents bus number.
        let bus_number_mask = (1 << 9) - 1;
        let ecam_addr: u64;
        let max_nr_bus: u64;
        #[cfg(target_arch = "x86_64")]
        {
            ecam_addr = MEM_LAYOUT[LayoutEntryType::PcieEcam as usize].0;
            max_nr_bus = (MEM_LAYOUT[LayoutEntryType::PcieEcam as usize].1 >> 20) & bus_number_mask;
        }
        #[cfg(target_arch = "aarch64")]
        {
            ecam_addr = MEM_LAYOUT[LayoutEntryType::HighPcieEcam as usize].0;
            max_nr_bus =
                (MEM_LAYOUT[LayoutEntryType::HighPcieEcam as usize].1 >> 20) & bus_number_mask;
        }

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
    /// `facs_addr` - Offset of ACPI FACS table in `acpi_data`.
    /// `dsdt_addr` - Offset of ACPI DSDT table in `acpi_data`.
    fn build_fadt_table(
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
        facs_addr: u64,
        dsdt_addr: u64,
    ) -> Result<u64>
    where
        Self: Sized,
    {
        let mut fadt = AcpiTable::new(*b"FACP", 6, *b"STRATO", *b"VIRTFACP", 1);

        fadt.set_table_len(208_usize);
        // PM1A_EVENT bit, offset is 56.
        #[cfg(target_arch = "x86_64")]
        fadt.set_field(56, 0x600);
        // PM1A_CONTROL bit, offset is 64.
        #[cfg(target_arch = "x86_64")]
        fadt.set_field(64, 0x604);
        // PM_TMR_BLK bit, offset is 76.
        #[cfg(target_arch = "x86_64")]
        fadt.set_field(76, 0x608);
        // PM1_EVT_LEN, offset is 88.
        #[cfg(target_arch = "x86_64")]
        fadt.set_field(88, 4);
        // PM1_CNT_LEN, offset is 89.
        #[cfg(target_arch = "x86_64")]
        fadt.set_field(89, 2);
        // PM_TMR_LEN, offset is 91.
        #[cfg(target_arch = "x86_64")]
        fadt.set_field(91, 4);
        #[cfg(target_arch = "aarch64")]
        {
            // FADT flag: enable HW_REDUCED_ACPI and LOW_POWER_S0_IDLE_CAPABLE bit on aarch64 plantform.
            fadt.set_field(112, 1 << 21 | 1 << 20 | 1 << 10 | 1 << 8);
            // ARM Boot Architecture Flags
            fadt.set_field(129, 0x3_u16);
        }
        // FADT minor revision
        fadt.set_field(131, 3);
        // X_PM_TMR_BLK bit, offset is 208.
        #[cfg(target_arch = "x86_64")]
        fadt.append_child(&AcpiGenericAddress::new_io_address(0x608_u32).aml_bytes());
        // FADT table size is fixed.
        fadt.set_table_len(276_usize);

        #[cfg(target_arch = "x86_64")]
        {
            // FADT flag: disable HW_REDUCED_ACPI bit on x86 plantform.
            fadt.set_field(112, 1 << 10 | 1 << 8);
            // Reset Register bit, offset is 116.
            fadt.set_field(116, 0x01_u8);
            fadt.set_field(117, 0x08_u8);
            fadt.set_field(120, RST_CTRL_OFFSET as u64);
            fadt.set_field(128, 0x0F_u8);
            // PM1a event register bit, offset is 148.
            fadt.set_field(148, 0x01_u8);
            fadt.set_field(149, 0x20_u8);
            fadt.set_field(152, PM_EVENT_OFFSET as u64);
            // PM1a control register bit, offset is 172.
            fadt.set_field(172, 0x01_u8);
            fadt.set_field(173, 0x10_u8);
            fadt.set_field(176, PM_CTRL_OFFSET as u64);
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

        // FACS address field's offset in FADT.
        let facs_offset = 36_u32;
        // Size of FACS address.
        let facs_size = 4_u8;
        loader.add_pointer_entry(
            ACPI_TABLE_FILE,
            fadt_begin + facs_offset,
            facs_size,
            ACPI_TABLE_FILE,
            facs_addr as u32,
        )?;

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

    /// Build ACPI FACS table, returns the offset of ACPI FACS table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    fn build_facs_table(acpi_data: &Arc<Mutex<Vec<u8>>>) -> Result<u64>
    where
        Self: Sized,
    {
        let mut facs_data = vec![0_u8; 0x40];
        // FACS table signature.
        facs_data[0] = b'F';
        facs_data[1] = b'A';
        facs_data[2] = b'C';
        facs_data[3] = b'S';
        // FACS table length.
        facs_data[4] = 0x40;

        let mut locked_acpi_data = acpi_data.lock().unwrap();
        let facs_begin = locked_acpi_data.len() as u32;
        locked_acpi_data.extend(facs_data);
        drop(locked_acpi_data);

        Ok(facs_begin as u64)
    }

    /// Build ACPI SRAT CPU table.
    ///  # Arguments
    ///
    /// `proximity_domain` - The proximity domain.
    /// `node` - The NUMA node.
    /// `srat` - The SRAT table.
    fn build_srat_cpu(&self, proximity_domain: u32, node: &NumaNode, srat: &mut AcpiTable);

    /// Build ACPI SRAT memory table.
    ///  # Arguments
    ///
    /// `base_addr` - The base address of the memory range.
    /// `proximity_domain` - The proximity domain.
    /// `node` - The NUMA node.
    /// `srat` - The SRAT table.
    fn build_srat_mem(
        &self,
        base_addr: u64,
        proximity_domain: u32,
        node: &NumaNode,
        srat: &mut AcpiTable,
    ) -> u64;

    /// Build ACPI SRAT table, returns the offset of ACPI SRAT table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `loader` - ACPI table loader.
    fn build_srat_table(
        &self,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> Result<u64>;

    /// Build ACPI SLIT table, returns the offset of ACPI SLIT table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `numa_nodes` - The information of NUMA nodes.
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `loader` - ACPI table loader.
    fn build_slit_table(
        numa_nodes: &NumaNodes,
        acpi_data: &Arc<Mutex<Vec<u8>>>,
        loader: &mut TableLoader,
    ) -> Result<u64> {
        let mut slit = AcpiTable::new(*b"SLIT", 1, *b"STRATO", *b"VIRTSLIT", 1);
        slit.append_child((numa_nodes.len() as u64).as_bytes());

        let existing_nodes: Vec<u32> = numa_nodes.keys().cloned().collect();
        for (id, node) in numa_nodes.iter().enumerate() {
            let distances = &node.1.distances;
            for i in existing_nodes.iter() {
                let dist: u8 = if id as u32 == *i {
                    10
                } else if let Some(distance) = distances.get(i) {
                    *distance
                } else {
                    20
                };
                slit.append_child(dist.as_bytes());
            }
        }

        let slit_begin = StdMachine::add_table_to_loader(acpi_data, loader, &slit)
            .with_context(|| "Fail to add SLIT table to loader")?;
        Ok(slit_begin)
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

impl StdMachine {
    fn handle_unplug_usb_request(&mut self, id: String) -> Result<()> {
        let vm_config = self.get_vm_config();
        let mut locked_vmconfig = vm_config.lock().unwrap();
        self.detach_usb_from_xhci_controller(&mut locked_vmconfig, id)
    }

    /// When windows emu exits, stratovirt should exits too.
    #[cfg(feature = "windows_emu_pid")]
    pub(crate) fn watch_windows_emu_pid(
        &self,
        vm_config: &VmConfig,
        power_button: Arc<EventFd>,
        shutdown_req: Arc<EventFd>,
    ) {
        let emu_pid = vm_config.windows_emu_pid.as_ref();
        if emu_pid.is_none() {
            return;
        }
        log::info!("Watching on windows emu lifetime");
        crate::check_windows_emu_pid(
            "/proc/".to_owned() + emu_pid.unwrap(),
            power_button,
            shutdown_req,
        );
    }

    #[cfg(target_arch = "x86_64")]
    fn plug_cpu_device(&mut self, args: &qmp_schema::DeviceAddArgument) -> Result<()> {
        if self.get_numa_nodes().is_some() {
            bail!("Not support to hotplug/hotunplug cpu in numa architecture now.")
        }
        let device_id = args.id.clone();
        if device_id.is_empty() {
            bail!("Device id can't be empty.")
        }

        if let Some(cpu_id) = args.cpu_id {
            let nr_cpus = self.get_cpu_topo().nrcpus;
            let max_cpus = self.get_cpu_topo().max_cpus;

            if nr_cpus == max_cpus {
                bail!("There is no hotpluggable cpu-id for this VM.")
            }
            if cpu_id < nr_cpus {
                bail!("Cpu-id {} already exist.", cpu_id)
            }
            if cpu_id >= max_cpus {
                bail!("Max cpu-id is {}", max_cpus - 1)
            }

            let mut locked_controller = self.get_cpu_controller().lock().unwrap();
            locked_controller.check_id_existed(&device_id, cpu_id)?;
            locked_controller.set_hotplug_cpu_info(device_id, cpu_id)?;
            locked_controller.trigger_hotplug_cpu()
        } else {
            bail!("Argument cpu-id is required.")
        }
    }
}

impl MachineAddressInterface for StdMachine {
    #[cfg(target_arch = "x86_64")]
    fn pio_in(&self, addr: u64, data: &mut [u8]) -> bool {
        self.machine_base().pio_in(addr, data)
    }

    #[cfg(target_arch = "x86_64")]
    fn pio_out(&self, addr: u64, data: &[u8]) -> bool {
        self.machine_base().pio_out(addr, data)
    }

    fn mmio_read(&self, addr: u64, data: &mut [u8]) -> bool {
        self.machine_base().mmio_read(addr, data)
    }

    fn mmio_write(&self, addr: u64, data: &[u8]) -> bool {
        self.machine_base().mmio_write(addr, data)
    }
}

impl DeviceInterface for StdMachine {
    fn query_status(&self) -> Response {
        let vm_state = self.get_vm_state();
        let vmstate = vm_state.deref().0.lock().unwrap();
        let qmp_state = match *vmstate {
            VmState::Running => qmp_schema::StatusInfo {
                singlestep: false,
                running: true,
                status: qmp_schema::RunState::running,
            },
            VmState::Paused => qmp_schema::StatusInfo {
                singlestep: false,
                running: false,
                status: qmp_schema::RunState::paused,
            },
            _ => Default::default(),
        };

        Response::create_response(serde_json::to_value(qmp_state).unwrap(), None)
    }

    fn query_cpus(&self) -> Response {
        let mut cpu_vec: Vec<serde_json::Value> = Vec::new();
        let cpu_topo = self.get_cpu_topo();
        let cpus = self.get_cpus();
        for cpu_index in 0..cpu_topo.max_cpus {
            if cpu_topo.get_mask(cpu_index as usize) == 1 {
                let thread_id = cpus[cpu_index as usize].tid();
                let cpu_instance = cpu_topo.get_topo_instance_for_qmp(cpu_index as usize);
                let cpu_common = qmp_schema::CpuInfoCommon {
                    current: true,
                    qom_path: String::from("/machine/unattached/device[")
                        + &cpu_index.to_string()
                        + "]",
                    halted: false,
                    props: Some(cpu_instance),
                    CPU: cpu_index as isize,
                    thread_id: thread_id as isize,
                };
                #[cfg(target_arch = "x86_64")]
                {
                    let cpu_info = qmp_schema::CpuInfo::x86 {
                        common: cpu_common,
                        x86: qmp_schema::CpuInfoX86 {},
                    };
                    cpu_vec.push(serde_json::to_value(cpu_info).unwrap());
                }
                #[cfg(target_arch = "aarch64")]
                {
                    let cpu_info = qmp_schema::CpuInfo::Arm {
                        common: cpu_common,
                        arm: qmp_schema::CpuInfoArm {},
                    };
                    cpu_vec.push(serde_json::to_value(cpu_info).unwrap());
                }
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
            return Response::create_response(serde_json::to_value(ret).unwrap(), None);
        }
        Response::create_error_response(
            qmp_schema::QmpErrorClass::DeviceNotActive(
                "No balloon device has been activated".to_string(),
            ),
            None,
        )
    }

    fn query_mem(&self) -> Response {
        self.mem_show();
        Response::create_empty_response()
    }

    fn query_vnc(&self) -> Response {
        #[cfg(feature = "vnc")]
        if let Some(vnc_info) = qmp_query_vnc() {
            return Response::create_response(serde_json::to_value(vnc_info).unwrap(), None);
        }
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(
                "The service of VNC is not supported".to_string(),
            ),
            None,
        )
    }

    fn query_display_image(&self) -> Response {
        let mut _err = String::from("The gtk feature is not supported");
        #[cfg(feature = "gtk")]
        match qmp_query_display_image() {
            Ok(gpu_info) => {
                return Response::create_response(serde_json::to_value(gpu_info).unwrap(), None);
            }
            Err(e) => {
                _err = format!("Failed to query_display_image: {:?}", e);
            }
        };
        Response::create_error_response(qmp_schema::QmpErrorClass::GenericError(_err), None)
    }

    fn device_add(&mut self, args: Box<qmp_schema::DeviceAddArgument>) -> Response {
        if let Err(e) = self.check_device_id_existed(&args.id) {
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            );
        }

        let driver = args.driver.as_str();
        let vm_config = self.get_vm_config();
        let mut locked_vmconfig = vm_config.lock().unwrap();
        let mut vm_config_clone = locked_vmconfig.clone();
        match driver {
            "virtio-blk-pci" => {
                let cfg_args = locked_vmconfig.add_device_config(args.as_ref());
                if let Err(e) = self.add_virtio_pci_blk(&mut vm_config_clone, &cfg_args, true) {
                    error!("{:?}", e);
                    locked_vmconfig.del_device_by_id(args.id);
                    let err_str = format!("Failed to add virtio pci blk: {}", e);
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(err_str),
                        None,
                    );
                }
            }
            "virtio-scsi-pci" => {
                let cfg_args = locked_vmconfig.add_device_config(args.as_ref());
                if let Err(e) = self.add_virtio_pci_scsi(&mut vm_config_clone, &cfg_args, true) {
                    error!("{:?}", e);
                    locked_vmconfig.del_device_by_id(args.id);
                    let err_str = format!("Failed to add virtio scsi controller: {}", e);
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(err_str),
                        None,
                    );
                }
            }
            "vhost-user-blk-pci" => {
                let cfg_args = locked_vmconfig.add_device_config(args.as_ref());
                if let Err(e) = self.add_vhost_user_blk_pci(&mut vm_config_clone, &cfg_args, true) {
                    error!("{:?}", e);
                    locked_vmconfig.del_device_by_id(args.id);
                    let err_str = format!("Failed to add vhost user blk pci: {}", e);
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(err_str),
                        None,
                    );
                }
            }
            "virtio-net-pci" => {
                let cfg_args = locked_vmconfig.add_device_config(args.as_ref());
                if let Err(e) = self.add_virtio_pci_net(&mut vm_config_clone, &cfg_args, true) {
                    error!("{:?}", e);
                    locked_vmconfig.del_device_by_id(args.id);
                    let err_str = format!("Failed to add virtio pci net: {}", e);
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(err_str),
                        None,
                    );
                }
            }
            "vfio-pci" => {
                let cfg_args = locked_vmconfig.add_device_config(args.as_ref());
                if let Err(e) = self.add_vfio_device(&cfg_args, true) {
                    error!("{:?}", e);
                    locked_vmconfig.del_device_by_id(args.id);
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                        None,
                    );
                }
            }
            "usb-kbd" | "usb-tablet" | "usb-camera" | "usb-host" => {
                let cfg_args = locked_vmconfig.add_device_config(args.as_ref());
                if let Err(e) = self.add_usb_device(&mut vm_config_clone, &cfg_args) {
                    error!("{:?}", e);
                    locked_vmconfig.del_device_by_id(args.id);
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                        None,
                    );
                }
                return Response::create_empty_response();
            }
            #[cfg(target_arch = "x86_64")]
            "generic-x86-cpu" => {
                if let Err(e) = self.plug_cpu_device(args.as_ref()) {
                    error!("{:?}", e);
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                        None,
                    );
                }
                return Response::create_empty_response();
            }
            _ => {
                let err_str = format!("Failed to add device: Driver {} is not support", driver);
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(err_str),
                    None,
                );
            }
        }
        drop(locked_vmconfig);

        // It's safe to call get_pci_host().unwrap() because it has been checked before.
        let locked_pci_host = self.get_pci_host().unwrap().lock().unwrap();
        if let Some((bus, dev)) = PciBus::find_attached_bus(&locked_pci_host.root_bus, &args.id) {
            match handle_plug(&bus, &dev) {
                Ok(()) => Response::create_empty_response(),
                Err(e) => {
                    if let Err(e) = PciBus::detach_device(&bus, &dev) {
                        error!("{:?}", e);
                        error!("Failed to detach device");
                    }
                    let err_str = format!("Failed to plug device: {}", e);
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
            return match handle_unplug_pci_request(&bus, &dev) {
                Ok(()) => {
                    let locked_dev = dev.lock().unwrap();
                    let dev_id = &locked_dev.name();
                    drop(locked_pci_host);
                    self.del_bootindex_devices(dev_id);
                    let vm_config = self.get_vm_config();
                    let mut locked_config = vm_config.lock().unwrap();
                    locked_config.del_device_by_id(device_id);
                    drop(locked_config);
                    Response::create_empty_response()
                }
                Err(e) => Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                ),
            };
        }
        drop(locked_pci_host);

        // Assume it is a cpu device, try to find this device in cpu device.
        #[cfg(target_arch = "x86_64")]
        if let Some(cpu_id) = self.find_cpu_id_by_device_id(&device_id) {
            return match self.remove_vcpu_device(cpu_id) {
                Ok(()) => Response::create_empty_response(),
                Err(e) => Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                ),
            };
        }

        // The device is not a pci device and not a cpu device, assume it is a usb device.
        match self.handle_unplug_usb_request(device_id) {
            Ok(()) => Response::create_empty_response(),
            Err(e) => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            ),
        }
    }

    fn blockdev_add(&self, args: Box<qmp_schema::BlockDevAddArgument>) -> Response {
        let config = match parse_blockdev(&args) {
            Ok(config) => config,
            Err(e) => {
                error!("{:?}", e);
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                );
            }
        };

        // Register drive backend file for hotplug drive.
        if let Err(e) = self.register_drive_file(
            &config.id,
            &args.file.filename,
            config.read_only,
            config.direct,
        ) {
            error!("{:?}", e);
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
            Err(e) => {
                error!("{:?}", e);
                // It's safe to unwrap as the path has been registered.
                self.unregister_drive_file(&args.file.filename).unwrap();
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        }
    }

    fn blockdev_del(&self, node_name: String) -> Response {
        match self
            .get_vm_config()
            .lock()
            .unwrap()
            .del_drive_by_id(&node_name)
        {
            Ok(path) => {
                // It's safe to unwrap as the path has been registered.
                self.unregister_drive_file(&path).unwrap();
                Response::create_empty_response()
            }
            Err(e) => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            ),
        }
    }

    fn chardev_add(&mut self, args: qmp_schema::CharDevAddArgument) -> Response {
        let config = match get_chardev_config(args) {
            Ok(conf) => conf,
            Err(e) => {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                );
            }
        };

        if let Err(e) = config.check() {
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            );
        }

        match self
            .get_vm_config()
            .lock()
            .unwrap()
            .add_chardev_with_config(config)
        {
            Ok(()) => Response::create_empty_response(),
            Err(e) => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            ),
        }
    }

    fn chardev_remove(&mut self, id: String) -> Response {
        match self.get_vm_config().lock().unwrap().del_chardev_by_id(&id) {
            Ok(()) => Response::create_empty_response(),
            Err(e) => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            ),
        }
    }

    fn netdev_add(&mut self, args: Box<qmp_schema::NetDevAddArgument>) -> Response {
        let config = match get_netdev_config(args) {
            Ok(conf) => conf,
            Err(e) => {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                );
            }
        };

        match self
            .get_vm_config()
            .lock()
            .unwrap()
            .add_netdev_with_config(config)
        {
            Ok(()) => Response::create_empty_response(),
            Err(e) => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            ),
        }
    }

    fn netdev_del(&mut self, id: String) -> Response {
        match self.get_vm_config().lock().unwrap().del_netdev_by_id(&id) {
            Ok(()) => Response::create_empty_response(),
            Err(e) => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            ),
        }
    }

    #[cfg(feature = "usb_camera")]
    fn cameradev_add(&mut self, args: qmp_schema::CameraDevAddArgument) -> Response {
        let config = match get_cameradev_config(args) {
            Ok(conf) => conf,
            Err(e) => {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                );
            }
        };

        match self
            .get_vm_config()
            .lock()
            .unwrap()
            .add_cameradev_with_config(config)
        {
            Ok(()) => Response::create_empty_response(),
            Err(e) => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            ),
        }
    }

    #[cfg(feature = "usb_camera")]
    fn cameradev_del(&mut self, id: String) -> Response {
        match self
            .get_vm_config()
            .lock()
            .unwrap()
            .del_cameradev_by_id(&id)
        {
            Ok(()) => Response::create_empty_response(),
            Err(e) => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            ),
        }
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

    fn update_region(&mut self, args: UpdateRegionArgument) -> Response {
        if args.size >= MAX_REGION_SIZE {
            let err_resp = qmp_schema::QmpErrorClass::GenericError(format!(
                "Region size {} is out of range",
                args.size
            ));
            return Response::create_error_response(err_resp, None);
        }
        #[derive(Default)]
        struct DummyDevice {
            head: u64,
        }

        impl DummyDevice {
            fn read(&mut self, data: &mut [u8], _base: GuestAddress, _offset: u64) -> bool {
                if data.len() != std::mem::size_of::<u64>() {
                    return false;
                }

                for (i, data) in data.iter_mut().enumerate().take(std::mem::size_of::<u64>()) {
                    *data = (self.head >> (8 * i)) as u8;
                }
                true
            }

            fn write(&mut self, data: &[u8], _addr: GuestAddress, _offset: u64) -> bool {
                if data.len() != std::mem::size_of::<u64>() {
                    return false;
                }

                let val = match u64::from_bytes(data) {
                    None => {
                        error!("DummyDevice: cannot read u64 from data");
                        return false;
                    }
                    Some(v) => v,
                };
                self.head = match val.checked_mul(2) {
                    None => {
                        error!("DummyDevice: val({}) * 2 is overflow", val);
                        return false;
                    }
                    Some(v) => v,
                };
                true
            }
        }

        let dummy_dev = Arc::new(Mutex::new(DummyDevice::default()));
        let dummy_dev_clone = dummy_dev.clone();
        let read_ops = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
            let mut device_locked = dummy_dev_clone.lock().unwrap();
            device_locked.read(data, addr, offset)
        };
        let dummy_dev_clone = dummy_dev;
        let write_ops = move |data: &[u8], addr: GuestAddress, offset: u64| -> bool {
            let mut device_locked = dummy_dev_clone.lock().unwrap();
            device_locked.write(data, addr, offset)
        };

        let dummy_dev_ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };

        let mut fd = None;
        if args.region_type.eq("rom_device_region") || args.region_type.eq("ram_device_region") {
            if let Some(file_name) = args.device_fd_path {
                fd = Some(
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(file_name)
                        .unwrap(),
                );
            }
        }

        let region;
        match args.region_type.as_str() {
            "io_region" => {
                region = Region::init_io_region(args.size, dummy_dev_ops, "UpdateRegionTest");
                if args.ioeventfd.is_some() && args.ioeventfd.unwrap() {
                    let ioeventfds = vec![RegionIoEventFd {
                        fd: Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()),
                        addr_range: AddressRange::from((
                            0,
                            args.ioeventfd_size.unwrap_or_default(),
                        )),
                        data_match: args.ioeventfd_data.is_some(),
                        data: args.ioeventfd_data.unwrap_or_default(),
                    }];
                    region.set_ioeventfds(&ioeventfds);
                }
            }
            "rom_device_region" => {
                region = Region::init_rom_device_region(
                    Arc::new(
                        HostMemMapping::new(
                            GuestAddress(args.offset),
                            None,
                            args.size,
                            fd.map(FileBackend::new_common),
                            false,
                            true,
                            true,
                        )
                        .unwrap(),
                    ),
                    dummy_dev_ops,
                    "RomDeviceRegionTest",
                );
            }
            "ram_device_region" => {
                region = Region::init_ram_device_region(
                    Arc::new(
                        HostMemMapping::new(
                            GuestAddress(args.offset),
                            None,
                            args.size,
                            fd.map(FileBackend::new_common),
                            false,
                            true,
                            false,
                        )
                        .unwrap(),
                    ),
                    "RamdeviceregionTest",
                );
            }
            _ => {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError("invalid rergion_type".to_string()),
                    None,
                );
            }
        };

        region.set_priority(args.priority as i32);
        if let Some(read_only) = args.romd {
            if region.set_rom_device_romd(read_only).is_err() {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(
                        "set_rom_device_romd failed".to_string(),
                    ),
                    None,
                );
            }
        }

        let sys_mem = self.get_sys_mem();
        match args.update_type.as_str() {
            "add" => {
                if sys_mem.root().add_subregion(region, args.offset).is_err() {
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError("add subregion failed".to_string()),
                        None,
                    );
                }
            }
            "delete" => {
                region.set_offset(GuestAddress(args.offset));
                if sys_mem.root().delete_subregion(&region).is_err() {
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(
                            "delete subregion failed".to_string(),
                        ),
                        None,
                    );
                }
            }
            _ => {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError("invalid update_type".to_string()),
                    None,
                )
            }
        };

        Response::create_empty_response()
    }

    fn input_event(&self, key: String, value: String) -> Response {
        match send_input_event(key, value) {
            Ok(()) => Response::create_empty_response(),
            Err(e) => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            ),
        }
    }

    fn human_monitor_command(&self, args: qmp_schema::HumanMonitorCmdArgument) -> Response {
        let cmd_args: Vec<&str> = args.command_line.split(' ').collect();
        match cmd_args[0] {
            "drive_add" => {
                // The drive_add command has three arguments split by space:
                // "drive_add dummy file=/path/to/file,format=raw,if=none,id=drive-id..."
                // The 'dummy' here is a placeholder for pci address which is not needed for drive.
                if cmd_args.len() != 3 {
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(
                            "Invalid number of arguments".to_string(),
                        ),
                        None,
                    );
                }
                let drive_cfg = match self
                    .get_vm_config()
                    .lock()
                    .unwrap()
                    .add_block_drive(cmd_args[2])
                {
                    Ok(cfg) => cfg,
                    Err(ref e) => {
                        return Response::create_error_response(
                            qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                            None,
                        );
                    }
                };
                if let Err(e) = self.register_drive_file(
                    &drive_cfg.id,
                    &drive_cfg.path_on_host,
                    drive_cfg.read_only,
                    drive_cfg.direct,
                ) {
                    error!("{:?}", e);
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                        None,
                    );
                }
            }
            "drive_del" => {
                // The drive_del command has two arguments split by space:
                // "drive_del drive-id"
                if cmd_args.len() != 2 {
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(
                            "Invalid number of arguments".to_string(),
                        ),
                        None,
                    );
                }
                return self.blockdev_del(cmd_args[1].to_string());
            }
            "info" => {
                // Only support to query snapshots information by:
                // "info snapshots"
                if cmd_args.len() != 2 {
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(
                            "Invalid number of arguments".to_string(),
                        ),
                        None,
                    );
                }
                if cmd_args[1] != "snapshots" {
                    return Response::create_error_response(
                        qmp_schema::QmpErrorClass::GenericError(format!(
                            "Unsupported command: {} {}",
                            cmd_args[0], cmd_args[1]
                        )),
                        None,
                    );
                }

                let qcow2_list = QCOW2_LIST.lock().unwrap();
                if qcow2_list.len() == 0 {
                    return Response::create_response(
                        serde_json::to_value("There is no snapshot available.\r\n").unwrap(),
                        None,
                    );
                }

                let mut info_str = "List of snapshots present on all disks:\r\n".to_string();
                // Note: VM state is "None" in disk snapshots. It's used for vm snapshots which we
                // don't support.
                let vmstate_str = "None\r\n".to_string();
                info_str += &vmstate_str;

                for (drive_name, qcow2driver) in qcow2_list.iter() {
                    let dev_str = format!(
                        "\r\nList of partial (non-loadable) snapshots on \'{}\':\r\n",
                        drive_name
                    );
                    let snap_infos = qcow2driver.lock().unwrap().list_snapshots();
                    info_str += &(dev_str + &snap_infos);
                }

                return Response::create_response(serde_json::to_value(info_str).unwrap(), None);
            }
            _ => {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(format!(
                        "Unsupported command: {}",
                        cmd_args[0]
                    )),
                    None,
                );
            }
        }
        Response::create_empty_response()
    }

    fn blockdev_snapshot_internal_sync(
        &self,
        args: qmp_schema::BlockdevSnapshotInternalArgument,
    ) -> Response {
        let qcow2_list = QCOW2_LIST.lock().unwrap();
        let qcow2driver = qcow2_list.get(&args.device);
        if qcow2driver.is_none() {
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::DeviceNotFound(format!(
                    "No device drive named {} while creating snapshot {}",
                    args.device, args.name
                )),
                None,
            );
        }

        // Do not unlock or drop the locked_status in this function.
        let status = qcow2driver.unwrap().lock().unwrap().get_status();
        let mut locked_status = status.lock().unwrap();
        *locked_status = BlockStatus::Snapshot;

        let vm_clock_nsec = EventLoop::get_ctx(None)
            .unwrap()
            .get_virtual_clock()
            .as_nanos() as u64;
        if let Err(e) = qcow2driver
            .unwrap()
            .lock()
            .unwrap()
            .create_snapshot(args.name.clone(), vm_clock_nsec)
        {
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(format!(
                    "Device {} Creates snapshot {} error: {}.",
                    args.device, args.name, e
                )),
                None,
            );
        }

        Response::create_empty_response()
    }

    fn blockdev_snapshot_delete_internal_sync(
        &self,
        args: qmp_schema::BlockdevSnapshotInternalArgument,
    ) -> Response {
        let qcow2_list = QCOW2_LIST.lock().unwrap();
        let qcow2driver = qcow2_list.get(&args.device);
        if qcow2driver.is_none() {
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::DeviceNotFound(format!(
                    "No device drive named {} while deleting snapshot {}",
                    args.device, args.name
                )),
                None,
            );
        }

        // Do not unlock or drop the locked_status in this function.
        let status = qcow2driver.unwrap().lock().unwrap().get_status();
        let mut locked_status = status.lock().unwrap();
        *locked_status = BlockStatus::Snapshot;

        let result = qcow2driver
            .unwrap()
            .lock()
            .unwrap()
            .delete_snapshot(args.name.clone());
        match result {
            Ok(snap_info) => {
                Response::create_response(serde_json::to_value(snap_info).unwrap(), None)
            }
            Err(e) => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(format!(
                    "Device {} deletes snapshot {} error! {}",
                    args.device, args.name, e
                )),
                None,
            ),
        }
    }

    fn query_vcpu_reg(&self, args: qmp_schema::QueryVcpuRegArgument) -> Response {
        let vcpu = args.vcpu;
        let addr = match u64::from_str_radix(args.addr.as_str(), 16) {
            Ok(addr) => addr,
            _ => {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(
                        "address not in hexadecimal".to_string(),
                    ),
                    None,
                );
            }
        };

        if let Some(val) = self.get_vcpu_reg_val(addr, vcpu) {
            return Response::create_response(
                serde_json::to_value(format!("{:X}", val)).unwrap(),
                None,
            );
        }

        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError("not supported or arguments error".to_string()),
            None,
        )
    }

    fn query_mem_gpa(&self, args: qmp_schema::QueryMemGpaArgument) -> Response {
        let gpa = match u64::from_str_radix(args.gpa.as_str(), 16) {
            Ok(gpa) => gpa,
            _ => {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(
                        "address not in hexadecimal".to_string(),
                    ),
                    None,
                );
            }
        };

        match self
            .machine_base()
            .sys_mem
            .read_object::<u32>(GuestAddress(gpa))
        {
            Ok(val) => {
                Response::create_response(serde_json::to_value(format!("{:X}", val)).unwrap(), None)
            }
            _ => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(
                    "this gpa does not support query".to_string(),
                ),
                None,
            ),
        }
    }
}

fn parse_blockdev(args: &BlockDevAddArgument) -> Result<DriveConfig> {
    let mut config = DriveConfig {
        id: args.node_name.clone(),
        path_on_host: args.file.filename.clone(),
        read_only: args.read_only.unwrap_or(false),
        direct: true,
        iops: args.iops,
        aio: args.file.aio,
        media: "disk".to_string(),
        discard: false,
        write_zeroes: WriteZeroesState::Off,
        format: DiskFormat::Raw,
        l2_cache_size: None,
        refcount_cache_size: None,
    };
    if args.cache.is_some() && !args.cache.as_ref().unwrap().direct.unwrap_or(true) {
        config.direct = false;
        config.aio = AioEngine::Off;
    }
    if let Some(discard) = args.discard.as_ref() {
        config.discard = discard
            .as_str()
            .parse::<ExBool>()
            .with_context(|| {
                format!(
                    "Invalid discard argument '{}', expected 'unwrap' or 'ignore'",
                    discard
                )
            })?
            .into();
    }
    if let Some(detect_zeroes) = args.detect_zeroes.as_ref() {
        config.write_zeroes = detect_zeroes
            .as_str()
            .parse::<WriteZeroesState>()
            .with_context(|| {
                format!(
                    "Invalid write-zeroes argument '{}', expected 'on | off | unmap'",
                    detect_zeroes
                )
            })?;
    }
    if let Some(format) = args.driver.as_ref() {
        config.format = format.as_str().parse::<DiskFormat>()?;
    }
    if let Some(l2_cache) = args.l2_cache_size.as_ref() {
        let sz = memory_unit_conversion(l2_cache, M)
            .with_context(|| format!("Invalid l2 cache size: {}", l2_cache))?;
        config.l2_cache_size = Some(sz);
    }
    if let Some(rc_cache) = args.refcount_cache_size.as_ref() {
        let sz = memory_unit_conversion(rc_cache, M)
            .with_context(|| format!("Invalid refcount cache size: {}", rc_cache))?;
        config.refcount_cache_size = Some(sz);
    }
    config.check()?;
    config.check_path()?;
    Ok(config)
}

fn send_input_event(key: String, value: String) -> Result<()> {
    match key.as_str() {
        "keyboard" => {
            let vec: Vec<&str> = value.split(',').collect();
            if vec.len() != 2 {
                bail!("Invalid keyboard format: {}", value);
            }
            let keycode = vec[0].parse::<u16>()?;
            let down = vec[1].parse::<u8>()? == 1;
            key_event(keycode, down)?;
        }
        "pointer" => {
            let vec: Vec<&str> = value.split(',').collect();
            // There are four expected parameters for input_event,
            // includes: x, y, button and down.
            if vec.len() != 4 {
                bail!("Invalid pointer format: {}", value);
            }
            let x = vec[0].parse::<u32>()?;
            let y = vec[1].parse::<u32>()?;
            let btn = vec[2].parse::<u32>()?;
            let down = vec[3].parse::<u32>()?;
            input_move_abs(Axis::X, x)?;
            input_move_abs(Axis::Y, y)?;
            input_button(btn, down != 0)?;
            input_point_sync()?;
        }
        _ => {
            bail!("Invalid input type: {}", key);
        }
    };
    Ok(())
}
