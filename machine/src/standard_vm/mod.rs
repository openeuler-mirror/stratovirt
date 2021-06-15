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
        }
        foreign_links{
            Io(std::io::Error);
        }
        errors {
            InitPCIeHostErr {
                display("Failed to init PCIe host.")
            }
        }
    }
}

use std::mem::size_of;
use std::sync::{Arc, Mutex};

#[cfg(target_arch = "x86_64")]
use acpi::AcpiGenericAddress;
use acpi::{
    AcpiRsdp, AcpiTable, AmlBuilder, TableLoader, ACPI_RSDP_FILE, ACPI_TABLE_FILE,
    ACPI_TABLE_LOADER_FILE, TABLE_CHECKSUM_OFFSET,
};
use devices::legacy::FwCfgOps;
use errors::{Result, ResultExt};
use util::byte_code::ByteCode;

#[cfg(target_arch = "aarch64")]
use aarch64::{LayoutEntryType, MEM_LAYOUT};
#[cfg(target_arch = "x86_64")]
use x86_64::{LayoutEntryType, MEM_LAYOUT};

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
        // FADT flag: HW_REDUCED_ACPI bit.
        fadt.set_field(112, 1 << 20 | 1 << 10 | 1 << 8);
        // FADT minor revision
        fadt.set_field(131, 3);
        // X_PM_TMR_BLK bit, offset is 208.
        #[cfg(target_arch = "x86_64")]
        fadt.append_child(&AcpiGenericAddress::new_io_address(0x608_u32).aml_bytes());
        // FADT table size is fixed.
        fadt.set_table_len(276_usize);

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
