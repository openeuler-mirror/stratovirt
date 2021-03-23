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

use std::sync::{Arc, Mutex};

use acpi::TableLoader;
use devices::legacy::FwCfgOps;
use errors::Result;
use kvm_ioctls::VmFd;
use machine_manager::config::PFlashConfig;

trait StdMachineOps: AcpiBuilder {
    fn init_pci_host(&self, vm_fd: &Arc<VmFd>) -> Result<()>;

    /// Build all ACPI tables and RSDP, and add them to FwCfg as file entries.
    ///
    /// # Arguments
    ///
    /// `fw_cfg` - FwCfgOps trait object.
    fn build_acpi_tables(&self, _fw_cfg: &Arc<Mutex<dyn FwCfgOps>>) -> Result<()>
    where
        Self: Sized,
    {
        bail!("Not implemented");
    }

    fn add_fwcfg_device(&mut self, _vm_fd: &VmFd) -> Result<Arc<Mutex<dyn FwCfgOps>>> {
        bail!("Not implemented");
    }

    fn add_pflash_device(&mut self, _config: &PFlashConfig, _vm_fd: &VmFd) -> Result<()> {
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
    fn build_mcfg_table(
        &self,
        _acpi_data: &Arc<Mutex<Vec<u8>>>,
        _loader: &mut TableLoader,
    ) -> Result<u64> {
        bail!("Not implemented");
    }

    /// Build ACPI FADT table, returns the offset of ACPI FADT table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `loader` - ACPI table loader.
    /// `dsdt_addr` - Offset of ACPI DSDT table in `acpi_data`.
    fn build_fadt_table(
        _acpi_data: &Arc<Mutex<Vec<u8>>>,
        _loader: &mut TableLoader,
        _dsdt_addr: u64,
    ) -> Result<u64>
    where
        Self: Sized,
    {
        bail!("Not implemented");
    }

    /// Build ACPI XSDT table, returns the offset of ACPI XSDT table in `acpi_data`.
    ///
    /// # Arguments
    ///
    /// `acpi_data` - Bytes streams that ACPI tables converts to.
    /// `loader` - ACPI table loader.
    /// `xsdt_entries` - Offset of table entries in `acpi_data`, such as FADT, MADT, MCFG table.
    fn build_xsdt_table(
        _acpi_data: &Arc<Mutex<Vec<u8>>>,
        _loader: &mut TableLoader,
        _xsdt_entries: Vec<u64>,
    ) -> Result<u64>
    where
        Self: Sized,
    {
        bail!("Not implemented");
    }

    /// Build ACPI RSDP and add it to FwCfg as file-entry.
    ///
    /// # Arguments
    ///
    /// `loader` - ACPI table loader.
    /// `fw_cfg`: FwCfgOps trait object.
    /// `xsdt_addr` - Offset of ACPI XSDT table in `acpi_data`.
    fn build_rsdp(
        _loader: &mut TableLoader,
        _fw_cfg: &mut dyn FwCfgOps,
        _xsdt_addr: u64,
    ) -> Result<()>
    where
        Self: Sized,
    {
        bail!("Not implemented");
    }
}
