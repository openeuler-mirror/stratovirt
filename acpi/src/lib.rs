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

mod acpi_device;
pub mod acpi_table;
pub(crate) mod aml_compiler;
pub mod error;
mod table_loader;

pub use acpi_device::{AcpiPMTimer, AcpiPmCtrl, AcpiPmEvent};
pub use acpi_table::madt_subtable::*;
pub use acpi_table::*;
pub use aml_compiler::*;
pub use error::AcpiError;
pub use table_loader::TableLoader;

// The name of corresponding file-entry in FwCfg device that represents acpi table data.
pub const ACPI_TABLE_FILE: &str = "etc/acpi/tables";
// The name of corresponding file-entry in FwCfg device that represents acpi table loader.
pub const ACPI_TABLE_LOADER_FILE: &str = "etc/table-loader";
// The name of corresponding file-entry in FwCfg device that represents acpi rsdp struct.
pub const ACPI_RSDP_FILE: &str = "etc/acpi/rsdp";
