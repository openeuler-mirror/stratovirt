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

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;

mod acpi_device;
#[allow(dead_code)]
pub mod acpi_table;
#[allow(dead_code)]
pub(crate) mod aml_compiler;
#[allow(dead_code)]
mod table_loader;

pub use acpi_device::{AcpiPMTimer, AcpiPmCtrl, AcpiPmEvent};
pub use acpi_table::madt_subtable::*;
pub use acpi_table::*;
pub use aml_compiler::*;
pub use table_loader::TableLoader;

// The name of corresponding file-entry in FwCfg device that represents acpi table data.
pub const ACPI_TABLE_FILE: &str = "etc/acpi/tables";
// The name of corresponding file-entry in FwCfg device that represents acpi table loader.
pub const ACPI_TABLE_LOADER_FILE: &str = "etc/table-loader";
// The name of corresponding file-entry in FwCfg device that represents acpi rsdp struct.
pub const ACPI_RSDP_FILE: &str = "etc/acpi/rsdp";

pub mod errors {
    error_chain! {
        errors {
            FileEntryExist(name: String) {
                display("Failed to add AllocateEntry in TableLoader, file_blob {} already exists.", name)
            }
            NoMatchedFile(name: String) {
                display("Failed to find matched file_blob in TableLoader, file name: {}.", name)
            }
            Alignment(align: u32) {
                display("Invalid alignment {}. Alignment is in bytes, and must be a power of 2.", align)
            }
            AddrOverflow(offset: u32, size: u32, blob_size: usize) {
                display("Address overflows, offset {}, size {}, max size {}.", offset, size, blob_size)
            }
            AddPointerLength(size: u8) {
                display("Failed to add pointer command: pointer length {}, which is expected to be 1/2/4/8.", size)
            }
        }
    }
}
