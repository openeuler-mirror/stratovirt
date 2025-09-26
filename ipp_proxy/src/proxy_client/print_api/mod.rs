// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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

mod cups;
pub type PrintApi = cups::CupsPrintApi;

use std::collections::HashMap;

use anyhow::Result;
use util::byte_code::ByteCode;
use vmm_sys_util::eventfd::EventFd;

use crate::proxy_client::ipp_printer::{PageSizesIds, PrinterAttrs};

pub trait PrintOps {
    fn init_printers() -> Result<()>;
    fn create_printers_list(printer_uuid_num: &mut HashMap<String, u32>) -> Result<Vec<PrinterId>>;
    fn subscribe_printers_changes(update_evt: EventFd) -> Result<()>;
    fn fill_printer_attributes(
        sys_id: &PrinterId,
        pagesize_ids: &mut PageSizesIds,
    ) -> Result<PrinterAttrs>;
}

#[derive(Clone, Default, Debug)]
pub struct PrinterId {
    /// A printer NUM used to identify printer in printer manager
    pub printer_num: u32,
    /// A printer ID for ipp-url.
    pub printer_id: String,
    /// A printer ID used to identify printer on host.
    pub _host_printer_id: String,
    /// A name of the printer.
    pub _printer_name: String,
}

impl ByteCode for PrinterId {}

impl PrinterId {
    pub fn new(printer_num: u32, printer_id: &str, host_printer_id: &str, name: &str) -> Self {
        Self {
            printer_num,
            printer_id: printer_id.to_string(),
            _host_printer_id: host_printer_id.to_string(),
            _printer_name: name.to_string(),
        }
    }
}
